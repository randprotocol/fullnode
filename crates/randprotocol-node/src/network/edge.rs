//! The connection guard (audit v6, NET-1): what `libp2p::connection_limits` cannot count.
//!
//! libp2p's limiter treats every peer alike and knows two numbers about an inbound connection
//! that has not finished its handshake — that it exists, and how many there are. Sixty-four
//! stalled handshakes from one host therefore filled the pending cap of a validator, and the 256
//! established slots were first come, first served, a validator's reconnect after a restart
//! included. Reserved peers ([`super::NetworkHandle::reserve_peer`]) answer the second: libp2p's
//! own `bypass_peer_id` takes them out of the established caps. This behaviour adds the two
//! checks that leaves open:
//!
//! - **pending inbound connections per source address** ([`MAX_PENDING_INCOMING_PER_ADDR`]). The
//!   identity of a connection mid-handshake is unknown, so the only thing to count by is where it
//!   comes from. Honest peers behind one address share the allowance; validators sit on hosts
//!   of their own.
//! - **established connections per peer, reserved peers included**. libp2p's bypass skips the
//!   per-peer check with the rest, and a reserved identity — a validator's, which its operator
//!   may run badly or lose — must not be able to open connections without bound:
//!   [`MAX_ESTABLISHED_PER_RESERVED_PEER`] for those, the chain's ordinary per-peer cap for
//!   everyone else (the number libp2p already holds them to; checked here too so the rule is in
//!   one place for both kinds).
//!
//! - **a node-wide pending cap with slots reserved for validators** (audit v10, NET-1:
//!   [`super::MAX_PENDING_INCOMING`], of which [`super::RESERVED_PENDING_INCOMING`] only a
//!   reserved peer's source may take). libp2p's own pending cap is identity-blind, so sixteen
//!   hosts with four stalled handshakes each filled it and a validator reconnecting after a
//!   restart was refused with them; the guard now holds the node-wide count itself (libp2p's is
//!   off). A handshake's identity is unknown until it finishes, so "a reserved peer's source" is
//!   the source address of a reserved peer's bootstrap address, of an address it was learned at,
//!   or of a connection it held ([`ReservedSources`]).
//!
//! Modelled on libp2p-connection-limits 0.7.0: a behaviour with a dummy handler that emits
//! nothing and only ever says yes or no to a connection. The counting is in plain types
//! ([`PendingBySource`], [`EstablishedByPeer`]) so it is tested without a socket.

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::behaviour::{ConnectionClosed, ConnectionEstablished, ListenFailure};
use libp2p::swarm::{
    dummy, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fmt;
use std::net::Ipv4Addr;
use std::task::{Context, Poll};

/// Inbound connections still in their handshake that one source address may hold at once
/// (audit v6, NET-1). Four: a peer reconnecting dials once per address it knows for us, and two
/// nodes behind one address starting together are two or three dials; past four the rest are
/// refused at accept and retried by an honest dialer on its 30 s redial. Against the node-wide
/// pending cap of 64 it takes sixteen source addresses, not one, to fill it — and each stalled
/// handshake now lasts [`super::HANDSHAKE_TIMEOUT`], not libp2p's ten seconds.
pub const MAX_PENDING_INCOMING_PER_ADDR: u32 = 4;

/// Established connections one *reserved* peer may hold, in either direction (audit v6, NET-1).
/// An ordinary peer gets two — one each way when both sides dial at once; a reserved one gets
/// twice that, so a validator reconnecting while its old connections are still being torn down
/// is not refused by its own leftovers. It is a bound, which the libp2p bypass alone is not.
pub const MAX_ESTABLISHED_PER_RESERVED_PEER: u32 = 4;

/// Where an inbound connection comes from, as far as its address says: the key the pending cap
/// counts by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    V4(Ipv4Addr),
    /// An IPv6 address's first 64 bits: a host is routinely given a whole /64, so counting by
    /// the full address would give one machine 2^64 allowances.
    V6Prefix(u64),
    /// No IP component at all (a relayed or memory address). One bucket for all of them: an
    /// address that names no host cannot be told from another that names none.
    Unknown,
}

/// The [`Source`] of a remote multiaddr: its first IP component. An IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`) is the IPv4 host it names, so the two spellings share one allowance.
pub fn source_of(addr: &Multiaddr) -> Source {
    for p in addr.iter() {
        match p {
            Protocol::Ip4(ip) => return Source::V4(ip),
            Protocol::Ip6(ip) => {
                return match ip.to_ipv4_mapped() {
                    Some(v4) => Source::V4(v4),
                    None => Source::V6Prefix((u128::from(ip) >> 64) as u64),
                };
            }
            _ => {}
        }
    }
    Source::Unknown
}

/// The most source addresses one reserved peer is remembered at ([`ReservedSources`]): a host
/// with an IPv4 and an IPv6 address, plus a move or two. A new one past it evicts an advertised
/// source first, then the least recently seen observed one; configured ones are never evicted.
pub const MAX_SOURCES_PER_RESERVED_PEER: usize = 4;

/// The most pending handshakes one reserved peer may hold as a reserved peer, over all its
/// sources together (audit v10, NET-1 review). Past it its handshakes are a stranger's, so no
/// single validator — however many addresses it names — can take the reserved share from the
/// others: the 32 slots need eight such peers, not two.
pub const MAX_RESERVED_PENDING_PER_PEER: u32 = 4;

/// How long an advertised or observed reserved source stays trusted without being seen again
/// (audit v10, NET-1 review): a source with a connection open never expires, and the clock runs
/// from when its last connection closed (re-review N1). A configured (bootstrap) source does not
/// expire.
pub const RESERVED_SOURCE_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// How a reserved peer's source was learned, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SourceKind {
    /// An address the peer advertised (identify) when it was reserved: its own claim. At most one
    /// per peer.
    Advertised,
    /// The remote address of a connection the peer held: seen, not claimed.
    Observed,
    /// The operator's bootstrap address for it: never evicted, never expires.
    Configured,
}

#[derive(Clone, Copy, Debug)]
struct Known {
    source: Source,
    kind: SourceKind,
    seen: std::time::Instant,
    /// Connections the peer holds from this source right now: a source in use never expires,
    /// and its `seen` is refreshed again when the last one closes (NET-1 re-review, N1).
    open: u32,
}

/// The source addresses reserved peers are known at (audit v10, NET-1): what lets a handshake
/// whose identity is not yet known take one of the pending slots reserved for validators. Only
/// IP sources count — [`Source::Unknown`] names no host and is never trusted. Bounded per peer
/// ([`MAX_SOURCES_PER_RESERVED_PEER`], at most one [`SourceKind::Advertised`]), observed sources
/// preferred over advertised ones, and expiring ([`RESERVED_SOURCE_TTL`]).
#[derive(Default)]
pub struct ReservedSources {
    by_peer: HashMap<PeerId, Vec<Known>>,
}

impl ReservedSources {
    /// Remember that reserved `peer` is reachable from `source`, learned as `kind` at `now`.
    pub fn add(&mut self, peer: PeerId, source: Source, kind: SourceKind, now: std::time::Instant) {
        if source == Source::Unknown {
            return;
        }
        let list = self.by_peer.entry(peer).or_default();
        if let Some(k) = list.iter_mut().find(|k| k.source == source) {
            k.kind = k.kind.max(kind);
            k.seen = now;
            return;
        }
        if kind == SourceKind::Advertised && list.iter().any(|k| k.kind == SourceKind::Advertised) {
            return; // one claimed address per peer
        }
        if list.len() >= MAX_SOURCES_PER_RESERVED_PEER {
            // Evict the weakest, least recently seen, never a configured one or one stronger than
            // the newcomer.
            let victim = list
                .iter()
                .enumerate()
                .filter(|(_, k)| k.kind != SourceKind::Configured && k.open == 0 && k.kind <= kind)
                .min_by_key(|(_, k)| (k.kind, k.seen))
                .map(|(i, _)| i);
            match victim {
                Some(i) => {
                    list.swap_remove(i);
                }
                None => return,
            }
        }
        list.push(Known { source, kind, seen: now, open: 0 });
    }

    /// `peer` holds a connection from `source` (seen, so [`SourceKind::Observed`] at least): the
    /// source is remembered, refreshed, and does not expire while the connection lives.
    pub fn connected(&mut self, peer: PeerId, source: Source, now: std::time::Instant) {
        self.add(peer, source, SourceKind::Observed, now);
        if let Some(k) = self.by_peer.get_mut(&peer).and_then(|l| l.iter_mut().find(|k| k.source == source)) {
            k.open += 1;
        }
    }

    /// A connection [`ReservedSources::connected`] counted closed: the source was seen until now,
    /// so its expiry runs from here, not from when the connection opened.
    pub fn disconnected(&mut self, peer: &PeerId, source: Source, now: std::time::Instant) {
        if let Some(k) = self.by_peer.get_mut(peer).and_then(|l| l.iter_mut().find(|k| k.source == source)) {
            k.open = k.open.saturating_sub(1);
            k.seen = now;
        }
    }

    /// Whether `k` is still trusted at `now`: configured, in use, or seen within the TTL.
    fn live(k: &Known, now: std::time::Instant) -> bool {
        k.kind == SourceKind::Configured || k.open > 0 || now.saturating_duration_since(k.seen) < RESERVED_SOURCE_TTL
    }

    /// Forget every source of `peer` (it stopped being reserved).
    pub fn remove_peer(&mut self, peer: &PeerId) {
        self.by_peer.remove(peer);
    }

    /// Drop the advertised and observed sources not seen within [`RESERVED_SOURCE_TTL`] of `now`.
    pub fn expire(&mut self, now: std::time::Instant) {
        for list in self.by_peer.values_mut() {
            list.retain(|k| Self::live(k, now));
        }
        self.by_peer.retain(|_, l| !l.is_empty());
    }

    /// The reserved peers known at `source` (unexpired at `now`).
    pub fn peers_at(&self, source: &Source, now: std::time::Instant) -> Vec<PeerId> {
        self.by_peer
            .iter()
            .filter(|(_, l)| {
                l.iter().any(|k| &k.source == source && Self::live(k, now))
            })
            .map(|(p, _)| *p)
            .collect()
    }

    /// `peer`'s sources.
    pub fn sources_of(&self, peer: &PeerId) -> Vec<Source> {
        self.by_peer.get(peer).map_or_else(Vec::new, |l| l.iter().map(|k| k.source).collect())
    }

    /// Whether `source` is a live (unexpired at `now`) source of some reserved peer: the same
    /// rule [`ReservedSources::peers_at`] applies (re-review N5).
    pub fn contains(&self, source: &Source, now: std::time::Instant) -> bool {
        !self.peers_at(source, now).is_empty()
    }
}

/// The node-wide pending caps (audit v10, NET-1): `total` handshakes at once, of which
/// `reserved` are held back for sources of reserved peers — anyone else gets `total − reserved`.
/// `per_addr` is [`MAX_PENDING_INCOMING_PER_ADDR`], for reserved sources too.
#[derive(Clone, Copy, Debug)]
pub struct PendingCaps {
    pub per_addr: u32,
    pub total: u32,
    pub reserved: u32,
}

/// The inbound connections still in their handshake, by where they come from.
#[derive(Default)]
pub struct PendingBySource {
    /// Each pending connection's source, and the reserved peer it was admitted for, if any.
    by_conn: HashMap<ConnectionId, (Source, Option<PeerId>)>,
    count: HashMap<Source, u32>,
    /// How many of `by_conn` were admitted from an unreserved source.
    unreserved: u32,
    /// The pending connections admitted as a reserved peer's, by that peer (re-review N2: by
    /// peer, not by source, so a source leaving the peer's list does not free its share).
    reserved_count: HashMap<PeerId, u32>,
}

impl PendingBySource {
    /// Count `id` against `source` under the per-address cap alone, or refuse it: `false` when
    /// `source` already holds `max`. A refused connection is not recorded, so it needs no release.
    pub fn admit(&mut self, id: ConnectionId, source: Source, max: u32) -> bool {
        self.admit_with(id, source, None, PendingCaps { per_addr: max, total: u32::MAX, reserved: 0 }).is_ok()
    }

    /// Count `id` against `source` under every pending cap, or say which one refuses it: the
    /// node-wide `total` first (no one past it), then — for a source that is not a reserved
    /// peer's — `total − reserved`, then the per-address cap. A refused connection is not
    /// recorded, so it needs no release.
    /// `reserved_for` is the reserved peer the handshake takes a reserved slot for, `None` for a
    /// stranger's.
    pub fn admit_with(&mut self, id: ConnectionId, source: Source, reserved_for: Option<PeerId>, caps: PendingCaps) -> Result<(), Denied> {
        let reserved_source = reserved_for.is_some();
        if self.by_conn.len() as u64 >= u64::from(caps.total) {
            return Err(Denied { limit: caps.total, kind: Kind::PendingIncoming });
        }
        let open = caps.total.saturating_sub(caps.reserved);
        if !reserved_source && self.unreserved >= open {
            return Err(Denied { limit: open, kind: Kind::PendingIncomingUnreserved });
        }
        let n = self.count.entry(source).or_insert(0);
        if *n >= caps.per_addr {
            if *n == 0 {
                self.count.remove(&source);
            }
            return Err(Denied { limit: caps.per_addr, kind: Kind::PendingIncomingPerAddr });
        }
        *n += 1;
        self.by_conn.insert(id, (source, reserved_for));
        if let Some(peer) = reserved_for {
            *self.reserved_count.entry(peer).or_insert(0) += 1;
        } else {
            self.unreserved += 1;
        }
        Ok(())
    }

    /// The handshake of `id` ended — established, failed or refused by another behaviour. A no-op
    /// for a connection never admitted here, and for a second release of one that was.
    pub fn release(&mut self, id: ConnectionId) {
        let Some((source, reserved_for)) = self.by_conn.remove(&id) else { return };
        if let Some(peer) = reserved_for {
            if let Some(n) = self.reserved_count.get_mut(&peer) {
                *n -= 1;
                if *n == 0 {
                    self.reserved_count.remove(&peer);
                }
            }
        } else {
            self.unreserved -= 1;
        }
        if let Some(n) = self.count.get_mut(&source) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                // No entry outlives its last connection: the map is bounded by the pending
                // connections themselves, which libp2p's node-wide pending cap bounds.
                self.count.remove(&source);
            }
        }
    }

    /// The pending connections admitted as reserved `peer`'s.
    pub fn reserved_for(&self, peer: &PeerId) -> u32 {
        self.reserved_count.get(peer).copied().unwrap_or(0)
    }

    pub fn pending_from(&self, source: &Source) -> u32 {
        self.count.get(source).copied().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.by_conn.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_conn.is_empty()
    }
}

/// The established connections, by peer, and which peers are reserved.
#[derive(Default)]
pub struct EstablishedByPeer {
    by_peer: HashMap<PeerId, HashSet<ConnectionId>>,
    reserved: HashSet<PeerId>,
}

impl EstablishedByPeer {
    pub fn reserve(&mut self, peer: PeerId) {
        self.reserved.insert(peer);
    }

    pub fn unreserve(&mut self, peer: &PeerId) {
        self.reserved.remove(peer);
    }

    pub fn is_reserved(&self, peer: &PeerId) -> bool {
        self.reserved.contains(peer)
    }

    pub fn reserved_len(&self) -> usize {
        self.reserved.len()
    }

    pub fn established(&self, peer: &PeerId) -> u32 {
        self.by_peer.get(peer).map_or(0, |c| c.len() as u32)
    }

    /// The cap `peer` is held to, and whether one more connection fits under it.
    pub fn allows_another(&self, peer: &PeerId, per_peer: u32, per_reserved_peer: u32) -> Result<(), Denied> {
        let (limit, kind) = match self.is_reserved(peer) {
            true => (per_reserved_peer, Kind::EstablishedPerReservedPeer),
            false => (per_peer, Kind::EstablishedPerPeer),
        };
        if self.established(peer) >= limit {
            return Err(Denied { limit, kind });
        }
        Ok(())
    }

    pub fn opened(&mut self, peer: PeerId, id: ConnectionId) {
        self.by_peer.entry(peer).or_default().insert(id);
    }

    pub fn closed(&mut self, peer: &PeerId, id: ConnectionId) {
        if let Some(c) = self.by_peer.get_mut(peer) {
            c.remove(&id);
            if c.is_empty() {
                self.by_peer.remove(peer);
            }
        }
    }
}

/// Why the guard refused a connection. Reaches the log through
/// `SwarmEvent::IncomingConnectionError` / `OutgoingConnectionError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denied {
    pub limit: u32,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    PendingIncomingPerAddr,
    /// The node-wide pending cap (audit v10, NET-1).
    PendingIncoming,
    /// The share of the pending cap a source that is no reserved peer's may hold.
    PendingIncomingUnreserved,
    EstablishedPerPeer,
    EstablishedPerReservedPeer,
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            Kind::PendingIncomingPerAddr => "pending incoming connections from one source address",
            Kind::PendingIncoming => "pending incoming connections",
            Kind::PendingIncomingUnreserved => "pending incoming connections from sources that are no reserved peer's",
            Kind::EstablishedPerPeer => "established connections per peer",
            Kind::EstablishedPerReservedPeer => "established connections per reserved peer",
        };
        write!(f, "connection guard: at most {} {what} are allowed", self.limit)
    }
}

impl std::error::Error for Denied {}

/// The caps the guard enforces, from [`super::WireLimits`].
#[derive(Clone, Copy, Debug)]
pub struct GuardLimits {
    pub max_pending_incoming_per_addr: u32,
    /// The node-wide pending cap (libp2p's is off; audit v10, NET-1).
    pub max_pending_incoming: u32,
    /// Of `max_pending_incoming`, the slots only a reserved peer's source may take.
    pub reserved_pending_incoming: u32,
    pub max_established_per_peer: u32,
    pub max_established_per_reserved_peer: u32,
}

/// The behaviour. Second in [`super::behaviour::RandBehaviour`], right after libp2p's limiter,
/// so both have said yes before any other behaviour holds state for the connection. A pending
/// connection libp2p's limiter counted and this one refuses is released there by the
/// `ListenFailure` the swarm hands every behaviour for a denied connection.
pub struct Guard {
    limits: GuardLimits,
    pending: PendingBySource,
    established: EstablishedByPeer,
    sources: ReservedSources,
    /// Added to the clock (tests only move it): what the source expiry reads.
    skew: std::time::Duration,
    /// Every established connection's peer and remote source, so a peer reserved while
    /// connected has its live sources counted as in use (N1).
    conn_sources: HashMap<ConnectionId, (PeerId, Source)>,
    /// Sources recently seen on a closed connection of any peer (dialed or accepted), so a peer
    /// reserved later has them as observed — seen, not claimed (re-review N3). At most
    /// [`MAX_SOURCES_PER_RESERVED_PEER`] per peer and [`MAX_RECENT_PEERS`] peers; entries older
    /// than [`RESERVED_SOURCE_TTL`] are worthless and are dropped first.
    recent: HashMap<PeerId, Vec<(Source, std::time::Instant)>>,
}

/// How many peers [`Guard`] remembers recently seen sources for (N3): a bound, not a topology.
pub const MAX_RECENT_PEERS: usize = 4096;

impl Guard {
    pub fn new(limits: GuardLimits) -> Guard {
        Guard {
            limits,
            pending: PendingBySource::default(),
            established: EstablishedByPeer::default(),
            sources: ReservedSources::default(),
            skew: std::time::Duration::ZERO,
            conn_sources: HashMap::new(),
            recent: HashMap::new(),
        }
    }

    fn now(&self) -> std::time::Instant {
        std::time::Instant::now() + self.skew
    }

    /// Reserve `peer` (its sources are learned from its connections). A peer reserved while
    /// connected has the sources of its live connections remembered, in use, at once.
    pub fn reserve(&mut self, peer: PeerId) {
        if self.established.is_reserved(&peer) {
            return;
        }
        self.established.reserve(peer);
        let now = self.now();
        // Sources seen on its earlier, closed connections (a dial included): observed, at the time seen.
        for (s, seen) in self.recent.remove(&peer).unwrap_or_default() {
            if now.saturating_duration_since(seen) < RESERVED_SOURCE_TTL {
                self.sources.add(peer, s, SourceKind::Observed, seen);
            }
        }
        let live: Vec<Source> = self.conn_sources.values().filter(|(p, _)| *p == peer).map(|(_, s)| *s).collect();
        for s in live {
            self.sources.connected(peer, s, now);
        }
    }

    /// Remember that `peer` (not reserved) was seen at `source` (N3).
    fn remember_recent(&mut self, peer: PeerId, source: Source, now: std::time::Instant) {
        if source == Source::Unknown {
            return;
        }
        if !self.recent.contains_key(&peer) && self.recent.len() >= MAX_RECENT_PEERS {
            self.recent.retain(|_, l| l.iter().any(|(_, t)| now.saturating_duration_since(*t) < RESERVED_SOURCE_TTL));
            if self.recent.len() >= MAX_RECENT_PEERS {
                let oldest = self.recent.iter().min_by_key(|(_, l)| l.iter().map(|(_, t)| *t).max()).map(|(p, _)| *p);
                if let Some(p) = oldest {
                    self.recent.remove(&p);
                }
            }
        }
        let list = self.recent.entry(peer).or_default();
        list.retain(|(s, _)| *s != source);
        if list.len() >= MAX_SOURCES_PER_RESERVED_PEER {
            list.remove(0);
        }
        list.push((source, now));
    }

    /// [`Guard::reserve`] plus the sources of `addrs`, learned as `kind` (a bootstrap address is
    /// [`SourceKind::Configured`], an address the peer advertised [`SourceKind::Advertised`] — of
    /// which only the first is kept).
    pub fn reserve_at<'a>(&mut self, peer: PeerId, addrs: impl IntoIterator<Item = &'a Multiaddr>, kind: SourceKind) {
        self.reserve(peer);
        let now = self.now();
        for a in addrs {
            self.sources.add(peer, source_of(a), kind, now);
        }
    }

    /// The reserved peer a handshake from `source` may take a reserved slot for: one known there
    /// whose admitted handshakes — counted by peer, whatever source they came from — hold fewer
    /// than [`MAX_RESERVED_PENDING_PER_PEER`] reserved slots. `None`: a stranger's handshake.
    fn reserved_for(&mut self, source: &Source) -> Option<PeerId> {
        let now = self.now();
        self.sources.expire(now);
        self.sources.peers_at(source, now).into_iter().find(|p| self.pending.reserved_for(p) < MAX_RESERVED_PENDING_PER_PEER)
    }

    pub fn unreserve(&mut self, peer: &PeerId) {
        self.established.unreserve(peer);
        self.sources.remove_peer(peer);
        self.recent.remove(peer);
    }

    fn pending_caps(&self) -> PendingCaps {
        PendingCaps {
            per_addr: self.limits.max_pending_incoming_per_addr,
            total: self.limits.max_pending_incoming,
            reserved: self.limits.reserved_pending_incoming,
        }
    }

    fn check_peer(&self, peer: &PeerId) -> Result<(), ConnectionDenied> {
        self.established
            .allows_another(peer, self.limits.max_established_per_peer, self.limits.max_established_per_reserved_peer)
            .map_err(ConnectionDenied::new)
    }
}

impl NetworkBehaviour for Guard {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        let source = source_of(remote_addr);
        let reserved_for = self.reserved_for(&source);
        self.pending.admit_with(connection_id, source, reserved_for, self.pending_caps()).map_err(ConnectionDenied::new)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.pending.release(connection_id);
        self.check_peer(&peer)?;
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.check_peer(&peer)?;
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionEstablished(ConnectionEstablished { peer_id, connection_id, endpoint, .. }) => {
                self.pending.release(connection_id);
                self.established.opened(peer_id, connection_id);
                // A reserved peer seen at an address: its source takes reserved pending slots
                // from now on (its next reconnect after a restart, say).
                let source = source_of(endpoint.get_remote_address());
                self.conn_sources.insert(connection_id, (peer_id, source));
                if self.established.is_reserved(&peer_id) {
                    let now = self.now();
                    self.sources.connected(peer_id, source, now);
                }
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { peer_id, connection_id, endpoint, .. }) => {
                self.established.closed(&peer_id, connection_id);
                // N1: the source was in use until now; its expiry starts here.
                let source = self.conn_sources.remove(&connection_id).map_or_else(|| source_of(endpoint.get_remote_address()), |(_, s)| s);
                let now = self.now();
                if self.established.is_reserved(&peer_id) {
                    self.sources.disconnected(&peer_id, source, now);
                } else {
                    self.remember_recent(peer_id, source, now);
                }
            }
            FromSwarm::ListenFailure(ListenFailure { connection_id, .. }) => {
                self.pending.release(connection_id);
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(&mut self, _: PeerId, _: ConnectionId, event: THandlerOutEvent<Self>) {
        match event {}
    }

    fn poll(&mut self, _: &mut Context<'_>) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(n: usize) -> ConnectionId {
        ConnectionId::new_unchecked(n)
    }

    fn addr(s: &str) -> Multiaddr {
        s.parse().expect("a valid multiaddr")
    }

    /// Audit v6, NET-1: one source address holds at most the cap of handshakes; the fifth is
    /// refused while another address is still admitted, and a finished handshake — however it
    /// finished — gives its place back.
    #[test]
    fn pending_handshakes_are_capped_per_source_address() {
        let mut p = PendingBySource::default();
        let a = source_of(&addr("/ip4/203.0.113.7/tcp/40001"));
        let b = source_of(&addr("/ip4/203.0.113.8/tcp/40001"));
        for i in 0..MAX_PENDING_INCOMING_PER_ADDR as usize {
            assert!(p.admit(conn(i), a, MAX_PENDING_INCOMING_PER_ADDR), "handshake {i} from one address");
        }
        assert!(!p.admit(conn(100), a, MAX_PENDING_INCOMING_PER_ADDR), "the address is at its cap");
        assert_eq!(p.pending_from(&a), MAX_PENDING_INCOMING_PER_ADDR);
        assert!(p.admit(conn(101), b, MAX_PENDING_INCOMING_PER_ADDR), "another address is not held to the first one's count");

        // A refused connection was never recorded: releasing it changes nothing.
        p.release(conn(100));
        assert_eq!(p.pending_from(&a), MAX_PENDING_INCOMING_PER_ADDR);
        // One finishes (established, failed or denied elsewhere — all one release), one more fits.
        p.release(conn(0));
        p.release(conn(0));
        assert_eq!(p.pending_from(&a), MAX_PENDING_INCOMING_PER_ADDR - 1, "a second release of one id frees nothing twice");
        assert!(p.admit(conn(102), a, MAX_PENDING_INCOMING_PER_ADDR));

        // Nothing is kept for a source with no handshake left.
        for i in [1, 2, 3, 101, 102] {
            p.release(conn(i));
        }
        assert!(p.is_empty());
        assert_eq!(p.pending_from(&a), 0);
        assert!(p.count.is_empty(), "a source's counter leaves with its last connection");
    }

    /// The source is the host, not the socket: another port is the same bucket, an IPv6 host's
    /// whole /64 is one bucket, an IPv4-mapped address is its IPv4 host, and an address naming
    /// no IP is the one bucket of those.
    #[test]
    fn the_source_of_a_connection_is_its_host() {
        assert_eq!(source_of(&addr("/ip4/203.0.113.7/tcp/1")), source_of(&addr("/ip4/203.0.113.7/tcp/2")));
        assert_ne!(source_of(&addr("/ip4/203.0.113.7/tcp/1")), source_of(&addr("/ip4/203.0.113.8/tcp/1")));
        assert_eq!(source_of(&addr("/ip6/2001:db8:1:2::1/tcp/1")), source_of(&addr("/ip6/2001:db8:1:2:ffff::9/tcp/1")));
        assert_ne!(source_of(&addr("/ip6/2001:db8:1:2::1/tcp/1")), source_of(&addr("/ip6/2001:db8:1:3::1/tcp/1")));
        assert_eq!(source_of(&addr("/ip6/::ffff:203.0.113.7/tcp/1")), source_of(&addr("/ip4/203.0.113.7/tcp/9")));
        assert_eq!(source_of(&addr("/dns4/node.example/tcp/1")), Source::Unknown);
        assert_eq!(source_of(&addr("/memory/7")), Source::Unknown);
    }

    /// libp2p's bypass takes a reserved peer out of the per-peer cap with every other cap. The
    /// guard puts a bound back: four for a reserved peer, the ordinary two for anyone else, and a
    /// peer that stops being reserved is held to two again.
    #[test]
    fn a_reserved_peer_is_still_held_to_a_per_peer_cap() {
        let mut e = EstablishedByPeer::default();
        let (stranger, validator) = (PeerId::random(), PeerId::random());
        e.reserve(validator);
        let allows = |e: &EstablishedByPeer, p: &PeerId| e.allows_another(p, 2, MAX_ESTABLISHED_PER_RESERVED_PEER);

        for i in 0..2 {
            assert!(allows(&e, &stranger).is_ok());
            e.opened(stranger, conn(i));
        }
        assert_eq!(allows(&e, &stranger), Err(Denied { limit: 2, kind: Kind::EstablishedPerPeer }));

        for i in 10..14 {
            assert!(allows(&e, &validator).is_ok(), "connection {i} of a reserved peer");
            e.opened(validator, conn(i));
        }
        assert_eq!(
            allows(&e, &validator),
            Err(Denied { limit: MAX_ESTABLISHED_PER_RESERVED_PEER, kind: Kind::EstablishedPerReservedPeer }),
            "a reserved identity cannot open connections without bound"
        );
        e.closed(&validator, conn(10));
        assert!(allows(&e, &validator).is_ok(), "a closed connection gives its place back");

        e.unreserve(&validator);
        assert_eq!(allows(&e, &validator), Err(Denied { limit: 2, kind: Kind::EstablishedPerPeer }));

        e.closed(&stranger, conn(0));
        e.closed(&stranger, conn(1));
        assert_eq!(e.established(&stranger), 0);
        assert!(!e.by_peer.contains_key(&stranger), "no entry outlives a peer's last connection");
    }

    // ------------------------------------------- the behaviour itself, through libp2p's hooks
    //
    // What the swarm calls, in the order it calls it, with synthetic ids and addresses: the
    // verdicts must be the right `ConnectionDenied` causes, and every `FromSwarm` event that
    // ends a handshake or a connection must give its slot back.

    use libp2p::core::ConnectedPoint;
    use libp2p::swarm::ListenError;

    const PER_PEER: u32 = 2;

    fn guard() -> Guard {
        Guard::new(GuardLimits {
            max_pending_incoming_per_addr: MAX_PENDING_INCOMING_PER_ADDR,
            max_pending_incoming: super::super::MAX_PENDING_INCOMING,
            reserved_pending_incoming: super::super::RESERVED_PENDING_INCOMING,
            max_established_per_peer: PER_PEER,
            max_established_per_reserved_peer: MAX_ESTABLISHED_PER_RESERVED_PEER,
        })
    }

    fn local() -> Multiaddr {
        addr("/ip4/127.0.0.1/tcp/30303")
    }

    fn pending(g: &mut Guard, id: usize, remote: &str) -> Result<(), ConnectionDenied> {
        g.handle_pending_inbound_connection(conn(id), &local(), &addr(remote))
    }

    fn established_inbound(g: &mut Guard, id: usize, peer: PeerId, remote: &str) -> Result<(), ConnectionDenied> {
        g.handle_established_inbound_connection(conn(id), peer, &local(), &addr(remote)).map(|_| ())
    }

    fn established_outbound(g: &mut Guard, id: usize, peer: PeerId) -> Result<(), ConnectionDenied> {
        g.handle_established_outbound_connection(conn(id), peer, &addr("/ip4/203.0.113.9/tcp/1"), Endpoint::Dialer, PortUse::Reuse).map(|_| ())
    }

    fn listener_point(remote: &str) -> ConnectedPoint {
        ConnectedPoint::Listener { local_addr: local(), send_back_addr: addr(remote) }
    }

    fn connection_established(g: &mut Guard, id: usize, peer: PeerId, point: &ConnectedPoint, other: usize) {
        g.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id: peer,
            connection_id: conn(id),
            endpoint: point,
            failed_addresses: &[],
            other_established: other,
        }));
    }

    fn connection_closed(g: &mut Guard, id: usize, peer: PeerId, point: &ConnectedPoint, remaining: usize) {
        g.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id: peer,
            connection_id: conn(id),
            endpoint: point,
            cause: None,
            remaining_established: remaining,
        }));
    }

    fn listen_failure(g: &mut Guard, id: usize, remote: &str) {
        let error = ListenError::Aborted;
        g.on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
            local_addr: &local(),
            send_back_addr: &addr(remote),
            error: &error,
            connection_id: conn(id),
            peer_id: None,
        }));
    }

    /// The cause a refusal carries, as the swarm's `IncomingConnectionError` would downcast it.
    fn denied(r: Result<(), ConnectionDenied>) -> Denied {
        match r {
            Ok(()) => panic!("admitted"),
            Err(e) => e.downcast::<Denied>().expect("the guard's own cause, not another behaviour's"),
        }
    }

    /// Audit v6, NET-1 through the swarm's own hook: the fifth handshake from one host is a
    /// `ConnectionDenied` whose cause is the guard's `PendingIncomingPerAddr` verdict at the cap,
    /// another host is unaffected, and the refused connection holds nothing.
    #[test]
    fn the_fifth_pending_handshake_from_one_host_is_denied_with_the_pending_cause() {
        let mut g = guard();
        for i in 0..MAX_PENDING_INCOMING_PER_ADDR as usize {
            pending(&mut g, i, "/ip4/203.0.113.7/tcp/40001").unwrap_or_else(|e| panic!("handshake {i}: {e}"));
        }
        let verdict = denied(pending(&mut g, 100, "/ip4/203.0.113.7/tcp/40002"));
        assert_eq!(verdict, Denied { limit: MAX_PENDING_INCOMING_PER_ADDR, kind: Kind::PendingIncomingPerAddr });
        assert_eq!(verdict.to_string(), "connection guard: at most 4 pending incoming connections from one source address are allowed");
        assert_eq!(g.pending.len(), MAX_PENDING_INCOMING_PER_ADDR as usize, "the refused one is not recorded");
        pending(&mut g, 101, "/ip4/203.0.113.8/tcp/40001").expect("another host is admitted");
        // A `ListenFailure` for the refused id — which the swarm does send, since libp2p's own
        // limiter counted it — releases nothing that was never held.
        listen_failure(&mut g, 100, "/ip4/203.0.113.7/tcp/40002");
        assert_eq!(g.pending.pending_from(&Source::V4("203.0.113.7".parse().unwrap())), MAX_PENDING_INCOMING_PER_ADDR);
    }

    /// Each way a handshake ends gives its slot back: a `ListenFailure` (refused by another
    /// behaviour, failed, or timed out), an established inbound connection (the hook, then the
    /// event), and a `ConnectionEstablished` for an id this behaviour was never asked about.
    #[test]
    fn every_end_of_a_handshake_releases_its_pending_slot() {
        let host = "/ip4/203.0.113.7/tcp/40001";
        let source = Source::V4("203.0.113.7".parse().unwrap());
        let mut g = guard();
        for i in 0..4 {
            pending(&mut g, i, host).unwrap();
        }
        assert!(pending(&mut g, 9, host).is_err());

        listen_failure(&mut g, 0, host);
        assert_eq!(g.pending.pending_from(&source), 3, "a failed handshake gives its slot back");
        pending(&mut g, 10, host).expect("one more fits");

        let peer = PeerId::random();
        established_inbound(&mut g, 1, peer, host).expect("the handshake finished");
        assert_eq!(g.pending.pending_from(&source), 3, "an established connection is no longer pending");
        connection_established(&mut g, 1, peer, &listener_point(host), 0);
        assert_eq!(g.pending.pending_from(&source), 3, "the event for the same id releases nothing twice");
        assert_eq!(g.established.established(&peer), 1, "and it is counted against its peer");

        // A dial's connection was never pending here; its event must not disturb the count.
        let dialed = PeerId::random();
        connection_established(&mut g, 50, dialed, &ConnectedPoint::Dialer { address: addr("/ip4/203.0.113.7/tcp/1"), role_override: Endpoint::Dialer, port_use: PortUse::Reuse }, 0);
        assert_eq!(g.pending.pending_from(&source), 3);
        assert_eq!(g.established.established(&dialed), 1);
    }

    /// A stranger is held to the per-peer cap in both directions: with two connections up, a
    /// third — inbound or outbound — is a `ConnectionDenied` with the `EstablishedPerPeer`
    /// cause at the chain's cap, and the pending slot an inbound attempt took is still released
    /// when it is refused.
    #[test]
    fn a_stranger_is_held_to_the_per_peer_cap_in_both_directions() {
        let host = "/ip4/203.0.113.7/tcp/40001";
        let source = Source::V4("203.0.113.7".parse().unwrap());
        let mut g = guard();
        let peer = PeerId::random();
        // One inbound, one outbound: both sides dialed at once.
        pending(&mut g, 0, host).unwrap();
        established_inbound(&mut g, 0, peer, host).unwrap();
        connection_established(&mut g, 0, peer, &listener_point(host), 0);
        established_outbound(&mut g, 1, peer).unwrap();
        connection_established(&mut g, 1, peer, &ConnectedPoint::Dialer { address: addr(host), role_override: Endpoint::Dialer, port_use: PortUse::Reuse }, 1);
        assert_eq!(g.established.established(&peer), PER_PEER);

        assert_eq!(denied(established_outbound(&mut g, 2, peer)), Denied { limit: PER_PEER, kind: Kind::EstablishedPerPeer });
        pending(&mut g, 3, host).expect("the handshake itself is admitted: the identity is unknown until it finishes");
        assert_eq!(g.pending.pending_from(&source), 1);
        assert_eq!(denied(established_inbound(&mut g, 3, peer, host)), Denied { limit: PER_PEER, kind: Kind::EstablishedPerPeer });
        assert_eq!(g.pending.pending_from(&source), 0, "refused at the identity check, the handshake slot is released all the same");

        // A close frees a slot. A connection the hook admitted counts nothing until the swarm
        // reports it established — the hook is a check, the event is the count — so after both
        // closes the peer is at zero, and at one once the admitted dial's event arrives.
        connection_closed(&mut g, 0, peer, &listener_point(host), 1);
        established_outbound(&mut g, 4, peer).expect("a closed connection gives its place back");
        connection_closed(&mut g, 1, peer, &listener_point(host), 0);
        assert_eq!(g.established.established(&peer), 0, "admitted at the hook is not yet established");
        connection_established(&mut g, 4, peer, &listener_point(host), 0);
        assert_eq!(g.established.established(&peer), 1);
    }

    /// A reserved peer is not exempt from the guard: it bypasses libp2p's caps, so this is the
    /// only bound on it — `MAX_ESTABLISHED_PER_RESERVED_PEER`, with its own cause — and when it
    /// stops being reserved it is a stranger again, held to the chain's cap at once.
    #[test]
    fn a_reserved_peer_is_denied_at_its_own_cap_with_the_reserved_cause() {
        let host = "/ip4/203.0.113.7/tcp/40001";
        let mut g = guard();
        let validator = PeerId::random();
        g.reserve(validator);
        for i in 0..MAX_ESTABLISHED_PER_RESERVED_PEER as usize {
            established_outbound(&mut g, i, validator).unwrap_or_else(|e| panic!("connection {i} of a reserved peer: {e}"));
            connection_established(&mut g, i, validator, &listener_point(host), i);
        }
        let verdict = denied(established_outbound(&mut g, 10, validator));
        assert_eq!(verdict, Denied { limit: MAX_ESTABLISHED_PER_RESERVED_PEER, kind: Kind::EstablishedPerReservedPeer });
        assert!(verdict.to_string().contains("reserved peer"), "{verdict}");
        pending(&mut g, 11, host).unwrap();
        assert_eq!(denied(established_inbound(&mut g, 11, validator, host)).kind, Kind::EstablishedPerReservedPeer);

        g.unreserve(&validator);
        assert_eq!(denied(established_outbound(&mut g, 12, validator)), Denied { limit: PER_PEER, kind: Kind::EstablishedPerPeer }, "a stranger again, and over the stranger's cap");
        for i in 0..3 {
            connection_closed(&mut g, i, validator, &listener_point(host), 3 - i);
        }
        established_outbound(&mut g, 13, validator).expect("down to one, a second fits the stranger's cap");
        g.reserve(validator);
        connection_established(&mut g, 13, validator, &listener_point(host), 1);
        established_outbound(&mut g, 14, validator).expect("reserved again: the wider cap applies");
    }

    /// The pending cap counts hosts, not sockets or spellings: an IPv4-mapped IPv6 address
    /// shares its IPv4 host's allowance, a /64 is one IPv6 host, and the two addresses that
    /// name no host at all share the one `Unknown` bucket — all through the swarm's hook.
    #[test]
    fn the_pending_cap_is_per_host_through_the_hook() {
        let mut g = guard();
        pending(&mut g, 0, "/ip4/203.0.113.7/tcp/1").unwrap();
        pending(&mut g, 1, "/ip4/203.0.113.7/tcp/2").unwrap();
        pending(&mut g, 2, "/ip6/::ffff:203.0.113.7/tcp/3").unwrap();
        pending(&mut g, 3, "/ip6/::ffff:203.0.113.7/tcp/4").unwrap();
        assert_eq!(denied(pending(&mut g, 4, "/ip4/203.0.113.7/tcp/5")).kind, Kind::PendingIncomingPerAddr, "four spellings of one host");
        assert_eq!(denied(pending(&mut g, 5, "/ip6/::ffff:203.0.113.7/tcp/6")).kind, Kind::PendingIncomingPerAddr);

        for i in 10..14 {
            pending(&mut g, i, &format!("/ip6/2001:db8:1:2::{}/tcp/1", i)).unwrap();
        }
        assert!(pending(&mut g, 14, "/ip6/2001:db8:1:2:dead:beef::1/tcp/1").is_err(), "one /64 is one host");
        pending(&mut g, 15, "/ip6/2001:db8:1:3::1/tcp/1").expect("the next /64 is another host");

        pending(&mut g, 20, "/dns4/a.example/tcp/1").unwrap();
        pending(&mut g, 21, "/dns4/b.example/tcp/1").unwrap();
        pending(&mut g, 22, "/memory/1").unwrap();
        pending(&mut g, 23, "/p2p-circuit").unwrap();
        assert!(pending(&mut g, 24, "/dns6/c.example/tcp/1").is_err(), "addresses naming no host share one bucket");
        assert_eq!(g.pending.pending_from(&Source::Unknown), 4);
    }

    /// A cap of zero refuses every handshake and keeps no counter for the refused source: the
    /// branch that removes a fresh zero entry on refusal, so a refused-only source leaves no
    /// trace in the map.
    #[test]
    fn a_zero_pending_cap_refuses_everything_and_records_nothing() {
        let mut g = Guard::new(GuardLimits { max_pending_incoming_per_addr: 0, max_pending_incoming: 96, reserved_pending_incoming: 32, max_established_per_peer: PER_PEER, max_established_per_reserved_peer: 4 });
        assert_eq!(denied(pending(&mut g, 0, "/ip4/203.0.113.7/tcp/1")), Denied { limit: 0, kind: Kind::PendingIncomingPerAddr });
        assert!(g.pending.is_empty());
        assert!(g.pending.count.is_empty(), "a refused-only source leaves no counter behind");
        let mut p = PendingBySource::default();
        assert!(!p.admit(conn(1), Source::Unknown, 0));
        assert!(p.count.is_empty());
    }

    /// Audit v10, NET-1: strangers stalling handshakes from as many hosts as it takes fill only
    /// the unreserved share of the node-wide pending cap; a validator — a reserved peer, its
    /// source known from a connection it held or an address it was reserved at — still gets a
    /// slot, up to the node-wide total. Before, 64 stalled strangers locked every validator out.
    /// An unreserved validator's source is a stranger's again.
    #[test]
    fn strangers_cannot_fill_the_pending_slots_reserved_for_validators() {
        use super::super::{MAX_PENDING_INCOMING, RESERVED_PENDING_INCOMING};
        let mut g = guard();
        let validator = PeerId::random();
        let validator_host = "/ip4/198.51.100.20/tcp/30303";
        g.reserve(validator);
        // The validator was connected once (before this node's restart, say): its source is learned.
        let point = listener_point(validator_host);
        connection_established(&mut g, 9_000, validator, &point, 0);
        connection_closed(&mut g, 9_000, validator, &point, 0);
        // A second validator known only by the address it was reserved at (a bootstrap).
        let bootstrap = PeerId::random();
        g.reserve_at(bootstrap, [&addr("/ip4/198.51.100.21/tcp/30303")], SourceKind::Configured);

        // Strangers from 16+ hosts, four stalled handshakes each, until they are refused.
        let open = MAX_PENDING_INCOMING - RESERVED_PENDING_INCOMING;
        let mut id = 0usize;
        'fill: for host in 0..255u32 {
            for _ in 0..MAX_PENDING_INCOMING_PER_ADDR {
                match pending(&mut g, id, &format!("/ip4/203.0.{}.{}/tcp/40001", host / 250, host % 250 + 1)) {
                    Ok(()) => id += 1,
                    Err(e) => {
                        let d = e.downcast::<Denied>().unwrap();
                        assert_eq!(d, Denied { limit: open, kind: Kind::PendingIncomingUnreserved });
                        break 'fill;
                    }
                }
            }
        }
        assert_eq!(id as u32, open, "strangers hold exactly the unreserved share");
        assert!(denied(pending(&mut g, 50_000, "/ip4/192.0.2.99/tcp/1")).kind == Kind::PendingIncomingUnreserved, "and another host is refused");

        // Both validators are admitted past them, each up to its per-address cap.
        for i in 0..MAX_PENDING_INCOMING_PER_ADDR as usize {
            pending(&mut g, 60_000 + i, "/ip4/198.51.100.20/tcp/50000").unwrap_or_else(|e| panic!("validator handshake {i}: {e}"));
        }
        // The fifth: its peer's reserved share (= one host's cap) is used, so it is a stranger's
        // handshake, and the strangers' share is full.
        assert_eq!(denied(pending(&mut g, 60_100, "/ip4/198.51.100.20/tcp/50001")).kind, Kind::PendingIncomingUnreserved, "still bounded");
        pending(&mut g, 61_000, "/ip4/198.51.100.21/tcp/50000").expect("the bootstrap's host too");
        // One stranger's handshake ends: its slot is a stranger's again, not a reserved one.
        listen_failure(&mut g, 0, "/ip4/203.0.0.1/tcp/40001");
        pending(&mut g, 70_000, "/ip4/192.0.2.99/tcp/1").expect("a freed stranger slot");
        assert_eq!(denied(pending(&mut g, 70_001, "/ip4/192.0.2.98/tcp/1")).kind, Kind::PendingIncomingUnreserved);

        // Unreserved: the validator's host is a stranger's again.
        g.unreserve(&validator);
        assert_eq!(denied(pending(&mut g, 80_000, "/ip4/198.51.100.20/tcp/50002")).kind, Kind::PendingIncomingUnreserved);
    }

    /// The node-wide total binds reserved sources too, and an address naming no host is never
    /// trusted however it was learned.
    #[test]
    fn the_pending_total_binds_reserved_sources_and_an_unknown_source_is_never_reserved() {
        let caps = PendingCaps { per_addr: 4, total: 6, reserved: 4 };
        let mut p = PendingBySource::default();
        let v = PeerId::random();
        let host = |n: u8| Source::V4(std::net::Ipv4Addr::new(198, 51, 100, n));
        for i in 0..2 {
            p.admit_with(conn(i), host(1), None, caps).unwrap();
        }
        assert_eq!(p.admit_with(conn(2), host(2), None, caps), Err(Denied { limit: 2, kind: Kind::PendingIncomingUnreserved }));
        for i in 10..14 {
            p.admit_with(conn(i), host(3 + (i as u8 % 2)), Some(v), caps).unwrap();
        }
        assert_eq!(p.admit_with(conn(20), host(5), Some(v), caps), Err(Denied { limit: 6, kind: Kind::PendingIncoming }));
        p.release(conn(10));
        p.admit_with(conn(21), host(5), Some(v), caps).expect("a released slot");
        p.release(conn(0));
        p.admit_with(conn(22), host(2), None, caps).expect("the stranger's share back");
        for i in [1, 11, 12, 13, 21, 22] {
            p.release(conn(i));
        }
        assert!(p.is_empty() && p.unreserved == 0);

        let mut r = ReservedSources::default();
        let peer = PeerId::random();
        let now = std::time::Instant::now();
        r.add(peer, Source::Unknown, SourceKind::Observed, now);
        assert!(!r.contains(&Source::Unknown, now));
        for n in 0..10 {
            r.add(peer, host(n), SourceKind::Observed, now);
        }
        assert_eq!(r.sources_of(&peer).len(), MAX_SOURCES_PER_RESERVED_PEER, "bounded per peer");
        r.remove_peer(&peer);
        assert!(r.by_peer.is_empty());
    }

    /// NET-1 review: one reserved peer cannot take more than its share of the reserved slots,
    /// however many sources it is known at — past [`MAX_RESERVED_PENDING_PER_PEER`] over all of
    /// them its handshakes are a stranger's (refused once strangers hold their share) — while
    /// another validator still gets in.
    #[test]
    fn one_reserved_peer_cannot_take_more_than_its_share_of_the_reserved_slots() {
        use super::super::{MAX_PENDING_INCOMING, RESERVED_PENDING_INCOMING};
        let mut g = guard();
        let greedy = PeerId::random();
        g.reserve(greedy);
        // Known at four hosts (each seen on a connection: the strongest kind).
        for n in 0..4u8 {
            let point = listener_point(&format!("/ip4/198.51.100.{}/tcp/30303", 30 + n));
            connection_established(&mut g, 9_000 + n as usize, greedy, &point, 0);
            connection_closed(&mut g, 9_000 + n as usize, greedy, &point, 0);
        }
        assert_eq!(g.sources.sources_of(&greedy).len(), 4);
        let honest = PeerId::random();
        g.reserve_at(honest, [&addr("/ip4/198.51.100.50/tcp/30303")], SourceKind::Configured);
        // Strangers take their whole share.
        for i in 0..(MAX_PENDING_INCOMING - RESERVED_PENDING_INCOMING) as usize {
            pending(&mut g, i, &format!("/ip4/203.0.{}.{}/tcp/1", i / 4 / 200, (i / 4) % 200 + 1)).unwrap();
        }
        // The greedy peer: four reserved slots in all, then refused, on any of its hosts.
        let mut got = 0;
        for n in 0..4u8 {
            for k in 0..4usize {
                if pending(&mut g, 20_000 + 10 * n as usize + k, &format!("/ip4/198.51.100.{}/tcp/5{k}", 30 + n)).is_ok() {
                    got += 1;
                }
            }
        }
        assert_eq!(got, MAX_RESERVED_PENDING_PER_PEER, "its share, over all its sources together");
        pending(&mut g, 30_000, "/ip4/198.51.100.50/tcp/1").expect("another validator still gets in");
        // A handshake of the greedy peer ends: it may take one again.
        listen_failure(&mut g, 20_000, "/ip4/198.51.100.30/tcp/50");
        pending(&mut g, 30_001, "/ip4/198.51.100.33/tcp/1").expect("a freed share slot");
    }

    /// NET-1 review: an advertised address is the peer's own claim — one is kept per peer, and an
    /// observed source evicts it when the list is full; a configured (bootstrap) source is never
    /// evicted and never expires; advertised and observed sources expire unless seen again.
    #[test]
    fn reserved_sources_prefer_what_was_seen_and_expire() {
        let mut r = ReservedSources::default();
        let peer = PeerId::random();
        let host = |n: u8| Source::V4(std::net::Ipv4Addr::new(198, 51, 100, n));
        let t0 = std::time::Instant::now();
        r.add(peer, host(1), SourceKind::Configured, t0);
        r.add(peer, host(2), SourceKind::Advertised, t0);
        r.add(peer, host(3), SourceKind::Advertised, t0);
        assert_eq!(r.sources_of(&peer), vec![host(1), host(2)], "one advertised address per peer");
        r.add(peer, host(4), SourceKind::Observed, t0);
        r.add(peer, host(5), SourceKind::Observed, t0);
        assert_eq!(r.sources_of(&peer).len(), MAX_SOURCES_PER_RESERVED_PEER);
        r.add(peer, host(6), SourceKind::Observed, t0 + std::time::Duration::from_secs(1));
        let now = r.sources_of(&peer);
        assert!(!now.contains(&host(2)) && now.contains(&host(6)), "the advertised one went first: {now:?}");
        r.add(peer, host(7), SourceKind::Advertised, t0);
        assert!(!r.sources_of(&peer).contains(&host(7)), "an advertised address never evicts a seen one");
        // The oldest observed goes for a newer observation; the configured one never.
        r.add(peer, host(8), SourceKind::Observed, t0 + std::time::Duration::from_secs(2));
        let now = r.sources_of(&peer);
        assert!(now.contains(&host(1)) && now.contains(&host(8)) && now.len() == MAX_SOURCES_PER_RESERVED_PEER, "{now:?}");
        // Expiry: refreshed sources stay, stale ones go, the configured one stays.
        let later = t0 + RESERVED_SOURCE_TTL + std::time::Duration::from_secs(1);
        r.add(peer, host(8), SourceKind::Observed, later);
        r.expire(later);
        assert_eq!(r.sources_of(&peer), vec![host(1), host(8)]);
        // N5: `contains` honours expiry as `peers_at` does.
        assert!(r.contains(&host(8), later) && !r.contains(&host(8), later + RESERVED_SOURCE_TTL));
        assert!(r.contains(&host(1), later + RESERVED_SOURCE_TTL * 10), "configured never expires");
        assert!(r.peers_at(&host(1), later + RESERVED_SOURCE_TTL * 10).contains(&peer), "configured never expires");
        assert!(r.peers_at(&host(8), later + RESERVED_SOURCE_TTL).is_empty(), "expired at lookup too");
    }

    /// NET-1 re-review, N1: a validator's observed source does not lapse while its connection is
    /// held — a link kept past the TTL, then dropped, leaves the source trusted for another TTL
    /// from the drop, so the reconnect takes a reserved slot — and lapses a TTL after the drop.
    /// A peer reserved while already connected has that connection's source in use at once.
    #[test]
    fn a_held_connection_keeps_its_source_and_the_ttl_runs_from_the_drop() {
        use super::super::{MAX_PENDING_INCOMING, RESERVED_PENDING_INCOMING};
        let mut g = guard();
        let validator = PeerId::random();
        g.reserve(validator);
        let host = "/ip4/198.51.100.60/tcp/30303";
        let point = listener_point(host);
        connection_established(&mut g, 1, validator, &point, 0);
        // Strangers take their whole share, so only a reserved slot admits anyone.
        for i in 0..(MAX_PENDING_INCOMING - RESERVED_PENDING_INCOMING) as usize {
            pending(&mut g, 100 + i, &format!("/ip4/203.0.{}.{}/tcp/1", i / 4 / 200, (i / 4) % 200 + 1)).unwrap();
        }
        g.skew = RESERVED_SOURCE_TTL * 3; // held for three days
        pending(&mut g, 10, "/ip4/198.51.100.60/tcp/1").expect("in use: still reserved while connected");
        listen_failure(&mut g, 10, "/ip4/198.51.100.60/tcp/1");
        connection_closed(&mut g, 1, validator, &point, 0);
        g.skew = RESERVED_SOURCE_TTL * 3 + std::time::Duration::from_secs(3600);
        pending(&mut g, 11, "/ip4/198.51.100.60/tcp/2").expect("an hour after the drop: the reconnect is reserved");
        listen_failure(&mut g, 11, "/ip4/198.51.100.60/tcp/2");
        g.skew = RESERVED_SOURCE_TTL * 4 + std::time::Duration::from_secs(1);
        assert_eq!(denied(pending(&mut g, 12, "/ip4/198.51.100.60/tcp/3")).kind, Kind::PendingIncomingUnreserved, "a TTL after the drop it lapses");

        // Reserved while already connected: the live connection's source is in use.
        let late = PeerId::random();
        let late_point = listener_point("/ip4/198.51.100.61/tcp/30303");
        connection_established(&mut g, 2, late, &late_point, 0);
        g.reserve(late);
        g.skew += RESERVED_SOURCE_TTL * 2;
        pending(&mut g, 13, "/ip4/198.51.100.61/tcp/1").expect("its live connection keeps the source");
    }

    /// NET-1 re-review, N2: a reserved peer's in-flight handshakes count against its share by
    /// peer, so evicting the source they came from (here: four fresh observed sources) does not
    /// free the share while they are still pending.
    #[test]
    fn evicting_a_source_does_not_free_the_reserved_share_its_handshakes_hold() {
        use super::super::{MAX_PENDING_INCOMING, RESERVED_PENDING_INCOMING};
        let mut g = guard();
        let v = PeerId::random();
        g.reserve(v);
        let seen = |g: &mut Guard, id: usize, host: &str| {
            let point = listener_point(host);
            connection_established(g, id, v, &point, 0);
            connection_closed(g, id, v, &point, 0);
        };
        seen(&mut g, 1, "/ip4/198.51.100.70/tcp/1");
        for i in 0..(MAX_PENDING_INCOMING - RESERVED_PENDING_INCOMING) as usize {
            pending(&mut g, 100 + i, &format!("/ip4/203.0.{}.{}/tcp/1", i / 4 / 200, (i / 4) % 200 + 1)).unwrap();
        }
        for k in 0..MAX_RESERVED_PENDING_PER_PEER as usize {
            pending(&mut g, 10 + k, &format!("/ip4/198.51.100.70/tcp/{}", 10 + k)).unwrap();
        }
        // Four fresh sources evict the first one from the peer's list; its four handshakes pend on.
        for (n, id) in (71..75u8).zip(2usize..) {
            g.skew += std::time::Duration::from_secs(1);
            seen(&mut g, id, &format!("/ip4/198.51.100.{n}/tcp/1"));
        }
        assert!(!g.sources.sources_of(&v).contains(&source_of(&addr("/ip4/198.51.100.70/tcp/1"))), "evicted");
        assert_eq!(g.pending.reserved_for(&v), MAX_RESERVED_PENDING_PER_PEER);
        assert_eq!(denied(pending(&mut g, 50, "/ip4/198.51.100.71/tcp/9")).kind, Kind::PendingIncomingUnreserved, "the share is still held");
        listen_failure(&mut g, 10, "/ip4/198.51.100.70/tcp/10");
        pending(&mut g, 51, "/ip4/198.51.100.71/tcp/9").expect("one of them finished: one slot back");
    }

    /// NET-1 re-review, N3: a peer this node dialed (or accepted) before it was reserved has the
    /// sources of those connections as observed once reserved — they were seen, not claimed — so
    /// they are not crowded out by its single advertised address; stale ones are not carried.
    #[test]
    fn a_peer_reserved_after_a_dial_has_the_dialed_source_as_observed() {
        let mut g = guard();
        let v = PeerId::random();
        let dialed = ConnectedPoint::Dialer { address: addr("/ip4/198.51.100.80/tcp/30303"), role_override: Endpoint::Dialer, port_use: PortUse::Reuse };
        connection_established(&mut g, 1, v, &dialed, 0);
        connection_closed(&mut g, 1, v, &dialed, 0);
        let old = ConnectedPoint::Dialer { address: addr("/ip4/198.51.100.81/tcp/30303"), role_override: Endpoint::Dialer, port_use: PortUse::Reuse };
        g.skew = std::time::Duration::ZERO;
        connection_established(&mut g, 2, v, &old, 0);
        connection_closed(&mut g, 2, v, &old, 0);
        g.reserve_at(v, [&addr("/ip4/198.51.100.82/tcp/30303"), &addr("/ip4/198.51.100.83/tcp/30303")], SourceKind::Advertised);
        let s = g.sources.sources_of(&v);
        assert!(s.contains(&source_of(&addr("/ip4/198.51.100.80/tcp/1"))) && s.contains(&source_of(&addr("/ip4/198.51.100.81/tcp/1"))), "both dialed sources, observed: {s:?}");
        assert_eq!(s.len(), 3, "and one advertised address: {s:?}");
        pending(&mut g, 10, "/ip4/198.51.100.80/tcp/5").unwrap();
        assert_eq!(g.pending.reserved_for(&v), 1, "the dialed host takes a reserved slot");
        // A peer seen more than a TTL before it was reserved carries nothing.
        let w = PeerId::random();
        let p = ConnectedPoint::Dialer { address: addr("/ip4/198.51.100.90/tcp/1"), role_override: Endpoint::Dialer, port_use: PortUse::Reuse };
        connection_established(&mut g, 3, w, &p, 0);
        connection_closed(&mut g, 3, w, &p, 0);
        g.skew += RESERVED_SOURCE_TTL * 2;
        g.reserve(w);
        assert!(g.sources.sources_of(&w).is_empty());
    }

    /// The guard's handler is the dummy that does nothing, and it never asks the swarm for
    /// anything: its `poll` is always `Pending`.
    #[test]
    fn the_guard_never_emits_to_the_swarm() {
        let mut g = guard();
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert!(matches!(g.poll(&mut cx), Poll::Pending));
        let peer = PeerId::random();
        established_outbound(&mut g, 0, peer).unwrap();
        connection_established(&mut g, 0, peer, &listener_point("/ip4/203.0.113.7/tcp/1"), 0);
        assert!(matches!(g.poll(&mut cx), Poll::Pending));
    }

    /// Every `Denied` displays its limit and the thing it limits, so a log line about a refused
    /// connection says which cap and at what number.
    #[test]
    fn a_denial_names_its_limit_and_kind() {
        let cases = [
            (Kind::PendingIncomingPerAddr, 4, "at most 4 pending incoming connections from one source address"),
            (Kind::PendingIncoming, 96, "at most 96 pending incoming connections are allowed"),
            (Kind::PendingIncomingUnreserved, 64, "at most 64 pending incoming connections from sources that are no reserved peer's"),
            (Kind::EstablishedPerPeer, 2, "at most 2 established connections per peer"),
            (Kind::EstablishedPerReservedPeer, 4, "at most 4 established connections per reserved peer"),
        ];
        for (kind, limit, text) in cases {
            let d = Denied { limit, kind };
            assert!(d.to_string().contains(text), "{d}");
            // Through libp2p's wrapper and back: the cause survives the trip, and is not confused
            // with another error type.
            let wrapped = ConnectionDenied::new(d);
            assert!(wrapped.downcast_ref::<std::io::Error>().is_none());
            assert_eq!(wrapped.downcast::<Denied>().unwrap(), d);
        }
    }
}
