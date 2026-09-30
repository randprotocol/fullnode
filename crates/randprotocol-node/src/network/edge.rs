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

/// The inbound connections still in their handshake, by where they come from.
#[derive(Default)]
pub struct PendingBySource {
    by_conn: HashMap<ConnectionId, Source>,
    count: HashMap<Source, u32>,
}

impl PendingBySource {
    /// Count `id` against `source`, or refuse it: `false` when `source` already holds `max`.
    /// A refused connection is not recorded, so it needs no release.
    pub fn admit(&mut self, id: ConnectionId, source: Source, max: u32) -> bool {
        let n = self.count.entry(source).or_insert(0);
        if *n >= max {
            if *n == 0 {
                self.count.remove(&source);
            }
            return false;
        }
        *n += 1;
        self.by_conn.insert(id, source);
        true
    }

    /// The handshake of `id` ended — established, failed or refused by another behaviour. A no-op
    /// for a connection never admitted here, and for a second release of one that was.
    pub fn release(&mut self, id: ConnectionId) {
        let Some(source) = self.by_conn.remove(&id) else { return };
        if let Some(n) = self.count.get_mut(&source) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                // No entry outlives its last connection: the map is bounded by the pending
                // connections themselves, which libp2p's node-wide pending cap bounds.
                self.count.remove(&source);
            }
        }
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
    EstablishedPerPeer,
    EstablishedPerReservedPeer,
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            Kind::PendingIncomingPerAddr => "pending incoming connections from one source address",
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
}

impl Guard {
    pub fn new(limits: GuardLimits) -> Guard {
        Guard { limits, pending: PendingBySource::default(), established: EstablishedByPeer::default() }
    }

    pub fn reserve(&mut self, peer: PeerId) {
        self.established.reserve(peer);
    }

    pub fn unreserve(&mut self, peer: &PeerId) {
        self.established.unreserve(peer);
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
        let limit = self.limits.max_pending_incoming_per_addr;
        if !self.pending.admit(connection_id, source_of(remote_addr), limit) {
            return Err(ConnectionDenied::new(Denied { limit, kind: Kind::PendingIncomingPerAddr }));
        }
        Ok(())
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
            FromSwarm::ConnectionEstablished(ConnectionEstablished { peer_id, connection_id, .. }) => {
                self.pending.release(connection_id);
                self.established.opened(peer_id, connection_id);
            }
            FromSwarm::ConnectionClosed(ConnectionClosed { peer_id, connection_id, .. }) => {
                self.established.closed(&peer_id, connection_id);
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
}
