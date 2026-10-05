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
        let mut g = Guard::new(GuardLimits { max_pending_incoming_per_addr: 0, max_established_per_peer: PER_PEER, max_established_per_reserved_peer: 4 });
        assert_eq!(denied(pending(&mut g, 0, "/ip4/203.0.113.7/tcp/1")), Denied { limit: 0, kind: Kind::PendingIncomingPerAddr });
        assert!(g.pending.is_empty());
        assert!(g.pending.count.is_empty(), "a refused-only source leaves no counter behind");
        let mut p = PendingBySource::default();
        assert!(!p.admit(conn(1), Source::Unknown, 0));
        assert!(p.count.is_empty());
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
