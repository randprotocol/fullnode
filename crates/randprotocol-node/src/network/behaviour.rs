use super::codec::Codec;
use super::wire::{StemRequest, StemResponse, SyncRequest, SyncResponse};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{connection_limits, gossipsub, identify, kad, mdns, ping, request_response};
use std::convert::Infallible;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "RandEvent")]
pub struct RandBehaviour {
    /// First, so its verdict is the first thing an inbound connection meets: over the caps in
    /// [`super::WireLimits`] the handshake is refused before any other behaviour holds state for
    /// the peer (deep scan 2026-09-24 — without it a swarm accepted every fresh identity thrown at
    /// it). It emits nothing.
    pub limits: connection_limits::Behaviour,
    /// Second, for the same reason: the per-source pending cap and the per-peer cap that holds
    /// reserved peers too (audit v6, NET-1; [`super::edge`]). It emits nothing either.
    pub guard: super::edge::Guard,
    /// Consensus, status, peer bindings and — while [`super::EdgeConfig::anonymous_tx_only`] is
    /// off — the legacy transaction topic: `MessageAuthenticity::Signed`, on gossipsub's own
    /// `/meshsub` protocol.
    pub gossipsub: gossipsub::Behaviour,
    /// Transactions only (issue #146): `MessageAuthenticity::Anonymous` under
    /// `ValidationMode::Anonymous`, so a transaction carries no author, signature or sequence
    /// number, and one that does is refused. `MessageAuthenticity` is per behaviour, hence a
    /// second one, on a protocol of its own (`/rand/{chain}/txsub`) so the two never compete for
    /// one stream. Its events arrive as `RandEvent::Gossipsub` like the first's; the topic tells
    /// them apart, because each behaviour subscribes only its own.
    pub tx_gossip: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    /// Our own CBOR codec, not `request_response::cbor::Behaviour`: that one's size limits are
    /// private constants and it truncates rather than rejects (see [`super::codec`]).
    pub sync: request_response::Behaviour<Codec<SyncRequest, SyncResponse>>,
    /// Dandelion++'s stem (issue #145): `/rand/{chain}/stem/1`, one transaction to one peer.
    /// Absent under `--dandelion off`, so such a node advertises no stem protocol through identify
    /// and no peer ever stems to it.
    pub stem: Toggle<request_response::Behaviour<Codec<StemRequest, StemResponse>>>,
    /// Keeps connections from idling out and surfaces dead links quickly.
    pub ping: ping::Behaviour,
}

#[allow(clippy::large_enum_variant)] // moved once, never stored in bulk: boxing buys nothing
#[derive(Debug)]
pub enum RandEvent {
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Kademlia(kad::Event),
    Mdns(mdns::Event),
    Sync(request_response::Event<SyncRequest, SyncResponse>),
    Stem(request_response::Event<StemRequest, StemResponse>),
    Ping(ping::Event),
}

/// `connection_limits::Behaviour`'s `ToSwarm` is uninhabited, and so is the guard's: this arm
/// exists for the derive and can never run.
impl From<Infallible> for RandEvent {
    fn from(e: Infallible) -> Self {
        match e {}
    }
}
impl From<gossipsub::Event> for RandEvent {
    fn from(e: gossipsub::Event) -> Self {
        RandEvent::Gossipsub(e)
    }
}
impl From<identify::Event> for RandEvent {
    fn from(e: identify::Event) -> Self {
        RandEvent::Identify(e)
    }
}
impl From<kad::Event> for RandEvent {
    fn from(e: kad::Event) -> Self {
        RandEvent::Kademlia(e)
    }
}
impl From<mdns::Event> for RandEvent {
    fn from(e: mdns::Event) -> Self {
        RandEvent::Mdns(e)
    }
}
impl From<request_response::Event<SyncRequest, SyncResponse>> for RandEvent {
    fn from(e: request_response::Event<SyncRequest, SyncResponse>) -> Self {
        RandEvent::Sync(e)
    }
}

impl From<request_response::Event<StemRequest, StemResponse>> for RandEvent {
    fn from(e: request_response::Event<StemRequest, StemResponse>) -> Self {
        RandEvent::Stem(e)
    }
}

impl From<ping::Event> for RandEvent {
    fn from(e: ping::Event) -> Self {
        RandEvent::Ping(e)
    }
}
