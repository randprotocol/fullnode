use super::codec::Codec;
use super::wire::{SyncRequest, SyncResponse};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, identify, kad, mdns, ping, request_response};

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ShruggEvent")]
pub struct ShruggBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    /// Our own CBOR codec, not `request_response::cbor::Behaviour`: that one's size limits are
    /// private constants and it truncates rather than rejects (see [`super::codec`]).
    pub sync: request_response::Behaviour<Codec<SyncRequest, SyncResponse>>,
    /// Keeps connections from idling out and surfaces dead links quickly.
    pub ping: ping::Behaviour,
}

#[derive(Debug)]
pub enum ShruggEvent {
    Gossipsub(gossipsub::Event),
    Identify(identify::Event),
    Kademlia(kad::Event),
    Mdns(mdns::Event),
    Sync(request_response::Event<SyncRequest, SyncResponse>),
    Ping(ping::Event),
}

impl From<gossipsub::Event> for ShruggEvent {
    fn from(e: gossipsub::Event) -> Self {
        ShruggEvent::Gossipsub(e)
    }
}
impl From<identify::Event> for ShruggEvent {
    fn from(e: identify::Event) -> Self {
        ShruggEvent::Identify(e)
    }
}
impl From<kad::Event> for ShruggEvent {
    fn from(e: kad::Event) -> Self {
        ShruggEvent::Kademlia(e)
    }
}
impl From<mdns::Event> for ShruggEvent {
    fn from(e: mdns::Event) -> Self {
        ShruggEvent::Mdns(e)
    }
}
impl From<request_response::Event<SyncRequest, SyncResponse>> for ShruggEvent {
    fn from(e: request_response::Event<SyncRequest, SyncResponse>) -> Self {
        ShruggEvent::Sync(e)
    }
}

impl From<ping::Event> for ShruggEvent {
    fn from(e: ping::Event) -> Self {
        ShruggEvent::Ping(e)
    }
}
