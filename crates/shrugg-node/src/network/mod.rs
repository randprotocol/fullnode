//! P2P networking: libp2p swarm with gossipsub (consensus, transactions,
//! status), Kademlia + bootstrap list (WAN discovery), mDNS (LAN discovery),
//! identify, and a request-response protocol for block sync.
//!
//! The swarm runs on its own tokio task. The node talks to it through
//! `NetworkHandle` (commands in) and an `mpsc::Receiver<NetworkEvent>` (events out).

mod behaviour;
pub mod wire;

pub use wire::{GossipMessage, Status, SyncRequest, SyncResponse};

use behaviour::{ShruggBehaviour, ShruggEvent};
use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId, ValidationMode};
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport, ResponseChannel};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, identity, kad, mdns, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub chain_id: u64,
    pub listen: Vec<Multiaddr>,
    pub bootstrap: Vec<Multiaddr>,
    pub enable_mdns: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub addrs: Vec<String>,
    pub connected_secs: u64,
}

#[derive(Debug)]
pub enum NetworkEvent {
    Listening(Multiaddr),
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    Gossip { from: PeerId, msg: GossipMessage },
    SyncRequest { peer: PeerId, request: SyncRequest, channel: ResponseChannel<SyncResponse> },
    SyncResponse { peer: PeerId, request_id: OutboundRequestId, response: SyncResponse },
    SyncFailed { peer: PeerId, request_id: OutboundRequestId, error: String },
}

#[derive(Debug)]
pub enum NetworkCommand {
    Broadcast(GossipMessage),
    SendSyncRequest { peer: PeerId, request: SyncRequest, reply: oneshot::Sender<OutboundRequestId> },
    SendSyncResponse { channel: ResponseChannel<SyncResponse>, response: SyncResponse },
    Dial(Multiaddr),
    Peers(oneshot::Sender<Vec<PeerInfo>>),
    Shutdown,
}

#[derive(Clone)]
pub struct NetworkHandle {
    cmd: mpsc::Sender<NetworkCommand>,
    pub local_peer_id: PeerId,
}

impl NetworkHandle {
    pub async fn broadcast(&self, msg: GossipMessage) {
        let _ = self.cmd.send(NetworkCommand::Broadcast(msg)).await;
    }

    pub async fn send_sync_request(&self, peer: PeerId, request: SyncRequest) -> Option<OutboundRequestId> {
        let (reply, rx) = oneshot::channel();
        self.cmd.send(NetworkCommand::SendSyncRequest { peer, request, reply }).await.ok()?;
        rx.await.ok()
    }

    pub async fn send_sync_response(&self, channel: ResponseChannel<SyncResponse>, response: SyncResponse) {
        let _ = self.cmd.send(NetworkCommand::SendSyncResponse { channel, response }).await;
    }

    pub async fn dial(&self, addr: Multiaddr) {
        let _ = self.cmd.send(NetworkCommand::Dial(addr)).await;
    }

    pub async fn peers(&self) -> Vec<PeerInfo> {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(NetworkCommand::Peers(tx)).await.is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn shutdown(&self) {
        let _ = self.cmd.send(NetworkCommand::Shutdown).await;
    }
}

struct Topics {
    consensus: IdentTopic,
    tx: IdentTopic,
    status: IdentTopic,
}

impl Topics {
    fn new(chain_id: u64) -> Topics {
        Topics {
            consensus: IdentTopic::new(format!("shrugg/{chain_id}/consensus")),
            tx: IdentTopic::new(format!("shrugg/{chain_id}/tx")),
            status: IdentTopic::new(format!("shrugg/{chain_id}/status")),
        }
    }

    fn for_message(&self, msg: &GossipMessage) -> &IdentTopic {
        match msg {
            GossipMessage::Consensus(_) => &self.consensus,
            GossipMessage::Transaction(_) => &self.tx,
            GossipMessage::Status(_) => &self.status,
        }
    }
}

struct ConnectedPeer {
    addrs: Vec<Multiaddr>,
    connected_at: Instant,
}

/// Build the swarm, listen, and spawn the event loop. Returns immediately.
pub async fn start(
    cfg: NetworkConfig,
    identity_seed: [u8; 32],
) -> anyhow::Result<(NetworkHandle, mpsc::Receiver<NetworkEvent>)> {
    let mut seed = identity_seed;
    let keypair = identity::Keypair::ed25519_from_bytes(&mut seed)?;
    let local_peer_id = PeerId::from(keypair.public());

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_millis(500))
        .validation_mode(ValidationMode::Permissive)
        .max_transmit_size(16 * 1024 * 1024)
        .message_id_fn(|m: &gossipsub::Message| MessageId::from(blake3::hash(&m.data).as_bytes().to_vec()))
        .build()
        .map_err(|e| anyhow::anyhow!("gossipsub config: {e}"))?;
    let gossipsub = gossipsub::Behaviour::new(MessageAuthenticity::Signed(keypair.clone()), gossipsub_config)
        .map_err(|e| anyhow::anyhow!("gossipsub: {e}"))?;

    let identify = identify::Behaviour::new(identify::Config::new(
        format!("shrugg/{}/1", cfg.chain_id),
        keypair.public(),
    ));

    let kad_proto = StreamProtocol::try_from_owned(format!("/shrugg/{}/kad/1", cfg.chain_id))?;
    let kad_config = kad::Config::new(kad_proto);
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, kad::store::MemoryStore::new(local_peer_id), kad_config);
    kademlia.set_mode(Some(kad::Mode::Server));

    let mdns = if cfg.enable_mdns {
        Some(mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?)
    } else {
        None
    };

    let sync = request_response::cbor::Behaviour::<SyncRequest, SyncResponse>::new(
        [(StreamProtocol::try_from_owned(format!("/shrugg/{}/sync/1", cfg.chain_id))?, ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    );

    let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new().with_interval(Duration::from_secs(15)).with_timeout(Duration::from_secs(20)));
    let behaviour = ShruggBehaviour { gossipsub, identify, kademlia, mdns: Toggle::from(mdns), sync, ping };

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|_| behaviour)
        .map_err(|e| anyhow::anyhow!("behaviour: {e}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        .build();

    let topics = Topics::new(cfg.chain_id);
    for t in [&topics.consensus, &topics.tx, &topics.status] {
        swarm.behaviour_mut().gossipsub.subscribe(t)?;
    }
    for addr in &cfg.listen {
        swarm.listen_on(addr.clone())?;
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(4096);
    let (evt_tx, evt_rx) = mpsc::channel(4096);
    tokio::spawn(run(swarm, cfg, topics, cmd_rx, evt_tx));
    Ok((NetworkHandle { cmd: cmd_tx, local_peer_id }, evt_rx))
}

fn peer_id_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

/// Re-dial previously seen peers that are currently disconnected.
fn redial_known(swarm: &mut Swarm<ShruggBehaviour>, known: &HashMap<PeerId, Vec<Multiaddr>>, peers: &HashMap<PeerId, ConnectedPeer>) {
    for (id, addrs) in known {
        if peers.contains_key(id) || addrs.is_empty() {
            continue;
        }
        let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(*id).addresses(addrs.clone()).build();
        match swarm.dial(opts) {
            Ok(()) => tracing::debug!(%id, "redialing known peer"),
            Err(e) => tracing::debug!(%id, "redial: {e}"),
        }
    }
}

fn remember_addr(known: &mut HashMap<PeerId, Vec<Multiaddr>>, id: PeerId, addr: Multiaddr) {
    // Drop a trailing /p2p/<id> so the address is a plain transport address.
    let mut a = addr;
    if matches!(a.iter().last(), Some(libp2p::multiaddr::Protocol::P2p(_))) {
        a.pop();
    }
    let list = known.entry(id).or_default();
    if !list.contains(&a) {
        list.push(a);
        if list.len() > 8 {
            list.remove(0);
        }
    }
}

fn dial_bootstrap(swarm: &mut Swarm<ShruggBehaviour>, cfg: &NetworkConfig, peers: &HashMap<PeerId, ConnectedPeer>) {
    for addr in &cfg.bootstrap {
        if let Some(id) = peer_id_of(addr) {
            if peers.contains_key(&id) {
                continue;
            }
            swarm.behaviour_mut().kademlia.add_address(&id, addr.clone());
        }
        match swarm.dial(addr.clone()) {
            Ok(()) => tracing::debug!(%addr, "dialing bootstrap peer"),
            Err(e) => tracing::debug!(%addr, "bootstrap dial: {e}"),
        }
    }
}

async fn run(
    mut swarm: Swarm<ShruggBehaviour>,
    cfg: NetworkConfig,
    topics: Topics,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    evt_tx: mpsc::Sender<NetworkEvent>,
) {
    let mut peers: HashMap<PeerId, ConnectedPeer> = HashMap::new();
    // Dialable addresses of every peer we have ever connected to, so a dropped
    // link is re-established without waiting for mDNS or Kademlia to rediscover it.
    let mut known: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    dial_bootstrap(&mut swarm, &cfg, &peers);
    if !cfg.bootstrap.is_empty() {
        let _ = swarm.behaviour_mut().kademlia.bootstrap();
    }
    let mut redial = tokio::time::interval(Duration::from_secs(30));
    let mut kad_bootstrap = tokio::time::interval(Duration::from_secs(60));
    redial.tick().await;
    kad_bootstrap.tick().await;

    loop {
        tokio::select! {
            _ = redial.tick() => {
                dial_bootstrap(&mut swarm, &cfg, &peers);
                redial_known(&mut swarm, &known, &peers);
            }
            _ = kad_bootstrap.tick() => {
                if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                    tracing::debug!("kademlia bootstrap: {e}");
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    NetworkCommand::Broadcast(msg) => {
                        let topic = topics.for_message(&msg).clone();
                        match bincode::serialize(&msg) {
                            Ok(data) => {
                                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                                    match e {
                                        gossipsub::PublishError::InsufficientPeers => {
                                            tracing::debug!("publish: no peers yet")
                                        }
                                        gossipsub::PublishError::Duplicate => {}
                                        other => tracing::warn!("publish failed: {other}"),
                                    }
                                }
                            }
                            Err(e) => tracing::error!("encode gossip: {e}"),
                        }
                    }
                    NetworkCommand::SendSyncRequest { peer, request, reply } => {
                        let id = swarm.behaviour_mut().sync.send_request(&peer, request);
                        let _ = reply.send(id);
                    }
                    NetworkCommand::SendSyncResponse { channel, response } => {
                        if swarm.behaviour_mut().sync.send_response(channel, response).is_err() {
                            tracing::debug!("sync response dropped: channel closed");
                        }
                    }
                    NetworkCommand::Dial(addr) => {
                        if let Some(id) = peer_id_of(&addr) {
                            swarm.behaviour_mut().kademlia.add_address(&id, addr.clone());
                        }
                        if let Err(e) = swarm.dial(addr.clone()) {
                            tracing::debug!(%addr, "dial: {e}");
                        }
                    }
                    NetworkCommand::Peers(reply) => {
                        let now = Instant::now();
                        let list = peers
                            .iter()
                            .map(|(id, p)| PeerInfo {
                                peer_id: id.to_string(),
                                addrs: p.addrs.iter().map(|a| a.to_string()).collect(),
                                connected_secs: now.duration_since(p.connected_at).as_secs(),
                            })
                            .collect();
                        let _ = reply.send(list);
                    }
                    NetworkCommand::Shutdown => break,
                }
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(event, &mut swarm, &mut peers, &mut known, &evt_tx).await;
            }
        }
    }
    tracing::info!("network task stopped");
}

async fn handle_swarm_event(
    event: SwarmEvent<ShruggEvent>,
    swarm: &mut Swarm<ShruggBehaviour>,
    peers: &mut HashMap<PeerId, ConnectedPeer>,
    known: &mut HashMap<PeerId, Vec<Multiaddr>>,
    evt_tx: &mpsc::Sender<NetworkEvent>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::info!(%address, "listening");
            let _ = evt_tx.send(NetworkEvent::Listening(address)).await;
        }
        SwarmEvent::ConnectionEstablished { peer_id, endpoint, num_established, .. } => {
            let addr = endpoint.get_remote_address().clone();
            if endpoint.is_dialer() {
                remember_addr(known, peer_id, addr.clone());
            }
            let entry = peers.entry(peer_id).or_insert_with(|| ConnectedPeer { addrs: Vec::new(), connected_at: Instant::now() });
            if !entry.addrs.contains(&addr) {
                entry.addrs.push(addr);
            }
            if num_established.get() == 1 {
                tracing::info!(%peer_id, "peer connected");
                let _ = evt_tx.send(NetworkEvent::PeerConnected(peer_id)).await;
            }
        }
        SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
            if num_established == 0 {
                peers.remove(&peer_id);
                tracing::info!(%peer_id, "peer disconnected");
                let _ = evt_tx.send(NetworkEvent::PeerDisconnected(peer_id)).await;
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            tracing::debug!(?peer_id, "outgoing connection error: {error}");
        }
        SwarmEvent::Behaviour(ShruggEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
            match bincode::deserialize::<GossipMessage>(&message.data) {
                Ok(msg) => {
                    let from = message.source.unwrap_or(propagation_source);
                    let _ = evt_tx.send(NetworkEvent::Gossip { from, msg }).await;
                }
                Err(e) => tracing::debug!(%propagation_source, "undecodable gossip: {e}"),
            }
        }
        SwarmEvent::Behaviour(ShruggEvent::Gossipsub(_)) => {}
        SwarmEvent::Behaviour(ShruggEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
            for addr in info.listen_addrs {
                let is_loopback = addr.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::Ip4(ip) if ip.is_loopback()));
                if !is_loopback {
                    remember_addr(known, peer_id, addr.clone());
                }
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
            }
        }
        SwarmEvent::Behaviour(ShruggEvent::Ping(libp2p::ping::Event { peer, result: Err(e), .. })) => {
            tracing::debug!(%peer, "ping failed: {e}");
        }
        SwarmEvent::Behaviour(ShruggEvent::Ping(_)) => {}
        SwarmEvent::Behaviour(ShruggEvent::Identify(_)) => {}
        SwarmEvent::Behaviour(ShruggEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. })) => {
            tracing::debug!(%peer, "kademlia routing updated");
        }
        SwarmEvent::Behaviour(ShruggEvent::Kademlia(_)) => {}
        SwarmEvent::Behaviour(ShruggEvent::Mdns(mdns::Event::Discovered(list))) => {
            for (peer_id, addr) in list {
                tracing::info!(%peer_id, %addr, "mdns discovered peer");
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                if !peers.contains_key(&peer_id) {
                    if let Err(e) = swarm.dial(addr) {
                        tracing::debug!("mdns dial: {e}");
                    }
                }
            }
        }
        SwarmEvent::Behaviour(ShruggEvent::Mdns(mdns::Event::Expired(_))) => {}
        SwarmEvent::Behaviour(ShruggEvent::Sync(ev)) => match ev {
            request_response::Event::Message { peer, message } => match message {
                request_response::Message::Request { request, channel, .. } => {
                    let _ = evt_tx.send(NetworkEvent::SyncRequest { peer, request, channel }).await;
                }
                request_response::Message::Response { request_id, response } => {
                    let _ = evt_tx.send(NetworkEvent::SyncResponse { peer, request_id, response }).await;
                }
            },
            request_response::Event::OutboundFailure { peer, request_id, error } => {
                let _ = evt_tx.send(NetworkEvent::SyncFailed { peer, request_id, error: error.to_string() }).await;
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                tracing::debug!(%peer, "inbound sync failure: {error}");
            }
            request_response::Event::ResponseSent { .. } => {}
        },
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shrugg_core::Hash;

    async fn wait_for<T>(
        rx: &mut mpsc::Receiver<NetworkEvent>,
        timeout: Duration,
        mut f: impl FnMut(NetworkEvent) -> Option<T>,
    ) -> Option<T> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Some(ev)) => {
                    if let Some(v) = f(ev) {
                        return Some(v);
                    }
                }
                _ => return None,
            }
        }
    }

    #[tokio::test]
    async fn two_nodes_connect_gossip_and_sync() {
        let cfg_a = NetworkConfig {
            chain_id: 7,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![],
            enable_mdns: false,
        };
        let (a, mut a_rx) = start(cfg_a, [1u8; 32]).await.unwrap();
        let a_addr = wait_for(&mut a_rx, Duration::from_secs(5), |e| match e {
            NetworkEvent::Listening(addr) => Some(addr),
            _ => None,
        })
        .await
        .expect("A listening");
        let a_full = a_addr.with(libp2p::multiaddr::Protocol::P2p(a.local_peer_id));

        let cfg_b = NetworkConfig {
            chain_id: 7,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![a_full],
            enable_mdns: false,
        };
        let (b, mut b_rx) = start(cfg_b, [2u8; 32]).await.unwrap();

        let a_saw = wait_for(&mut a_rx, Duration::from_secs(10), |e| match e {
            NetworkEvent::PeerConnected(p) if p == b.local_peer_id => Some(()),
            _ => None,
        })
        .await;
        assert!(a_saw.is_some(), "A never saw B connect");
        let b_saw = wait_for(&mut b_rx, Duration::from_secs(10), |e| match e {
            NetworkEvent::PeerConnected(p) if p == a.local_peer_id => Some(()),
            _ => None,
        })
        .await;
        assert!(b_saw.is_some(), "B never saw A connect");
        assert_eq!(a.peers().await.len(), 1);

        // Gossip: B -> A, retried until the mesh forms.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut received = None;
        while received.is_none() && tokio::time::Instant::now() < deadline {
            b.broadcast(GossipMessage::Status(Status { height: 9, head_hash: Hash::digest(b"h"), view: 3 })).await;
            received = wait_for(&mut a_rx, Duration::from_millis(300), |e| match e {
                NetworkEvent::Gossip { from, msg: GossipMessage::Status(s) } => Some((from, s)),
                _ => None,
            })
            .await;
        }
        let (from, status) = received.expect("A never received B's status");
        assert_eq!(from, b.local_peer_id);
        assert_eq!(status.height, 9);
        assert_eq!(status.view, 3);

        // Sync request A -> B, response B -> A.
        let req_id = a
            .send_sync_request(b.local_peer_id, SyncRequest::Blocks { from_height: 0, max: 1 })
            .await
            .expect("request id");
        let channel = wait_for(&mut b_rx, Duration::from_secs(10), |e| match e {
            NetworkEvent::SyncRequest { peer, request: SyncRequest::Blocks { from_height: 0, max: 1 }, channel }
                if peer == a.local_peer_id =>
            {
                Some(channel)
            }
            _ => None,
        })
        .await
        .expect("B never got the sync request");
        b.send_sync_response(channel, SyncResponse::Blocks(vec![])).await;
        let resp = wait_for(&mut a_rx, Duration::from_secs(10), |e| match e {
            NetworkEvent::SyncResponse { peer, request_id, response } if peer == b.local_peer_id && request_id == req_id => {
                Some(response)
            }
            _ => None,
        })
        .await
        .expect("A never got the sync response");
        assert!(matches!(resp, SyncResponse::Blocks(v) if v.is_empty()));

        a.shutdown().await;
        b.shutdown().await;
    }
}
