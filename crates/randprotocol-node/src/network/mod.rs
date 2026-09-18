//! P2P networking: libp2p swarm with gossipsub (consensus, transactions,
//! status), Kademlia + bootstrap list (WAN discovery), mDNS (LAN discovery),
//! identify, and a request-response protocol for block sync.
//!
//! The swarm runs on its own tokio task. The node talks to it through
//! `NetworkHandle` (commands in) and an `mpsc::Receiver<NetworkEvent>` (events out).

mod behaviour;
pub mod codec;
pub mod wire;

pub use wire::{GossipMessage, Status, SyncRequest, SyncResponse};

/// Re-exported so the node can name a verdict without depending on libp2p directly. It derives
/// `Debug` and nothing else — see `admission::Acceptance` for the comparable copy the decision path
/// uses, which converts into this at the `NetworkHandle` boundary.
pub use libp2p::gossipsub::MessageAcceptance;

use behaviour::{RandBehaviour, RandEvent};
use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId, ValidationMode};
use libp2p::request_response::{self, OutboundRequestId, ProtocolSupport, ResponseChannel};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, identity, kad, mdns, noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// How long the request-response protocol waits for a sync response before reporting `SyncFailed`.
///
/// The node's own give-up (`node::SYNC_GIVE_UP`) is this same constant. A client deadline *shorter*
/// than the wire's abandons a request id that is still perfectly alive, re-requests the same range
/// under a new id, and then throws the answer to the old one away when it lands — which is the
/// other half of why chain-8 catch-up advanced one batch per 30-40 s.
pub const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// What a sync batch is allowed to weigh on the wire on a **default** chain (4 MiB blocks),
/// measured with the codec's own serializer. A running node uses its chain's own figure,
/// [`WireLimits::sync_max_wire_bytes`] — `max_block_bytes + 2 MiB` (call limits spec §8) — of
/// which this is the value at `gas::MAX_BLOCK_BYTES`.
///
/// The server fills a batch up to this and stops; one block is always included even if it alone is
/// larger, so a fat block is never unservable. A single block cannot exceed `max_block_bytes`
/// of transactions plus its two QCs and receipts, so one always fits inside this budget.
///
/// The number matters because a chain-8 block is 140 KB when *empty* — two 18-validator Dilithium2
/// QCs, the `justify` one in its header and the one that certifies it, each 18 votes of a
/// 1312-byte public key plus a 2420-byte signature — and a constraint-set-5 transfer proof is
/// another 1.3 MB. Measured, 100 empty chain-8 blocks:
///
/// | | 100 empty blocks |
/// |---|---|
/// | `block.encode()` only — what the retired 8 MiB budget counted | 6.88 MiB |
/// | whole `CommittedBlock`, bincode | 13.38 MiB |
/// | whole `CommittedBlock`, CBOR — the wire | **13.57 MiB** |
///
/// So the old budget let a batch go out at 13.57 MiB believing it was under 8 MiB, and libp2p's
/// codec cut it at 10 MiB. At a bare 13-vote quorum the same batch measures 9.91 MiB and *just*
/// fit, which is why catch-up sync advanced in fits and starts instead of not at all — and why a
/// node behind a block carrying a 1.3 MB proof could not get past it at any batch size it tried.
pub const SYNC_MAX_WIRE_BYTES: u64 = sync_budget_for(randprotocol_core::gas::MAX_BLOCK_BYTES);

/// The reader limit our codec enforces on a sync response, on a default chain; a running node
/// uses [`WireLimits::sync_response_wire_limit`], the same formula over its own budget.
///
/// Twice the server's batch budget plus framing headroom, so the budget sits at half of it — the
/// invariant [`codec`] exists to keep honest. Going over this is an *error* naming the limit, not
/// the silent truncation libp2p's hard-coded 10 MiB produced, which resurfaced on the reader as
/// `Eof { name: "bytes", .. }` and named nothing.
pub const SYNC_RESPONSE_WIRE_LIMIT: u64 = response_limit_for(SYNC_MAX_WIRE_BYTES);

/// The reader limit on a sync *request*. A request is a height and a count, or a block hash.
pub const SYNC_REQUEST_WIRE_LIMIT: u64 = 64 << 10;

/// gossipsub's own transmit-size ceiling on a default chain: the largest message (a gossiped
/// transaction or proposal, wrapped in [`GossipMessage`]) any peer will forward rather than drop.
/// A running node configures its swarm (`start`, below) with
/// [`WireLimits::gossip_max_transmit_size`], `max(16 MiB, max_block_bytes + 1 MiB)`, which is this
/// at the default block cap. Named so a byte-budget test — e.g.
/// `rpc::tests::a_deploy_at_the_zkvm_program_limit_fits_every_byte_cap` — can check the same number
/// instead of a copy of the literal that could drift from it.
pub const GOSSIP_MAX_TRANSMIT_SIZE: usize = gossip_transmit_for(randprotocol_core::gas::MAX_BLOCK_BYTES);

/// The sync budget for a chain whose blocks carry up to `max_block_bytes` of transactions: the
/// block plus 2 MiB for its two QCs, receipts and the CBOR framing.
const fn sync_budget_for(max_block_bytes: usize) -> u64 {
    max_block_bytes as u64 + (2 << 20)
}

/// The reader limit over a sync budget: twice it plus framing headroom, so the budget is half.
const fn response_limit_for(budget: u64) -> u64 {
    2 * budget + (256 << 10)
}

/// gossip's transmit size for a chain's block cap: never below today's 16 MiB, and always a whole
/// block plus 1 MiB, so a proposal carrying a full block is never dropped.
const fn gossip_transmit_for(max_block_bytes: usize) -> usize {
    let block = max_block_bytes + (1 << 20);
    if block > (16 << 20) {
        block
    } else {
        16 << 20
    }
}

/// The node's local wire limits, computed once at startup from the chain's genesis
/// `max_block_bytes` (call limits spec §8) and carried in [`NetworkConfig`] rather than read off
/// constants, so a chain cut with bigger blocks can gossip and sync them. Local to this node: none
/// of them is a consensus rule, and every node on one chain computes the same numbers from the same
/// genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireLimits {
    /// The byte budget a served sync batch fills to: `max_block_bytes + 2 MiB`.
    pub sync_max_wire_bytes: u64,
    /// The codec's reader limit on a sync response: `2 × sync_max_wire_bytes + 256 KiB`.
    pub sync_response_wire_limit: u64,
    /// gossipsub's `max_transmit_size`: `max(16 MiB, max_block_bytes + 1 MiB)`.
    pub gossip_max_transmit_size: usize,
}

impl WireLimits {
    pub const fn for_block_bytes(max_block_bytes: usize) -> WireLimits {
        let budget = sync_budget_for(max_block_bytes);
        WireLimits {
            sync_max_wire_bytes: budget,
            sync_response_wire_limit: response_limit_for(budget),
            gossip_max_transmit_size: gossip_transmit_for(max_block_bytes),
        }
    }

    /// The limits for the chain `ledger` is the genesis ledger of.
    pub fn for_ledger(ledger: &randprotocol_core::Ledger) -> WireLimits {
        WireLimits::for_block_bytes(ledger.max_block_bytes())
    }
}

/// A default chain's limits: exactly the named constants above.
impl Default for WireLimits {
    fn default() -> WireLimits {
        WireLimits::for_block_bytes(randprotocol_core::gas::MAX_BLOCK_BYTES)
    }
}

/// How reachable an address a peer advertised for itself actually is, from our side of the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrScope {
    /// `127.0.0.0/8` or `::1` — only ever reachable on the peer's own machine.
    Loopback,
    /// RFC1918 / RFC4193 / link-local — reachable only from the peer's own network.
    Private,
    /// Globally routable, or a name we cannot classify without resolving it.
    Global,
}

/// Classify a multiaddr by the reachability of its IP component.
///
/// An address with no IP component (a `/dns4/...` name) counts as [`AddrScope::Global`]: we cannot
/// tell without resolving it, and a name is not the failure mode this exists for.
pub fn addr_scope(addr: &Multiaddr) -> AddrScope {
    for p in addr.iter() {
        match p {
            libp2p::multiaddr::Protocol::Ip4(ip) => {
                return if ip.is_loopback() {
                    AddrScope::Loopback
                } else if ip.is_private() || ip.is_link_local() || ip.is_unspecified() {
                    AddrScope::Private
                } else {
                    AddrScope::Global
                };
            }
            libp2p::multiaddr::Protocol::Ip6(ip) => {
                let seg = ip.segments()[0];
                return if ip.is_loopback() {
                    AddrScope::Loopback
                } else if ip.is_unspecified() || seg & 0xffc0 == 0xfe80 || seg & 0xfe00 == 0xfc00 {
                    AddrScope::Private
                } else {
                    AddrScope::Global
                };
            }
            _ => {}
        }
    }
    AddrScope::Global
}

/// Whether an address a peer advertised through identify belongs in the dial table.
///
/// Every node advertises *all* of its listen addresses, and a node listening on
/// `/ip4/0.0.0.0/tcp/30303` advertises the loopback one among them. Dialing that reaches our own
/// machine, not the peer. On chain 8 it produced
/// `Failed to negotiate transport protocol(s): [(/ip4/127.0.0.1/tcp/30303/...` and, because the
/// loopback entry is tried as part of the same dial, it failed the dial and with it the sync
/// request that needed the connection — one lost batch per attempt, against a chain growing at a
/// block a second.
///
/// Loopback is therefore never dialable. A private address is dialable only for a peer we found on
/// our own link over mDNS (`peer_on_lan`) — which is how the two laptop nodes reach each other —
/// and never for a peer we learned about over the WAN, where `10.x` is the droplets' private
/// network and unreachable from here.
pub fn is_dialable_advertised_addr(addr: &Multiaddr, peer_on_lan: bool) -> bool {
    match addr_scope(addr) {
        AddrScope::Loopback => false,
        AddrScope::Private => peer_on_lan,
        AddrScope::Global => true,
    }
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub chain_id: u64,
    pub listen: Vec<Multiaddr>,
    pub bootstrap: Vec<Multiaddr>,
    pub enable_mdns: bool,
    /// The sync and gossip byte limits, from the genesis block cap ([`WireLimits::for_ledger`]).
    pub limits: WireLimits,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub addrs: Vec<String>,
    pub connected_secs: u64,
}

/// Everything `report_message_validation_result` needs, carried alongside every gossip event so
/// the node loop can report after it has decided.
///
/// `propagation_source` is the peer that forwarded the message, which is not always
/// `NetworkEvent::Gossip.from` (the author) — and it is also the peer the rate limit meters, for the
/// same reason `node::Peer` distinguishes `connected` from having published a `Status`. The
/// `message_id` is content-addressed (blake3 of the message bytes, see the `message_id_fn` in
/// [`start`]), so two peers forwarding one transaction produce the same id and each delivery is
/// reported against its own `(message_id, propagation_source)` pair.
#[derive(Clone, Debug)]
pub struct GossipId {
    pub message_id: MessageId,
    pub propagation_source: PeerId,
}

#[derive(Debug)]
pub enum NetworkEvent {
    Listening(Multiaddr),
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    /// One delivered gossip message. **Every one of these must be reported exactly once** with
    /// [`NetworkHandle::report_validation`], on every path including the error paths: with
    /// `validate_messages()` on, an unreported message is one this node silently stops forwarding.
    Gossip { from: PeerId, msg: GossipMessage, id: GossipId },
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
    /// The application's verdict on one delivered gossip message (see [`GossipId`]).
    ReportValidation { id: GossipId, acceptance: MessageAcceptance },
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

    /// Tell gossipsub what this node decided about one delivered message. A send, never a wait:
    /// the swarm task does the reporting, so the consensus loop never blocks on it.
    pub async fn report_validation(&self, id: GossipId, acceptance: MessageAcceptance) {
        let _ = self.cmd.send(NetworkCommand::ReportValidation { id, acceptance }).await;
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
            consensus: IdentTopic::new(format!("rand/{chain_id}/consensus")),
            tx: IdentTopic::new(format!("rand/{chain_id}/tx")),
            status: IdentTopic::new(format!("rand/{chain_id}/status")),
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
        .max_transmit_size(cfg.limits.gossip_max_transmit_size)
        .message_id_fn(|m: &gossipsub::Message| MessageId::from(blake3::hash(&m.data).as_bytes().to_vec()))
        // Application-level validation: this node forwards a transaction only after it has
        // verified here, off the consensus loop. Local to this node — the wire is unchanged, so it
        // rolls out onto a mixed fleet by ordinary restart. `ValidationMode` stays `Permissive`
        // above: that one *is* on the wire, and a Strict/Permissive mix across the fleet drops
        // messages. The cost of the switch is that every delivered message must be reported
        // exactly once (see [`GossipId`]) or this node stops forwarding it.
        .validate_messages()
        .build()
        .map_err(|e| anyhow::anyhow!("gossipsub config: {e}"))?;
    let gossipsub = gossipsub::Behaviour::new(MessageAuthenticity::Signed(keypair.clone()), gossipsub_config)
        .map_err(|e| anyhow::anyhow!("gossipsub: {e}"))?;

    let identify = identify::Behaviour::new(identify::Config::new(
        format!("rand/{}/1", cfg.chain_id),
        keypair.public(),
    ));

    let kad_proto = StreamProtocol::try_from_owned(format!("/rand/{}/kad/1", cfg.chain_id))?;
    let kad_config = kad::Config::new(kad_proto);
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, kad::store::MemoryStore::new(local_peer_id), kad_config);
    kademlia.set_mode(Some(kad::Mode::Server));

    let mdns = if cfg.enable_mdns {
        Some(mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?)
    } else {
        None
    };

    // Our codec, not `request_response::cbor::Behaviour`: that one's size limits are private
    // constants and it enforces them by truncation (see `codec`).
    let sync = request_response::Behaviour::with_codec(
        codec::Codec::<SyncRequest, SyncResponse>::new(SYNC_REQUEST_WIRE_LIMIT, cfg.limits.sync_response_wire_limit),
        [(StreamProtocol::try_from_owned(format!("/rand/{}/sync/1", cfg.chain_id))?, ProtocolSupport::Full)],
        request_response::Config::default().with_request_timeout(SYNC_REQUEST_TIMEOUT),
    );

    let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new().with_interval(Duration::from_secs(15)).with_timeout(Duration::from_secs(20)));
    let behaviour = RandBehaviour { gossipsub, identify, kademlia, mdns: Toggle::from(mdns), sync, ping };

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

/// Hand one verdict to gossipsub. The only place that calls
/// `report_message_validation_result`, so the "the message is gone" case is decided once.
///
/// `Ok(false)` means the message is no longer in gossipsub's cache, and it is an ordinary outcome
/// rather than a failure or a missed report: the verdict was still made exactly once, gossipsub
/// simply has nothing left to forward or to penalise. Three ways to reach it, all normal — a
/// verification that outlived the cache window (`history_length` 5 × the 500 ms heartbeat, so
/// 2.5 s), a second report of one id, and a topic this node has left in the meantime, because
/// leaving a topic drops its pending validations. Logged at `debug` for that reason: a node
/// shedding gossip while it catches up would otherwise fill the log with warnings about working
/// normally.
fn report_to_gossipsub(swarm: &mut Swarm<RandBehaviour>, id: &GossipId, acceptance: MessageAcceptance) {
    if !swarm.behaviour_mut().gossipsub.report_message_validation_result(&id.message_id, &id.propagation_source, acceptance)
    {
        tracing::debug!(?id, "validation reported for a message no longer in the cache");
    }
}

fn peer_id_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        libp2p::multiaddr::Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

/// Re-dial previously seen peers that are currently disconnected.
fn redial_known(swarm: &mut Swarm<RandBehaviour>, known: &HashMap<PeerId, Vec<Multiaddr>>, peers: &HashMap<PeerId, ConnectedPeer>) {
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

fn dial_bootstrap(swarm: &mut Swarm<RandBehaviour>, cfg: &NetworkConfig, peers: &HashMap<PeerId, ConnectedPeer>) {
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
    mut swarm: Swarm<RandBehaviour>,
    cfg: NetworkConfig,
    topics: Topics,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    evt_tx: mpsc::Sender<NetworkEvent>,
) {
    let mut peers: HashMap<PeerId, ConnectedPeer> = HashMap::new();
    // Dialable addresses of every peer we have ever connected to, so a dropped
    // link is re-established without waiting for mDNS or Kademlia to rediscover it.
    let mut known: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
    // Peers mDNS found on our own link: for these, and only these, a private advertised address is
    // worth dialing.
    let mut lan_peers: HashSet<PeerId> = HashSet::new();
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
                                        gossipsub::PublishError::NoPeersSubscribedToTopic => {
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
                    NetworkCommand::ReportValidation { id, acceptance } => {
                        report_to_gossipsub(&mut swarm, &id, acceptance);
                    }
                    NetworkCommand::Shutdown => break,
                }
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(event, &mut swarm, &mut peers, &mut known, &mut lan_peers, &evt_tx).await;
            }
        }
    }
    tracing::info!("network task stopped");
}

async fn handle_swarm_event(
    event: SwarmEvent<RandEvent>,
    swarm: &mut Swarm<RandBehaviour>,
    peers: &mut HashMap<PeerId, ConnectedPeer>,
    known: &mut HashMap<PeerId, Vec<Multiaddr>>,
    lan_peers: &mut HashSet<PeerId>,
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
        SwarmEvent::Behaviour(RandEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            message_id,
        })) => {
            match bincode::deserialize::<GossipMessage>(&message.data) {
                Ok(msg) => {
                    // `from` falls back to `propagation_source` for a message that carries no
                    // source, which is the only case where the two coincide by construction. The
                    // rate limit still keys on `propagation_source`.
                    let from = message.source.unwrap_or(propagation_source);
                    let id = GossipId { message_id, propagation_source };
                    let _ = evt_tx.send(NetworkEvent::Gossip { from, msg, id }).await;
                }
                Err(e) => {
                    tracing::debug!(%propagation_source, "undecodable gossip: {e}");
                    // Reported here rather than by the node loop, which never sees this message:
                    // an unreported delivery sits in gossipsub's cache and this node stops
                    // forwarding it for everyone. Reject rather than Ignore — bytes that are not a
                    // `GossipMessage` at all are this peer's fault.
                    let id = GossipId { message_id, propagation_source };
                    report_to_gossipsub(swarm, &id, MessageAcceptance::Reject);
                }
            }
        }
        SwarmEvent::Behaviour(RandEvent::Gossipsub(_)) => {}
        SwarmEvent::Behaviour(RandEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
            // A peer advertises every address it listens on, loopback and LAN included. Only the
            // ones we could actually reach it at go in: Kademlia's addresses are what
            // `request_response` dials when it has no open connection to a peer, so an unreachable
            // entry there does not merely waste a dial, it fails the sync request that needed the
            // connection (`is_dialable_advertised_addr`).
            let on_lan = lan_peers.contains(&peer_id);
            for addr in info.listen_addrs {
                if !is_dialable_advertised_addr(&addr, on_lan) {
                    tracing::trace!(%peer_id, %addr, "ignoring an unreachable advertised address");
                    continue;
                }
                remember_addr(known, peer_id, addr.clone());
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
            }
        }
        SwarmEvent::Behaviour(RandEvent::Ping(libp2p::ping::Event { peer, result: Err(e), .. })) => {
            tracing::debug!(%peer, "ping failed: {e}");
        }
        SwarmEvent::Behaviour(RandEvent::Ping(_)) => {}
        SwarmEvent::Behaviour(RandEvent::Identify(_)) => {}
        SwarmEvent::Behaviour(RandEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. })) => {
            tracing::debug!(%peer, "kademlia routing updated");
        }
        SwarmEvent::Behaviour(RandEvent::Kademlia(_)) => {}
        SwarmEvent::Behaviour(RandEvent::Mdns(mdns::Event::Discovered(list))) => {
            for (peer_id, addr) in list {
                tracing::info!(%peer_id, %addr, "mdns discovered peer");
                // mDNS only answers from our own link, so this peer's private addresses are
                // reachable and identify may keep advertising them to us.
                lan_peers.insert(peer_id);
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                if !peers.contains_key(&peer_id) {
                    if let Err(e) = swarm.dial(addr) {
                        tracing::debug!("mdns dial: {e}");
                    }
                }
            }
        }
        SwarmEvent::Behaviour(RandEvent::Mdns(mdns::Event::Expired(_))) => {}
        SwarmEvent::Behaviour(RandEvent::Sync(ev)) => match ev {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request { request, channel, .. } => {
                    let _ = evt_tx.send(NetworkEvent::SyncRequest { peer, request, channel }).await;
                }
                request_response::Message::Response { request_id, response } => {
                    let _ = evt_tx.send(NetworkEvent::SyncResponse { peer, request_id, response }).await;
                }
            },
            request_response::Event::OutboundFailure { peer, request_id, error, .. } => {
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
    use randprotocol_core::Hash;

    // ------------------------------------------- local limits from the genesis block cap
    //
    // Call limits spec §8: the sync budget, the reader limit it sits under and gossip's transmit
    // size are computed at startup from the chain's `max_block_bytes`, not read off constants.

    /// A default chain (4 MiB blocks) keeps today's numbers exactly — 6 MiB, 12.25 MiB, 16 MiB —
    /// and a 20 MiB chain gets `block + 2 MiB`, the same reader formula over it, and
    /// `max(16 MiB, block + 1 MiB)`.
    #[test]
    fn the_wire_limits_follow_the_ledgers_block_cap() {
        let d = WireLimits::default();
        assert_eq!(d, WireLimits::for_block_bytes(randprotocol_core::gas::MAX_BLOCK_BYTES));
        assert_eq!(d.sync_max_wire_bytes, 6 << 20);
        assert_eq!(d.sync_response_wire_limit, 2 * (6 << 20) + (256 << 10));
        assert_eq!(d.gossip_max_transmit_size, 16 << 20);
        // The named constants are the default chain's values, not a second source of truth.
        assert_eq!(d.sync_max_wire_bytes, SYNC_MAX_WIRE_BYTES);
        assert_eq!(d.sync_response_wire_limit, SYNC_RESPONSE_WIRE_LIMIT);
        assert_eq!(d.gossip_max_transmit_size, GOSSIP_MAX_TRANSMIT_SIZE);

        let mut ledger = crate::storage::fixtures::genesis(1).ledger;
        ledger.set_max_block_bytes(20 << 20);
        let raised = WireLimits::for_ledger(&ledger);
        assert_eq!(raised, WireLimits::for_block_bytes(20 << 20));
        assert_eq!(raised.sync_max_wire_bytes, 22 << 20);
        assert_eq!(raised.sync_response_wire_limit, 2 * (22 << 20) + (256 << 10));
        assert_eq!(raised.gossip_max_transmit_size, 21 << 20);
        assert!(2 * raised.sync_max_wire_bytes <= raised.sync_response_wire_limit);

        // Gossip never drops below today's 16 MiB: an 8 MiB chain keeps it.
        assert_eq!(WireLimits::for_block_bytes(8 << 20).gossip_max_transmit_size, 16 << 20);
        assert_eq!(WireLimits::for_block_bytes(15 << 20).gossip_max_transmit_size, 16 << 20);
        assert_eq!(WireLimits::for_block_bytes(64 << 20).gossip_max_transmit_size, 65 << 20);
    }

    // ------------------------------------------- advertised-address filtering
    //
    // Chain 8's other catch-up defect: every node listens on `/ip4/0.0.0.0/tcp/30303` and so
    // advertises `/ip4/127.0.0.1/tcp/30303` through identify beside its public address. That entry
    // went into Kademlia, `request_response` used it when it needed a connection to send a sync
    // request, and the dial — and the request with it — failed.

    fn addr(s: &str) -> Multiaddr {
        s.parse().expect("a valid multiaddr")
    }

    #[test]
    fn loopback_is_never_a_dialable_advertised_address() {
        for a in ["/ip4/127.0.0.1/tcp/30303", "/ip4/127.0.0.53/tcp/1", "/ip6/::1/tcp/30303"] {
            assert_eq!(addr_scope(&addr(a)), AddrScope::Loopback, "{a}");
            // Not even for a peer on our own link: its loopback is still its own machine.
            assert!(!is_dialable_advertised_addr(&addr(a), true), "{a} dialable on lan");
            assert!(!is_dialable_advertised_addr(&addr(a), false), "{a} dialable off lan");
        }
    }

    #[test]
    fn a_private_advertised_address_is_dialable_only_for_an_mdns_peer() {
        // `10.x` is the droplets' private network, which chain 8's nodes advertise beside their
        // public addresses and which is unreachable from a laptop.
        for a in [
            "/ip4/10.100.0.2/tcp/30303",
            "/ip4/192.168.100.79/tcp/30303",
            "/ip4/172.16.4.1/tcp/1",
            "/ip4/169.254.1.1/tcp/1",
            "/ip6/fe80::1/tcp/1",
            "/ip6/fd00::1/tcp/1",
        ] {
            assert_eq!(addr_scope(&addr(a)), AddrScope::Private, "{a}");
            assert!(!is_dialable_advertised_addr(&addr(a), false), "{a} dialable off lan");
            // The two laptop nodes find each other over mDNS and must keep working.
            assert!(is_dialable_advertised_addr(&addr(a), true), "{a} not dialable on lan");
        }
    }

    #[test]
    fn a_public_advertised_address_is_always_dialable() {
        for a in [
            "/ip4/107.170.49.234/tcp/30303",
            "/ip4/188.166.235.187/tcp/30303",
            "/ip6/2606:4700::1/tcp/1",
            "/dns4/node.example/tcp/30303",
        ] {
            assert_eq!(addr_scope(&addr(a)), AddrScope::Global, "{a}");
            assert!(is_dialable_advertised_addr(&addr(a), false), "{a}");
            assert!(is_dialable_advertised_addr(&addr(a), true), "{a}");
        }
    }

    /// Exactly what nyc2 advertised on chain 8, in the order the dial table would have tried it:
    /// the loopback entry first, then the public address, then two private ones.
    #[test]
    fn filtering_a_chain_8_advertisement_keeps_only_the_public_address() {
        let advertised = [
            "/ip4/127.0.0.1/tcp/30303",
            "/ip4/107.170.49.234/tcp/30303",
            "/ip4/10.13.0.5/tcp/30303",
            "/ip4/10.100.0.2/tcp/30303",
        ];
        let kept: Vec<&str> =
            advertised.iter().copied().filter(|a| is_dialable_advertised_addr(&addr(a), false)).collect();
        assert_eq!(kept, vec!["/ip4/107.170.49.234/tcp/30303"]);
    }

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

    /// Two nodes on loopback with an established connection, A reachable through B's bootstrap
    /// list. Both event streams come back, because a dropped receiver silently discards the events
    /// a test is about to wait for.
    async fn two_connected_nodes(
    ) -> (NetworkHandle, mpsc::Receiver<NetworkEvent>, NetworkHandle, mpsc::Receiver<NetworkEvent>) {
        let cfg_a = NetworkConfig {
            chain_id: 7,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![],
            enable_mdns: false,
            limits: WireLimits::default(),
        };
        let (a, mut a_rx) = start(cfg_a, [3u8; 32]).await.unwrap();
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
            limits: WireLimits::default(),
        };
        let (b, b_rx) = start(cfg_b, [4u8; 32]).await.unwrap();
        let a_saw = wait_for(&mut a_rx, Duration::from_secs(10), |e| match e {
            NetworkEvent::PeerConnected(p) if p == b.local_peer_id => Some(()),
            _ => None,
        })
        .await;
        assert!(a_saw.is_some(), "A never saw B connect");
        (a, a_rx, b, b_rx)
    }

    /// Publish `status` from `b` until `a` receives it, because the gossip mesh takes a heartbeat
    /// or two to form. Returns the author and the id the delivery must be reported against.
    async fn gossip_status_to(
        b: &NetworkHandle,
        a_rx: &mut mpsc::Receiver<NetworkEvent>,
        status: Status,
    ) -> (PeerId, GossipId) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut received = None;
        while received.is_none() && tokio::time::Instant::now() < deadline {
            b.broadcast(GossipMessage::Status(status.clone())).await;
            received = wait_for(a_rx, Duration::from_millis(300), |e| match e {
                NetworkEvent::Gossip { from, msg: GossipMessage::Status(_), id } => Some((from, id)),
                _ => None,
            })
            .await;
        }
        received.expect("A never received B's status")
    }

    /// With application-level validation on, gossipsub holds a message until the application
    /// reports on it. A node that forgets to report stops forwarding — so this asserts the round
    /// trip: B publishes, A receives with an id, A reports Accept, and A can then report again
    /// without the swarm having lost the message.
    #[tokio::test]
    async fn a_gossiped_message_carries_the_id_its_validation_is_reported_with() {
        let (a, mut a_rx, b, _b_rx) = two_connected_nodes().await;
        let (from, id) =
            gossip_status_to(&b, &mut a_rx, Status { height: 9, head_hash: Hash::digest(b"h"), view: 3 }).await;
        assert_eq!(from, b.local_peer_id);
        assert_eq!(id.propagation_source, b.local_peer_id, "one hop, so the forwarder is the author");
        assert!(!id.message_id.0.is_empty());

        let first_id = id.message_id.clone();
        a.report_validation(id.clone(), MessageAcceptance::Accept).await;
        // Reporting the same id again is the "no longer in the cache" path — `Ok(false)` from
        // gossipsub, which must be a no-op and not a panic, because a verdict can also land after
        // the 2.5 s mcache window or after the topic was left. The report is still made once per
        // delivery; this second one is the test that a miss is survivable.
        a.report_validation(id, MessageAcceptance::Ignore).await;

        // The mesh still works afterwards: a second, different message arrives the same way, with
        // its own content-addressed id.
        let (_, next) =
            gossip_status_to(&b, &mut a_rx, Status { height: 11, head_hash: Hash::digest(b"h2"), view: 4 }).await;
        assert_ne!(next.message_id, first_id, "a different message is a different id");
        a.report_validation(next, MessageAcceptance::Accept).await;

        a.shutdown().await;
        b.shutdown().await;
    }

    #[tokio::test]
    async fn two_nodes_connect_gossip_and_sync() {
        let cfg_a = NetworkConfig {
            chain_id: 7,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![],
            enable_mdns: false,
            limits: WireLimits::default(),
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
            limits: WireLimits::default(),
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
                NetworkEvent::Gossip { from, msg: GossipMessage::Status(s), .. } => Some((from, s)),
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
