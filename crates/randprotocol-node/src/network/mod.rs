//! P2P networking: libp2p swarm with gossipsub (consensus, transactions,
//! status), Kademlia + bootstrap list (WAN discovery), mDNS (LAN discovery),
//! identify, and a request-response protocol for block sync.
//!
//! The swarm runs on its own tokio task. The node talks to it through
//! `NetworkHandle` (commands in) and an `mpsc::Receiver<NetworkEvent>` (events out).

mod behaviour;
pub mod codec;
pub mod edge;
pub mod wire;

pub use edge::{MAX_ESTABLISHED_PER_RESERVED_PEER, MAX_PENDING_INCOMING_PER_ADDR};
pub use wire::{GossipMessage, PeerBinding, Status, SyncRequest, SyncResponse};

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

/// How long the request-response protocol waits for a sync response before reporting `SyncFailed`,
/// on a **default** chain. A running node uses [`WireLimits::sync_request_timeout`], which is this
/// floor or one second per MiB of its reader limit, whichever is longer.
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

/// The sync request timeout over a reader limit: one second per MiB the response may weigh
/// (rounded up), never below [`SYNC_REQUEST_TIMEOUT`]. A default chain's 12.25 MiB limit keeps the
/// 30 s floor; a 20 MiB-block chain's 44.25 MiB gets 45 s, so a response that is legitimately
/// larger is not cut off by a deadline sized for a smaller one.
const fn request_timeout_for(response_limit: u64) -> Duration {
    let secs = response_limit.div_ceil(1 << 20);
    if secs > SYNC_REQUEST_TIMEOUT.as_secs() {
        Duration::from_secs(secs)
    } else {
        SYNC_REQUEST_TIMEOUT
    }
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
    /// The request-response timeout on a sync request, and the node's own give-up
    /// (`Node::sync_from` abandons an in-flight request after it): `max(30 s, ⌈sync_response_wire_limit / 1 MiB⌉ s)`.
    pub sync_request_timeout: Duration,
    /// How many established *inbound* connections the swarm carries at once
    /// ([`MAX_ESTABLISHED_INCOMING`]); the next one is refused at the handshake (deep scan
    /// 2026-09-24: without it 200 fresh identities were all accepted). Outbound dials — this node's
    /// own bootstraps and redials — are never counted against it, so a validator is never locked
    /// out of the peers it dials.
    pub max_established_incoming: u32,
    /// Established connections per remote peer, in either direction ([`MAX_ESTABLISHED_PER_PEER`]):
    /// two, because two nodes dialing each other at once legitimately hold one each way.
    pub max_established_per_peer: u32,
    /// Inbound connections still in their handshake at once ([`MAX_PENDING_INCOMING`]).
    pub max_pending_incoming: u32,
    /// Of those, how many one source address may hold ([`MAX_PENDING_INCOMING_PER_ADDR`]; audit
    /// v6, NET-1): without it the 64 above were one host's to fill.
    pub max_pending_incoming_per_addr: u32,
    /// Established connections per *reserved* peer ([`MAX_ESTABLISHED_PER_RESERVED_PEER`]): a
    /// reserved peer bypasses libp2p's caps, the per-peer one included, so the guard holds it to
    /// this instead.
    pub max_established_per_reserved_peer: u32,
}

/// The default inbound connection cap: eighteen validators plus every explorer and observer fit
/// many times over, and a fresh identity is free to mint, so the number is a bound on what one
/// host can be made to hold, not a topology.
pub const MAX_ESTABLISHED_INCOMING: u32 = 256;
/// The default per-peer connection cap (see [`WireLimits::max_established_per_peer`]).
pub const MAX_ESTABLISHED_PER_PEER: u32 = 2;
/// The default cap on inbound connections mid-handshake.
pub const MAX_PENDING_INCOMING: u32 = 64;

/// How long a connection may take to set up, in either direction, before the transport drops it
/// (audit v6, NET-1): the TCP connect of a dial, then the whole upgrade — multistream-select,
/// the Noise handshake and the yamux negotiation — on both dials and accepted connections.
/// libp2p's builder default is ten seconds; an inbound connection that stalls holds one of the
/// [`MAX_PENDING_INCOMING`] slots for all of it, so the time is the other half of the pending
/// cap. Five seconds is still several times an honest handshake across the fleet's longest
/// path (four or five round trips at ~300 ms). It does not bound an established connection —
/// that is the swarm's idle timeout and ping.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

impl WireLimits {
    pub const fn for_block_bytes(max_block_bytes: usize) -> WireLimits {
        let budget = sync_budget_for(max_block_bytes);
        let limit = response_limit_for(budget);
        WireLimits {
            sync_max_wire_bytes: budget,
            sync_response_wire_limit: limit,
            gossip_max_transmit_size: gossip_transmit_for(max_block_bytes),
            sync_request_timeout: request_timeout_for(limit),
            max_established_incoming: MAX_ESTABLISHED_INCOMING,
            max_established_per_peer: MAX_ESTABLISHED_PER_PEER,
            max_pending_incoming: MAX_PENDING_INCOMING,
            max_pending_incoming_per_addr: MAX_PENDING_INCOMING_PER_ADDR,
            max_established_per_reserved_peer: MAX_ESTABLISHED_PER_RESERVED_PEER,
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

/// The per-forwarder byte budget on gossip frames, in whole frames of the chain's
/// [`WireLimits::gossip_max_transmit_size`] (audit v6, GOSSIP-1): a burst of eight and two a
/// second. Charged by a frame's length before it is decoded, so a forwarder over it costs this
/// node neither the decode nor, for a transaction, the hash that follows.
///
/// Sized from CN-4's consensus byte budget (eight views of burst, two a second), which already
/// has to pass an honest forwarder carrying full blocks — plus the transactions those blocks
/// carry, which reach a node over the same forwarder as gossip before the proposal does: at the
/// fleet's ~1.4 s a block and every block full, that is two blocks' bytes a view, about 1.4
/// frames a second. One frame a second would refuse an honest peer at full load; two is the
/// headroom. What the budget bounds is the rest: an attacker's frames cost it a connection's
/// worth of bandwidth for each byte this node decodes, as before, but no longer without a cap.
pub const GOSSIP_FRAME_BURST: u32 = 8;
pub const GOSSIP_FRAMES_PER_SEC: f64 = 2.0;

/// The per-forwarder byte meter on gossip frames (audit v6, GOSSIP-1; [`GOSSIP_FRAME_BURST`]).
/// Its entries are the forwarders of frames — connected peers, bounded by the swarm's caps —
/// and each leaves when its peer's last connection closes.
pub struct FrameMeter {
    limiter: crate::admission::PeerLimiter,
    buckets: HashMap<PeerId, crate::admission::TokenBucket>,
}

impl FrameMeter {
    pub fn new(max_transmit: usize) -> FrameMeter {
        let frame = max_transmit as u64;
        let burst = frame.saturating_mul(GOSSIP_FRAME_BURST as u64).min(u32::MAX as u64) as u32;
        FrameMeter {
            limiter: crate::admission::PeerLimiter::new(burst, frame as f64 * GOSSIP_FRAMES_PER_SEC),
            buckets: HashMap::new(),
        }
    }

    /// Whether to decode a frame of `len` bytes `forwarder` delivered: charged all or nothing,
    /// so a refused frame spends none of the budget.
    pub fn admit(&mut self, forwarder: PeerId, len: usize, now: Instant) -> bool {
        let bucket = self.buckets.entry(forwarder).or_default();
        self.limiter.allow_n(bucket, len as f64, now)
    }

    /// `peer`'s last connection closed.
    pub fn forget(&mut self, peer: &PeerId) {
        self.buckets.remove(peer);
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
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

/// What [`start_with`] is told about the edge beyond [`NetworkConfig`] (audit v6, NET-1). Its
/// own struct, not fields of `NetworkConfig`, so every caller that builds that one literally —
/// the tests of three crates' worth of files — keeps compiling, and [`start`] means "no
/// reserved peers beyond the bootstraps".
#[derive(Clone, Debug, Default)]
pub struct EdgeConfig {
    /// Peers reserved for the life of the process: the operator's `--reserved-peer` list. The
    /// peer ids of [`NetworkConfig::bootstrap`] are reserved the same way without being named
    /// here. [`NetworkHandle::unreserve_peer`] never removes one of these.
    pub reserved: Vec<PeerId>,
    /// Peers reserved from the start that may later stop being: the validators' identities this
    /// node learned over gossip before its last restart (`node`'s persisted peer bindings),
    /// handed over here so they are reserved before the first connection is accepted.
    pub bound: Vec<PeerId>,
    /// gossipsub's `ValidationMode::Strict` instead of `Permissive` (audit v6, CH-7;
    /// `--strict-gossip`): every delivered message must carry a valid author signature, sequence
    /// number and source, so an unsigned message claiming any author is dropped by gossipsub
    /// itself. Off by default. Every node already signs what it publishes
    /// (`MessageAuthenticity::Signed`), and the mode only governs what a node accepts, so a
    /// strict node and a permissive one exchange honest messages both ways (pinned by
    /// `a_strict_node_takes_a_permissive_nodes_signed_gossip_and_drops_a_forged_unsigned_one`).
    pub strict_gossip: bool,
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

#[allow(clippy::large_enum_variant)] // moved once, never stored in bulk: boxing buys nothing
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

#[allow(clippy::large_enum_variant)] // moved once, never stored in bulk: boxing buys nothing
#[derive(Debug)]
pub enum NetworkCommand {
    Broadcast(GossipMessage),
    SendSyncRequest { peer: PeerId, request: SyncRequest, reply: oneshot::Sender<OutboundRequestId> },
    SendSyncResponse { channel: ResponseChannel<SyncResponse>, response: SyncResponse },
    Dial(Multiaddr),
    Peers(oneshot::Sender<Vec<PeerInfo>>),
    /// The application's verdict on one delivered gossip message (see [`GossipId`]).
    ReportValidation { id: GossipId, acceptance: MessageAcceptance },
    /// Reserve a peer (audit v6, NET-1): see [`NetworkHandle::reserve_peer`].
    Reserve(PeerId),
    /// Stop reserving a peer reserved through [`NetworkCommand::Reserve`] or
    /// [`EdgeConfig::bound`]; a bootstrap or `--reserved-peer` identity stays reserved.
    Unreserve(PeerId),
    Shutdown,
}

#[derive(Clone)]
pub struct NetworkHandle {
    cmd: mpsc::Sender<NetworkCommand>,
    pub local_peer_id: PeerId,
}

impl NetworkHandle {
    /// A handle with no swarm behind it, for tests of the node loop's own methods: every command
    /// the node sends arrives on the returned receiver instead.
    #[cfg(test)]
    pub(crate) fn detached_for_test(local_peer_id: PeerId) -> (NetworkHandle, mpsc::Receiver<NetworkCommand>) {
        let (cmd, rx) = mpsc::channel(64);
        (NetworkHandle { cmd, local_peer_id }, rx)
    }

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

    /// Reserve `peer` (audit v6, NET-1): its connections are no longer checked against the
    /// established-inbound cap, so it is admitted however many strangers hold slots; the guard
    /// still holds it to [`WireLimits::max_established_per_reserved_peer`] connections. Takes
    /// effect for connections made from now on; idempotent.
    pub async fn reserve_peer(&self, peer: PeerId) {
        let _ = self.cmd.send(NetworkCommand::Reserve(peer)).await;
    }

    /// Undo [`NetworkHandle::reserve_peer`] for a peer that is no longer a validator's identity.
    /// A no-op for a bootstrap or `--reserved-peer` identity. Connections it already holds stay.
    pub async fn unreserve_peer(&self, peer: PeerId) {
        let _ = self.cmd.send(NetworkCommand::Unreserve(peer)).await;
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
    /// Validators' signed peer bindings (audit v6, NET-1). A topic of its own: a build that
    /// predates it is not subscribed, so it never receives a `GossipMessage` variant it cannot
    /// decode — a mixed fleet sees no change on the three topics it shares.
    peers: IdentTopic,
}

impl Topics {
    fn new(chain_id: u64) -> Topics {
        Topics {
            consensus: IdentTopic::new(format!("rand/{chain_id}/consensus")),
            tx: IdentTopic::new(format!("rand/{chain_id}/tx")),
            status: IdentTopic::new(format!("rand/{chain_id}/status")),
            peers: IdentTopic::new(format!("rand/{chain_id}/peers")),
        }
    }

    fn for_message(&self, msg: &GossipMessage) -> &IdentTopic {
        match msg {
            GossipMessage::Consensus(_) => &self.consensus,
            GossipMessage::Transaction(_) => &self.tx,
            GossipMessage::Status(_) => &self.status,
            GossipMessage::PeerBinding(_) => &self.peers,
        }
    }
}

struct ConnectedPeer {
    addrs: Vec<Multiaddr>,
    connected_at: Instant,
}

/// Build the swarm, listen, and spawn the event loop. Returns immediately. No reserved peers
/// beyond the bootstraps: [`start_with`] under a default [`EdgeConfig`].
pub async fn start(
    cfg: NetworkConfig,
    identity_seed: [u8; 32],
) -> anyhow::Result<(NetworkHandle, mpsc::Receiver<NetworkEvent>)> {
    start_with(cfg, identity_seed, EdgeConfig::default()).await
}

/// [`start`], with the operator's reserved peers and the bindings learned before this start.
pub async fn start_with(
    cfg: NetworkConfig,
    identity_seed: [u8; 32],
    edge: EdgeConfig,
) -> anyhow::Result<(NetworkHandle, mpsc::Receiver<NetworkEvent>)> {
    let mut seed = identity_seed;
    let keypair = identity::Keypair::ed25519_from_bytes(&mut seed)?;
    let local_peer_id = PeerId::from(keypair.public());

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_millis(500))
        .validation_mode(if edge.strict_gossip { ValidationMode::Strict } else { ValidationMode::Permissive })
        .max_transmit_size(cfg.limits.gossip_max_transmit_size)
        .message_id_fn(|m: &gossipsub::Message| MessageId::from(blake3::hash(&m.data).as_bytes().to_vec()))
        // Application-level validation: this node forwards a transaction only after it has
        // verified here, off the consensus loop. Local to this node — the wire is unchanged, so it
        // rolls out onto a mixed fleet by ordinary restart. `ValidationMode` is `Permissive`
        // unless `--strict-gossip` ([`EdgeConfig::strict_gossip`]): it too governs only what this
        // node accepts, and since every node signs what it publishes, a strict node drops nothing
        // an honest permissive one sends (tested, audit v6 CH-7). The cost of the switch is that
        // every delivered message must be reported exactly once (see [`GossipId`]) or this node
        // stops forwarding it.
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
        request_response::Config::default().with_request_timeout(cfg.limits.sync_request_timeout),
    );

    let ping = libp2p::ping::Behaviour::new(libp2p::ping::Config::new().with_interval(Duration::from_secs(15)).with_timeout(Duration::from_secs(20)));
    // Inbound only, plus the per-peer bound: this node's own dials are never refused by its own
    // caps, so a validator always reaches the peers it bootstraps to (`WireLimits`'s field docs).
    let mut limits = libp2p::connection_limits::Behaviour::new(
        libp2p::connection_limits::ConnectionLimits::default()
            .with_max_established_incoming(Some(cfg.limits.max_established_incoming))
            .with_max_established_per_peer(Some(cfg.limits.max_established_per_peer))
            .with_max_pending_incoming(Some(cfg.limits.max_pending_incoming)),
    );
    let mut guard = edge::Guard::new(edge::GuardLimits {
        max_pending_incoming_per_addr: cfg.limits.max_pending_incoming_per_addr,
        max_established_per_peer: cfg.limits.max_established_per_peer,
        max_established_per_reserved_peer: cfg.limits.max_established_per_reserved_peer,
    });
    // Reserved before the swarm exists, so before the first connection is accepted (audit v6,
    // NET-1): the bootstraps and the operator's list for good (`pinned`), the bindings learned
    // before this start until the node says otherwise. libp2p's limiter does not check a
    // bypassed peer against the established caps — it does still count its connections, so a
    // reserved peer's inbound connection takes one of the 256 from the strangers' side, never
    // the other way round.
    let pinned: HashSet<PeerId> = cfg.bootstrap.iter().filter_map(peer_id_of).chain(edge.reserved.iter().copied()).collect();
    for id in pinned.iter().chain(edge.bound.iter()) {
        limits.bypass_peer_id(id);
        guard.reserve(*id);
    }
    let behaviour = RandBehaviour { limits, guard, gossipsub, identify, kademlia, mdns: Toggle::from(mdns), sync, ping };

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(tcp::Config::default().nodelay(true), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|_| behaviour)
        .map_err(|e| anyhow::anyhow!("behaviour: {e}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(120)))
        // Only settable here, after the swarm config (libp2p 0.57's builder: the build phase).
        .with_connection_timeout(HANDSHAKE_TIMEOUT)
        .build();

    let topics = Topics::new(cfg.chain_id);
    for t in [&topics.consensus, &topics.tx, &topics.status, &topics.peers] {
        swarm.behaviour_mut().gossipsub.subscribe(t)?;
    }
    for addr in &cfg.listen {
        swarm.listen_on(addr.clone())?;
    }

    let (cmd_tx, cmd_rx) = mpsc::channel(4096);
    let (evt_tx, evt_rx) = mpsc::channel(4096);
    tokio::spawn(run(swarm, cfg, pinned, topics, cmd_rx, evt_tx));
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
    // Reserved for the life of the process: no `Unreserve` removes one (see [`EdgeConfig`]).
    pinned: HashSet<PeerId>,
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
    // What each forwarder may deliver before its frames are decoded (GOSSIP-1).
    let mut frames = FrameMeter::new(cfg.limits.gossip_max_transmit_size);
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
                    NetworkCommand::Reserve(id) => {
                        let b = swarm.behaviour_mut();
                        b.limits.bypass_peer_id(&id);
                        b.guard.reserve(id);
                    }
                    NetworkCommand::Unreserve(id) => {
                        if !pinned.contains(&id) {
                            let b = swarm.behaviour_mut();
                            b.limits.remove_peer_id(&id);
                            b.guard.unreserve(&id);
                        }
                    }
                    NetworkCommand::Shutdown => break,
                }
            }
            event = swarm.select_next_some() => {
                handle_swarm_event(event, &mut swarm, &mut peers, &mut known, &mut lan_peers, &mut frames, &evt_tx).await;
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
    frames: &mut FrameMeter,
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
                frames.forget(&peer_id);
                tracing::info!(%peer_id, "peer disconnected");
                let _ = evt_tx.send(NetworkEvent::PeerDisconnected(peer_id)).await;
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            tracing::debug!(?peer_id, "outgoing connection error: {error}");
        }
        SwarmEvent::IncomingConnectionError { send_back_addr, error, .. } => {
            // A refusal by the caps or the guard lands here, as does a handshake that failed or
            // ran past [`HANDSHAKE_TIMEOUT`].
            tracing::debug!(%send_back_addr, "incoming connection error: {error}");
        }
        SwarmEvent::Behaviour(RandEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message,
            message_id,
        })) => {
            // Metered by length before anything reads the bytes (audit v6, GOSSIP-1): up to a
            // transmit size's worth of bincode was decoded, and a transaction hashed, before any
            // per-peer meter ran. Over the budget: `Ignore` — not relayed, no one penalised, and
            // reported here because the node loop never sees it.
            if !frames.admit(propagation_source, message.data.len(), Instant::now()) {
                tracing::debug!(%propagation_source, bytes = message.data.len(), "gossip frame over the forwarder's byte budget; not decoded");
                report_to_gossipsub(swarm, &GossipId { message_id, propagation_source }, MessageAcceptance::Ignore);
                return;
            }
            match bincode::deserialize::<GossipMessage>(&message.data) {
                Ok(msg) => {
                    // `from` falls back to `propagation_source` for a message that carries no
                    // source, which is the only case where the two coincide by construction. The
                    // rate limit still keys on `propagation_source`. Under `Permissive` an unsigned
                    // message's `source` is only claimed, never proven: the node reads a `Status`
                    // only when the two agree (SYNC-1, `node::on_status_gossip`).
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
        assert_eq!(d.sync_request_timeout, SYNC_REQUEST_TIMEOUT, "a default chain keeps 30 s");
        assert_eq!(SYNC_REQUEST_TIMEOUT, Duration::from_secs(30));

        let mut ledger = crate::storage::fixtures::genesis(1).ledger;
        ledger.set_max_block_bytes(20 << 20);
        let raised = WireLimits::for_ledger(&ledger);
        assert_eq!(raised, WireLimits::for_block_bytes(20 << 20));
        assert_eq!(raised.sync_max_wire_bytes, 22 << 20);
        assert_eq!(raised.sync_response_wire_limit, 2 * (22 << 20) + (256 << 10));
        assert_eq!(raised.gossip_max_transmit_size, 21 << 20);
        assert!(2 * raised.sync_max_wire_bytes <= raised.sync_response_wire_limit);
        // 44.25 MiB of reader limit: ⌈44.25⌉ = 45 s.
        assert_eq!(raised.sync_request_timeout, Duration::from_secs(45));
        // The floor holds up to a 30 MiB reader limit, and one byte over a whole MiB rounds up.
        assert_eq!(request_timeout_for(30 << 20), Duration::from_secs(30));
        assert_eq!(request_timeout_for((30 << 20) + 1), Duration::from_secs(31));
        assert_eq!(WireLimits::for_block_bytes(64 << 20).sync_request_timeout, Duration::from_secs(133));

        // Gossip never drops below today's 16 MiB: an 8 MiB chain keeps it.
        assert_eq!(WireLimits::for_block_bytes(8 << 20).gossip_max_transmit_size, 16 << 20);
        assert_eq!(WireLimits::for_block_bytes(15 << 20).gossip_max_transmit_size, 16 << 20);
        assert_eq!(WireLimits::for_block_bytes(64 << 20).gossip_max_transmit_size, 65 << 20);
    }

    /// Audit v6, GOSSIP-1: a forwarder's frames are charged by length before decoding. Its burst
    /// of full frames passes — an honest forwarder relaying full blocks is not refused — and the
    /// next frame is not decoded until the budget refills; another forwarder's budget is its
    /// own, a refused frame is charged nothing, and a departed peer's entry goes.
    #[test]
    fn a_forwarder_over_its_frame_budget_is_not_decoded() {
        let limits = WireLimits::for_block_bytes(20 << 20);
        let frame = limits.gossip_max_transmit_size;
        let mut m = FrameMeter::new(frame);
        let (a, b) = (PeerId::random(), PeerId::random());
        let t = Instant::now();
        for i in 0..GOSSIP_FRAME_BURST {
            assert!(m.admit(a, frame, t), "full frame {i} of the burst");
        }
        assert!(!m.admit(a, frame, t), "past the burst: not decoded");
        assert!(!m.admit(a, 1 << 20, t), "not even a small one while the budget is spent");
        assert!(m.admit(b, frame, t), "another forwarder's budget is its own");
        // Refill: two frames a second, and a refused frame was charged nothing.
        let later = t + Duration::from_millis(500);
        assert!(m.admit(a, frame, later), "half a second buys one frame back");
        assert!(!m.admit(a, frame, later));
        assert_eq!(m.len(), 2);
        m.forget(&a);
        assert_eq!(m.len(), 1);
        assert!(m.admit(a, frame, later), "a returning peer starts full: its connection was the cost");
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

    /// The premise `node::on_status_gossip`'s author rule rests on (SYNC-1, network scan
    /// 2026-09-26): under `ValidationMode::Permissive` an unsigned message carrying any `source`
    /// is delivered, and `NetworkEvent::Gossip.from` is that claimed author — only
    /// `GossipId.propagation_source` is the peer the bytes actually came from. If this ever stops
    /// holding (a switch to `Strict`, which needs a fleet canary), the node-side rule is merely
    /// redundant, never wrong.
    #[tokio::test]
    async fn a_forged_unsigned_status_reaches_the_node_under_the_claimed_author() {
        use libp2p::futures::StreamExt;
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
        .unwrap();
        // The identity being impersonated: some honest validator's peer id.
        let victim_id = PeerId::from(identity::Keypair::ed25519_from_bytes([9u8; 32]).unwrap().public());
        let attacker_kp = identity::Keypair::generate_ed25519();
        let gcfg = gossipsub::ConfigBuilder::default()
            .validation_mode(ValidationMode::Permissive)
            .heartbeat_interval(Duration::from_millis(200))
            .build()
            .unwrap();
        let gs: gossipsub::Behaviour = gossipsub::Behaviour::new(MessageAuthenticity::Author(victim_id), gcfg).unwrap();
        let mut sw = libp2p::SwarmBuilder::with_existing_identity(attacker_kp)
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|_| gs)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let topic = IdentTopic::new("rand/7/status");
        sw.behaviour_mut().subscribe(&topic).unwrap();
        sw.dial(a_addr.with(libp2p::multiaddr::Protocol::P2p(a.local_peer_id))).unwrap();
        let forged = Status { height: 5, head_hash: Hash::ZERO, view: 5, floor: u64::MAX };
        let data = bincode::serialize(&GossipMessage::Status(forged)).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        let mut got = None;
        while got.is_none() && tokio::time::Instant::now() < deadline {
            let _ = sw.behaviour_mut().publish(topic.clone(), data.clone());
            let until = tokio::time::Instant::now() + Duration::from_millis(300);
            loop {
                tokio::select! {
                    _ = sw.select_next_some() => {}
                    ev = a_rx.recv() => {
                        if let Some(NetworkEvent::Gossip { from, msg: GossipMessage::Status(s), id }) = ev {
                            got = Some((from, s, id.propagation_source));
                            break;
                        }
                    }
                    _ = tokio::time::sleep_until(until) => break,
                }
            }
        }
        let (from, s, prop) = got.expect("the forged status was delivered");
        assert_eq!(from, victim_id, "attributed to the impersonated peer, not the sender");
        assert_ne!(prop, victim_id);
        assert_eq!(s.floor, u64::MAX);
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
            gossip_status_to(&b, &mut a_rx, Status { height: 9, head_hash: Hash::digest(b"h"), view: 3, floor: 0 }).await;
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
            gossip_status_to(&b, &mut a_rx, Status { height: 11, head_hash: Hash::digest(b"h2"), view: 4, floor: 0 }).await;
        assert_ne!(next.message_id, first_id, "a different message is a different id");
        a.report_validation(next, MessageAcceptance::Accept).await;

        a.shutdown().await;
        b.shutdown().await;
    }

    /// A node with no connection limit accepts every inbound connection, and a fresh libp2p
    /// identity costs nothing to mint (deep scan 2026-09-24: 200 of them were all accepted). With
    /// the inbound cap at 3, eight dialers must leave the target holding at most three peers,
    /// however long they keep at it — and the first three do get in, so it is a cap and not a
    /// closed door.
    #[tokio::test]
    async fn inbound_connections_past_the_cap_are_refused() {
        const CAP: u32 = 3;
        let cfg = |bootstrap, limits| NetworkConfig {
            chain_id: 7,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap,
            enable_mdns: false,
            limits,
        };
        let capped = WireLimits { max_established_incoming: CAP, ..WireLimits::default() };
        let (target, mut target_rx) = start(cfg(vec![], capped), [40u8; 32]).await.unwrap();
        let addr = wait_for(&mut target_rx, Duration::from_secs(5), |e| match e {
            NetworkEvent::Listening(addr) => Some(addr),
            _ => None,
        })
        .await
        .expect("target listening");
        let full = addr.with(libp2p::multiaddr::Protocol::P2p(target.local_peer_id));

        let mut dialers = Vec::new();
        for i in 0..(CAP + 5) as u8 {
            let (d, rx) = start(cfg(vec![full.clone()], WireLimits::default()), [41 + i; 32]).await.unwrap();
            dialers.push((d, rx));
        }
        // Drain the target's events (a dropped receiver would silently discard them) and watch the
        // peer count over a window generous enough for every dial to land.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        let mut max_seen = 0usize;
        while tokio::time::Instant::now() < deadline {
            while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(10), target_rx.recv()).await {}
            let n = target.peers().await.len();
            max_seen = max_seen.max(n);
            assert!(n <= CAP as usize, "the target holds {n} peers, over the cap of {CAP}");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert_eq!(max_seen, CAP as usize, "the first {CAP} dialers get in");

        target.shutdown().await;
        for (d, _) in &dialers {
            d.shutdown().await;
        }
    }

    fn loopback_cfg(bootstrap: Vec<Multiaddr>, limits: WireLimits) -> NetworkConfig {
        NetworkConfig { chain_id: 7, listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()], bootstrap, enable_mdns: false, limits }
    }

    fn peer_of_seed(seed: u8) -> PeerId {
        PeerId::from(identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public())
    }

    /// Audit v6, NET-1: with the inbound cap full of strangers, a further stranger is refused —
    /// and a reserved peer is still admitted. Before, the cap was first come, first served, and a
    /// validator restarting into a host whose slots strangers held could not get back in.
    #[tokio::test]
    async fn a_reserved_peer_is_admitted_past_an_inbound_cap_full_of_strangers() {
        const CAP: u32 = 2;
        let reserved_seed = 90u8;
        let capped = WireLimits { max_established_incoming: CAP, ..WireLimits::default() };
        let edge = EdgeConfig { reserved: vec![peer_of_seed(reserved_seed)], ..EdgeConfig::default() };
        let (target, mut target_rx) = start_with(loopback_cfg(vec![], capped), [80u8; 32], edge).await.unwrap();
        let addr = wait_for(&mut target_rx, Duration::from_secs(5), |e| match e {
            NetworkEvent::Listening(addr) => Some(addr),
            _ => None,
        })
        .await
        .expect("target listening");
        let full = addr.with(libp2p::multiaddr::Protocol::P2p(target.local_peer_id));

        // Two strangers fill the cap, one after the other.
        let mut nodes = Vec::new();
        for seed in [81u8, 82] {
            let (d, rx) = start(loopback_cfg(vec![full.clone()], WireLimits::default()), [seed; 32]).await.unwrap();
            let id = d.local_peer_id;
            let got = wait_for(&mut target_rx, Duration::from_secs(10), |e| matches!(e, NetworkEvent::PeerConnected(p) if p == id).then_some(())).await;
            assert!(got.is_some(), "stranger {seed} fills a slot");
            nodes.push((d, rx));
        }
        // A third stranger is refused; the reserved peer gets in.
        let (late, late_rx) = start(loopback_cfg(vec![full.clone()], WireLimits::default()), [83u8; 32]).await.unwrap();
        let (reserved, reserved_rx) = start(loopback_cfg(vec![full.clone()], WireLimits::default()), [reserved_seed; 32]).await.unwrap();
        let (late_id, reserved_id) = (late.local_peer_id, reserved.local_peer_id);
        let mut saw_late = false;
        let got = wait_for(&mut target_rx, Duration::from_secs(10), |e| match e {
            NetworkEvent::PeerConnected(p) if p == late_id => {
                saw_late = true;
                None
            }
            NetworkEvent::PeerConnected(p) if p == reserved_id => Some(()),
            _ => None,
        })
        .await;
        assert!(got.is_some(), "the reserved peer was refused at a cap full of strangers");
        // Give the stranger the same window again: still out.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let peers: Vec<String> = target.peers().await.into_iter().map(|p| p.peer_id).collect();
        assert!(!saw_late && !peers.contains(&late_id.to_string()), "a stranger past the cap was admitted: {peers:?}");
        assert_eq!(peers.len(), CAP as usize + 1, "the strangers who filled the cap, and the reserved peer");

        target.shutdown().await;
        for (d, _) in nodes.iter().chain([(late, late_rx), (reserved, reserved_rx)].iter()) {
            d.shutdown().await;
        }
    }

    /// Whether the node closed a raw TCP connection within `within`: a read that ends (EOF or
    /// reset) rather than timing out. The bytes the listener's multistream-select sends first,
    /// if any, are read past.
    async fn closed_within(stream: &mut tokio::net::TcpStream, within: Duration) -> bool {
        use tokio::io::AsyncReadExt;
        let deadline = tokio::time::Instant::now() + within;
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
                Err(_) => return false,
                Ok(Ok(0)) | Ok(Err(_)) => return true,
                Ok(Ok(_)) => continue,
            }
        }
    }

    /// Audit v6, NET-1, the pending half: TCP connections from one address that never begin a
    /// handshake. Past [`MAX_PENDING_INCOMING_PER_ADDR`] the node closes them at once — before,
    /// all of them held a pending slot, and 64 held every one — and the ones it keeps are
    /// dropped at [`HANDSHAKE_TIMEOUT`], not libp2p's ten seconds.
    #[tokio::test]
    async fn stalled_handshakes_are_capped_per_address_and_dropped_at_the_handshake_timeout() {
        let (target, mut target_rx) = start(loopback_cfg(vec![], WireLimits::default()), [84u8; 32]).await.unwrap();
        let addr = wait_for(&mut target_rx, Duration::from_secs(5), |e| match e {
            NetworkEvent::Listening(addr) => Some(addr),
            _ => None,
        })
        .await
        .expect("target listening");
        let port = addr
            .iter()
            .find_map(|p| match p {
                libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
                _ => None,
            })
            .unwrap();
        let extra = 3usize;
        let mut stalled = Vec::new();
        for _ in 0..MAX_PENDING_INCOMING_PER_ADDR as usize + extra {
            stalled.push(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap());
            // One at a time, so the node has taken each before the next arrives.
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let started = tokio::time::Instant::now();
        let mut closed_now = 0;
        for s in stalled.iter_mut() {
            if closed_within(s, Duration::from_millis(300)).await {
                closed_now += 1;
            }
        }
        assert_eq!(closed_now, extra, "the connections past the per-address cap are refused at once, the rest held");
        // The held ones go at the handshake timeout, well before libp2p's default of ten seconds.
        for s in stalled.iter_mut() {
            assert!(closed_within(s, Duration::from_secs(8)).await, "a stalled handshake outlived the handshake timeout");
        }
        let held_for = started.elapsed();
        assert!(held_for < Duration::from_secs(8), "held for {held_for:?}");
        // Their places are given back: a real peer from the same address connects.
        let (d, _d_rx) = start(loopback_cfg(vec![addr.with(libp2p::multiaddr::Protocol::P2p(target.local_peer_id))], WireLimits::default()), [85u8; 32]).await.unwrap();
        let id = d.local_peer_id;
        let got = wait_for(&mut target_rx, Duration::from_secs(10), |e| matches!(e, NetworkEvent::PeerConnected(p) if p == id).then_some(())).await;
        assert!(got.is_some(), "a real peer from the same address after the stalled ones went");
        target.shutdown().await;
        d.shutdown().await;
    }

    /// A forged status — an unsigned message claiming `victim`'s authorship — published at
    /// `target` from a fresh identity until `target` delivers it or `within` passes. Whether it
    /// was delivered.
    async fn forged_status_is_delivered(target: &NetworkHandle, target_addr: Multiaddr, rx: &mut mpsc::Receiver<NetworkEvent>, within: Duration) -> bool {
        use libp2p::futures::StreamExt;
        let victim_id = peer_of_seed(9);
        let gcfg = gossipsub::ConfigBuilder::default()
            .validation_mode(ValidationMode::Permissive)
            .heartbeat_interval(Duration::from_millis(200))
            .build()
            .unwrap();
        let gs: gossipsub::Behaviour = gossipsub::Behaviour::new(MessageAuthenticity::Author(victim_id), gcfg).unwrap();
        let mut sw = libp2p::SwarmBuilder::with_existing_identity(identity::Keypair::generate_ed25519())
            .with_tokio()
            .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)
            .unwrap()
            .with_behaviour(|_| gs)
            .unwrap()
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        let topic = IdentTopic::new("rand/7/status");
        sw.behaviour_mut().subscribe(&topic).unwrap();
        sw.dial(target_addr.with(libp2p::multiaddr::Protocol::P2p(target.local_peer_id))).unwrap();
        let data = bincode::serialize(&GossipMessage::Status(Status { height: 5, head_hash: Hash::ZERO, view: 5, floor: u64::MAX })).unwrap();
        let deadline = tokio::time::Instant::now() + within;
        while tokio::time::Instant::now() < deadline {
            let _ = sw.behaviour_mut().publish(topic.clone(), data.clone());
            let until = tokio::time::Instant::now() + Duration::from_millis(300);
            loop {
                tokio::select! {
                    _ = sw.select_next_some() => {}
                    ev = rx.recv() => {
                        if let Some(NetworkEvent::Gossip { from, msg: GossipMessage::Status(_), .. }) = ev {
                            if from == victim_id {
                                return true;
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(until) => break,
                }
            }
        }
        false
    }

    /// Audit v6, CH-7, `--strict-gossip`. What a mixed fleet actually does, found by running it:
    /// gossipsub's validation mode governs only what a node *accepts*, and every node publishes
    /// signed (`MessageAuthenticity::Signed`), so a strict node delivers a permissive node's
    /// gossip exactly as a permissive one does, and the other way round — two strict nodes
    /// likewise. What strict changes is the forged, unsigned message: a permissive node delivers
    /// it under the author it claims (`a_forged_unsigned_status_reaches_the_node_under_the_claimed_author`),
    /// a strict one drops it before the application sees it. So the flag can roll node by node.
    #[tokio::test]
    async fn a_strict_node_takes_a_permissive_nodes_signed_gossip_and_drops_a_forged_unsigned_one() {
        let strict = EdgeConfig { strict_gossip: true, ..EdgeConfig::default() };
        // A strict node, and a permissive and a strict node dialing it.
        let (s, mut s_rx) = start_with(loopback_cfg(vec![], WireLimits::default()), [70u8; 32], strict.clone()).await.unwrap();
        let s_addr = wait_for(&mut s_rx, Duration::from_secs(5), |e| match e {
            NetworkEvent::Listening(addr) => Some(addr),
            _ => None,
        })
        .await
        .expect("listening");
        let s_full = s_addr.clone().with(libp2p::multiaddr::Protocol::P2p(s.local_peer_id));
        let (p, mut p_rx) = start(loopback_cfg(vec![s_full.clone()], WireLimits::default()), [71u8; 32]).await.unwrap();
        let (s2, mut s2_rx) = start_with(loopback_cfg(vec![s_full], WireLimits::default()), [72u8; 32], strict).await.unwrap();
        for id in [p.local_peer_id, s2.local_peer_id] {
            assert!(wait_for(&mut s_rx, Duration::from_secs(10), |e| matches!(e, NetworkEvent::PeerConnected(x) if x == id).then_some(())).await.is_some());
        }
        // Permissive → strict, strict → strict, strict → permissive.
        let (from, _) = gossip_status_to(&p, &mut s_rx, Status { height: 1, head_hash: Hash::digest(b"p"), view: 1, floor: 0 }).await;
        assert_eq!(from, p.local_peer_id, "a strict node delivers a permissive node's signed gossip");
        let (from, _) = gossip_status_to(&s2, &mut s_rx, Status { height: 2, head_hash: Hash::digest(b"s2"), view: 2, floor: 0 }).await;
        assert_eq!(from, s2.local_peer_id, "two strict nodes exchange gossip");
        let (from, _) = gossip_status_to(&s, &mut p_rx, Status { height: 3, head_hash: Hash::digest(b"s"), view: 3, floor: 0 }).await;
        assert_eq!(from, s.local_peer_id, "a permissive node delivers a strict node's gossip");
        let _ = &mut s2_rx;

        // The forged unsigned message: dropped by the strict node.
        assert!(!forged_status_is_delivered(&s, s_addr, &mut s_rx, Duration::from_secs(6)).await, "a strict node delivered an unsigned message");
        for n in [s, p, s2] {
            n.shutdown().await;
        }
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
            b.broadcast(GossipMessage::Status(Status { height: 9, head_hash: Hash::digest(b"h"), view: 3, floor: 0 })).await;
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
