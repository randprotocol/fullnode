//! The node event loop: owns the HotStuff replica, mempool, storage handle and
//! network handle; turns consensus `Action`s into I/O and network events into
//! consensus input.

use crate::admission::{self, GossipOutcome, Verdict, VerifySource, MAX_VERIFY_IN_FLIGHT};
use crate::mempool::{Mempool, MempoolError};
use crate::network::{
    self, GossipId, GossipMessage, NetworkConfig, NetworkEvent, NetworkHandle, Status, SyncRequest, SyncResponse,
};
use crate::rpc::{self, NodeCommand, NodeStatus, RpcState};
use crate::storage::{Storage, VerifyMode};
use anyhow::{Context, Result};
use libp2p::{Multiaddr, PeerId};
use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::consensus::{Action, CommittedBlock, ConsensusConfig, ConsensusError, ConsensusMessage, HotStuff};
use shrugg_core::gas;
use shrugg_core::genesis::{Genesis, GenesisState};
use shrugg_core::{Hash, Keypair, Ledger, ShieldedAddress, Transaction, ValidatorSet, Word8, FAUCET_MAX_UNITS};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::notes::{Note, SpendKey};
use shrugg_zkvm::viewing::TxKey;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, oneshot};

const SYNC_BATCH: u32 = 100;

/// Smallest batch the client falls back to after a failure. One block always fits, whatever it
/// carries.
const SYNC_BATCH_MIN: u32 = 1;

/// Charged to every batch before its first block: the CBOR framing around the blocks themselves
/// (the `SyncResponse::Blocks` variant, and the array header, which grows to 9 bytes at most).
/// Generous on purpose — the budget should over-estimate the response, never under-estimate it.
const SYNC_RESPONSE_FRAMING_BYTES: u64 = 64;

/// How long the node waits for a sync response before it abandons the request.
///
/// The wire's own timeout, deliberately. A shorter deadline here abandons a request that is still
/// alive, and the node then discarded the response when it arrived: the 10 s give-up this replaces
/// meant only a batch answered inside 10 s counted, and a 1-vCPU droplet serving 100 blocks from
/// RocksDB on the same event loop that verifies proofs frequently took longer. This is an upper
/// bound rather than the usual case — a request that fails reports `SyncFailed` and is re-picked at
/// once.
pub(crate) const SYNC_GIVE_UP: Duration = network::SYNC_REQUEST_TIMEOUT;

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub datadir: PathBuf,
    pub seed: [u8; 32],
    pub listen: Vec<Multiaddr>,
    pub bootstrap: Vec<Multiaddr>,
    pub rpc_addr: SocketAddr,
    pub enable_mdns: bool,
    pub validator: bool,
    pub block_interval: Duration,
    pub base_timeout: Duration,
    pub max_timeout: Duration,
    /// Chain integrity check at startup; damaged tail is truncated and resynced from peers.
    pub verify: VerifyMode,
}

/// Handles returned by `Node::start` so tests and the CLI can observe the node.
pub struct NodeHandle {
    pub rpc_addr: SocketAddr,
    pub network: NetworkHandle,
    pub listen_addrs: Vec<Multiaddr>,
    pub status: Arc<RwLock<NodeStatus>>,
    pub storage: Arc<Storage>,
    pub address: shrugg_core::Address,
    pub task: tokio::task::JoinHandle<Result<()>>,
    pub rpc_task: tokio::task::JoinHandle<()>,
}

impl NodeHandle {
    /// Stop the node loop, the RPC server and the network task, releasing the
    /// database so the data directory can be reopened.
    pub async fn shutdown(self) {
        self.network.shutdown().await;
        self.task.abort();
        self.rpc_task.abort();
        let _ = self.task.await;
        let _ = self.rpc_task.await;
        drop(self.storage);
    }
}

/// The confidential-computation executor a chain's genesis calls for.
///
/// The ledger gates `Deploy`/`Call` with its own `confidential` flag, so there is no
/// disabled-executor variant to pick between: a node always builds a `ZkExecutor`, including on
/// a chain whose genesis sets `confidential: false`. Building the genesis *state* needs one too
/// — the deposit notes go into a real commitment tree — which is why this takes the raw
/// `Genesis` rather than the built `GenesisState`.
pub fn executor_for_profile(fri_profile: &str) -> Result<Arc<dyn ConfidentialExecutor>> {
    let profile =
        ZkExecutor::profile_from_str(fri_profile).with_context(|| format!("genesis fri_profile {fri_profile}"))?;
    Ok(Arc::new(ZkExecutor::new(profile)))
}

/// The genesis file, its executor, and the state they build. One function because the state
/// cannot be built without the executor and the executor is named by the file.
pub fn load_genesis(datadir: &std::path::Path) -> Result<(GenesisState, Arc<dyn ConfidentialExecutor>)> {
    let path = datadir.join("genesis.json");
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let genesis = Genesis::from_json(&text)?;
    let executor = executor_for_profile(&genesis.fri_profile)?;
    let gs = genesis.build(executor.as_ref())?;
    Ok((gs, executor))
}

/// Verify the on-disk chain. If the tail is damaged, truncate to the last good
/// block (keeping safety state); the missing blocks are re-fetched from peers by
/// the normal sync path. Returns the height the node will resume from.
/// The ledger a restarting node runs on: the persisted state, plus the three things that live
/// in the genesis file rather than in the database.
///
/// `epoch_blocks` is one of them, and it is not cosmetic: `Unbond` writes `epoch() +
/// UNBONDING_EPOCHS` into the register, which the state root hashes. A node that came back up
/// with the default 1000 on a chain that runs shorter epochs would compute a release epoch
/// nobody else does, disagree about the state root from its first unbond on, and never rejoin.
/// One function, so a restart cannot pick up two of the three and be wrong about the chain.
pub fn reload_ledger(storage: &Storage, gs: &GenesisState, executor: &dyn ConfidentialExecutor) -> Result<Ledger> {
    let mut ledger = storage.load_ledger(executor)?;
    ledger.set_faucet(gs.faucet);
    ledger.set_confidential(gs.confidential);
    ledger.set_epoch_blocks(gs.epoch_blocks);
    Ok(ledger)
}

/// The consensus replica a node comes back up on: the persisted head and its certificate, the
/// reloaded ledger, the safety state, and **every epoch set storage recorded**.
///
/// One function because the epoch sets are the easy half to forget: a node that resumed with the
/// genesis set alone has no set for the epoch it is actually in, and stalls on `UnknownEpochSet`
/// — it can neither lead, nor vote, nor verify the certificates its peers send it.
pub fn resume_consensus(
    storage: &Storage,
    gs: &GenesisState,
    signer: Option<Keypair>,
    base_timeout: Duration,
    max_timeout: Duration,
    executor: Arc<dyn ConfidentialExecutor>,
) -> Result<HotStuff> {
    let head_block = storage.head_block()?;
    let head_qc = storage.head_qc()?;
    let ledger = reload_ledger(storage, gs, executor.as_ref())?;
    let safety = storage.load_safety()?;
    let mut ccfg = ConsensusConfig::new(gs.chain_id, gs.validators.clone(), gs.hash());
    ccfg.epoch_blocks = gs.epoch_blocks;
    ccfg.base_timeout = base_timeout;
    ccfg.max_timeout = max_timeout;
    let epoch_sets = storage.load_epoch_sets()?;
    Ok(HotStuff::resume(ccfg, signer, head_block, head_qc, ledger, safety, epoch_sets, executor))
}

pub fn check_and_repair_chain(storage: &Storage, gs: &GenesisState, mode: VerifyMode, executor: &dyn ConfidentialExecutor) -> Result<u64> {
    if mode == VerifyMode::Off {
        return Ok(storage.head()?.height);
    }
    let t = Instant::now();
    let check = storage.verify_chain(gs, mode, executor)?;
    match &check.problem {
        None => {
            tracing::info!("chain verified: {} blocks ok ({:?}, {:.1?})", check.head + 1, mode, t.elapsed());
            Ok(check.head)
        }
        Some(problem) => {
            let resume = if check.genesis_ok { check.last_good } else { 0 };
            tracing::warn!(
                "CORRUPT CHAIN at height {}: {problem}; truncating {} -> {} and resyncing from peers",
                check.last_good + 1,
                check.head,
                resume
            );
            let ledger = if check.genesis_ok { check.ledger } else { gs.ledger.clone() };
            storage.truncate_to(gs, resume, &ledger)?;
            let again = storage.verify_chain(gs, mode, executor)?;
            if let Some(p) = again.problem {
                anyhow::bail!("chain still corrupt after truncation: {p}");
            }
            Ok(resume)
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

struct Node {
    cfg: NodeConfig,
    gs: GenesisState,
    /// This node's own validator address, whether or not it is signing today: what
    /// `active_validator` is looked up by.
    address: shrugg_core::Address,
    executor: Arc<dyn ConfidentialExecutor>,
    storage: Arc<Storage>,
    hs: HotStuff,
    mempool: Mempool,
    net: NetworkHandle,
    status: Arc<RwLock<NodeStatus>>,
    /// Committed heads, for whatever WebSocket clients are subscribed. Held here rather than read
    /// back out of the `RpcState` because this is the only place that writes it.
    heads: broadcast::Sender<rpc::HeadSummary>,
    /// The live WebSocket connection count `ws::upgrade` maintains; reported as
    /// `NodeStatus::ws_clients`.
    ws_conns: Arc<AtomicUsize>,
    peers: HashMap<PeerId, Peer>,
    timeout: Option<(u64, Instant)>,
    propose_at: Option<(u64, Instant)>,
    last_block_at: Instant,
    sync_inflight: Option<(PeerId, libp2p::request_response::OutboundRequestId, Instant)>,
    /// Blocks to ask for in the next batch. Halved toward [`SYNC_BATCH_MIN`] after a failure and
    /// reset to [`SYNC_BATCH`] after a batch applies, so a batch size the wire cannot carry is
    /// backed away from instead of retried forever.
    sync_batch: u32,
    /// Sync batch requests that *failed*: a wire or codec error, a give-up past the wire timeout,
    /// or a batch we asked for and could not apply. Surfaced in `shrugg status`, because the
    /// failure mode this counts was invisible on chain 8.
    ///
    /// Deliberately not the same number as [`Node::sync_late_batches`]: one says the round trip was
    /// lost, the other says it was merely slow, and an operator reading a stall needs to tell them
    /// apart.
    sync_failures: u64,
    /// Batches that arrived after their request had been given up on and were applied anyway.
    /// Progress, not failure — but a rising count means the give-up is firing on live requests.
    sync_late_batches: u64,
    fetch_inflight: HashMap<libp2p::request_response::OutboundRequestId, Hash>,
    /// Block hash -> (attempts so far, peers already asked) for by-hash fetches.
    fetch_attempts: HashMap<Hash, (usize, Vec<PeerId>)>,
    /// Transaction hashes this node has already refused for a reason about their bytes, so a
    /// re-gossiped copy costs a hash lookup instead of a proof verification.
    refused: admission::RefusedCache,
    /// Policy only — every bucket lives on its [`Peer`], so nothing here has to track the peer set.
    limiter: admission::PeerLimiter,
    /// The tip the pending verifications are running against, refreshed lazily: a full ledger clone
    /// per consensus message would cost one per vote, so it is taken only when a transaction is
    /// waiting and the tip's `(height, root)` has moved since the last one.
    snapshot: Option<(u64, Word8, Arc<Ledger>)>,
    /// Verifications on blocking workers right now, capped at [`MAX_VERIFY_IN_FLIGHT`].
    verify_in_flight: usize,
    /// Transactions waiting for one of those slots, capped at `admission::MAX_VERIFY_QUEUE` by
    /// [`GossipOutcome::for_transaction`].
    verify_queue: VecDeque<(Transaction, VerifySource)>,
    /// The sender every verification task answers on; its receiver is an arm of the loop's
    /// `select!`.
    verdicts_tx: mpsc::Sender<Verdict>,
}

const MAX_FETCH_ATTEMPTS: usize = 8;

/// What the node knows about one peer.
///
/// Connectedness is tracked apart from the status, because the two arrive from different places and
/// a peer can have one without the other. A `Status` reaches us over gossipsub, whose `from` is the
/// message's *author* — so a validator several hops away, with no connection to us at all, lands in
/// this map. Sending it a sync request makes `request_response` open a connection first, and on
/// chain 8 that dial went to whatever identify had advertised and failed, taking the request with
/// it. Only [`Peer::connected`] peers are asked for blocks.
#[derive(Clone, Debug, Default)]
struct Peer {
    /// The last status this peer published, if we have seen one.
    status: Option<Status>,
    /// We currently hold an open connection to it.
    connected: bool,
    /// This peer's gossip-submission allowance. Metered only when the peer is the *forwarder* of a
    /// transaction (`GossipId.propagation_source`); a peer we know of only as the author of relayed
    /// gossip never spends from it. Dropped with the entry on `PeerDisconnected`, which is why
    /// `PeerLimiter` keeps no map.
    tx_bucket: admission::TokenBucket,
}

/// The wire cost of one committed block in a sync batch.
///
/// Measured with the codec's own CBOR serializer ([`network::codec::cbor_size`]) rather than with
/// bincode, so the budget is in the units the wire actually charges — and over the whole
/// [`CommittedBlock`], which is what goes out. The budget this feeds used to count
/// `cb.block.encode()` alone and so missed the QC that certifies the block: on an 18-validator
/// chain, half the payload. `deposits` is `#[serde(skip)]`, so it costs nothing here, matching the
/// wire.
fn committed_block_wire_size(cb: &CommittedBlock) -> u64 {
    // A block that cannot be sized is charged the whole budget, which ends the batch rather than
    // letting an unmeasured block through.
    network::codec::cbor_size(cb).map(|n| n as u64).unwrap_or(network::SYNC_MAX_WIRE_BYTES)
}

/// The two decisions to make about an arriving `Blocks` response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BatchDecision {
    /// These blocks continue our chain: apply them.
    apply: bool,
    /// They arrived after their own request had been given up on. Applied anyway — the blocks are
    /// good — but counted, because a give-up firing on live requests is worth seeing.
    late: bool,
    /// Free the in-flight slot. Only ever when this response *is* the request the slot holds: on the
    /// late path the slot holds the replacement we sent when we gave up, and that one is still on
    /// the wire.
    clear_inflight: bool,
}

/// A batch is judged by what it holds, not by which request asked for it.
///
/// The node used to drop any response whose id was not the current one, which threw away good
/// blocks every time its own give-up had already re-requested the same range — so only a batch that
/// arrived inside the give-up window counted, and catch-up moved one batch per 30-40 s with nothing
/// in the log to say why. A batch whose first block is exactly our next height continues our chain
/// whoever asked for it and however late; applying it twice is impossible, because the second copy
/// no longer starts there. `None` is an empty batch: the peer has nothing past our height.
fn batch_decision(first_height: Option<u64>, my_height: u64, is_current: bool) -> BatchDecision {
    let apply = first_height == Some(my_height + 1);
    BatchDecision { apply, late: apply && !is_current, clear_inflight: is_current }
}

/// Take committed blocks from `blocks` while they fit in `budget` bytes of wire.
///
/// The first block is always taken, however large it is: a block fatter than the whole budget must
/// still be servable, or a node stuck behind it has no way past it. Every later block is charged
/// its CBOR size before it is admitted, and the batch ends as soon as one would take the total
/// over.
///
/// `blocks` is consumed lazily, so a batch that fills on bytes never reads the rest from storage.
fn fill_sync_batch(blocks: impl IntoIterator<Item = CommittedBlock>, budget: u64) -> Vec<CommittedBlock> {
    let mut out: Vec<CommittedBlock> = Vec::new();
    // Seeded with the enclosing framing — the `SyncResponse` variant tag and the array header —
    // rather than starting at zero, so the running total is an over-estimate of the response and
    // never an under-estimate of it. A few bytes against a 6 MiB budget, but the direction of the
    // error is the point.
    let mut bytes = SYNC_RESPONSE_FRAMING_BYTES;
    for cb in blocks {
        bytes = bytes.saturating_add(committed_block_wire_size(&cb));
        if !out.is_empty() && bytes > budget {
            break;
        }
        out.push(cb);
    }
    out
}

/// How many bytes of blocks one sync response may carry.
///
/// Half the reader limit the codec enforces, by construction: the budget is the server's promise
/// and the limit is the client's check, and keeping the first at half the second leaves room for
/// framing and for a peer on a slightly different build.
pub(crate) fn serve_sync_budget() -> u64 {
    debug_assert!(network::SYNC_MAX_WIRE_BYTES * 2 <= network::SYNC_RESPONSE_WIRE_LIMIT);
    network::SYNC_MAX_WIRE_BYTES
}

pub async fn start(cfg: NodeConfig) -> Result<NodeHandle> {
    let key = Keypair::from_seed(cfg.seed).context("bad key seed")?;
    let (gs, executor) = load_genesis(&cfg.datadir)?;
    // Every shielded-pool proof on this chain is against one guest, pinned by the genesis. A
    // node built from a different commit would verify nothing and vote against every bundle,
    // which looks like a consensus bug rather than the build mismatch it is — so say so here.
    let built = ZkExecutor::hc_bundle();
    if built != gs.hc_bundle {
        anyhow::bail!(
            "this build's bundle guest ({}) differs from the genesis hc_bundle ({}); \
             rebuild from the chain's pinned commit",
            shrugg_core::notes::word8_to_hex(&built),
            shrugg_core::notes::word8_to_hex(&gs.hc_bundle)
        );
    }
    let storage = Arc::new(Storage::open(&cfg.datadir)?);
    storage.init_genesis(&gs)?;
    check_and_repair_chain(&storage, &gs, cfg.verify, executor.as_ref())?;

    // "Is a validator" is "has a signer", not "is in the genesis set" (spec §8): a validator that
    // bonds in after genesis must already hold its key when its first epoch arrives, and a node
    // that refused the key at startup would have nothing to vote with. `HotStuff::resume` keeps a
    // signer that is in no current set and observes until an epoch admits it; what the RPC
    // reports as *in the current set* is `active_validator`.
    let signer = if cfg.validator { Some(Keypair::from_seed(cfg.seed)?) } else { None };
    let hs = resume_consensus(&storage, &gs, signer, cfg.base_timeout, cfg.max_timeout, executor.clone())?;

    // Network.
    let identity = key.derive_subkey(b"shrugg-p2p-identity");
    let (net, mut events) = network::start(
        NetworkConfig {
            chain_id: gs.chain_id,
            listen: cfg.listen.clone(),
            bootstrap: cfg.bootstrap.clone(),
            enable_mdns: cfg.enable_mdns,
        },
        identity,
    )
    .await?;

    // Collect listen addrs briefly so callers (tests, logs) know where we are.
    let mut listen_addrs = Vec::new();
    let mut early = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while listen_addrs.len() < cfg.listen.len() && Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
            Ok(Some(NetworkEvent::Listening(a))) => listen_addrs.push(a),
            Ok(Some(e)) => early.push(e),
            Ok(None) => anyhow::bail!("network closed"),
            Err(_) => {}
        }
    }
    for a in &listen_addrs {
        tracing::info!("listening on {a}/p2p/{}", net.local_peer_id);
    }

    // RPC.
    let status = Arc::new(RwLock::new(NodeStatus {
        is_validator: hs.is_validator(),
        active_validator: hs.current_set().contains(&key.address()),
        faucet: gs.faucet,
        confidential: gs.confidential,
        fri_profile: gs.fri_profile.clone(),
        address: Some(key.address().to_base58()),
        peer_id: net.local_peer_id.to_string(),
        ..Default::default()
    }));
    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    // The receiver is dropped: every subscriber makes its own at upgrade, and a channel with no
    // receiver simply drops what is sent, which is the normal case for a node nobody watches.
    let (heads, _) = broadcast::channel(rpc::HEAD_CHANNEL);
    let ws_conns = Arc::new(AtomicUsize::new(0));
    let (rpc_addr, rpc_task) = rpc::serve(
        cfg.rpc_addr,
        RpcState {
            storage: storage.clone(),
            status: status.clone(),
            node: cmd_tx,
            chain_id: gs.chain_id,
            executor: executor.clone(),
            heads: heads.clone(),
            ws_conns: ws_conns.clone(),
        },
    )
    .await?;
    tracing::info!("rpc listening on http://{rpc_addr}");
    tracing::info!(
        "node {} height {} view {} validator={}",
        key.address(),
        hs.committed_height(),
        hs.view(),
        hs.is_validator()
    );

    // Warm verifier keys off the consensus thread: the bundle guest's always (every block can
    // carry bundles, so the first one must not pay for the key), and every program already on
    // chain.
    {
        let programs: Vec<_> = hs.committed_ledger().programs().values().cloned().collect();
        let ex = executor.clone();
        tokio::task::spawn_blocking(move || {
            ex.warm_bundle();
            tracing::info!("bundle verifier key warmed");
            for rec in programs {
                ex.warm(&rec);
            }
            tracing::info!("verifier keys warmed");
        });
    }

    let address = key.address();
    // At most `MAX_VERIFY_IN_FLIGHT` verdicts can be outstanding — a worker only exists because the
    // loop counted it in — so the channel never has to hold more than that.
    let (verdicts_tx, verdicts_rx) = mpsc::channel(MAX_VERIFY_IN_FLIGHT);
    let node = Node {
        cfg,
        gs,
        address,
        executor: executor.clone(),
        storage: storage.clone(),
        hs,
        mempool: Mempool::new(10_000),
        net: net.clone(),
        status: status.clone(),
        heads,
        ws_conns,
        peers: HashMap::new(),
        timeout: None,
        propose_at: None,
        last_block_at: Instant::now(),
        sync_inflight: None,
        sync_batch: SYNC_BATCH,
        sync_failures: 0,
        sync_late_batches: 0,
        fetch_inflight: HashMap::new(),
        fetch_attempts: HashMap::new(),
        refused: admission::RefusedCache::new(admission::REFUSED_CACHE_ENTRIES),
        limiter: admission::PeerLimiter::new(admission::PEER_TX_BURST, admission::PEER_TX_PER_SEC),
        snapshot: None,
        verify_in_flight: 0,
        verify_queue: VecDeque::new(),
        verdicts_tx,
    };
    // A fatal error in the loop ends the node, but most embedders (every cluster test, and any
    // caller that keeps the handle without awaiting it) never look at the `JoinHandle`, so
    // without this the node simply goes quiet and looks like a consensus or networking stall.
    // The `Result` is still returned for whoever does await it.
    let task = tokio::spawn(async move {
        let outcome = node.run(events, cmd_rx, verdicts_rx, early).await;
        match &outcome {
            Ok(()) => tracing::info!("node loop stopped"),
            Err(e) => tracing::error!("node loop exited: {e:#}"),
        }
        outcome
    });
    Ok(NodeHandle { rpc_addr, network: net, listen_addrs, status, storage, address, task, rpc_task })
}

async fn sleep_until(t: Option<Instant>) {
    match t {
        Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
        None => std::future::pending().await,
    }
}

impl Node {
    async fn run(
        mut self,
        mut events: mpsc::Receiver<NetworkEvent>,
        mut cmds: mpsc::Receiver<NodeCommand>,
        mut verdicts: mpsc::Receiver<Verdict>,
        early: Vec<NetworkEvent>,
    ) -> Result<()> {
        let actions = self.hs.start();
        self.handle_actions(actions).await?;
        for e in early {
            self.on_network_event(e).await?;
        }
        let mut status_tick = tokio::time::interval(Duration::from_secs(3));
        let mut sync_tick = tokio::time::interval(Duration::from_secs(2));
        loop {
            self.publish_status();
            tokio::select! {
                ev = events.recv() => match ev {
                    Some(ev) => self.on_network_event(ev).await?,
                    None => { tracing::warn!("network closed; shutting down"); return Ok(()); }
                },
                cmd = cmds.recv() => match cmd {
                    Some(cmd) => self.on_command(cmd).await?,
                    None => { tracing::info!("rpc closed; shutting down"); return Ok(()); }
                },
                // A proof verification that finished on a blocking worker. The whole point of this
                // arm: the ~20 ms it cost was not spent here.
                v = verdicts.recv() => match v {
                    Some(v) => self.on_verdict(v).await?,
                    // This node holds a sender for as long as it lives, so the channel cannot close
                    // under it; stopping beats spinning on a closed receiver if it ever does.
                    None => { tracing::warn!("verify channel closed; shutting down"); return Ok(()); }
                },
                _ = sleep_until(self.timeout.map(|t| t.1)) => {
                    if let Some((view, _)) = self.timeout.take() {
                        let acts = self.hs.on_timeout(view);
                        self.handle_actions(acts).await?;
                    }
                },
                _ = sleep_until(self.propose_at.map(|t| t.1)) => {
                    if let Some((view, _)) = self.propose_at.take() {
                        self.propose(view).await?;
                    }
                },
                _ = status_tick.tick() => self.broadcast_status().await,
                _ = sync_tick.tick() => self.maybe_sync().await,
            }
        }
    }

    fn publish_status(&self) {
        let mut s = self.status.write().unwrap_or_else(|e| e.into_inner());
        s.height = self.hs.committed_height();
        s.head_hash = self.hs.committed_hash().to_hex();
        s.view = self.hs.view();
        s.high_qc_view = self.hs.high_qc().view;
        // `peer_count` keeps the meaning it has always had — every peer we know of, including
        // those seen only as the author of relayed gossip — because dashboards threshold on it.
        // `connected_peers` is the new number, and the one that matters for sync: only a peer we
        // hold an open connection to can be asked for blocks.
        s.peer_count = self.peers.len();
        s.connected_peers = self.peers.values().filter(|p| p.connected).count();
        s.mempool_size = self.mempool.len();
        // Whether this node's key is in the set running the epoch the next block belongs to.
        // Distinct from `is_validator`, which only says the node holds a key at all.
        s.active_validator = self.hs.current_set().contains(&self.address);
        let ledger = self.hs.committed_ledger();
        s.programs = ledger.programs().len() as u64;
        // The pool's public size, straight from the committed ledger rather than a second read
        // of storage: this runs on the node loop after every commit.
        s.notes = ledger.next_index();
        s.nullifiers = ledger.nullifiers().len() as u64;
        s.tree_root = shrugg_core::notes::word8_to_hex(&ledger.root());
        s.hc_bundle = shrugg_core::notes::word8_to_hex(&ledger.hc_bundle());
        let target = self.peers.values().filter_map(|p| p.status.as_ref()).map(|p| p.height).max().unwrap_or(0);
        s.sync_target = target.max(s.height);
        s.syncing = self.sync_inflight.is_some();
        // Without these, a node that is `syncing: true` with a rising target and no warning in the
        // log looks healthy while making no progress at all — which is exactly how chain 8's
        // catch-up stall presented.
        s.sync_inflight_age_ms = self.sync_inflight.map(|(_, _, at)| at.elapsed().as_millis() as u64);
        s.sync_failures = self.sync_failures;
        s.sync_late_batches = self.sync_late_batches;
        s.ws_clients = self.ws_conns.load(SeqCst);
        // Admission's two numbers, beside the sync ones and never mixed with them: a verification
        // that was shed or refused is not a sync failure, and the two sets answer different
        // questions for an operator.
        s.refused_cache = self.refused.len();
        s.verify_queue = self.verify_queue.len();
    }

    /// The tip ledger the pending verifications run against, cloned at most once per tip change.
    ///
    /// Taken lazily — only when a transaction is actually waiting — because a clone per consensus
    /// message would be a clone per vote. On an idle chain there is none at all, and on a busy one
    /// at most one per block.
    fn snapshot(&mut self) -> Arc<Ledger> {
        let key = {
            let tip = self.hs.tip_ledger();
            (tip.height(), tip.root())
        };
        if self.snapshot.as_ref().map(|(h, r, _)| (*h, *r)) != Some(key) {
            self.snapshot = Some((key.0, key.1, Arc::new(self.hs.tip_ledger().clone())));
        }
        self.snapshot.as_ref().expect("just set").2.clone()
    }

    /// Start verifications from the queue while there is a free slot.
    ///
    /// Nothing here blocks: `spawn_blocking` puts the proof work on a worker thread and the loop
    /// goes straight back to the `select!`. The verdict returns on its own arm.
    fn pump_verify(&mut self) {
        while self.verify_in_flight < MAX_VERIFY_IN_FLIGHT {
            let Some((tx, source)) = self.verify_queue.pop_front() else { break };
            let ledger = self.snapshot();
            let executor = self.executor.clone();
            let out = self.verdicts_tx.clone();
            self.verify_in_flight += 1;
            tokio::task::spawn_blocking(move || {
                let result = ledger.validate(&tx, executor.as_ref());
                // The loop is the only receiver and outlives every task it spawned, so a send
                // failure means the node is already shutting down.
                let _ = out.blocking_send(Verdict { tx, result, source });
            });
        }
    }

    /// One finished verification: the second half of the exactly-once report, and the only way a
    /// gossiped transaction reaches the pool.
    async fn on_verdict(&mut self, v: Verdict) -> Result<()> {
        self.verify_in_flight = self.verify_in_flight.saturating_sub(1);
        let hash = v.tx.hash();
        let acceptance = admission::acceptance_for(&v.result, hash, &mut self.refused);
        // A verified transaction is pooled against the *current* tip, not the snapshot it was
        // verified on: `insert_verified` re-runs `precheck` there, so a nullifier spent or an anchor
        // scrolled out in the meantime is caught on the state it is actually being pooled on.
        let pooled = match &v.result {
            Ok(()) => self.mempool.insert_verified(v.tx.clone(), self.hs.tip_ledger(), self.executor.as_ref()),
            Err(e) => Err(MempoolError::Invalid(e.clone())),
        };
        match v.source {
            // `acceptance`, not `pooled`: a transaction that verified and then lost a pool conflict
            // is still a valid message, and another node's pool may have room for it.
            VerifySource::Gossip(id) => self.net.report_validation(id, acceptance.into()).await,
            VerifySource::Rpc(reply) => {
                if pooled.is_ok() {
                    self.net.broadcast(GossipMessage::Transaction(v.tx)).await;
                }
                let _ = reply.send(pooled);
            }
        }
        self.pump_verify();
        Ok(())
    }

    /// Hand one decision to gossipsub. Every path that delivers a gossip message ends here or in
    /// [`Node::on_verdict`], exactly once, which is what `validate_messages()` demands.
    async fn report(&self, id: GossipId, outcome: GossipOutcome) {
        let a = match outcome {
            GossipOutcome::Report(a) => a,
            // Only `for_transaction` answers `Verify`, and its caller queues the transaction rather
            // than reporting it. Accepting is the safe reading if that ever changes: a message
            // forwarded once too often beats a message this node silently stops relaying.
            GossipOutcome::Verify => admission::Acceptance::Accept,
        };
        self.net.report_validation(id, a.into()).await;
    }

    /// One gossiped transaction. Reported exactly once: here when the decision is final, or on its
    /// verdict when it goes to a worker.
    async fn on_gossiped_tx(&mut self, tx: Transaction, id: GossipId) -> Result<()> {
        let outcome = {
            // The *forwarder's* bucket, not the author's, and spent in place — `TokenBucket` is
            // `Copy`, so metering a local copy of it would leave every call seeing a full bucket.
            let bucket = &mut self.peers.entry(id.propagation_source).or_default().tx_bucket;
            GossipOutcome::for_transaction(
                &tx,
                Some(bucket),
                &mut self.refused,
                &self.limiter,
                self.verify_queue.len(),
                Instant::now(),
            )
        };
        if outcome != GossipOutcome::Verify {
            self.report(id, outcome).await;
            return Ok(());
        }
        // Everything the pool can answer for free, before a ~20 ms proof is scheduled for it. A
        // duplicate or a conflict never reaches the queue.
        if let Err(e) = self.mempool.precheck(&tx, self.hs.tip_ledger(), self.executor.as_ref()) {
            let a = admission::acceptance_for_pool(&e, tx.hash(), &mut self.refused);
            self.report(id, GossipOutcome::Report(a)).await;
            return Ok(());
        }
        self.verify_queue.push_back((tx, VerifySource::Gossip(id)));
        self.pump_verify();
        Ok(())
    }

    /// An RPC submission takes the same queue as a gossiped transaction, with the caller's oneshot
    /// in place of a message id. Not metered: that port is the operator's own, and it is already
    /// bounded by `rpc::RPC_MAX_BODY_BYTES`.
    async fn submit_tx(&mut self, tx: Transaction, reply: oneshot::Sender<Result<Hash, MempoolError>>) {
        let hash = tx.hash();
        let outcome = GossipOutcome::for_transaction(
            &tx,
            None,
            &mut self.refused,
            &self.limiter,
            self.verify_queue.len(),
            Instant::now(),
        );
        if let GossipOutcome::Report(a) = outcome {
            let _ = reply.send(Err(admission::rpc_refusal(a, &hash, &self.refused)));
            return;
        }
        // A pre-screen refusal is the caller's answer directly, so every error message a submitter
        // can hear is the one `Mempool::insert` always produced (`docs/rpc.md` quotes them). The
        // acceptance is discarded here — only its caching side effect matters, so a resubmission of
        // a permanently bad transaction is answered for free.
        if let Err(e) = self.mempool.precheck(&tx, self.hs.tip_ledger(), self.executor.as_ref()) {
            let _ = admission::acceptance_for_pool(&e, hash, &mut self.refused);
            let _ = reply.send(Err(e));
            return;
        }
        self.verify_queue.push_back((tx, VerifySource::Rpc(reply)));
        self.pump_verify();
    }

    async fn broadcast_status(&self) {
        self.net
            .broadcast(GossipMessage::Status(Status {
                height: self.hs.committed_height(),
                head_hash: self.hs.committed_hash(),
                view: self.hs.view(),
            }))
            .await;
    }

    async fn propose(&mut self, view: u64) -> Result<()> {
        let txs = self.mempool.candidates_within(self.hs.tip_ledger(), gas::MAX_BLOCK_TXS, gas::MAX_BLOCK_BYTES);
        match self.hs.propose(view, txs, now_ms()) {
            Ok(acts) => {
                self.last_block_at = Instant::now();
                self.handle_actions(acts).await
            }
            Err(ConsensusError::NotReady) => Ok(()),
            Err(ConsensusError::UnknownParent(h)) => {
                let acts = self.fetch_block(h).await;
                self.handle_actions(acts).await
            }
            Err(e) => {
                tracing::warn!("propose failed: {e}");
                Ok(())
            }
        }
    }

    async fn handle_actions(&mut self, actions: Vec<Action>) -> Result<()> {
        let mut queue: std::collections::VecDeque<Action> = actions.into();
        // One `on_message` can emit several `Commit` actions — a node catching up resolves a
        // run of orphans and commits in steps — but the replica has finished processing before
        // it hands the actions back, so `hs.committed_ledger()` is already the state after the
        // *last* of them. Persisting each batch separately would therefore pair early blocks
        // with a ledger that describes later ones. They are contiguous by construction, so the
        // fix is to write them as one commit, once, against the ledger that does describe them.
        let mut to_commit: Vec<CommittedBlock> = Vec::new();
        // Emitted immediately before the `Commit` carrying the epoch's first block, and written
        // in the same batch as it: a set persisted separately could be lost to a crash between
        // the two writes, and that epoch's QCs would be unverifiable on the next replay.
        let mut to_record: Vec<(u64, ValidatorSet)> = Vec::new();
        while let Some(a) = queue.pop_front() {
            match a {
                Action::PersistSafety(s) => self.storage.save_safety(&s)?,
                Action::Broadcast(m) | Action::SendTo(_, m) => {
                    self.net.broadcast(GossipMessage::Consensus(m)).await;
                }
                Action::Commit(blocks) => to_commit.extend(blocks),
                Action::RecordEpochSet(epoch, set) => {
                    tracing::info!("epoch {epoch} starts with {} validators", set.len());
                    to_record.push((epoch, set));
                }
                Action::ScheduleTimeout { view, duration } => {
                    self.timeout = Some((view, Instant::now() + duration));
                }
                Action::ReadyToPropose { view } => {
                    let at = (self.last_block_at + self.cfg.block_interval).max(Instant::now());
                    self.propose_at = Some((view, at));
                }
                Action::FetchBlock(h) => queue.extend(self.fetch_block(h).await),
            }
        }
        self.commit(to_commit, to_record).await
    }

    async fn commit(&mut self, blocks: Vec<CommittedBlock>, epoch_sets: Vec<(u64, ValidatorSet)>) -> Result<()> {
        if blocks.is_empty() {
            self.storage.commit(&[], self.hs.committed_ledger(), &epoch_sets, self.executor.as_ref())?;
            return Ok(());
        }
        let ledger = self.hs.committed_ledger().clone();
        self.storage.commit(&blocks, &ledger, &epoch_sets, self.executor.as_ref())?;
        for cb in &blocks {
            let included: Vec<Hash> = cb.block.transactions.iter().map(|tx| tx.hash()).collect();
            self.mempool.remove(&included);
            tracing::info!(
                "committed block {} view {} txs {} hash {:?}",
                cb.block.height(),
                cb.block.view(),
                cb.block.transactions.len(),
                cb.block.hash()
            );
        }
        self.mempool.prune(self.hs.tip_ledger());
        self.publish_heads(&blocks);
        self.warm_new_programs(&blocks);
        self.fetch_attempts.clear();
        Ok(())
    }

    /// One `newHeads` notification per committed block, in order — a light wallet tracking heads
    /// must not silently skip heights, so a commit of three blocks is three notifications and not
    /// one for the tip. `send` fails only when nobody is subscribed, which is the normal case.
    ///
    /// Called after `storage.commit` has returned, on both paths a block becomes committed by: a
    /// subscriber must never be told about a head this node could still lose. On the sync path
    /// that is before the replica is resumed, so a batch's heads go out in their own order and
    /// never behind a head the restarted replica commits.
    ///
    /// `view` is the *block's* view, which is what certified it. `shrugg_getHead` reports the
    /// node's current view instead — the same field, and for the tip usually the same number, but
    /// a notification is a statement about one block rather than about this node's clock.
    fn publish_heads(&self, blocks: &[CommittedBlock]) {
        for cb in blocks {
            let _ = self.heads.send(rpc::HeadSummary {
                height: cb.block.height(),
                hash: cb.block.hash().to_hex(),
                view: cb.block.view(),
            });
        }
    }

    /// Precompute verifier keys for programs deployed in `blocks`, off the node loop.
    fn warm_new_programs(&self, blocks: &[CommittedBlock]) {
        let ledger = self.hs.committed_ledger();
        let records: Vec<_> = blocks
            .iter()
            .flat_map(|cb| cb.block.transactions.iter())
            .filter_map(|tx| match &tx.action {
                shrugg_core::Action::Deploy { base_pc, words } => {
                    ledger.program(&shrugg_core::program::program_id(*base_pc, words)).cloned()
                }
                _ => None,
            })
            .collect();
        if records.is_empty() {
            return;
        }
        let ex = self.executor.clone();
        tokio::task::spawn_blocking(move || {
            for rec in records {
                let t = Instant::now();
                ex.warm(&rec);
                tracing::info!("verifier key ready for program {} ({:.1?})", rec.id, t.elapsed());
            }
        });
    }

    async fn on_command(&mut self, cmd: NodeCommand) -> Result<()> {
        match cmd {
            NodeCommand::SubmitTx { tx, reply } => self.submit_tx(tx, reply).await,
            NodeCommand::Peers { reply } => {
                let _ = reply.send(self.net.peers().await);
            }
            NodeCommand::Mint { to, amount, reply } => {
                let _ = reply.send(self.mint(to, amount).await);
            }
            NodeCommand::Epoch { reply } => {
                let tip = self.hs.tip_ledger();
                let _ = reply.send(rpc::EpochInfo {
                    epoch: tip.epoch(),
                    epoch_blocks: tip.epoch_blocks(),
                    current: self.hs.current_set().iter().map(|v| v.address()).collect(),
                    // What the register would produce if this epoch ended now; an empty
                    // derivation is reported as empty rather than as the carry-forward
                    // consensus would apply, because that is what the register says.
                    next: tip.derive_next_set().iter().map(|v| v.address()).collect(),
                });
            }
        }
        Ok(())
    }

    /// Testnet faucet: this node signs a `Mint` with its own key and submits it like any other
    /// transaction, so every node applies it through consensus.
    ///
    /// A mint is only admissible with a *validator's* signature (spec §6), so an observer cannot
    /// serve this at all — it has no key the ledger would accept, and forwarding to a peer would
    /// silently hand someone else's faucet the request. It says so instead.
    ///
    /// The note is sealed to `to` under a throwaway sender key: a faucet has no identity worth
    /// preserving and no reason to keep an outgoing-viewing record, so the `to_sender` half of
    /// the envelope is addressed to a key that is dropped on the next line and never recoverable.
    /// Only `to` can open the note, which is the whole intent.
    async fn mint(&mut self, to: ShieldedAddress, amount: u64) -> std::result::Result<Hash, String> {
        if !self.gs.faucet {
            return Err("faucet is disabled on this chain".into());
        }
        if !self.hs.is_validator() {
            return Err("faucet mints are signed by validators; ask a validator node".into());
        }
        if amount > FAUCET_MAX_UNITS {
            return Err(format!("mint of {amount} exceeds the faucet cap of {FAUCET_MAX_UNITS}"));
        }
        let key = Keypair::from_seed(self.cfg.seed).expect("seed validated at startup");
        let height = self.hs.tip_ledger().height();
        let note = Note::new(to.pk, [0; 8], amount, 0, height as u32);
        let throwaway = SpendKey::random().viewing_key();
        let envelope = shrugg_zkvm::address::seal_note(&throwaway, &to, &note, &TxKey::random())?;
        let tx = Transaction::mint(self.gs.chain_id, note.commitment(), envelope, amount, &key);
        let hash = self
            .mempool
            .insert(tx.clone(), self.hs.tip_ledger(), self.executor.as_ref())
            .map_err(|e| e.to_string())?;
        self.net.broadcast(GossipMessage::Transaction(tx)).await;
        Ok(hash)
    }

    async fn on_network_event(&mut self, ev: NetworkEvent) -> Result<()> {
        match ev {
            NetworkEvent::Listening(a) => tracing::info!("listening on {a}"),
            NetworkEvent::PeerConnected(p) => {
                self.peers.entry(p).or_default().connected = true;
                self.broadcast_status().await;
            }
            NetworkEvent::PeerDisconnected(p) => {
                self.peers.remove(&p);
                if self.sync_inflight.map(|s| s.0) == Some(p) {
                    self.sync_inflight = None;
                    // The peer we were waiting on is gone: go to another one now rather than
                    // sitting out the rest of the give-up window.
                    self.maybe_sync().await;
                }
            }
            // Every arm here reports exactly once, and this is the whole list: a consensus or status
            // message immediately, a transaction either immediately or on its verdict. An
            // undecodable message never gets this far — the network task reports that one itself.
            NetworkEvent::Gossip { from, msg, id } => match msg {
                GossipMessage::Consensus(m) => {
                    // Before handling, because a proposal's verification stays on this loop and the
                    // report must not queue behind it. `GossipOutcome::for_consensus` is this
                    // decision, spelled out and tested there.
                    self.report(id, GossipOutcome::for_consensus()).await;
                    self.on_consensus(m).await?
                }
                GossipMessage::Transaction(tx) => self.on_gossiped_tx(tx, id).await?,
                GossipMessage::Status(s) => {
                    self.report(id, GossipOutcome::for_consensus()).await;
                    let ahead = s.height > self.hs.committed_height() + 1;
                    self.peers.entry(from).or_default().status = Some(s);
                    if ahead && self.sync_inflight.is_none() {
                        self.maybe_sync().await;
                    }
                }
            },
            NetworkEvent::SyncRequest { peer, request, channel } => {
                let response = self.serve_sync(request);
                tracing::debug!("serving sync request from {peer}");
                self.net.send_sync_response(channel, response).await;
            }
            NetworkEvent::SyncResponse { peer, request_id, response } => {
                self.on_sync_response(peer, request_id, response).await?;
            }
            NetworkEvent::SyncFailed { peer, request_id, error } => {
                let was_batch = self.sync_inflight.map(|s| s.1) == Some(request_id);
                if was_batch {
                    let elapsed = self.sync_inflight.map(|(_, _, at)| at.elapsed().as_millis() as u64).unwrap_or(0);
                    self.sync_failures += 1;
                    self.sync_inflight = None;
                    // Halve the batch, down to a single block. A batch too big for the wire fails
                    // identically every time it is retried at the same size — which is how a node
                    // that fell behind chain 8's first 1.3 MB transfer proof stopped dead at that
                    // height across restarts, asking four peers in turn for the same 100 blocks
                    // and getting `Eof { name: "bytes", .. }` back from each. At `warn` because at
                    // `debug` an operator on the default `RUST_LOG=info` saw nothing at all.
                    self.sync_batch = (self.sync_batch / 2).max(SYNC_BATCH_MIN);
                    tracing::warn!(
                        %peer, ?request_id, elapsed_ms = elapsed, failures = self.sync_failures,
                        next_batch = self.sync_batch,
                        "sync batch request failed: {error}"
                    );
                } else {
                    tracing::info!(%peer, ?request_id, "sync request failed: {error}");
                }
                self.retry_fetch(request_id).await?;
                if was_batch {
                    // Straight to another peer rather than waiting out the 2 s tick.
                    self.sync_from(Some(peer)).await;
                }
            }
        }
        Ok(())
    }

    async fn on_consensus(&mut self, m: ConsensusMessage) -> Result<()> {
        let is_proposal = matches!(m, ConsensusMessage::Proposal(_));
        match self.hs.on_message(m, now_ms()) {
            Ok(acts) => {
                if is_proposal {
                    // Pace proposals from the last block seen, whoever proposed it.
                    self.last_block_at = Instant::now();
                }
                self.handle_actions(acts).await
            }
            Err(ConsensusError::NotLeader) | Err(ConsensusError::Stale(_)) => Ok(()),
            Err(ConsensusError::UnknownParent(h)) => {
                // Far behind: batch-sync committed blocks instead of walking parents one by one.
                let behind = self.best_peer_height() > self.hs.committed_height() + 2;
                if behind {
                    tracing::debug!("proposal with unknown parent {h:?}; batch syncing");
                    self.maybe_sync().await;
                } else {
                    tracing::debug!("proposal with unknown parent {h:?}; fetching");
                    let acts = self.fetch_block(h).await;
                    self.handle_actions(acts).await?;
                }
                Ok(())
            }
            Err(e) => {
                tracing::warn!("rejected consensus message: {e}");
                Ok(())
            }
        }
    }

    fn serve_sync(&self, req: SyncRequest) -> SyncResponse {
        match req {
            SyncRequest::Blocks { from_height, max } => {
                let max = max.min(SYNC_BATCH);
                // Lazy: a batch that fills up on bytes must not have read the rest from RocksDB.
                let heights = from_height..from_height.saturating_add(max as u64);
                let blocks = heights.map_while(|h| self.storage.committed_block(h).ok().flatten());
                SyncResponse::Blocks(fill_sync_batch(blocks, serve_sync_budget()))
            }
            SyncRequest::BlockByHash(h) => {
                let b = self.hs.block(&h).cloned().or_else(|| self.storage.block_by_hash(&h).ok().flatten());
                SyncResponse::Block(b)
            }
        }
    }

    /// Ask a peer for a block by hash. Peers are tried in turn: first those that have
    /// advertised a status at or above our height (they are on our chain and current),
    /// then any other; a peer that answers "not found" or fails is not asked again for
    /// the same hash. Gives up after `MAX_FETCH_ATTEMPTS`.
    async fn fetch_block(&mut self, h: Hash) -> Vec<Action> {
        if self.hs.has_block(&h) || self.fetch_inflight.values().any(|x| *x == h) {
            return Vec::new();
        }
        let entry = self.fetch_attempts.entry(h).or_insert((0, Vec::new()));
        if entry.0 >= MAX_FETCH_ATTEMPTS {
            return self.unobtainable(h);
        }
        let asked = entry.1.clone();
        let my_height = self.hs.committed_height();
        let mut candidates: Vec<PeerId> = self
            .peers
            .iter()
            // Connected, not yet asked, and on our chain at or past our height. A by-hash fetch
            // goes over a connection for the same reason a batch request does (see [`Peer`]).
            .filter(|(p, peer)| {
                peer.connected
                    && !asked.contains(p)
                    && peer.status.as_ref().map(|s| s.height >= my_height).unwrap_or(false)
            })
            .map(|(p, _)| *p)
            .collect();
        if candidates.is_empty() {
            // Any connected peer, even one that has not told us its height.
            candidates = self
                .peers
                .iter()
                .filter(|(p, peer)| peer.connected && !asked.contains(p))
                .map(|(p, _)| *p)
                .collect();
        }
        let Some(peer) = candidates.first().copied() else {
            tracing::debug!("no peer left to fetch block {h:?} from");
            return self.unobtainable(h);
        };
        if let Some(id) = self.net.send_sync_request(peer, SyncRequest::BlockByHash(h)).await {
            self.fetch_inflight.insert(id, h);
            let e = self.fetch_attempts.get_mut(&h).expect("inserted above");
            e.0 += 1;
            e.1.push(peer);
        }
        Vec::new()
    }

    /// No peer can supply block `h`. If consensus is waiting on it as the high QC's block,
    /// let the replica fall back to the committed head so it can propose again.
    fn unobtainable(&mut self, h: Hash) -> Vec<Action> {
        self.hs.fallback_high_qc(&h)
    }

    /// A by-hash fetch came back empty or failed: try the next peer.
    async fn retry_fetch(&mut self, request_id: libp2p::request_response::OutboundRequestId) -> Result<()> {
        if let Some(h) = self.fetch_inflight.remove(&request_id) {
            if !self.hs.has_block(&h) {
                let acts = self.fetch_block(h).await;
                self.handle_actions(acts).await?;
            }
        }
        Ok(())
    }

    fn best_peer_height(&self) -> u64 {
        self.peers.values().filter_map(|p| p.status.as_ref()).map(|s| s.height).max().unwrap_or(0)
    }

    async fn maybe_sync(&mut self) {
        self.sync_from(None).await
    }

    /// Ask the best peer ahead of us for the next batch of committed blocks.
    ///
    /// `skip` is a peer not to choose — the one whose request just failed, so a failure moves to
    /// another peer instead of re-picking the same one by the same `max_by_key`. On chain 8 the
    /// picker chose the same unreachable peer six times in two seconds.
    ///
    /// Only *connected* peers are candidates; see [`Peer`].
    async fn sync_from(&mut self, skip: Option<PeerId>) {
        if let Some((peer, id, started)) = self.sync_inflight {
            if started.elapsed() < SYNC_GIVE_UP {
                return;
            }
            // Past the wire's own timeout, so the request is gone rather than merely slow.
            tracing::warn!(
                %peer, ?id, elapsed_ms = started.elapsed().as_millis() as u64,
                "sync request abandoned after the wire timeout; trying another peer"
            );
            self.sync_failures += 1;
            self.sync_inflight = None;
        }
        let my_height = self.hs.committed_height();
        let best = self
            .peers
            .iter()
            .filter(|(p, peer)| peer.connected && Some(**p) != skip)
            .filter_map(|(p, peer)| peer.status.as_ref().map(|s| (*p, s.height)))
            .filter(|(_, h)| *h > my_height)
            .max_by_key(|(_, h)| *h);
        let Some((peer, _)) = best else { return };
        let req = SyncRequest::Blocks { from_height: my_height + 1, max: self.sync_batch };
        if let Some(id) = self.net.send_sync_request(peer, req).await {
            self.sync_inflight = Some((peer, id, Instant::now()));
        }
    }

    async fn on_sync_response(
        &mut self,
        peer: PeerId,
        request_id: libp2p::request_response::OutboundRequestId,
        response: SyncResponse,
    ) -> Result<()> {
        match response {
            SyncResponse::Block(Some(b)) => {
                if let Some(h) = self.fetch_inflight.remove(&request_id) {
                    self.fetch_attempts.remove(&h);
                }
                self.on_consensus(ConsensusMessage::Proposal(b)).await?;
            }
            SyncResponse::Block(None) => {
                tracing::debug!("peer {peer} does not have a requested block; trying another");
                self.retry_fetch(request_id).await?;
            }
            SyncResponse::Blocks(blocks) => {
                let current = self.sync_inflight.map(|s| s.1) == Some(request_id);
                let elapsed = self.sync_inflight.map(|(_, _, at)| at.elapsed().as_millis() as u64);
                let my_height = self.hs.committed_height();
                let d = batch_decision(blocks.first().map(|b| b.block.height()), my_height, current);
                if d.clear_inflight {
                    self.sync_inflight = None;
                }
                if !d.apply {
                    tracing::info!(
                        %peer, ?request_id, current_request = current, ?elapsed,
                        first = ?blocks.first().map(|b| b.block.height()),
                        my_height, blocks = blocks.len(),
                        "ignoring a sync batch that does not start at our next height"
                    );
                    return Ok(());
                }
                if d.late {
                    self.sync_late_batches += 1;
                    tracing::info!(
                        %peer, ?request_id, late_batches = self.sync_late_batches, blocks = blocks.len(),
                        "applying a sync batch that arrived after its request was abandoned"
                    );
                }
                let n = blocks.len();
                if let Err(e) = self.apply_synced(blocks).await {
                    // Blocks we asked for and could not use: a peer on a different chain, or a
                    // damaged batch. It cost us a round trip either way.
                    self.sync_failures += 1;
                    tracing::warn!(%peer, failures = self.sync_failures, "sync batch rejected: {e}");
                    self.peers.remove(&peer);
                    return Ok(());
                }
                // A batch got through, so the wire carries this size: ask for more next time, but
                // *double* rather than snapping straight back to full. Against a peer still on the
                // old build — whose block-only budget puts a 13.57 MiB response on the wire for a
                // 100-block request — snapping back would oscillate full/rejected/halved/full for
                // as long as we sync from it, paying a rejected multi-megabyte download every
                // other round trip. Doubling settles at the largest size that peer can actually
                // deliver.
                //
                // The server caps by bytes as well, so a batch can be shorter than we asked for
                // without meaning the chain has run out — follow up on any batch that moved us
                // while a peer is still ahead.
                self.sync_batch = (self.sync_batch * 2).min(SYNC_BATCH);
                if n > 0 && self.best_peer_height() > self.hs.committed_height() {
                    self.maybe_sync().await;
                }
            }
        }
        Ok(())
    }

    /// Verify and persist committed blocks received from a peer, then rebuild
    /// the consensus replica on the new head.
    ///
    /// Sync crosses epoch boundaries like consensus does and by the same rule (spec §8): at the
    /// first block of an epoch the set is derived from the register as of its parent, checked
    /// against any set already known for that epoch, and recorded — because every QC here is
    /// verified against the set of *its own* block's epoch, and because a node that synced past
    /// a boundary without recording the set would have nothing to verify that epoch with after a
    /// restart. Every block verified here is a block this node holds, so nothing in this path
    /// relies on the replica's weaker "a QC for a block we do not have is counted in the current
    /// set" fallback.
    async fn apply_synced(&mut self, blocks: Vec<CommittedBlock>) -> Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let mut ledger: Ledger = self.hs.committed_ledger().clone();
        let mut head_hash = self.hs.committed_hash();
        let mut head_height = self.hs.committed_height();
        let epoch_blocks = self.gs.epoch_blocks.max(1);
        let mut sets = self.hs.epoch_sets().clone();
        let mut recorded: Vec<(u64, ValidatorSet)> = Vec::new();
        let mut accepted = Vec::new();
        for cb in blocks {
            let b = &cb.block;
            if b.height() != head_height + 1 || b.parent() != head_hash {
                anyhow::bail!("non-contiguous block {}", b.height());
            }
            if cb.qc.block_hash != b.hash() || cb.qc.view != b.view() {
                anyhow::bail!("qc does not certify block {}", b.height());
            }
            let epoch = b.height() / epoch_blocks;
            if b.height() % epoch_blocks == 0 && b.height() > 0 {
                // `ledger` is the state after this block's parent, which is the last block of
                // the previous epoch: exactly what the set is derived from.
                let mut derived = ledger.derive_next_set();
                if derived.is_empty() {
                    // The same carry-forward consensus does when every validator has unbonded
                    // below the minimum: an epoch with no leader is a halt nothing can end.
                    let Some(previous) = sets.get(epoch - 1) else {
                        anyhow::bail!("epoch {} derives an empty set and epoch {} is unknown", epoch, epoch - 1);
                    };
                    derived = previous.clone();
                }
                match sets.get(epoch) {
                    Some(known) if *known == derived => {}
                    Some(_) => anyhow::bail!("block {} starts epoch {epoch} with a set we do not derive", b.height()),
                    None => {
                        sets.insert(epoch, derived.clone());
                        recorded.push((epoch, derived));
                    }
                }
            }
            let Some(set) = sets.get(epoch) else {
                anyhow::bail!("no validator set for epoch {epoch} (block {})", b.height());
            };
            if !cb.qc.verify(set, &self.gs.hash()) {
                anyhow::bail!("invalid qc for block {} in epoch {epoch}", b.height());
            }
            if b.proposer() != set.leader(b.view()) {
                anyhow::bail!("wrong leader for block {} in epoch {epoch}", b.height());
            }
            let receipts = ledger.apply_block(b, self.executor.as_ref())?;
            if receipts != cb.receipts {
                anyhow::bail!("receipts for block {} do not match our execution", b.height());
            }
            head_hash = b.hash();
            head_height = b.height();
            // The notes this block made the ledger create, from our own execution rather than
            // from the peer's copy (which the wire does not carry).
            let deposits = ledger.take_deposits();
            accepted.push(CommittedBlock { receipts, deposits, ..cb });
        }
        self.storage.commit(&accepted, &ledger, &recorded, self.executor.as_ref())?;
        for cb in &accepted {
            tracing::info!("synced block {} ({} txs)", cb.block.height(), cb.block.transactions.len());
            let included: Vec<Hash> = cb.block.transactions.iter().map(|tx| tx.hash()).collect();
            self.mempool.remove(&included);
        }
        self.publish_heads(&accepted);
        let head = accepted.last().expect("non-empty");
        let mut ccfg = ConsensusConfig::new(self.gs.chain_id, self.gs.validators.clone(), self.gs.hash());
        ccfg.epoch_blocks = self.gs.epoch_blocks;
        ccfg.base_timeout = self.cfg.base_timeout;
        ccfg.max_timeout = self.cfg.max_timeout;
        let signer = if self.hs.is_validator() { Some(Keypair::from_seed(self.cfg.seed)?) } else { None };
        let safety = self.hs.safety_state();
        self.hs = HotStuff::resume(
            ccfg,
            signer,
            head.block.clone(),
            head.qc.clone(),
            ledger,
            Some(safety),
            sets,
            self.executor.clone(),
        );
        self.timeout = None;
        self.propose_at = None;
        let acts = self.hs.start();
        self.handle_actions(acts).await?;
        self.mempool.prune(self.hs.tip_ledger());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fixtures::{alloc_note, bundle_fee, bundle_tx, genesis_of, key, make_block_voted};
    use shrugg_core::confidential::StubExecutor;
    use shrugg_core::consensus::{EpochSets, HotStuff};
    use shrugg_core::genesis::GenesisState;
    use shrugg_core::{Block, BlockHeader, QuorumCertificate, Vote};

    /// A one-validator chain with two-block epochs, committed past its first boundary: blocks 1
    /// (epoch 0) and 2 (the first block of epoch 1, whose set is recorded with it).
    fn chain_past_a_boundary() -> (tempfile::TempDir, Storage, GenesisState, Ledger) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let gs = genesis_of(7, &[&key(1)], vec![alloc_note(20, 5 * shrugg_core::UNITS_PER_SHRUGG)], 2);
        storage.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();

        ledger.set_height(1);
        let tx = bundle_tx(&ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        let b1 = make_block_voted(&gs.block, &mut ledger, vec![tx], &key(1), &[&key(1)]);
        storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

        let epoch1 = ledger.derive_next_set();
        ledger.set_height(2);
        let tx = bundle_tx(&ledger, [[5; 8], [6; 8]], [[7; 8], [8; 8]], bundle_fee());
        let b2 = make_block_voted(&b1.block, &mut ledger, vec![tx], &key(1), &[&key(1)]);
        storage.commit(std::slice::from_ref(&b2), &ledger, &[(1, epoch1)], &StubExecutor).unwrap();
        (dir, storage, gs, ledger)
    }

    /// The next block of the epoch the chain is in, as a peer would propose it: certified parent,
    /// increasing view, and the state root the ledger really produces.
    fn next_block(head: &Block, ledger: &Ledger, k: &shrugg_core::Keypair) -> Block {
        let height = head.height() + 1;
        let mut after = ledger.clone();
        after.set_height(height);
        after.set_timestamp_ms(height);
        after.apply_transactions(&[], &k.address(), &StubExecutor).unwrap();
        after.record_anchor(height);
        let header = BlockHeader {
            height,
            view: head.view() + 1,
            parent: head.hash(),
            proposer: k.public_key().clone(),
            timestamp_ms: height,
            tx_root: Block::tx_root(&[]),
            state_root: after.state_root(),
            justify: QuorumCertificate {
                view: head.view(),
                block_hash: head.hash(),
                votes: vec![Vote::sign(head.view(), head.hash(), k)],
            },
        };
        Block::sign(header, Vec::new(), k)
    }

    /// The restart this task exists to fix: a node whose head is past an epoch boundary comes
    /// back up with the set that epoch runs with, and can take part in it. Resuming from the
    /// genesis set alone — what the node did before the sets were persisted — leaves it unable
    /// to place a block of its own epoch at all.
    #[test]
    fn a_node_resuming_past_an_epoch_boundary_accepts_a_block_of_the_current_epoch() {
        let (_d, storage, gs, ledger) = chain_past_a_boundary();
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let head = storage.head_block().unwrap();
        assert_eq!(head.height(), 2, "the head is the first block of epoch 1");
        let proposal = next_block(&head, &ledger, &key(1));

        let mut hs = resume_consensus(
            &storage,
            &gs,
            Some(key(1)),
            Duration::from_secs(1),
            Duration::from_secs(8),
            executor.clone(),
        )
        .unwrap();
        assert_eq!(hs.committed_height(), 2);
        assert_eq!(hs.epoch_sets().known().count(), 2, "epoch 0 from genesis, epoch 1 from the commit");
        hs.on_proposal(proposal.clone(), 3).expect("a block of the epoch the node resumed into");

        // The same node without the recorded sets: it has no set for epoch 1, so the block of
        // its own epoch is one it cannot even place.
        let mut ccfg = ConsensusConfig::new(gs.chain_id, gs.validators.clone(), gs.hash());
        ccfg.epoch_blocks = gs.epoch_blocks;
        let mut blind = HotStuff::resume(
            ccfg,
            Some(key(1)),
            head,
            storage.head_qc().unwrap(),
            reload_ledger(&storage, &gs, executor.as_ref()).unwrap(),
            None,
            EpochSets::new(gs.validators.clone()),
            executor,
        );
        assert_eq!(blind.on_proposal(proposal, 3), Err(ConsensusError::UnknownEpochSet(1)));
    }

    // ------------------------------------------------------- sync batch wire budget
    //
    // Chain 8 stopped a late-joining node dead at the height of the chain's first
    // constraint-set-5 transfer: every peer asked for the 100-block batch containing it answered
    // with a response the reader cut at its 10 MiB limit, which then failed to decode
    // (`Eof { name: "bytes", .. }`). The server believed the batch was inside its 8 MiB budget,
    // because that budget counted `cb.block.encode()` and ignored the QC certifying the block —
    // on an 18-validator chain, half of what goes on the wire.

    /// `n` votes over `hash`, by the first `n` of `ks`.
    fn votes_of(view: u64, hash: Hash, ks: &[Keypair], n: usize) -> QuorumCertificate {
        QuorumCertificate { view, block_hash: hash, votes: ks[..n].iter().map(|k| Vote::sign(view, hash, k)).collect() }
    }

    /// A committed block shaped like chain 8's: `votes` votes in both the header's `justify` QC and
    /// the QC that certifies it, carrying `txs`.
    fn sized_block(height: u64, ks: &[Keypair], votes: usize, txs: Vec<Transaction>) -> CommittedBlock {
        let parent = Hash::digest(&height.to_be_bytes());
        let header = BlockHeader {
            height,
            view: height,
            parent,
            proposer: ks[0].public_key().clone(),
            timestamp_ms: height,
            tx_root: Block::tx_root(&txs),
            state_root: parent,
            justify: votes_of(height.saturating_sub(1), parent, ks, votes),
        };
        let block = Block::sign(header, txs, &ks[0]);
        let hash = block.hash();
        CommittedBlock { block, qc: votes_of(height, hash, ks, votes), receipts: Vec::new(), deposits: Vec::new() }
    }

    fn validators(n: u8) -> Vec<Keypair> {
        (1..=n).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect()
    }

    /// A shielded transaction carrying a `proof_bytes`-byte proof, standing in for a real one.
    fn fat_tx(proof_bytes: usize) -> Transaction {
        let bundle = shrugg_core::notes::Bundle {
            anchor: [1; 8],
            nullifiers: [[2; 8], [3; 8]],
            commitments: [[4; 8], [5; 8]],
            fee: 1,
            burn: 0,
            asset: 0,
            time: 1,
            envelopes: [crate::storage::fixtures::env(1), crate::storage::fixtures::env(2)],
            proof: vec![7u8; proof_bytes],
        };
        Transaction::shielded(7, bundle, shrugg_core::Action::None)
    }

    fn wire_size(blocks: &[CommittedBlock]) -> u64 {
        network::codec::cbor_size(&SyncResponse::Blocks(blocks.to_vec())).unwrap() as u64
    }

    /// The measurement that explains the stall: on an 18-validator chain a batch of 100 *empty*
    /// blocks is over 13 MiB on the wire, while the retired budget — `block.encode()` only, capped
    /// at 8 MiB — saw less than 7 MiB of it and let it go.
    #[test]
    fn a_hundred_empty_chain_8_blocks_overrun_the_reader_limit_libp2p_would_have_used() {
        let ks = validators(18);
        let blocks: Vec<CommittedBlock> = (1..=100).map(|h| sized_block(h, &ks, 18, vec![])).collect();
        let on_the_wire = wire_size(&blocks);
        // The limit libp2p's own `cbor::Behaviour` would have applied, and truncated at.
        const LIBP2P_DEFAULT_RESPONSE_MAXIMUM: u64 = 10 << 20;
        assert!(
            on_the_wire > LIBP2P_DEFAULT_RESPONSE_MAXIMUM,
            "expected a 100-block batch to overrun 10 MiB, measured {on_the_wire} B"
        );
        let old_budget_would_have_counted: u64 = blocks.iter().map(|b| b.block.encode().len() as u64).sum();
        assert!(
            old_budget_would_have_counted < 8 << 20,
            "the old 8 MiB budget should have thought this batch fit: {old_budget_would_have_counted} B"
        );
    }

    #[test]
    fn the_batch_budget_is_at_most_half_the_reader_limit() {
        assert!(2 * network::SYNC_MAX_WIRE_BYTES <= network::SYNC_RESPONSE_WIRE_LIMIT);
        assert_eq!(serve_sync_budget(), network::SYNC_MAX_WIRE_BYTES);
    }

    #[test]
    fn a_capped_batch_of_chain_8_blocks_fits_on_the_wire() {
        let ks = validators(18);
        let blocks: Vec<CommittedBlock> = (1..=SYNC_BATCH as u64).map(|h| sized_block(h, &ks, 18, vec![])).collect();
        let batch = fill_sync_batch(blocks, serve_sync_budget());
        assert!(batch.len() < SYNC_BATCH as usize, "the budget should have cut the batch short");
        assert!(!batch.is_empty());
        let on_the_wire = wire_size(&batch);
        assert!(
            on_the_wire <= network::SYNC_RESPONSE_WIRE_LIMIT,
            "a capped batch must be readable: {on_the_wire} B over {} B",
            network::SYNC_RESPONSE_WIRE_LIMIT
        );
        // Contiguous from the first block, so the client can apply it.
        for (i, cb) in batch.iter().enumerate() {
            assert_eq!(cb.block.height(), 1 + i as u64);
        }
    }

    /// The worst block the consensus rules admit: `MAX_BLOCK_BYTES` of transactions — two proofs at
    /// `MAX_PROOF_BYTES` — under 18-validator QCs. It has to be servable on its own, because a node
    /// stuck behind it has no other way past it, and readable, or the reader limit is the new wall.
    #[test]
    fn the_largest_admissible_block_is_servable_and_readable_alone() {
        let ks = validators(18);
        let txs = vec![fat_tx(gas::MAX_PROOF_BYTES), fat_tx(gas::MAX_PROOF_BYTES)];
        let tx_bytes: usize = txs.iter().map(|t| bincode::serialize(t).unwrap().len()).sum();
        assert!(tx_bytes >= gas::MAX_BLOCK_BYTES / 2, "the fixture should be a fat block: {tx_bytes} B");
        let block = sized_block(1, &ks, 18, txs);

        let batch = fill_sync_batch(vec![block], serve_sync_budget());
        assert_eq!(batch.len(), 1, "a fat block must never be dropped from an empty batch");
        let on_the_wire = wire_size(&batch);
        assert!(
            on_the_wire <= network::SYNC_RESPONSE_WIRE_LIMIT,
            "the largest admissible block must be readable: {on_the_wire} B over {} B",
            network::SYNC_RESPONSE_WIRE_LIMIT
        );
    }

    /// A block over the budget ends the batch rather than joining it — but only once something is
    /// in the batch already.
    #[test]
    fn a_block_over_the_budget_ends_the_batch_it_cannot_join() {
        let ks = validators(4);
        let small = sized_block(1, &ks, 4, vec![]);
        let fat = sized_block(2, &ks, 4, vec![fat_tx(gas::MAX_PROOF_BYTES)]);
        let tiny_budget = committed_block_wire_size(&small) + 1;
        let batch = fill_sync_batch(vec![small, fat], tiny_budget);
        assert_eq!(batch.len(), 1, "the fat block should not have been admitted over the budget");
        assert_eq!(batch[0].block.height(), 1);
    }

    /// A batch is charged for the whole `CommittedBlock`, not just its block: the certifying QC is
    /// most of an empty block on a large validator set, and missing it is what let batches overrun.
    #[test]
    fn the_wire_size_of_a_block_counts_its_certifying_qc() {
        let ks = validators(18);
        let cb = sized_block(1, &ks, 18, vec![]);
        let counted = committed_block_wire_size(&cb);
        let block_only = cb.block.encode().len() as u64;
        assert!(
            counted > block_only + (60 << 10),
            "an 18-vote QC is ~68 KB and must be charged for: counted {counted} B against {block_only} B of block"
        );
    }

    #[test]
    fn the_client_batch_halves_toward_one_and_never_below() {
        let mut batch = SYNC_BATCH;
        let mut seen = vec![batch];
        for _ in 0..10 {
            batch = (batch / 2).max(SYNC_BATCH_MIN);
            seen.push(batch);
        }
        assert_eq!(&seen[..4], &[100, 50, 25, 12]);
        assert_eq!(*seen.last().unwrap(), SYNC_BATCH_MIN);
        assert!(seen.iter().all(|b| *b >= 1));
    }

    /// After a success the batch *doubles* rather than snapping back to full.
    ///
    /// Snapping back oscillated against a peer still on the old build, whose block-only budget puts
    /// a 13.57 MiB response on the wire for a 100-block request: full, rejected, halved, succeeds,
    /// full again — paying a rejected multi-megabyte download every other round trip for as long as
    /// we sync from it. Doubling settles at the largest size that peer can deliver.
    #[test]
    fn the_client_batch_grows_back_geometrically_and_stops_at_full() {
        let grow = |b: u32| (b * 2).min(SYNC_BATCH);
        assert_eq!(grow(SYNC_BATCH_MIN), 2);
        assert_eq!(grow(25), 50);
        // Never past the ceiling, from either side of it.
        assert_eq!(grow(50), SYNC_BATCH);
        assert_eq!(grow(SYNC_BATCH), SYNC_BATCH);

        // A peer that can serve 25 but not 50: halving after each failure and doubling after each
        // success settles on 25 rather than retrying 100 forever.
        let mut batch = SYNC_BATCH;
        let deliverable = 25;
        let mut asked = Vec::new();
        for _ in 0..8 {
            asked.push(batch);
            batch = if batch > deliverable { (batch / 2).max(SYNC_BATCH_MIN) } else { grow(batch) };
        }
        // It reaches the deliverable size and then alternates 25/50 — never back to 100.
        assert_eq!(&asked[..3], &[100, 50, 25]);
        assert!(asked[3..].iter().all(|b| *b <= 50), "must not snap back to a full batch: {asked:?}");
        assert!(asked[3..].contains(&deliverable));
    }

    /// A late but usable batch is applied, counted as late rather than as a failure, and — the fix —
    /// leaves the in-flight slot alone.
    ///
    /// When the give-up fires the node sends a replacement and records it. If the abandoned
    /// request's answer then arrives and is applied, clearing the slot would forget that live
    /// replacement: the follow-up would put a third request on the wire and the replacement's
    /// answer, up to a full batch, would arrive orphaned.
    #[test]
    fn a_late_acceptance_applies_the_batch_and_leaves_the_live_replacement_recorded() {
        let d = batch_decision(Some(301), 300, false);
        assert!(d.apply, "the blocks continue our chain, whoever asked for them");
        assert!(d.late, "counted as late, not as a failure");
        assert!(!d.clear_inflight, "the replacement request is still on the wire");
    }

    /// Answering the request the slot holds frees it, and is not late.
    #[test]
    fn the_current_requests_answer_frees_the_slot() {
        let d = batch_decision(Some(301), 300, true);
        assert!(d.apply);
        assert!(!d.late);
        assert!(d.clear_inflight);
    }

    /// An unusable response frees the slot only when it is the one the slot holds — otherwise it is
    /// a stale answer to a request we already gave up on, and the live one must survive it.
    #[test]
    fn an_unusable_batch_never_takes_the_live_request_with_it() {
        for first in [None, Some(300u64), Some(302), Some(250)] {
            let stale = batch_decision(first, 300, false);
            assert!(!stale.apply, "{first:?}");
            assert!(!stale.late, "an unapplied batch is not a late batch: {first:?}");
            assert!(!stale.clear_inflight, "a stale answer must not free the live slot: {first:?}");

            let current = batch_decision(first, 300, true);
            assert!(!current.apply, "{first:?}");
            assert!(current.clear_inflight, "the slot's own answer frees it even when unusable: {first:?}");
        }
    }

    // ------------------------------------------------- the response-acceptance rule
    //
    // A batch is judged by what it holds, not by which request asked for it. The node used to drop
    // any response whose id was not the current one, so a batch that arrived after its own 10 s
    // give-up had re-requested the same range was thrown away — and on a 1-vCPU peer serving 100
    // blocks, most of them did.

    /// Whether a batch would be applied, over the shipped decision.
    fn accepts(first_height: Option<u64>, my_height: u64) -> bool {
        batch_decision(first_height, my_height, true).apply
    }

    #[test]
    fn a_batch_starting_at_our_next_height_is_accepted_however_late() {
        assert!(accepts(Some(301), 300));
    }

    #[test]
    fn a_batch_that_is_behind_or_overlaps_what_we_already_have_is_ignored() {
        // Applied from another response while this one was in flight.
        assert!(!accepts(Some(301), 400));
        // Starts at a height we already hold, so it would not be contiguous.
        assert!(!accepts(Some(300), 300));
    }

    #[test]
    fn a_batch_that_skips_a_height_is_ignored() {
        assert!(!accepts(Some(302), 300));
    }

    #[test]
    fn an_empty_batch_is_not_progress() {
        assert!(!accepts(None, 300));
    }

    /// The invariant the stall turned on: a give-up shorter than the wire's timeout abandons live
    /// requests and then discards their answers.
    #[test]
    fn the_client_give_up_is_not_shorter_than_the_wire_timeout() {
        assert!(SYNC_GIVE_UP >= network::SYNC_REQUEST_TIMEOUT);
    }

    // ------------------------------------- gossip validation: one acceptance per delivery
    //
    // With `validate_messages()` on, gossipsub holds every delivered message until this node
    // reports on it, and an unreported message is one this node silently stops forwarding for
    // everyone. So the decision path has to name exactly one acceptance on every path, including
    // the ones that never reach a proof.

    /// A distinct shielded transfer per `tag`. Nothing here verifies a proof, so the bytes only
    /// have to differ.
    fn transfer(tag: u8) -> Transaction {
        let n = tag as u32;
        let bundle = shrugg_core::notes::Bundle {
            anchor: [n; 8],
            nullifiers: [[n + 10; 8], [n + 20; 8]],
            commitments: [[n + 30; 8], [n + 40; 8]],
            fee: 1,
            burn: 0,
            asset: 0,
            time: 1,
            envelopes: [crate::storage::fixtures::env(tag), crate::storage::fixtures::env(tag.wrapping_add(1))],
            proof: vec![tag; 32],
        };
        Transaction::shielded(7, bundle, shrugg_core::Action::None)
    }

    #[test]
    fn every_gossip_outcome_names_exactly_one_acceptance() {
        use crate::admission::{Acceptance, GossipOutcome, PeerLimiter, RefusedCache, TokenBucket, MAX_VERIFY_QUEUE};
        let mut refused = RefusedCache::new(4);
        let limiter = PeerLimiter::new(1, 1.0);
        // One forwarding peer's bucket, as it is held on `node::Peer::tx_bucket`.
        let mut bucket = TokenBucket::default();
        let t = Instant::now();
        let tx = transfer(1);
        refused.insert(tx.hash(), shrugg_core::TxError::BadDigest);

        // A consensus or status message is accepted at once — this node does not validate them at
        // the application level, exactly as before validate_messages() was turned on.
        assert_eq!(GossipOutcome::for_consensus(), GossipOutcome::Report(Acceptance::Accept));
        // A transaction already refused here is rejected without any verification.
        assert_eq!(
            GossipOutcome::for_transaction(&tx, Some(&mut bucket), &mut refused, &limiter, 0, t),
            GossipOutcome::Report(Acceptance::Reject)
        );
        // A fresh one is queued (and the caller must report when the verdict lands).
        let fresh = transfer(2);
        assert_eq!(
            GossipOutcome::for_transaction(&fresh, Some(&mut bucket), &mut refused, &limiter, 0, t),
            GossipOutcome::Verify
        );
        // The same *forwarder's* next one is over the rate limit: ignored, not rejected — an honest
        // peer in a burst must not be penalised.
        assert_eq!(
            GossipOutcome::for_transaction(&fresh, Some(&mut bucket), &mut refused, &limiter, 0, t),
            GossipOutcome::Report(Acceptance::Ignore)
        );
        // A different forwarder has its own bucket, because it has its own `node::Peer`.
        let mut other = TokenBucket::default();
        assert_eq!(
            GossipOutcome::for_transaction(&fresh, Some(&mut other), &mut refused, &limiter, 0, t),
            GossipOutcome::Verify
        );
        // And a full queue sheds the same way (no bucket: this is the RPC path).
        assert_eq!(
            GossipOutcome::for_transaction(&fresh, None, &mut refused, &limiter, MAX_VERIFY_QUEUE, t),
            GossipOutcome::Report(Acceptance::Ignore)
        );
        // The refused cache is consulted *before* the bucket, so a peer flooding one known-bad
        // transaction never spends an allowance it could have used on a good one — and the queue
        // depth last, so a full queue does not mask a free refusal.
        assert_eq!(
            GossipOutcome::for_transaction(&tx, Some(&mut TokenBucket::default()), &mut refused, &limiter, MAX_VERIFY_QUEUE, t),
            GossipOutcome::Report(Acceptance::Reject)
        );
    }

    /// A verdict decides the acceptance, and only a permanent one reaches the cache.
    #[test]
    fn a_verdict_reports_and_caches_by_permanence() {
        use crate::admission::{acceptance_for, Acceptance, RefusedCache};
        use shrugg_core::TxError;
        let mut refused = RefusedCache::new(8);
        assert_eq!(acceptance_for(&Ok(()), Hash::ZERO, &mut refused), Acceptance::Accept);
        assert_eq!(refused.len(), 0);
        assert_eq!(
            acceptance_for(&Err(TxError::BadDigest), Hash::digest(b"a"), &mut refused),
            Acceptance::Reject
        );
        assert_eq!(refused.len(), 1, "a bad digest is worth remembering");
        assert_eq!(
            acceptance_for(&Err(TxError::UnknownAnchor), Hash::digest(b"b"), &mut refused),
            Acceptance::Ignore
        );
        assert_eq!(refused.len(), 1, "a stale anchor is not this transaction's fault");
    }

    /// The pre-screen's refusals map the same way, one level up: the pool's own answers are about
    /// this node, and only a `TxError` about the bytes is cached and rejected.
    #[test]
    fn a_pre_screen_refusal_reports_by_whose_fault_it_is() {
        use crate::admission::{acceptance_for_pool, Acceptance, RefusedCache};
        use crate::mempool::MempoolError;
        use shrugg_core::TxError;
        let mut refused = RefusedCache::new(8);
        let h = Hash::digest(b"x");
        // A transaction we already hold, one that collides with a pending one, and a full pool are
        // all statements about this node's pool — another node's may have room for it.
        for e in [
            MempoolError::Duplicate,
            MempoolError::Conflict([1; 8]),
            MempoolError::AttestationConflict(h),
            MempoolError::Full,
        ] {
            assert_eq!(acceptance_for_pool(&e, h, &mut refused), Acceptance::Ignore, "{e}");
        }
        assert_eq!(refused.len(), 0, "nothing about the pool is worth caching");
        // The pre-screen's own byte-level refusal: an attestation over the cap.
        assert_eq!(
            acceptance_for_pool(&MempoolError::Invalid(TxError::AttestationTooLarge), h, &mut refused),
            Acceptance::Reject
        );
        assert_eq!(refused.len(), 1);
        // And its state-level one, which is not.
        assert_eq!(
            acceptance_for_pool(&MempoolError::Invalid(TxError::Spent([2; 8])), Hash::digest(b"y"), &mut refused),
            Acceptance::Ignore
        );
        assert_eq!(refused.len(), 1);
    }

    /// What an RPC submitter hears for a decision taken before any verification. The messages are
    /// the ones `Mempool::insert` already produced, because `docs/rpc.md` quotes them.
    #[test]
    fn an_rpc_submission_refused_before_verification_keeps_the_pools_own_errors() {
        use crate::admission::{rpc_refusal, Acceptance, RefusedCache};
        use crate::mempool::MempoolError;
        use shrugg_core::TxError;
        let mut refused = RefusedCache::new(8);
        let h = Hash::digest(b"z");
        refused.insert(h, TxError::BadDigest);
        // A `Reject` can only be the refused cache — the RPC path passes no bucket and a full
        // queue is an `Ignore` — so the caller hears the verdict the ledger gave it the first time.
        assert_eq!(rpc_refusal(Acceptance::Reject, &h, &refused), MempoolError::Invalid(TxError::BadDigest));
        // A full verify queue is a "not now", which is what `Full` already says to a client.
        assert_eq!(rpc_refusal(Acceptance::Ignore, &h, &refused), MempoolError::Full);
    }
}
