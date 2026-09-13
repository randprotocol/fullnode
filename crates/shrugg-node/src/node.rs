//! The node event loop: owns the HotStuff replica, mempool, storage handle and
//! network handle; turns consensus `Action`s into I/O and network events into
//! consensus input.

use crate::mempool::Mempool;
use crate::network::{self, GossipMessage, NetworkConfig, NetworkEvent, NetworkHandle, Status, SyncRequest, SyncResponse};
use crate::rpc::{self, NodeCommand, NodeStatus, RpcState};
use crate::storage::{Storage, VerifyMode};
use anyhow::{Context, Result};
use libp2p::{Multiaddr, PeerId};
use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::consensus::{Action, CommittedBlock, ConsensusConfig, ConsensusError, ConsensusMessage, HotStuff};
use shrugg_core::gas;
use shrugg_core::genesis::{Genesis, GenesisState};
use shrugg_core::{Hash, Keypair, Ledger, ShieldedAddress, Transaction, ValidatorSet, FAUCET_MAX_UNITS};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::notes::{Note, SpendKey};
use shrugg_zkvm::viewing::TxKey;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

const SYNC_BATCH: u32 = 100;
/// Approximate cap on a sync batch response: the request-response codec caps
/// messages at 10 MiB, so an unbounded 100-block batch of fat blocks would be
/// undeliverable and the requester would retry the same range forever.
const SYNC_MAX_BYTES: usize = 8 << 20;

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
    peers: HashMap<PeerId, Option<Status>>,
    timeout: Option<(u64, Instant)>,
    propose_at: Option<(u64, Instant)>,
    last_block_at: Instant,
    sync_inflight: Option<(PeerId, libp2p::request_response::OutboundRequestId, Instant)>,
    fetch_inflight: HashMap<libp2p::request_response::OutboundRequestId, Hash>,
    /// Block hash -> (attempts so far, peers already asked) for by-hash fetches.
    fetch_attempts: HashMap<Hash, (usize, Vec<PeerId>)>,
}

const MAX_FETCH_ATTEMPTS: usize = 8;

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
    let (rpc_addr, rpc_task) = rpc::serve(
        cfg.rpc_addr,
        RpcState {
            storage: storage.clone(),
            status: status.clone(),
            node: cmd_tx,
            chain_id: gs.chain_id,
            executor: executor.clone(),
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
        peers: HashMap::new(),
        timeout: None,
        propose_at: None,
        last_block_at: Instant::now(),
        sync_inflight: None,
        fetch_inflight: HashMap::new(),
        fetch_attempts: HashMap::new(),
    };
    // A fatal error in the loop ends the node, but most embedders (every cluster test, and any
    // caller that keeps the handle without awaiting it) never look at the `JoinHandle`, so
    // without this the node simply goes quiet and looks like a consensus or networking stall.
    // The `Result` is still returned for whoever does await it.
    let task = tokio::spawn(async move {
        let outcome = node.run(events, cmd_rx, early).await;
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
        s.peer_count = self.peers.len();
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
        let target = self.peers.values().flatten().map(|p| p.height).max().unwrap_or(0);
        s.sync_target = target.max(s.height);
        s.syncing = self.sync_inflight.is_some();
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
        self.warm_new_programs(&blocks);
        self.fetch_attempts.clear();
        Ok(())
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
            NodeCommand::SubmitTx { tx, reply } => {
                let res = self.mempool.insert(tx.clone(), self.hs.tip_ledger(), self.executor.as_ref());
                if res.is_ok() {
                    self.net.broadcast(GossipMessage::Transaction(tx)).await;
                }
                let _ = reply.send(res);
            }
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
                self.peers.entry(p).or_insert(None);
                self.broadcast_status().await;
            }
            NetworkEvent::PeerDisconnected(p) => {
                self.peers.remove(&p);
                if self.sync_inflight.map(|s| s.0) == Some(p) {
                    self.sync_inflight = None;
                }
            }
            NetworkEvent::Gossip { from, msg } => match msg {
                GossipMessage::Consensus(m) => self.on_consensus(m).await?,
                GossipMessage::Transaction(tx) => {
                    let _ = self.mempool.insert(tx, self.hs.tip_ledger(), self.executor.as_ref());
                }
                GossipMessage::Status(s) => {
                    let ahead = s.height > self.hs.committed_height() + 1;
                    self.peers.insert(from, Some(s));
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
                tracing::debug!("sync request to {peer} failed: {error}");
                if self.sync_inflight.map(|s| s.1) == Some(request_id) {
                    self.sync_inflight = None;
                }
                self.retry_fetch(request_id).await?;
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
                let mut out = Vec::new();
                let mut bytes = 0usize;
                for h in from_height..from_height.saturating_add(max as u64) {
                    match self.storage.committed_block(h) {
                        Ok(Some(cb)) => {
                            bytes += cb.block.encode().len();
                            if !out.is_empty() && bytes > SYNC_MAX_BYTES {
                                break;
                            }
                            out.push(cb);
                        }
                        _ => break,
                    }
                }
                SyncResponse::Blocks(out)
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
            .filter(|(p, s)| !asked.contains(p) && s.as_ref().map(|s| s.height >= my_height).unwrap_or(false))
            .map(|(p, _)| *p)
            .collect();
        if candidates.is_empty() {
            candidates = self.peers.keys().filter(|p| !asked.contains(p)).copied().collect();
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
        self.peers.values().flatten().map(|s| s.height).max().unwrap_or(0)
    }

    async fn maybe_sync(&mut self) {
        if let Some((_, _, started)) = self.sync_inflight {
            if started.elapsed() < Duration::from_secs(10) {
                return;
            }
            self.sync_inflight = None;
        }
        let my_height = self.hs.committed_height();
        let best = self
            .peers
            .iter()
            .filter_map(|(p, s)| s.as_ref().map(|s| (*p, s.height)))
            .filter(|(_, h)| *h > my_height)
            .max_by_key(|(_, h)| *h);
        let Some((peer, _)) = best else { return };
        let req = SyncRequest::Blocks { from_height: my_height + 1, max: SYNC_BATCH };
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
                if self.sync_inflight.map(|s| s.1) != Some(request_id) {
                    return Ok(());
                }
                self.sync_inflight = None;
                let n = blocks.len();
                if let Err(e) = self.apply_synced(blocks).await {
                    tracing::warn!("sync batch from {peer} rejected: {e}");
                    self.peers.remove(&peer);
                    return Ok(());
                }
                if n as u32 == SYNC_BATCH {
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
}
