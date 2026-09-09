//! The node event loop: owns the HotStuff replica, mempool, storage handle and
//! network handle; turns consensus `Action`s into I/O and network events into
//! consensus input.

use crate::mempool::Mempool;
use crate::network::{self, GossipMessage, NetworkConfig, NetworkEvent, NetworkHandle, Status, SyncRequest, SyncResponse};
use crate::rpc::{self, NodeCommand, NodeStatus, RpcState};
use crate::storage::{Storage, VerifyMode};
use anyhow::{Context, Result};
use libp2p::{Multiaddr, PeerId};
use shrugg_core::bridge::BridgeState;
use shrugg_core::confidential::{ConfidentialExecutor, DisabledExecutor};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_core::consensus::{Action, CommittedBlock, ConsensusConfig, ConsensusError, ConsensusMessage, HotStuff};
use shrugg_core::gas;
use shrugg_core::genesis::{Genesis, GenesisState};
use shrugg_core::{Address, Hash, Keypair, Ledger, Transaction, FAUCET_MAX_UNITS};
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

pub fn load_genesis(datadir: &std::path::Path) -> Result<GenesisState> {
    let path = datadir.join("genesis.json");
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Genesis::from_json(&text)?.build()?)
}

/// The confidential-computation executor a chain's genesis calls for.
pub fn executor_for(gs: &GenesisState) -> Result<Arc<dyn ConfidentialExecutor>> {
    if !gs.confidential {
        return Ok(Arc::new(DisabledExecutor));
    }
    let profile = ZkExecutor::profile_from_str(&gs.fri_profile)
        .with_context(|| format!("genesis fri_profile {}", gs.fri_profile))?;
    Ok(Arc::new(ZkExecutor::new(profile)))
}

/// Verify the on-disk chain. If the tail is damaged, truncate to the last good
/// block (keeping safety state); the missing blocks are re-fetched from peers by
/// the normal sync path. Returns the height the node will resume from.
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
    let gs = load_genesis(&cfg.datadir)?;
    let storage = Arc::new(Storage::open(&cfg.datadir)?);
    storage.init_genesis(&gs)?;
    let executor = executor_for(&gs)?;
    check_and_repair_chain(&storage, &gs, cfg.verify, executor.as_ref())?;

    // Consensus replica from persisted head.
    let head_block = storage.head_block()?;
    let head_qc = storage.head_qc()?;
    let mut ledger = storage.load_ledger()?;
    ledger.set_faucet(gs.faucet);
    // A bridged chain whose database predates the bridge column families has
    // no stored bridge state. That is only recoverable at the genesis block,
    // where the state is exactly what the genesis section derives; past it the
    // balances and consumed digests are gone and a replay must rebuild them.
    if ledger.bridge().is_none() {
        if let Some(cfg) = &gs.bridge {
            let head = storage.head()?;
            if head.height != 0 {
                anyhow::bail!(
                    "genesis has a bridge section but the database at height {} has no bridge state; \
                     delete the data directory and resync, or restore a backup",
                    head.height
                );
            }
            tracing::info!("initializing bridge state from the genesis bridge section");
            ledger.set_bridge(Some(BridgeState::from_config(cfg)));
        }
    }
    let safety = storage.load_safety()?;
    let signer = if cfg.validator && gs.validators.contains(&key.address()) {
        Some(Keypair::from_seed(cfg.seed)?)
    } else {
        if cfg.validator {
            tracing::warn!("--validator set but {} is not in the genesis validator set; running as observer", key.address());
        }
        None
    };
    let mut ccfg = ConsensusConfig::new(gs.chain_id, gs.validators.clone(), gs.hash());
    ccfg.base_timeout = cfg.base_timeout;
    ccfg.max_timeout = cfg.max_timeout;
    let hs = HotStuff::resume(ccfg, signer, head_block, head_qc, ledger, safety, executor.clone());

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
            validators: gs.validators.clone(),
            chain_id: gs.chain_id,
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

    // Warm verifier keys for every program already on chain, off the consensus thread.
    {
        let programs: Vec<_> = hs.committed_ledger().programs().values().cloned().collect();
        let ex = executor.clone();
        if !programs.is_empty() {
            tokio::task::spawn_blocking(move || {
                for rec in programs {
                    ex.warm(&rec);
                }
                tracing::info!("verifier keys warmed");
            });
        }
    }

    let address = key.address();
    let node = Node {
        cfg,
        gs,
        executor: executor.clone(),
        storage: storage.clone(),
        hs,
        mempool: Mempool::new(10_000, 64),
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
    let task = tokio::spawn(node.run(events, cmd_rx, early));
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
        s.programs = self.hs.committed_ledger().programs().len() as u64;
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
        while let Some(a) = queue.pop_front() {
            match a {
                Action::PersistSafety(s) => self.storage.save_safety(&s)?,
                Action::Broadcast(m) | Action::SendTo(_, m) => {
                    self.net.broadcast(GossipMessage::Consensus(m)).await;
                }
                Action::Commit(blocks) => self.commit(blocks).await?,
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
        Ok(())
    }

    async fn commit(&mut self, blocks: Vec<CommittedBlock>) -> Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let ledger = self.hs.committed_ledger().clone();
        self.storage.commit(&blocks, &ledger)?;
        for cb in &blocks {
            for tx in &cb.block.transactions {
                self.mempool.remove(&tx.hash());
            }
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
            .filter_map(|tx| match &tx.body.kind {
                shrugg_core::TxKind::Deploy { base_pc, words } => ledger.program(&shrugg_core::program::program_id(*base_pc, words)).cloned(),
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
        }
        Ok(())
    }

    /// Testnet faucet: this node signs a `Mint` with its own key and submits it
    /// like any other transaction, so every node applies it through consensus.
    async fn mint(&mut self, to: Address, amount: u128) -> std::result::Result<Hash, crate::mempool::MempoolError> {
        use crate::mempool::MempoolError;
        use shrugg_core::TxError;
        if !self.gs.faucet {
            return Err(MempoolError::Invalid(TxError::FaucetDisabled));
        }
        if amount > FAUCET_MAX_UNITS {
            return Err(MempoolError::Invalid(TxError::MintTooLarge { amount, cap: FAUCET_MAX_UNITS }));
        }
        let key = Keypair::from_seed(self.cfg.seed).expect("seed validated at startup");
        // Next usable nonce: account nonce plus whatever this node already has pending.
        let me = key.address();
        let mut nonce = self.hs.tip_ledger().nonce(&me);
        while self.mempool.has_nonce(&me, nonce) {
            nonce += 1;
        }
        let tx = Transaction::mint(&key, self.gs.chain_id, nonce, to, amount, 0);
        let hash = self.mempool.insert(tx.clone(), self.hs.tip_ledger(), self.executor.as_ref())?;
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
    async fn apply_synced(&mut self, blocks: Vec<CommittedBlock>) -> Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        let mut ledger: Ledger = self.hs.committed_ledger().clone();
        let mut head_hash = self.hs.committed_hash();
        let mut head_height = self.hs.committed_height();
        let mut accepted = Vec::new();
        for cb in blocks {
            let b = &cb.block;
            if b.height() != head_height + 1 || b.parent() != head_hash {
                anyhow::bail!("non-contiguous block {}", b.height());
            }
            if cb.qc.block_hash != b.hash() || cb.qc.view != b.view() {
                anyhow::bail!("qc does not certify block {}", b.height());
            }
            if !cb.qc.verify(&self.gs.validators, &self.gs.hash()) {
                anyhow::bail!("invalid qc for block {}", b.height());
            }
            if b.proposer() != self.gs.validators.leader(b.view()) {
                anyhow::bail!("wrong leader for block {}", b.height());
            }
            let receipts = ledger.apply_block(b, self.executor.as_ref())?;
            if receipts != cb.receipts {
                anyhow::bail!("receipts for block {} do not match our execution", b.height());
            }
            head_hash = b.hash();
            head_height = b.height();
            accepted.push(CommittedBlock { receipts, ..cb });
        }
        self.storage.commit(&accepted, &ledger)?;
        for cb in &accepted {
            tracing::info!("synced block {} ({} txs)", cb.block.height(), cb.block.transactions.len());
            for tx in &cb.block.transactions {
                self.mempool.remove(&tx.hash());
            }
        }
        let head = accepted.last().expect("non-empty");
        let mut ccfg = ConsensusConfig::new(self.gs.chain_id, self.gs.validators.clone(), self.gs.hash());
        ccfg.base_timeout = self.cfg.base_timeout;
        ccfg.max_timeout = self.cfg.max_timeout;
        let signer = if self.hs.is_validator() { Some(Keypair::from_seed(self.cfg.seed)?) } else { None };
        let safety = self.hs.safety_state();
        self.hs = HotStuff::resume(ccfg, signer, head.block.clone(), head.qc.clone(), ledger, Some(safety), self.executor.clone());
        self.timeout = None;
        self.propose_at = None;
        let acts = self.hs.start();
        self.handle_actions(acts).await?;
        self.mempool.prune(self.hs.tip_ledger());
        Ok(())
    }
}
