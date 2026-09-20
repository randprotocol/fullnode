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
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::consensus::{Action, CommittedBlock, ConsensusConfig, ConsensusError, ConsensusMessage, HotStuff};
use randprotocol_core::genesis::{Genesis, GenesisState};
use randprotocol_core::{Hash, Keypair, Ledger, ShieldedAddress, Transaction, ValidatorSet, Word8, FAUCET_MAX_UNITS};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::notes::{Note, SpendKey};
use randprotocol_zkvm::viewing::TxKey;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
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

/// How long the node waits for a sync response before it abandons the request, on a default
/// chain; a running node uses its own [`network::WireLimits::sync_request_timeout`] (the same
/// floor, raised for a chain whose sync responses may weigh more).
///
/// The wire's own timeout, deliberately. A shorter deadline here abandons a request that is still
/// alive, and the node then discarded the response when it arrived: the 10 s give-up this replaces
/// meant only a batch answered inside 10 s counted, and a 1-vCPU droplet serving 100 blocks from
/// RocksDB on the same event loop that verifies proofs frequently took longer. This is an upper
/// bound rather than the usual case — a request that fails reports `SyncFailed` and is re-picked at
/// once.
#[cfg_attr(not(test), allow(dead_code))]
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
    /// Let the viewing-key RPC methods answer callers that are not on loopback. Off by default:
    /// nothing in the RPC authenticates anyone, and the facility is meant for this node's own
    /// explorer (audit v3, VK-3).
    pub viewing_open: bool,
    /// Keep the raw proofs of sealed bundles (spec §6.2's archive flag): the pruning pass
    /// never runs when set.
    pub keep_raw_proofs: bool,
}

/// Handles returned by `Node::start` so tests and the CLI can observe the node.
pub struct NodeHandle {
    pub rpc_addr: SocketAddr,
    pub network: NetworkHandle,
    pub listen_addrs: Vec<Multiaddr>,
    pub status: Arc<RwLock<NodeStatus>>,
    pub storage: Arc<Storage>,
    pub address: randprotocol_core::Address,
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
///
/// The concrete type is [`AggExecutor`], the `ZkExecutor` plus the rVM-backed aggregate surface:
/// the ledger likewise gates the aggregation actions on `genesis.aggregation`, so on a chain
/// without the section the rVM half is built (cheap — a machine config, no keys) and never
/// called, and a chain with it never meets `ConfidentialError::AggregationUnsupported`.
pub fn executor_for_profile(fri_profile: &str) -> Result<Arc<dyn ConfidentialExecutor>> {
    let profile =
        ZkExecutor::profile_from_str(fri_profile).with_context(|| format!("genesis fri_profile {fri_profile}"))?;
    Ok(Arc::new(crate::agg_executor::AggExecutor::new(profile)))
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
/// The ledger a restarting node runs on: the persisted state, plus the things that live in the
/// genesis file rather than in the database.
///
/// `epoch_blocks` is one of them, and it is not cosmetic: `Unbond` writes `epoch() +
/// UNBONDING_EPOCHS` into the register, which the state root hashes. A node that came back up
/// with the default 1000 on a chain that runs shorter epochs would compute a release epoch
/// nobody else does, disagree about the state root from its first unbond on, and never rejoin.
/// One function, so a restart cannot pick up some of them and be wrong about the chain.
pub fn reload_ledger(storage: &Storage, gs: &GenesisState, executor: &dyn ConfidentialExecutor) -> Result<Ledger> {
    let mut ledger = storage.load_ledger(executor)?;
    ledger.set_faucet(gs.faucet);
    ledger.set_confidential(gs.confidential);
    ledger.set_epoch_blocks(gs.epoch_blocks);
    // The aggregation gate lives in the genesis file too: without this a restarted chain-9 node
    // would compute state-2 roots and refuse every aggregation action by name.
    ledger.set_aggregation(gs.ledger.aggregation().cloned());
    // The program cap too (v0.4 `max_program_words`): `load_ledger` comes back at the 4 096-word
    // default, and a node that kept it would refuse deploys its peers admit — a fork at the
    // first large program after its first restart.
    ledger.set_max_program_words(gs.ledger.max_program_words());
    // And the call limits, for the same reason: `load_ledger` comes back at today's caps, and a
    // node that kept them would disagree with its peers about which proofs, blocks, envelopes
    // and deploys fit.
    ledger.set_max_proof_bytes(gs.ledger.max_proof_bytes());
    ledger.set_max_block_bytes(gs.ledger.max_block_bytes());
    ledger.set_max_call_envelope_bytes(gs.ledger.max_call_envelope_bytes());
    ledger.set_max_program_public_words(gs.ledger.max_program_public_words());
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

/// The chain's FRI profile as the ledger's mirror enum, parsed from the genesis file — which
/// `executor_for_profile` already validated, so the `expect` cannot fire.
fn core_profile(fri_profile: &str) -> randprotocol_core::types::FriProfile {
    match ZkExecutor::profile_from_str(fri_profile).expect("genesis fri_profile was validated at load") {
        randprotocol_zkvm::machine::FriProfile::Test => randprotocol_core::types::FriProfile::Test,
        randprotocol_zkvm::machine::FriProfile::Production => randprotocol_core::types::FriProfile::Production,
    }
}

/// The worker's validation of one transaction. An aggregate's covered bundles live in storage,
/// not the ledger, so its admission pre-flights the byte checks (spec §4 step 1), assembles the
/// covered records (§3.2's coverability), and takes the covered-carrying path; every other
/// transaction is the ledger's own `validate`.
fn validate_for_pool(
    tx: &Transaction,
    ledger: &Ledger,
    storage: &Storage,
    profile: randprotocol_core::types::FriProfile,
    executor: &dyn ConfidentialExecutor,
) -> Result<(), randprotocol_core::TxError> {
    let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action else {
        return ledger.validate(tx, executor);
    };
    ledger.preflight_aggregate(tx)?;
    let window = ledger.aggregation().expect("preflight checked the gate").window;
    let covered = assemble_covered(storage, ledger.height(), window, profile, covers)?;
    ledger.validate_aggregate(tx, &covered, executor).map(|_| ())
}

/// The covered-bundle records an aggregate's admission needs (spec §3.2), assembled from the
/// store: the records themselves come from [`Storage::covered_record`] (one read for the raw
/// and the pruned form), and the policy half is here — a stored block is finalised by
/// construction (only committed blocks are stored), chain-9 is implied by the genesis gate, the
/// window (§3.3), and the seal (§6.1): a covered bundle is never coverable again. A stored
/// record that cannot be read back indicts this node's store, not the transaction:
/// `CoverStoreCorrupt`, never a permanent verdict.
fn assemble_covered(
    storage: &Storage,
    head: u64,
    window: u64,
    profile: randprotocol_core::types::FriProfile,
    covers: &[Hash],
) -> Result<Vec<randprotocol_core::types::CoveredBundle>, randprotocol_core::TxError> {
    use randprotocol_core::ledger::aggregation::AggregationError as A;
    use randprotocol_core::TxError;
    covers
        .iter()
        .map(|cover| {
            let corrupt = || TxError::Aggregation(A::CoverStoreCorrupt(*cover));
            let (height, _) = storage.tx_location(cover).map_err(|_| corrupt())?.ok_or(TxError::Aggregation(A::UnknownCover(*cover)))?;
            // The window (spec §3.3): the bundle's block must be newer than `head - window`.
            if height + window <= head {
                return Err(TxError::Aggregation(A::CoverOutsideWindow { cover: *cover, block: height, head }));
            }
            if storage.sealed_by(cover).map_err(|_| corrupt())?.is_some() {
                return Err(TxError::Aggregation(A::CoverSealed(*cover)));
            }
            storage
                .covered_record(cover, profile)
                .map_err(|_| corrupt())?
                .ok_or(TxError::Aggregation(A::CoverNotABundle(*cover)))
        })
        .collect()
}

/// HotStuff's covered source over the store (spec §3.2): the record half of
/// `assemble_covered`, answered against the committed head. The seal and the window are not
/// re-checked here — they are consensus through the ledger's coverable set (the fee bucket
/// records every bundle and drops it at its cover or its sweep; `validate_aggregate` step 4
/// refuses a cover with no entry), so a block that re-covers a sealed bundle is invalid on
/// every replica whatever this source answers. `assemble_covered` keeps the three named
/// verdicts for admission's error reporting.
struct StoreCovered {
    storage: Arc<Storage>,
    profile: randprotocol_core::types::FriProfile,
}

impl randprotocol_core::consensus::CoveredSource for StoreCovered {
    /// The record-only flavor (spec §3.2's data half): existence, bundle-ness, and the public
    /// values and declared shape — one read for the raw and the pruned form. Coverability
    /// *policy* — the window and the seal — is admission's, run on the node's worker
    /// (`assemble_covered` in `validate_for_pool`), never here: whether a cover would still be
    /// coverable today says nothing about the validity of a committed block that covers it,
    /// and a slow syncer replaying an aggregate whose window has since passed must not be
    /// refused for it (the aggregate's own proof, and the ledger's bucket, are the validity).
    fn covered(&self, covers: &[Hash]) -> Option<Vec<randprotocol_core::types::CoveredBundle>> {
        covers
            .iter()
            .map(|cover| match self.storage.covered_record(cover, self.profile) {
                Ok(Some(record)) => Some(record),
                _ => None,
            })
            .collect()
    }
}

/// The form a stored block is served in (spec §7): every transaction whose record is
/// `Pruned` rides as the record's marker form with a side-table entry — the raw hash, the
/// proof hash, the 34 public values and the declared shape — in transaction order. A block
/// with no pruned records is raw by construction: the two forms share one wire type.
fn sealed_form_of(storage: &Storage, cb: &CommittedBlock) -> CommittedBlock {
    let mut block = cb.block.clone();
    let mut pruned = Vec::new();
    for tx in &mut block.transactions {
        // The record is keyed by the raw hash, which is `tx.hash()` for a raw-stored tx;
        // for a marker-form one (this block itself arrived sealed), the record is found by
        // the proof hash the marker carries.
        let key = match tx.bundle.as_ref().and_then(|b| randprotocol_core::notes::pruned_proof_hash(&b.proof)) {
            Some(ph) => match storage.tx_hash_by_proof_hash(&ph) {
                Ok(Some(k)) => k,
                _ => continue,
            },
            None => tx.hash(),
        };
        let Ok(Some(crate::storage::TxRecord::Pruned { tx_hash, tx: pruned_tx, proof_hash, public_values, shape, .. })) =
            storage.tx_record(&key)
        else {
            continue;
        };
        *tx = pruned_tx;
        pruned.push(randprotocol_core::consensus::PrunedBundle { tx_hash, proof_hash, public_values, shape });
    }
    CommittedBlock { block, pruned, ..cb.clone() }
}

/// The sealed acceptance's coverage half (spec §7), one pruned transaction at a time: the
/// marker must carry a side-table entry, and the entry's raw hash must name a bundle this
/// node has already sealed or this batch carries an aggregate for. Anything else is the
/// raw-form fallback; a marker without an entry is a damaged batch.
fn check_sealed_coverage(storage: &Storage, batch_covers: &BTreeSet<Hash>, cb: &CommittedBlock) -> Result<()> {
    for tx in &cb.block.transactions {
        let Some(proof_hash) = tx.bundle.as_ref().and_then(|bd| randprotocol_core::notes::pruned_proof_hash(&bd.proof)) else {
            continue;
        };
        let Some(p) = cb.pruned.iter().find(|p| p.proof_hash == proof_hash) else {
            anyhow::bail!("block {} carries a pruned bundle with no side-table entry", cb.block.height());
        };
        let covered = storage.sealed_by(&p.tx_hash)?.is_some() || batch_covers.contains(&p.tx_hash);
        if !covered {
            return Err(RawFallback(cb.block.height()).into());
        }
    }
    Ok(())
}

/// The raw-form fallback (spec §7): a pruned bundle arrived whose covering aggregate is
/// neither applied nor in this batch. Serving closes a batch's coverage before it goes out
/// ([`close_batch_coverage`]), so what remains here is the genuine archive case — the cover
/// sits beyond the reader limit's reach, or the peer's store is torn — and another peer may
/// hold the raw proofs. Not a failure: serving pruned history is policy, not malice, so the
/// peer wears no strike for it.
#[derive(Debug)]
struct RawFallback(u64);

impl std::fmt::Display for RawFallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "block {} is pruned history without its covering aggregate", self.0)
    }
}

impl std::error::Error for RawFallback {}

/// The sync peer for the next batch request, or `None` when nothing usable exists: the
/// freshest connected peer ahead of `my_height`; and when no peer is connected *and* fresh at
/// once but the chain is known to be ahead (`best_peer_height` says so), any connected peer
/// whose stale answer costs one round trip — the fallback that keeps the cycle alive where a
/// silent stall costs the chain (the sealed-sync stall's shape, shown under load).
fn pick_sync_peer(
    peers: &HashMap<PeerId, Peer>,
    my_height: u64,
    best_peer_height: u64,
    skipped: &[PeerId],
) -> Option<PeerId> {
    let best = peers
        .iter()
        .filter(|(p, peer)| peer.connected && !skipped.contains(p))
        .filter_map(|(p, peer)| peer.status.as_ref().map(|s| (*p, s.height)))
        .filter(|(_, h)| *h > my_height)
        .max_by_key(|(_, h)| *h)
        .map(|(p, _)| p);
    best.or_else(|| {
        if best_peer_height > my_height + 1 {
            peers.iter().find(|(p, peer)| peer.connected && !skipped.contains(p)).map(|(p, _)| *p)
        } else {
            None
        }
    })
}

struct Node {
    cfg: NodeConfig,
    gs: GenesisState,
    /// This node's own validator address, whether or not it is signing today: what
    /// `active_validator` is looked up by.
    address: randprotocol_core::Address,
    executor: Arc<dyn ConfidentialExecutor>,
    storage: Arc<Storage>,
    hs: HotStuff,
    mempool: Mempool,
    net: NetworkHandle,
    status: Arc<RwLock<NodeStatus>>,
    /// Viewing keys imported over RPC, shared with the `RpcState`; read here only so
    /// `publish_status` can report the count (`NodeStatus::viewing_keys`).
    viewing: Arc<RwLock<crate::viewing::Registry>>,
    /// The registry's live key count, for `publish_status` (audit v3, VK-1).
    viewing_count: Arc<std::sync::atomic::AtomicUsize>,
    /// Committed heads, for whatever WebSocket clients are subscribed. Held here rather than read
    /// back out of the `RpcState` because this is the only place that writes it.
    heads: broadcast::Sender<rpc::HeadSummary>,
    /// Committed blocks' transaction hashes and receipts, sent beside each head, for the
    /// `receipts` and `transaction` topics. Written only here, like `heads`.
    commits: broadcast::Sender<rpc::CommitSummary>,
    /// Refusals that entered the refused cache, with their reason, for the `transaction` topic.
    refusals: broadcast::Sender<(Hash, String)>,
    /// The live WebSocket connection count `ws::upgrade` maintains; reported as
    /// `NodeStatus::ws_clients`.
    ws_conns: Arc<AtomicUsize>,
    /// The faucet's own allowance, per process (node I4): `rand_mint` is fee-less and pooled, so
    /// an unthrottled one is free pool pressure on a chain that keeps the faucet on behind a live
    /// bridge. The same token bucket the gossip limiter uses, over one bucket rather than a map —
    /// the RPC port has no peer identity to meter.
    faucet_limiter: admission::PeerLimiter,
    faucet_bucket: admission::TokenBucket,
    peers: HashMap<PeerId, Peer>,
    /// This chain's sync and gossip byte limits, from its genesis `max_block_bytes`; the same
    /// value the swarm was started with.
    wire: network::WireLimits,
    timeout: Option<(u64, Instant)>,
    propose_at: Option<(u64, Instant)>,
    last_block_at: Instant,
    sync_inflight: Option<(PeerId, libp2p::request_response::OutboundRequestId, Instant)>,
    /// Blocks to ask for in the next batch. Halved toward [`SYNC_BATCH_MIN`] after a failure and
    /// reset to [`SYNC_BATCH`] after a batch applies, so a batch size the wire cannot carry is
    /// backed away from instead of retried forever.
    sync_batch: u32,
    /// Ask the next sync from the committed head rather than from the tree's tip: set when the
    /// blocks we hold above the head turn out not to be the ancestors of what peers are serving
    /// (review C2).
    sync_from_committed: bool,
    /// Sync batch requests that *failed*: a wire or codec error, a give-up past the wire timeout,
    /// or a batch we asked for and could not apply. Surfaced in `rand status`, because the
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
    // A block that cannot be sized is charged more than any budget or reader limit, which ends the
    // batch rather than letting an unmeasured block through.
    network::codec::cbor_size(cb).map(|n| n as u64).unwrap_or(u64::MAX)
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

/// The node's committed history and the set's disagree. Carried as a typed error so the sync
/// path, which reports most failures as "sync batch rejected" and moves to another peer, lets this
/// one through and stops the node (review M2).
#[derive(Debug, thiserror::Error)]
#[error("consensus safety violation: committed {committed:?}, attempted {attempted:?}")]
pub struct FatalSafety {
    pub committed: Hash,
    pub attempted: Hash,
}

/// A batch is judged by what it holds, not by which request asked for it.
///
/// The node used to drop any response whose id was not the current one, which threw away good
/// blocks every time its own give-up had already re-requested the same range — so only a batch that
/// arrived inside the give-up window counted, and catch-up moved one batch per 30-40 s with nothing
/// in the log to say why. A batch whose first block is exactly our next height continues our chain
/// whoever asked for it and however late; applying it twice is impossible, because the second copy
/// no longer starts there. `None` is an empty batch: the peer has nothing past our height.
/// `my_height` is the highest block this node *holds* — its pending tip, not its committed head —
/// because a node whose tree is ahead of its commits asks for blocks above the tree (review C2),
/// and a batch that starts there is the continuation it asked for.
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

/// How many bytes of blocks one sync response may carry, on the chain `limits` were computed for
/// (`max_block_bytes + 2 MiB`, call limits spec §8).
///
/// Half the reader limit the codec enforces, by construction: the budget is the server's promise
/// and the limit is the client's check, and keeping the first at half the second leaves room for
/// framing and for a peer on a slightly different build.
pub(crate) fn serve_sync_budget(limits: &network::WireLimits) -> u64 {
    debug_assert!(limits.sync_max_wire_bytes * 2 <= limits.sync_response_wire_limit);
    limits.sync_max_wire_bytes
}

/// The coverage-closure half of serving (spec §7): a batch that ends between a pruned block
/// and its covering aggregate is unusable to the syncer — its coverage check fails and the
/// batch comes back as the raw-form fallback, identically from every pruned peer, however
/// often it is re-asked. Both cuts produce that shape: a count halved on wire failures (the
/// capstone stall's: window at 33, cover at 46, batch cut to four) and a byte budget spent on
/// raw proofs before the cover's height. Neither the requester nor the filler knows where the
/// covers sit — but this store does: every pruned entry it serves carries a seal mark naming
/// the aggregate's committing height (the mark landed with the aggregate's block, or the
/// record would still be raw). So a batch that leaves a served pruned entry's cover beyond
/// its end extends — past the count asked for and past the soft byte budget — until every
/// cover is in. The extension's only ceiling is the reader's own wire limit: a batch that
/// cannot close inside it serves as far as it can, and the syncer's fallback is then the
/// genuine archive case it exists for.
fn close_batch_coverage(storage: &Storage, batch: &mut Vec<CommittedBlock>, limits: &network::WireLimits) {
    let farthest_cover = |batch: &[CommittedBlock]| -> Option<u64> {
        batch
            .iter()
            .flat_map(|cb| &cb.pruned)
            .filter_map(|p| storage.sealed_by(&p.tx_hash).ok().flatten())
            .map(|(_, height)| height)
            .max()
    };
    let Some(mut farthest) = farthest_cover(batch) else { return };
    let Some(mut end) = batch.last().map(|cb| cb.block.height()) else { return };
    if farthest <= end {
        return;
    }
    let mut bytes: u64 =
        SYNC_RESPONSE_FRAMING_BYTES + batch.iter().map(committed_block_wire_size).sum::<u64>();
    while farthest > end {
        let h = end + 1;
        // A mark never names a height past this store's head, so a miss here is a torn
        // store — serve what the batch holds and let the syncer's fallback say so.
        let Ok(Some(cb)) = storage.committed_block(h) else { return };
        let cb = sealed_form_of(storage, &cb);
        bytes = bytes.saturating_add(committed_block_wire_size(&cb));
        if bytes > limits.sync_response_wire_limit {
            return;
        }
        // The extension can cross another pruned window whose own covers sit farther out.
        for p in &cb.pruned {
            if let Ok(Some((_, height))) = storage.sealed_by(&p.tx_hash) {
                farthest = farthest.max(height);
            }
        }
        batch.push(cb);
        end = h;
    }
}

/// What this build can run, checked against the genesis before anything is opened.
///
/// - Every shielded-pool proof on the chain is against one guest, pinned by the genesis. A node
///   built from a different commit would verify nothing and vote against every bundle, which
///   looks like a consensus bug rather than the build mismatch it is — so say so here.
/// - **Block aggregation is gated off on the hidden-asset bundle** (chain 14,
///   `docs/superpowers/specs/2026-09-19-hidden-asset-bundle-design.md` §5): every admitted shape
///   in an `aggregation` section, the rVM recursion fixtures and the `aggregate` daemon were
///   measured for the retired 2-in-2-out guest, whose proof shape (program and input heights) the
///   hidden guest does not share. Aggregation is inactive on every live chain; it has to be
///   re-measured against the hidden guest before a genesis may carry it again. Refused with a
///   clear error rather than started into a chain whose aggregates could never cover a bundle.
pub fn check_build_runs_genesis(gs: &GenesisState, built_hc_bundle: &randprotocol_core::notes::Word8) -> Result<()> {
    if *built_hc_bundle != gs.hc_bundle {
        anyhow::bail!(
            "this build's bundle guest ({}) differs from the genesis hc_bundle ({}); \
             rebuild from the chain's pinned commit",
            randprotocol_core::notes::word8_to_hex(built_hc_bundle),
            randprotocol_core::notes::word8_to_hex(&gs.hc_bundle)
        );
    }
    if gs.ledger.aggregation().is_some() {
        anyhow::bail!(
            "this genesis enables block aggregation, which is not supported on the hidden-asset \
             bundle yet: its admitted shapes and the recursion fixtures were measured for the \
             retired 2-in-2-out guest and must be re-measured before aggregation is activated"
        );
    }
    Ok(())
}

pub async fn start(cfg: NodeConfig) -> Result<NodeHandle> {
    let key = Keypair::from_seed(cfg.seed).context("bad key seed")?;
    let (gs, executor) = load_genesis(&cfg.datadir)?;
    check_build_runs_genesis(&gs, &ZkExecutor::hc_bundle())?;
    let storage = Arc::new(Storage::open(&cfg.datadir)?);
    storage.init_genesis(&gs)?;
    check_and_repair_chain(&storage, &gs, cfg.verify, executor.as_ref())?;

    // "Is a validator" is "has a signer", not "is in the genesis set" (spec §8): a validator that
    // bonds in after genesis must already hold its key when its first epoch arrives, and a node
    // that refused the key at startup would have nothing to vote with. `HotStuff::resume` keeps a
    // signer that is in no current set and observes until an epoch admits it; what the RPC
    // reports as *in the current set* is `active_validator`.
    let signer = if cfg.validator { Some(Keypair::from_seed(cfg.seed)?) } else { None };
    let mut hs = resume_consensus(&storage, &gs, signer, cfg.base_timeout, cfg.max_timeout, executor.clone())?;
    // The covered source (spec §3.2): on a chain that aggregates, proposals and candidates
    // carrying an `Aggregate` apply through the covered-carrying path, answered from the store.
    // Set once, before the loop's first proposal; a chain without the section never consults it.
    if gs.ledger.aggregation().is_some() {
        hs.set_covered_source(Arc::new(StoreCovered {
            storage: storage.clone(),
            profile: core_profile(&gs.fri_profile),
        }));
    }

    // Network. The sync and gossip byte limits follow the genesis block cap (call limits
    // spec §8), computed once here and handed to the swarm and the serve path.
    let identity = key.derive_subkey(b"rand-p2p-identity");
    let wire = network::WireLimits::for_ledger(&gs.ledger);
    let (net, mut events) = network::start(
        NetworkConfig {
            chain_id: gs.chain_id,
            listen: cfg.listen.clone(),
            bootstrap: cfg.bootstrap.clone(),
            enable_mdns: cfg.enable_mdns,
            limits: wire,
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
    let (commits, _) = broadcast::channel(rpc::HEAD_CHANNEL);
    let (refusals, _) = broadcast::channel(rpc::HEAD_CHANNEL);
    let ws_conns = Arc::new(AtomicUsize::new(0));
    // Viewing keys imported over RPC (`rand_importViewingKey`), in memory only. Shared with the
    // node loop purely so `rand_status` can say how many keys this process is holding.
    let viewing = Arc::new(RwLock::new(crate::viewing::Registry::default()));
    let viewing_count = viewing.read().unwrap_or_else(|e| e.into_inner()).count();
    // The RPC's limits, computed once from the genesis ledger.
    let rpc_limits = rpc::ChainLimits::of(&gs.ledger);
    let (rpc_addr, rpc_task) = rpc::serve(
        cfg.rpc_addr,
        RpcState {
            viewing_open: cfg.viewing_open,
            storage: storage.clone(),
            status: status.clone(),
            node: cmd_tx,
            chain_id: gs.chain_id,
            // The RPC's limits follow the genesis (call limits spec §8), like the wire's above.
            limits: rpc_limits,
            max_body_bytes: rpc_limits.rpc_max_body_bytes(),
            executor: executor.clone(),
            heads: heads.clone(),
            commits: commits.clone(),
            refusals: refusals.clone(),
            ws_conns: ws_conns.clone(),
            viewing: viewing.clone(),
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
    // carry bundles, so the first one must not pay for the key), every program already on
    // chain, and — on a chain with an aggregation section — the aggregate program and its N=1
    // landing tier's rVM verifier key per admitted shape (spec §2.3's startup obligation; the
    // ~30–70 s production key-build happens here, not inside the first aggregate's admission).
    {
        let programs: Vec<_> = hs.committed_ledger().programs().values().cloned().collect();
        let agg_shapes: Vec<_> = hs
            .committed_ledger()
            .aggregation()
            .map(|c| c.admitted_shapes.iter().map(|a| a.shape).collect())
            .unwrap_or_default();
        let ex = executor.clone();
        tokio::task::spawn_blocking(move || {
            ex.warm_bundle();
            tracing::info!("bundle verifier key warmed");
            for rec in programs {
                ex.warm(&rec);
            }
            tracing::info!("verifier keys warmed");
            for shape in &agg_shapes {
                ex.warm_aggregation(shape);
            }
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
        viewing,
        viewing_count,
        heads,
        commits,
        refusals,
        ws_conns,
        peers: HashMap::new(),
        wire,
        timeout: None,
        propose_at: None,
        last_block_at: Instant::now(),
        sync_inflight: None,
        sync_batch: SYNC_BATCH,
        sync_from_committed: false,
        sync_failures: 0,
        sync_late_batches: 0,
        fetch_inflight: HashMap::new(),
        fetch_attempts: HashMap::new(),
        refused: admission::RefusedCache::new(admission::REFUSED_CACHE_ENTRIES),
        limiter: admission::PeerLimiter::new(admission::PEER_TX_BURST, admission::PEER_TX_PER_SEC),
        faucet_limiter: admission::PeerLimiter::new(admission::FAUCET_MINT_BURST, admission::FAUCET_MINT_PER_SEC),
        faucet_bucket: admission::TokenBucket::default(),
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
        // The aggregation section (spec §8): the register's size straight from the ledger, and
        // the work-list count over the window the chain runs with — both zeroed without the
        // section. The count re-reads the window's blocks each commit; at the chain's scale
        // that is a few hundred transactions.
        s.aggregation.registered = ledger.aggregators().len();
        s.aggregation.unsealed = match ledger.aggregation() {
            Some(cfg) => {
                crate::rpc::unsealed_bundles(
                    &self.storage,
                    self.hs.committed_height(),
                    cfg.window,
                    self.hs.committed_height().saturating_sub(cfg.window),
                    usize::MAX,
                )
                .0
                .len()
            }
            None => 0,
        };
        s.aggregation.verify_queue = self.verify_queue.len();
        if let Some(cfg) = ledger.aggregation() {
            s.aggregation.max_covers = cfg.max_covers;
            s.aggregation.window = cfg.window;
            s.aggregation.subsidy_base = cfg.subsidy_base;
            s.aggregation.halving_blocks = cfg.halving_blocks;
            s.aggregation.sealed_blocks = ledger.supply().sealed_blocks;
        }
        // The pool's public size, straight from the committed ledger rather than a second read
        // of storage: this runs on the node loop after every commit.
        s.notes = ledger.next_index();
        s.nullifiers = ledger.nullifiers().len() as u64;
        s.tree_root = randprotocol_core::notes::word8_to_hex(&ledger.root());
        s.hc_bundle = randprotocol_core::notes::word8_to_hex(&ledger.hc_bundle());
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
        // Read without touching the registry's lock: this runs on the node loop every pass, and a
        // scan holds its own key's lock for as long as it takes (audit v3, VK-1).
        s.viewing_keys = self.viewing_count.load(std::sync::atomic::Ordering::Relaxed);
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
            let storage = self.storage.clone();
            let profile = core_profile(&self.gs.fri_profile);
            let executor = self.executor.clone();
            let out = self.verdicts_tx.clone();
            self.verify_in_flight += 1;
            tokio::task::spawn_blocking(move || {
                let result = validate_for_pool(&tx, &ledger, &storage, profile, executor.as_ref());
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
        self.note_refusal(hash);
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
            let hash = tx.hash();
            let a = admission::acceptance_for_pool(&e, hash, &mut self.refused);
            self.note_refusal(hash);
            self.report(id, GossipOutcome::Report(a)).await;
            return Ok(());
        }
        self.verify_queue.push_back((tx, VerifySource::Gossip(id)));
        self.pump_verify();
        Ok(())
    }

    /// An RPC submission takes the same queue as a gossiped transaction, with the caller's oneshot
    /// in place of a message id. Not metered: that port is the operator's own, and it is already
    /// bounded by `RpcState::max_body_bytes`.
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
            self.note_refusal(hash);
            let _ = reply.send(Err(admission::rpc_refusal(a, &hash, &self.refused)));
            return;
        }
        // A pre-screen refusal is the caller's answer directly, so every error message a submitter
        // can hear is the one `Mempool::insert` always produced (`docs/rpc.md` quotes them). The
        // acceptance is discarded here — only its caching side effect matters, so a resubmission of
        // a permanently bad transaction is answered for free.
        if let Err(e) = self.mempool.precheck(&tx, self.hs.tip_ledger(), self.executor.as_ref()) {
            let _ = admission::acceptance_for_pool(&e, hash, &mut self.refused);
            self.note_refusal(hash);
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
        let txs = self.mempool.block_candidates(self.hs.tip_ledger());
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
                // Nothing is persisted and nothing else in the batch runs: this node's committed
                // history and the set's disagree, so every finality answer it could give from here
                // is suspect. Stop; startup's `verify_chain` decides what the restart does with the
                // store (audit v3).
                Action::SafetyViolation { committed, attempted } => {
                    tracing::error!(?committed, ?attempted, "conflicting finality: stopping this node");
                    // Tagged, because the sync path turns an ordinary error into "sync batch
                    // rejected" and carries on (review M2): this one must not be swallowed there.
                    return Err(anyhow::Error::new(FatalSafety { committed, attempted }));
                }
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
        let mut newly_sealed: Vec<Hash> = Vec::new();
        for cb in &blocks {
            let included: Vec<Hash> = cb.block.transactions.iter().map(|tx| tx.hash()).collect();
            self.mempool.remove(&included);
            for tx in &cb.block.transactions {
                if let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action {
                    newly_sealed.extend_from_slice(covers);
                }
            }
            tracing::info!(
                "committed block {} view {} txs {} hash {:?}",
                cb.block.height(),
                cb.block.view(),
                cb.block.transactions.len(),
                cb.block.hash()
            );
        }
        // Spec §3.4's pool rule: a pooled aggregate whose cover set just sealed is dead — its
        // excess would pay out nothing new — so it leaves the pool here rather than at the
        // window's end.
        if !newly_sealed.is_empty() {
            let doomed: Vec<Hash> = self
                .mempool
                .pooled_aggregate_covers()
                .into_iter()
                .filter(|(_, covers)| covers.iter().any(|c| newly_sealed.contains(c)))
                .map(|(hash, _)| hash)
                .collect();
            self.mempool.remove(&doomed);
        }
        // The pruning pass (spec §6.2 — policy, never consensus): sealed bundles whose window
        // has passed become their pruned record. Every 16 blocks is often enough that the pass
        // lags the gate by at most that; `--keep-raw-proofs` archives instead.
        let head = self.hs.committed_height();
        if !self.cfg.keep_raw_proofs && head % 16 == 0 {
            if let Some(agg) = self.hs.committed_ledger().aggregation().cloned() {
                let profile = core_profile(&self.gs.fri_profile);
                let storage = self.storage.clone();
                let pruned = tokio::task::spawn_blocking(move || storage.prune_sealed(head, agg.window, profile))
                    .await
                    .map_err(|e| anyhow::anyhow!("pruning task: {e}"))??;
                if pruned > 0 {
                    tracing::info!("pruned {pruned} sealed bundle records at head {head}");
                }
            }
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
    /// Each head is followed by its block's [`rpc::CommitSummary`] on the `commits` channel, for
    /// the `receipts` and `transaction` topics, under the same rules.
    ///
    /// Called after `storage.commit` has returned, on both paths a block becomes committed by: a
    /// subscriber must never be told about a head this node could still lose. On the sync path
    /// that is before the replica is resumed, so a batch's heads go out in their own order and
    /// never behind a head the restarted replica commits.
    ///
    /// `view` is the *block's* view, which is what certified it. `rand_getHead` reports the
    /// node's current view instead — the same field, and for the tip usually the same number, but
    /// a notification is a statement about one block rather than about this node's clock.
    fn publish_heads(&self, blocks: &[CommittedBlock]) {
        for cb in blocks {
            let _ = self.heads.send(rpc::HeadSummary {
                height: cb.block.height(),
                hash: cb.block.hash().to_hex(),
                view: cb.block.view(),
            });
            let _ = self.commits.send(rpc::CommitSummary {
                height: cb.block.height(),
                hash: cb.block.hash(),
                tx_hashes: cb.block.transactions.iter().map(|t| t.hash()).collect(),
                receipts: cb.receipts.clone(),
            });
        }
    }

    /// Tell `transaction` subscribers that `hash` was refused, if it was refused for good — that
    /// is, if the refusal is now in the refused cache. Called right after each decision that can
    /// put it there, so the set announced is exactly the set `rand_getTransactionStatus` reports
    /// as `rejected`, with the same reason: a `Duplicate`, a pool conflict or a full queue is a
    /// "not now" about this node, never enters the cache, and is not announced. A resubmission of
    /// an already-refused hash is announced again, which costs nothing — a `transaction`
    /// subscription removes itself after one delivery.
    fn note_refusal(&self, hash: Hash) {
        if let Some(e) = self.refused.get(&hash) {
            let _ = self.refusals.send((hash, e.to_string()));
        }
    }

    /// Precompute verifier keys for programs deployed in `blocks`, off the node loop.
    fn warm_new_programs(&self, blocks: &[CommittedBlock]) {
        let ledger = self.hs.committed_ledger();
        let records: Vec<_> = blocks
            .iter()
            .flat_map(|cb| cb.block.transactions.iter())
            .filter_map(|tx| match &tx.action {
                randprotocol_core::Action::Deploy { base_pc, words, public } => {
                    ledger.program(&randprotocol_core::program::program_id_with_public(*base_pc, words, public)).cloned()
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
            NodeCommand::MempoolInfo { reply } => {
                let _ = reply.send(self.mempool.info(Instant::now()));
            }
            NodeCommand::TxStatus { hashes, reply } => {
                let out = hashes
                    .iter()
                    .map(|h| {
                        if self.mempool.contains(h) {
                            rpc::PoolStatus::Pending
                        } else if let Some(e) = self.refused.get(h) {
                            rpc::PoolStatus::Rejected(e.to_string())
                        } else {
                            rpc::PoolStatus::Unknown
                        }
                    })
                    .collect();
                let _ = reply.send(out);
            }
            NodeCommand::Finality { hash, reply } => {
                // The tree holds only the committed head plus uncommitted blocks (older
                // committed blocks are pruned), so a hash in it is the committed head exactly
                // when it equals `committed_hash`; otherwise it is certified (a QC names it) or
                // merely proposed.
                let f = if let Some(b) = self.hs.block(&hash) {
                    let height = b.height();
                    if hash == self.hs.committed_hash() {
                        rpc::Finality::Committed { height, hash }
                    } else if let Some(qc_view) = self.hs.certified(&hash) {
                        rpc::Finality::Certified { height, hash, qc_view }
                    } else {
                        rpc::Finality::Proposed { height, hash }
                    }
                } else {
                    rpc::Finality::Unknown
                };
                let _ = reply.send(f);
            }
            NodeCommand::Proposer { views, reply } => {
                let epoch = self.hs.tip_ledger().epoch();
                let _ = reply.send((epoch, views.iter().map(|v| self.hs.leader(*v)).collect()));
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
        // Last of the cheap refusals, and the only one that is about this node rather than the
        // request: a mint is fee-less and costs a pooled transaction, so the faucet is metered
        // (node I4, `admission::FAUCET_MINT_BURST`/`FAUCET_MINT_PER_SEC` — 8 back to back,
        // refilling at 1/s). Per process: the RPC port has no peer identity to key a bucket on.
        if !self.faucet_limiter.allow(&mut self.faucet_bucket, Instant::now()) {
            return Err(format!(
                "faucet is rate limited on this node ({} mints back to back, refilling at {}/s); try again shortly",
                admission::FAUCET_MINT_BURST,
                admission::FAUCET_MINT_PER_SEC
            ));
        }
        let key = Keypair::from_seed(self.cfg.seed).expect("seed validated at startup");
        let height = self.hs.tip_ledger().height();
        let note = Note::new(to.pk, [0; 8], amount, 0, height as u32);
        let throwaway = SpendKey::random().viewing_key();
        let envelope = randprotocol_zkvm::address::seal_note(&throwaway, &to, &note, &TxKey::random())?;
        let tx =
            Transaction::mint(self.gs.chain_id, note.pk, note.time, note.r, envelope, amount, &key, self.executor.as_ref());
        debug_assert_eq!(tx.commitments(), vec![note.commitment()], "the sealed note is the one admission derives");
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
                let blocks = heights
                    .map_while(|h| self.storage.committed_block(h).ok().flatten())
                    .map(|cb| sealed_form_of(&self.storage, &cb));
                let mut batch = fill_sync_batch(blocks, serve_sync_budget(&self.wire));
                close_batch_coverage(&self.storage, &mut batch, &self.wire);
                SyncResponse::Blocks(batch)
            }
            SyncRequest::BlockByHash(h) => {
                let b = self.hs.block(&h).cloned().or_else(|| self.storage.block_by_hash(&h).ok().flatten());
                // A by-hash fetch is a single block with no aggregate context beside it: serve
                // the stored block untouched, marker forms and all, and let the fetcher's
                // acceptance decide (the batch path's sealed form is built in `Blocks`).
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
            if started.elapsed() < self.wire.sync_request_timeout {
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
        // Ask above what we *hold*, not above what we have committed (review C2). A batch whose
        // blocks the three-chain rule cannot commit — three blocks over the byte budget is enough,
        // about eighteen bundle proofs on chain 14 — leaves those blocks in the tree as pending.
        // Asking from the committed head again would fetch the same blocks forever: the node would
        // hot-loop and never rejoin, and a rolling update that restarts nodes a few hundred blocks
        // back would take the chain down one node at a time. The blocks above are the proof the
        // pending ones are waiting for, so that is what to ask for.
        let my_height = if std::mem::take(&mut self.sync_from_committed) {
            self.hs.committed_height()
        } else {
            self.hs.pending_tip_height().max(self.hs.committed_height())
        };
        let mut skipped: Vec<PeerId> = skip.into_iter().collect();
        // The starvation shape the sealed-sync stall showed under load: the chain is known to
        // be ahead (some peer's status says so) and nothing is outstanding, yet the obvious
        // candidate is unusable — no connected-and-fresh peer, or the send cannot go out. Both
        // are give-ups, never stalls: fall to the next candidate — a possibly-stale answer
        // costs one round trip, and it keeps the cycle alive where a silent stall costs the chain.
        for _ in 0..3 {
            let Some(peer) = pick_sync_peer(&self.peers, my_height, self.best_peer_height(), &skipped) else { return };
            let req = SyncRequest::Blocks { from_height: my_height + 1, max: self.sync_batch };
            if let Some(id) = self.net.send_sync_request(peer, req).await {
                self.sync_inflight = Some((peer, id, Instant::now()));
                return;
            }
            tracing::warn!(%peer, "sync request could not be sent; trying another peer");
            self.sync_failures += 1;
            skipped.push(peer);
        }
        if self.best_peer_height() > my_height + 1 {
            tracing::warn!(
                height = my_height,
                target = self.best_peer_height(),
                peers = ?self.peers.iter().map(|(p, peer)| format!("{p} connected={} status={:?}", peer.connected, peer.status.as_ref().map(|s| s.height))).collect::<Vec<_>>(),
                "sync wanted but every candidate refused the request"
            );
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
                // The height this node asked from: the pending tip when its tree is ahead of its
                // commits (review C2), the committed head otherwise.
                let my_height = self.hs.pending_tip_height().max(self.hs.committed_height());
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
                    // The raw-form fallback (spec §7): pruned history without its covering
                    // aggregate is a request to try another peer, not a failure — serving
                    // pruned history is policy, not malice, so the peer wears no strike and is
                    // not dropped; the next batch is asked of someone else.
                    if e.downcast_ref::<RawFallback>().is_some() {
                        tracing::info!(%peer, "{e}; asking another peer for the raw form");
                        self.sync_from(Some(peer)).await;
                        return Ok(());
                    }
                    // Conflicting finality stops this node; it is not a bad peer (review M2).
                    if e.downcast_ref::<FatalSafety>().is_some() {
                        return Err(e);
                    }
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
        // Audit v3, CON-1a: a QC says a block was *certified*, not that it was committed. Blocks
        // are certified and then abandoned at every view change, so accepting each block on its
        // own QC — which is all this path used to check — let any peer, validator or not, hand a
        // syncing node a certified fork to finalise. Status messages are unsigned, so claiming the
        // height that wins the sync costs nothing.
        //
        // The same three-chain rule the live path uses decides here (`committed_prefix`). The last
        // blocks of a batch carry no proof of their own commitment — the blocks that would prove
        // them are the ones the server has not committed yet — so they are handed to the live path
        // below as ordinary pending blocks instead, and commit when the chain's next blocks
        // arrive.
        // A batch that starts above our committed head extends blocks we hold but have not
        // committed — what `sync_from` asks for once the tree is ahead (review C2). Those parents
        // live in the replica's tree, not in storage, so the whole batch goes to the live path.
        if blocks[0].block.height() != self.hs.committed_height() + 1 {
            return self.offer_pending(blocks).await;
        }
        // The views that are the *evidence* must themselves be verified, or the evidence is the
        // attacker's (review C1): a peer serving one real certified block followed by two blocks
        // it invented at view+1 and view+2 would otherwise have the real one finalised, because
        // the invented pair sits in the tail this function never checks. So the whole batch is
        // verified below — every QC, leader, epoch set and execution — and the prefix is computed
        // over that verified run. A batch with a junk tail fails verification whole and commits
        // nothing.
        let prefix = randprotocol_core::consensus::commit_rule::committed_prefix(
            &blocks.iter().map(|cb| cb.block.view()).collect::<Vec<_>>(),
        );
        let mut ledger: Ledger = self.hs.committed_ledger().clone();
        let mut head_hash = self.hs.committed_hash();
        let mut head_height = self.hs.committed_height();
        let epoch_blocks = self.gs.epoch_blocks.max(1);
        let mut sets = self.hs.epoch_sets().clone();
        let mut recorded: Vec<(u64, ValidatorSet)> = Vec::new();
        let mut accepted = Vec::new();
        // The ledger and the epoch sets as they stood at the end of the committed prefix; the loop
        // below keeps verifying past it (see the prefix comment above).
        let mut committed_ledger: Option<Ledger> = None;
        let mut committed_recorded: Vec<(u64, ValidatorSet)> = Vec::new();
        let profile = core_profile(&self.gs.fri_profile);
        // The sealed form's coverage map (spec §7): every cover every aggregate in this batch
        // names — checked before each pruned bundle's skip, and the batch is atomic if one
        // fails.
        let mut batch_covers: BTreeSet<Hash> = BTreeSet::new();
        for cb in &blocks {
            for tx in &cb.block.transactions {
                if let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action {
                    batch_covers.extend(covers.iter().copied());
                }
            }
        }
        let mut recent: HashMap<Hash, randprotocol_core::types::CoveredBundle> = HashMap::new();
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
            // The sealed form's acceptance (spec §7): a pruned bundle is accepted only if its
            // block is finalised — the QC above — and a covering aggregate names its raw hash,
            // applied already (a local mark) or carried later in this very batch (whose commit
            // is atomic: if the aggregate then fails any admission step, the whole batch —
            // this block's tentative skip included — is discarded, exactly as an invalid raw
            // block fails today). Anything else is the raw-form fallback: another peer may
            // hold the raw proofs, and serving pruned history is policy, not malice.
            check_sealed_coverage(&self.storage, &batch_covers, &cb)?;
            // The covered-carrying sidecar for any aggregate in the block: the records the
            // batch has produced so far, then the store's (spec §3.2's data — the pruned form
            // reads exactly as the raw one).
            let mut sidecar = BTreeMap::new();
            for (index, tx) in b.transactions.iter().enumerate() {
                if let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action {
                    let mut records = Vec::with_capacity(covers.len());
                    for cover in covers {
                        let record = match recent.get(cover) {
                            Some(r) => r.clone(),
                            None => self
                                .storage
                                .covered_record(cover, profile)?
                                .ok_or_else(|| anyhow::anyhow!("cover {cover} of block {} names no stored bundle", b.height()))?,
                        };
                        records.push(record);
                    }
                    sidecar.insert(index, records);
                }
            }
            let receipts = ledger.apply_block_for_sync(b, &sidecar, &cb.pruned, self.executor.as_ref())?;
            if receipts != cb.receipts {
                anyhow::bail!("receipts for block {} do not match our execution", b.height());
            }
            // The records this block makes available to later aggregates in the batch: raw
            // bundles by their proofs, marker-form ones by the side table.
            for tx in &b.transactions {
                match tx.bundle.as_ref().and_then(|bd| randprotocol_core::notes::pruned_proof_hash(&bd.proof)) {
                    Some(proof_hash) => {
                        let p = cb.pruned.iter().find(|p| p.proof_hash == proof_hash).expect("checked above");
                        let pv: [u64; 34] = p.public_values.clone().try_into().expect("a side table's list is 34 words");
                        recent.insert(p.tx_hash, randprotocol_core::types::CoveredBundle { public_values: pv, shape: p.shape });
                    }
                    None => {
                        if let Some(bd) = &tx.bundle {
                            if let Ok(proof) = postcard::from_bytes::<randprotocol_zkvm::machine::Proof>(&bd.proof) {
                                let pv: [u64; 34] = proof.public_values.clone().try_into().expect("cs6 proofs carry 34 public values");
                                recent.insert(
                                    tx.hash(),
                                    randprotocol_core::types::CoveredBundle {
                                        public_values: pv,
                                        shape: randprotocol_core::types::DeclaredShape {
                                            profile,
                                            tier: proof.tier.0 as u8,
                                            program_log_height: proof.program_log_height,
                                            input_log_height: proof.input_log_height,
                                            keccak_log_height: proof.keccak_log_height,
                                            sha256_log_height: proof.sha256_log_height,
                                            public_log_height: proof.public_log_height,
                                            mem_log_height: proof.mem_log_height,
                                        },
                                    },
                                );
                            }
                        }
                    }
                }
            }
            head_hash = b.hash();
            head_height = b.height();
            // The notes this block made the ledger create, from our own execution rather than
            // from the peer's copy (which the wire does not carry).
            let deposits = ledger.take_deposits();
            accepted.push(CommittedBlock { receipts, deposits, ..cb });
            // The state that belongs with the committed prefix. Verification runs past it — the
            // blocks above are this prefix's own proof — but only what the three-chain rule
            // commits is written, so the ledger written beside it is the one that describes it.
            if accepted.len() == prefix {
                committed_ledger = Some(ledger.clone());
                committed_recorded = recorded.clone();
            }
        }
        // Everything verified. Now split: the prefix commits, the rest goes to the live path.
        let pending = accepted.split_off(prefix);
        if !pending.is_empty() {
            tracing::debug!(
                "sync batch: {} block(s) commit by the three-chain rule, {} verified and held for the live path",
                accepted.len(),
                pending.len()
            );
        }
        if accepted.is_empty() {
            // Nothing in this batch proves a commit. The blocks are verified, so hand them to the
            // replica: each enters the tree and commits through the live rule once a three-chain
            // forms over it.
            return self.offer_pending(pending).await;
        }
        let ledger = committed_ledger.expect("the prefix is non-empty, so its ledger was taken");
        let recorded = committed_recorded;
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
        // The covered source does not ride the resume: `HotStuff::resume` is a fresh replica,
        // and without this a synced node would refuse every aggregate-carrying block at the
        // sidecar forever (the capstone's AggregateNeedsCovered).
        if self.gs.ledger.aggregation().is_some() {
            self.hs.set_covered_source(Arc::new(StoreCovered {
                storage: self.storage.clone(),
                profile: core_profile(&self.gs.fri_profile),
            }));
        }
        self.timeout = None;
        self.propose_at = None;
        let acts = self.hs.start();
        self.handle_actions(acts).await?;
        self.mempool.prune(self.hs.tip_ledger());
        // The tail the three-chain rule does not prove (audit v3, CON-1a).
        self.offer_pending(pending).await?;
        Ok(())
    }

    /// Blocks a sync batch carried that the commit rule does not commit yet: hand them to the
    /// replica exactly as if they had been gossiped. `on_proposal` re-verifies each one — leader,
    /// justify, execution — and commits it once a three-chain forms over it, so nothing here can
    /// finalise a branch on a peer's say-so. Errors are ordinary: a block whose parent we do not
    /// hold, or one from an abandoned branch, is not a failure of the sync.
    async fn offer_pending(&mut self, pending: Vec<CommittedBlock>) -> Result<()> {
        for cb in pending {
            let height = cb.block.height();
            match self.hs.on_proposal(cb.block, now_ms()) {
                Ok(acts) => self.handle_actions(acts).await?,
                Err(randprotocol_core::consensus::ConsensusError::UnknownParent(parent)) => {
                    // The blocks we hold above the committed head are not this block's ancestors:
                    // the branch in our tree is a dead end (its leader was replaced at a view
                    // change). Asking above that branch would fetch blocks we can never link, so
                    // the next request goes back to the committed head (review C2).
                    tracing::debug!(
                        "synced block {height} has unknown parent {parent:?}; syncing from the committed head again"
                    );
                    self.sync_from_committed = true;
                    break;
                }
                Err(e) => {
                    tracing::debug!("synced block {height} not taken by the replica: {e}");
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fixtures::{alloc_note, bundle_fee, bundle_tx, genesis_of, key, make_block_voted};
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::consensus::{EpochSets, HotStuff};
    use randprotocol_core::gas;
    use randprotocol_core::genesis::GenesisState;
    use randprotocol_core::{Block, BlockHeader, QuorumCertificate, Vote};

    /// A one-validator chain with two-block epochs, committed past its first boundary: blocks 1
    /// (epoch 0) and 2 (the first block of epoch 1, whose set is recorded with it).
    fn chain_past_a_boundary() -> (tempfile::TempDir, Storage, GenesisState, Ledger) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let gs = genesis_of(7, &[&key(1)], vec![alloc_note(20, 5 * randprotocol_core::UNITS_PER_RAND)], 2);
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
    fn next_block(head: &Block, ledger: &Ledger, k: &randprotocol_core::Keypair) -> Block {
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

    /// The sync peer selection (the stall shape's unit test): the freshest connected peer
    /// ahead wins; the fallback asks any connected peer when the chain is known ahead but no
    /// connected-and-fresh pair exists; and a statusless connected peer is still askable.
    #[test]
    fn pick_sync_peer_prefers_fresh_and_falls_back_to_any_connected() {
        let pid = |seed: u8| {
            let kp = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            PeerId::from(kp.public())
        };
        let p = |seed: u8, connected: bool, height: Option<u64>| {
            (
                pid(seed),
                Peer {
                    status: height.map(|height| Status { height, head_hash: Hash::ZERO, view: height }),
                    connected,
                    tx_bucket: Default::default(),
                },
            )
        };
        let peers: HashMap<PeerId, Peer> = [p(1, true, Some(163)), p(2, true, Some(120)), p(3, false, Some(200))].into_iter().collect();
        // The freshest connected-and-ahead peer wins — never a disconnected one, however fresh.
        assert_eq!(pick_sync_peer(&peers, 43, 200, &[]), Some(pid(1)));
        // The stall shape: the fresh peer is disconnected and the connected one is statusless,
        // but the chain is known ahead — the fallback asks the connected peer anyway.
        let peers: HashMap<PeerId, Peer> = [p(1, false, Some(163)), p(2, true, None)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 163, &[]), Some(pid(2)));
        // Nothing ahead at all: no fallback (a peer at our height is not worth asking).
        let peers: HashMap<PeerId, Peer> = [p(1, true, None)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 43, &[]), None);
        // The skip list (a give-up) is honored before the fallback too.
        let skipped = [pid(2)];
        let peers: HashMap<PeerId, Peer> = [p(1, false, Some(163)), p(2, true, None), p(3, true, Some(50))].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 163, &skipped), Some(pid(3)));
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

    /// The startup check (H3): a genesis whose `hc_bundle` is not this build's guest is refused,
    /// and so is any genesis with an `aggregation` section — aggregation's shapes were measured
    /// for the retired bundle guest and are gated off until re-measured. A genesis without the
    /// section and with this build's guest starts.
    #[test]
    fn startup_refuses_another_guest_and_an_aggregation_section() {
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        let hc = gs.hc_bundle;
        assert!(check_build_runs_genesis(&gs, &hc).is_ok());
        let other = check_build_runs_genesis(&gs, &[0xdead; 8]).unwrap_err().to_string();
        assert!(other.contains("differs from the genesis hc_bundle"), "{other}");
        gs.ledger.set_aggregation(Some(randprotocol_core::ledger::aggregation::AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![],
        }));
        let gated = check_build_runs_genesis(&gs, &hc).unwrap_err().to_string();
        assert!(gated.contains("block aggregation") && gated.contains("re-measured"), "{gated}");
    }

    /// The aggregation gate survives a restart: it lives in the genesis file, so a reloaded
    /// ledger must carry it — a node that resumed without it would compute state-2 roots and
    /// refuse every aggregation action by name, forking off a chain-9 fleet at its first restart.
    #[test]
    fn a_restart_restores_the_aggregation_gate() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        let cfg = randprotocol_core::ledger::aggregation::AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![],
        };
        gs.ledger.set_aggregation(Some(cfg.clone()));
        storage.init_genesis(&gs).unwrap();
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.aggregation(), Some(&cfg));
        assert_eq!(
            reloaded.state_root(),
            gs.ledger.state_root(),
            "the reloaded ledger hashes the gated state-3 root, not state-2"
        );
    }

    /// The program cap survives a restart the same way: it lives in the genesis file, and
    /// `load_ledger` alone comes back at the 4 096-word default — so a v0.4 node that resumed
    /// without `reload_ledger` setting it would refuse, as `ProgramTooLarge`, a deploy its peers
    /// admit, and fork off at the first large program after its first restart.
    #[test]
    fn a_restart_restores_the_program_cap() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        gs.ledger.set_max_program_words(gas::MAX_PROGRAM_WORDS_LIMIT);
        storage.init_genesis(&gs).unwrap();
        assert_eq!(storage.load_ledger(&StubExecutor).unwrap().max_program_words(), gas::MAX_PROGRAM_WORDS);
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.max_program_words(), gas::MAX_PROGRAM_WORDS_LIMIT);
        assert_eq!(reloaded, gs.ledger);
    }

    /// The four call-limits parameters survive a restart the same way: `load_ledger` comes back
    /// at today's caps, and a node that kept them would disagree with its peers about which
    /// proofs, blocks, envelopes and deploys fit.
    #[test]
    fn a_restart_restores_the_call_limits() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        gs.ledger.set_max_proof_bytes(8 << 20);
        gs.ledger.set_max_block_bytes(20 << 20);
        gs.ledger.set_max_call_envelope_bytes(65_536);
        gs.ledger.set_max_program_public_words(32_768);
        storage.init_genesis(&gs).unwrap();
        let stored = storage.load_ledger(&StubExecutor).unwrap();
        assert_eq!(stored.max_proof_bytes(), gas::MAX_PROOF_BYTES);
        assert_eq!(stored.max_block_bytes(), gas::MAX_BLOCK_BYTES);
        assert_eq!(stored.max_call_envelope_bytes(), randprotocol_core::types::actions::MAX_CALL_ENVELOPE_BYTES);
        assert_eq!(stored.max_program_public_words(), gas::MAX_PROGRAM_PUBLIC_WORDS);
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.max_proof_bytes(), 8 << 20);
        assert_eq!(reloaded.max_block_bytes(), 20 << 20);
        assert_eq!(reloaded.max_call_envelope_bytes(), 65_536);
        assert_eq!(reloaded.max_program_public_words(), 32_768);
        assert_eq!(reloaded, gs.ledger);
    }

    /// The register and the bucket survive the same restart, hashed into and computed into the
    /// state root as they are: a node that came back without them would fork at the next block
    /// (the register's root) or mis-pay the next aggregate (the bucket's excesses).
    #[test]
    fn a_restart_restores_the_aggregator_register_and_the_fee_bucket() {
        use crate::storage::fixtures::make_block;
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        let cfg = randprotocol_core::ledger::aggregation::AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![],
        };
        gs.ledger.set_aggregation(Some(cfg.clone()));
        storage.init_genesis(&gs).unwrap();

        // Block 1: a fee-paying bundle (its excess buckets) and a registration, both anchored
        // to the genesis root, applied by `make_block`.
        let mut ledger = gs.ledger.clone();
        ledger.set_height(1);
        let fee = randprotocol_core::gas::BUNDLE_BASE + 60;
        let fee_tx = bundle_tx(&ledger, [[41; 8], [42; 8]], [[43; 8], [44; 8]], fee);
        let register_tx = {
            let kp = key(7);
            let payout = ShieldedAddress { pk: [7; 8], kem_ek: vec![8; randprotocol_core::notes::KEM_EK_BYTES] };
            let registration = AggregatorRegistration {
                public_key: kp.public_key().clone(),
                payout: payout.clone(),
                signature: kp.sign(aggregator_register_message(7, &payout).as_bytes()),
            };
            let mut b = randprotocol_core::notes::Bundle {
                anchor: ledger.root(),
                nullifiers: crate::storage::fixtures::pad4([[45; 8], [46; 8]]),
                commitments: crate::storage::fixtures::pad4([[47; 8], [48; 8]]),
                fee: randprotocol_core::gas::BUNDLE_BASE,
                burn_a: 0,
                burn_r: cfg.bond,
                burn_asset: 0,
                time: 1,
                envelopes: [env(1), env(2), env(1), env(2)],
                proof: vec![],
            };
            let d = StubExecutor.bundle_digest(&b.digest_input());
            b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
            randprotocol_core::confidential::StubExecutor::bound(Transaction::shielded(7, b, randprotocol_core::types::Action::RegisterAggregator { registration }))
        };
        let b1 = make_block(&gs.block, &mut ledger, vec![fee_tx, register_tx], &key(1));
        storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        assert_eq!(ledger.unsealed_fees().len(), 2, "every bundle is recorded: the excess, and the register's at 0");
        assert_eq!(ledger.aggregators().len(), 1, "the aggregator is registered");

        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.aggregators(), ledger.aggregators(), "the register round-trips");
        assert_eq!(reloaded.unsealed_fees(), ledger.unsealed_fees(), "the bucket round-trips");
        assert_eq!(reloaded.state_root(), ledger.state_root(), "and the root agrees");
    }

    // ---------------------------------- block aggregation: covered assembly and the worker arm

    use crate::storage::fixtures::{env, make_block_unchecked, HC};
    use randprotocol_core::ledger::aggregation::{AggregationConfig, AggregationError};
    use randprotocol_core::types::actions::{aggregate_signing_hash, aggregator_register_message, AggregatorRegistration};
    use randprotocol_core::types::{CoveredBundle, DeclaredShape};

    /// The fixture proof's declared shape as the ledger's mirror type (profile `Test`).
    fn fixture_shape(p: &randprotocol_zkvm::machine::Proof) -> DeclaredShape {
        DeclaredShape {
            profile: randprotocol_core::types::FriProfile::Test,
            tier: p.tier.0 as u8,
            program_log_height: p.program_log_height,
            input_log_height: p.input_log_height,
            keccak_log_height: p.keccak_log_height,
            sha256_log_height: p.sha256_log_height,
            public_log_height: p.public_log_height,
            mem_log_height: p.mem_log_height,
        }
    }

    /// The fixture bundle's guest digest as a `Hash`: its `HC0..7` public values are the eight
    /// little-endian `u32` words of it.
    fn fixture_hc(p: &randprotocol_zkvm::machine::Proof) -> Hash {
        let words: [u32; 8] = std::array::from_fn(|k| {
            u32::try_from(p.public_values[randprotocol_core::types::pv::HC0 + k]).expect("a guest digest word is u32-range")
        });
        Hash(randprotocol_core::notes::word8_to_bytes(&words))
    }

    fn agg_cfg(shape: DeclaredShape, hc: Hash) -> AggregationConfig {
        AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![randprotocol_core::ledger::aggregation::AdmittedShape {
                shape,
                hc,
                aggregate_program_digest: [1; 4],
            }],
        }
    }

    fn aggregate_tx(chain_id: u64, kp: &Keypair, nonce: u64, time: u32, covers: Vec<Hash>, proof: Vec<u8>) -> Transaction {
        let aggregator = kp.public_key().address();
        let r = [9; 8];
        let signature =
            kp.sign(aggregate_signing_hash(chain_id, nonce, time, &r, &covers, &Hash::digest(&proof)).as_bytes());
        Transaction {
            chain_id,
            bundle: None,
            action: randprotocol_core::types::Action::Aggregate {
                covers,
                proof,
                aggregator,
                nonce,
                time,
                r,
                envelope: env(9),
                signature,
            },
        }
    }

    /// Register `kp` as an aggregator on a stub-executor ledger: the registration bundle burns
    /// exactly the bond, its stub proof publishing the digest the ledger recomputes.
    fn register_aggregator(l: &mut Ledger, kp: &Keypair, bond: u64) {
        let mut b = randprotocol_core::notes::Bundle {
            anchor: l.root(),
            nullifiers: crate::storage::fixtures::pad4([[1; 8], [2; 8]]),
            commitments: crate::storage::fixtures::pad4([[3; 8], [4; 8]]),
            fee: gas::BUNDLE_BASE,
            burn_a: 0,
            burn_r: bond,
            burn_asset: 0,
            time: l.height() as u32,
            envelopes: [env(1), env(2), env(1), env(2)],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&HC, &d, &[0; 8]);
        let payout = ShieldedAddress { pk: [7; 8], kem_ek: vec![8; randprotocol_core::notes::KEM_EK_BYTES] };
        let registration = AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(aggregator_register_message(l.chain_id(), &payout).as_bytes()),
        };
        let tx = randprotocol_core::confidential::StubExecutor::bound(Transaction::shielded(l.chain_id(), b, randprotocol_core::types::Action::RegisterAggregator { registration }));
        let proposer = *l.validators().keys().next().unwrap();
        l.apply_tx(&tx, &proposer, &StubExecutor).unwrap();
    }

    /// A chain whose block 1 carries two transactions: a bundle whose proof is a real fixture
    /// proof, and a bundle-less mint. The block is built `unchecked` (a stub-executor chain
    /// cannot apply a real proof); the ledger the commit is balanced against applies the stub
    /// twins — the same commitments and nullifiers, so the note bookkeeping matches.
    fn chain_with_a_real_proof() -> (tempfile::TempDir, Storage, GenesisState, Transaction, Transaction) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let gs = genesis_of(7, &[&key(1)], vec![], 2);
        storage.init_genesis(&gs).unwrap();

        // The stored set: the fixture-proof bundle and the mint.
        let mut covered_tx = bundle_tx(&gs.ledger, [[21; 8], [22; 8]], [[23; 8], [24; 8]], bundle_fee());
        covered_tx.bundle.as_mut().unwrap().proof = crate::agg_executor::fixture_proof(0).to_bytes();
        let mint_tx = Transaction::mint(7, [31; 8], 0, [31; 8], env(3), 1000, &key(1), &StubExecutor);
        // The applied set: identical apart from the bundle's proof, which is the stub's.
        let stub_tx = bundle_tx(&gs.ledger, [[21; 8], [22; 8]], [[23; 8], [24; 8]], bundle_fee());
        let mut ledger_after = gs.ledger.clone();
        ledger_after.set_height(1);
        ledger_after.set_timestamp_ms(1);
        ledger_after
            .apply_transactions(&[stub_tx, mint_tx.clone()], &key(1).address(), &StubExecutor)
            .unwrap();
        ledger_after.record_anchor(1);

        let b1 = make_block_unchecked(&gs.block, &ledger_after, vec![covered_tx.clone(), mint_tx.clone()], &key(1));
        storage.commit(std::slice::from_ref(&b1), &ledger_after, &[], &StubExecutor).unwrap();
        (dir, storage, gs, covered_tx, mint_tx)
    }

    /// Assembly reads the store (spec §3.2): the covered bundle's 34 public values and its
    /// declared shape come back off the stored proof's header, the profile filled from the chain.
    #[test]
    fn assembly_reads_the_stored_bundle_records() {
        let (_d, storage, _gs, covered_tx, _mint) = chain_with_a_real_proof();
        let proof = crate::agg_executor::fixture_proof(0);
        let covered =
            assemble_covered(&storage, 1, 256, randprotocol_core::types::FriProfile::Test, &[covered_tx.hash()]).unwrap();
        assert_eq!(covered.len(), 1);
        let expected: [u64; 34] = proof.public_values.clone().try_into().unwrap();
        assert_eq!(covered[0], CoveredBundle { public_values: expected, shape: fixture_shape(&proof) });
    }

    /// The coverability refusals: a hash no committed transaction has, a transaction with no
    /// bundle, and a block scrolled out of the window — each named.
    #[test]
    fn assembly_refuses_the_unknown_the_bundle_less_and_the_window_expired() {
        let (_d, storage, _gs, covered_tx, mint_tx) = chain_with_a_real_proof();
        let unknown = Hash::digest(b"nobody committed this");
        assert_eq!(
            assemble_covered(&storage, 1, 256, randprotocol_core::types::FriProfile::Test, &[unknown]),
            Err(randprotocol_core::TxError::Aggregation(AggregationError::UnknownCover(unknown)))
        );
        assert_eq!(
            assemble_covered(&storage, 1, 256, randprotocol_core::types::FriProfile::Test, &[mint_tx.hash()]),
            Err(randprotocol_core::TxError::Aggregation(AggregationError::CoverNotABundle(mint_tx.hash())))
        );
        // Height 1 is inside the window at head 200 and out of it at head 300 (window 256).
        let hash = covered_tx.hash();
        assert!(
            assemble_covered(&storage, 200, 256, randprotocol_core::types::FriProfile::Test, &[hash]).is_ok(),
            "height 1 + 256 > 200 is inside"
        );
        assert_eq!(
            assemble_covered(&storage, 300, 256, randprotocol_core::types::FriProfile::Test, &[hash]),
            Err(randprotocol_core::TxError::Aggregation(AggregationError::CoverOutsideWindow {
                cover: hash,
                block: 1,
                head: 300
            }))
        );
        // And a sealed bundle is never coverable again (spec §3.2.3): the mark lands and the
        // same assembly now names it.
        storage.mark_sealed(hash, Hash::digest(b"the covering aggregate"), 2).unwrap();
        assert_eq!(
            assemble_covered(&storage, 200, 256, randprotocol_core::types::FriProfile::Test, &[hash]),
            Err(randprotocol_core::TxError::Aggregation(AggregationError::CoverSealed(hash)))
        );
    }

    // ---------------------------------- the proposer–validator invariant, live

    /// The capstone's mechanism, replayed against a real store: two replicas with a
    /// `StoreCovered` over one storage — the leader's own block carrying an aggregate applies
    /// on it with no state-root mismatch, and the peer accepts it to the same root.
    #[test]
    fn a_proposal_carrying_an_aggregate_applies_identically_on_proposer_and_peer_live() {
        use randprotocol_core::consensus::{ConsensusConfig, CoveredSource, HotStuff};

        let (_d, storage, gs, covered_tx, _mint) = chain_with_a_real_proof();
        let storage = Arc::new(storage);
        let proof = crate::agg_executor::fixture_proof(0);
        let cfg = randprotocol_core::ledger::aggregation::AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![randprotocol_core::ledger::aggregation::AdmittedShape {
                shape: fixture_shape(&proof),
                hc: fixture_hc(&proof),
                aggregate_program_digest: [1; 4],
            }],
        };
        // The gated ledger, with the aggregator registered at height 1 (the block-1 state the
        // proposal builds on).
        let mut ledger = gs.ledger.clone();
        ledger.set_aggregation(Some(cfg));
        ledger.set_height(1);
        let kp = key(7);
        register_aggregator(&mut ledger, &kp, 100 * randprotocol_core::UNITS_PER_RAND);
        // The stored bundle was applied before the section was set, so it is not in the
        // ledger's coverable set (H1's block rule): record it as the gated apply would have.
        ledger.set_unsealed_fees([(covered_tx.hash(), (0, key(1).address(), u64::MAX))].into_iter().collect());

        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let source: Arc<dyn CoveredSource> = Arc::new(StoreCovered {
            storage: storage.clone(),
            profile: randprotocol_core::types::FriProfile::Test,
        });
        let mk = |signer: Option<randprotocol_core::Keypair>| {
            let mut hs = HotStuff::new(
                ConsensusConfig::new(7, gs.validators.clone(), gs.hash()),
                signer,
                gs.block.clone(),
                ledger.clone(),
                executor.clone(),
            );
            hs.set_covered_source(source.clone());
            hs
        };
        let mut leader = mk(Some(key(1)));
        let mut peer = mk(Some(key(1)));
        leader.start();
        peer.start();

        let tx = aggregate_tx(7, &kp, 0, 1, vec![covered_tx.hash()], b"ok".to_vec());
        let acts = leader.propose(1, vec![tx.clone()], 1).expect("the leader's own block must apply");
        let block = acts
            .iter()
            .find_map(|a| match a {
                randprotocol_core::consensus::Action::Broadcast(randprotocol_core::consensus::ConsensusMessage::Proposal(b)) => Some(b.clone()),
                _ => None,
            })
            .expect("a proposal was built");
        assert!(block.transactions.iter().any(|t| t.hash() == tx.hash()), "the aggregate is in the block");
        peer.on_proposal(block, 1).expect("the peer applies the same block to the same root");
        assert_eq!(
            peer.committed_ledger().state_root(),
            leader.committed_ledger().state_root(),
            "proposer and peer hold one root"
        );
    }

    /// The replay flavor (spec §3.2's data, not its admission policy): a cover whose window
    /// has long passed still answers its record — a slow syncer replaying a historical
    /// aggregate block must not be refused for what is no longer coverable today. The
    /// admission-side check (`assemble_covered`'s window arm) is where that policy lives.
    #[test]
    fn the_covered_source_answers_replayed_history_past_the_window() {
        use randprotocol_core::consensus::CoveredSource as _;
        let (_d, storage, _gs, covered_tx, _mint) = chain_with_a_real_proof();
        let proof = crate::agg_executor::fixture_proof(0);
        let source = StoreCovered { storage: Arc::new(storage), profile: randprotocol_core::types::FriProfile::Test };
        let covered = source.covered(&[covered_tx.hash()]).expect("the record answers at any head");
        let expect = fixture_shape(&proof);
        assert_eq!(covered.len(), 1);
        assert_eq!(covered[0].shape, expect);
        let pv: [u64; 34] = proof.public_values.clone().try_into().unwrap();
        assert_eq!(covered[0].public_values, pv);
        // And the admission policy is where it belongs: `assemble_covered` still refuses the
        // same bundle once the window passes.
        match assemble_covered(source.storage.as_ref(), 300, 256, randprotocol_core::types::FriProfile::Test, &[covered_tx.hash()]) {
            Err(randprotocol_core::TxError::Aggregation(AggregationError::CoverOutsideWindow { .. })) => {}
            other => panic!("the window is admission policy, got {other:?}"),
        }
    }

    // ---------------------------------- sealed-form sync (spec §7)

    /// A sealed-form block built from `chain_with_a_real_proof`'s covered tx: the proof swapped
    /// for the marker form, the side table attesting the raw hash, proof hash, pv and shape.
    fn sealed_form_fixture() -> (tempfile::TempDir, Storage, GenesisState, CommittedBlock) {
        let (dir, storage, gs, covered_tx, _mint) = chain_with_a_real_proof();
        let proof = crate::agg_executor::fixture_proof(0);
        let proof_hash = Hash::digest(&proof.to_bytes());
        let mut marker = randprotocol_core::notes::PRUNED_PROOF_MARKER.to_vec();
        marker.extend_from_slice(proof_hash.as_bytes());
        let mut marker_tx = covered_tx.clone();
        marker_tx.bundle.as_mut().unwrap().proof = marker;
        let side = randprotocol_core::consensus::PrunedBundle {
            tx_hash: covered_tx.hash(),
            proof_hash,
            public_values: proof.public_values.clone(),
            shape: fixture_shape(&proof),
        };
        let mut cb = make_block_unchecked(&gs.block, &gs.ledger, vec![marker_tx], &key(1));
        cb.pruned = vec![side];
        (dir, storage, gs, cb)
    }

    /// The sealed form of a hidden-asset (four-slot) bundle, end to end and with no recursion
    /// fixture: the pruned record round-trips through RocksDB with all four nullifiers,
    /// commitments and envelopes and the three burn fields intact; the marker form hashes to the
    /// raw hash, so the served block's certified tx root still holds; the serve path swaps in the
    /// marker and its side-table entry; the coverage rule accepts it once sealed; and a fresh
    /// replica replaying the sealed block reaches the raw block's state root with four leaves
    /// appended. A peer substituting any single slot word or envelope — the dummy slots included —
    /// breaks the root (pre-v0.1 M1, per slot), and a side table whose `OUT` words are not the
    /// four-slot digest is refused at the ledger's pruned branch.
    #[test]
    fn a_four_slot_bundle_round_trips_through_the_pruned_record_and_the_sealed_form() {
        use crate::storage::fixtures::with_distinct_envelopes;
        use crate::storage::TxRecord;
        use randprotocol_core::confidential::ConfidentialExecutor;
        use randprotocol_core::notes::PRUNED_PROOF_MARKER;
        use randprotocol_core::types::pv;
        use randprotocol_core::BlockError;

        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let gs = genesis_of(7, &[&key(1)], vec![], 100);
        storage.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        let raw = with_distinct_envelopes(bundle_tx(&ledger, [[21; 8], [22; 8]], [[23; 8], [24; 8]], bundle_fee()), 0x30);
        let b1 = crate::storage::fixtures::make_block(&gs.block, &mut ledger, vec![raw.clone()], &key(1));
        storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

        // The pruned record exactly as the pruning pass writes it: the marker form, the proof
        // hash, 34 public values whose `OUT` words are the bundle's digest, a declared shape.
        let bundle = raw.bundle.as_ref().unwrap();
        let digest = StubExecutor.bundle_digest(&bundle.digest_input());
        let mut public_values = vec![0u64; pv::NUM];
        public_values[pv::TIER] = 14;
        for k in 0..8 {
            public_values[pv::OUT0 + k] = digest[k] as u64;
            public_values[pv::HC0 + k] = HC[k] as u64;
        }
        let shape = DeclaredShape {
            profile: randprotocol_core::types::FriProfile::Test,
            tier: 14,
            program_log_height: 13,
            input_log_height: 12,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 2,
            mem_log_height: 18,
        };
        let proof_hash = Hash::digest(&bundle.proof);
        let mut marker_tx = raw.clone();
        marker_tx.bundle.as_mut().unwrap().proof = [PRUNED_PROOF_MARKER, proof_hash.as_bytes().as_slice()].concat();
        let record = TxRecord::Pruned {
            height: 1,
            index: 0,
            tx_hash: raw.hash(),
            tx: marker_tx.clone(),
            proof_hash,
            public_values: public_values.clone(),
            shape,
        };
        storage.put_pruned(&record).unwrap();

        // The round trip: every slot and every burn field survives, and the marker form is the
        // raw transaction by id.
        let back = storage.tx_record(&raw.hash()).unwrap().unwrap();
        assert_eq!(back, record);
        let (was, now) = (raw.bundle.as_ref().unwrap(), back.transaction().bundle.as_ref().unwrap());
        assert_eq!((now.nullifiers, now.commitments), (was.nullifiers, was.commitments));
        assert_eq!(now.envelopes, was.envelopes, "all four envelopes, each in its slot");
        assert_eq!((now.fee, now.burn_a, now.burn_r, now.burn_asset, now.time), (was.fee, was.burn_a, was.burn_r, was.burn_asset, was.time));
        assert_eq!(back.transaction().hash(), raw.hash(), "the proof enters the id by digest");
        assert_eq!(storage.tx_hash_by_proof_hash(&proof_hash).unwrap(), Some(raw.hash()));

        // Serve: the marker form and one side entry, under the block's own certified root.
        let served = sealed_form_of(&storage, &b1);
        assert_eq!(served.block.transactions, vec![marker_tx.clone()]);
        assert_eq!(served.pruned.len(), 1);
        assert_eq!((served.pruned[0].tx_hash, served.pruned[0].proof_hash), (raw.hash(), proof_hash));
        assert_eq!(served.pruned[0].public_values, public_values);
        assert!(served.block.verify_tx_root(), "the marker form hashes to the raw hash");

        // Accept: covered by a local mark, then replayed by a fresh replica to the raw root.
        assert!(check_sealed_coverage(&storage, &BTreeSet::new(), &served).is_err(), "unsealed: the fallback");
        storage.mark_sealed(raw.hash(), Hash::digest(b"the covering aggregate"), 2).unwrap();
        check_sealed_coverage(&storage, &BTreeSet::new(), &served).unwrap();
        let mut replica = gs.ledger.clone();
        replica.apply_block_for_sync(&served.block, &BTreeMap::new(), &served.pruned, &StubExecutor).unwrap();
        assert_eq!(replica.state_root(), ledger.state_root());
        assert_eq!(replica.next_index(), gs.ledger.next_index() + 4, "four leaves, dummies included");

        // A substituted slot word or envelope — any of the four — breaks the certified root.
        let substitute = |f: &dyn Fn(&mut randprotocol_core::Bundle)| {
            let mut bad = served.clone();
            f(bad.block.transactions[0].bundle.as_mut().unwrap());
            gs.ledger.clone().apply_block_for_sync(&bad.block, &BTreeMap::new(), &bad.pruned, &StubExecutor)
        };
        for slot in 0..4 {
            assert_eq!(substitute(&|b| b.nullifiers[slot][0] ^= 1), Err(BlockError::TxRootMismatch), "nf {slot}");
            assert_eq!(substitute(&|b| b.commitments[slot][0] ^= 1), Err(BlockError::TxRootMismatch), "cm {slot}");
            assert_eq!(substitute(&|b| b.envelopes[slot].body[0] ^= 1), Err(BlockError::TxRootMismatch), "env {slot}");
        }
        assert_eq!(substitute(&|b| b.burn_r = 1), Err(BlockError::TxRootMismatch), "a burn field");
        // And a side table vouching for another digest is refused at the pruned branch.
        let mut lying = served.clone();
        lying.pruned[0].public_values[pv::OUT0] ^= 1;
        assert!(matches!(
            gs.ledger.clone().apply_block_for_sync(&lying.block, &BTreeMap::new(), &lying.pruned, &StubExecutor),
            Err(BlockError::InvalidTx { index: 0, error: randprotocol_core::TxError::BadDigest })
        ));
    }

    /// The coverage rule (spec §7): a pruned bundle is accepted when its raw hash is sealed
    /// locally or carried by an aggregate in the batch — and falls back to the raw form,
    /// never a ban, when neither holds.
    #[test]
    fn the_sealed_coverage_rule_accepts_marks_and_batch_and_falls_back_otherwise() {
        let (_d, storage, _gs, cb) = sealed_form_fixture();
        let hash = cb.pruned[0].tx_hash;
        // No mark, no batch aggregate: the raw-form fallback, at the block's height.
        let err = check_sealed_coverage(&storage, &BTreeSet::new(), &cb).unwrap_err();
        assert!(err.downcast_ref::<RawFallback>().is_some(), "expected RawFallback, got {err:?}");
        // A batch carrying an aggregate for it: accepted.
        let batch: BTreeSet<Hash> = [hash].into_iter().collect();
        check_sealed_coverage(&storage, &batch, &cb).unwrap();
        // A local mark: accepted without the batch too.
        storage.mark_sealed(hash, Hash::digest(b"the covering aggregate"), 2).unwrap();
        check_sealed_coverage(&storage, &BTreeSet::new(), &cb).unwrap();
        // A marker with no side-table entry is a damaged batch, not a fallback.
        let mut damaged = cb.clone();
        damaged.pruned = Vec::new();
        let err = check_sealed_coverage(&storage, &batch, &damaged).unwrap_err();
        assert!(err.downcast_ref::<RawFallback>().is_none(), "a damaged batch is not the fallback: {err:?}");
    }

    /// The serve half (spec §7): on a pruned store the block rides with its pruned bundle in
    /// marker form and the side table carrying exactly the record's contents; the same block
    /// before pruning is raw by construction.
    #[test]
    fn the_serve_form_carries_the_marker_and_the_table_once_pruned() {
        let (_d, storage, gs, covered_tx, _mint) = chain_with_a_real_proof();
        let raw_cb = make_block_unchecked(&gs.block, &gs.ledger, vec![covered_tx.clone()], &key(1));
        let raw_form = sealed_form_of(&storage, &raw_cb);
        assert!(raw_form.pruned.is_empty(), "nothing pruned: the raw form");
        assert_eq!(raw_form.block.transactions[0], covered_tx, "untouched");
        // Seal and prune it, then serve again.
        storage.mark_sealed(covered_tx.hash(), Hash::digest(b"the covering aggregate"), 1).unwrap();
        assert_eq!(storage.prune_sealed(300, 256, randprotocol_core::types::FriProfile::Test).unwrap(), 1);
        let sealed = sealed_form_of(&storage, &raw_cb);
        assert_eq!(sealed.pruned.len(), 1, "one bundle, one side entry");
        let side = &sealed.pruned[0];
        assert_eq!(side.tx_hash, covered_tx.hash());
        let proof = crate::agg_executor::fixture_proof(0);
        assert_eq!(side.proof_hash, Hash::digest(&proof.to_bytes()));
        assert_eq!(side.public_values, proof.public_values);
        assert_eq!(side.shape, fixture_shape(&proof));
        let served_tx = &sealed.block.transactions[0];
        let field = served_tx.bundle.as_ref().unwrap().proof.clone();
        assert!(field.starts_with(randprotocol_core::notes::PRUNED_PROOF_MARKER), "the marker form rides");
    }

    /// The capstone stall's chain shape, stored: block 2 carries the fixture-proof bundle,
    /// `fat` heights each carry one max-size raw proof (the raw bundles that spend the byte
    /// budget between a window and its cover), and the covering aggregate lands at
    /// `aggregate_at`, the chain's last block. The bundle is sealed at the aggregate's height
    /// and pruned, so serving returns block 2 in marker form. The stored blocks are built
    /// unchecked; the ledger applies each bundle's stub twin (same commitments and
    /// nullifiers), so the commit's note bookkeeping balances.
    fn chain_with_a_split_cover(fat: &[u64], aggregate_at: u64) -> (tempfile::TempDir, Storage, Transaction) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let gs = genesis_of(7, &[&key(1)], vec![], 2);
        storage.init_genesis(&gs).unwrap();
        let mut ledger_after = gs.ledger.clone();
        let mut covered: Option<Transaction> = None;
        let mut agg: Option<Transaction> = None;
        let mut parent = gs.block.clone();
        let mut blocks = Vec::new();
        for h in 1..=aggregate_at {
            ledger_after.set_height(h);
            ledger_after.set_timestamp_ms(h);
            let stored: Vec<Transaction> = if h == 2 {
                let twin = bundle_tx(&ledger_after, [[21; 8], [22; 8]], [[23; 8], [24; 8]], bundle_fee());
                ledger_after.apply_transactions(std::slice::from_ref(&twin), &key(1).address(), &StubExecutor).unwrap();
                let mut tx = twin;
                tx.bundle.as_mut().unwrap().proof = crate::agg_executor::fixture_proof(0).to_bytes();
                covered = Some(tx.clone());
                vec![tx]
            } else if h == aggregate_at {
                let tx = aggregate_tx(7, &key(7), 0, 1, vec![covered.as_ref().unwrap().hash()], b"ok".to_vec());
                agg = Some(tx.clone());
                vec![tx]
            } else if fat.contains(&h) {
                let n = h as u32;
                let twin = bundle_tx(&ledger_after, [[n; 8], [n + 40; 8]], [[n + 80; 8], [n + 120; 8]], bundle_fee());
                ledger_after.apply_transactions(std::slice::from_ref(&twin), &key(1).address(), &StubExecutor).unwrap();
                let mut tx = twin;
                tx.bundle.as_mut().unwrap().proof = vec![7u8; gas::MAX_PROOF_BYTES];
                vec![tx]
            } else {
                vec![]
            };
            ledger_after.record_anchor(h);
            let cb = make_block_unchecked(&parent, &ledger_after, stored, &key(1));
            parent = cb.block.clone();
            blocks.push(cb);
        }
        storage.commit(&blocks, &ledger_after, &[], &StubExecutor).unwrap();
        let covered = covered.expect("block 2 carries the covered bundle");
        storage.mark_sealed(covered.hash(), agg.expect("the last block carries the aggregate").hash(), aggregate_at).unwrap();
        assert_eq!(storage.prune_sealed(aggregate_at + 256, 256, randprotocol_core::types::FriProfile::Test).unwrap(), 1);
        (dir, storage, covered)
    }

    /// Serve `Blocks { from_height: 1, max }` against the split-cover store the way
    /// `serve_sync` does: the lazy read, the sealed form, the budget — and the coverage
    /// closure.
    fn serve_blocks(storage: &Storage, max: u64) -> Vec<CommittedBlock> {
        let heights = 1..1u64.saturating_add(max);
        let blocks = heights
            .map_while(|h| storage.committed_block(h).ok().flatten())
            .map(|cb| sealed_form_of(storage, &cb));
        let mut batch = fill_sync_batch(blocks, serve_sync_budget(&network::WireLimits::default()));
        close_batch_coverage(storage, &mut batch, &network::WireLimits::default());
        batch
    }

    /// What the syncer does with a batch: the covers its aggregates carry, then the coverage
    /// check against its own (fresh, mark-less) store.
    fn accepted_by_a_fresh_store(batch: &[CommittedBlock]) -> Result<()> {
        let dir = tempfile::tempdir().unwrap();
        let client = Storage::open(dir.path()).unwrap();
        let mut batch_covers = BTreeSet::new();
        for cb in batch {
            for tx in &cb.block.transactions {
                if let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action {
                    batch_covers.extend(covers.iter().copied());
                }
            }
        }
        for cb in batch {
            check_sealed_coverage(&client, &batch_covers, cb)?;
        }
        Ok(())
    }

    /// The stall's mechanism, pinned: a batch cut between a pruned block and its covering
    /// aggregate — here by the count, halved on wire failures under load — is unusable to the
    /// syncer and comes back as the raw-form fallback, identically from every pruned peer
    /// (the ping-pong the capstone showed). The serve closes the coverage instead: the
    /// response extends past the count it was asked for until the cover is in, and the
    /// syncer accepts the batch.
    #[test]
    fn a_batch_cut_short_of_its_cover_extends_until_the_coverage_closes() {
        let (_d, storage, covered_tx) = chain_with_a_split_cover(&[], 5);
        // The fill without the closure: the halved count's three blocks, the cover at 5
        // unserved — the exact shape the fallback ping-ponged on.
        let heights = 1..=3u64;
        let blocks = heights
            .map_while(|h| storage.committed_block(h).ok().flatten())
            .map(|cb| sealed_form_of(&storage, &cb));
        let cut = fill_sync_batch(blocks, serve_sync_budget(&network::WireLimits::default()));
        assert_eq!(cut.len(), 3);
        assert_eq!(cut[1].pruned.len(), 1, "block 2 rides in marker form");
        assert!(accepted_by_a_fresh_store(&cut).unwrap_err().downcast_ref::<RawFallback>().is_some());
        // The served batch: the closure reaches the aggregate's block, and the syncer takes it.
        let batch = serve_blocks(&storage, 3);
        assert_eq!(batch.last().unwrap().block.height(), 5, "the extension closed the coverage");
        assert!(batch[1].pruned[0].tx_hash == covered_tx.hash());
        accepted_by_a_fresh_store(&batch).expect("a coverage-closed batch is accepted");
    }

    /// The byte-budget twin of the count cut: max-proof raw bundles between the pruned block
    /// and its cover spend the budget before the cover's height, so even a full-count ask is
    /// cut. The extension goes past the soft budget but stays inside the reader's limit.
    #[test]
    fn a_batch_cut_by_bytes_short_of_its_cover_extends_within_the_reader_limit() {
        let (_d, storage, _covered_tx) = chain_with_a_split_cover(&[4, 5, 6], 7);
        let batch = serve_blocks(&storage, SYNC_BATCH as u64);
        assert!(batch.last().unwrap().block.height() > 5, "the budget alone would have cut at 5");
        assert_eq!(batch.last().unwrap().block.height(), 7, "the cover's block");
        let on_the_wire = wire_size(&batch);
        assert!(
            on_the_wire > network::SYNC_MAX_WIRE_BYTES,
            "the closure goes past the soft budget: {on_the_wire} B"
        );
        assert!(
            on_the_wire <= network::SYNC_RESPONSE_WIRE_LIMIT,
            "and stays readable: {on_the_wire} B over {} B",
            network::SYNC_RESPONSE_WIRE_LIMIT
        );
        accepted_by_a_fresh_store(&batch).expect("a coverage-closed batch is accepted");
    }

    /// The case the fallback is for: a cover so far out the extension cannot reach it inside
    /// the reader limit. The serve stops at the limit rather than past it — an undeliverable
    /// response helps no one — and the syncer's raw-form fallback (an archive peer) is what
    /// remains.
    #[test]
    fn the_extension_stops_at_the_reader_limit_and_serves_what_it_can() {
        let (_d, storage, _covered_tx) = chain_with_a_split_cover(&[4, 5, 6, 7, 8, 9, 10, 11], 12);
        let batch = serve_blocks(&storage, SYNC_BATCH as u64);
        let last = batch.last().unwrap().block.height();
        assert!(last > 5, "it extended past the soft cut as far as the limit allows: {last}");
        assert!(last < 12, "the cover at 12 stays out of reach: {last}");
        let on_the_wire = wire_size(&batch);
        assert!(
            on_the_wire <= network::SYNC_RESPONSE_WIRE_LIMIT,
            "never past the reader's limit: {on_the_wire} B over {} B",
            network::SYNC_RESPONSE_WIRE_LIMIT
        );
        // Unclosed, so the fresh syncer's answer is the fallback — the archive case, pinned
        // in `the_sealed_coverage_rule_accepts_marks_and_batch_and_falls_back_otherwise`.
        assert!(accepted_by_a_fresh_store(&batch).unwrap_err().downcast_ref::<RawFallback>().is_some());
    }

    /// The worker arm's ordering (cheap before expensive, and bytes before storage): the wire
    /// caps and the chain id refuse before a single cover is looked up, an ungated chain names
    /// the gate, and anything that is not an aggregate is the ledger's own `validate`.
    #[test]
    fn validate_for_pool_preflights_before_any_storage_read() {
        let (_d, storage, gs, _covered, _mint) = chain_with_a_real_proof();
        let kp = key(7);
        let mut gated = gs.ledger.clone();
        gated.set_aggregation(Some(agg_cfg(
            fixture_shape(&crate::agg_executor::fixture_proof(0)),
            fixture_hc(&crate::agg_executor::fixture_proof(0)),
        )));
        // Wrong chain id *and* an unknown cover: the byte verdict must come first.
        let tx = aggregate_tx(99, &kp, 0, 1, vec![Hash::digest(b"unknown")], b"ok".to_vec());
        match validate_for_pool(&tx, &gated, &storage, randprotocol_core::types::FriProfile::Test, &StubExecutor) {
            Err(randprotocol_core::TxError::WrongChain { expected: 7, actual: 99 }) => {}
            other => panic!("the preflight's WrongChain must precede assembly, got {other:?}"),
        }
        // Ungated: the gate is the preflight's first check.
        let tx = aggregate_tx(7, &kp, 0, 1, vec![], b"ok".to_vec());
        assert_eq!(
            validate_for_pool(&tx, &gs.ledger, &storage, randprotocol_core::types::FriProfile::Test, &StubExecutor),
            Err(randprotocol_core::TxError::UnsupportedAction("aggregation"))
        );
        // Not an aggregate: delegated. A valid mint validates; a forged one is the ledger's answer.
        let mint = Transaction::mint(7, [41; 8], 0, [41; 8], env(4), 1000, &key(1), &StubExecutor);
        assert!(
            validate_for_pool(&mint, &gs.ledger, &storage, randprotocol_core::types::FriProfile::Test, &StubExecutor).is_ok()
        );
    }

    /// End to end through the worker arm: the stored fixture bundle assembled, the ledger's
    /// nine steps against it, and a well-formed aggregate admitted.
    #[test]
    fn validate_for_pool_admits_a_well_formed_aggregate_end_to_end() {
        let (_d, storage, gs, covered_tx, _mint) = chain_with_a_real_proof();
        let proof = crate::agg_executor::fixture_proof(0);
        let cfg = agg_cfg(fixture_shape(&proof), fixture_hc(&proof));
        let mut ledger = gs.ledger.clone();
        ledger.set_aggregation(Some(cfg.clone()));
        ledger.set_height(1);
        let kp = key(7);
        register_aggregator(&mut ledger, &kp, cfg.bond);
        // As above: the stored bundle into the coverable set the gated apply would have built.
        ledger.set_unsealed_fees([(covered_tx.hash(), (0, key(1).address(), u64::MAX))].into_iter().collect());

        let tx = aggregate_tx(7, &kp, 0, 1, vec![covered_tx.hash()], b"ok".to_vec());
        validate_for_pool(&tx, &ledger, &storage, randprotocol_core::types::FriProfile::Test, &StubExecutor)
            .expect("a well-formed aggregate over a stored bundle validates");
        // And the state-dependent verdicts come off the snapshot: a wrong nonce is the
        // register's answer, not assembly's.
        let tx = aggregate_tx(7, &kp, 5, 1, vec![covered_tx.hash()], b"ok".to_vec());
        match validate_for_pool(&tx, &ledger, &storage, randprotocol_core::types::FriProfile::Test, &StubExecutor) {
            Err(randprotocol_core::TxError::Aggregation(AggregationError::BadNonce { expected: 0, actual: 5 })) => {}
            other => panic!("expected BadNonce, got {other:?}"),
        }
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
        CommittedBlock { block, pruned: Vec::new(), qc: votes_of(height, hash, ks, votes), receipts: Vec::new(), deposits: Vec::new() }
    }

    fn validators(n: u8) -> Vec<Keypair> {
        (1..=n).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect()
    }

    /// A shielded transaction carrying a `proof_bytes`-byte proof, standing in for a real one.
    ///
    /// The proof bytes are pseudo-random (a splitmix64 stream seeded by the length), as a real
    /// proof's are: a run of one small value would measure the CBOR wire at one byte per byte
    /// even as an integer array (CBOR writes an integer below 24 in one byte), hiding the ~1.9x an
    /// integer array costs on real proof bytes.
    fn fat_tx(proof_bytes: usize) -> Transaction {
        let mut state = proof_bytes as u64 ^ 0x5eed_5eed_5eed_5eed;
        let mut next = || {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let proof: Vec<u8> = (0..proof_bytes.div_ceil(8)).flat_map(|_| next().to_le_bytes()).take(proof_bytes).collect();
        let bundle = randprotocol_core::notes::Bundle {
            anchor: [1; 8],
            nullifiers: crate::storage::fixtures::pad4([[2; 8], [3; 8]]),
            commitments: crate::storage::fixtures::pad4([[4; 8], [5; 8]]),
            fee: 1,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 1,
            envelopes: [crate::storage::fixtures::env(1), crate::storage::fixtures::env(2), crate::storage::fixtures::env(1), crate::storage::fixtures::env(2)],
            proof,
        };
        randprotocol_core::confidential::StubExecutor::bound(Transaction::shielded(7, bundle, randprotocol_core::Action::None))
    }

    /// The byte-vector fields ride the CBOR sync wire as byte strings (`crypto::wire_bytes`), not
    /// as integer arrays: a block of pseudo-random proof bytes weighs on the wire what it weighs
    /// in bincode, plus the CBOR map keys and headers — about 500 B here, where an integer array
    /// would have been ~1.9x.
    #[test]
    fn a_block_of_random_proof_bytes_is_no_larger_in_cbor_than_in_bincode() {
        let ks = validators(4);
        let cb = sized_block(1, &ks, 4, vec![fat_tx(2 << 20), fat_tx(1 << 20), fat_tx(300_000)]);
        let bincode_len = bincode::serialize(&cb).unwrap().len() as u64;
        let cbor_len = wire_size(std::slice::from_ref(&cb));
        // Measured: 3 480 995 B bincode, 3 481 497 B CBOR (6 604 236 B as integer arrays).
        let margin = 16 << 10;
        assert!(bincode_len > 3 << 20, "{bincode_len} B");
        assert!(cbor_len <= bincode_len + margin, "cbor {cbor_len} B vs bincode {bincode_len} B");
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
        assert_eq!(serve_sync_budget(&network::WireLimits::default()), network::SYNC_MAX_WIRE_BYTES);
        // A raised chain's budget is its own, and keeps the same relation to its reader limit.
        let raised = network::WireLimits::for_block_bytes(20 << 20);
        assert_eq!(serve_sync_budget(&raised), 22 << 20);
        assert!(2 * serve_sync_budget(&raised) <= raised.sync_response_wire_limit);
    }

    /// Twenty-mebibyte blocks (call limits spec §8): the worst block a 20 MiB chain admits is
    /// over the default reader limit, so the limits must come from the ledger — and with them it
    /// is servable alone and readable.
    #[test]
    fn the_largest_block_a_20_mib_chain_admits_is_servable_and_readable_alone() {
        let mut ledger = crate::storage::fixtures::genesis(1).ledger;
        ledger.set_max_proof_bytes(8 << 20);
        ledger.set_max_block_bytes(20 << 20);
        let limits = network::WireLimits::for_ledger(&ledger);
        let ks = validators(18);
        let txs = vec![fat_tx(8 << 20), fat_tx(8 << 20), fat_tx(3 << 20)];
        let tx_bytes: usize = txs.iter().map(|t| bincode::serialize(t).unwrap().len()).sum();
        assert!(tx_bytes <= ledger.max_block_bytes(), "a block the chain admits: {tx_bytes} B");
        let block = sized_block(1, &ks, 18, txs);

        let batch = fill_sync_batch(vec![block], serve_sync_budget(&limits));
        assert_eq!(batch.len(), 1);
        let on_the_wire = wire_size(&batch);
        assert!(on_the_wire > network::SYNC_RESPONSE_WIRE_LIMIT, "the default reader would refuse it: {on_the_wire} B");
        assert!(
            on_the_wire <= limits.sync_response_wire_limit,
            "the chain's own reader takes it: {on_the_wire} B over {} B",
            limits.sync_response_wire_limit
        );
    }

    async fn wait_for_event<T>(
        rx: &mut mpsc::Receiver<NetworkEvent>,
        timeout: Duration,
        mut f: impl FnMut(NetworkEvent) -> Option<T>,
    ) -> Option<T> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
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

    /// Two swarms on loopback with `limits`, B bootstrapped to A, both sides connected.
    async fn two_swarms(
        limits: network::WireLimits,
        seeds: (u8, u8),
    ) -> (NetworkHandle, mpsc::Receiver<NetworkEvent>, NetworkHandle, mpsc::Receiver<NetworkEvent>) {
        let cfg = |bootstrap| NetworkConfig {
            chain_id: 7,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap,
            enable_mdns: false,
            limits,
        };
        let (a, mut a_rx) = network::start(cfg(vec![]), [seeds.0; 32]).await.unwrap();
        let a_addr = wait_for_event(&mut a_rx, Duration::from_secs(5), |e| match e {
            NetworkEvent::Listening(addr) => Some(addr),
            _ => None,
        })
        .await
        .expect("A listening");
        let a_full = a_addr.with(libp2p::multiaddr::Protocol::P2p(a.local_peer_id));
        let (b, mut b_rx) = network::start(cfg(vec![a_full]), [seeds.1; 32]).await.unwrap();
        let b_id = b.local_peer_id;
        let a_id = a.local_peer_id;
        assert!(wait_for_event(&mut a_rx, Duration::from_secs(10), |e| matches!(e, NetworkEvent::PeerConnected(p) if p == b_id).then_some(())).await.is_some());
        assert!(wait_for_event(&mut b_rx, Duration::from_secs(10), |e| matches!(e, NetworkEvent::PeerConnected(p) if p == a_id).then_some(())).await.is_some());
        (a, a_rx, b, b_rx)
    }

    /// A asks B for block 1; B serves `block` through the node's own batch fill. What A hears.
    async fn sync_one_block(limits: network::WireLimits, seeds: (u8, u8), block: CommittedBlock) -> Result<Vec<CommittedBlock>, String> {
        let (a, mut a_rx, b, mut b_rx) = two_swarms(limits, seeds).await;
        let req_id = a
            .send_sync_request(b.local_peer_id, SyncRequest::Blocks { from_height: 1, max: 1 })
            .await
            .expect("request id");
        let a_id = a.local_peer_id;
        let channel = wait_for_event(&mut b_rx, Duration::from_secs(10), |e| match e {
            NetworkEvent::SyncRequest { peer, channel, .. } if peer == a_id => Some(channel),
            _ => None,
        })
        .await
        .expect("B got the sync request");
        let batch = fill_sync_batch(vec![block], serve_sync_budget(&limits));
        b.send_sync_response(channel, SyncResponse::Blocks(batch)).await;
        let b_id = b.local_peer_id;
        let out = wait_for_event(&mut a_rx, limits.sync_request_timeout + Duration::from_secs(10), |e| match e {
            NetworkEvent::SyncResponse { peer, request_id, response: SyncResponse::Blocks(v) } if peer == b_id && request_id == req_id => {
                Some(Ok(v))
            }
            NetworkEvent::SyncFailed { peer, request_id, error } if peer == b_id && request_id == req_id => Some(Err(error)),
            _ => None,
        })
        .await
        .expect("A heard back about its request");
        a.shutdown().await;
        b.shutdown().await;
        out
    }

    /// Two local nodes sync a block larger than 6 MiB — larger, in fact, than the whole default
    /// reader limit (12.25 MiB) — on a chain whose genesis raised `max_block_bytes` to 20 MiB,
    /// because both ends size their sync codec from the ledger. The same block between nodes on
    /// today's constants is refused: the limits are what moved.
    #[tokio::test]
    async fn two_nodes_on_a_20_mib_chain_sync_a_block_over_the_default_reader_limit() {
        let ks = validators(4);
        let block = sized_block(1, &ks, 4, (0..7).map(|_| fat_tx(2 << 20)).collect());
        let on_the_wire = wire_size(std::slice::from_ref(&block));
        assert!(on_the_wire > 6 << 20, "{on_the_wire} B");
        assert!(on_the_wire > network::SYNC_RESPONSE_WIRE_LIMIT, "{on_the_wire} B");
        let want = block.block.hash();

        let mut ledger = crate::storage::fixtures::genesis(1).ledger;
        ledger.set_max_proof_bytes(8 << 20);
        ledger.set_max_block_bytes(20 << 20);
        let got = sync_one_block(network::WireLimits::for_ledger(&ledger), (31, 32), block.clone())
            .await
            .expect("a 20 MiB chain's nodes sync it");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].block.hash(), want);

        let refused = sync_one_block(network::WireLimits::default(), (33, 34), block).await;
        assert!(refused.is_err(), "today's limits cannot carry it");
    }

    #[test]
    fn a_capped_batch_of_chain_8_blocks_fits_on_the_wire() {
        let ks = validators(18);
        let blocks: Vec<CommittedBlock> = (1..=SYNC_BATCH as u64).map(|h| sized_block(h, &ks, 18, vec![])).collect();
        let batch = fill_sync_batch(blocks, serve_sync_budget(&network::WireLimits::default()));
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

        let batch = fill_sync_batch(vec![block], serve_sync_budget(&network::WireLimits::default()));
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
        // The running node gives up on its chain's own wire timeout, the one `network::start`
        // hands to request-response — the same value, so neither side is shorter.
        for block_bytes in [randprotocol_core::gas::MAX_BLOCK_BYTES, 20 << 20] {
            let wire = network::WireLimits::for_block_bytes(block_bytes);
            assert!(wire.sync_request_timeout >= SYNC_GIVE_UP);
        }
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
        let bundle = randprotocol_core::notes::Bundle {
            anchor: [n; 8],
            nullifiers: crate::storage::fixtures::pad4([[n + 10; 8], [n + 20; 8]]),
            commitments: crate::storage::fixtures::pad4([[n + 30; 8], [n + 40; 8]]),
            fee: 1,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 1,
            envelopes: [crate::storage::fixtures::env(tag), crate::storage::fixtures::env(tag.wrapping_add(1)), crate::storage::fixtures::env(tag), crate::storage::fixtures::env(tag.wrapping_add(1))],
            proof: vec![tag; 32],
        };
        randprotocol_core::confidential::StubExecutor::bound(Transaction::shielded(7, bundle, randprotocol_core::Action::None))
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
        refused.insert(tx.hash(), randprotocol_core::TxError::BadDigest);

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

    /// Task 5b review, fix round 1: a marker-form copy must not poison the refused cache. The
    /// copy — the honest transaction with `bundle.proof` replaced by the sealed form's marker —
    /// hashes to the honest transaction's id by design (M1). If its refusal were cached, the node
    /// would then refuse the honest transaction from the cache without verifying it: any gossip
    /// peer that saw a transaction first could censor it network-wide. The copy first, then the
    /// honest one: the honest one is verified and admitted.
    #[test]
    fn a_marker_form_copy_does_not_poison_the_refused_cache_for_the_raw_transaction() {
        use crate::admission::{acceptance_for, Acceptance, GossipOutcome, PeerLimiter, RefusedCache};
        let (_d, storage, gs) = crate::storage::fixtures::genesis_with_two_notes();
        let raw = bundle_tx(&gs.ledger, [[1; 8], [2; 8]], [[3; 8], [4; 8]], bundle_fee());
        let mut marker = raw.clone();
        let b = marker.bundle.as_mut().unwrap();
        let mut m = randprotocol_core::notes::PRUNED_PROOF_MARKER.to_vec();
        m.extend_from_slice(Hash::digest(&b.proof).as_bytes());
        b.proof = m;
        assert_eq!(marker.hash(), raw.hash(), "the marker form carries the raw id");
        let profile = randprotocol_core::types::FriProfile::Test;
        let mut refused = RefusedCache::new(8);
        let limiter = PeerLimiter::new(16, 4.0);
        let now = std::time::Instant::now();
        // The copy arrives first and is verified — and refused, but not as a statement about the id.
        assert_eq!(GossipOutcome::for_transaction(&marker, None, &mut refused, &limiter, 0, now), GossipOutcome::Verify);
        let verdict = validate_for_pool(&marker, &gs.ledger, &storage, profile, &StubExecutor);
        assert!(verdict.is_err(), "the marker form is not admissible outside sync");
        assert_ne!(acceptance_for(&verdict, marker.hash(), &mut refused), Acceptance::Reject);
        assert!(refused.is_empty(), "nothing cached under the shared id: {:?}", refused.get(&raw.hash()));
        // The honest transaction is then verified, not answered from the cache, and admitted.
        assert_eq!(GossipOutcome::for_transaction(&raw, None, &mut refused, &limiter, 0, now), GossipOutcome::Verify);
        assert_eq!(validate_for_pool(&raw, &gs.ledger, &storage, profile, &StubExecutor), Ok(()));
    }

    /// A verdict decides the acceptance, and only a permanent one reaches the cache.
    #[test]
    fn a_verdict_reports_and_caches_by_permanence() {
        use crate::admission::{acceptance_for, Acceptance, RefusedCache};
        use randprotocol_core::TxError;
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
        use randprotocol_core::TxError;
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
        use randprotocol_core::TxError;
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
