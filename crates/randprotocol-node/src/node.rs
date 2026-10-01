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
use anyhow::{anyhow, Context, Result};
use libp2p::{Multiaddr, PeerId};
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::consensus::{Action, CommittedBlock, ConsensusConfig, ConsensusError, ConsensusMessage, HotStuff, NotHeld};
use randprotocol_core::Block;
use randprotocol_core::genesis::{Genesis, GenesisState};
use randprotocol_core::{Hash, Keypair, Ledger, NoVerified, ShieldedAddress, Transaction, ValidatorSet, Word8, FAUCET_MAX_UNITS};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::notes::{Note, SpendKey};
use randprotocol_zkvm::viewing::TxKey;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering, Ordering::SeqCst};
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
    /// Refuse to start with less than this free on the data directory's filesystem, and report
    /// `disk_low` in `rand_getHealth` under [`disk::DISK_LOW_FACTOR`] times it (audit v4 OPS-3).
    /// `--min-free-disk-mb`, default 1 GB; zero disables the guard.
    pub min_free_disk_bytes: u64,
    /// Keep only this much block history (history pruning spec §1); `None` keeps everything.
    pub prune_history: Option<Duration>,
    /// Spec 2026-09-28 §4.1: price calls by their proof header; None = no policy.
    pub gas_policy: Option<randprotocol_core::gas::GasPolicy>,
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
    /// The public listener's bound address and task, when `--public-rpc` was given.
    pub public_rpc_addr: Option<SocketAddr>,
    pub public_rpc_task: Option<tokio::task::JoinHandle<()>>,
}

impl NodeHandle {
    /// Stop the node loop, the RPC server and the network task, releasing the
    /// database so the data directory can be reopened.
    pub async fn shutdown(self) {
        self.network.shutdown().await;
        self.task.abort();
        self.rpc_task.abort();
        if let Some(t) = &self.public_rpc_task {
            t.abort();
        }
        let _ = self.task.await;
        let _ = self.rpc_task.await;
        if let Some(t) = self.public_rpc_task {
            let _ = t.await;
        }
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
    // The staking gate (audit v4, STAKE-2) lives there too: without this a restarted node would
    // compute `rand-state-2` roots against peers on `rand-state-5`, refuse nothing the faucet
    // budget refuses and seat a bond an epoch early — a fork at its first restart.
    ledger.set_staking(gs.ledger.staking().cloned());
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
    // And the exact envelope size (spec 2026-09-26 §2.4): `load_ledger` comes back at `None`,
    // today's at-most rule, and a node that forgot it would admit short envelopes its peers
    // refuse — a fork at its first restart.
    ledger.set_envelope_bytes(gs.ledger.envelope_bytes());
    // And the v0.6 switch (`hardening_v6`, the pc window first): a node that came back without it
    // would admit and apply what its peers refuse — a fork at the first such transaction after its
    // restart.
    ledger.set_hardening_v6(gs.ledger.hardening_v6());
    // And split authorisation's auth guest (genesis `hc_auth`): a node that came back without it
    // would recompute the v1 digest and refuse every v3 bundle its peers apply — a fork at the
    // first transaction after its restart.
    ledger.set_hc_auth(gs.ledger.hc_auth());
    // And the gas section (design 2026-09-28 §4.2, §4.3, §7.1): `load_ledger` comes back at
    // `None`, and a node that kept it would run without the prices and the bundle gas limit its
    // peers enforce.
    ledger.set_gas(gs.ledger.gas().cloned());
    // And the testnet marker (audit v6, STAKE-2): served, not judged, but a node that came
    // back without it would tell wallets a testnet is not one.
    ledger.set_testnet(gs.ledger.testnet());
    // And the proof window (issue #118; genesis `proof_window_blocks`), with the anchor rows past
    // the 256 `load_ledger` reads: a node that came back at 256 would refuse every bundle whose
    // anchor or `time` is older than that and inside the genesis window — applied by its peers,
    // so a fork at the first one after its restart.
    storage.restore_proof_window(&mut ledger, gs)?;
    // And the consensus signing domain (audit v4): `load_ledger` comes back at v0, and a node
    // that kept it on a v1 chain would refuse every peer's proposal at the ledger's own
    // signature check.
    ledger.set_signing_domain(gs.signing_domain());
    // And the binding domain (audit v6, BIND-1; genesis `binding_domain`): `load_ledger` comes
    // back at `ChainId`, and a node that kept it on a `binding_domain: 1` chain would recompute
    // every transaction's binding and every signed action message without the genesis hash —
    // refusing each transaction its peers apply, and admitting ones made for any other chain
    // that shares the chain id. A fork at the first transaction after its restart.
    ledger.set_binding_domain(*gs.ledger.binding_domain());
    // And the bridge fees (v0.6.8, genesis `bridge.fees`): stored with the bridge, but a genesis
    // parameter, so the file is the authority — a node that came back without them would mint
    // every deposit whole and release every burn whole while its peers split them, and compute a
    // different bridge root besides: a fork at its first block.
    if let Some(bridge) = ledger.bridge_mut() {
        bridge.fees = gs.ledger.bridge().and_then(|b| b.fees.clone());
    }
    // The vesting register is state, not a switch: storage holds it (claims move it), so it is
    // never re-seeded from the file — but the two must agree that the chain has one, or this
    // node would compute a different state-root domain from its peers at its first block.
    if gs.ledger.vesting().is_some() != ledger.vesting().is_some() {
        anyhow::bail!(
            "the genesis file {} a vesting section but the database {} a vesting register",
            if gs.ledger.vesting().is_some() { "has" } else { "has no" },
            if ledger.vesting().is_some() { "holds" } else { "holds no" },
        );
    }
    // Program state (RPL-2) is state too — cells and vaults move with every `Invoke` — and the
    // same presence rule holds: a node on one side of it would hash `rand-state-8` against
    // peers that do not, or refuse every invoke they apply.
    if gs.ledger.program_state().is_some() != ledger.program_state().is_some() {
        anyhow::bail!(
            "the genesis file {} program_state section but the database {} program state",
            if gs.ledger.program_state().is_some() { "has a" } else { "has no" },
            if ledger.program_state().is_some() { "holds" } else { "holds no" },
        );
    }
    // One field of the blob is not state: `cell_fee` is the genesis parameter, bound into the
    // genesis hash and outside the state root. The file's value is the authority, as for every
    // other genesis parameter this function restores — a stored fee that differed (a damaged
    // blob; nothing on chain moves it) would otherwise price this node's invokes unlike its
    // peers' and refuse blocks they apply. `verify_chain` names such a blob and the repair
    // rewrites it; this makes the running ledger right either way.
    if let (Some(genesis), Some(stored)) = (gs.ledger.program_state(), ledger.program_state()) {
        if stored.cell_fee != genesis.cell_fee {
            let mut fixed = stored.clone();
            fixed.cell_fee = genesis.cell_fee;
            ledger.set_program_state(Some(fixed));
        }
    }
    Ok(ledger)
}

/// Audit v6, CON-5: a node that stopped on conflicting finality does not start again on its own.
/// The halt it recorded names what it saw; an operator reads it (`rand-node safety status`),
/// decides what the store is worth — a re-sync from an archive is the usual answer — and clears
/// it (`rand-node safety clear-halt`). Before the chain is even verified: a store this node has
/// reason to distrust is not one to repair in place on a restart loop.
pub fn refuse_a_halted_store(storage: &Storage) -> Result<()> {
    match storage.safety_halt()? {
        None => Ok(()),
        Some(h) => Err(anyhow!(
            "this node stopped on conflicting finality and has not been cleared: at height {} it held committed head {:?} \
             and a certified three-chain tried to commit {:?}, which does not descend from it (recorded at {} ms). \
             Do not restart it blindly: compare its head with the fleet's, re-sync from an archive if it differs, \
             then run `rand-node safety clear-halt --datadir <dir>` (audit v6, CON-5)",
            h.height,
            h.committed,
            h.attempted,
            h.at_ms
        )),
    }
}

/// The snapshot is the head block's state or this node does not start on it (audit v6, OPS-5).
/// A pruned node's startup check is structural — blocks, links, certificates from the floor —
/// and `--verify-chain off` checks nothing, so until this comparison the stored ledger was taken
/// on trust: a damaged or altered nullifier set, note tree or register was resumed on, voted
/// with, and answered from. The head header's `state_root` is certified by the head's QC; the
/// reload reproduces it exactly on an honest store (the restart tests pin that), so any
/// difference is the snapshot's. Not repaired in place: a pruned node holds one ledger and no
/// history to rebuild it from.
pub fn snapshot_is_the_head_state(head_block: &Block, reloaded: &Ledger) -> Result<()> {
    let reloaded_root = reloaded.state_root();
    if reloaded_root != head_block.header.state_root {
        anyhow::bail!(
            "the stored ledger snapshot is not the state of the head block: height {} commits to state root {:?} and the \
             snapshot hashes to {:?}. The store is damaged or was altered; do not run this node on it — re-sync it \
             (from an archive if it is pruned) (audit v6, OPS-5)",
            head_block.height(),
            head_block.header.state_root,
            reloaded_root
        );
    }
    Ok(())
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
    snapshot_is_the_head_state(&head_block, &ledger)?;
    let safety = storage.load_safety()?;
    // The certified chain above the head (audit v5, CON-4), which `resume` puts back in the
    // tree. A database v0.5.4 wrote holds instead the one locked block it kept beside the lock
    // (audit v4): that is read once more, folded into the pending set below, and its key retired.
    let mut pending = storage.pending_blocks()?;
    let legacy = storage.locked_block()?;
    if pending.is_empty() {
        pending.extend(legacy.clone());
    }
    let mut ccfg = ConsensusConfig::new(gs.chain_id, gs.validators.clone(), gs.hash());
    ccfg.epoch_blocks = gs.epoch_blocks;
    ccfg.domain = gs.signing_domain();
    ccfg.base_timeout = base_timeout;
    ccfg.max_timeout = max_timeout;
    let epoch_sets = storage.load_epoch_sets()?;
    let hs = HotStuff::resume(ccfg, signer, head_block, head_qc, ledger, safety, pending, epoch_sets, executor);
    if legacy.is_some() {
        storage.save_pending_blocks(&hs.certified_chain_blocks())?;
        storage.clear_locked_block()?;
        tracing::info!("the v0.5.4 locked block was folded into the pending set; its key is retired");
    }
    Ok(hs)
}

/// The answer to a by-hash fetch: the block from the tree or the committed chain; failing that,
/// a validator's signed not-held (audit v4, CON-4) so the asker can count its stake toward
/// releasing a lock, and an observer's `Block(None)` — its word carries no stake. A block kept
/// only as an orphan is held, not attested unheld (scan 2026-09-27, CN-3): `Block(None)`. The
/// signed answer comes from `signed` when this hash was answered before in the current view
/// (SW-2): a not-held is over the genesis, the hash and the signer's view (CN-3), so a kept one
/// is as good as a fresh one until the view moves, and a repeated request no longer buys a
/// Dilithium2 signature — at most one per hash and view. The block lookup runs first on every
/// request, so a block that arrives after its not-held was kept is served, never denied.
fn block_by_hash_response(hs: &HotStuff, storage: &Storage, h: &Hash, signed: &mut NotHeldCache) -> SyncResponse {
    match hs.block(h).cloned().or_else(|| storage.block_by_hash(h).ok().flatten()) {
        Some(b) => SyncResponse::Block(Some(b)),
        None if hs.holds_orphan(h) => SyncResponse::Block(None),
        None => match signed.get_or_sign(h, hs.view(), || hs.not_held(h)) {
            Some(n) => SyncResponse::NotHeld(n),
            None => SyncResponse::Block(None),
        },
    }
}

/// Signed not-held answers kept for re-serving (SW-2). A lock-release round asks about one hash
/// — the locked block — so a handful would do; 256 covers every hash a burst of fetches names,
/// at ~3.8 KB each (a Dilithium2 key and signature), under a megabyte.
pub const NOT_HELD_CACHE: usize = 256;

/// This validator's signed not-held answers by hash, oldest evicted first ([`NOT_HELD_CACHE`]).
/// Each carries the view it was signed at (CN-3) and is re-served only in that view.
#[derive(Default)]
struct NotHeldCache {
    by_hash: HashMap<Hash, NotHeld>,
    order: VecDeque<Hash>,
}

impl NotHeldCache {
    /// The kept answer for `h` when it was signed at `view`, else `sign()`'s — replacing a kept
    /// one from an earlier view, so an asker is never handed a stale word as the current one —
    /// kept when there is one (an observer's `None` is not).
    fn get_or_sign(&mut self, h: &Hash, view: u64, sign: impl FnOnce() -> Option<NotHeld>) -> Option<NotHeld> {
        if let Some(n) = self.by_hash.get(h) {
            if n.view == view {
                return Some(n.clone());
            }
        }
        let n = sign()?;
        if let Some(kept) = self.by_hash.get_mut(h) {
            *kept = n.clone();
            return Some(n);
        }
        if self.order.len() >= NOT_HELD_CACHE {
            if let Some(old) = self.order.pop_front() {
                self.by_hash.remove(&old);
            }
        }
        self.order.push_back(*h);
        self.by_hash.insert(*h, n.clone());
        Some(n)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_hash.len()
    }
}

pub fn check_and_repair_chain(storage: &Storage, gs: &GenesisState, mode: VerifyMode, executor: &dyn ConfidentialExecutor) -> Result<u64> {
    if mode == VerifyMode::Off {
        return Ok(storage.head()?.height);
    }
    let t = Instant::now();
    let check = storage.verify_chain(gs, mode, executor)?;
    if check.floor > 0 {
        return match &check.problem {
            None => {
                tracing::info!(
                    "pruned node: history verified from {} to {} ({:?}, {:.1?}); the ledger snapshot is compared with the head's state root at resume",
                    check.floor, check.head, mode, t.elapsed()
                );
                Ok(check.head)
            }
            Some(problem) => anyhow::bail!(
                "pruned node: {problem}; history cannot be repaired locally — re-sync from the archive"
            ),
        };
    }
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

/// The retention window must hold the aggregation window (history pruning spec §5): a cover's
/// aggregate is read within it, and pruning it would make sealed blocks unservable.
fn prune_window_check(prune_history: Option<Duration>, window: Option<u64>, block_interval: Duration) -> std::result::Result<(), String> {
    let (Some(keep), Some(window)) = (prune_history, window) else { return Ok(()) };
    let needed = block_interval.saturating_mul(u32::try_from(window).unwrap_or(u32::MAX));
    if keep < needed {
        return Err(format!(
            "prune-history {keep:?} is shorter than the aggregation window ({window} blocks at {block_interval:?} = {needed:?})"
        ));
    }
    Ok(())
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
    validate_for_pool_with(tx, ledger, executor, |window, covers| {
        assemble_covered(storage, ledger.height(), window, profile, covers)
    })
}

/// Runs one admission verification (`f`, [`validate_for_pool`] in the worker) and turns a panic
/// inside it into `TxError::VerifierPanicked` (the 2026-09-27 reviews' coverage gap: Plonky3 has
/// never been fuzzed against malformed production proofs here, and nothing caught a panic).
///
/// Why here and not around each `Machine::verify`: the worker is where a panic does lasting
/// harm. It is a `spawn_blocking` task that sends its verdict at the end, so a panicking verify
/// killed it silently — no verdict, the in-flight slot (`MAX_VERIFY_IN_FLIGHT`) never returned,
/// the gossip message never reported (gossipsub then stops forwarding it) — and four such proofs
/// left the node admitting nothing. On the consensus path (block apply) a panic is left to crash
/// the node, as before: every honest node panics on the same bytes, so swallowing it there would
/// turn a verifier bug into a silent fork risk rather than a loud stop.
///
/// `AssertUnwindSafe`: the closure reads a ledger snapshot (an `Arc`, never mutated here), the
/// store (RocksDB handles, read-only here) and the executor, whose one shared mutable state — the
/// verifier-key cache — is behind a `Mutex` whose poisoning later `lock().unwrap()`s would surface
/// as further panics this same guard catches, not as silent corruption.
fn guard_verify(f: impl FnOnce() -> Result<(), randprotocol_core::TxError>) -> Result<(), randprotocol_core::TxError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|payload| {
        let what = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "a non-string panic".into());
        tracing::warn!("the proof verifier panicked during admission: {what}");
        Err(randprotocol_core::TxError::VerifierPanicked(what))
    })
}

/// [`validate_for_pool`] over any covered-record source — the store in production, a counting
/// stand-in in the test that pins the order: everything the transaction's own bytes and the
/// register decide runs in `preflight_aggregate`, before `assemble` reads a single cover.
fn validate_for_pool_with(
    tx: &Transaction,
    ledger: &Ledger,
    executor: &dyn ConfidentialExecutor,
    assemble: impl FnOnce(u64, &[Hash]) -> Result<Vec<randprotocol_core::types::CoveredBundle>, randprotocol_core::TxError>,
) -> Result<(), randprotocol_core::TxError> {
    let randprotocol_core::types::Action::Aggregate { covers, .. } = &tx.action else {
        return ledger.validate(tx, executor);
    };
    ledger.preflight_aggregate(tx)?;
    let window = ledger.aggregation().expect("preflight checked the gate").window;
    let covered = assemble(window, covers)?;
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
/// proof hash, the `pv::NUM` (35) public values and the declared shape — in transaction order. A block
/// with no pruned records is raw by construction: the two forms share one wire type.
fn sealed_form_of(storage: &Storage, cb: &CommittedBlock) -> CommittedBlock {
    let mut block = cb.block.clone();
    let mut pruned = Vec::new();
    for tx in &mut block.transactions {
        // The record is keyed by the raw hash, which is `tx.hash()` for a raw-stored tx;
        // for a marker-form one (this block arrived sealed, or this node pruned it — the pass
        // shrinks the block row with the record, INTERFACE-9), the record is found by the proof
        // hash the marker carries.
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

/// INTERFACE-6's residual (issue #59): a sealed-form side-table entry's `shape` is not covered by
/// anything the ledger checks — `apply_block_for_sync` binds the record's transaction, digest and
/// `H_PUB`, never its seven shape bytes — yet this node stores it with the record and hands it to
/// every later reader of that cover (`Storage::covered_record`: a later aggregate's sidecar, the
/// startup replay of the covering aggregate's block, re-serving). An aggregate carried in the same
/// batch binds it (its admission wants every covered shape equal and admitted, and the rVM verify
/// is for that shape); nothing else did. So every entry must name a shape this chain's genesis
/// admits for the guest its public values say it proves (`pv::HC0..7 == admitted.hc`) — the only
/// shapes a covering aggregate can have verified. A chain without an `aggregation` section has no
/// admissible pruned record at all. Refused as a damaged batch, not the raw-form fallback: an
/// honest peer's record carries the shape its own pruning pass read off the verified proof.
fn check_pruned_shapes(
    aggregation: Option<&randprotocol_core::ledger::aggregation::AggregationConfig>,
    height: u64,
    pruned: &[randprotocol_core::consensus::PrunedBundle],
) -> Result<()> {
    for p in pruned {
        let admitted = aggregation.is_some_and(|cfg| {
            cfg.admitted_shapes.iter().any(|a| {
                let hc = randprotocol_core::notes::word8_from_bytes(a.hc.as_bytes()).expect("a Hash is 32 bytes");
                a.shape == p.shape
                    && (0..8).all(|k| p.public_values.get(randprotocol_core::types::pv::HC0 + k) == Some(&(hc[k] as u64)))
            })
        });
        if !admitted {
            anyhow::bail!(
                "block {height} carries a pruned record for {} whose shape is not one this chain admits for its guest",
                p.tx_hash
            );
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

/// How far the chain is known to have committed: the highest height any peer's own `Status`
/// claims, or — while no status has been heard at all — three under the highest proposal this
/// replica has handled (a block is committed under the three-chain rule once three more are
/// certified above it, so a proposal at `h` puts the committed head near `h − 3`, never above).
///
/// The proposal half is for the seconds after a restart (audit v6, PROC-8): a node whose one
/// peer's status had not reached it for 40 s fetched each proposal's parent by hash, spent that
/// peer's allowance, and never batch-synced. A proposal's height is signed by its leader alone
/// — the justify certifies the parent's hash, not its height — so it counts only while there is
/// no status to weigh it against: the most a lying leader buys is a few batch requests from a
/// node that has heard from no peer yet.
fn chain_height_known(best_status: Option<u64>, highest_proposal: u64) -> u64 {
    best_status.unwrap_or_else(|| highest_proposal.saturating_sub(3))
}

/// The sync peer for the next batch request, or `None` when nothing usable exists: the
/// freshest connected peer ahead of `my_height`; and when no peer is connected *and* fresh at
/// once but the chain is known to be ahead (`best_peer_height` says so), any connected peer
/// whose stale answer costs one round trip — the fallback that keeps the cycle alive where a
/// silent stall costs the chain (the sealed-sync stall's shape, shown under load).
/// Whether a proposal with an unknown parent means this replica is far behind (batch-sync the
/// committed blocks) or merely lacks one uncommitted block (fetch it by hash). "Behind" is
/// measured on what the replica *holds* — its pending tip, never below its committed head — the
/// way `sync_from` asks above what it holds (review C2): a replica whose committed head trails
/// but which already holds the committed tail as pending can only be missing an uncommitted
/// parent, and no batch serves one. Six validators sat exactly there on 2026-09-24, batch-syncing
/// blocks they held while the chain waited for their votes.
fn orphan_wants_batch_sync(best_peer_height: u64, committed_height: u64, pending_tip_height: u64) -> bool {
    best_peer_height > pending_tip_height.max(committed_height) + 2
}

/// Record `id` as connected. Belt and braces under the swarm's own inbound cap
/// (`WireLimits::max_established_incoming`, the same `max`): a connected peer is always recorded —
/// the swarm already bounds how many there are, and a validator must never be refused — but the
/// map never grows past `max` on the strength of entries that are *not* connected: at the bound
/// those are dropped first.
///
/// A peer that was here before gets its meters back from `memory` (CN-2) — onto a new entry, or
/// over one gossip or a request made for it while it was not recorded as connected, whose
/// buckets are at most a moment old. Entries dropped at the bound are remembered the same way.
fn connect_peer<'a>(peers: &'a mut HashMap<PeerId, Peer>, memory: &mut PeerMemory, id: PeerId, max: usize) -> &'a mut Peer {
    if !peers.contains_key(&id) && peers.len() >= max {
        peers.retain(|pid, p| {
            if !p.connected {
                memory.remember(*pid, p);
            }
            p.connected
        });
    }
    let p = peer_entry(peers, memory, id);
    if let Some(m) = memory.recall(&id) {
        m.restore(p);
    }
    p.connected = true;
    p
}

/// Record a gossiped `Status` against its *author* `from` (deep scan 2026-09-24, medium): only an
/// existing entry — a peer this node holds, or held, a connection to — is updated. The author of
/// relayed gossip may be several hops away and a peer id is free to mint, so an entry created here
/// would be one nothing ever removes (`PeerDisconnected` is the only removal), a way around the
/// swarm's connection cap. Nothing is lost: sync asks only `connected` peers (`pick_sync_peer`).
fn record_status(peers: &mut HashMap<PeerId, Peer>, from: PeerId, s: Status) {
    if let Some(p) = peers.get_mut(&from) {
        p.status = Some(s);
    }
}

/// The `Status` gossip arm's decision: metered against the peer that *forwarded* the message
/// (`GossipId.propagation_source`, the only one with a connection to spend from — the author may be
/// hops away), then recorded against the author through [`record_status`]. `Ignore`, never
/// `Reject`, over the limit: the message is not wrong, this node is merely not reading it now.
///
/// Read only from its own author (SYNC-1, network scan 2026-09-26): gossipsub runs `Permissive`,
/// so an unsigned message's `source` is whatever its sender wrote, and a `Status` relayed "from"
/// an honest validator with a floor past every height hid that validator from `pick_sync_peer`.
/// `from == forwarder` is the one attribution a connection proves; anything else is `Ignore`d —
/// neither recorded nor forwarded, and not the forwarder's fault, since an honest relay looks the
/// same. Nothing sync needs is lost: only connected peers are asked for blocks, and a publisher
/// floods its own status to every peer it is connected to (gossipsub's `flood_publish`). A peer's
/// own status whose floor is above its own height describes a node holding no head at all:
/// `Reject` — checked after the author, so a relay (an older build forwards without looking) is
/// never blamed for it.
fn on_status_gossip(
    peers: &mut HashMap<PeerId, Peer>,
    limiter: &admission::PeerLimiter,
    from: PeerId,
    forwarder: PeerId,
    s: Status,
    now: Instant,
) -> GossipOutcome {
    // Spent in place on the forwarder's own entry — `TokenBucket` is `Copy`, so a local copy
    // would see a full bucket every time. No entry (a forwarder this node holds no connection
    // to, which gossipsub does not produce) is nothing to meter against: ignored.
    let Some(f) = peers.get_mut(&forwarder) else {
        return GossipOutcome::Report(admission::Acceptance::Ignore);
    };
    if !limiter.allow(&mut f.status_bucket, now) {
        return GossipOutcome::Report(admission::Acceptance::Ignore);
    }
    if from != forwarder {
        return GossipOutcome::Report(admission::Acceptance::Ignore);
    }
    if s.floor > s.height {
        return GossipOutcome::Report(admission::Acceptance::Reject);
    }
    record_status(peers, from, s);
    GossipOutcome::for_consensus()
}

fn pick_sync_peer(
    peers: &HashMap<PeerId, Peer>,
    my_height: u64,
    best_peer_height: u64,
    skipped: &[PeerId],
    now: Instant,
) -> Option<PeerId> {
    let serves = |s: &Status| s.floor <= my_height.saturating_add(1);
    // A peer backed off after a miss — an empty answer to a live request (SYNC-2), a failed or
    // abandoned one (CN-1) — is no candidate on either branch until its back-off expires.
    let askable = |p: &PeerId, peer: &Peer| {
        peer.connected
            && !skipped.contains(p)
            && peer.sync_backoff_until.is_none_or(|until| now >= until)
            && peer.sync_busy_until.is_none_or(|until| now >= until)
    };
    // And once it has expired, a peer's record ranks before its claim (CN-1): fewest consecutive
    // misses first (`sync_backoff` is zero until one, doubles per miss, clears on a batch that
    // applied), the claimed height only among equals. A claimed height costs nothing to make, so
    // ranking on it alone let two silent peers claiming the top take every turn between them, their
    // back-offs expiring while the other held the request. An honest peer that missed once — a
    // metered answer (SW-2) — is outranked only until a clean peer is asked, and a sybil has to
    // serve the chain to climb back, at which point it is no longer in the way.
    let rank = |peer: &Peer, h: u64| (std::cmp::Reverse(peer.sync_backoff), h);
    let best = peers
        .iter()
        .filter(|(p, peer)| askable(p, peer))
        .filter_map(|(p, peer)| peer.status.as_ref().filter(|s| serves(s)).map(|s| (*p, rank(peer, s.height), s.height)))
        .filter(|(_, _, h)| *h > my_height)
        .max_by_key(|(_, r, _)| *r)
        .map(|(p, _, _)| p);
    best.or_else(|| {
        if best_peer_height > my_height + 1 {
            peers
                .iter()
                .filter(|(p, peer)| askable(p, peer))
                .filter(|(_, peer)| peer.status.as_ref().is_none_or(serves))
                .min_by_key(|(_, peer)| peer.sync_backoff)
                .map(|(p, _)| *p)
        } else {
            None
        }
    })
}

/// Every connected peer with a known status, as `"{peer_id} floor={floor} height={height}"` —
/// the operator-readable form of [`Node::sync_from`]'s "no candidate can serve our next height"
/// warning (final-review fix #2). A disconnected peer, or one whose status we have never seen,
/// is omitted: `pick_sync_peer` would never have chosen either as a candidate anyway. Sorted for
/// a stable log line and a deterministic test.
fn no_peer_summary(peers: &HashMap<PeerId, Peer>) -> Vec<String> {
    let mut out: Vec<String> = peers
        .iter()
        .filter(|(_, peer)| peer.connected)
        .filter_map(|(p, peer)| peer.status.as_ref().map(|s| format!("{p} floor={} height={}", s.floor, s.height)))
        .collect();
    out.sort();
    out
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
    /// The viewing-key registry's live key count, for `publish_status` (audit v3, VK-1). The
    /// registry itself is the `RpcState`'s alone: the node loop never takes its lock.
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
    /// The outstanding batch request: peer, request id, when it went out, and **the height it
    /// asked from**. The height rides here rather than in a field of its own (review round 3, R1)
    /// so it cannot outlive the request — every path that drops the request drops it too, and a
    /// late answer is judged against the height its own request asked for.
    sync_inflight: Option<(PeerId, libp2p::request_response::OutboundRequestId, Instant, u64)>,
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
    /// By-hash fetches outstanding, with when each was sent: one older than the wire timeout is
    /// abandoned by `fetch_block` (audit v5) — libp2p neither answered nor reported it.
    fetch_inflight: HashMap<libp2p::request_response::OutboundRequestId, (Hash, Instant)>,
    /// Block hash -> (attempts so far, peers already asked) for by-hash fetches.
    fetch_attempts: HashMap<Hash, (usize, Vec<PeerId>)>,
    /// History-retention passes that deleted at least one block (history pruning spec §1),
    /// counted to space out the compaction pass.
    prune_passes: u64,
    /// Set for the duration of a background `compact_pruned_history` call (final-review fix
    /// #1): compaction is a RocksDB range compaction, potentially the slowest single operation
    /// this node ever runs, and it must never overlap itself or block the node loop, so the
    /// every-64th-pass check spawns it without awaiting and this flag is how the next check
    /// tells "still running" from "safe to start another".
    compacting: Arc<AtomicBool>,
    /// The last time [`Node::sync_from`] logged the "no peer holds our next height" warning,
    /// rate-limited to once per minute so a node stuck behind every peer's retention floor does
    /// not spam its log once per sync attempt.
    no_peer_warned_at: Option<Instant>,
    /// The highest proposal this replica has handled (passed the gossip precheck), for
    /// [`chain_height_known`] while no peer's status has been heard.
    highest_proposal_seen: u64,
    /// Free space on the data directory's filesystem, measured at startup and on every status
    /// tick; what `NodeStatus::disk_free_bytes` and `disk_low` publish (audit v4 OPS-3).
    disk_free_bytes: u64,
    /// Transaction hashes this node has already refused for a reason about their bytes, so a
    /// re-gossiped copy costs a hash lookup instead of a proof verification.
    refused: admission::RefusedCache,
    /// Transaction hashes whose proofs this node already verified (audit v3, B5), shared with
    /// the consensus replica: the admission workers fill it, and at propose and at a proposal's
    /// apply the ledger decodes a hit's proofs instead of re-verifying them. Behind the lock
    /// because the workers write from blocking threads; never held across an await.
    verified: Arc<RwLock<admission::VerifiedSet>>,
    /// Policy only — every bucket lives on its [`Peer`], so nothing here has to track the peer set.
    limiter: admission::PeerLimiter,
    /// The policy over every peer's `status_bucket` (see [`on_status_gossip`]).
    status_limiter: admission::PeerLimiter,
    /// The policy over every peer's `consensus_bucket` (see [`on_consensus_gossip`]).
    consensus_limiter: admission::PeerLimiter,
    /// The byte policy over every peer's `consensus_byte_bucket` ([`consensus_byte_limiter`], CN-4).
    consensus_byte_limiter: admission::PeerLimiter,
    /// The policy over every peer's `binding_bucket` ([`crate::peer_bindings::on_binding_gossip`]).
    binding_limiter: admission::PeerLimiter,
    /// The validators' libp2p identities this node has verified, and the operator's pinned ones
    /// (audit v6, NET-1): reserved at the swarm, persisted, and SYNC-3's "validator peer".
    peer_bindings: crate::peer_bindings::PeerBindings,
    /// This validator's key, for signing its own binding; `None` on a node without `--validator`,
    /// which has no validator identity to state.
    binding_signer: Option<Keypair>,
    /// When this node last announced its binding, and whether a peer connected since
    /// ([`crate::peer_bindings::announce_due`]).
    binding_announced_at: Option<Instant>,
    binding_announce_wanted: bool,
    /// The policy over every peer's `sync_bucket` (see [`admit_sync_request`]).
    sync_limiter: admission::PeerLimiter,
    /// This validator's signed not-held answers, re-served to repeated by-hash requests (SW-2).
    not_held_signed: NotHeldCache,
    /// The meters of peers that have left, restored when they return (CN-2).
    peer_memory: PeerMemory,
    /// The node-wide budget on `Blocks` requests served, over every peer (CN-2).
    sync_serve_budget: SyncServeBudget,
    /// The blocking-worker slots `Blocks` answers are built in, off this loop
    /// ([`MAX_SYNC_SERVES_IN_FLIGHT`], [`spawn_sync_serve`]).
    sync_serving: Arc<tokio::sync::Semaphore>,
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
    /// gossip never spends from it. Leaves with the entry on `PeerDisconnected`, which is why
    /// `PeerLimiter` keeps no map — into [`PeerMemory`], with every other meter here, and back
    /// onto the entry if the peer returns (CN-2).
    tx_bucket: admission::TokenBucket,
    /// The same, for the `Status` messages this peer forwards (`on_status_gossip`): a status is
    /// three fields and costs nothing to check, so the bucket is generous ([`STATUS_GOSSIP_BURST`],
    /// [`STATUS_GOSSIP_PER_SEC`]), but a forwarder cannot make this loop record one for every id
    /// it can mint at wire speed.
    status_bucket: admission::TokenBucket,
    /// The same, for the consensus messages this peer forwards ([`on_consensus_gossip`]).
    consensus_bucket: admission::TokenBucket,
    /// Those messages' bytes (CN-4): the count alone let one forwarder push 64 messages a second
    /// of up to gossip's 16 MiB transmit size each ([`classify_consensus_gossip`]).
    consensus_byte_bucket: admission::TokenBucket,
    /// The same, for the sync requests this peer sends us ([`admit_sync_request`]).
    sync_bucket: admission::TokenBucket,
    /// The same, for the peer bindings this peer forwards (audit v6, NET-1): each new one costs a
    /// signature verify.
    binding_bucket: admission::TokenBucket,
    /// Not asked for a batch before this instant (SYNC-2): set by [`back_off_sync_peer`] when the
    /// peer answered our live batch request with nothing we could use, or when that request failed
    /// or was abandoned (CN-1, [`on_sync_batch_failed`]).
    sync_backoff_until: Option<Instant>,
    /// The length of the last back-off, doubled per consecutive miss up to [`SYNC_BACKOFF_MAX`];
    /// zero after a batch from this peer applied. Outlives the back-off itself: `pick_sync_peer`
    /// ranks on it before the claimed height (CN-1).
    sync_backoff: Duration,
    /// Not asked for a batch before this instant because it answered our last one `Busy`
    /// (audit v6, SYNC-3): its node-wide budget was spent by others, which says nothing about
    /// whether it holds the blocks, so this is a pause of [`SYNC_BUSY_PAUSE`] — never a
    /// back-off, and the peer's rank in `pick_sync_peer` does not move.
    sync_busy_until: Option<Instant>,
}

/// `Status` messages one forwarding peer may deliver back to back, and the rate it recovers them
/// at. A node publishes one status per connection it makes and per commit it sees, so sixteen and
/// four a second is far above any honest peer's share (the transaction bucket's numbers).
pub const STATUS_GOSSIP_BURST: u32 = 16;
pub const STATUS_GOSSIP_PER_SEC: f64 = 4.0;

/// Consensus messages one forwarding peer may deliver back to back, and the rate it recovers them
/// at (SW-1(d)/SW-3). Sized from the honest load, which all of it may reach this node through one
/// forwarder (a node with a single connection): per view one proposal, up to one vote per
/// validator and, on a timeout, up to one NewView per validator — 37 messages on an
/// 18-validator set — and gossipsub delivers each message id at most once per forwarder. At the
/// measured ~1.4 s a block that is ≤ ~26 a second; 64 a second is two and a half times it, and a
/// burst of 256 is some seven whole views arriving at once (a leader's catch-up, a view-change
/// storm after a stall). A validator set several times larger would need these raised.
pub const CONSENSUS_GOSSIP_BURST: u32 = 256;
pub const CONSENSUS_GOSSIP_PER_SEC: f64 = 64.0;

/// The consensus gossip arm's decision (SW-1(d)/SW-3): metered against the forwarder
/// (`GossipId.propagation_source`) and accepted — so forwarded — within its budget, exactly as
/// before; over it, `Ignore`d, neither forwarded nor handled. Never `Reject`: an honest relay in a
/// burst looks the same. A forwarder with no entry is metered on a fresh one, as a transaction's
/// is (`on_gossiped_tx`), not refused: gossip can race its `PeerConnected`, a rejected sync batch
/// drops a still-connected peer's entry, and a validator's votes must not be lost to bookkeeping.
/// Only a connected peer is ever a `propagation_source`, so this cannot grow the map past the
/// swarm's connection cap.
fn on_consensus_gossip(
    peers: &mut HashMap<PeerId, Peer>,
    limiter: &admission::PeerLimiter,
    forwarder: PeerId,
    now: Instant,
) -> GossipOutcome {
    // Spent in place: `TokenBucket` is `Copy`.
    let bucket = &mut peers.entry(forwarder).or_default().consensus_bucket;
    if !limiter.allow(bucket, now) {
        return GossipOutcome::Report(admission::Acceptance::Ignore);
    }
    GossipOutcome::for_consensus()
}

/// The per-view allowance of consensus bytes one forwarder carries beyond a full block's
/// transactions (CN-4): a proposal's header — its proposer key and signature, 3.7 KB, and its
/// justify, one ~3.8 KB vote per validator of the set (68 KB at 18, 380 KB at 100) — plus the
/// view's votes (18 × 3.8 KB) and, on a timeout, one NewView per validator each carrying a
/// high QC (18 × ~72 KB ≈ 1.3 MB). 2 MiB covers all of it for an 18-validator set with room,
/// and a set of about 25 before the NewView storm alone reaches it.
pub const CONSENSUS_GOSSIP_VIEW_OVERHEAD_BYTES: usize = 2 << 20;
/// The byte burst, in views' worth ([`consensus_view_bytes`]): eight, the count burst's "some
/// seven whole views arriving at once" plus one — a leader's catch-up, or a view-change storm,
/// delivering full blocks back to back through this node's one forwarder.
pub const CONSENSUS_GOSSIP_BURST_VIEWS: u32 = 8;
/// The byte refill, in views' worth a second: two. An honest view carries at most one proposal
/// and the fleet runs ≥ 1 s a block (~1.4 s measured), so a forwarder's honest share is at most
/// one view a second even when every block is full and every view also times out — which two
/// cannot both be at once. Twice that is the headroom.
pub const CONSENSUS_GOSSIP_VIEWS_PER_SEC: f64 = 2.0;

/// One view's worth of honest consensus bytes on a chain whose blocks carry up to
/// `max_block_bytes` of transactions: a full block plus [`CONSENSUS_GOSSIP_VIEW_OVERHEAD_BYTES`].
pub fn consensus_view_bytes(max_block_bytes: usize) -> usize {
    max_block_bytes.saturating_add(CONSENSUS_GOSSIP_VIEW_OVERHEAD_BYTES)
}

/// The byte policy over every forwarder's `consensus_byte_bucket` (CN-4). On a default 4 MiB
/// chain that is 48 MiB of burst and 12 MiB a second; before, the count bucket alone admitted
/// 256 × 16 MiB = 4 GiB of burst and 64 × 16 MiB = 1 GiB a second per connection. The burst is
/// eight views, so it always exceeds the largest honest message (one proposal, under one view)
/// and gossip's transmit size (`max(16 MiB, max_block_bytes + 1 MiB)`): nothing an honest peer
/// can send is unpassable.
pub fn consensus_byte_limiter(max_block_bytes: usize) -> admission::PeerLimiter {
    let view = consensus_view_bytes(max_block_bytes);
    let burst = (view as u64).saturating_mul(CONSENSUS_GOSSIP_BURST_VIEWS as u64).min(u32::MAX as u64) as u32;
    admission::PeerLimiter::new(burst, view as f64 * CONSENSUS_GOSSIP_VIEWS_PER_SEC)
}

/// What the consensus gossip arm does with one delivered message (CN-4): the one report
/// gossipsub gets for it, and whether the replica is handed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsensusGossipVerdict {
    pub report: admission::Acceptance,
    pub handle: bool,
}

/// The consensus gossip arm's whole decision, in order (CN-4):
///
/// 1. The forwarder's message count ([`on_consensus_gossip`], SW-1(d)/SW-3) and then its bytes
///    ([`consensus_byte_limiter`]): over either, `Ignore`d — not forwarded, not handled, never
///    `Reject`ed, since an honest relay in a burst looks the same. The size is the message's
///    encoded size, a walk of the decoded value with no allocation.
/// 2. [`HotStuff::precheck_gossip`]: lengths, counts, a known signer and one signature verify.
///    `Accept` forwards and hands it to the replica, as every metered message was before.
///    `Reject` — malformed or forged whatever this node's state — is neither forwarded nor
///    handled. `Ignore` — stale, too far ahead, a signer in no set this replica knows — is not
///    forwarded but is still handed to the replica, which is the authority: a node that has not
///    derived the next epoch's set yet must still take the first proposal of that epoch; it
///    just does not vouch for it to the mesh.
///
/// The precheck costs one Dilithium2 verify (~0.1 ms) before the report, which is what the
/// report used to be free of; that is what it takes to stop relaying forged messages, and a
/// proposal's execution — the reason the report goes out before handling — is still after it.
#[allow(clippy::too_many_arguments)]
fn classify_consensus_gossip(
    peers: &mut HashMap<PeerId, Peer>,
    limiter: &admission::PeerLimiter,
    byte_limiter: &admission::PeerLimiter,
    hs: &HotStuff,
    forwarder: PeerId,
    msg: &ConsensusMessage,
    now: Instant,
) -> ConsensusGossipVerdict {
    use admission::Acceptance;
    use randprotocol_core::consensus::GossipPrecheck;
    let ignored = ConsensusGossipVerdict { report: Acceptance::Ignore, handle: false };
    if on_consensus_gossip(peers, limiter, forwarder, now) != GossipOutcome::for_consensus() {
        return ignored;
    }
    let bytes = bincode::serialized_size(msg).unwrap_or(u64::MAX) as f64;
    // Spent in place: `TokenBucket` is `Copy`. The entry exists: `on_consensus_gossip` made it.
    let bucket = &mut peers.entry(forwarder).or_default().consensus_byte_bucket;
    if !byte_limiter.allow_n(bucket, bytes, now) {
        tracing::debug!(%forwarder, bytes, "consensus gossip over the forwarder's byte budget; ignored");
        return ignored;
    }
    match hs.precheck_gossip(msg) {
        GossipPrecheck::Accept => ConsensusGossipVerdict { report: Acceptance::Accept, handle: true },
        GossipPrecheck::Ignore(why) => {
            tracing::debug!(%forwarder, "consensus gossip not forwarded: {why}");
            ConsensusGossipVerdict { report: Acceptance::Ignore, handle: true }
        }
        GossipPrecheck::Reject(why) => {
            tracing::debug!(%forwarder, "consensus gossip rejected: {why}");
            ConsensusGossipVerdict { report: Acceptance::Reject, handle: false }
        }
    }
}

/// Inbound sync requests one peer may send back to back, and the rate it recovers them at (SW-2).
/// A `Blocks` answer is up to ~6 MiB read and assembled on the consensus loop
/// ([`serve_sync_budget`]) and a by-hash miss may cost a signature, for a request of a few dozen
/// bytes. An honest syncer keeps one batch request in flight and applies it before the next, and
/// fetches by hash only for a proposal's missing parent; eight at once and two a second after
/// is a full batch every half second from each peer — past that it is told "nothing" and, under
/// SYNC-2, moves on to another peer for a few seconds, spreading a catch-up across the fleet.
pub const SYNC_REQUEST_BURST: u32 = 8;
pub const SYNC_REQUEST_PER_SEC: f64 = 2.0;

/// What [`admit_sync_request`] decided, and so what the asker hears.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SyncAdmission {
    Serve,
    /// Over the peer's own bucket ([`refused_sync_response`]): `Busy` to a batch, an unsigned
    /// `Block(None)` to a by-hash fetch. Never a miss for the asker — the peer it asked did
    /// nothing wrong; the asker spent its own allowance.
    OverPeerLimit,
    /// Over the node-wide budget (audit v6, SYNC-3): `SyncResponse::Busy`, which the asker
    /// counts as nothing and takes elsewhere — someone else spent the budget.
    NodeBusy,
}

impl SyncAdmission {
    #[cfg(test)]
    fn serve(self) -> bool {
        self == SyncAdmission::Serve
    }
}

/// Whether to serve `peer`'s sync request now (SW-2): metered on its own `sync_bucket`. `peer` is
/// the request's connection, never a claimed identity, and only a connected peer can send one,
/// so an entry made here is bounded by the swarm's connection cap. The bucket outlives the
/// connection (CN-2, [`PeerMemory`]), and a `Blocks` request within it is charged to the node's
/// own budget too ([`SyncServeBudget`]) — to the validators' share first when `validator` says
/// the peer is one (audit v6, SYNC-3: `PeerBindings::is_validator_peer`), so a handful of
/// strangers spending the general share cannot starve a lagging validator's batch.
#[allow(clippy::too_many_arguments)]
fn admit_sync_request(
    peers: &mut HashMap<PeerId, Peer>,
    memory: &mut PeerMemory,
    limiter: &admission::PeerLimiter,
    global: &mut SyncServeBudget,
    peer: PeerId,
    validator: bool,
    req: &SyncRequest,
    now: Instant,
) -> SyncAdmission {
    // Spent in place: `TokenBucket` is `Copy`. The peer's own bucket first, restored if it has
    // been here before (CN-2), so a request its own limit refuses spends nothing node-wide.
    if !limiter.allow(&mut peer_entry(peers, memory, peer).sync_bucket, now) {
        return SyncAdmission::OverPeerLimit;
    }
    match req {
        SyncRequest::Blocks { .. } if global.allow(validator, now) => SyncAdmission::Serve,
        SyncRequest::Blocks { .. } => SyncAdmission::NodeBusy,
        // One block, per-peer metered; see [`SYNC_SERVE_BURST`] for why it is not charged here.
        SyncRequest::BlockByHash(_) => SyncAdmission::Serve,
    }
}

/// How long a peer that answered our batch `Busy` sits out of the pick (audit v6, SYNC-3): long
/// enough that two busy peers are not asked in alternation at round-trip speed — which would
/// spend their per-peer buckets and earn the empty answers a back-off *is* for — and short
/// against the node-wide budget's refill (eight a second).
pub const SYNC_BUSY_PAUSE: Duration = Duration::from_secs(1);

/// Our live batch request was answered `Busy` (audit v6, SYNC-3): paused for
/// [`SYNC_BUSY_PAUSE`], with its back-off and its miss count untouched — the budget it ran out of
/// was spent by others, and backing it off 5–120 s as if it had nothing is what let a few
/// identities push a lagging validator off its best peers.
fn on_sync_busy(peers: &mut HashMap<PeerId, Peer>, peer: PeerId, now: Instant) {
    if let Some(p) = peers.get_mut(&peer) {
        p.sync_busy_until = Some(now + SYNC_BUSY_PAUSE);
    }
}

/// The answer to a request over its peer's limit: `Busy` to a batch, and an unsigned
/// `Block(None)` to a by-hash fetch, which is a fetch attempt and never lock-release evidence.
/// Every request is still answered, so the asker is not left waiting out a wire timeout.
///
/// A batch is answered `Busy`, not empty (audit v6, PROC-8, the fourth shape of the
/// `restart_cycles_keep_all_nodes_in_sync` failure, CI run on `e55ad51`): a node that restarts
/// hears certificates for blocks it lacks before any peer's `Status` reaches it, so it does not
/// yet know it is behind and fetches them by hash — a dozen requests in milliseconds, past this
/// bucket. Its first batch request was then answered empty, which the asker counts as a miss
/// and backs the peer off for 5 s, 10 s, 20 s: 42 s without a batch while the chain moved on.
/// `Busy` costs the asker [`SYNC_BUSY_PAUSE`] on this peer and sends it to another, which is
/// what an over-limit request should cost — the bucket still bounds what it is served.
fn refused_sync_response(req: &SyncRequest) -> SyncResponse {
    match req {
        SyncRequest::Blocks { .. } => SyncResponse::Busy,
        SyncRequest::BlockByHash(_) => SyncResponse::Block(None),
    }
}

/// The first back-off of a peer that answered a batch request with nothing usable, and the cap
/// its doubling stops at (SYNC-2).
pub const SYNC_BACKOFF_BASE: Duration = Duration::from_secs(5);
pub const SYNC_BACKOFF_MAX: Duration = Duration::from_secs(120);

/// A peer answered our live batch request with nothing we could apply (SYNC-2), or never answered
/// it at all (CN-1, [`on_sync_batch_failed`]): not asked again
/// for [`SYNC_BACKOFF_BASE`], doubling per consecutive miss to [`SYNC_BACKOFF_MAX`]. Its claimed
/// height is what made `pick_sync_peer` choose it, and nothing else would stop the same claim
/// winning the next tick's `max_by_key` — an honest peer that pruned the height, or one briefly
/// refusing (a metered sync request, SW-2), costs a few seconds of preference and nothing more.
/// Held on the peer's entry and remembered past a disconnect ([`PeerMemory`], CN-2), so a
/// reconnect restores it rather than starting it over.
fn back_off_sync_peer(peer: &mut Peer, now: Instant) {
    peer.sync_backoff =
        if peer.sync_backoff.is_zero() { SYNC_BACKOFF_BASE } else { (peer.sync_backoff * 2).min(SYNC_BACKOFF_MAX) };
    peer.sync_backoff_until = Some(now + peer.sync_backoff);
}

/// Our live batch request to `peer` failed — a wire or codec error, libp2p's own timeout — or was
/// abandoned past the wire timeout by [`Node::sync_from`] (CN-1, 2026-09-27): a miss exactly as
/// SYNC-2's empty answer is, so the same back-off. Before, only an *answered* miss backed a peer
/// off, and a peer that simply never answers is cheaper to run than one that answers empty: two
/// of them claiming the top height alternated for ever, the failure path skipping only the one
/// that had just failed, and the honest peer was never asked. The back-off alone would not have
/// been enough — a silent peer holds each request for the wire's whole timeout (30 s), far past
/// the first 5 s back-off, so the other sybil's had always expired again by its turn — which is
/// why `pick_sync_peer` also ranks a peer's unbroken misses ahead of its claim. A peer with no
/// entry (disconnected meanwhile, or dropped for a rejected batch) has nothing to back off.
fn on_sync_batch_failed(peers: &mut HashMap<PeerId, Peer>, peer: PeerId, now: Instant) {
    if let Some(p) = peers.get_mut(&peer) {
        back_off_sync_peer(p, now);
    }
}

/// A batch from this peer applied: it is asked again at once, and a later miss starts at the base.
fn clear_sync_backoff(peer: &mut Peer) {
    peer.sync_backoff = Duration::ZERO;
    peer.sync_backoff_until = None;
}

/// Departed peers whose meters are remembered (CN-2): a reconnecting id gets its buckets and its
/// sync back-off back instead of a fresh set. Only peers that have *left* are held here — a
/// connected one's meters are on its [`Peer`], and those are bounded by the swarm's inbound cap
/// (DS-2, 256) — so this is the one place the bound is set. 4096 records of a few dozen bytes
/// each, under half a megabyte.
///
/// What eviction buys an attacker, oldest first: to push one id's record out it has to bring
/// 4096 other ids through a connection each (DS-2 meters those: 64 pending, 2 per peer) and
/// back out again, and at the end of it the evicted id has one fresh burst — which each of the
/// 4096 new ids had anyway. A fresh id always costs a connection and always starts full; what
/// bounds the sum over every id is the node-wide budget ([`SyncServeBudget`]), not this map.
pub const PEER_MEMORY_ENTRIES: usize = 4096;

/// A peer's rate-limiter state — everything on [`Peer`] that metering or the sync picker
/// accumulates about it — lifted off the entry when the peer leaves (CN-2). The status and
/// connectedness are not carried: a returning peer has to say where it is again.
#[derive(Clone, Copy, Debug)]
struct PeerMeters {
    tx_bucket: admission::TokenBucket,
    status_bucket: admission::TokenBucket,
    consensus_bucket: admission::TokenBucket,
    sync_bucket: admission::TokenBucket,
    binding_bucket: admission::TokenBucket,
    sync_backoff_until: Option<Instant>,
    sync_backoff: Duration,
}

impl PeerMeters {
    fn of(p: &Peer) -> PeerMeters {
        PeerMeters {
            tx_bucket: p.tx_bucket,
            status_bucket: p.status_bucket,
            consensus_bucket: p.consensus_bucket,
            sync_bucket: p.sync_bucket,
            binding_bucket: p.binding_bucket,
            sync_backoff_until: p.sync_backoff_until,
            sync_backoff: p.sync_backoff,
        }
    }

    fn restore(self, p: &mut Peer) {
        p.tx_bucket = self.tx_bucket;
        p.status_bucket = self.status_bucket;
        p.consensus_bucket = self.consensus_bucket;
        p.sync_bucket = self.sync_bucket;
        p.binding_bucket = self.binding_bucket;
        p.sync_backoff_until = self.sync_backoff_until;
        p.sync_backoff = self.sync_backoff;
    }
}

/// The departed peers' [`PeerMeters`], oldest evicted first ([`PEER_MEMORY_ENTRIES`]). A record
/// is *taken* when its peer returns, so each id sits either here or on its entry, never both.
/// Nothing here expires on time and nothing needs to: a remembered bucket refills from its
/// last use when it is next spent (`PeerLimiter::allow`), and a back-off's instant simply passes.
#[derive(Default)]
struct PeerMemory {
    by_id: HashMap<PeerId, PeerMeters>,
    order: VecDeque<PeerId>,
}

impl PeerMemory {
    fn remember(&mut self, id: PeerId, p: &Peer) {
        if self.by_id.insert(id, PeerMeters::of(p)).is_some() {
            // A record already held (a peer that came back without its entry being restored, and
            // left again): refreshed, and moved to the young end. A linear scan of at most
            // [`PEER_MEMORY_ENTRIES`] per departure.
            self.order.retain(|x| *x != id);
        } else if self.order.len() >= PEER_MEMORY_ENTRIES {
            if let Some(old) = self.order.pop_front() {
                self.by_id.remove(&old);
            }
        }
        self.order.push_back(id);
    }

    fn recall(&mut self, id: &PeerId) -> Option<PeerMeters> {
        let m = self.by_id.remove(id)?;
        self.order.retain(|x| x != id);
        Some(m)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_id.len()
    }
}

/// `id`'s entry, restored from `memory` when this node holds none (CN-2): the entry a request or
/// a connection creates for a peer that was here before carries its old meters, not a fresh set.
fn peer_entry<'a>(peers: &'a mut HashMap<PeerId, Peer>, memory: &mut PeerMemory, id: PeerId) -> &'a mut Peer {
    peers.entry(id).or_insert_with(|| {
        let mut p = Peer::default();
        if let Some(m) = memory.recall(&id) {
            m.restore(&mut p);
        }
        p
    })
}

/// `id`'s connection closed, or its entry is dropped for a batch we could not use: the entry goes,
/// its meters are remembered (CN-2). `held_our_batch` — it left while our live batch request was
/// on it — is a miss exactly as a silent peer's is (CN-1), so it is backed off first: before
/// this, walking out on a request was the one way to decline one that cost a sybil nothing, the
/// in-flight slot being cleared without a failure ever reaching [`on_sync_batch_failed`].
fn disconnect_peer(peers: &mut HashMap<PeerId, Peer>, memory: &mut PeerMemory, id: PeerId, held_our_batch: bool, now: Instant) {
    if let Some(mut p) = peers.remove(&id) {
        if held_our_batch {
            back_off_sync_peer(&mut p, now);
        }
        memory.remember(id, &p);
    }
}

/// `Blocks` requests this node serves back to back across *every* peer, and the rate it recovers
/// them at (CN-2). The per-peer bucket ([`SYNC_REQUEST_BURST`]) bounds one connection, and 256 of
/// them (DS-2's inbound cap) at 2 a second was ~512 batch requests a second, each up to a
/// [`serve_sync_budget`] read (~6 MiB). Eight a second is four honest syncers each keeping one
/// full-rate batch in flight — an honest syncer asks for the next only after applying the last,
/// which takes longer than half a second for a full batch — and caps what one node reads and
/// sends for sync at eight budgets a second.
///
/// Over it the answer is `SyncResponse::Busy` (audit v6, SYNC-3; it used to be the per-peer
/// limit's empty batch, which the asker backed off for 5–120 s as if this node had nothing), and
/// an honest syncer asks another peer without holding it against this one. The price of any node-wide
/// budget is that it can be spent by someone else: four ids at their own full rate keep this
/// node's sync service busy — the service, not the consensus loop, which is the point
/// ([`spawn_sync_serve`]) — and a lagging node goes to another peer, every node having its own.
/// A by-hash request is left out on purpose: it is one block, metered per peer, and a signed
/// not-held is kept for re-serving (SW-2); a global cap on it would let a few ids deny every
/// validator's not-held at once — the evidence a lock release (CON-4) waits for.
pub const SYNC_SERVE_BURST: u32 = 32;
pub const SYNC_SERVE_PER_SEC: f64 = 8.0;

/// The node-wide `Blocks` budget ([`SYNC_SERVE_BURST`]): one bucket, like the faucet's, since it
/// meters the node and not a peer — and a second of the same size for validator peers only
/// (audit v6, SYNC-3). A validator draws on its own share first and on the general one after,
/// a stranger on the general one alone, so the general share spent by strangers leaves a
/// validator a full budget; the most this node serves is twice the old figure, and only while
/// validators are asking.
struct SyncServeBudget {
    limiter: admission::PeerLimiter,
    bucket: admission::TokenBucket,
    validators: admission::TokenBucket,
}

impl SyncServeBudget {
    fn new() -> SyncServeBudget {
        SyncServeBudget {
            limiter: admission::PeerLimiter::new(SYNC_SERVE_BURST, SYNC_SERVE_PER_SEC),
            bucket: admission::TokenBucket::default(),
            validators: admission::TokenBucket::default(),
        }
    }

    fn allow(&mut self, validator: bool, now: Instant) -> bool {
        // Spent in place: `TokenBucket` is `Copy`. `allow` spends nothing when it refuses, so a
        // validator refused by its own share is not charged for trying.
        (validator && self.limiter.allow(&mut self.validators, now)) || self.limiter.allow(&mut self.bucket, now)
    }
}

/// `Blocks` answers being read and assembled at once, on blocking workers (CN-2). Four, the
/// admission verifiers' number, against a pool the node shares with them, the RPC's blocking
/// reads and the prune pass; each holds at most a reader limit's worth of blocks
/// (`sync_response_wire_limit`) from the read until its answer is handed to the swarm, so the
/// memory this can pin is bounded too. With every slot taken the request is answered `Busy`, as
/// an over-budget one is.
pub const MAX_SYNC_SERVES_IN_FLIGHT: usize = 4;

/// Run `work` — a `Blocks` answer's storage reads and batch assembly — on a blocking worker under
/// one of `slots`, and hand its result to `reply` (the network task's `send_sync_response`, which
/// is how a `ResponseChannel` is answered from off the swarm: a command to it, like every other).
/// Hands `reply` back, having started nothing, when every slot is taken: the caller answers the
/// request with it (CN-2) — dropped instead, it would drop the `ResponseChannel` inside it and
/// the asker would wait for a failure rather than read an empty batch.
///
/// Before, the read ran inside `on_network_event` on the loop that handles votes and proposals —
/// up to a hundred blocks from RocksDB and their sealed forms, and the coverage closure past
/// that, per request — so an inbound sync load was a consensus-loop load. A panicking read
/// answers an empty batch, which is what a refused request gets.
fn spawn_sync_serve<R, Fut>(
    slots: &Arc<tokio::sync::Semaphore>,
    work: impl FnOnce() -> SyncResponse + Send + 'static,
    reply: R,
) -> Result<(), R>
where
    R: FnOnce(SyncResponse) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Ok(permit) = slots.clone().try_acquire_owned() else {
        return Err(reply);
    };
    tokio::spawn(async move {
        let response = tokio::task::spawn_blocking(work).await.unwrap_or_else(|e| {
            tracing::warn!("serving a sync batch failed: {e}");
            SyncResponse::Blocks(vec![])
        });
        reply(response).await;
        // Held until the answer is with the swarm, so the slots bound the batches held in memory
        // as well as the reads.
        drop(permit);
    });
    Ok(())
}

/// A `Blocks` request's answer, read from `storage` (SW-2's budget, spec §7's coverage closure):
/// what `serve_sync` built on the loop, now a free function so it can run on a blocking worker
/// ([`spawn_sync_serve`]).
fn serve_blocks(storage: &Storage, wire: &network::WireLimits, from_height: u64, max: u32) -> SyncResponse {
    let max = max.min(SYNC_BATCH);
    // Lazy: a batch that fills up on bytes must not have read the rest from RocksDB.
    let heights = from_height..from_height.saturating_add(max as u64);
    let blocks = heights.map_while(|h| storage.committed_block(h).ok().flatten()).map(|cb| sealed_form_of(storage, &cb));
    let mut batch = fill_sync_batch(blocks, serve_sync_budget(wire));
    close_batch_coverage(storage, &mut batch, wire);
    SyncResponse::Blocks(batch)
}

/// Drop the by-hash fetches sent more than `timeout` ago (audit v5): a request libp2p neither
/// answered nor reported by then is gone, and left in place it would block every further
/// attempt for its hash. Returns the hashes dropped. Each was counted as an attempt when sent.
fn expire_stale_fetches<K: std::hash::Hash + Eq + Clone>(
    inflight: &mut HashMap<K, (Hash, Instant)>,
    timeout: Duration,
    now: Instant,
) -> Vec<Hash> {
    let stale: Vec<K> =
        inflight.iter().filter(|(_, (_, sent))| now.duration_since(*sent) > timeout).map(|(k, _)| k.clone()).collect();
    stale.iter().filter_map(|k| inflight.remove(k)).map(|(h, _)| h).collect()
}

/// Whether a by-hash fetch for `h` is still outstanding, after [`expire_stale_fetches`].
/// Whether a by-hash fetch should wait for batch sync instead (audit v6, PROC-8's third failure
/// mode, seen three times in four CI runs at `restart_cycles_keep_all_nodes_in_sync`). A node
/// that is behind hears a certificate — through every NewView and every proposal's justify — for
/// each block it lacks, and fetched each one by hash: dozens of requests in a second to the same
/// three peers, past their per-peer sync allowance (`SYNC_REQUEST_BURST`, `SYNC_REQUEST_PER_SEC`).
/// The peers then answered its *batch* request with an empty batch too, which is a miss, and the
/// node backed every peer off for 5–120 s while the chain moved on without it. Batch sync brings
/// those same blocks in order, so while the node knows it is more than a block behind it does not
/// also fetch by hash; the fetch resumes once it has caught up (a parent for a live proposal, the
/// locked block, a leader's high-QC block).
fn fetch_deferred_to_batch_sync(best_peer_height: u64, committed_height: u64) -> bool {
    best_peer_height > committed_height.saturating_add(1)
}

fn fetch_blocked<K>(inflight: &HashMap<K, (Hash, Instant)>, h: &Hash) -> bool {
    inflight.values().any(|(x, _)| x == h)
}

/// The history-pruning cutoff: blocks stamped before it lose their history. Measured from the
/// earlier of the head's timestamp and this node's clock (PR-2): block timestamps are only
/// bounded per step (`MAX_TIMESTAMP_STEP_MS`), so faulty leaders can ratchet the chain's clock
/// ahead of real time, and measured from the head alone that would over-prune. A node whose own
/// clock is behind prunes less, never more — the safe direction for retention.
fn prune_cutoff_ms(head_ms: u64, now_ms: u64, keep: Duration) -> u64 {
    head_ms.min(now_ms).saturating_sub(u64::try_from(keep.as_millis()).unwrap_or(u64::MAX))
}

/// Whether this history-pruning pass should kick off a background compaction (final-review fix
/// #1): every 64th pass that deleted anything, and only when the previous compaction (if any)
/// has finished. Flips `compacting` to `true` itself, atomically with the check, so two callers
/// racing on the same 64th pass cannot both start one — there is only ever one caller in
/// practice (the node loop is single-threaded here), but the compare-exchange is what makes the
/// flag's meaning exact rather than advisory.
fn should_compact(prune_passes: u64, compacting: &AtomicBool) -> bool {
    prune_passes.is_multiple_of(64) && compacting.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok()
}

/// The background compaction's body: run `compact`, then mark the compaction finished — on a
/// panic too (PR-3), through a drop guard, since a flag left set would make `should_compact`
/// refuse every later compaction until a restart.
fn run_compaction(compacting: &AtomicBool, compact: impl FnOnce()) {
    struct Done<'a>(&'a AtomicBool);
    impl Drop for Done<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let _done = Done(compacting);
    compact();
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
    /// The live request's own answer, and nothing we can apply (SYNC-2): an empty batch or one
    /// that starts elsewhere, from a peer `pick_sync_peer` chose because it claimed to be ahead.
    miss: bool,
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
    BatchDecision { apply, late: apply && !is_current, clear_inflight: is_current, miss: is_current && !apply }
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

/// The chains this build refuses to run, by genesis hash, each with the reason it gives. Every
/// chain up to 13 pins the retired 2-in-2-out guest, which this build does not carry, so the
/// `hc_bundle` check already refuses it; the chains below pin a guest this build still carries (a
/// new genesis may name v1 or v2), so they are named here:
///
/// - **Chains 14 and 15** committed proofs under constraint set 6. Every verifier key moved with
///   constraint set 7 (v0.6.1) and again with constraint set 8 ([`BUILD_CONSTRAINT_SET`], the gas
///   meter): a node on either chain would refuse the chain's own history at its startup replay.
/// - **Chain 16** (v0.6.1/v0.6.2) committed proofs under constraint set 7, and runs on the bundle
///   wire and transaction ids before split authorisation. This build appends
///   `auth_commit`/`auth_proof` to every `Bundle` (bincode is positional, so none of chain 16's
///   bundles decode) and hashes every transaction under `rand-txid-3`, so it would fail at chain
///   16's first bundle.
/// - **Chain 17** (v0.6.3, live since 2026-09-29 03:03 UTC) commits proofs under constraint set 7
///   and pins bundle guest v3 and `hc_auth`, both of which this build still carries — so only its
///   hash refuses it: this binary installed on a chain-17 host would otherwise start, refuse the
///   chain's own history at its startup replay, and a `verify --repair` would truncate it.
pub const CHAINS_THIS_BUILD_CANNOT_RUN: [(u64, &str, &str); 4] = [
    (14, "1cff3b7da248d93ab547aef5c05bb7d0d22da510b592dab9cf7374807de7c7ff", CONSTRAINT_SET_6_REASON),
    (15, "cc30e0854fb25b3abcee96bb7bc206dcd6e37862f6dfe80a05b3e474c2d1b6b8", CONSTRAINT_SET_6_REASON),
    (16, "20925ae63cfa6e6c96f3ff369486ead8ea04821fec026a55df9e2893f3d53005", SPLIT_AUTH_REASON),
    (17, "d1afefc3dd68f73e3799aa0803b692d0e6a5c7c27d228bdeb3d06cdf4027e7ff", CONSTRAINT_SET_7_REASON),
];

/// The constraint set this build proves and verifies under: 8, the gas meter (`pv::GAS`, chain 18).
pub const BUILD_CONSTRAINT_SET: u8 = 8;

const CONSTRAINT_SET_6_REASON: &str = "its proofs were made under constraint set 6; this build is constraint \
     set 8 (v0.6.5 and later) and verifies none of them, so its startup replay would refuse the chain's own \
     history and a `verify --repair` would truncate it — on an archive node, the only full copy. Run the \
     chain's own release (v0.6 or earlier), never this one";

const SPLIT_AUTH_REASON: &str = "its proofs were made under constraint set 7 and this build is constraint set 8, \
     and this build changes the bundle wire and every transaction id (rand-txid-3, split authorisation): a \
     `verify --repair` would truncate the chain's history — on an archive node, the only full copy. Use the \
     v0.6.1/v0.6.2 release for chain 16";

const CONSTRAINT_SET_7_REASON: &str = "its proofs were made under constraint set 7; this build is constraint \
     set 8 (v0.6.5 and later) and verifies none of them, so its startup replay would refuse the chain's own \
     history and a `verify --repair` would truncate it. Use the v0.6.3 release for chain 17";

/// Refuse a genesis in [`CHAINS_THIS_BUILD_CANNOT_RUN`]: `run` (through
/// [`check_build_runs_genesis`]) and `verify` both call it before touching the datadir's blocks,
/// so this binary installed on a chain-14, -15, -16 or -17 host neither starts nor `verify --repair`s
/// that chain's history away — on an archive (obs1, rand-archive-2) that history is the only full
/// copy there is.
pub fn refuse_chains_this_build_cannot_run(gs: &GenesisState) -> Result<()> {
    let hash = gs.hash().to_hex();
    if let Some((chain, _, why)) = CHAINS_THIS_BUILD_CANNOT_RUN.iter().find(|(_, h, _)| *h == hash) {
        anyhow::bail!("genesis {hash} is chain {chain}: {why}");
    }
    Ok(())
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
///
/// `built_hc_bundles` is every bundle guest this build carries (`ZkExecutor::known_hc_bundles`):
/// since the branch-free guest (INT-2 / GV-1) there are two, and the genesis picks one by its
/// `hc_bundle` — chains 14 and 15 name v1, a later cut names v2. Verification needs nothing more
/// (the program is digested in-circuit and both guests declare the same heights), so either is
/// runnable; a genesis naming anything else is refused as before.
pub fn check_build_runs_genesis(gs: &GenesisState, built_hc_bundles: &[randprotocol_core::notes::Word8]) -> Result<()> {
    refuse_chains_this_build_cannot_run(gs)?;
    if !built_hc_bundles.contains(&gs.hc_bundle) {
        anyhow::bail!(
            "every bundle guest this build carries ({}) differs from the genesis hc_bundle ({}); \
             rebuild from the chain's pinned commit",
            built_hc_bundles.iter().map(randprotocol_core::notes::word8_to_hex).collect::<Vec<_>>().join(", "),
            randprotocol_core::notes::word8_to_hex(&gs.hc_bundle)
        );
    }
    // Kept, and widened (the 2026-09-27 recursion-VM report's recommendation 5): a second reason
    // now holds aggregation off. RVM-1 let a prover choose the high lane of every extension value
    // the rVM stores to memory — thousands of free field elements in the aggregate verifier — and
    // the same day's zk scan found the reduce chip's clock, row-kind, run-end and address-range
    // gaps. The fixed rVM (circuits 971b96b, vendored here) closes them, but no forged aggregate
    // has yet been built end to end against it; `docs/aggregation.md`, "Before enabling
    // aggregation", lists what has to happen first. Any genesis carrying an `aggregation` section
    // is refused until then, whichever reason is the last to clear.
    // Split authorisation (genesis `hc_auth`, delegated proving Phase 2): the auth guest and
    // bundle guest v3 come as a pair. The ledger recomputes the v3 digest exactly when `hc_auth`
    // is set, and only v3 publishes it, so a v3 `hc_bundle` without `hc_auth` (or `hc_auth` with a
    // v1/v2 guest) is a chain on which no bundle can ever be admitted; and an `hc_auth` this
    // build does not carry is a guest no wallet built from it can prove. Core cannot name guests,
    // so this is where the pairing is enforced.
    let v3 = ZkExecutor::hc_hidden_bundle_v3();
    match gs.ledger.hc_auth() {
        Some(h) if h != ZkExecutor::hc_auth() => anyhow::bail!(
            "the genesis hc_auth ({}) is not this build's auth guest ({}); rebuild from the chain's pinned commit",
            randprotocol_core::notes::word8_to_hex(&h),
            randprotocol_core::notes::word8_to_hex(&ZkExecutor::hc_auth())
        ),
        Some(_) if gs.hc_bundle != v3 => anyhow::bail!(
            "the genesis names hc_auth (split authorisation) but its hc_bundle ({}) is not bundle guest v3 ({}): \
             the auth guest needs v3, the only bundle guest that publishes the auth commitment",
            randprotocol_core::notes::word8_to_hex(&gs.hc_bundle),
            randprotocol_core::notes::word8_to_hex(&v3)
        ),
        None if gs.hc_bundle == v3 => anyhow::bail!(
            "the genesis pins bundle guest v3 but names no hc_auth: v3 needs hc_auth (split \
             authorisation) — without it the ledger recomputes the v1 digest and admits no bundle"
        ),
        _ => {}
    }
    if gs.ledger.aggregation().is_some() {
        anyhow::bail!(
            "this genesis enables block aggregation, which is not supported on the hidden-asset \
             bundle yet: its admitted shapes and the recursion fixtures were measured for the \
             retired 2-in-2-out guest and must be re-measured before aggregation is activated; \
             and aggregation also stays blocked until the fixed recursion VM (RVM-1, the STOREE \
             high lane, and the other rVM findings of the 2026-09-27 release) has shipped and an \
             end-to-end forged-aggregate exercise has been run against it (docs/aggregation.md, \
             \"Before enabling aggregation\")"
        );
    }
    Ok(())
}

/// What [`start_with`] adds to the RPC beyond [`NodeConfig`] (audit v6, VK-2 / RPC-4).
#[derive(Clone, Default)]
pub struct RpcOptions {
    /// A second, **public** listener (`--public-rpc`): a fixed method set, no batches, no
    /// WebSocket, one meter for every caller together, and no caller counted as loopback. This
    /// is what a reverse proxy or an SSH forward should be pointed at; the operator's listener
    /// (`--rpc`) stays on loopback with everything on it.
    pub public_addr: Option<SocketAddr>,
    /// A bearer token the viewing-key methods require on the operator's listener
    /// (`--rpc-viewing-token-file`). `None` keeps the loopback rule.
    pub viewing_token: Option<Arc<str>>,
}

/// What [`start_with`] adds to the network beyond [`NodeConfig`] (audit v6, NET-1): its own
/// struct, beside [`RpcOptions`], so the many places that build a `NodeConfig` literally are
/// untouched.
#[derive(Clone, Debug, Default)]
pub struct NetOptions {
    /// Peers admitted past the inbound connection cap for the life of the process, and served
    /// from the validators' share of the sync budget (`--reserved-peer`). The bootstraps' peer
    /// ids are reserved the same way without being listed; validators' identities learned over
    /// gossip are added as they arrive.
    pub reserved_peers: Vec<PeerId>,
    /// gossipsub's strict validation (`--strict-gossip`, audit v6, CH-7): see
    /// [`network::EdgeConfig::strict_gossip`].
    pub strict_gossip: bool,
}

pub async fn start(cfg: NodeConfig) -> Result<NodeHandle> {
    start_with(cfg, RpcOptions::default(), NetOptions::default()).await
}

pub async fn start_with(cfg: NodeConfig, rpc_options: RpcOptions, net_options: NetOptions) -> Result<NodeHandle> {
    // The public listener is its own socket (audit v6): the same address as the operator's
    // would make one of them unreachable, and a wildcard operator port beside it would put the
    // full method set back on the path the public listener exists to close.
    if let Some(public) = rpc_options.public_addr {
        if public == cfg.rpc_addr || (public.port() == cfg.rpc_addr.port() && (public.ip().is_unspecified() || cfg.rpc_addr.ip().is_unspecified())) {
            anyhow::bail!("--public-rpc {public} collides with --rpc {}: the public listener needs its own port", cfg.rpc_addr);
        }
    }
    let key = Keypair::from_seed(cfg.seed).context("bad key seed")?;
    let (gs, executor) = load_genesis(&cfg.datadir)?;
    check_build_runs_genesis(&gs, &ZkExecutor::known_hc_bundles())?;
    // Before RocksDB opens its ~1000 table files (issue #41): a node started under the default
    // soft limit of 1024 ran out of descriptors and its RPC refused every connection.
    match crate::rlimit::raise_nofile_limit() {
        Ok((soft, hard)) => tracing::info!(soft, hard, "open-files limit"),
        Err(e) => tracing::warn!("could not raise the open-files limit: {e}"),
    }
    // The disk guard (audit v4 OPS-3): a node that opens RocksDB on a full disk crash-loops
    // with the RPC never up; refusing here names the directory and the flag instead.
    let disk_free_bytes =
        crate::disk::free_bytes(&cfg.datadir).map_err(|e| anyhow!("free space of {}: {e}", cfg.datadir.display()))?;
    if disk_free_bytes < cfg.min_free_disk_bytes {
        return Err(anyhow!(
            "{} has {} MB free, under the {} MB minimum; free space or pass --min-free-disk-mb (audit v4 OPS-3)",
            cfg.datadir.display(),
            disk_free_bytes / (1 << 20),
            cfg.min_free_disk_bytes / (1 << 20)
        ));
    }
    prune_window_check(cfg.prune_history, gs.ledger.aggregation().map(|a| a.window), cfg.block_interval)
        .map_err(|e| anyhow::anyhow!(e))?;
    let storage = Arc::new(Storage::open(&cfg.datadir)?);
    storage.init_genesis(&gs)?;
    refuse_a_halted_store(&storage)?;
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
    // The admission cache (audit v3, B5): one set, shared with the replica — the verification
    // workers fill it, and propose/apply read it through the ledger. Like the covered source it
    // is re-registered on every replica this process builds (`apply_synced` resumes).
    let verified = Arc::new(RwLock::new(admission::VerifiedSet::new(admission::VERIFIED_SET_ENTRIES)));
    hs.set_verified_proofs(verified.clone());

    // Network. The sync and gossip byte limits follow the genesis block cap (call limits
    // spec §8), computed once here and handed to the swarm and the serve path.
    let identity = key.derive_subkey(b"rand-p2p-identity");
    let wire = network::WireLimits::for_ledger(&gs.ledger);
    // The consensus byte budget is sized off the same genesis cap (CN-4).
    let max_block_bytes = gs.ledger.max_block_bytes();
    // The validators' identities this node verified before it stopped (audit v6, NET-1), read
    // before the swarm starts so they are reserved before the first connection is accepted. The
    // operator's `--reserved-peer` list and the bootstraps are pinned beside them.
    let pinned: std::collections::HashSet<PeerId> = cfg
        .bootstrap
        .iter()
        .filter_map(|a| a.iter().find_map(|p| match p { libp2p::multiaddr::Protocol::P2p(id) => Some(id), _ => None }))
        .chain(net_options.reserved_peers.iter().copied())
        .collect();
    let rows = storage.peer_bindings().unwrap_or_else(|e| {
        tracing::warn!("persisted peer bindings unreadable, starting without them: {e}");
        Default::default()
    });
    let peer_bindings = crate::peer_bindings::PeerBindings::load(gs.hash(), pinned, rows);
    if !peer_bindings.is_empty() {
        tracing::info!(bound = peer_bindings.len(), "validator peer bindings restored from the last run");
    }
    let (net, mut events) = network::start_with(
        NetworkConfig {
            chain_id: gs.chain_id,
            listen: cfg.listen.clone(),
            bootstrap: cfg.bootstrap.clone(),
            enable_mdns: cfg.enable_mdns,
            limits: wire,
        },
        identity,
        network::EdgeConfig {
            reserved: net_options.reserved_peers.clone(),
            bound: peer_bindings.bound_peers(),
            strict_gossip: net_options.strict_gossip,
        },
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
        testnet: gs.testnet,
        fri_profile: gs.fri_profile.clone(),
        address: Some(key.address().to_base58()),
        peer_id: net.local_peer_id.to_string(),
        prune_floor: 0,
        prune_history_secs: cfg.prune_history.map(|d| d.as_secs()),
        reserved_peers: peer_bindings.reserved_count(),
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
    // The RPC's limits, computed once from the genesis ledger. A chain's own `gas` section
    // (Phase 1) is consensus state, and `with_gas_policy` refuses to let a node's
    // `--gas-price`/`--byte-price` flags override it — warn once here, since the flags are
    // otherwise silently ignored (spec 2026-09-28 §8).
    if cfg.gas_policy.is_some() && gs.ledger.gas().is_some() {
        tracing::warn!("this chain's genesis carries its own gas section; --gas-price/--byte-price are ignored");
    }
    let rpc_limits = rpc::ChainLimits::of(&gs.ledger).with_gas_policy(cfg.gas_policy);
    let rpc_state = RpcState {
            limiter: Arc::new(crate::rpc::RpcLimiter::default()),
            viewing_open: cfg.viewing_open,
            public: false,
            public_meter: Arc::new(crate::rpc::PublicMeter::default()),
            read_slots: Arc::new(crate::rpc::ReadSlots::default()),
            viewing_token: rpc_options.viewing_token.clone(),
            storage: storage.clone(),
            status: status.clone(),
            node: cmd_tx,
            chain_id: gs.chain_id,
            // The RPC's limits follow the genesis (call limits spec §8), like the wire's above.
            limits: rpc_limits.clone(),
            max_body_bytes: rpc_limits.rpc_max_body_bytes(),
            executor: executor.clone(),
            heads: heads.clone(),
            commits: commits.clone(),
            refusals: refusals.clone(),
            ws_conns: ws_conns.clone(),
            viewing,
    };
    let public_rpc = match rpc_options.public_addr {
        Some(addr) => Some(rpc::serve(addr, rpc_state.for_public_listener()).await.with_context(|| format!("binding --public-rpc {addr}"))?),
        None => None,
    };
    let (rpc_addr, rpc_task) = rpc::serve(cfg.rpc_addr, rpc_state).await?;
    tracing::info!("rpc listening on http://{rpc_addr}");
    match &public_rpc {
        Some((addr, _)) => tracing::info!(
            "public rpc listening on http://{addr}: {} methods, no batches, no websocket, one meter for all callers",
            rpc::PUBLIC_METHODS.len()
        ),
        // Said plainly, because the operator's listener trusts loopback and a proxy or an SSH
        // forward arrives on loopback (audit v6, VK-2 / RPC-4).
        None if !cfg.rpc_addr.ip().is_loopback() => tracing::warn!(
            "--rpc {rpc_addr} is not loopback and serves every method; put a public endpoint on --public-rpc instead"
        ),
        None => {}
    }
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
        // Under genesis `hardening_v6` a call proves over other shapes (the call binding, INT-4),
        // so its keys are the hardened ones.
        let hardened = hs.committed_ledger().hardening_v6();
        // Split authorisation (genesis `hc_auth`): every bundle on such a chain carries an auth
        // proof too, so its key is warmed beside the bundle's; a chain without it never needs one.
        let split_auth = hs.committed_ledger().hc_auth().is_some();
        let ex = executor.clone();
        tokio::task::spawn_blocking(move || {
            ex.warm_bundle();
            tracing::info!("bundle verifier key warmed");
            if split_auth {
                ex.warm_auth();
                tracing::info!("auth verifier key warmed");
            }
            for rec in programs {
                if hardened {
                    ex.warm_hardened(&rec);
                } else {
                    ex.warm(&rec);
                }
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
    // RESCAN-LEDGER-1: this pool admits faucet mints from the genesis's minters only.
    let mut mempool = Mempool::new(10_000);
    mempool.set_faucet_minters(admission::faucet_minters(&gs));
    if let Some(p) = cfg.gas_policy {
        mempool.set_gas_policy(p);
    }
    let binding_signer = if cfg.validator { Some(Keypair::from_seed(cfg.seed)?) } else { None };
    let node = Node {
        cfg,
        gs,
        address,
        executor: executor.clone(),
        storage: storage.clone(),
        hs,
        mempool,
        net: net.clone(),
        status: status.clone(),
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
        prune_passes: 0,
        compacting: Arc::new(AtomicBool::new(false)),
        no_peer_warned_at: None,
        highest_proposal_seen: 0,
        disk_free_bytes,
        refused: admission::RefusedCache::new(admission::REFUSED_CACHE_ENTRIES),
        verified,
        limiter: admission::PeerLimiter::new(admission::PEER_TX_BURST, admission::PEER_TX_PER_SEC),
        status_limiter: admission::PeerLimiter::new(STATUS_GOSSIP_BURST, STATUS_GOSSIP_PER_SEC),
        consensus_limiter: admission::PeerLimiter::new(CONSENSUS_GOSSIP_BURST, CONSENSUS_GOSSIP_PER_SEC),
        consensus_byte_limiter: consensus_byte_limiter(max_block_bytes),
        binding_limiter: admission::PeerLimiter::new(
            crate::peer_bindings::BINDING_GOSSIP_BURST,
            crate::peer_bindings::BINDING_GOSSIP_PER_SEC,
        ),
        peer_bindings,
        binding_signer,
        binding_announced_at: None,
        binding_announce_wanted: false,
        sync_limiter: admission::PeerLimiter::new(SYNC_REQUEST_BURST, SYNC_REQUEST_PER_SEC),
        not_held_signed: NotHeldCache::default(),
        peer_memory: PeerMemory::default(),
        sync_serve_budget: SyncServeBudget::new(),
        sync_serving: Arc::new(tokio::sync::Semaphore::new(MAX_SYNC_SERVES_IN_FLIGHT)),
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
    let (public_rpc_addr, public_rpc_task) = public_rpc.map_or((None, None), |(a, t)| (Some(a), Some(t)));
    Ok(NodeHandle { rpc_addr, public_rpc_addr, network: net, listen_addrs, status, storage, address, task, rpc_task, public_rpc_task })
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
                _ = status_tick.tick() => {
                    self.check_disk();
                    self.broadcast_status().await;
                    self.announce_binding().await;
                }
                _ = sync_tick.tick() => self.maybe_sync().await,
            }
        }
    }

    /// Free space under `DISK_LOW_FACTOR` times the startup minimum (audit v4 OPS-3).
    fn disk_low(&self) -> bool {
        self.disk_free_bytes < self.cfg.min_free_disk_bytes.saturating_mul(crate::disk::DISK_LOW_FACTOR)
    }

    /// Re-measure the data directory's free space; once per status tick, and warned about once
    /// per tick while low. A measurement that fails keeps the last one rather than reading zero.
    fn check_disk(&mut self) {
        match crate::disk::free_bytes(&self.cfg.datadir) {
            Ok(free) => self.disk_free_bytes = free,
            Err(e) => tracing::warn!("free space of {}: {e}", self.cfg.datadir.display()),
        }
        if self.disk_low() {
            tracing::warn!(
                "{} has {} MB free, under {} MB: disk_low (audit v4 OPS-3)",
                self.cfg.datadir.display(),
                self.disk_free_bytes / (1 << 20),
                self.cfg.min_free_disk_bytes.saturating_mul(crate::disk::DISK_LOW_FACTOR) / (1 << 20)
            );
        }
    }

    /// `Storage::prune_floor`, defaulting to 0 (an archive's floor) and logging when the meta
    /// row is actually unreadable rather than merely absent, so a status advertising 0 for that
    /// reason is not silently confused with an honest archive.
    fn prune_floor_or_zero(&self) -> u64 {
        self.storage.prune_floor().unwrap_or_else(|e| {
            tracing::warn!("prune floor unreadable: {e}; advertising 0");
            0
        })
    }

    fn publish_status(&self) {
        let mut s = self.status.write().unwrap_or_else(|e| e.into_inner());
        s.height = self.hs.committed_height();
        s.disk_free_bytes = self.disk_free_bytes;
        s.disk_low = self.disk_low();
        s.prune_floor = self.prune_floor_or_zero();
        s.prune_history_secs = self.cfg.prune_history.map(|d| d.as_secs());
        s.head_hash = self.hs.committed_hash().to_hex();
        s.view = self.hs.view();
        s.high_qc_view = self.hs.high_qc().view;
        // `peer_count` is every entry in the map, because dashboards threshold on it; since
        // `record_status` stopped creating entries for the authors of relayed gossip, the map
        // holds only peers this node is or was connected to. `connected_peers` is the number that
        // matters for sync: only a peer we hold an open connection to can be asked for blocks.
        s.peer_count = self.peers.len();
        s.connected_peers = self.peers.values().filter(|p| p.connected).count();
        s.reserved_peers = self.peer_bindings.reserved_count();
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
                    ledger.unsealed_fees(),
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
        // Spec 2026-09-28 §7.1, §8: the tip's live gas prices, `null` without a `gas` section —
        // what `rand_status` reports and what `rand_getLimits` reads for a `dynamic` chain's
        // current prices, since `ChainLimits::of`'s snapshot is only ever taken at startup.
        s.gas_prices = ledger.gas().is_some().then(|| ledger.gas_prices().into());
        // The pool's public size, straight from the committed ledger rather than a second read
        // of storage: this runs on the node loop after every commit.
        s.notes = ledger.next_index();
        s.nullifiers = ledger.nullifiers().len() as u64;
        s.tree_root = randprotocol_core::notes::word8_to_hex(&ledger.root());
        s.hc_bundle = randprotocol_core::notes::word8_to_hex(&ledger.hc_bundle());
        s.hc_auth = ledger.hc_auth().map(|h| randprotocol_core::notes::word8_to_hex(&h));
        s.binding_domain = ledger.binding_domain().version();
        let target = self.peers.values().filter_map(|p| p.status.as_ref()).map(|p| p.height).max().unwrap_or(0);
        s.sync_target = target.max(s.height);
        s.syncing = self.sync_inflight.is_some();
        // Without these, a node that is `syncing: true` with a rising target and no warning in the
        // log looks healthy while making no progress at all — which is exactly how chain 8's
        // catch-up stall presented.
        s.sync_inflight_age_ms = self.sync_inflight.map(|(_, _, at, _)| at.elapsed().as_millis() as u64);
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
            let verified = self.verified.clone();
            let out = self.verdicts_tx.clone();
            self.verify_in_flight += 1;
            tokio::task::spawn_blocking(move || {
                let result = guard_verify(|| validate_for_pool(&tx, &ledger, &storage, profile, executor.as_ref()));
                if result.is_ok() {
                    // B5: remember that these exact bytes verified — the hash binds the proofs —
                    // so the consensus path decodes them instead of verifying again. The pool's
                    // own answer (`insert_verified`) is irrelevant here: a proof that verified is
                    // verified, whatever the state-dependent half later says.
                    verified.write().unwrap_or_else(|e| e.into_inner()).insert(tx.hash());
                }
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

    /// Announce this validator's peer binding when it is due (audit v6, NET-1;
    /// [`crate::peer_bindings::announce_due`]): hung off the status tick, so a connect is answered
    /// within one tick — by when gossipsub has learned the new peer's subscriptions, which a
    /// publish at the connect itself would be too early for. Signed afresh each time with the
    /// current clock, so every announcement is a new message and supersedes the last.
    async fn announce_binding(&mut self) {
        let Some(key) = &self.binding_signer else { return };
        let now = Instant::now();
        if !crate::peer_bindings::announce_due(self.binding_announced_at, self.binding_announce_wanted, now) {
            return;
        }
        let binding = network::PeerBinding::sign(key, &self.gs.hash(), &self.net.local_peer_id, now_ms());
        self.binding_announced_at = Some(now);
        self.binding_announce_wanted = false;
        self.net.broadcast(GossipMessage::PeerBinding(binding)).await;
    }

    /// Do what a binding offer asked for (audit v6, NET-1): reserve, un-reserve, persist.
    async fn apply_binding_change(&mut self, change: crate::peer_bindings::BindingChange) {
        for p in change.unreserve {
            self.net.unreserve_peer(p).await;
        }
        if let Some(p) = change.reserve {
            tracing::info!(peer = %p, "validator peer binding recorded; peer reserved");
            self.net.reserve_peer(p).await;
        }
        if change.persist {
            if let Err(e) = self.storage.put_peer_bindings(&self.peer_bindings.rows()) {
                tracing::warn!("persisting peer bindings: {e}");
            }
        }
    }

    async fn broadcast_status(&self) {
        self.net
            .broadcast(GossipMessage::Status(Status {
                height: self.hs.committed_height(),
                head_hash: self.hs.committed_hash(),
                view: self.hs.view(),
                floor: self.prune_floor_or_zero(),
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
        // The certified chain above the head (audit v5, CON-4), written in order — before the
        // safety state that follows it in the batch, so the set on disk always holds the block
        // the persisted high QC names — except after a `Commit`: the replica emits the post-
        // commit set after `Commit`, and written before the commit lands it would, on a crash
        // between the two, lose the block just committed. That one is deferred to after the
        // commit below; a later set in the batch replaces an earlier one whole.
        let mut pending: Option<Vec<Block>> = None;
        while let Some(a) = queue.pop_front() {
            match a {
                Action::PersistSafety(s) => self.storage.save_safety(&s)?,
                Action::PersistPending(blocks) if to_commit.is_empty() => self.storage.save_pending_blocks(&blocks)?,
                Action::PersistPending(blocks) => pending = Some(blocks),
                // Nothing is persisted and nothing else in the batch runs: this node's committed
                // history and the set's disagree, so every finality answer it could give from here
                // is suspect. Stop; startup's `verify_chain` decides what the restart does with the
                // store (audit v3).
                Action::SafetyViolation { committed, attempted } => {
                    tracing::error!(?committed, ?attempted, "conflicting finality: stopping this node");
                    // Written down before the stop (audit v6, CON-5): the unit restarts a stopped
                    // node, and without a record it came back and served again. With it, the next
                    // start refuses until an operator has read it and cleared it.
                    let halt = crate::storage::SafetyHalt { committed, attempted, height: self.hs.committed_height(), at_ms: now_ms() };
                    if let Err(e) = self.storage.save_safety_halt(&halt) {
                        tracing::error!("the safety halt could not be recorded: {e}");
                    }
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
                // Audit v6, STAKE-1: the replica saw a leader sign two headers for one view, on
                // a chain that slashes. Pool the evidence as a `SlashEquivocation` — through the
                // pool's own admission, so it is refused here exactly as a peer's copy would be
                // (a jailed offender, an old header) — and gossip it: the next honest leader
                // includes it.
                Action::Equivocation { first, second } => self.pool_equivocation(first, second).await,
            }
        }
        self.commit(to_commit, to_record).await?;
        if let Some(blocks) = pending {
            self.storage.save_pending_blocks(&blocks)?;
        }
        Ok(())
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
        if !self.cfg.keep_raw_proofs && head.is_multiple_of(16) {
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
        // The history-retention pass (history pruning spec §1): every 16 blocks, the blocks
        // older than the window measured on the chain's own clock lose their history. Never
        // inside the aggregation window, never the head or its parent, never genesis.
        if let Some(keep) = self.cfg.prune_history {
            if head.is_multiple_of(16) {
                let head_ms = self.storage.head_block()?.header.timestamp_ms;
                let cutoff_ms = prune_cutoff_ms(head_ms, now_ms(), keep);
                let window = self.hs.committed_ledger().aggregation().map(|a| a.window).unwrap_or(0);
                let keep_from = head.saturating_sub(window.max(2));
                let storage = self.storage.clone();
                let pruned = tokio::task::spawn_blocking(move || storage.prune_history(cutoff_ms, keep_from, crate::storage::PRUNE_PASS_MAX))
                    .await
                    .map_err(|e| anyhow::anyhow!("history pruning task: {e}"))??;
                if pruned > 0 {
                    self.prune_passes += 1;
                    tracing::info!("pruned {pruned} blocks below height {} at head {head}", self.storage.prune_floor()?);
                    if should_compact(self.prune_passes, &self.compacting) {
                        // Off the node loop entirely (final-review fix #1): a range compaction
                        // over days of blocks can run far longer than the delete pass above, and
                        // this call is fire-and-forget, not awaited, so it cannot stall a commit.
                        let storage = self.storage.clone();
                        let compacting = self.compacting.clone();
                        tokio::task::spawn_blocking(move || {
                            run_compaction(&compacting, || {
                                if let Err(e) = storage.compact_pruned_history() {
                                    tracing::warn!("history compaction failed: {e}");
                                }
                            })
                        });
                    } else if self.prune_passes.is_multiple_of(64) {
                        tracing::debug!("history compaction already running; skipping this pass");
                    }
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
    ///
    /// One blocking task per deploy-carrying commit, but never more than one key build at a time:
    /// `ZkExecutor::warm` holds the executor's warm lock across its whole body (CPUV-1), so a
    /// burst of deploys queues here — each task parked on the lock holds a blocking-pool thread
    /// and no key memory — instead of building side by side (six at once measured 1.58 GB on a
    /// 2 GB droplet). The startup warm and `warm_bundle` take the same lock, and the bundle key
    /// lives in a `Machine` of its own, so nothing warmed here can evict it.
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
        let hardened = ledger.hardening_v6();
        // RPL-2: an `Invoke` needs nothing more warmed. Its segment is held to the hardened
        // call's public table (`program_state::segment_fits`) and every other pin is the
        // hardened call's, so the keys `warm_hardened` builds are the keys it verifies under —
        // and the `program_state` section requires `hardening_v6`.
        let ex = self.executor.clone();
        tokio::task::spawn_blocking(move || {
            for rec in records {
                let t = Instant::now();
                if hardened {
                    ex.warm_hardened(&rec);
                } else {
                    ex.warm(&rec);
                }
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
                    next: tip.derive_next_set(tip.epoch() + 1).iter().map(|v| v.address()).collect(),
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
        let envelope_bytes = self.hs.tip_ledger().envelope_bytes();
        let domain = *self.hs.tip_ledger().binding_domain();
        let tx = faucet_mint_tx(&domain, self.gs.chain_id, envelope_bytes, &to, amount, height, &key, self.executor.as_ref())?;
        let hash = self
            .mempool
            .insert(tx.clone(), self.hs.tip_ledger(), self.executor.as_ref())
            .map_err(|e| e.to_string())?;
        self.net.broadcast(GossipMessage::Transaction(tx)).await;
        Ok(hash)
    }

    /// Audit v6, STAKE-1: turn a captured equivocation into the transaction that slashes it and
    /// pool it, exactly as the faucet pools a mint — the pool's `insert` runs the ledger's own
    /// validation (the section, the window, the offender's stake and jail, both signatures), so
    /// a pair the chain would refuse is dropped here with the reason, and a valid one is
    /// gossiped for the next leader. Every replica that saw both proposals builds the same
    /// transaction (`SignedHeader::ordered`), so the pool and gossip see one id per offence.
    async fn pool_equivocation(
        &mut self,
        first: Box<randprotocol_core::types::actions::SignedHeader>,
        second: Box<randprotocol_core::types::actions::SignedHeader>,
    ) {
        let (offender, view) = (first.header.proposer.address(), first.header.view);
        let tx = Transaction {
            chain_id: self.gs.chain_id,
            bundle: None,
            action: randprotocol_core::types::Action::SlashEquivocation { first, second },
        };
        match self.mempool.insert(tx.clone(), self.hs.tip_ledger(), self.executor.as_ref()) {
            Ok(hash) => {
                tracing::warn!(%offender, view, %hash, "leader equivocation evidence pooled as a SlashEquivocation");
                self.net.broadcast(GossipMessage::Transaction(tx)).await;
            }
            Err(MempoolError::Duplicate) => {}
            Err(e) => tracing::warn!(%offender, view, "leader equivocation evidence not pooled: {e}"),
        }
    }

    async fn on_network_event(&mut self, ev: NetworkEvent) -> Result<()> {
        match ev {
            NetworkEvent::Listening(a) => tracing::info!("listening on {a}"),
            NetworkEvent::PeerConnected(p) => {
                connect_peer(&mut self.peers, &mut self.peer_memory, p, self.wire.max_established_incoming as usize);
                self.broadcast_status().await;
                // Announced at the next status tick, rate-limited (audit v6, NET-1).
                self.binding_announce_wanted = true;
            }
            NetworkEvent::PeerDisconnected(p) => {
                let held_our_batch = self.sync_inflight.map(|s| s.0) == Some(p);
                disconnect_peer(&mut self.peers, &mut self.peer_memory, p, held_our_batch, Instant::now());
                if held_our_batch {
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
                    // Metered per forwarder by count and bytes (SW-1(d)/SW-3, CN-4), then prechecked
                    // (CN-4): only a message this node would vouch for is accepted, so forwarded
                    // (`classify_consensus_gossip`). Still reported before handling, because a
                    // proposal's execution stays on this loop and the report must not queue behind
                    // it (moving the accept after handling would change when votes and proposals
                    // reach the rest of the fleet); the precheck is one signature verify.
                    let verdict = classify_consensus_gossip(
                        &mut self.peers,
                        &self.consensus_limiter,
                        &self.consensus_byte_limiter,
                        &self.hs,
                        id.propagation_source,
                        &m,
                        Instant::now(),
                    );
                    self.report(id, GossipOutcome::Report(verdict.report)).await;
                    if verdict.handle {
                        if let ConsensusMessage::Proposal(b) = &m {
                            self.highest_proposal_seen = self.highest_proposal_seen.max(b.height());
                        }
                        self.on_consensus(m).await?
                    }
                }
                GossipMessage::Transaction(tx) => self.on_gossiped_tx(tx, id).await?,
                GossipMessage::Status(s) => {
                    let ahead = s.height > self.hs.committed_height() + 1;
                    let outcome = on_status_gossip(
                        &mut self.peers,
                        &self.status_limiter,
                        from,
                        id.propagation_source,
                        s,
                        Instant::now(),
                    );
                    let recorded = outcome == GossipOutcome::for_consensus();
                    tracing::debug!(%from, forwarder = %id.propagation_source, recorded, "status gossip");
                    self.report(id, outcome).await;
                    if recorded && ahead && self.sync_inflight.is_none() {
                        self.maybe_sync().await;
                    }
                }
                // Metered per forwarder, then shape, signer, freshness and signature (audit v6,
                // NET-1): one report on every path, then whatever the record asks for.
                GossipMessage::PeerBinding(b) => {
                    let hs = &self.hs;
                    let verdict = crate::peer_bindings::on_binding_gossip(
                        &mut self.peer_bindings,
                        &mut self.peers.entry(id.propagation_source).or_default().binding_bucket,
                        &self.binding_limiter,
                        |a| hs.knows_validator(a),
                        &b,
                        Instant::now(),
                        now_ms(),
                    );
                    self.report(id, GossipOutcome::Report(verdict.report)).await;
                    if let Some(change) = verdict.change {
                        self.apply_binding_change(change).await;
                    }
                }
            },
            NetworkEvent::SyncRequest { peer, request, channel } => {
                let admission = admit_sync_request(
                    &mut self.peers,
                    &mut self.peer_memory,
                    &self.sync_limiter,
                    &mut self.sync_serve_budget,
                    peer,
                    self.peer_bindings.is_validator_peer(&peer),
                    &request,
                    Instant::now(),
                );
                let response = if admission == SyncAdmission::Serve {
                    tracing::debug!("serving sync request from {peer}");
                    match request {
                        // Read and assembled off this loop (CN-2), answered from the worker
                        // through the network task's command channel.
                        SyncRequest::Blocks { from_height, max } => {
                            let (storage, wire, net) = (self.storage.clone(), self.wire, self.net.clone());
                            let (work, reply) = (
                                move || serve_blocks(&storage, &wire, from_height, max),
                                move |r| async move { net.send_sync_response(channel, r).await },
                            );
                            if let Err(reply) = spawn_sync_serve(&self.sync_serving, work, reply) {
                                // Every slot taken: this node is busy, as over the node-wide
                                // budget (SYNC-3), through the reply the refusal handed back (it
                                // owns the channel).
                                tracing::debug!(%peer, "sync request past the serving slots; answered busy");
                                reply(SyncResponse::Busy).await;
                            }
                            return Ok(());
                        }
                        // One block and a kept signature: cheap enough to stay here, and it needs
                        // the replica's tree.
                        SyncRequest::BlockByHash(_) => self.serve_sync(request),
                    }
                } else if admission == SyncAdmission::NodeBusy {
                    tracing::debug!(%peer, "sync request over the node-wide budget; answered busy");
                    SyncResponse::Busy
                } else {
                    tracing::debug!(%peer, "sync request over the peer's own limit; answered busy or Block(None)");
                    refused_sync_response(&request)
                };
                self.net.send_sync_response(channel, response).await;
            }
            NetworkEvent::SyncResponse { peer, request_id, response } => {
                self.on_sync_response(peer, request_id, response).await?;
            }
            NetworkEvent::SyncFailed { peer, request_id, error } => {
                let was_batch = self.sync_inflight.map(|s| s.1) == Some(request_id);
                if was_batch {
                    let elapsed = self.sync_inflight.map(|(_, _, at, _)| at.elapsed().as_millis() as u64).unwrap_or(0);
                    self.sync_failures += 1;
                    self.sync_inflight = None;
                    // The peer missed (CN-1): backed off, and — below — skipped for the retry.
                    on_sync_batch_failed(&mut self.peers, peer, Instant::now());
                    // The halving stays on every failure, a silent peer's included (CN-1 looked at
                    // halving only on a size-shaped error): a batch too big for a slow link also
                    // ends in a timeout, and a peer choosing its failure can make any error it
                    // likes, so the error's shape proves nothing. What bounds the cost is the
                    // doubling back on each batch that applies, below in `on_sync_response`: with
                    // the silent peers backed off and outranked, two misses cost an honest peer
                    // two doublings, not a batch stuck at one block.
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
        let result = self.hs.on_message(m, now_ms());
        // Audit v6, STAKE-1: an equivocation is refused with an error, which carries no actions,
        // so the evidence the replica kept is collected here, on every outcome.
        let evidence = self.hs.take_equivocations();
        if !evidence.is_empty() {
            self.handle_actions(evidence).await?;
        }
        match result {
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
                let behind = orphan_wants_batch_sync(
                    self.best_peer_height(),
                    self.hs.committed_height(),
                    self.hs.pending_tip_height(),
                );
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

    fn serve_sync(&mut self, req: SyncRequest) -> SyncResponse {
        match req {
            // The loop sends a `Blocks` request to a blocking worker (CN-2, `spawn_sync_serve`);
            // this arm is the same answer, for any caller that is already off the loop's path.
            SyncRequest::Blocks { from_height, max } => serve_blocks(&self.storage, &self.wire, from_height, max),
            SyncRequest::BlockByHash(h) => {
                // A by-hash fetch is a single block with no aggregate context beside it: serve
                // the stored block untouched, marker forms and all, and let the fetcher's
                // acceptance decide (the batch path's sealed form is built in `Blocks`). A block
                // this node does not hold gets a validator's signed not-held (audit v4, CON-4).
                block_by_hash_response(&self.hs, &self.storage, &h, &mut self.not_held_signed)
            }
        }
    }

    /// Ask a peer for a block by hash. Peers are tried in turn: first those that have
    /// advertised a status at or above our height (they are on our chain and current),
    /// then any other; a peer that answers "not found" or fails is not asked again for
    /// the same hash. Gives up after `MAX_FETCH_ATTEMPTS`.
    async fn fetch_block(&mut self, h: Hash) -> Vec<Action> {
        // A request libp2p neither answers nor reports would otherwise block the hash for
        // good: on node A (2026-09-24) one `NotHeld` and one timeout were followed by no third
        // attempt for thirty minutes, so no leader ever reached the eight failures the fallback
        // needs. Past the wire's own timeout the request is gone rather than merely slow — the
        // same rule `sync_from` applies to a batch request. It was counted as an attempt when
        // it was sent, and its peer stays on the asked list.
        for stale in expire_stale_fetches(&mut self.fetch_inflight, self.wire.sync_request_timeout, Instant::now()) {
            tracing::debug!("by-hash fetch of {stale:?} got no answer within the wire timeout; abandoned");
        }
        if self.hs.has_block(&h) || fetch_blocked(&self.fetch_inflight, &h) {
            return Vec::new();
        }
        if fetch_deferred_to_batch_sync(self.best_peer_height(), self.hs.committed_height()) {
            tracing::debug!("not fetching block {h:?} by hash while {} blocks behind: batch sync brings it", self.best_peer_height() - self.hs.committed_height());
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
            self.fetch_inflight.insert(id, (h, Instant::now()));
            let e = self.fetch_attempts.get_mut(&h).expect("inserted above");
            e.0 += 1;
            e.1.push(peer);
        }
        Vec::new()
    }

    /// No peer can supply block `h`. If consensus is waiting on it as the high QC's block,
    /// let the replica fall back to the committed head so it can propose again. The lock is not
    /// released here (audit v4, CON-4): failed fetches are attempts, not evidence — that comes
    /// only from the signed `NotHeld` answers counted in `on_sync_response`.
    fn unobtainable(&mut self, h: Hash) -> Vec<Action> {
        self.hs.fallback_high_qc(&h)
    }

    /// A by-hash fetch came back empty or failed: try the next peer.
    async fn retry_fetch(&mut self, request_id: libp2p::request_response::OutboundRequestId) -> Result<()> {
        if let Some((h, _)) = self.fetch_inflight.remove(&request_id) {
            if !self.hs.has_block(&h) {
                let acts = self.fetch_block(h).await;
                self.handle_actions(acts).await?;
            }
        }
        Ok(())
    }

    fn best_peer_height(&self) -> u64 {
        chain_height_known(
            self.peers.values().filter_map(|p| p.status.as_ref()).map(|s| s.height).max(),
            self.highest_proposal_seen,
        )
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
        if let Some((peer, id, started, _asked)) = self.sync_inflight {
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
            // A peer that held our request for the whole timeout is a miss (CN-1): backed off,
            // which also keeps it out of the pick just below.
            on_sync_batch_failed(&mut self.peers, peer, Instant::now());
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
            let Some(peer) = pick_sync_peer(&self.peers, my_height, self.best_peer_height(), &skipped, Instant::now()) else {
                // No candidate at all — not merely a send failure — is the silent case: every
                // peer that could serve our next height has pruned past it (final-review fix
                // #2). Rate-limited to once a minute so a node stuck here does not spam its log
                // on every sync tick.
                if self.best_peer_height() > my_height + 1 {
                    let now = Instant::now();
                    if self.no_peer_warned_at.is_none_or(|at| now.duration_since(at) >= Duration::from_secs(60)) {
                        self.no_peer_warned_at = Some(now);
                        tracing::warn!(
                            height = my_height,
                            target = self.best_peer_height(),
                            peers = ?no_peer_summary(&self.peers),
                            "no peer holds height {}: every candidate has pruned it, or is backed off after a miss and asked again when that expires — a node behind every peer's retention must sync from the archive",
                            my_height + 1
                        );
                    }
                }
                return;
            };
            let req = SyncRequest::Blocks { from_height: my_height + 1, max: self.sync_batch };
            if let Some(id) = self.net.send_sync_request(peer, req).await {
                self.sync_inflight = Some((peer, id, Instant::now(), my_height));
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
                floors = ?self.peers.values().filter_map(|p| p.status.as_ref().map(|s| s.floor)).collect::<Vec<_>>(),
                "sync wanted but no candidate can serve our next height (a peer that pruned it, or none connected) — a node behind every peer's retention must sync from the archive"
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
                if let Some((h, _)) = self.fetch_inflight.remove(&request_id) {
                    self.fetch_attempts.remove(&h);
                }
                self.on_consensus(ConsensusMessage::Proposal(b)).await?;
            }
            SyncResponse::Block(None) => {
                tracing::debug!("peer {peer} does not have a requested block; trying another");
                self.retry_fetch(request_id).await?;
            }
            SyncResponse::NotHeld(n) => {
                // Signed evidence (audit v4, CON-4), counted only for the hash this request asked
                // for; the replica verifies the signer against its current set. Then on to the
                // next peer, as for `Block(None)`.
                match self.fetch_inflight.get(&request_id).map(|(h, _)| *h) {
                    Some(h) if n.hash == h => {
                        // Counted, reported by the replica once a quorum has said so, and never
                        // acted on (audit v6, CON-4): the lock is the operator's to release.
                        self.hs.record_not_held(&n);
                    }
                    _ => tracing::debug!("peer {peer} attested not-held for a hash this node did not ask it for; ignored"),
                }
                tracing::debug!("peer {peer} attests it does not hold a requested block; trying another");
                self.retry_fetch(request_id).await?;
            }
            SyncResponse::Busy => {
                // The peer's node-wide budget is spent (audit v6, SYNC-3): no miss, no back-off,
                // no batch halving — ask another peer now, and this one again after a pause.
                if self.sync_inflight.map(|s| s.1) == Some(request_id) {
                    self.sync_inflight = None;
                    on_sync_busy(&mut self.peers, peer, Instant::now());
                    tracing::debug!(%peer, "sync peer busy; asking another");
                    self.sync_from(Some(peer)).await;
                } else {
                    // Only a batch is ever answered busy; a by-hash fetch that somehow is moves on
                    // like a `Block(None)`.
                    self.retry_fetch(request_id).await?;
                }
            }
            SyncResponse::Blocks(blocks) => {
                let current = self.sync_inflight.map(|s| s.1) == Some(request_id);
                let elapsed = self.sync_inflight.map(|(_, _, at, _)| at.elapsed().as_millis() as u64);
                // The height this node actually asked from (review round 2, N1). Falling back to
                // the tree's current shape is only right when no request is outstanding: after the
                // committed-head fallback fired they differ, and judging by the tree ignored the
                // answer to the request we had just sent.
                let my_height = self
                    .sync_inflight
                    .map(|(_, _, _, asked)| asked)
                    .unwrap_or_else(|| self.hs.pending_tip_height().max(self.hs.committed_height()));
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
                    if d.miss {
                        // The peer we chose for its claimed height had nothing to give (SYNC-2):
                        // back it off, or the next tick re-picks it on the same claim, and ask the
                        // next candidate now.
                        if let Some(p) = self.peers.get_mut(&peer) {
                            back_off_sync_peer(p, Instant::now());
                            tracing::info!(%peer, backoff_s = p.sync_backoff.as_secs(), "sync peer backed off after an unusable answer");
                        }
                        self.sync_from(Some(peer)).await;
                    }
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
                    // Its meters are remembered, not dropped with the entry (CN-2): a rejected
                    // batch must not buy its sender a fresh set.
                    disconnect_peer(&mut self.peers, &mut self.peer_memory, peer, false, Instant::now());
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
                if let Some(p) = self.peers.get_mut(&peer) {
                    clear_sync_backoff(p);
                }
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
        let mut committed_sets: Option<randprotocol_core::consensus::EpochSets> = None;
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
                let mut derived = ledger.derive_next_set(epoch);
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
            if !cb.qc.verify(&self.gs.signing_domain(), set) {
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
            check_pruned_shapes(ledger.aggregation(), b.height(), &cb.pruned)?;
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
            let receipts = ledger.apply_block_for_sync(b, &sidecar, &cb.pruned, self.executor.as_ref(), &NoVerified)?;
            if receipts != cb.receipts {
                anyhow::bail!("receipts for block {} do not match our execution", b.height());
            }
            // The records this block makes available to later aggregates in the batch: raw
            // bundles by their proofs, marker-form ones by the side table.
            for tx in &b.transactions {
                match tx.bundle.as_ref().and_then(|bd| randprotocol_core::notes::pruned_proof_hash(&bd.proof)) {
                    Some(proof_hash) => {
                        let p = cb.pruned.iter().find(|p| p.proof_hash == proof_hash).expect("checked above");
                        // The ledger refused any other length above (`MalformedPrunedRecord`);
                        // a peer's list is still never unwrapped on trust.
                        let Some(pv) = p.public_values_array() else {
                            return Err(anyhow!("pruned record for tx {} carries {} public values", p.tx_hash, p.public_values.len()));
                        };
                        recent.insert(p.tx_hash, randprotocol_core::types::CoveredBundle { public_values: pv, shape: p.shape });
                    }
                    None => {
                        if let Some(bd) = &tx.bundle {
                            if let Ok(proof) = postcard::from_bytes::<randprotocol_zkvm::machine::Proof>(&bd.proof) {
                                let pv: [u64; randprotocol_core::types::pv::NUM] = proof.public_values.clone().try_into().expect("cs8 proofs carry pv::NUM public values");
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
                // The epoch sets too (review round 2, N2). A set derived while verifying the
                // *tail* must not reach `resume`: the replica would then already hold it, so when
                // that epoch's first block later commits through the live path it emits no
                // `RecordEpochSet` and the set is never written to RocksDB. Silent until the next
                // restart, where `verify_chain` finds no stored set for that epoch, truncates to
                // before the boundary and resyncs.
                committed_sets = Some(sets.clone());
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
        let sets = committed_sets.expect("the prefix is non-empty, so its epoch sets were taken");
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
        ccfg.domain = self.gs.signing_domain();
        ccfg.base_timeout = self.cfg.base_timeout;
        ccfg.max_timeout = self.cfg.max_timeout;
        let signer = if self.hs.is_validator() { Some(Keypair::from_seed(self.cfg.seed)?) } else { None };
        let safety = self.hs.safety_state();
        // The certified chain the replica being replaced holds (audit v5, CON-4): what extends
        // the new head is put back, the rest — at or under it, or off the synced branch — is
        // dropped by `resume`; the set on disk is then rewritten to what the new replica holds.
        let held = self.hs.certified_chain_blocks();
        self.hs = HotStuff::resume(
            ccfg,
            signer,
            head.block.clone(),
            head.qc.clone(),
            ledger,
            Some(safety),
            held,
            sets,
            self.executor.clone(),
        );
        self.storage.save_pending_blocks(&self.hs.certified_chain_blocks())?;
        // The covered source does not ride the resume: `HotStuff::resume` is a fresh replica,
        // and without this a synced node would refuse every aggregate-carrying block at the
        // sidecar forever (the capstone's AggregateNeedsCovered).
        if self.gs.ledger.aggregation().is_some() {
            self.hs.set_covered_source(Arc::new(StoreCovered {
                storage: self.storage.clone(),
                profile: core_profile(&self.gs.fri_profile),
            }));
        }
        // The admission cache (audit v3, B5) does not ride the resume either: re-register the
        // set this process already holds — its entries are as valid for the resumed replica as
        // they were for the one it replaces.
        self.hs.set_verified_proofs(self.verified.clone());
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
                        "synced block {height} has unknown parent {parent:?}; fetching it and syncing from the committed head again"
                    );
                    self.sync_from_committed = true;
                    let acts = self.fetch_block(parent).await;
                    self.handle_actions(acts).await?;
                    break;
                }
                // A block at or below the committed head is one we already have: the rest of the
                // batch may still be new, so keep going (review round 3, R2). Any other refusal is
                // about this branch, and the blocks above it descend from the block just refused.
                Err(randprotocol_core::consensus::ConsensusError::Stale(_)) => continue,
                Err(e) => {
                    tracing::debug!("synced block {height} not taken by the replica: {e}");
                    break;
                }
            }
        }
        Ok(())
    }
}

/// The faucet mint's transaction: a note for `to` sealed in the chain's own envelope format
/// (`EnvelopeFormat::for_chain(envelope_bytes)`, spec 2026-09-26 §2.4), signed by `minter`.
///
/// Factored out of [`Node::mint`] as the pure half — no network, no mempool, no rate limiter —
/// so it is unit-testable against a bare ledger rather than the whole running node. No memo: a
/// faucet has no sender's intent to write one for.
#[allow(clippy::too_many_arguments)]
fn faucet_mint_tx(
    domain: &randprotocol_core::BindingDomain,
    chain_id: u64,
    envelope_bytes: Option<usize>,
    to: &ShieldedAddress,
    amount: u64,
    height: u64,
    minter: &Keypair,
    executor: &dyn ConfidentialExecutor,
) -> std::result::Result<Transaction, String> {
    let format =
        randprotocol_core::notes::EnvelopeFormat::for_chain(envelope_bytes.and_then(|n| u32::try_from(n).ok()));
    let note = Note::new(to.pk, [0; 8], amount, 0, height as u32);
    let throwaway = SpendKey::random().viewing_key();
    let envelope = randprotocol_zkvm::address::seal_note_as(format, &throwaway, to, &note, &TxKey::random(), "")?;
    // BIND-1: signed under the chain's binding domain — with the genesis hash under genesis
    // `binding_domain: 1` — which is what the ledger verifies the mint against.
    let tx = Transaction::mint_in(domain, chain_id, note.pk, note.time, note.r, envelope, amount, minter, executor);
    debug_assert_eq!(tx.commitments(), vec![note.commitment()], "the sealed note is the one admission derives");
    Ok(tx)
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

        let epoch1 = ledger.derive_next_set(1);
        ledger.set_height(2);
        let tx = bundle_tx(&ledger, [[5; 8], [6; 8]], [[7; 8], [8; 8]], bundle_fee());
        let b2 = make_block_voted(&b1, &mut ledger, vec![tx], &key(1), &[&key(1)]);
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
                votes: vec![Vote::sign(&randprotocol_core::consensus::SigningDomain::v0(Hash::ZERO), head.view(), head.hash(), k)],
            },
        };
        Block::sign(&randprotocol_core::consensus::SigningDomain::v0(Hash::ZERO), header, Vec::new(), k)
    }

    /// A by-hash fetch that libp2p neither answers nor reports (audit v5, node A on 2026-09-24:
    /// after one `NotHeld` and one timeout, no third attempt for thirty minutes) must not hold
    /// the hash un-fetchable forever: an inflight entry older than the wire timeout is dropped
    /// — it was counted as an attempt when it was sent — and no longer blocks a new attempt; a
    /// fresh one still does.
    #[test]
    fn an_inflight_fetch_older_than_the_timeout_does_not_block_a_new_attempt() {
        let timeout = Duration::from_secs(20);
        let now = Instant::now();
        let stale = Hash::digest(b"asked long ago");
        let fresh = Hash::digest(b"asked just now");
        let mut inflight: HashMap<u64, (Hash, Instant)> = HashMap::new();
        inflight.insert(1, (stale, now - timeout - Duration::from_secs(1)));
        inflight.insert(2, (fresh, now - Duration::from_secs(1)));
        assert_eq!(expire_stale_fetches(&mut inflight, timeout, now), vec![stale]);
        assert!(!fetch_blocked(&inflight, &stale), "a stale fetch no longer blocks a new attempt");
        assert!(fetch_blocked(&inflight, &fresh), "a fresh one still does");
        assert_eq!(inflight.len(), 1);
        // Exactly at the timeout the request is still the wire's to answer.
        inflight.insert(3, (stale, now - timeout));
        assert_eq!(expire_stale_fetches(&mut inflight, timeout, now), Vec::<Hash>::new());
        assert!(fetch_blocked(&inflight, &stale));
    }

    /// The sync peer selection (the stall shape's unit test): the freshest connected peer
    /// ahead wins; the fallback asks any connected peer when the chain is known ahead but no
    /// connected-and-fresh pair exists; and a statusless connected peer is still askable.
    /// The 2026-09-24 stall's last piece: six validators sat at committed 248947 holding
    /// 248948–248953 pending, and every proposal they saw extended an uncommitted 248954. With
    /// "behind" measured on the committed height they batch-synced for blocks they already held
    /// instead of fetching the one they lacked by hash, so they could never vote and the
    /// twelve at the tip were one short of a quorum. "Behind" is measured on what the replica
    /// holds, exactly as `sync_from` asks above what it holds (review C2).
    #[test]
    fn an_orphan_is_fetched_by_hash_once_the_replica_holds_every_committed_block() {
        // Holds nothing above its head and the chain is far ahead: batch-sync.
        assert!(orphan_wants_batch_sync(248_953, 248_947, 248_947));
        // Holds the committed tail as pending: the missing parent is uncommitted, fetch it.
        assert!(!orphan_wants_batch_sync(248_953, 248_947, 248_953));
        // At the tip either way: fetch.
        assert!(!orphan_wants_batch_sync(248_953, 248_953, 248_953));
        // A gap of two is a fetch, three is a batch (the rule's existing margin).
        assert!(!orphan_wants_batch_sync(10, 8, 8));
        assert!(orphan_wants_batch_sync(11, 8, 8));
    }

    /// The peer map is bounded by the swarm's inbound cap as belt and braces (deep scan
    /// 2026-09-24): at the bound a new connection evicts the entries that are not connected
    /// before it is recorded, so hearsay entries can never hold the map above it — while a
    /// connected peer is always recorded, because the swarm is what bounds those and a
    /// validator must never be refused.
    #[test]
    fn the_peer_map_never_grows_past_the_cap_on_disconnected_entries() {
        let pid = |seed: u8| {
            let kp = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            PeerId::from(kp.public())
        };
        let entry = |connected: bool| Peer { connected, ..Default::default() };
        const CAP: usize = 3;
        let mut peers: HashMap<PeerId, Peer> = [(pid(1), entry(false)), (pid(2), entry(false)), (pid(3), entry(false))].into_iter().collect();
        connect_peer(&mut peers, &mut PeerMemory::default(), pid(4), CAP);
        assert!(peers.len() <= CAP, "{} entries, over the cap of {CAP}", peers.len());
        assert!(peers[&pid(4)].connected, "the new peer is recorded");
        // Connected entries are never evicted, and a connected peer is never refused: at the
        // bound with every entry connected the map grows, as the swarm's cap is what holds it.
        let mut peers: HashMap<PeerId, Peer> = [(pid(1), entry(true)), (pid(2), entry(true)), (pid(3), entry(true))].into_iter().collect();
        connect_peer(&mut peers, &mut PeerMemory::default(), pid(4), CAP);
        assert_eq!(peers.len(), 4);
        assert!(peers.values().all(|p| p.connected));
        // Under the bound nothing is evicted, whatever its state.
        let mut peers: HashMap<PeerId, Peer> = [(pid(1), entry(false))].into_iter().collect();
        connect_peer(&mut peers, &mut PeerMemory::default(), pid(2), CAP);
        assert_eq!(peers.len(), 2);
        // A known peer reconnecting is an update, not growth.
        connect_peer(&mut peers, &mut PeerMemory::default(), pid(1), CAP);
        assert_eq!(peers.len(), 2);
        assert!(peers[&pid(1)].connected);
    }

    /// A gossiped `Status` is keyed by its *author*, which gossipsub delivers multi-hop, and a
    /// peer id is free to mint: recording one for an author this node is not connected to made
    /// an entry nothing ever removes — a way past the swarm's connection cap (deep scan
    /// 2026-09-24, medium). Only an existing entry is updated.
    #[test]
    fn a_status_from_an_author_this_node_is_not_connected_to_creates_no_peer_entry() {
        let pid = |seed: u8| {
            let kp = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            PeerId::from(kp.public())
        };
        let status = |height: u64| Status { height, head_hash: Hash::ZERO, view: height, floor: 0 };
        let forwarder = pid(1);
        let author = pid(2);
        let mut peers: HashMap<PeerId, Peer> =
            [(forwarder, Peer { connected: true, ..Default::default() })].into_iter().collect();
        for i in 0..64u8 {
            record_status(&mut peers, pid(10 + i), status(9));
        }
        record_status(&mut peers, author, status(9));
        assert_eq!(peers.len(), 1, "an author this node is not connected to must not get an entry ({} entries)", peers.len());
        assert!(!peers.contains_key(&author));
    }

    /// The other half: a connected forwarder's own status (one hop, `from == propagation_source`)
    /// still lands, and keeps landing, on its entry — that is what `pick_sync_peer` reads.
    #[test]
    fn a_connected_forwarders_own_status_still_updates() {
        let pid = |seed: u8| {
            let kp = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            PeerId::from(kp.public())
        };
        let status = |height: u64| Status { height, head_hash: Hash::ZERO, view: height, floor: 0 };
        let forwarder = pid(1);
        let mut peers: HashMap<PeerId, Peer> =
            [(forwarder, Peer { connected: true, ..Default::default() })].into_iter().collect();
        record_status(&mut peers, forwarder, status(9));
        assert_eq!(peers[&forwarder].status.as_ref().map(|s| s.height), Some(9));
        record_status(&mut peers, forwarder, status(10));
        assert_eq!(peers[&forwarder].status.as_ref().map(|s| s.height), Some(10));
        assert_eq!(peers.len(), 1);
    }

    /// A `Status` is metered against its *forwarder*, the way a transaction is (deep scan
    /// 2026-09-24): the burst is admitted, the next one within the window is `Ignore`d and not
    /// recorded, a second's refill re-admits four, and another forwarder spends its own bucket.
    #[test]
    fn status_gossip_is_metered_per_forwarder() {
        use crate::admission::{Acceptance, PeerLimiter};
        let pid = |seed: u8| {
            let kp = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            PeerId::from(kp.public())
        };
        let status = |height: u64| Status { height, head_hash: Hash::ZERO, view: height, floor: 0 };
        let limiter = PeerLimiter::new(STATUS_GOSSIP_BURST, STATUS_GOSSIP_PER_SEC);
        let (f1, f2) = (pid(1), pid(2));
        let mut peers: HashMap<PeerId, Peer> = [f1, f2]
            .into_iter()
            .map(|p| (p, Peer { connected: true, ..Default::default() }))
            .collect();
        let now = Instant::now();
        for i in 0..STATUS_GOSSIP_BURST as u64 {
            let o = on_status_gossip(&mut peers, &limiter, f1, f1, status(i), now);
            assert_eq!(o, GossipOutcome::for_consensus(), "status {i} of the burst: {o:?}");
        }
        let over = on_status_gossip(&mut peers, &limiter, f1, f1, status(99), now);
        assert_eq!(over, GossipOutcome::Report(Acceptance::Ignore), "the {}th status within the window: {over:?}", STATUS_GOSSIP_BURST + 1);
        assert_eq!(peers[&f1].status.as_ref().map(|s| s.height), Some(15), "an ignored status is not recorded");
        // One second on: four more, then over again.
        let later = now + Duration::from_secs(1);
        for i in 0..4 {
            assert_eq!(on_status_gossip(&mut peers, &limiter, f1, f1, status(20 + i), later), GossipOutcome::for_consensus(), "refilled {i}");
        }
        assert_eq!(on_status_gossip(&mut peers, &limiter, f1, f1, status(30), later), GossipOutcome::Report(Acceptance::Ignore));
        // The other forwarder's bucket is its own: f2's own status lands while f1 is over. A
        // relay of f1's status spends f2's allowance but is not read (SYNC-1: a status is read
        // only from its author).
        assert_eq!(on_status_gossip(&mut peers, &limiter, f2, f2, status(40), later), GossipOutcome::for_consensus());
        assert_eq!(peers[&f2].status.as_ref().map(|s| s.height), Some(40));
        assert_eq!(on_status_gossip(&mut peers, &limiter, f1, f2, status(41), later), GossipOutcome::Report(Acceptance::Ignore));
        assert_eq!(peers[&f1].status.as_ref().map(|s| s.height), Some(23));
        // A forwarder this node holds no entry for cannot be metered, and is ignored.
        assert_eq!(on_status_gossip(&mut peers, &limiter, f1, pid(3), status(50), later), GossipOutcome::Report(Acceptance::Ignore));
        assert_eq!(peers.len(), 2);
    }

    /// SW-1(d)/SW-3 (network scan 2026-09-26): consensus gossip was accepted — and so forwarded
    /// fleet-wide — before it was handled, with no per-peer limit, so one peer could push junk
    /// proposals and votes through every node at wire speed. Metered now against the forwarder
    /// like a transaction or a status: the burst passes, the next within the window is `Ignore`d
    /// (not forwarded, not handled, not `Reject`ed — an honest relay in a burst looks the same),
    /// the refill re-admits, and another forwarder spends its own bucket.
    #[test]
    fn consensus_gossip_is_metered_per_forwarder() {
        use crate::admission::{Acceptance, PeerLimiter};
        let pid = |seed: u8| PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public());
        let limiter = PeerLimiter::new(CONSENSUS_GOSSIP_BURST, CONSENSUS_GOSSIP_PER_SEC);
        let (f1, f2) = (pid(1), pid(2));
        let mut peers: HashMap<PeerId, Peer> =
            [f1, f2].into_iter().map(|p| (p, Peer { connected: true, ..Default::default() })).collect();
        let now = Instant::now();
        for i in 0..CONSENSUS_GOSSIP_BURST {
            assert_eq!(on_consensus_gossip(&mut peers, &limiter, f1, now), GossipOutcome::for_consensus(), "message {i} of the burst");
        }
        assert_eq!(on_consensus_gossip(&mut peers, &limiter, f1, now), GossipOutcome::Report(Acceptance::Ignore), "over the burst");
        assert_eq!(on_consensus_gossip(&mut peers, &limiter, f2, now), GossipOutcome::for_consensus(), "f2's bucket is its own");
        let later = now + Duration::from_secs(1);
        for i in 0..CONSENSUS_GOSSIP_PER_SEC as u32 {
            assert_eq!(on_consensus_gossip(&mut peers, &limiter, f1, later), GossipOutcome::for_consensus(), "refilled {i}");
        }
        assert_eq!(on_consensus_gossip(&mut peers, &limiter, f1, later), GossipOutcome::Report(Acceptance::Ignore));
        // A forwarder with no entry yet (gossip racing its `PeerConnected`, or an entry dropped after
        // a rejected sync batch) is metered on a fresh one, as a transaction's is — never refused
        // outright: a validator's votes must not be lost to bookkeeping.
        assert_eq!(on_consensus_gossip(&mut peers, &limiter, pid(3), now), GossipOutcome::for_consensus());
    }

    /// A four-validator replica (keys 1..=4) at genesis, as the node's gossip arm sees it.
    fn gossip_replica() -> HotStuff {
        let (k1, k2, k3, k4) = (key(1), key(2), key(3), key(4));
        let gs = genesis_of(7, &[&k1, &k2, &k3, &k4], vec![], 1000);
        let mut ccfg = ConsensusConfig::new(7, gs.validators.clone(), gs.hash());
        ccfg.domain = gs.signing_domain();
        HotStuff::new(ccfg, Some(key(1)), gs.block.clone(), gs.ledger.clone(), Arc::new(StubExecutor))
    }

    /// An honest proposal for the replica's view by that view's leader, extending genesis and
    /// carrying `txs` (their root filled in).
    fn gossip_proposal(hs: &HotStuff, txs: Vec<Transaction>) -> ConsensusMessage {
        let genesis = hs.committed_hash();
        let leader = (1..=4u8).map(key).find(|k| k.address() == hs.leader(hs.view())).unwrap();
        let header = BlockHeader {
            height: 1,
            view: hs.view(),
            parent: genesis,
            proposer: leader.public_key().clone(),
            timestamp_ms: 0,
            tx_root: Block::tx_root(&txs),
            state_root: Hash::ZERO,
            justify: QuorumCertificate::genesis(genesis),
        };
        ConsensusMessage::Proposal(Block::sign(hs.domain(), header, txs, &leader))
    }

    /// CN-4 (scan 2026-09-27, medium): the consensus arm accepted — so gossipsub forwarded
    /// fleet-wide — every decodable proposal, vote and new view before anything looked at it. A
    /// vote from a key no set holds is not forwarded now, one forged under a validator's key is
    /// rejected and never handed to the replica, and honest messages are accepted exactly as
    /// before. A message this replica merely cannot place (too far ahead) is not forwarded but
    /// still handled: the replica decides, and nobody is penalised.
    #[test]
    fn consensus_gossip_is_prechecked_before_it_is_forwarded() {
        use crate::admission::{Acceptance, PeerLimiter};
        let hs = gossip_replica();
        let pid = PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([1; 32]).unwrap().public());
        let mut peers: HashMap<PeerId, Peer> = HashMap::new();
        let limiter = PeerLimiter::new(CONSENSUS_GOSSIP_BURST, CONSENSUS_GOSSIP_PER_SEC);
        let bytes = consensus_byte_limiter(gas::MAX_BLOCK_BYTES);
        let now = Instant::now();
        let mut judge = |m: &ConsensusMessage| classify_consensus_gossip(&mut peers, &limiter, &bytes, &hs, pid, m, now);
        let accepted = ConsensusGossipVerdict { report: Acceptance::Accept, handle: true };
        let rejected = ConsensusGossipVerdict { report: Acceptance::Reject, handle: false };
        let not_forwarded = ConsensusGossipVerdict { report: Acceptance::Ignore, handle: true };

        let view = hs.view();
        let vote = |k: u8, v: u64| ConsensusMessage::Vote(Vote::sign(hs.domain(), v, Hash([7; 32]), &key(k)));
        assert_eq!(judge(&vote(2, view)), accepted, "an honest vote");
        let nv = randprotocol_core::consensus::NewView::sign(hs.domain(), view, hs.high_qc().clone(), &key(3));
        assert_eq!(judge(&ConsensusMessage::NewView(nv)), accepted, "an honest new view");
        assert_eq!(judge(&gossip_proposal(&hs, vec![])), accepted, "an honest proposal");

        assert_eq!(judge(&vote(9, view)), not_forwarded, "a non-validator's vote");
        let ConsensusMessage::Vote(mut forged) = vote(2, view) else { unreachable!() };
        forged.block_hash = Hash([8; 32]);
        assert_eq!(judge(&ConsensusMessage::Vote(forged)), rejected, "a validator key's vote over another block");
        let ConsensusMessage::Proposal(mut forged) = gossip_proposal(&hs, vec![]) else { unreachable!() };
        forged.header.timestamp_ms = 1;
        assert_eq!(judge(&ConsensusMessage::Proposal(forged)), rejected, "a leader's proposal re-headed");
        let far = view + randprotocol_core::consensus::PROPOSAL_VIEW_WINDOW + 1;
        assert_eq!(judge(&vote(2, far)), not_forwarded, "an honest vote past the proposal window");
    }

    /// CN-4: the count bucket let a forwarder deliver 64 messages a second of up to gossip's
    /// 16 MiB transmit size each — ~1 GiB a second per connection. The byte bucket stops a flood
    /// of maximum-size messages after its burst (ignored, not handled), while a minute of honest
    /// traffic — a burst of seven full blocks, then a full block, four votes and four new views
    /// every second — never trips it.
    #[test]
    fn consensus_gossip_is_metered_by_bytes() {
        use crate::admission::{Acceptance, PeerLimiter};
        let hs = gossip_replica();
        let pid = |seed: u8| PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public());
        let (honest, flooder) = (pid(1), pid(2));
        let mut peers: HashMap<PeerId, Peer> = HashMap::new();
        let limiter = PeerLimiter::new(CONSENSUS_GOSSIP_BURST, CONSENSUS_GOSSIP_PER_SEC);
        let bytes = consensus_byte_limiter(gas::MAX_BLOCK_BYTES);
        let t0 = Instant::now();
        let metered_out = ConsensusGossipVerdict { report: Acceptance::Ignore, handle: false };

        // A 16 MiB "signature" on a vote: the size gossip lets through.
        let ConsensusMessage::Vote(mut junk) = ConsensusMessage::Vote(Vote::sign(hs.domain(), hs.view(), Hash([7; 32]), &key(2)))
        else {
            unreachable!()
        };
        junk.signature = bincode::deserialize(&bincode::serialize(&vec![0u8; 16 << 20]).unwrap()).unwrap();
        let junk = ConsensusMessage::Vote(junk);
        let through = (0..CONSENSUS_GOSSIP_BURST)
            .filter(|_| classify_consensus_gossip(&mut peers, &limiter, &bytes, &hs, flooder, &junk, t0) != metered_out)
            .count();
        let most = (consensus_view_bytes(gas::MAX_BLOCK_BYTES) * CONSENSUS_GOSSIP_BURST_VIEWS as usize) / (16 << 20);
        assert!(through <= most, "{through} maximum-size messages got past the byte budget, at most {most} may");

        // Honest traffic, all accepted: a full block's worth of transactions under the cap.
        let full: Vec<Transaction> = (0..3u32)
            .map(|i| {
                let envelope = randprotocol_core::notes::Envelope {
                    kem_ct: vec![0; 1_300_000],
                    to_receiver: vec![],
                    to_sender: vec![],
                    body: vec![],
                };
                Transaction::mint(7, [1; 8], 0, [i; 8], envelope, 1, &key(1), &StubExecutor)
            })
            .collect();
        let proposal = gossip_proposal(&hs, full);
        let view = hs.view();
        let votes: Vec<ConsensusMessage> =
            (1..=4u8).map(|k| ConsensusMessage::Vote(Vote::sign(hs.domain(), view, Hash([7; 32]), &key(k)))).collect();
        let nvs: Vec<ConsensusMessage> = (1..=4u8)
            .map(|k| {
                ConsensusMessage::NewView(randprotocol_core::consensus::NewView::sign(hs.domain(), view, hs.high_qc().clone(), &key(k)))
            })
            .collect();
        let accepted = ConsensusGossipVerdict { report: Acceptance::Accept, handle: true };
        for i in 0..7 {
            assert_eq!(classify_consensus_gossip(&mut peers, &limiter, &bytes, &hs, honest, &proposal, t0), accepted, "burst block {i}");
        }
        for s in 1..=60u64 {
            let now = t0 + Duration::from_secs(s);
            for m in std::iter::once(&proposal).chain(&votes).chain(&nvs) {
                assert_eq!(classify_consensus_gossip(&mut peers, &limiter, &bytes, &hs, honest, m, now), accepted, "second {s}");
            }
        }
    }

    /// SYNC-1 (fullnode network scan 2026-09-26, high): gossipsub runs `Permissive`, so an
    /// unsigned message's author is whatever its sender wrote (`network`'s
    /// `a_forged_unsigned_status_reaches_the_node_under_the_claimed_author` pins that). One
    /// connected peer forwarding a `Status` "authored" by every honest peer, each with a floor
    /// past any height, used to hide all seventeen from `pick_sync_peer`. A status is now read
    /// only from its own author (`from == propagation_source`, the one identity a connection
    /// proves) — anything relayed is `Ignore`d and not forwarded — and a floor above its own
    /// height, which no node can hold, is `Reject`ed.
    #[test]
    fn a_forged_status_via_one_forwarder_hides_no_honest_peer_from_sync() {
        use crate::admission::{Acceptance, PeerLimiter};
        let pid = |seed: u8| PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public());
        let honest = |h: u64| Peer { status: Some(Status { height: h, head_hash: Hash::ZERO, view: h, floor: 0 }), connected: true, ..Default::default() };
        let forged = Status { height: 500, head_hash: Hash::ZERO, view: 500, floor: u64::MAX };
        let attacker = pid(99);
        let mut peers: HashMap<PeerId, Peer> = (1..=17).map(|i| (pid(i), honest(500))).collect();
        peers.insert(attacker, Peer { connected: true, ..Default::default() });
        let limiter = PeerLimiter::new(STATUS_GOSSIP_BURST, STATUS_GOSSIP_PER_SEC);
        let now = Instant::now();
        for i in 1..=17u8 {
            let out = on_status_gossip(&mut peers, &limiter, pid(i), attacker, forged.clone(), now + Duration::from_secs(i as u64));
            assert_eq!(out, GossipOutcome::Report(Acceptance::Ignore), "a status relayed under peer {i}'s name is neither read nor forwarded");
        }
        let pick = pick_sync_peer(&peers, 43, 500, &[], Instant::now());
        assert!(pick.is_some() && pick != Some(attacker), "an honest peer still serves 44: {pick:?}");
        // The attacker's own status with an impossible floor is malformed, not merely unread.
        let out = on_status_gossip(&mut peers, &limiter, attacker, attacker, forged, now + Duration::from_secs(60));
        assert_eq!(out, GossipOutcome::Report(Acceptance::Reject));
        assert!(peers[&attacker].status.is_none(), "a malformed status is not recorded");
        // An honest peer's own status still lands.
        let own = Status { height: 501, head_hash: Hash::ZERO, view: 501, floor: 400 };
        assert_eq!(on_status_gossip(&mut peers, &limiter, pid(1), pid(1), own, now + Duration::from_secs(61)), GossipOutcome::for_consensus());
        assert_eq!(peers[&pid(1)].status.as_ref().map(|s| s.height), Some(501));
    }

    /// Audit v6, PROC-8 (CI on `e55ad51`, `restart_cycles_keep_all_nodes_in_sync`): a restarted
    /// node connected to one peer whose `Status` did not reach it for 40 s knew of no height
    /// above its own, so it fetched every proposal's parent by hash, spent that peer's allowance,
    /// and never batch-synced. Until a status arrives the proposals it handles say how far the
    /// chain has gone — three blocks under the newest, what the three-chain rule has committed at
    /// most — and once any status is known, statuses alone decide: one leader's header (its
    /// height is signed by it alone) never outbids the peers.
    #[test]
    fn with_no_status_heard_the_proposals_say_how_far_the_chain_has_committed() {
        assert_eq!(chain_height_known(None, 0), 0, "nothing heard: nothing known");
        assert_eq!(chain_height_known(None, 2), 0);
        assert_eq!(chain_height_known(None, 144), 141, "no status: a proposal at 144 means 141 is committed");
        assert_eq!(chain_height_known(Some(120), 144), 120, "a status heard: the peers decide, not one leader");
        assert_eq!(chain_height_known(Some(150), 144), 150);
        // And with it a fresh node far behind asks a connected peer that has told it nothing.
        let pid = PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([7; 32]).unwrap().public());
        let peers: HashMap<PeerId, Peer> = [(pid, Peer { connected: true, ..Default::default() })].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 127, chain_height_known(None, 144), &[], Instant::now()), Some(pid));
        assert!(orphan_wants_batch_sync(chain_height_known(None, 144), 127, 130));
        assert!(fetch_deferred_to_batch_sync(chain_height_known(None, 144), 127));
    }

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
                    status: height.map(|height| Status { height, head_hash: Hash::ZERO, view: height, floor: 0 }),
                    connected,
                    ..Default::default()
                },
            )
        };
        let peers: HashMap<PeerId, Peer> = [p(1, true, Some(163)), p(2, true, Some(120)), p(3, false, Some(200))].into_iter().collect();
        // The freshest connected-and-ahead peer wins — never a disconnected one, however fresh.
        assert_eq!(pick_sync_peer(&peers, 43, 200, &[], Instant::now()), Some(pid(1)));
        // The stall shape: the fresh peer is disconnected and the connected one is statusless,
        // but the chain is known ahead — the fallback asks the connected peer anyway.
        let peers: HashMap<PeerId, Peer> = [p(1, false, Some(163)), p(2, true, None)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 163, &[], Instant::now()), Some(pid(2)));
        // Nothing ahead at all: no fallback (a peer at our height is not worth asking).
        let peers: HashMap<PeerId, Peer> = [p(1, true, None)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 43, &[], Instant::now()), None);
        // The skip list (a give-up) is honored before the fallback too.
        let skipped = [pid(2)];
        let peers: HashMap<PeerId, Peer> = [p(1, false, Some(163)), p(2, true, None), p(3, true, Some(50))].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 163, &skipped, Instant::now()), Some(pid(3)));
    }

    #[test]
    fn pick_sync_peer_never_picks_a_peer_that_pruned_our_next_height() {
        let pid = |seed: u8| {
            let kp = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            PeerId::from(kp.public())
        };
        let p = |seed: u8, height: u64, floor: u64| {
            (pid(seed), Peer { status: Some(Status { height, head_hash: Hash::ZERO, view: height, floor }), connected: true, ..Default::default() })
        };
        // We are at 43 and need 44. Peer 1 is far ahead but pruned everything below 100;
        // peer 2 is lower but still holds 44.
        let peers: HashMap<PeerId, Peer> = [p(1, 500, 100), p(2, 120, 0)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 500, &[], Instant::now()), Some(pid(2)));
        // A floor exactly at our next height is fine.
        let peers: HashMap<PeerId, Peer> = [p(1, 500, 44)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 500, &[], Instant::now()), Some(pid(1)));
        // Every candidate pruned it: no pick, even though the chain is ahead.
        let peers: HashMap<PeerId, Peer> = [p(1, 500, 100), p(2, 300, 60)].into_iter().collect();
        assert_eq!(pick_sync_peer(&peers, 43, 500, &[], Instant::now()), None);
    }

    #[test]
    fn no_peer_summary_lists_connected_peers_with_their_floor_and_height_and_omits_disconnected() {
        let pid = |seed: u8| {
            let kp = libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap();
            PeerId::from(kp.public())
        };
        let mut peers: HashMap<PeerId, Peer> = HashMap::new();
        peers.insert(pid(1), Peer { status: Some(Status { height: 500, head_hash: Hash::ZERO, view: 500, floor: 100 }), connected: true, ..Default::default() });
        peers.insert(pid(2), Peer { status: Some(Status { height: 300, head_hash: Hash::ZERO, view: 300, floor: 60 }), connected: true, ..Default::default() });
        // Connected but no status yet: omitted, nothing to report.
        peers.insert(pid(3), Peer { status: None, connected: true, ..Default::default() });
        // A fresh status from a peer we are not connected to: omitted too.
        peers.insert(pid(4), Peer { status: Some(Status { height: 900, head_hash: Hash::ZERO, view: 900, floor: 0 }), connected: false, ..Default::default() });
        let summary = no_peer_summary(&peers);
        assert_eq!(summary.len(), 2);
        assert!(summary.contains(&format!("{} floor=100 height=500", pid(1))));
        assert!(summary.contains(&format!("{} floor=60 height=300", pid(2))));
        assert!(!summary.iter().any(|s| s.contains(&pid(3).to_string())));
        assert!(!summary.iter().any(|s| s.contains(&pid(4).to_string())));
    }

    #[test]
    fn should_compact_fires_on_the_64th_pass_when_idle_and_flips_the_flag() {
        let compacting = AtomicBool::new(false);
        // Not the 64th pass: never fires, and the flag is left alone.
        for passes in [1, 63, 65, 128 - 1] {
            assert!(!should_compact(passes, &compacting));
            assert!(!compacting.load(Ordering::SeqCst));
        }
        // The 64th pass, idle: fires, and flips the flag to busy.
        assert!(should_compact(64, &compacting));
        assert!(compacting.load(Ordering::SeqCst));
        // The 128th pass, still busy from the previous one: does not fire, flag unchanged.
        assert!(!should_compact(128, &compacting));
        assert!(compacting.load(Ordering::SeqCst));
        // Once the background task clears it, the next 64th pass fires again.
        compacting.store(false, Ordering::SeqCst);
        assert!(should_compact(192, &compacting));
    }

    /// PR-2: the cutoff is measured from the earlier of the head's timestamp and this node's
    /// clock. A run of faulty leaders can ratchet block timestamps forward (up to
    /// `MAX_TIMESTAMP_STEP_MS` a block); measured from the head alone, a day of retention would
    /// then delete blocks that are, by the wall clock, minutes old.
    #[test]
    fn the_prune_cutoff_never_runs_ahead_of_the_local_clock() {
        let day = Duration::from_secs(86_400);
        let day_ms = 86_400_000u64;
        let now = 10 * day_ms;
        // An honest head, a little behind the clock: measured from the head.
        assert_eq!(prune_cutoff_ms(now - 1_500, now, day), now - 1_500 - day_ms);
        // A head ratcheted a whole day ahead of the clock: measured from the clock instead.
        assert_eq!(prune_cutoff_ms(now + day_ms, now, day), now - day_ms);
        // Early in a chain's life nothing is old enough: saturates at zero.
        assert_eq!(prune_cutoff_ms(1_000, now, day), 0);
        assert_eq!(prune_cutoff_ms(u64::MAX, 1_000, day), 0);
    }

    /// PR-3: a compaction that panics still clears the busy flag. Before, the flag was cleared
    /// by the statement after the compaction, which a panic skips — and `should_compact` then
    /// refused every later compaction until a restart, so pruned space never came back.
    #[test]
    fn a_panicking_compaction_still_clears_the_busy_flag() {
        let compacting = Arc::new(AtomicBool::new(false));
        assert!(should_compact(64, &compacting));
        let flag = compacting.clone();
        let joined = std::thread::spawn(move || run_compaction(&flag, || panic!("compaction blew up"))).join();
        assert!(joined.is_err(), "the compaction was meant to panic");
        assert!(!compacting.load(Ordering::SeqCst), "a panicked compaction left the flag set");
        assert!(should_compact(128, &compacting));
    }

    #[test]
    fn a_window_shorter_than_the_aggregation_window_refuses_to_start() {
        // 256-block window at 1 s blocks is 256 s; a 100 s history cannot hold it.
        let err = prune_window_check(Some(Duration::from_secs(100)), Some(256), Duration::from_secs(1)).unwrap_err();
        assert!(err.contains("shorter than the aggregation window"), "{err}");
        assert!(prune_window_check(Some(Duration::from_secs(300)), Some(256), Duration::from_secs(1)).is_ok());
        assert!(prune_window_check(None, Some(256), Duration::from_secs(1)).is_ok());
        assert!(prune_window_check(Some(Duration::from_secs(10)), None, Duration::from_secs(1)).is_ok());
        assert!(prune_window_check(Some(Duration::from_secs(256)), Some(256), Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn a_pruned_store_missing_its_floor_block_is_fatal_not_truncated() {
        let (_dir, st, gs, _blocks) = crate::storage::fixtures::timed_chain(12);
        st.prune_history(u64::MAX, 10, crate::storage::PRUNE_PASS_MAX).unwrap();
        st.db_for_test().delete_cf(st.cf_for_test("blocks"), crate::storage::height_key_for_test(10)).unwrap();
        let err = check_and_repair_chain(&st, &gs, VerifyMode::Quick, &StubExecutor).unwrap_err().to_string();
        assert!(err.contains("re-sync from the archive"), "{err}");
        assert_eq!(st.head().unwrap().height, 12, "nothing was truncated");
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
            Vec::new(),
            EpochSets::new(gs.validators.clone()),
            executor,
        );
        assert_eq!(blind.on_proposal(proposal, 3), Err(ConsensusError::UnknownEpochSet(1)));
    }

    /// Audit v6, CON-5 and CON-4 (D23), the operator's side. A node that stopped on conflicting
    /// finality wrote nothing down and the unit restarted it; now the halt is on disk and the
    /// start refuses until it is cleared. And the lock, which no quorum of words releases any
    /// more, is lowered offline — to the head's certificate, keeping the view and the votes.
    #[test]
    fn a_recorded_safety_halt_refuses_the_start_and_the_lock_is_released_only_offline() {
        let (_d, storage, gs, ledger) = chain_past_a_boundary();
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        assert!(refuse_a_halted_store(&storage).is_ok(), "no halt, no refusal");
        let halt = crate::storage::SafetyHalt { committed: Hash([1; 32]), attempted: Hash([2; 32]), height: 9, at_ms: 5 };
        storage.save_safety_halt(&halt).unwrap();
        let refused = refuse_a_halted_store(&storage).unwrap_err().to_string();
        assert!(refused.contains("conflicting finality") && refused.contains("safety clear-halt"), "{refused}");
        assert_eq!(storage.clear_safety_halt().unwrap(), Some(halt));
        assert!(refuse_a_halted_store(&storage).is_ok(), "cleared by the operator");

        // A lock above the head whose block this store does not hold.
        let head = storage.head_block().unwrap();
        let head_qc = storage.head_qc().unwrap();
        let lost = next_block(&head, &ledger, &key(1));
        let qc = QuorumCertificate {
            view: lost.view(),
            block_hash: lost.hash(),
            votes: vec![Vote::sign(&randprotocol_core::consensus::SigningDomain::v0(Hash::ZERO), lost.view(), lost.hash(), &key(1))],
        };
        assert_eq!(storage.release_lock().unwrap(), None, "no safety state, nothing to release");
        let voted = vec![(lost.view(), lost.hash())];
        storage
            .save_safety(&randprotocol_core::consensus::SafetyState {
                view: lost.view() + 3,
                high_qc: head_qc.clone(),
                locked_qc: qc.clone(),
                last_voted_view: lost.view(),
                voted: voted.clone(),
                last_proposed_view: 0,
            })
            .unwrap();
        let resume = || {
            resume_consensus(&storage, &gs, Some(key(1)), Duration::from_secs(1), Duration::from_secs(8), executor.clone()).unwrap()
        };
        let hs = resume();
        assert_eq!(hs.locked_qc(), &qc, "the lock is restored as it was persisted");
        assert_eq!(hs.not_held(&lost.hash()), None, "and no not-held is signed for the block it names");
        assert_eq!(storage.release_lock().unwrap(), Some(qc), "the override returns what it gave up");
        let after = storage.load_safety().unwrap().unwrap();
        assert_eq!(after.locked_qc, head_qc, "lowered to the head's certificate");
        assert_eq!((after.view, after.last_voted_view, after.voted), (lost.view() + 3, lost.view(), voted), "the view and the votes stay");
        assert_eq!(storage.release_lock().unwrap(), None, "a second release finds nothing above the head");
        let hs = resume();
        assert_eq!(hs.locked_qc().view, hs.committed_qc_view());
        assert_eq!(hs.not_held(&lost.hash()), None, "a released lock does not un-cast the vote");
    }

    /// Audit v6, OPS-5 (the integrity half). A pruned validator verifies its retained blocks
    /// structurally and then loads the stored ledger snapshot without comparing it with anything
    /// ("ledger snapshot trusted"), and `--verify-chain off` loads it on any node; a damaged or
    /// altered snapshot was resumed on, voted with and attested from. The reloaded ledger's state
    /// root is now compared with the head block's before a replica is built on it.
    #[test]
    fn a_ledger_snapshot_that_is_not_the_head_blocks_state_is_refused_at_resume() {
        let (_d, storage, gs, ledger) = chain_past_a_boundary();
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let resume = || resume_consensus(&storage, &gs, Some(key(1)), Duration::from_secs(1), Duration::from_secs(8), executor.clone());
        let hs = resume().expect("the honest store resumes");
        assert_eq!(hs.committed_ledger().state_root(), storage.head_block().unwrap().header.state_root);
        assert_eq!(ledger.state_root(), storage.head_block().unwrap().header.state_root);
        // One nullifier no block spent: every later double-spend check would read it.
        storage.plant_nullifier_for_testing(&[0xdead_beef; 8]).unwrap();
        let err = resume().err().expect("the altered snapshot is refused").to_string();
        assert!(err.contains("ledger snapshot") && err.contains("state root") && err.contains("re-sync"), "{err}");
    }

    /// The upgrade from v0.5.4 (audit v5, CON-4): a database holding the locked block under the
    /// old key and no pending set resumes with that block in the tree exactly as v0.5.4 did —
    /// once. The first startup folds it into the pending set and retires the old key, and the
    /// next startup reads the pending set alone.
    #[test]
    fn a_v054_locked_block_is_read_once_then_superseded_by_the_pending_set() {
        let (_d, storage, gs, ledger) = chain_past_a_boundary();
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let head = storage.head_block().unwrap();
        let locked = next_block(&head, &ledger, &key(1));
        let qc = QuorumCertificate {
            view: locked.view(),
            block_hash: locked.hash(),
            votes: vec![Vote::sign(&randprotocol_core::consensus::SigningDomain::v0(Hash::ZERO), locked.view(), locked.hash(), &key(1))],
        };
        // What v0.5.4 left behind: a lock above the head, the locked block under the old key,
        // and no pending set.
        storage
            .save_safety(&randprotocol_core::consensus::SafetyState {
                view: locked.view() + 1,
                high_qc: qc.clone(),
                locked_qc: qc.clone(),
                last_voted_view: locked.view(),
                voted: Vec::new(),
                last_proposed_view: 0,
            })
            .unwrap();
        storage.put_locked_block_v054_for_testing(&locked).unwrap();
        assert!(storage.pending_blocks().unwrap().is_empty());

        let resume = || {
            resume_consensus(&storage, &gs, Some(key(1)), Duration::from_secs(1), Duration::from_secs(8), executor.clone()).unwrap()
        };
        let hs = resume();
        assert!(hs.has_block(&locked.hash()), "the v0.5.4 locked block is back in the tree");
        assert_eq!(hs.high_qc(), &qc);
        assert_eq!(hs.locked_qc(), &qc);
        assert_eq!(storage.pending_blocks().unwrap(), vec![locked.clone()], "folded into the pending set");
        assert_eq!(storage.locked_block().unwrap(), None, "and the old key is retired");

        let again = resume();
        assert!(again.has_block(&locked.hash()), "the second startup reads the pending set alone");
        assert_eq!(storage.pending_blocks().unwrap(), vec![locked.clone()]);
    }

    /// A by-hash fetch for a block this node does not hold (audit v4, CON-4): a validator answers
    /// with a signed not-held over the genesis hash and the block hash, so the asker can count its
    /// stake toward releasing a lock; an observer, whose word carries no stake, answers
    /// `Block(None)` as before. A block it holds is served as before.
    #[test]
    fn a_validator_answers_an_unknown_hash_with_a_signed_not_held_and_an_observer_does_not() {
        let (_d, storage, gs, _ledger) = chain_past_a_boundary();
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let resume = |signer: Option<Keypair>| {
            resume_consensus(&storage, &gs, signer, Duration::from_secs(1), Duration::from_secs(8), executor.clone()).unwrap()
        };
        let validator = resume(Some(key(1)));
        let mut signed = NotHeldCache::default();
        let unknown = Hash::digest(b"nobody has this");
        match block_by_hash_response(&validator, &storage, &unknown, &mut signed) {
            SyncResponse::NotHeld(n) => {
                assert_eq!(n.hash, unknown);
                assert_eq!(n.signer, *key(1).public_key());
                assert!(n.verify(&gs.hash()));
                assert!(!n.verify(&Hash::ZERO), "bound to this chain");
            }
            other => panic!("a validator answers a signed not-held: {other:?}"),
        }
        let head = storage.head_block().unwrap();
        assert!(matches!(
            block_by_hash_response(&validator, &storage, &head.hash(), &mut signed),
            SyncResponse::Block(Some(b)) if b.hash() == head.hash()
        ));
        let observer = resume(None);
        assert!(matches!(block_by_hash_response(&observer, &storage, &unknown, &mut NotHeldCache::default()), SyncResponse::Block(None)));
    }

    /// SW-2 (network scan 2026-09-26, medium), the signing half: a by-hash request for a block
    /// this validator does not hold made it sign a fresh Dilithium2 not-held every time, so one
    /// peer repeating one ~40-byte request bought a signature per message. The signed answer is
    /// now kept per hash (FIFO, [`NOT_HELD_CACHE`] hashes) and re-served; an observer's `None` is
    /// nothing to keep.
    #[test]
    fn a_repeated_not_held_is_served_from_the_cache_not_re_signed() {
        let (_d, storage, gs, _ledger) = chain_past_a_boundary();
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let validator =
            resume_consensus(&storage, &gs, Some(key(1)), Duration::from_secs(1), Duration::from_secs(8), executor).unwrap();
        let unknown = Hash::digest(b"nobody has this");
        let mut cache = NotHeldCache::default();
        let mut signs = 0;
        let view = validator.view();
        let first = cache.get_or_sign(&unknown, view, || {
            signs += 1;
            validator.not_held(&unknown)
        });
        let again = cache.get_or_sign(&unknown, view, || {
            signs += 1;
            validator.not_held(&unknown)
        });
        assert_eq!(signs, 1, "the repeat is served from the cache");
        assert!(first.is_some() && first == again);
        // Wired into the by-hash answer: a repeat does not grow the cache or re-sign.
        let mut signed = NotHeldCache::default();
        let a = block_by_hash_response(&validator, &storage, &unknown, &mut signed);
        let b = block_by_hash_response(&validator, &storage, &unknown, &mut signed);
        assert_eq!(signed.len(), 1);
        match (a, b) {
            (SyncResponse::NotHeld(a), SyncResponse::NotHeld(b)) => assert_eq!(a, b, "the same signed answer, not a second signature"),
            other => panic!("{other:?}"),
        }
        // An observer's `None` is not kept.
        let mut none = NotHeldCache::default();
        assert_eq!(none.get_or_sign(&unknown, view, || None), None);
        assert_eq!(none.len(), 0);
        // Bounded, oldest first.
        let mut bounded = NotHeldCache::default();
        for i in 0..NOT_HELD_CACHE as u64 + 10 {
            let h = Hash::digest(&i.to_le_bytes());
            bounded.get_or_sign(&h, view, || validator.not_held(&h));
        }
        assert_eq!(bounded.len(), NOT_HELD_CACHE);
        let oldest = Hash::digest(&0u64.to_le_bytes());
        let mut resigned = false;
        bounded.get_or_sign(&oldest, view, || {
            resigned = true;
            validator.not_held(&oldest)
        });
        assert!(resigned, "the oldest entry was evicted");
    }

    /// CN-3 (scan 2026-09-27, medium), the serving half: a not-held now carries the signer's
    /// view, and an asker counts only a recent one that postdates its lock. A kept answer from an
    /// earlier view is therefore not re-served as the current word: once the view moves the next
    /// request is signed afresh at the new view, replacing the kept one (the cache does not grow),
    /// and repeats within that view are served from the cache again.
    #[test]
    fn a_kept_not_held_is_re_signed_once_the_view_moves() {
        let (_d, storage, gs, _ledger) = chain_past_a_boundary();
        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let mut validator =
            resume_consensus(&storage, &gs, Some(key(1)), Duration::from_secs(1), Duration::from_secs(8), executor).unwrap();
        let unknown = Hash::digest(b"nobody has this");
        let mut signed = NotHeldCache::default();
        let at = |r: SyncResponse| match r {
            SyncResponse::NotHeld(n) => n,
            other => panic!("a validator answers a signed not-held: {other:?}"),
        };
        let v0 = validator.view();
        let first = at(block_by_hash_response(&validator, &storage, &unknown, &mut signed));
        assert_eq!(first.view, v0, "signed at the validator's own view");
        assert!(first.verify(&gs.hash()));
        validator.on_timeout(v0);
        assert!(validator.view() > v0);
        let moved = at(block_by_hash_response(&validator, &storage, &unknown, &mut signed));
        assert_eq!(moved.view, validator.view(), "the stale word is not served once the view moved");
        assert!(moved.verify(&gs.hash()));
        assert_eq!(signed.len(), 1, "replaced in place");
        let again = at(block_by_hash_response(&validator, &storage, &unknown, &mut signed));
        assert_eq!(again, moved, "within one view the kept answer is served");
    }

    /// SW-2, the metering half: a ~30-byte `Blocks` request makes this node read and assemble up
    /// to a ~6 MiB batch on the consensus loop, and nothing limited how often one peer could ask.
    /// Inbound sync requests are metered per requesting peer (the connection's own identity):
    /// [`SYNC_REQUEST_BURST`] back to back, [`SYNC_REQUEST_PER_SEC`] after; over it the answer is
    /// the protocol's own "nothing" — an empty batch or `Block(None)`, which an honest syncer
    /// already treats as "ask someone else" (SYNC-2's back-off) — so no request goes unanswered.
    #[test]
    fn inbound_sync_requests_are_metered_per_peer_and_answered_busy_over_the_limit() {
        use crate::admission::PeerLimiter;
        let pid = |seed: u8| PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public());
        let limiter = PeerLimiter::new(SYNC_REQUEST_BURST, SYNC_REQUEST_PER_SEC);
        let (p1, p2) = (pid(1), pid(2));
        let mut peers: HashMap<PeerId, Peer> = HashMap::new();
        let (mut memory, mut global) = (PeerMemory::default(), SyncServeBudget::new());
        let req = SyncRequest::Blocks { from_height: 1, max: 100 };
        let mut admit_sync_request = |peers: &mut HashMap<PeerId, Peer>, limiter: &PeerLimiter, p: PeerId, t: Instant| {
            admit_sync_request(peers, &mut memory, limiter, &mut global, p, false, &req, t).serve()
        };
        let now = Instant::now();
        for i in 0..SYNC_REQUEST_BURST {
            assert!(admit_sync_request(&mut peers, &limiter, p1, now), "request {i} of the burst");
        }
        assert!(!admit_sync_request(&mut peers, &limiter, p1, now), "over the burst");
        assert!(admit_sync_request(&mut peers, &limiter, p2, now), "p2's bucket is its own");
        let later = now + Duration::from_secs(1);
        for i in 0..SYNC_REQUEST_PER_SEC as u32 {
            assert!(admit_sync_request(&mut peers, &limiter, p1, later), "refilled {i}");
        }
        assert!(!admit_sync_request(&mut peers, &limiter, p1, later));
        // A batch over the asker's own limit is answered `Busy`, never an empty batch (audit v6,
        // PROC-8): an empty batch is a miss, and the asker backed off a peer that had done nothing
        // wrong — for 5 s, then 10, 20 — after its own by-hash fetches at startup spent the bucket.
        assert!(
            matches!(refused_sync_response(&SyncRequest::Blocks { from_height: 1, max: 100 }), SyncResponse::Busy),
            "a batch over the peer's own limit must be answered busy, not empty"
        );
        assert!(matches!(refused_sync_response(&SyncRequest::BlockByHash(Hash::ZERO)), SyncResponse::Block(None)));
    }

    /// CN-2, the reconnect half: every per-peer meter lived on the `Peer` entry and
    /// `PeerDisconnected` removed it, so a reconnect bought a fresh burst of each — one peer id,
    /// ten reconnects, eighty sync requests served — and wiped the CN-1 back-off a sybil had
    /// earned. A peer that leaves is remembered (bounded, [`PEER_MEMORY_ENTRIES`]) and a reconnect
    /// restores its buckets and its back-off; one that leaves while holding our live batch
    /// request has missed it, exactly as a silent one has (CN-1).
    #[test]
    fn a_reconnect_restores_the_peers_meters_and_back_off_instead_of_resetting_them() {
        use crate::admission::PeerLimiter;
        let pid = |seed: u16| {
            let mut s = [7u8; 32];
            s[..2].copy_from_slice(&seed.to_le_bytes());
            PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes(s).unwrap().public())
        };
        const CAP: usize = 256;
        let limiter = PeerLimiter::new(SYNC_REQUEST_BURST, SYNC_REQUEST_PER_SEC);
        let consensus = PeerLimiter::new(CONSENSUS_GOSSIP_BURST, CONSENSUS_GOSSIP_PER_SEC);
        let req = SyncRequest::Blocks { from_height: 1, max: 100 };
        let (mut peers, mut memory) = (HashMap::<PeerId, Peer>::new(), PeerMemory::default());
        let now = Instant::now();
        let p = pid(1);
        // Ten reconnects in the same instant: only the first burst is served.
        let mut served = 0;
        for _ in 0..10 {
            connect_peer(&mut peers, &mut memory, p, CAP);
            for _ in 0..SYNC_REQUEST_BURST {
                // A fresh global budget per request: this test is about the peer's own bucket.
                served += admit_sync_request(&mut peers, &mut memory, &limiter, &mut SyncServeBudget::new(), p, false, &req, now).serve() as u32;
            }
            for _ in 0..CONSENSUS_GOSSIP_BURST {
                on_consensus_gossip(&mut peers, &consensus, p, now);
            }
            disconnect_peer(&mut peers, &mut memory, p, false, now);
        }
        assert_eq!(served, SYNC_REQUEST_BURST, "ten reconnects must not buy ten bursts");
        connect_peer(&mut peers, &mut memory, p, CAP);
        assert_eq!(
            on_consensus_gossip(&mut peers, &consensus, p, now),
            GossipOutcome::Report(admission::Acceptance::Ignore),
            "the consensus bucket survives a reconnect"
        );
        // The CN-1 back-off survives one too, and leaving with our batch in hand is a miss.
        on_sync_batch_failed(&mut peers, p, now);
        disconnect_peer(&mut peers, &mut memory, p, true, now);
        connect_peer(&mut peers, &mut memory, p, CAP);
        assert_eq!(peers[&p].sync_backoff, SYNC_BACKOFF_BASE * 2, "two misses: the failed batch and the walk-out");
        assert!(peers[&p].sync_backoff_until.is_some_and(|u| u > now));
        // A peer rejected mid-connection (its entry dropped for a bad batch) is restored too.
        disconnect_peer(&mut peers, &mut memory, p, false, now);
        assert_eq!(admit_sync_request(&mut peers, &mut memory, &limiter, &mut SyncServeBudget::new(), p, false, &req, now), SyncAdmission::OverPeerLimit);
        // Bounded: the oldest record goes first, and a restored record leaves the memory.
        let mut memory = PeerMemory::default();
        let mut peers = HashMap::new();
        for i in 0..=PEER_MEMORY_ENTRIES as u16 {
            connect_peer(&mut peers, &mut memory, pid(1000 + i), CAP);
            disconnect_peer(&mut peers, &mut memory, pid(1000 + i), false, now);
        }
        assert_eq!(memory.len(), PEER_MEMORY_ENTRIES);
        assert!(!memory.by_id.contains_key(&pid(1000)), "the oldest record was evicted");
        connect_peer(&mut peers, &mut memory, pid(1001), CAP);
        assert_eq!(memory.len(), PEER_MEMORY_ENTRIES - 1, "a reconnected peer's record moves back to its entry");
        assert_eq!(memory.order.len(), memory.by_id.len());
    }

    /// CN-2, the global half: the per-peer bucket bounds one connection, not the node — 256
    /// inbound ids at 2 a second each was ~512 batch requests a second, each up to a ~6 MiB read.
    /// Many ids each inside their own budget are held to the node-wide one; a by-hash request is
    /// one block and stays outside it (see [`SyncServeBudget`]).
    #[test]
    fn many_peers_each_within_their_budget_are_held_to_the_global_sync_budget() {
        use crate::admission::PeerLimiter;
        let pid = |seed: u16| {
            let mut s = [9u8; 32];
            s[..2].copy_from_slice(&seed.to_le_bytes());
            PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes(s).unwrap().public())
        };
        let limiter = PeerLimiter::new(SYNC_REQUEST_BURST, SYNC_REQUEST_PER_SEC);
        let blocks = SyncRequest::Blocks { from_height: 1, max: 100 };
        let (mut peers, mut memory, mut global) = (HashMap::new(), PeerMemory::default(), SyncServeBudget::new());
        let now = Instant::now();
        let ids: Vec<PeerId> = (0..64).map(pid).collect();
        let mut admit = |t: Instant, req: &SyncRequest| {
            ids.iter().map(|p| admit_sync_request(&mut peers, &mut memory, &limiter, &mut global, *p, false, req, t).serve() as u32).sum::<u32>()
        };
        // Two requests from each of 64 ids — a quarter of each one's own burst.
        let served = admit(now, &blocks) + admit(now, &blocks);
        assert_eq!(served, SYNC_SERVE_BURST, "128 requests, each within its peer's budget, against a node-wide burst");
        let later = now + Duration::from_secs(1);
        assert_eq!(admit(later, &blocks), SYNC_SERVE_PER_SEC as u32, "and the node-wide rate after it");
        // By-hash requests are not charged to it: each id still has its own tokens for them.
        assert_eq!(admit(later, &SyncRequest::BlockByHash(Hash::ZERO)), 64);
    }

    /// Audit v6, SYNC-3: eight stranger identities at their own full rate spend the node-wide
    /// budget — before, a lagging validator's batch request then got an empty answer and backed
    /// this node off. A validator peer draws on a share of its own first, so it is still served;
    /// and when that share is spent too it falls back to the general one, never below a
    /// stranger. A budget refusal is `NodeBusy` (answered `Busy`), an own-bucket one
    /// `OverPeerLimit` (answered `Busy` to a batch too since PROC-8, but still bounded by the bucket).
    #[test]
    fn stranger_identities_spending_the_sync_budget_cannot_starve_a_validator_peer() {
        use crate::admission::PeerLimiter;
        let pid = |seed: u8| PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public());
        let limiter = PeerLimiter::new(SYNC_REQUEST_BURST, SYNC_REQUEST_PER_SEC);
        let blocks = SyncRequest::Blocks { from_height: 1, max: 100 };
        let (mut peers, mut memory, mut global) = (HashMap::new(), PeerMemory::default(), SyncServeBudget::new());
        let now = Instant::now();
        let strangers: Vec<PeerId> = (1..=8).map(pid).collect();
        let validator = pid(99);
        let mut busy = 0;
        for _ in 0..SYNC_REQUEST_BURST {
            for s in &strangers {
                if admit_sync_request(&mut peers, &mut memory, &limiter, &mut global, *s, false, &blocks, now) == SyncAdmission::NodeBusy {
                    busy += 1;
                }
            }
        }
        assert_eq!(busy, 8 * SYNC_REQUEST_BURST - SYNC_SERVE_BURST, "the strangers spent the general share, and heard busy past it");
        assert_eq!(
            admit_sync_request(&mut peers, &mut memory, &limiter, &mut global, pid(50), false, &blocks, now),
            SyncAdmission::NodeBusy,
            "a ninth stranger too"
        );
        for i in 0..SYNC_REQUEST_BURST {
            assert_eq!(
                admit_sync_request(&mut peers, &mut memory, &limiter, &mut global, validator, true, &blocks, now),
                SyncAdmission::Serve,
                "the validator's batch request {i} is served from its own share"
            );
        }
        // Its own bucket still binds it.
        assert_eq!(admit_sync_request(&mut peers, &mut memory, &limiter, &mut global, validator, true, &blocks, now), SyncAdmission::OverPeerLimit);

        // With the validators' share spent, a validator falls back to the general one.
        let mut global = SyncServeBudget::new();
        for _ in 0..SYNC_SERVE_BURST {
            assert!(global.allow(true, now));
        }
        assert!(global.allow(true, now), "the general share is still there for a validator");
        assert!(global.allow(false, now), "and for a stranger: the validators' share took nothing from it");
    }

    /// Audit v6, SYNC-3, the asker's side: a `Busy` answer to our batch is no miss — the peer's
    /// back-off and rank do not move — and the next request goes to another peer; the busy one
    /// is asked again once [`SYNC_BUSY_PAUSE`] passes, still ahead of a peer that missed.
    #[test]
    fn a_busy_answer_does_not_back_the_peer_off_and_the_next_request_goes_elsewhere() {
        let pid = |seed: u8| PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public());
        let at = |h: u64| Peer { status: Some(Status { height: h, head_hash: Hash::ZERO, view: h, floor: 0 }), connected: true, ..Default::default() };
        let (busy, other) = (pid(1), pid(2));
        let mut peers: HashMap<PeerId, Peer> = [(busy, at(1_000)), (other, at(900))].into_iter().collect();
        let t0 = Instant::now();
        assert_eq!(pick_sync_peer(&peers, 43, 1_000, &[], t0), Some(busy));
        on_sync_busy(&mut peers, busy, t0);
        assert_eq!(peers[&busy].sync_backoff, Duration::ZERO, "no miss recorded");
        assert_eq!(peers[&busy].sync_backoff_until, None, "not backed off");
        assert_eq!(pick_sync_peer(&peers, 43, 1_000, &[], t0), Some(other), "the next request goes to another peer");
        assert_eq!(pick_sync_peer(&peers, 43, 1_000, &[other], t0), None, "the busy one sits out the pause");
        assert_eq!(pick_sync_peer(&peers, 43, 1_000, &[], t0 + SYNC_BUSY_PAUSE), Some(busy), "and is first again after it");
        // A peer that missed ranks behind it: busy is not a miss.
        back_off_sync_peer(peers.get_mut(&other).unwrap(), t0);
        assert_eq!(pick_sync_peer(&peers, 43, 1_000, &[], t0 + SYNC_BACKOFF_BASE + SYNC_BUSY_PAUSE), Some(busy));
    }

    /// CN-2, the off-loop half: a `Blocks` answer is read and assembled on a blocking worker, not
    /// on the loop that handles votes and proposals, under [`MAX_SYNC_SERVES_IN_FLIGHT`] slots —
    /// with every slot taken the request is refused (the caller answers it `Busy`) and no read
    /// starts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_is_served_off_the_loop_under_a_bounded_number_of_slots() {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_SYNC_SERVES_IN_FLIGHT));
        let loop_thread = std::thread::current().id();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (ran_tx, ran_rx) = std::sync::mpsc::channel();
        let (reply_tx, mut reply_rx) = mpsc::channel(1);
        let spawned = spawn_sync_serve(
            &slots,
            move || {
                ran_tx.send(std::thread::current().id()).unwrap();
                // Holds its worker until the test lets go — inline, this would wait out the timeout.
                let _ = release_rx.recv_timeout(Duration::from_secs(5));
                SyncResponse::Blocks(vec![])
            },
            move |r| async move {
                reply_tx.send(r).await.unwrap();
            },
        );
        assert!(spawned.is_ok());
        let ran_on = ran_rx.recv_timeout(Duration::from_secs(5)).expect("the serve ran");
        assert_ne!(ran_on, loop_thread, "the read ran on the calling thread");
        assert!(reply_rx.try_recv().is_err(), "the caller got control back before the answer was ready");
        release_tx.send(()).unwrap();
        let r = tokio::time::timeout(Duration::from_secs(5), reply_rx.recv()).await.unwrap().unwrap();
        assert!(matches!(r, SyncResponse::Blocks(b) if b.is_empty()));
        // Saturated: every slot held, the next serve is refused and its read never starts.
        let _held = slots.clone().acquire_many_owned(MAX_SYNC_SERVES_IN_FLIGHT as u32).await.unwrap();
        let ran = Arc::new(AtomicBool::new(false));
        let r2 = ran.clone();
        let spawned = spawn_sync_serve(&slots, move || { r2.store(true, SeqCst); SyncResponse::Blocks(vec![]) }, |_| async {});
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(spawned.is_err(), "a serve past the slots is refused, its reply handed back");
        assert!(!ran.load(SeqCst), "and reads nothing");
    }

    /// The startup check (H3): a genesis whose `hc_bundle` is not this build's guest is refused,
    /// and so is any genesis with an `aggregation` section — aggregation's shapes were measured
    /// for the retired bundle guest and are gated off until re-measured. A genesis without the
    /// section and with this build's guest starts.
    #[test]
    fn startup_refuses_another_guest_and_an_aggregation_section() {
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        let hc = gs.hc_bundle;
        assert!(check_build_runs_genesis(&gs, &[hc]).is_ok());
        let other = check_build_runs_genesis(&gs, &[[0xdead; 8]]).unwrap_err().to_string();
        assert!(other.contains("differs from the genesis hc_bundle"), "{other}");
        // The build's guests (v1, the branch-free v2 of INT-2 / GV-1, and v3's split
        // authorisation): a genesis naming any of them starts; one naming none — the retired
        // 2-in-2-out guest, say — does not.
        for named in ZkExecutor::known_hc_bundles() {
            gs.hc_bundle = named;
            // v3 comes with its auth guest (`startup_pairs_bundle_guest_v3_with_hc_auth`).
            gs.ledger.set_hc_auth((named == ZkExecutor::hc_hidden_bundle_v3()).then(ZkExecutor::hc_auth));
            assert!(check_build_runs_genesis(&gs, &ZkExecutor::known_hc_bundles()).is_ok());
        }
        gs.ledger.set_hc_auth(None);
        gs.hc_bundle = ZkExecutor::hc_legacy_bundle();
        let retired = check_build_runs_genesis(&gs, &ZkExecutor::known_hc_bundles()).unwrap_err().to_string();
        assert!(retired.contains("differs from the genesis hc_bundle"), "{retired}");
        gs.hc_bundle = hc;
        gs.ledger.set_aggregation(Some(randprotocol_core::ledger::aggregation::AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![],
        }));
        let gated = check_build_runs_genesis(&gs, &[hc]).unwrap_err().to_string();
        assert!(gated.contains("block aggregation") && gated.contains("re-measured"), "{gated}");
        // And the second reason (the 2026-09-27 recursion-VM report, recommendation 5).
        assert!(gated.contains("RVM-1") && gated.contains("forged-aggregate exercise"), "{gated}");
    }

    /// Split authorisation: genesis `hc_auth` and bundle guest v3 come as a pair, and `hc_auth`
    /// must be this build's auth guest. v3 without `hc_auth` would recompute the v1 digest and
    /// admit nothing; `hc_auth` with a v1/v2 guest likewise (neither publishes the v3 digest); an
    /// unknown `hc_auth` is a guest no wallet of this build can prove.
    #[test]
    fn startup_pairs_bundle_guest_v3_with_hc_auth() {
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        let known = ZkExecutor::known_hc_bundles();
        gs.hc_bundle = ZkExecutor::hc_hidden_bundle_v3();
        gs.ledger.set_hc_auth(Some(ZkExecutor::hc_auth()));
        assert!(check_build_runs_genesis(&gs, &known).is_ok(), "v3 with this build's auth guest starts");
        gs.ledger.set_hc_auth(None);
        let bare = check_build_runs_genesis(&gs, &known).unwrap_err().to_string();
        assert!(bare.contains("v3 needs hc_auth"), "{bare}");
        gs.ledger.set_hc_auth(Some([0xdead; 8]));
        let unknown = check_build_runs_genesis(&gs, &known).unwrap_err().to_string();
        assert!(unknown.contains("not this build's auth guest"), "{unknown}");
        for old in [ZkExecutor::hc_hidden_bundle(), ZkExecutor::hc_hidden_bundle_v2()] {
            gs.hc_bundle = old;
            gs.ledger.set_hc_auth(Some(ZkExecutor::hc_auth()));
            let paired = check_build_runs_genesis(&gs, &known).unwrap_err().to_string();
            assert!(paired.contains("is not bundle guest v3"), "{paired}");
            gs.ledger.set_hc_auth(None);
            assert!(check_build_runs_genesis(&gs, &known).is_ok(), "v1/v2 without hc_auth: today's chains");
        }
    }

    /// The startup guard is independent of genesis validation (the 2026-09-28 interface fixes):
    /// a section `Genesis::validate` now accepts — its one admitted shape the pinned bundle header
    /// (IFACE-9), buildable by the rVM — still does not start. Every aggregation fix since rides
    /// node-only because of this refusal; it lifts only with the re-measurement it names. The
    /// message is not asserted here (it is the startup test's).
    #[test]
    fn startup_still_refuses_an_aggregation_section_that_validates() {
        use randprotocol_core::confidential::ConfidentialExecutor as _;
        use randprotocol_core::genesis::Genesis;
        let hc = ZkExecutor::hc_bundle();
        let shape = randprotocol_core::types::DeclaredShape {
            profile: randprotocol_core::types::FriProfile::Test,
            tier: randprotocol_core::types::BUNDLE_PROOF_TIER,
            program_log_height: 12,
            input_log_height: 10,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: randprotocol_core::types::BUNDLE_PUBLIC_LOG_HEIGHT,
            mem_log_height: 16,
        };
        crate::agg_executor::check_admitted_shape(&shape).expect("the rVM builds the pinned header");
        let mut file: Genesis = crate::storage::fixtures::genesis_file_of(7, &[&key(1)], vec![], 2);
        file.fri_profile = "test".into();
        file.hc_bundle = randprotocol_core::notes::word8_to_hex(&hc);
        file.aggregation = Some(randprotocol_core::ledger::aggregation::AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![randprotocol_core::ledger::aggregation::AdmittedShape {
                shape,
                hc: Hash(randprotocol_core::notes::word8_to_bytes(&hc)),
                aggregate_program_digest: StubExecutor.aggregate_program_digest(&shape).unwrap(),
            }],
        });
        let gs = file.build(&StubExecutor).expect("the section validates");
        assert!(gs.ledger.aggregation().is_some());
        assert!(check_build_runs_genesis(&gs, &[hc]).is_err(), "a validating aggregation genesis still does not start");
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

    /// The staking gate (audit v4, STAKE-2) survives a restart the same way: it lives in the
    /// genesis file, `load_ledger` comes back without it, and a node that kept running without
    /// it would compute `rand-state-2` roots against peers on `rand-state-5`, refuse nothing the
    /// budget refuses and seat bonds an epoch early — a fork at its first restart.
    #[test]
    fn a_restart_restores_the_staking_gate() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut g = crate::storage::fixtures::genesis_file_of(7, &[&key(1)], vec![], 2);
        let cfg = randprotocol_core::genesis::StakingConfig {
            faucet_budget_per_epoch: 100 * randprotocol_core::UNITS_PER_RAND,
            bond_activation_epochs: 2,
            ..Default::default()
        };
        g.staking = Some(cfg.clone());
        let gs = g.build(&StubExecutor).unwrap();
        storage.init_genesis(&gs).unwrap();
        assert!(storage.load_ledger(&StubExecutor).unwrap().staking().is_none(), "storage does not hold the gate");
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.staking(), Some(&cfg));
        assert_eq!(reloaded.state_root(), gs.ledger.state_root(), "the reloaded ledger hashes the gated state-5 root");
        assert_eq!(reloaded, gs.ledger);
    }

    /// Audit v6, STAKE-2: the admitted set survives a restart — it is state, so storage holds
    /// it — and so does the flag that gives it meaning, which lives in the genesis file's
    /// `staking` section. A node that came back without either would compute another state root
    /// than its peers (the `rand-state-admitted-1` wrapper) and judge the admitted key's
    /// registration differently: a fork at its first restart.
    #[test]
    fn a_restart_restores_the_admitted_set() {
        use crate::storage::fixtures::{admission_genesis, admit_tx, make_block};
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let (a, b, c, d) = (key(1), key(2), key(3), key(4));
        let gs = admission_genesis(&[&a, &b, &c, &d]);
        storage.init_genesis(&gs).unwrap();
        let newcomer = key(9);
        let mut ledger = gs.ledger.clone();
        // Three of four vote the newcomer in, in a block the first validator proposes.
        let proposer = gs.validators.iter().next().unwrap().address();
        let proposer = [&a, &b, &c, &d].into_iter().find(|k| k.address() == proposer).unwrap();
        let vote = admit_tx(&ledger, &newcomer, &[&a, &b, &c]);
        let b1 = make_block(&gs.block, &mut ledger, vec![vote], proposer);
        storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        assert!(ledger.admitted().contains(&newcomer.address()));

        let bare = storage.load_ledger(&StubExecutor).unwrap();
        assert!(bare.staking().is_none(), "storage does not hold the gate");
        assert!(bare.admitted().contains(&newcomer.address()), "but it holds the set");
        assert_ne!(bare.state_root(), ledger.state_root(), "without the gate the root is another chain's");
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert!(reloaded.staking().is_some_and(|s| s.admission_by_vote()));
        assert_eq!(reloaded.admitted(), ledger.admitted());
        assert_eq!(reloaded.state_root(), ledger.state_root(), "the same state root after the restart");
        assert_eq!(reloaded, ledger);
    }

    /// Audit v6, STAKE-1: a slash survives a restart — the jail and the cut stake are state
    /// storage holds — and so does the section that gives them meaning, from the genesis file: the
    /// reloaded ledger keeps the jailed key out and hashes the same `rand-state-slashing-1` root.
    #[test]
    fn a_restart_restores_the_slash_and_the_jail() {
        use crate::storage::fixtures::{make_block, slash_tx, slashing_genesis};
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let keys = [key(1), key(2), key(3), key(4)];
        let gs = slashing_genesis(&keys.iter().collect::<Vec<_>>());
        storage.init_genesis(&gs).unwrap();
        let proposer = keys.iter().find(|k| k.address() == gs.validators.leader(1)).unwrap();
        let offender = keys.iter().find(|k| k.address() != proposer.address()).unwrap();
        let mut ledger = gs.ledger.clone();
        let evidence = slash_tx(&ledger, offender, 1, 1);
        let b1 = make_block(&gs.block, &mut ledger, vec![evidence], proposer);
        storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        let bare = storage.load_ledger(&StubExecutor).unwrap();
        assert!(bare.staking().is_none(), "storage does not hold the section");
        assert_eq!(bare.jailed(), ledger.jailed(), "but it holds the jail");
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.state_root(), ledger.state_root());
        assert_eq!(reloaded, ledger);
        assert!(!reloaded.derive_next_set(1).contains(&offender.address()));
    }

    /// Audit v6, STAKE-2: the testnet marker survives a restart the same way — it lives in the
    /// genesis file, `load_ledger` comes back without it, and a node that kept running without it
    /// would tell every wallet and explorer a testnet is not one.
    #[test]
    fn a_restart_restores_the_testnet_marker() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut g = crate::storage::fixtures::genesis_file_of(7, &[&key(1)], vec![], 2);
        g.testnet = Some(true);
        let gs = g.build(&StubExecutor).unwrap();
        storage.init_genesis(&gs).unwrap();
        assert!(!storage.load_ledger(&StubExecutor).unwrap().testnet(), "storage does not hold the marker");
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert!(reloaded.testnet(), "restored from the genesis state");
        assert_eq!(reloaded, gs.ledger, "and it is not state");
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

    /// The v0.6 switch (`hardening_v6`, ZKV-11's pc window first) survives a restart the same way: `load_ledger` comes back with
    /// it off, and a node that kept it off would apply a deploy its peers refuse.
    #[test]
    fn a_restart_restores_the_hardening_v6_switch() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        gs.ledger.set_hardening_v6(true);
        storage.init_genesis(&gs).unwrap();
        assert!(!storage.load_ledger(&StubExecutor).unwrap().hardening_v6());
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert!(reloaded.hardening_v6(), "restored from the genesis state");
    }

    /// Split authorisation's auth guest survives a restart the same way (review M-2): a node that
    /// came back without `hc_auth` would recompute the v1 bundle digest and refuse every v3 bundle
    /// its peers apply — a fork at its first transaction after the restart.
    #[test]
    fn a_restart_restores_hc_auth() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        gs.ledger.set_hc_auth(Some([21; 8]));
        storage.init_genesis(&gs).unwrap();
        assert_eq!(storage.load_ledger(&StubExecutor).unwrap().hc_auth(), None);
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.hc_auth(), Some([21; 8]), "restored from the genesis state");
    }

    /// v0.6.8: core's `kem_ek_is_valid` (genesis `bridge.fees.recipient`) agrees with the KEM the
    /// node seals with (`address::to_research`, `ml_kem`'s own check) on a real wallet's key, on
    /// the zero key, and on keys with one coefficient at and past the modulus.
    #[test]
    fn the_core_kem_check_agrees_with_ml_kem() {
        use randprotocol_core::notes::{kem_ek_is_valid, ShieldedAddress, KEM_EK_BYTES};
        let real = randprotocol_zkvm::address::address_of(&randprotocol_zkvm::notes::SpendKey::random().viewing_key());
        let mut cases = vec![real.kem_ek.clone(), vec![0; KEM_EK_BYTES], vec![0xff; KEM_EK_BYTES]];
        for (i, triple) in [[0x01, 0x0d, 0x00], [0x00, 0x10, 0xd0], [0x00, 0x0d, 0xd0]].into_iter().enumerate() {
            let mut k = real.kem_ek.clone();
            k[3 * (i + 7)..3 * (i + 7) + 3].copy_from_slice(&triple);
            cases.push(k);
        }
        for kem_ek in cases {
            let ours = kem_ek_is_valid(&kem_ek);
            let theirs = randprotocol_zkvm::address::to_research(&ShieldedAddress { pk: [1; 8], kem_ek }).is_ok();
            assert_eq!(ours, theirs);
        }
        assert!(kem_ek_is_valid(&real.kem_ek));
    }

    /// The gas section (design 2026-09-28 §4.2, §4.3, §7.1) survives a restart the same way:
    /// `load_ledger` comes back at `None`, and a node that kept it would run without the prices
    /// and the bundle gas limit its peers enforce.
    #[test]
    fn a_restart_restores_the_gas_section() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        gs.ledger.set_gas(Some(gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: 20_479,
            metering: gas::GasMetering::Circuit,
            dynamic: None,
        }));
        storage.init_genesis(&gs).unwrap();
        assert!(storage.load_ledger(&StubExecutor).unwrap().gas().is_none());
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        let g = reloaded.gas().expect("restored from the genesis state");
        assert_eq!(g.gas_price, 100);
        assert_eq!(g.byte_price, 800);
        assert_eq!(g.bundle_gas_limit, 20_479);
    }

    /// Issue #118: genesis `proof_window_blocks` survives a restart. `load_ledger` comes back at
    /// `None`, 256/256, and a node that kept it would refuse a bundle whose anchor or `time` is
    /// 257..window blocks old — admitted and applied by its peers: a fork at the first one.
    #[test]
    fn a_restart_restores_the_proof_window() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        gs.ledger.set_proof_window_blocks(Some(1024));
        storage.init_genesis(&gs).unwrap();
        assert_eq!(storage.load_ledger(&StubExecutor).unwrap().proof_window_blocks(), None, "storage does not hold it");
        let mut reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.proof_window_blocks(), Some(1024), "restored from the genesis state");
        reloaded.set_height(1000);
        assert!(reloaded.time_in_window(0), "a time 1 000 blocks old is inside the restored window");
    }

    /// BIND-1 (audit v6): the binding domain survives a restart the same way. `load_ledger`
    /// comes back at `ChainId`, and a node that kept it on a `binding_domain: 1` chain would
    /// recompute every binding and signed message without the genesis hash: refusing what its
    /// peers apply, admitting what any chain sharing the id would — a fork at its first
    /// transaction after the restart.
    #[test]
    fn a_restart_restores_the_binding_domain() {
        use randprotocol_core::BindingDomain;
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        gs.ledger.set_binding_domain(BindingDomain::Genesis(gs.hash()));
        storage.init_genesis(&gs).unwrap();
        assert_eq!(storage.load_ledger(&StubExecutor).unwrap().binding_domain(), &BindingDomain::ChainId, "storage does not hold it");
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.binding_domain(), &BindingDomain::Genesis(gs.hash()), "restored from the genesis state");
        // A chain-id-bound mint (today's) is refused on the reloaded ledger and a genesis-bound one
        // is admitted — the restored domain is the one that decides.
        let env = randprotocol_core::Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] };
        let chain_id = Transaction::mint(7, [5; 8], 0, [6; 8], env.clone(), 1, &key(1), &StubExecutor);
        let bound = Transaction::mint_in(reloaded.binding_domain(), 7, [5; 8], 0, [6; 8], env, 1, &key(1), &StubExecutor);
        assert_eq!(reloaded.validate(&chain_id, &StubExecutor), Err(randprotocol_core::TxError::BadMintSignature));
        assert_eq!(reloaded.validate(&bound, &StubExecutor), Ok(()));
        // Without the field (chain 18) a restart keeps the chain-id domain and today's mint.
        let plain = genesis_of(7, &[&key(1)], vec![], 2);
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        storage.init_genesis(&plain).unwrap();
        let reloaded = reload_ledger(&storage, &plain, &StubExecutor).unwrap();
        assert_eq!(reloaded.binding_domain(), &BindingDomain::ChainId);
        assert_eq!(reloaded.validate(&chain_id, &StubExecutor), Ok(()));
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

    /// Spec 2026-09-26 §2.4: the exact envelope size survives a restart too — `load_ledger`
    /// comes back at `None`, and a node that kept it would admit envelopes its peers refuse.
    #[test]
    fn a_restart_restores_envelope_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let mut gs = genesis_of(7, &[&key(1)], vec![], 2);
        gs.ledger.set_envelope_bytes(Some(randprotocol_core::notes::MEMO_ENVELOPE_BYTES));
        storage.init_genesis(&gs).unwrap();
        assert_eq!(storage.load_ledger(&StubExecutor).unwrap().envelope_bytes(), None);
        let reloaded = reload_ledger(&storage, &gs, &StubExecutor).unwrap();
        assert_eq!(reloaded.envelope_bytes(), Some(randprotocol_core::notes::MEMO_ENVELOPE_BYTES));
    }

    /// Task 6 (spec 2026-09-26 §2.4): the faucet's mint follows the chain's own declared
    /// envelope format, not always the legacy shape. On a plain genesis it seals the legacy way
    /// and the ledger admits it; on a genesis declaring `envelope_bytes: 1860` the same call
    /// produces a 1 860-byte envelope, and *that* is what the ledger admits — sealing the old,
    /// shorter way here is exactly what a validator running yesterday's binary would do, and the
    /// ledger refuses it (`EnvelopeSize`), which is the red this test starts from.
    #[test]
    fn a_faucet_mint_is_sealed_in_the_chains_declared_envelope_format() {
        // The real executor, not `StubExecutor`: `faucet_mint_tx`'s `debug_assert_eq!` checks the
        // sealed note's own commitment against `ConfidentialExecutor::note_commitment`, and those
        // two agree only under a real `ZkExecutor` (`StubExecutor::note_commitment` hashes under
        // a distinct `rand-stub-note` domain, so the assert would fire — in *every* debug build,
        // not just `--release` — for a reason unrelated to what this test is about). Cheap here:
        // a bundle-less mint proves nothing, so this costs no proving key or STARK verify.
        let ex = ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
        let to = crate::storage::fixtures::payout(9);

        // The plain chain: legacy format, and the ledger admits it.
        let gs = crate::storage::fixtures::genesis(1);
        let tx = faucet_mint_tx(gs.ledger.binding_domain(), gs.ledger.chain_id(), gs.ledger.envelope_bytes(), &to, 1_000, gs.ledger.height(), &key(1), &ex)
            .unwrap();
        let randprotocol_core::types::Action::Mint { envelope, .. } = &tx.action else { panic!("not a mint") };
        assert_ne!(envelope.len(), randprotocol_core::notes::MEMO_ENVELOPE_BYTES, "the legacy shape is shorter");
        assert_eq!(gs.ledger.validate(&tx, &ex), Ok(()));

        // The memo chain: the mint's envelope is exactly `envelope_bytes` long, and the ledger
        // admits it too.
        let mut memo_gs = crate::storage::fixtures::genesis(1);
        memo_gs.ledger.set_envelope_bytes(Some(randprotocol_core::notes::MEMO_ENVELOPE_BYTES));
        let tx = faucet_mint_tx(
            memo_gs.ledger.binding_domain(),
            memo_gs.ledger.chain_id(),
            memo_gs.ledger.envelope_bytes(),
            &to,
            1_000,
            memo_gs.ledger.height(),
            &key(1),
            &ex,
        )
        .unwrap();
        let randprotocol_core::types::Action::Mint { envelope, .. } = &tx.action else { panic!("not a mint") };
        assert_eq!(memo_gs.ledger.validate(&tx, &ex), Ok(()));
        assert_eq!(envelope.len(), randprotocol_core::notes::MEMO_ENVELOPE_BYTES);
    }

    /// HB-1 (zkVM/ISA review, low): a `kem_ek` of the right length (1 184 bytes) that is not an
    /// ML-KEM-768 encapsulation key — a coefficient past q — panicked the vendored
    /// `Envelope::seal` (`.expect("valid encapsulation key")`), and the faucet seals on the node's
    /// own loop (`Node::mint`), so one `rand_mint` call with such an address took the node down.
    /// Now it is the faucet's error, like a wrong-length key already was; every node path that
    /// seals to an address it was handed goes through the same `address::to_research` check.
    #[test]
    fn a_faucet_mint_to_an_invalid_ml_kem_key_is_an_error_not_a_panic() {
        let ex = ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
        let gs = crate::storage::fixtures::genesis(1);
        let mut to = crate::storage::fixtures::payout(9);
        to.kem_ek = vec![0xff; randprotocol_core::notes::KEM_EK_BYTES];
        let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            faucet_mint_tx(gs.ledger.binding_domain(), gs.ledger.chain_id(), gs.ledger.envelope_bytes(), &to, 1_000, gs.ledger.height(), &key(1), &ex)
        }));
        let err = got.expect("the finding: sealing to a length-valid bad key panics").expect_err("refused");
        assert!(err.contains("not a valid ML-KEM-768 encapsulation key"), "{err}");
    }

    /// The 2026-09-27 reviews' coverage gap: nothing caught a panic inside proof verification,
    /// and the admission worker is a `spawn_blocking` task that reports its verdict at the end —
    /// so a proof that panicked Plonky3 killed the task, no verdict was ever sent, the worker slot
    /// (`verify_in_flight`, four of them) was never given back and the gossip message was never
    /// reported. Four such proofs and the node verified nothing more. The worker's body now runs
    /// under `guard_verify`: a panic is a `VerifierPanicked` verdict (non-permanent: Ignore, never
    /// cached), which `on_verdict` handles like any other.
    #[test]
    fn a_panic_inside_admission_verification_is_a_verdict_not_a_dead_worker() {
        let got = std::panic::catch_unwind(|| guard_verify(|| panic!("index out of bounds: the len is 3 but the index is 7")));
        let verdict = got.expect("the finding: the panic escapes the worker");
        assert!(matches!(&verdict, Err(randprotocol_core::TxError::VerifierPanicked(m)) if m.contains("index out of bounds")), "{verdict:?}");
        assert!(!admission::is_permanent(&verdict.unwrap_err()), "never cached");
        assert_eq!(guard_verify(|| Ok(())), Ok(()), "a verdict passes through");
        assert_eq!(guard_verify(|| Err(randprotocol_core::TxError::BadDigest)), Err(randprotocol_core::TxError::BadDigest));
    }

    /// Audit v6, PROC-8: a node more than one block behind defers by-hash fetches to batch sync;
    /// at the head, and one block behind (a live proposal's parent), it fetches.
    #[test]
    fn by_hash_fetches_wait_for_batch_sync_while_behind() {
        assert!(!fetch_deferred_to_batch_sync(0, 0), "no status yet: fetch");
        assert!(!fetch_deferred_to_batch_sync(100, 100));
        assert!(!fetch_deferred_to_batch_sync(101, 100), "one block behind is a live proposal's parent");
        assert!(fetch_deferred_to_batch_sync(102, 100));
        assert!(fetch_deferred_to_batch_sync(1_000, 100));
        assert!(!fetch_deferred_to_batch_sync(50, 100), "peers behind us say nothing about what we lack");
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
                auth_commit: [0; 8],
                auth_proof: Vec::new(),
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
                aggregate_program_digest: StubExecutor.aggregate_program_digest(&shape).unwrap(),
            }],
        }
    }

    fn aggregate_tx(chain_id: u64, kp: &Keypair, nonce: u64, time: u32, covers: Vec<Hash>, proof: Vec<u8>) -> Transaction {
        let aggregator = kp.public_key().address();
        let r = [9; 8];
        let signature =
            kp.sign(aggregate_signing_hash(chain_id, nonce, time, &r, &covers, &Hash::digest(&proof), &randprotocol_core::types::actions::envelope_digest(&env(9))).as_bytes());
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
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
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

    /// Assembly reads the store (spec §3.2): the covered bundle's `pv::NUM` public values and its
    /// declared shape come back off the stored proof's header, the profile filled from the chain.
    #[test]
    fn assembly_reads_the_stored_bundle_records() {
        let (_d, storage, _gs, covered_tx, _mint) = chain_with_a_real_proof();
        let proof = crate::agg_executor::fixture_proof(0);
        let covered =
            assemble_covered(&storage, 1, 256, randprotocol_core::types::FriProfile::Test, &[covered_tx.hash()]).unwrap();
        assert_eq!(covered.len(), 1);
        let expected: [u64; randprotocol_core::types::pv::NUM] = proof.public_values.clone().try_into().unwrap();
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
                aggregate_program_digest: StubExecutor.aggregate_program_digest(&fixture_shape(&proof)).unwrap(),
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

    /// RPL-2, the pool and the proposer together. Three invokes are pooled: two on disjoint
    /// cells and a third that reads and writes the first one's cell. The proposer is offered all
    /// three, packs the two that do not touch each other into one block and skips the third
    /// where it sits (its read is stale on the state the first left); a peer applies that block
    /// to the same root; and at the prune that follows the block the third leaves the pool
    /// rather than being re-offered to every block after.
    #[test]
    fn the_proposer_packs_two_invokes_on_disjoint_cells_and_the_stale_third_is_pruned() {
        use crate::mempool::Mempool;
        use crate::storage::fixtures::{rpl2_cell, rpl2_genesis, rpl2_invoke_tx, rpl2_program, rpl2_setup_txs, rpl2_transition, RPL2_FEE};
        use randprotocol_core::consensus::{ConsensusConfig, HotStuff};
        use randprotocol_core::ledger::program_state::Transition;

        let gs = rpl2_genesis(7);
        // The state the proposal builds on: the program deployed and its token registered (the
        // fixture chain's first block, applied in place — the replicas start from it).
        let mut ledger = gs.ledger.clone();
        for tx in rpl2_setup_txs(&gs.ledger) {
            ledger.apply_tx(&tx, &key(1).address(), &StubExecutor).unwrap();
        }
        let step = |k, from, to| Transition { reads: vec![rpl2_cell(k, from)], writes: vec![rpl2_cell(k, to)], ..rpl2_transition() };
        let first = rpl2_invoke_tx(&ledger, 10, RPL2_FEE, (0, 0, 0), step(1, 0, 5));
        let disjoint = rpl2_invoke_tx(&ledger, 20, RPL2_FEE, (0, 0, 0), step(2, 0, 5));
        // Pays less, so it is tried after `first` — and reads the cell `first` writes.
        let loser = rpl2_invoke_tx(&ledger, 30, RPL2_FEE - 1_000, (0, 0, 0), step(1, 0, 9));
        let mut pool = Mempool::new(100);
        for tx in [&first, &disjoint, &loser] {
            pool.insert(tx.clone(), &ledger, &StubExecutor).unwrap();
        }

        let executor: Arc<dyn ConfidentialExecutor> = Arc::new(StubExecutor);
        let mk = || {
            HotStuff::new(
                ConsensusConfig::new(7, gs.validators.clone(), gs.hash()),
                Some(key(1)),
                gs.block.clone(),
                ledger.clone(),
                executor.clone(),
            )
        };
        let (mut leader, mut peer) = (mk(), mk());
        leader.start();
        peer.start();
        let candidates = pool.block_candidates(leader.tip_ledger());
        assert_eq!(candidates.len(), 3, "the pool offers all three: which fit is the trial apply's to say");
        let acts = leader.propose(1, candidates, 1).expect("the leader's own block applies");
        let block = acts
            .iter()
            .find_map(|a| match a {
                randprotocol_core::consensus::Action::Broadcast(randprotocol_core::consensus::ConsensusMessage::Proposal(b)) => Some(b.clone()),
                _ => None,
            })
            .expect("a proposal was built");
        let mined: Vec<Hash> = block.transactions.iter().map(|t| t.hash()).collect();
        assert_eq!(mined.len(), 2, "two invokes in one block");
        assert!(mined.contains(&first.hash()) && mined.contains(&disjoint.hash()), "the two on disjoint cells");
        peer.on_proposal(block.clone(), 1).expect("the peer applies the same block");

        // The state after the block, and the commit path's two pool steps against it.
        let mut after = ledger.clone();
        after.apply_transactions(&block.transactions, &key(1).address(), &StubExecutor).unwrap();
        let (program, _) = rpl2_program();
        let state = after.program_state().unwrap();
        assert_eq!(state.cell(&program, &rpl2_cell(1, 0).key), rpl2_cell(1, 5).value, "`first` won cell 1");
        assert_eq!(state.cell(&program, &rpl2_cell(2, 0).key), rpl2_cell(2, 5).value);
        pool.remove(&mined);
        assert_eq!(pool.len(), 1);
        assert!(matches!(
            after.validate(&loser, &StubExecutor),
            Err(randprotocol_core::TxError::ProgramState(randprotocol_core::ledger::program_state::ProgramStateError::StaleRead { .. }))
        ));
        pool.prune(&after);
        assert!(pool.is_empty(), "the stale invoke is pruned at the block that made it stale");
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
        let pv: [u64; randprotocol_core::types::pv::NUM] = proof.public_values.clone().try_into().unwrap();
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
        // hash, `pv::NUM` public values whose `OUT` words are the bundle's digest, a declared shape.
        let bundle = raw.bundle.as_ref().unwrap();
        let digest = StubExecutor.bundle_digest(&bundle.digest_input());
        let mut public_values = vec![0u64; pv::NUM];
        public_values[pv::TIER] = 14;
        // The covered proof's H_PUB is its transaction's binding (INTERFACE-6 checks it).
        let hpub = StubExecutor.public_digest(&raw.binding(&randprotocol_core::BindingDomain::ChainId));
        for k in 0..8 {
            public_values[pv::OUT0 + k] = digest[k] as u64;
            public_values[pv::HC0 + k] = HC[k] as u64;
            public_values[pv::PUB0 + k] = hpub[k] as u64;
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
        replica.apply_block_for_sync(&served.block, &BTreeMap::new(), &served.pruned, &StubExecutor, &NoVerified).unwrap();
        assert_eq!(replica.state_root(), ledger.state_root());
        assert_eq!(replica.next_index(), gs.ledger.next_index() + 4, "four leaves, dummies included");

        // A substituted slot word or envelope — any of the four — breaks the certified root.
        let substitute = |f: &dyn Fn(&mut randprotocol_core::Bundle)| {
            let mut bad = served.clone();
            f(bad.block.transactions[0].bundle.as_mut().unwrap());
            gs.ledger.clone().apply_block_for_sync(&bad.block, &BTreeMap::new(), &bad.pruned, &StubExecutor, &NoVerified)
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
            gs.ledger.clone().apply_block_for_sync(&lying.block, &BTreeMap::new(), &lying.pruned, &StubExecutor, &NoVerified),
            Err(BlockError::InvalidTx { index: 0, error: randprotocol_core::TxError::BadDigest })
        ));
    }

    /// INTERFACE-6's residual (issue #59): a side-table entry's shape was taken on the serving
    /// peer's word. It must be a shape the genesis admits for the guest its `HC0..7` names; any
    /// other shape, another guest's words, or a chain without aggregation is a damaged batch.
    #[test]
    fn a_pruned_records_shape_must_be_an_admitted_shape_of_its_guest() {
        use randprotocol_core::ledger::aggregation::{AdmittedShape, AggregationConfig};
        use randprotocol_core::types::pv;
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
        let cfg = AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![AdmittedShape {
                shape,
                hc: Hash(randprotocol_core::notes::word8_to_bytes(&HC)),
                aggregate_program_digest: StubExecutor.aggregate_program_digest(&shape).unwrap(),
            }],
        };
        let mut public_values = vec![0u64; pv::NUM];
        for k in 0..8 {
            public_values[pv::HC0 + k] = HC[k] as u64;
        }
        let entry = randprotocol_core::consensus::PrunedBundle {
            tx_hash: Hash::digest(b"a sealed bundle"),
            proof_hash: Hash::digest(b"its proof"),
            public_values,
            shape,
        };
        check_pruned_shapes(Some(&cfg), 5, std::slice::from_ref(&entry)).unwrap();
        let mut taller = entry.clone();
        taller.shape.mem_log_height += 1;
        let err = check_pruned_shapes(Some(&cfg), 5, &[entry.clone(), taller]).unwrap_err().to_string();
        assert!(err.contains("block 5") && err.contains("shape"), "{err}");
        let mut other_guest = entry.clone();
        other_guest.public_values[pv::HC0] ^= 1;
        assert!(check_pruned_shapes(Some(&cfg), 5, &[other_guest]).is_err(), "the shape, but for another guest");
        assert!(check_pruned_shapes(None, 5, std::slice::from_ref(&entry)).is_err(), "no aggregation, no pruned record");
        check_pruned_shapes(None, 5, &[]).unwrap();
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

    /// INTERFACE-9 (issue #51): the pruning pass now shrinks the block row with the record, so
    /// a node serves its own pruned history from a marker-form row, exactly as a node that
    /// synced it in sealed form always has. The serve path must not notice: the same marker
    /// form and side entry as the record, a batch cut short of the cover still extends until
    /// the coverage closes, and a fresh syncer accepts it. Stub-proved end to end (the pass's
    /// reader is `stub_proof_reader`), so it runs without a recursion fixture — the stub twin
    /// of `a_batch_cut_short_of_its_cover_extends_until_the_coverage_closes`.
    #[test]
    fn a_block_row_this_node_pruned_serves_coverage_closed_like_a_sealed_synced_one() {
        use crate::storage::TxRecord;
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::open(dir.path()).unwrap();
        let gs = genesis_of(7, &[&key(1)], vec![], 2);
        storage.init_genesis(&gs).unwrap();
        let mut ledger_after = gs.ledger.clone();
        let mut covered: Option<Transaction> = None;
        let mut parent = gs.block.clone();
        let mut blocks = Vec::new();
        for h in 1..=5u64 {
            ledger_after.set_height(h);
            ledger_after.set_timestamp_ms(h);
            let stored: Vec<Transaction> = match h {
                2 => {
                    let tx = bundle_tx(&ledger_after, [[21; 8], [22; 8]], [[23; 8], [24; 8]], bundle_fee());
                    ledger_after.apply_transactions(std::slice::from_ref(&tx), &key(1).address(), &StubExecutor).unwrap();
                    covered = Some(tx.clone());
                    vec![tx]
                }
                5 => vec![aggregate_tx(7, &key(7), 0, 1, vec![covered.as_ref().unwrap().hash()], b"ok".to_vec())],
                _ => vec![],
            };
            ledger_after.record_anchor(h);
            let cb = make_block_unchecked(&parent, &ledger_after, stored, &key(1));
            parent = cb.block.clone();
            blocks.push(cb);
        }
        storage.commit(&blocks, &ledger_after, &[], &StubExecutor).unwrap();
        let covered = covered.unwrap();
        assert_eq!(storage.sealed_by(&covered.hash()).unwrap().map(|(_, at)| at), Some(5), "the aggregate's commit sealed it");
        let reader = crate::storage::fixtures::stub_proof_reader(std::slice::from_ref(&covered));
        assert_eq!(storage.prune_sealed_with(5 + 256, 256, u64::MAX, &reader).unwrap(), 1);

        // The block row is the marker form now, under the certified root.
        let row = storage.block_by_height(2).unwrap().unwrap();
        let Some(TxRecord::Pruned { tx: marker_tx, proof_hash, public_values, shape, .. }) = storage.tx_record(&covered.hash()).unwrap()
        else {
            panic!("the record is pruned")
        };
        assert_eq!(row.transactions, vec![marker_tx.clone()], "the block row shrank with the record");
        assert_eq!(row.hash(), blocks[1].block.hash());

        // Served from that row: the record's form and its side entry.
        let served = sealed_form_of(&storage, &storage.committed_block(2).unwrap().unwrap());
        assert_eq!(served.block.transactions, vec![marker_tx]);
        assert_eq!(served.pruned.len(), 1);
        let side = &served.pruned[0];
        assert_eq!((side.tx_hash, side.proof_hash, &side.public_values, side.shape), (covered.hash(), proof_hash, &public_values, shape));

        // Coverage-closed: a count cut at 3 extends to the aggregate at 5, and a fresh store takes it.
        let batch = serve_blocks(&storage, 3);
        assert_eq!(batch.last().unwrap().block.height(), 5, "the extension closed the coverage");
        assert_eq!(batch[1].pruned[0].tx_hash, covered.hash());
        accepted_by_a_fresh_store(&batch).expect("a coverage-closed batch is accepted");
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

    /// The rescan's ZKQ-1: `preflight_aggregate` checked only the gate, the sizes and the chain
    /// id, so the cover count, the duplicates and the aggregator's signature were checked after
    /// `assemble_covered` had read every cover from the store. One real bundle hash repeated to
    /// the byte cap (~65 000 times, with a junk proof) cost that many RocksDB reads and decodes of
    /// a ~1.2 MB record, and saturated the admission workers. Every one of those verdicts is the
    /// transaction's own bytes or the register's, so each now refuses before a single read.
    #[test]
    fn a_cover_set_or_signature_admission_can_refuse_reads_nothing_from_the_store() {
        let gs = genesis_of(7, &[&key(1)], vec![], 2);
        let shape = DeclaredShape {
            profile: randprotocol_core::types::FriProfile::Test,
            tier: 14,
            program_log_height: 12,
            input_log_height: 10,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 4,
            mem_log_height: 16,
        };
        let mut ledger = gs.ledger.clone();
        ledger.set_aggregation(Some(agg_cfg(shape, Hash::digest(b"the bundle guest"))));
        ledger.set_height(1);
        let kp = key(7);
        register_aggregator(&mut ledger, &kp, 100 * randprotocol_core::UNITS_PER_RAND);
        let reads = std::cell::Cell::new(0usize);
        let run = |tx: &Transaction| {
            validate_for_pool_with(tx, &ledger, &StubExecutor, |_, covers| {
                reads.set(reads.get() + covers.len());
                Err(randprotocol_core::TxError::Aggregation(AggregationError::UnknownCover(covers[0])))
            })
        };
        let h = |i: u8| Hash::digest(&[i]);
        let repeated = aggregate_tx(7, &kp, 0, 1, vec![h(1); 1000], b"junk".to_vec());
        let too_many = aggregate_tx(7, &kp, 0, 1, (0..4).map(h).collect(), b"junk".to_vec());
        let empty = aggregate_tx(7, &kp, 0, 1, vec![], b"junk".to_vec());
        let unknown = aggregate_tx(7, &key(8), 0, 1, vec![h(1)], b"junk".to_vec());
        let mut forged = aggregate_tx(7, &kp, 0, 1, vec![h(1)], b"junk".to_vec());
        if let randprotocol_core::types::Action::Aggregate { signature, .. } = &mut forged.action {
            *signature = key(8).sign(b"not the aggregate's signing hash");
        }
        let stale = aggregate_tx(7, &kp, 3, 1, vec![h(1)], b"junk".to_vec());
        for (what, tx) in [
            ("repeated", &repeated),
            ("too many", &too_many),
            ("empty", &empty),
            ("unregistered", &unknown),
            ("forged", &forged),
            ("stale nonce", &stale),
        ] {
            match run(tx) {
                Err(randprotocol_core::TxError::Aggregation(
                    AggregationError::TooManyCovers { .. }
                    | AggregationError::DuplicateCover(_)
                    | AggregationError::EmptyCoverSet
                    | AggregationError::UnknownAggregator(_)
                    | AggregationError::BadSignature
                    | AggregationError::BadNonce { .. },
                )) => {}
                other => panic!("{what}: refused by its bytes or the register, got {other:?}"),
            }
            assert_eq!(reads.get(), 0, "{what}: no cover was read from the store");
        }
        // A well-formed one does reach the store, once per cover.
        let fine = aggregate_tx(7, &kp, 0, 1, vec![h(1), h(2)], b"junk".to_vec());
        assert!(run(&fine).is_err());
        assert_eq!(reads.get(), 2, "the honest set is assembled");
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
        QuorumCertificate { view, block_hash: hash, votes: ks[..n].iter().map(|k| Vote::sign(&randprotocol_core::consensus::SigningDomain::v0(Hash::ZERO), view, hash, k)).collect() }
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
        let block = Block::sign(&randprotocol_core::consensus::SigningDomain::v0(Hash::ZERO), header, txs, &ks[0]);
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
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
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
        const { assert!(2 * network::SYNC_MAX_WIRE_BYTES <= network::SYNC_RESPONSE_WIRE_LIMIT) };
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

    /// SYNC-2 (network scan 2026-09-26, medium): a peer that claims a huge height and answers our
    /// live batch request empty (or starting elsewhere) was re-picked on every tick by
    /// `pick_sync_peer`'s `max_by_key` on the claimed height, so the node never asked anyone
    /// else. Such an answer is now a miss: the peer is backed off — five seconds, doubling to a
    /// two-minute cap — and the next candidate is asked meanwhile; a batch that applies clears it.
    #[test]
    fn a_peer_that_answers_our_batch_empty_is_backed_off_and_another_is_asked() {
        let pid = |seed: u8| PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public());
        let at = |h: u64| Peer { status: Some(Status { height: h, head_hash: Hash::ZERO, view: h, floor: 0 }), connected: true, ..Default::default() };
        let (liar, honest) = (pid(1), pid(2));
        let mut peers: HashMap<PeerId, Peer> = [(liar, at(1_000_000)), (honest, at(500))].into_iter().collect();
        let t0 = Instant::now();
        assert_eq!(pick_sync_peer(&peers, 43, 1_000_000, &[], t0), Some(liar), "the highest claim is asked first");
        // The live request's own answer, empty or mis-started, is a miss; a stale one is not.
        for first in [None, Some(40u64), Some(45)] {
            assert!(batch_decision(first, 43, true).miss, "{first:?}");
            assert!(!batch_decision(first, 43, false).miss, "a stale answer is no one's miss: {first:?}");
        }
        assert!(!batch_decision(Some(44), 43, true).miss);
        back_off_sync_peer(peers.get_mut(&liar).unwrap(), t0);
        assert_eq!(pick_sync_peer(&peers, 43, 1_000_000, &[], t0), Some(honest), "the next candidate is asked");
        assert_eq!(pick_sync_peer(&peers, 43, 1_000_000, &[], t0 + SYNC_BACKOFF_BASE - Duration::from_millis(1)), Some(honest));
        // Back once the back-off expires — a candidate again, though no longer ahead of a peer
        // with no miss (CN-1: the record ranks before the claim), so shown with that peer skipped.
        assert_eq!(pick_sync_peer(&peers, 43, 1_000_000, &[honest], t0 + SYNC_BACKOFF_BASE - Duration::from_millis(1)), None);
        assert_eq!(pick_sync_peer(&peers, 43, 1_000_000, &[honest], t0 + SYNC_BACKOFF_BASE), Some(liar), "back once the back-off expires");
        assert_eq!(pick_sync_peer(&peers, 43, 1_000_000, &[], t0 + SYNC_BACKOFF_BASE), Some(honest), "but outranked by a peer with no miss");
        // A second miss in a row doubles it.
        let t1 = t0 + SYNC_BACKOFF_BASE;
        back_off_sync_peer(peers.get_mut(&liar).unwrap(), t1);
        assert_eq!(pick_sync_peer(&peers, 43, 1_000_000, &[honest], t1 + SYNC_BACKOFF_BASE), None);
        assert_eq!(pick_sync_peer(&peers, 43, 1_000_000, &[honest], t1 + 2 * SYNC_BACKOFF_BASE), Some(liar));
        // The fallback branch (no fresh candidate) honours it too: alone and backed off, no pick.
        let mut alone: HashMap<PeerId, Peer> = [(liar, at(1_000_000))].into_iter().collect();
        back_off_sync_peer(alone.get_mut(&liar).unwrap(), t0);
        assert_eq!(pick_sync_peer(&alone, 43, 1_000_000, &[], t0), None);
        // Capped.
        let p = peers.get_mut(&liar).unwrap();
        for _ in 0..20 {
            back_off_sync_peer(p, t0);
        }
        assert_eq!(p.sync_backoff, SYNC_BACKOFF_MAX);
        // A batch that applied clears it: asked again at once, and the next miss starts over.
        clear_sync_backoff(p);
        assert_eq!(pick_sync_peer(&peers, 43, 1_000_000, &[], t0), Some(liar));
        back_off_sync_peer(peers.get_mut(&liar).unwrap(), t0);
        assert_eq!(peers[&liar].sync_backoff, SYNC_BACKOFF_BASE);
    }

    /// CN-1 (2026-09-27, high): two peers that each claim a height near `u64::MAX` and never answer
    /// held a lagging node's batch sync for ever. A failed or timed-out batch request halved the
    /// batch and re-picked with only that one peer skipped, so the two alternated — each holding
    /// the request for the wire's whole timeout — and the honest peer slightly ahead was asked
    /// zero times. A failure now backs the peer off as SYNC-2's empty answer does, and the picker
    /// ranks the fewest consecutive misses before the claimed height: the back-off alone expires
    /// (5 s) well inside the 30 s a silent peer holds each request, so it cannot be the whole fix.
    #[test]
    fn two_silent_sybils_claiming_the_top_height_cannot_starve_the_honest_peer() {
        let pid = |seed: u8| PeerId::from(libp2p::identity::Keypair::ed25519_from_bytes([seed; 32]).unwrap().public());
        let at = |h: u64| Peer { status: Some(Status { height: h, head_hash: Hash::ZERO, view: h, floor: 0 }), connected: true, ..Default::default() };
        let (s1, s2, honest) = (pid(1), pid(2), pid(3));
        let top = u64::MAX - 1;
        let mut peers: HashMap<PeerId, Peer> = [(s1, at(top)), (s2, at(top)), (honest, at(50))].into_iter().collect();
        let my = 43;
        let mut now = Instant::now();
        // The node's own loop, reduced to its decisions: pick; a sybil holds the request for the
        // wire's whole timeout and it fails (`SyncFailed`, or `sync_from`'s abandon on the tick);
        // the failure handling runs and the next candidate is picked with that peer skipped.
        let mut skip: Option<PeerId> = None;
        let mut asked = Vec::new();
        for _ in 0..8 {
            let Some(p) = pick_sync_peer(&peers, my, top, skip.as_slice(), now) else {
                now += Duration::from_secs(2); // the sync tick
                skip = None;
                continue;
            };
            asked.push(p);
            if p == honest {
                break;
            }
            now += network::SYNC_REQUEST_TIMEOUT;
            on_sync_batch_failed(&mut peers, p, now);
            skip = Some(p);
        }
        assert_eq!(asked.last(), Some(&honest), "the honest peer must be asked; asked: {asked:?}");
        assert!(asked.len() <= 3, "each sybil costs at most one request; asked: {asked:?}");
        // The honest batch applies. Its next request goes to it again — even once the sybils'
        // back-offs have expired, their unbroken misses rank them below it.
        clear_sync_backoff(peers.get_mut(&honest).unwrap());
        let later = now + SYNC_BACKOFF_MAX;
        assert_eq!(pick_sync_peer(&peers, my, top, &[], later), Some(honest));
        // Liveness: with the honest peer gone, an expired back-off is a candidate again (on the
        // fresh branch and the fallback alike), never a stall ...
        peers.remove(&honest);
        assert!(pick_sync_peer(&peers, my, top, &[], later).is_some());
        // ... and while every ahead peer is still backed off there is no pick until one expires.
        for p in [s1, s2] {
            on_sync_batch_failed(&mut peers, p, later);
        }
        assert_eq!(pick_sync_peer(&peers, my, top, &[], later), None);
        assert!(pick_sync_peer(&peers, my, top, &[], later + SYNC_BACKOFF_MAX).is_some());
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
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
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
        // A transaction already refused here is rejected without any verification — from within
        // its forwarder's allowance, which the hash that finds it in the cache is paid from
        // (audit v6, GOSSIP-1).
        assert_eq!(
            GossipOutcome::for_transaction(&tx, Some(&mut TokenBucket::default()), &mut refused, &limiter, 0, t),
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
        // The refused cache is consulted before the queue depth, so a full queue does not mask a
        // refusal — but after the bucket (GOSSIP-1): a forwarder over its allowance is ignored
        // before its transaction is hashed, known-bad or not.
        assert_eq!(
            GossipOutcome::for_transaction(&tx, Some(&mut TokenBucket::default()), &mut refused, &limiter, MAX_VERIFY_QUEUE, t),
            GossipOutcome::Report(Acceptance::Reject)
        );
        assert_eq!(
            GossipOutcome::for_transaction(&tx, Some(&mut bucket), &mut refused, &limiter, 0, t),
            GossipOutcome::Report(Acceptance::Ignore)
        );
    }

    /// Audit v6, GOSSIP-1: the transaction id hashes the whole transaction, proofs included, and
    /// it was computed for the refused-cache lookup before the forwarder's bucket was consulted —
    /// so a forwarder over its allowance still cost a hash of every frame. Counted through the
    /// hashing seam: an empty bucket, no hash; within the allowance, one.
    #[test]
    fn a_gossiped_transaction_is_hashed_only_within_its_forwarders_allowance() {
        use crate::admission::{Acceptance, GossipOutcome, PeerLimiter, RefusedCache, TokenBucket};
        let (mut refused, limiter, t) = (RefusedCache::new(4), PeerLimiter::new(1, 0.0), Instant::now());
        let tx = transfer(3);
        let hashes = std::cell::Cell::new(0u32);
        let counted = || {
            hashes.set(hashes.get() + 1);
            tx.hash()
        };
        let mut spent = TokenBucket::default();
        assert!(limiter.allow(&mut spent, t));
        assert_eq!(
            GossipOutcome::for_transaction_hashed(&tx, counted, Some(&mut spent), &mut refused, &limiter, 0, t),
            GossipOutcome::Report(Acceptance::Ignore)
        );
        assert_eq!(hashes.get(), 0, "a forwarder over its allowance cost no hash");
        let counted = || {
            hashes.set(hashes.get() + 1);
            tx.hash()
        };
        assert_eq!(
            GossipOutcome::for_transaction_hashed(&tx, counted, Some(&mut TokenBucket::default()), &mut refused, &limiter, 0, t),
            GossipOutcome::Verify
        );
        assert_eq!(hashes.get(), 1, "within it, the transaction is hashed once");
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
            acceptance_for(&Err(TxError::UnknownAnchor { window: 256 }), Hash::digest(b"b"), &mut refused),
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
