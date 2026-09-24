use super::{
    Action, CommittedBlock, ConsensusConfig, ConsensusError, ConsensusMessage, EpochSets, NewView, NotHeld, SafetyState,
    SigningDomain, PROPOSAL_VIEW_WINDOW,
};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{Address, Hash, Keypair};
use crate::ledger::{BlockError, Ledger, NoVerified, TxError, VerifiedProofs};
use crate::types::{Block, BlockHeader, CoveredBundle, QuorumCertificate, Transaction, ValidatorSet, Vote};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How far ahead of our current view an inbound message's view may be before it is
/// rejected. Deliberately generous (days of timed-out views): the bound exists to keep
/// `view + 1` arithmetic away from u64 overflow and to bound speculative state, not to
/// police legitimate catch-up, which goes through block sync and `resume`.
const MAX_VIEW_AHEAD: u64 = 1_000_000;
/// Cap on distinct (view, block) vote collections kept while leading.
const MAX_PENDING_VOTE_KEYS: usize = 4096;
/// Cap on distinct views with buffered NewView messages.
const MAX_NEW_VIEW_KEYS: usize = 2048;
/// Cap on cached epoch-set derivations. Every key is a block in the tree, so this only bites if
/// the tree cap is raised far past it.
const MAX_DERIVED_SETS: usize = 1024;
/// How many epochs back a replica keeps validator sets for. Blocks below the committed head are
/// refused as stale, so nothing consensus verifies reaches further back than the committed
/// height's own epoch; the node keeps the durable copy for replay and sync.
const EPOCH_SETS_KEPT: u64 = 2;

struct Entry {
    block: Block,
    ledger_after: Ledger,
    receipts: Vec<crate::program::CallReceipt>,
    /// The certificate this replica has seen for the block, if any (audit v5, CON-4): a child's
    /// `justify`, or a QC that was the high QC. What `highest_held_qc` falls back to — a QC only
    /// ever held as `high_qc` was lost the moment a QC on a block nobody held replaced it.
    qc: Option<QuorumCertificate>,
}

/// Chained HotStuff replica. Validators hold a `signer`; observing full nodes do not.
/// What the covered-carrying apply path asks of the node (block aggregation, spec §3.2): the
/// covered bundles' records for an aggregate's cover set, or `None` when any of them is
/// unavailable — which the block's validators then read as the covered-carrying admission's
/// own refusal, at the aggregate's index. The node answers from its transaction store; the
/// ledger itself has none, which is why this is a callback and not a method on it.
pub trait CoveredSource: Send + Sync {
    fn covered(&self, covers: &[Hash]) -> Option<Vec<CoveredBundle>>;
}

pub struct HotStuff {
    cfg: ConsensusConfig,
    signer: Option<Keypair>,
    executor: Arc<dyn ConfidentialExecutor>,
    /// The node's covered-bundle record source (block aggregation, spec §3.2): consulted only
    /// for blocks and candidates that carry an `Aggregate`, whose admission needs the covered
    /// bundles' records — which live in the node's store, not the ledger. `None` until the node
    /// sets one (tests, and any chain that never aggregates): an `Aggregate` then takes the T4
    /// signpost error, exactly as before.
    covered: Option<Arc<dyn CoveredSource>>,
    /// The node's admission cache of already-verified proofs (audit v3, B5): consulted at
    /// propose (the trial apply) and at a proposal's apply, where a hit skips only the STARK
    /// verification. [`NoVerified`] until the node sets its shared set — tests, and any replay
    /// path, verify every proof, exactly as before.
    verified: Arc<dyn VerifiedProofs>,

    view: u64,
    high_qc: QuorumCertificate,
    locked_qc: QuorumCertificate,
    /// QC certifying the committed head; the fallback when `high_qc`'s block is unobtainable.
    head_qc: QuorumCertificate,
    last_voted_view: u64,
    consecutive_timeouts: u32,
    proposed_in_view: bool,

    committed_height: u64,
    committed_hash: Hash,
    committed_ledger: Ledger,
    /// Uncommitted blocks plus the committed head (so children can find their parent).
    tree: HashMap<Hash, Entry>,
    /// Blocks waiting for a parent, keyed by parent hash.
    orphans: HashMap<Hash, Vec<Block>>,
    orphan_count: usize,
    /// The one block this replica holds per (view, proposer) (audit v4, CON-3): a second,
    /// different block from the same leader for the same view is an equivocation and is refused.
    /// Entries follow the tree — `prune` and `evict_for_room` drop them with their blocks — so
    /// the map is bounded by `max_tree_blocks`.
    proposed: BTreeMap<(u64, Address), Hash>,
    /// Validators of the current set that have signed that they do not hold the locked block
    /// (audit v4, CON-4), keyed by that block's hash. Kept for the locked block alone — the one
    /// hash the evidence can act on — so it holds at most one entry; cleared when the block
    /// arrives, when the lock is released, and on commit.
    not_held: HashMap<Hash, std::collections::BTreeSet<Address>>,
    /// Blocks every fetch failed for — the hash `fallback_high_qc` moved away from. A QC on one
    /// of them is not raised again until the block itself arrives (`execute_and_insert` removes
    /// it; a commit clears the set): after a whole-fleet restart every replica's persisted high
    /// QC named a block nobody held, each fell back, and every peer's NewView re-announced the
    /// ghost and raised it straight back, so no leader ever proposed on the head — the livelock
    /// that held chain 14 for hours on 2026-09-24.
    unobtainable: std::collections::HashSet<Hash>,

    /// Votes collected while acting as the next leader: (view, block) -> voter -> vote.
    pending_votes: BTreeMap<(u64, Hash), BTreeMap<Address, Vote>>,
    /// NewView messages per view: view -> sender -> message.
    new_views: BTreeMap<u64, BTreeMap<Address, NewView>>,

    /// Sets of the epochs whose first block has committed, for the node to persist (spec §8).
    epoch_sets: EpochSets,
    /// Sets derived from the block tree for epochs that have started but not committed their
    /// first block, keyed by `(epoch, hash of the epoch-start block's parent)`. Deriving walks
    /// the register, which consensus would otherwise redo for every proposal and every vote.
    /// `prune` drops entries whose parent has left the tree — by then the epoch's first block is
    /// committed, so `epoch_sets` answers for it. Behind a `Mutex` only so a replica stays
    /// `Sync`: the lock is never held across a call and never contended.
    derived: Mutex<HashMap<(u64, Hash), Arc<ValidatorSet>>>,
    /// The set of `epoch(high_qc height + 1)`: the set that proposes, votes and counts NewView
    /// quorums for the block this replica would build next.
    current: Arc<ValidatorSet>,
    /// The epoch `current` was derived for. It falls behind `epoch(high_qc height + 1)` only when
    /// the newer set is unresolvable, which [`current_set_epoch_gap`](HotStuff::current_set_epoch_gap)
    /// reports so callers fail closed instead of counting a quorum in the wrong epoch.
    current_epoch: u64,
}

impl HotStuff {
    /// Start from genesis.
    pub fn new(
        cfg: ConsensusConfig,
        signer: Option<Keypair>,
        genesis_block: Block,
        genesis_ledger: Ledger,
        executor: Arc<dyn ConfidentialExecutor>,
    ) -> HotStuff {
        let genesis_hash = genesis_block.hash();
        assert_eq!(genesis_hash, cfg.genesis_hash, "genesis mismatch");
        let qc = QuorumCertificate::genesis(genesis_hash);
        let epoch_sets = EpochSets::new(cfg.genesis_set.clone());
        Self::resume(cfg, signer, genesis_block, qc, genesis_ledger, None, Vec::new(), epoch_sets, executor)
    }

    /// Resume from a committed head plus persisted safety state and the epoch sets storage holds.
    ///
    /// A signer whose key is not in the current set is kept: it observes — no votes, no proposals
    /// — until an epoch's register admits it again (spec §8), which is how a validator that
    /// unbonded below the minimum, or one that bonded mid-epoch, rejoins.
    ///
    /// `pending` is the certified chain storage kept above the head (audit v5, CON-4: the last
    /// `Action::PersistPending`), in height order. Each block is re-executed on its parent and
    /// put back in the tree — skipping what is at or under the head (a set written before the
    /// commit that moved the head), dropping silently what does not extend a block this replica
    /// holds — so the block the restored `high_qc` or `locked_qc` names is one it holds, and
    /// the next proposal is checked against its own promise instead of a fetch that, after a
    /// whole-fleet restart, no peer can answer. The lock is then restored from the safety state
    /// exactly as before; the high QC too, unless its block is not among the restored blocks —
    /// a ghost by construction, which falls to the highest QC certifying a held block.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        cfg: ConsensusConfig,
        signer: Option<Keypair>,
        head: Block,
        head_qc: QuorumCertificate,
        head_ledger: Ledger,
        safety: Option<SafetyState>,
        pending: Vec<Block>,
        epoch_sets: EpochSets,
        executor: Arc<dyn ConfidentialExecutor>,
    ) -> HotStuff {
        let mut epoch_sets = epoch_sets;
        if epoch_sets.get(0).is_none() {
            epoch_sets.insert(0, cfg.genesis_set.clone());
        }
        // A loaded ledger carries neither block height nor block time (`Ledger::from_parts`
        // starts both at 0, and equality ignores them): position it at the head block it was
        // reloaded from, so RPC and the next proposal see the tip's time and — the reason this
        // matters for admission — so `validate`'s `time` window (spec §7 step 5) is measured
        // against the real head height. Without the height, every bundle submitted between a
        // restart and the second new block is refused with `time N is outside [0, 0]`.
        let head_hash = head.hash();
        let head_height = head.height();
        let mut head_ledger = head_ledger;
        head_ledger.set_height(head_height);
        head_ledger.set_timestamp_ms(head.header.timestamp_ms);
        let mut tree = HashMap::new();
        tree.insert(head_hash, Entry { block: head, ledger_after: head_ledger.clone(), receipts: Vec::new(), qc: Some(head_qc.clone()) });
        // The lock is a promise this replica made to the rest of the set, and it outlives the
        // process (audit v3, CON-1b): a restart that reset the lock to the committed head's QC let
        // this node vote for a branch conflicting with one it was locked on, which is exactly the
        // extra vote a conflicting QC needs. So a persisted `locked_qc`/`high_qc` is restored
        // whenever it is *ahead* of the head's QC, and a stale one is raised to the head — never
        // lowered below it, because nothing under the committed head can be contradicted any more.
        let (view, high_qc, locked_qc, last_voted_view) = match safety {
            Some(s) => {
                let view = s.view.max(head_qc.view.saturating_add(1));
                let newer = |qc: QuorumCertificate| if qc.view > head_qc.view { qc } else { head_qc.clone() };
                (view, newer(s.high_qc), newer(s.locked_qc), s.last_voted_view)
            }
            None => (head_qc.view.saturating_add(1), head_qc.clone(), head_qc.clone(), 0),
        };
        let current = epoch_sets.shared(0).expect("epoch 0 is seeded above");
        let mut hs = HotStuff {
            cfg,
            signer,
            executor,
            covered: None,
            verified: Arc::new(NoVerified),
            view,
            high_qc,
            locked_qc,
            head_qc,
            last_voted_view,
            consecutive_timeouts: 0,
            proposed_in_view: false,
            committed_height: head_height,
            committed_hash: head_hash,
            committed_ledger: head_ledger,
            tree,
            orphans: HashMap::new(),
            orphan_count: 0,
            proposed: BTreeMap::new(),
            not_held: HashMap::new(),
            unobtainable: std::collections::HashSet::new(),
            pending_votes: BTreeMap::new(),
            new_views: BTreeMap::new(),
            epoch_sets,
            derived: Mutex::new(HashMap::new()),
            current,
            current_epoch: 0,
        };
        hs.refresh_current_set();
        hs.restore_pending(pending);
        // With every certified block persisted, a persisted high QC whose block is not among
        // them (and not the head) is a ghost by construction — every legitimately certified
        // block above the head is in the set — so it is not restored: the high QC falls to the
        // highest QC certifying a block this replica holds. Restoring it re-created the
        // 2026-09-24 stall at every restart: a high QC on a block nobody held, fetched, failed,
        // fallen back from, and re-announced by every NewView. The lock is not touched — only
        // the not-held quorum releases it.
        if hs.high_qc.view > hs.head_qc.view && !hs.tree.contains_key(&hs.high_qc.block_hash) {
            let held = hs.highest_held_qc();
            tracing::warn!(
                "persisted high QC (view {}) names block {:?}, which is not in the persisted certified chain: \
                 a ghost; resuming on the highest held QC (view {})",
                hs.high_qc.view,
                hs.high_qc.block_hash,
                held.view
            );
            hs.high_qc = held;
            hs.refresh_current_set();
        }
        if let Some(s) = &hs.signer {
            if !hs.current.contains(&s.address()) {
                tracing::info!("{} is not in the current validator set; observing until an epoch admits it", s.address());
            }
        }
        hs
    }

    /// Put the persisted certified chain back in the tree (audit v5, CON-4), each block
    /// re-executed on its parent the way `on_proposal` executes a proposal. The set is this
    /// replica's own write, but it can be stale — a crash between a commit and the rewrite that
    /// follows it leaves one that starts at or under the new head — so a block at or under the
    /// head is skipped, a block whose parent is not held is dropped (never inserted, review
    /// focus 3), and a block that does not re-execute is dropped with a warning: the fetch path
    /// answers for whatever is missing, exactly as before there was a set.
    fn restore_pending(&mut self, pending: Vec<Block>) {
        let mut restored = 0usize;
        for block in pending {
            let hash = block.hash();
            if block.height() <= self.committed_height || self.tree.contains_key(&hash) {
                continue;
            }
            if !self.tree.contains_key(&block.parent()) {
                tracing::info!("pending block {hash:?} (height {}) does not extend a block this replica holds; dropped", block.height());
                continue;
            }
            match self.execute_and_insert(&block) {
                Ok(()) => restored += 1,
                Err(e) => tracing::warn!("pending block {hash:?} (height {}) did not re-execute: {e}; dropped", block.height()),
            }
        }
        if restored > 0 {
            self.refresh_current_set();
            tracing::info!(
                "{restored} certified block(s) restored above the head (high QC view {}, lock view {})",
                self.high_qc.view,
                self.locked_qc.view
            );
        }
    }

    // ---- accessors ---------------------------------------------------------

    pub fn view(&self) -> u64 {
        self.view
    }
    pub fn high_qc(&self) -> &QuorumCertificate {
        &self.high_qc
    }
    pub fn locked_qc(&self) -> &QuorumCertificate {
        &self.locked_qc
    }
    /// The view of a quorum certificate this replica holds for `hash`, if any: the high, locked or
    /// head QC, or the `justify` a child in the tree carries for it.
    pub fn certified(&self, hash: &Hash) -> Option<u64> {
        [&self.high_qc, &self.locked_qc, &self.head_qc]
            .iter()
            .find(|qc| qc.block_hash == *hash)
            .map(|qc| qc.view)
            .or_else(|| self.tree.values().map(|e| &e.block.header.justify).find(|qc| qc.block_hash == *hash).map(|qc| qc.view))
    }
    pub fn committed_height(&self) -> u64 {
        self.committed_height
    }
    /// The view of the QC that certifies the committed head — the floor under the lock: a
    /// persisted `locked_qc` older than this one is stale, and `resume` raises it to this.
    pub fn committed_qc_view(&self) -> u64 {
        self.head_qc.view
    }

    /// Tests only: put this replica's committed head somewhere the tree does not reach, which is
    /// the position conflicting finality leaves a node in (audit v3).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn force_committed_hash_for_testing(&mut self, hash: Hash) {
        self.committed_hash = hash;
    }

    pub fn committed_hash(&self) -> Hash {
        self.committed_hash
    }
    /// What this replica signs and verifies consensus messages under (audit v4).
    pub fn domain(&self) -> &SigningDomain {
        &self.cfg.domain
    }
    pub fn committed_ledger(&self) -> &Ledger {
        &self.committed_ledger
    }
    pub fn is_validator(&self) -> bool {
        self.signer.is_some()
    }
    pub fn address(&self) -> Option<Address> {
        self.signer.as_ref().map(|k| k.address())
    }

    /// Register the node's covered-bundle record source (block aggregation): the store the
    /// covered-carrying apply path consults for any proposal or candidate carrying an
    /// `Aggregate`. Called once at startup; everything before it keeps the T4 behavior.
    pub fn set_covered_source(&mut self, source: Arc<dyn CoveredSource>) {
        self.covered = Some(source);
    }

    /// Register the node's admission cache of verified proofs (audit v3, B5). Like
    /// [`Self::set_covered_source`], it does not ride a `resume`: the node re-sets it on every
    /// replica it builds. Called once at startup; everything before it verifies every proof.
    pub fn set_verified_proofs(&mut self, verified: Arc<dyn VerifiedProofs>) {
        self.verified = verified;
    }

    /// The covered-bundle records a block's `Aggregate` transactions need, keyed by their
    /// index in it — empty for a block that carries none, so a chain that never aggregates
    /// never consults the source. An aggregate the source cannot cover is the covered-carrying
    /// admission's refusal, at its index.
    fn covered_sidecar(&self, block: &Block) -> Result<BTreeMap<usize, Vec<CoveredBundle>>, ConsensusError> {
        let mut sidecar = BTreeMap::new();
        for (index, tx) in block.transactions.iter().enumerate() {
            if let crate::types::Action::Aggregate { covers, .. } = &tx.action {
                let records = self.covered.as_ref().and_then(|s| s.covered(covers)).ok_or(BlockError::InvalidTx {
                    index,
                    error: TxError::AggregateNeedsCovered,
                })?;
                sidecar.insert(index, records);
            }
        }
        Ok(sidecar)
    }

    // ---- epochs ------------------------------------------------------------

    /// `epoch(h) = h / epoch_blocks` (spec §8): genesis is epoch 0.
    fn epoch(&self, height: u64) -> u64 {
        height / self.cfg.epoch_blocks.max(1)
    }

    /// Hash of the block the set of `epoch` is derived from: the last block of `epoch - 1` on
    /// the branch ending at `parent`. `None` once it has left the tree, which happens only after
    /// the epoch's first block committed and `epoch_sets` holds the answer.
    fn epoch_start_parent(&self, epoch: u64, parent: &Hash) -> Option<Hash> {
        let mut cur = *parent;
        loop {
            let entry = self.tree.get(&cur)?;
            if self.epoch(entry.block.height()) < epoch {
                return Some(cur);
            }
            cur = entry.block.parent();
        }
    }

    /// The derived-set cache. A poisoned lock only means a panic happened while the cache was
    /// being updated; the cache is pure derived state, so it is taken as it stands.
    fn derived(&self) -> std::sync::MutexGuard<'_, HashMap<(u64, Hash), Arc<ValidatorSet>>> {
        self.derived.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The set a block at `height` extending `parent` is proposed and voted by, shared.
    fn shared_set_for_height(&self, height: u64, parent: &Hash) -> Option<Arc<ValidatorSet>> {
        let epoch = self.epoch(height);
        if epoch == 0 {
            return self.epoch_sets.shared(0);
        }
        let Some(start) = self.epoch_start_parent(epoch, parent) else {
            // The branch no longer reaches the epoch's start: it is committed, and the set was
            // recorded when its first block committed.
            return self.epoch_sets.shared(epoch);
        };
        if let Some(cached) = self.derived().get(&(epoch, start)).cloned() {
            return Some(cached);
        }
        // `epoch_start_parent` only returns hashes it found in the tree.
        let entry = &self.tree[&start];
        let register = entry.ledger_after.derive_next_set(epoch);
        let set = if register.is_empty() {
            // Every validator unbonded below the minimum. Carrying the previous epoch's set
            // forward keeps a block in which they can bond back in; an epoch with no leader is a
            // halt nothing can end (`staking::derive_set` hands this decision here).
            tracing::warn!("epoch {epoch} derives an empty validator set; carrying epoch {} forward", epoch - 1);
            self.shared_set_for_height(entry.block.height(), &entry.block.parent())?
        } else {
            Arc::new(register)
        };
        let mut derived = self.derived();
        // Bounded by the tree already (the key is a block in it), capped again as a backstop.
        if derived.len() < MAX_DERIVED_SETS {
            derived.insert((epoch, start), set.clone());
        }
        Some(set)
    }

    /// The validator set of the epoch a block at `height` extending `parent` belongs to: the
    /// register as of the last block of the previous epoch (spec §8). `None` when this replica
    /// holds neither the branch back to that block nor the epoch's recorded set.
    pub fn set_for_height(&self, height: u64, parent: &Hash) -> Option<ValidatorSet> {
        self.shared_set_for_height(height, parent).map(|s| (*s).clone())
    }

    /// The set of `epoch(high_qc height + 1)`: the one that leads, votes and counts NewView
    /// quorums for the block this replica would build next.
    /// Which epoch [`current_set`](Self::current_set) is the set for. A replica whose head has
    /// moved past a boundary and whose `current_epoch` has not is judging votes, new views and
    /// leaders against a set the chain has left behind (review I3).
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn current_set(&self) -> &ValidatorSet {
        &self.current
    }

    /// Sets of the epochs whose first block has committed, for the node to persist.
    pub fn epoch_sets(&self) -> &EpochSets {
        &self.epoch_sets
    }

    /// The set a vote for `block_hash` is counted in: the set of that block's epoch when this
    /// replica holds the block, and the current set otherwise — a vote for a block we have never
    /// seen carries no epoch of its own, and the current one is the epoch it would be voted in.
    fn set_for_vote(&self, block_hash: &Hash) -> Arc<ValidatorSet> {
        let Some(entry) = self.tree.get(block_hash) else { return self.current.clone() };
        self.shared_set_for_height(entry.block.height(), &entry.block.parent()).unwrap_or_else(|| self.current.clone())
    }

    /// The set a QC is verified against: the set of the epoch the block it certifies belonged to.
    fn set_for_qc(&self, qc: &QuorumCertificate) -> Arc<ValidatorSet> {
        self.set_for_vote(&qc.block_hash)
    }

    /// Recompute [`current_set`](Self::current_set) after `high_qc` or the tree moved. A
    /// `high_qc` whose block this replica cannot obtain leaves the previous set in place; the
    /// fallback in [`fallback_high_qc`](Self::fallback_high_qc) is what resolves that.
    fn refresh_current_set(&mut self) {
        // A `high_qc` certifying a block we do not hold says nothing about the epoch *its* block
        // sits in — but the committed head does, and it is always in the tree. Before review I3
        // this returned here, and since `resume` now restores a `high_qc` that is often ahead of
        // the head and whose block a fresh replica does not have, `current` stayed at the epoch-0
        // set after every restart and after every sync batch. Harmless while the set never changes,
        // wrong from the first bond or unbond: votes, new views and leaders would all be judged
        // against a set the chain has left behind.
        let anchor = match self.tree.get(&self.high_qc.block_hash) {
            Some(entry) => (entry.block.height(), self.high_qc.block_hash),
            None => (self.committed_height, self.committed_hash),
        };
        let next = anchor.0 + 1;
        let epoch = self.epoch(next);
        match self.shared_set_for_height(next, &anchor.1) {
            Some(set) => {
                self.current = set;
                self.current_epoch = epoch;
            }
            None if epoch != self.current_epoch => tracing::warn!(
                "no validator set for epoch {epoch}: still holding epoch {}'s set, so this replica \
                 cannot admit new views or lead until the epoch's set is known",
                self.current_epoch
            ),
            None => {}
        }
    }

    /// The epoch `current_set` should be for when it is not the epoch it is for — a replica that
    /// resumed past a boundary without the recorded sets. `None` when the two agree, or when the
    /// `high_qc` block is missing and the epoch is simply unknown.
    fn current_set_epoch_gap(&self) -> Option<u64> {
        // The same anchor `refresh_current_set` uses, for the same reason (review I3).
        let height = match self.tree.get(&self.high_qc.block_hash) {
            Some(entry) => entry.block.height(),
            None => self.committed_height,
        };
        let want = self.epoch(height + 1);
        (want != self.current_epoch).then_some(want)
    }

    pub fn leader(&self, view: u64) -> Address {
        self.current.leader(view)
    }
    pub fn is_leader(&self, view: u64) -> bool {
        self.address() == Some(self.leader(view))
    }
    /// The highest block this replica holds, committed or pending. A syncing node asks its peers
    /// for blocks above this rather than above its committed head: the blocks it already holds
    /// but has not committed are exactly the ones whose own proof it is still waiting for, and
    /// re-fetching them forever is how a node that cannot commit a short batch stops making
    /// progress altogether (review C2).
    pub fn pending_tip_height(&self) -> u64 {
        self.tree.values().map(|e| e.block.height()).max().unwrap_or(self.committed_height)
    }

    pub fn has_block(&self, hash: &Hash) -> bool {
        self.tree.contains_key(hash)
    }
    pub fn block(&self, hash: &Hash) -> Option<&Block> {
        self.tree.get(hash).map(|e| &e.block)
    }
    /// Ledger state on top of the block the next proposal would extend.
    pub fn tip_ledger(&self) -> &Ledger {
        self.tree
            .get(&self.high_qc.block_hash)
            .map(|e| &e.ledger_after)
            .unwrap_or(&self.committed_ledger)
    }
    pub fn safety_state(&self) -> SafetyState {
        SafetyState {
            view: self.view,
            high_qc: self.high_qc.clone(),
            locked_qc: self.locked_qc.clone(),
            last_voted_view: self.last_voted_view,
        }
    }

    /// The blocks `Action::PersistPending` carries (audit v5, CON-4): every block this replica
    /// holds on the chain from the committed head (exclusive) up to the high QC's block, and up
    /// to the locked block when the lock is not on that chain — the same set `evict_for_room`
    /// keeps — in height order, so `resume` can re-execute each on its parent. Empty when
    /// neither certified block is held (the fetch case), which storage writes as "nothing".
    pub fn certified_chain_blocks(&self) -> Vec<Block> {
        let keep = self.certified_chain();
        let mut blocks: Vec<Block> = keep
            .iter()
            .filter(|h| **h != self.committed_hash)
            .filter_map(|h| self.tree.get(h).map(|e| e.block.clone()))
            .collect();
        blocks.sort_by(|a, b| a.height().cmp(&b.height()).then_with(|| a.hash().cmp(&b.hash())));
        blocks
    }

    /// The highest QC this replica holds that certifies a block it holds (audit v5, CON-4): the
    /// head's, the lock's when the locked block is held, and every certificate a tree entry
    /// remembers for its block (a child's `justify`, or a QC that was the high QC). What
    /// `high_qc` falls to when its own block is unobtainable — never blindly the head's: a
    /// replica holding certified pending blocks above its head that fell back to the head's QC
    /// proposed a sibling of the first pending block, which nobody could vote for (chain 14,
    /// 2026-09-24).
    fn highest_held_qc(&self) -> QuorumCertificate {
        let mut best = self.head_qc.clone();
        let candidates = std::iter::once(&self.locked_qc).chain(self.tree.values().filter_map(|e| e.qc.as_ref()));
        for qc in candidates {
            if qc.view > best.view && self.tree.contains_key(&qc.block_hash) {
                best = qc.clone();
            }
        }
        best
    }

    /// Remember `qc` as the certificate of its block, when this replica holds the block. A block
    /// is certified in one view only, so the first one seen is the one.
    fn remember_qc(&mut self, qc: &QuorumCertificate) {
        if let Some(entry) = self.tree.get_mut(&qc.block_hash) {
            if entry.qc.is_none() {
                entry.qc = Some(qc.clone());
            }
        }
    }

    /// This replica's signed word that it does not hold `hash` (audit v4, CON-4), for the
    /// node's answer to a by-hash fetch it cannot serve. `None` without a signer: an observer's
    /// word carries no stake.
    pub fn not_held(&self, hash: &Hash) -> Option<NotHeld> {
        self.signer.as_ref().map(|k| NotHeld::sign(k, &self.cfg.genesis_hash, hash))
    }

    /// The stake of the current set's validators that have attested not holding `hash`.
    pub fn not_held_stake(&self, hash: &Hash) -> u128 {
        self.not_held
            .get(hash)
            .map(|signers| signers.iter().filter_map(|a| self.current.get(a)).map(|v| v.stake).sum())
            .unwrap_or(0)
    }

    /// Record a peer's signed not-held for the locked block (audit v4, CON-4). Counts only an
    /// attestation for the block this replica is locked on above its head and does not hold,
    /// from a validator of the *current* set (a member of an earlier epoch's set counts
    /// nothing), with a signature over this chain's genesis. Once the signers hold a quorum —
    /// strictly more than two thirds of the set's stake (audit v5: a third is exactly what the
    /// Byzantine validators may hold, so "more than a third" need not include anyone honest) —
    /// the block is attested unobtainable by a majority of the honest stake, and the lock is
    /// lowered to the committed head's QC, which is safe for the same reason the old unsigned
    /// fallback was: nothing above the head is committed. Returns whether the lock was released
    /// by this attestation.
    pub fn record_not_held(&mut self, n: &NotHeld) -> bool {
        let locked = self.locked_qc.block_hash;
        // Evidence for any other hash is stale — the lock moved on — or never mattered.
        self.not_held.retain(|h, _| *h == locked);
        if n.hash != locked || self.locked_qc.view <= self.head_qc.view || self.tree.contains_key(&locked) {
            return false;
        }
        let signer = n.signer.address();
        if !self.current.contains(&signer) || !n.verify(&self.cfg.genesis_hash) {
            return false;
        }
        self.not_held.entry(locked).or_default().insert(signer);
        let stake = self.not_held_stake(&locked);
        if !self.current.has_quorum(stake) {
            return false;
        }
        tracing::warn!(
            "locked block {:?} (view {}) is attested unheld by a quorum of the stake; \
             releasing the lock to the committed head QC (view {})",
            locked,
            self.locked_qc.view,
            self.head_qc.view
        );
        self.locked_qc = self.head_qc.clone();
        self.not_held.clear();
        self.unobtainable.clear();
        true
    }

    /// Action to arm the timer for the current view. Call once after construction.
    pub fn start(&mut self) -> Vec<Action> {
        let mut out = vec![self.schedule_timeout()];
        self.maybe_ready_to_propose(&mut out);
        out
    }

    /// Liveness escape hatch. If `high_qc` certifies a block this replica cannot obtain
    /// (every peer that had it is gone or unreachable), drop back to the highest QC whose
    /// block is known — the highest certified pending block it holds, else the committed head
    /// (audit v5: it used to be the head unconditionally, which made a leader holding certified
    /// pending blocks propose a sibling of the first of them). Safe: nothing past the head is
    /// committed, so no committed block can be contradicted; replicas locked on the abandoned
    /// branch simply withhold their vote until a newer QC releases their lock.
    /// Returns actions (possibly `ReadyToPropose`); an empty vec means nothing changed.
    ///
    /// The *lock* is not touched here any more (audit v4, CON-4). It used to be lowered on the
    /// same evidence — `MAX_FETCH_ATTEMPTS` failed fetches, each an unsigned `Block(None)` or a
    /// timeout from a peer chosen by an unsigned status — which let eight sybils take back any
    /// honest validator's promise. `high_qc` is liveness state and keeps this fallback; the lock
    /// is released only by [`record_not_held`](Self::record_not_held), on signed not-held from
    /// validators holding a quorum — more than two thirds of the stake. The whole-fleet-restart case that
    /// motivated the old release is covered by the persisted locked block (`resume`).
    pub fn fallback_high_qc(&mut self, unobtainable: &Hash) -> Vec<Action> {
        let mut out = Vec::new();
        if self.high_qc.block_hash != *unobtainable || self.tree.contains_key(unobtainable) {
            return out;
        }
        let held = self.highest_held_qc();
        tracing::warn!(
            "high QC (view {}) certifies an unobtainable block {:?}; falling back to the highest held QC (view {}, head view {})",
            self.high_qc.view,
            unobtainable,
            held.view,
            self.head_qc.view
        );
        self.unobtainable.insert(*unobtainable);
        self.high_qc = held;
        self.refresh_current_set();
        self.maybe_ready_to_propose(&mut out);
        out
    }

    // ---- inbound -----------------------------------------------------------

    /// `now_ms` is the replica's wall clock, carried through to proposals so a leader never
    /// stamps a block behind its parent.
    pub fn on_message(&mut self, msg: ConsensusMessage, now_ms: u64) -> Result<Vec<Action>, ConsensusError> {
        match msg {
            ConsensusMessage::Proposal(b) => self.on_proposal(b, now_ms),
            ConsensusMessage::Vote(v) => self.on_vote(v),
            ConsensusMessage::NewView(nv) => self.on_new_view(nv),
        }
    }

    pub fn on_proposal(&mut self, block: Block, now_ms: u64) -> Result<Vec<Action>, ConsensusError> {
        let mut out = Vec::new();
        let hash = block.hash();
        if self.tree.contains_key(&hash) {
            return Ok(out);
        }
        if block.view() > self.view.saturating_add(MAX_VIEW_AHEAD) {
            return Err(ConsensusError::ViewOutOfRange { view: block.view() });
        }
        // The proposal window (audit v4, CON-3): a block for a view far past this replica's is
        // refused before its signature is even checked, and is not kept as an orphan either —
        // the view moves on QCs and NewViews, and a far-behind replica catches up through sync.
        if block.view() > self.view.saturating_add(PROPOSAL_VIEW_WINDOW) {
            return Err(ConsensusError::ViewTooFarAhead { view: block.view(), current: self.view });
        }
        if block.height() <= self.committed_height {
            return Err(ConsensusError::Stale(block.height()));
        }
        if !block.verify_signature(&self.cfg.domain) {
            return Err(ConsensusError::BadSignature);
        }
        // The set of a block's epoch is derived from its branch, so the parent comes first.
        let parent_hash = block.parent();
        let Some(parent) = self.tree.get(&parent_hash) else {
            self.add_orphan(block);
            return Err(ConsensusError::UnknownParent(parent_hash));
        };
        let parent_height = parent.block.height();
        let parent_view = parent.block.view();
        let grandparent = parent.block.parent();
        // Pin the block to its parent before deriving anything from its height: the epoch of an
        // unchecked height is attacker-chosen, and each distinct one would be a fresh register
        // walk and a fresh cache entry keyed on a parent that never leaves the tree.
        if block.view() <= parent_view {
            return Err(ConsensusError::ViewNotIncreasing { block: block.view(), parent: parent_view });
        }
        if block.height() != parent_height + 1 {
            return Err(ConsensusError::BadHeight { block: block.height(), parent: parent_height });
        }
        let Some(set) = self.shared_set_for_height(block.height(), &parent_hash) else {
            return Err(ConsensusError::UnknownEpochSet(self.epoch(block.height())));
        };
        if block.proposer() != set.leader(block.view()) {
            return Err(ConsensusError::WrongLeader(block.view()));
        }
        // One block per (view, leader) (audit v4, CON-3). Checked once the signature and the
        // leader are known, so the first block is the leader's own evidence: a second, different
        // one for the same view is an equivocation, refused and logged with both hashes.
        let proposed_key = (block.view(), block.proposer());
        if let Some(first) = self.proposed.get(&proposed_key) {
            if *first != hash {
                tracing::warn!(
                    view = block.view(),
                    proposer = %block.proposer(),
                    first = ?first,
                    second = ?hash,
                    "leader equivocated: a second block for a view it already proposed in"
                );
                return Err(ConsensusError::Equivocation { view: block.view(), first: *first, second: hash });
            }
        }
        if block.header.justify.block_hash != parent_hash {
            return Err(ConsensusError::JustifyParentMismatch);
        }
        // `justify` certifies the parent, so it is the parent's own epoch that voted for it.
        let Some(parent_set) = self.shared_set_for_height(parent_height, &grandparent) else {
            return Err(ConsensusError::UnknownEpochSet(self.epoch(parent_height)));
        };
        if !block.header.justify.verify(&self.cfg.domain, &parent_set) {
            return Err(ConsensusError::BadJustify);
        }
        if block.header.justify.view != parent_view && !block.header.justify.is_genesis() {
            return Err(ConsensusError::BadJustify);
        }
        let parent = &self.tree[&parent_hash];
        // The shielded chain reads no clock: `time` is bounded in block heights (spec §7
        // item 5), so a block's timestamp constrains nothing a replica must agree on. A
        // proposer still never moves it backwards (see `propose`). The one exception is a
        // bridged chain, where block time decides guardian-set expiry and the mint-cap day —
        // `apply_block` below refuses a rewind there with `BlockError::TimestampRewind` and a
        // leap past the parent with `BlockError::TimestampLeap` (B2's step rule), which reach
        // this function's caller as `ConsensusError::Execution` like any other block rule. B2's
        // drift rule is a vote rule, applied at `try_vote` below: never a validity rule.
        let bridged = parent.ledger_after.bridge().is_some();

        // Execute on top of the parent's state. A full tree first sheds what is not on the
        // certified chain (audit v4, CON-3), so a leader's siblings can never crowd out the
        // proposal that extends the high QC.
        if self.tree.len() >= self.cfg.max_tree_blocks {
            self.evict_for_room();
        }
        if self.tree.len() >= self.cfg.max_tree_blocks {
            return Err(ConsensusError::TreeFull);
        }
        // `evict_for_room` never removes the certified chain, so the parent is still there.
        self.execute_and_insert(&block)?;
        self.refresh_current_set();

        // A valid proposal for view v moves us into view v.
        let justify = block.header.justify.clone();
        self.update_high_qc(&justify, &mut out);
        // The block the high QC already named arrived (a fetch, or an orphan's parent): the
        // certified chain is whole again, so persist it (audit v5, CON-4). `update_high_qc`
        // persists on the other order — the QC arriving after the block.
        if self.high_qc.block_hash == hash {
            out.push(Action::PersistPending(self.certified_chain_blocks()));
        }
        if block.view() > self.view {
            self.enter_view(block.view(), &mut out);
        }
        self.update_lock_and_commit(&block, &mut out);
        // B2's vote rule (bridge hardening spec §3): on a bridged chain, no vote for a block
        // more than `MAX_CLOCK_DRIFT_MS` ahead of this replica's clock. The block stays in the
        // tree — it is valid, and a quorum of validators whose clocks agree with it may still
        // certify it. Sync's replay calls the ledger's `apply_block_for_sync` itself and never
        // comes through here.
        if !(bridged && block.header.timestamp_ms > now_ms.saturating_add(super::MAX_CLOCK_DRIFT_MS)) {
            self.try_vote(&block, &mut out);
        }
        self.maybe_ready_to_propose(&mut out);

        // Children that were waiting for this block.
        if let Some(children) = self.orphans.remove(&hash) {
            self.orphan_count -= children.len();
            for child in children {
                if let Ok(more) = self.on_proposal(child, now_ms) {
                    out.extend(more);
                }
            }
        }
        Ok(out)
    }

    /// Execute `block` on its parent's state and put it in the tree: the one insertion path,
    /// shared by `on_proposal` and the locked block's restore. The parent must be in the tree.
    fn execute_and_insert(&mut self, block: &Block) -> Result<(), ConsensusError> {
        let hash = block.hash();
        let parent_hash = block.parent();
        let parent = self.tree.get(&parent_hash).ok_or(ConsensusError::UnknownParent(parent_hash))?;
        let mut ledger = parent.ledger_after.clone();
        let sidecar = self.covered_sidecar(block)?;
        // B5: the admission cache comes along — a transaction this node verified at the pool is
        // decoded here, not re-verified. Everything stateful is re-checked either way.
        let receipts = ledger.apply_block_for_sync(block, &sidecar, &[], self.executor.as_ref(), self.verified.as_ref())?;
        self.tree.insert(hash, Entry { block: block.clone(), ledger_after: ledger, receipts, qc: None });
        self.proposed.insert((block.view(), block.proposer()), hash);
        // The child's `justify` is the parent's certificate.
        self.remember_qc(&block.header.justify);
        // The block arrived: whatever was attested about not holding it is moot.
        self.not_held.remove(&hash);
        self.unobtainable.remove(&hash);
        Ok(())
    }

    pub fn on_vote(&mut self, vote: Vote) -> Result<Vec<Action>, ConsensusError> {
        let mut out = Vec::new();
        let voter = vote.voter_address();
        let set = self.set_for_vote(&vote.block_hash);
        if !set.contains(&voter) {
            return Err(ConsensusError::NotValidator);
        }
        if vote.view > self.view.saturating_add(MAX_VIEW_AHEAD) {
            return Err(ConsensusError::ViewOutOfRange { view: vote.view });
        }
        // Every validator collects votes and assembles QCs locally: relaying
        // votes only through the next leader loses the QC whenever that leader
        // is down, which breaks finality for the whole three-view pipeline.
        if vote.view < self.high_qc.view || vote.view.saturating_add(1) < self.view {
            return Ok(out); // stale
        }
        if !vote.verify(&self.cfg.domain) {
            return Err(ConsensusError::BadVote);
        }
        let key = (vote.view, vote.block_hash);
        if self.pending_votes.len() >= MAX_PENDING_VOTE_KEYS && !self.pending_votes.contains_key(&key) {
            tracing::warn!("vote-key bookkeeping full; dropping vote for view {}", vote.view);
            return Ok(out);
        }
        let votes = self.pending_votes.entry(key).or_default();
        votes.insert(voter, vote);
        let stake: u128 = votes.keys().filter_map(|a| set.get(a)).map(|v| v.stake).sum();
        if set.has_quorum(stake) {
            let qc = QuorumCertificate { view: key.0, block_hash: key.1, votes: votes.values().cloned().collect() };
            self.pending_votes.remove(&key);
            self.consecutive_timeouts = 0;
            self.update_high_qc(&qc, &mut out);
            if qc.view.saturating_add(1) > self.view {
                self.enter_view(qc.view.saturating_add(1), &mut out);
            }
            self.maybe_ready_to_propose(&mut out);
        }
        Ok(out)
    }

    pub fn on_new_view(&mut self, nv: NewView) -> Result<Vec<Action>, ConsensusError> {
        let mut out = Vec::new();
        // Admission and the quorum below are counted in `current`, so a set known to be for the
        // wrong epoch fails closed rather than refusing legitimate senders as non-validators.
        if let Some(epoch) = self.current_set_epoch_gap() {
            return Err(ConsensusError::UnknownEpochSet(epoch));
        }
        let sender = nv.sender_address();
        if !self.current.contains(&sender) {
            return Err(ConsensusError::NotValidator);
        }
        if nv.view < self.view {
            return Ok(out);
        }
        if nv.view > self.view.saturating_add(MAX_VIEW_AHEAD) {
            return Err(ConsensusError::ViewOutOfRange { view: nv.view });
        }
        if !nv.verify(&self.cfg.domain) {
            return Err(ConsensusError::BadNewView);
        }
        if !nv.high_qc.verify(&self.cfg.domain, &self.set_for_qc(&nv.high_qc)) {
            return Err(ConsensusError::BadJustify);
        }
        self.update_high_qc(&nv.high_qc.clone(), &mut out);
        let view = nv.view;
        // View synchronisation: a validator ahead of us pulls us into its view so
        // a node that started late (or was partitioned) does not have to time out
        // through every intermediate view. We echo our own NewView so the leader
        // of that view can reach quorum.
        if view > self.view {
            self.enter_view(view, &mut out);
            if let Some(key) = &self.signer {
                let mine = NewView::sign(&self.cfg.domain, view, self.high_qc.clone(), key);
                out.push(Action::Broadcast(ConsensusMessage::NewView(mine.clone())));
                if self.is_leader(view) {
                    self.record_new_view(view, mine);
                }
            }
        }
        if !self.is_leader(view) {
            return Ok(out);
        }
        self.record_new_view(view, nv);
        let Some(collected) = self.new_views.get(&view) else { return Ok(out) };
        let stake: u128 = collected.keys().filter_map(|a| self.current.get(a)).map(|v| v.stake).sum();
        if self.current.has_quorum(stake) {
            if view > self.view {
                self.enter_view(view, &mut out);
            }
            self.maybe_ready_to_propose(&mut out);
        }
        Ok(out)
    }

    /// Buffer a NewView for quorum counting, bounding how many distinct views
    /// are tracked so speculative bookkeeping stays finite.
    fn record_new_view(&mut self, view: u64, nv: NewView) {
        if self.new_views.len() >= MAX_NEW_VIEW_KEYS && !self.new_views.contains_key(&view) {
            tracing::warn!("new-view bookkeeping full; dropping NewView for view {view}");
            return;
        }
        self.new_views.entry(view).or_default().insert(nv.sender_address(), nv);
    }

    /// Pacemaker: the timer for `view` fired.
    pub fn on_timeout(&mut self, view: u64) -> Vec<Action> {
        let mut out = Vec::new();
        if view != self.view {
            return out; // stale timer
        }
        self.consecutive_timeouts += 1;
        let next = self.view.saturating_add(1);
        self.enter_view(next, &mut out);
        if let Some(key) = &self.signer {
            let nv = NewView::sign(&self.cfg.domain, next, self.high_qc.clone(), key);
            out.push(Action::Broadcast(ConsensusMessage::NewView(nv.clone())));
            if self.is_leader(next) {
                if let Ok(more) = self.on_new_view(nv) {
                    out.extend(more);
                }
            }
        }
        out
    }

    /// Build, sign and locally process a proposal for `view` at wall-clock
    /// `now_ms`. Invalid transactions are skipped rather than failing the
    /// block.
    pub fn propose(
        &mut self,
        view: u64,
        candidates: Vec<Transaction>,
        now_ms: u64,
    ) -> Result<Vec<Action>, ConsensusError> {
        let Some(signer) = &self.signer else { return Err(ConsensusError::NotReady) };
        if view != self.view || self.proposed_in_view || !self.is_leader(view) {
            return Err(ConsensusError::NotReady);
        }
        let parent_hash = self.high_qc.block_hash;
        let Some(parent) = self.tree.get(&parent_hash) else {
            return Err(ConsensusError::UnknownParent(parent_hash));
        };
        // Lead the epoch of the block being built, which is the parent's only mid-epoch.
        let height = parent.block.height() + 1;
        match self.shared_set_for_height(height, &parent_hash) {
            Some(set) if set.leader(view) == signer.address() => {}
            _ => return Err(ConsensusError::NotReady),
        }
        // Block time never moves backwards, whatever this leader's clock says:
        // a lagging clock would otherwise produce a block its peers reject. On a bridged chain
        // it never steps more than `MAX_TIMESTAMP_STEP_MS` past the parent either (B2): after a
        // stall the chain's time catches up a step per block instead of leaping.
        let parent_ms = parent.block.header.timestamp_ms;
        let mut timestamp_ms = now_ms.max(parent_ms);
        if parent.ledger_after.bridge().is_some() {
            timestamp_ms = timestamp_ms.min(parent_ms.saturating_add(crate::ledger::MAX_TIMESTAMP_STEP_MS));
        }
        let mut ledger = parent.ledger_after.clone();
        ledger.set_height(parent.block.height() + 1);
        // Select against the time this block will carry, so a validator
        // re-applying it through `apply_block` reaches the same verdict.
        ledger.set_timestamp_ms(timestamp_ms);
        let mut txs = Vec::with_capacity(candidates.len());
        let me = signer.address();
        // The aggregate selection (spec §3.4): at most one `Aggregate` per block — the largest
        // cover set among the candidates that apply, ties to the lowest proof hash. The rest
        // stay pooled for a later block; a cover set the store cannot cover skips its own
        // candidate, never the block.
        let mut aggregates: Vec<(usize, crate::types::Transaction)> = Vec::new();
        let mut ordinary = Vec::new();
        for (i, tx) in candidates.into_iter().enumerate() {
            if matches!(tx.action, crate::types::Action::Aggregate { .. }) {
                aggregates.push((i, tx));
            } else {
                ordinary.push(tx);
            }
        }
        aggregates.sort_by(|(_, a), (_, b)| {
            let (crate::types::Action::Aggregate { covers: ca, proof: pa, .. }, crate::types::Action::Aggregate { covers: cb, proof: pb, .. }) =
                (&a.action, &b.action)
            else {
                unreachable!("filtered above")
            };
            cb.len().cmp(&ca.len()).then_with(|| Hash::digest(pa).cmp(&Hash::digest(pb)))
        });
        for tx in ordinary {
            // Apply on a trial clone: a transaction that fails part-way through
            // must not leave the cumulative ledger dirty for the next candidate
            // or for the state root committed to the header. B5: with the admission
            // cache along, a candidate's proofs are not verified a second time here.
            let mut trial = ledger.clone();
            if trial.apply_tx_with(&tx, &me, self.executor.as_ref(), self.verified.as_ref()).is_ok() {
                ledger = trial;
                txs.push(tx);
            }
        }
        // The aggregate's trial apply runs where its place in the block is: after the ordinary
        // transactions, so the proposer's state root is the one every validator recomputes in
        // list order.
        for (_, tx) in aggregates {
            let crate::types::Action::Aggregate { covers, .. } = &tx.action else { unreachable!() };
            let Some(c) = self.covered.as_ref().and_then(|s| s.covered(covers)) else { continue };
            let mut trial = ledger.clone();
            if trial.apply_aggregate(&tx, &c, self.executor.as_ref()).is_ok() {
                ledger = trial;
                txs.push(tx);
                break;
            }
        }
        // The same block-end steps `apply_block_for_sync` runs before it recomputes the root.
        ledger.close_block(height, &me);
        let header = BlockHeader {
            height: parent.block.height() + 1,
            view,
            parent: parent_hash,
            proposer: signer.public_key().clone(),
            timestamp_ms,
            tx_root: Block::tx_root(&txs),
            state_root: ledger.state_root(),
            justify: self.high_qc.clone(),
        };
        let block = Block::sign(&self.cfg.domain, header, txs, signer);
        self.proposed_in_view = true;
        let mut out = vec![Action::Broadcast(ConsensusMessage::Proposal(block.clone()))];
        // The leader's own clock is "now": its vote on its own block follows B2's drift rule
        // like any validator's. `timestamp_ms` exceeds `now_ms` only when the parent already
        // did (monotonicity), so a leader withholds its own vote only when its clock lags the
        // certified parent by more than the drift bound. `now_ms` is read nowhere else here.
        out.extend(self.on_proposal(block, now_ms)?);
        Ok(out)
    }

    // ---- internals ---------------------------------------------------------

    fn timeout_for(&self) -> Duration {
        let mult = 1u32 << self.consecutive_timeouts.min(10);
        (self.cfg.base_timeout * mult).min(self.cfg.max_timeout)
    }

    fn schedule_timeout(&self) -> Action {
        Action::ScheduleTimeout { view: self.view, duration: self.timeout_for() }
    }

    fn enter_view(&mut self, view: u64, out: &mut Vec<Action>) {
        debug_assert!(view > self.view);
        self.view = view;
        self.proposed_in_view = false;
        // drop stale bookkeeping
        self.new_views = self.new_views.split_off(&view);
        let keep = self.pending_votes.split_off(&(view.saturating_sub(1), Hash::ZERO));
        self.pending_votes = keep;
        out.push(self.schedule_timeout());
    }

    fn update_high_qc(&mut self, qc: &QuorumCertificate, out: &mut Vec<Action>) {
        self.remember_qc(qc);
        // A QC on a block that proved unobtainable is not believed again until the block turns
        // up: raising the high QC to it would only send this replica back to the fetch that
        // already failed everywhere, and — re-announced by every NewView — keep it there.
        if self.unobtainable.contains(&qc.block_hash) && !self.tree.contains_key(&qc.block_hash) {
            return;
        }
        if qc.view > self.high_qc.view {
            self.high_qc = qc.clone();
            self.refresh_current_set();
            // The certified chain grew by a block this replica holds: persist it (audit v5,
            // CON-4). A QC on a block not held persists nothing new — the block arrives through
            // `on_proposal`, which persists then.
            if self.tree.contains_key(&qc.block_hash) {
                out.push(Action::PersistPending(self.certified_chain_blocks()));
            }
        }
    }

    /// Leader of the current view proposes once it holds a QC for view-1 or a
    /// quorum of NewView messages for this view, and knows the block to extend.
    fn maybe_ready_to_propose(&mut self, out: &mut Vec<Action>) {
        if self.signer.is_none() || self.proposed_in_view || !self.is_leader(self.view) {
            return;
        }
        let have_qc = self.high_qc.view.saturating_add(1) == self.view;
        let have_new_views = self
            .new_views
            .get(&self.view)
            .map(|m| {
                let stake: u128 = m.keys().filter_map(|a| self.current.get(a)).map(|v| v.stake).sum();
                self.current.has_quorum(stake)
            })
            .unwrap_or(false);
        if !(have_qc || have_new_views) {
            return;
        }
        if !self.tree.contains_key(&self.high_qc.block_hash) {
            out.push(Action::FetchBlock(self.high_qc.block_hash));
            return;
        }
        if !out.iter().any(|a| matches!(a, Action::ReadyToPropose { .. })) {
            out.push(Action::ReadyToPropose { view: self.view });
        }
    }

    /// Chained HotStuff lock and three-chain commit rules, evaluated on `b_star`.
    fn update_lock_and_commit(&mut self, b_star: &Block, out: &mut Vec<Action>) {
        // b'' is certified by b*.justify; b' by b''.justify; b by b'.justify.
        let b2_hash = b_star.header.justify.block_hash;
        let Some(b2) = self.tree.get(&b2_hash) else { return };
        let b2_justify = b2.block.header.justify.clone();
        if b2_justify.view > self.locked_qc.view {
            self.locked_qc = b2_justify.clone();
        }
        let b1_hash = b2_justify.block_hash;
        let Some(b1) = self.tree.get(&b1_hash) else { return };
        let b1_justify = b1.block.header.justify.clone();
        let b_hash = b1_justify.block_hash;
        let Some(b) = self.tree.get(&b_hash) else { return };
        // Chained HotStuff commit rule: the QCs certifying b, b1 and b2 must sit in
        // three consecutive views. Parent links are already enforced to equal justify
        // links, so this is a three-chain — but without the view check two forks can
        // ratchet past each other's locks (each new QC's justify outranks the other's
        // lock) and finalize conflicting blocks at the same height.
        let qc_b = b1_justify.view;
        let qc_b1 = b2_justify.view;
        let qc_b2 = b_star.header.justify.view;
        if qc_b1 != qc_b.saturating_add(1) || qc_b2 != qc_b1.saturating_add(1) {
            return;
        }
        let target_height = b.block.height();
        if target_height <= self.committed_height {
            return;
        }
        // Collect the path from committed head (exclusive) to b (inclusive).
        let mut path: Vec<(Hash, QuorumCertificate)> = Vec::new();
        let mut cur = b_hash;
        let mut cert = b1_justify; // certifies b
        loop {
            let entry = self.tree.get(&cur).expect("ancestor present");
            if entry.block.height() <= self.committed_height {
                break;
            }
            path.push((cur, cert.clone()));
            cert = entry.block.header.justify.clone();
            cur = entry.block.parent();
        }
        if cur != self.committed_hash {
            // b does not descend from our committed head. Every ancestor on this path was in the
            // tree (the walk above would have panicked otherwise), so this is not "we are behind":
            // it is a certified three-chain on a branch that contradicts what this replica has
            // already committed. Ignoring it left the node serving a finality answer it had just
            // been shown to be wrong about, which is how a double-spend against this node's users
            // goes unnoticed. Hand it to the node layer as fatal.
            tracing::error!(
                committed = ?self.committed_hash,
                attempted = ?b_hash,
                "commit path does not reach the committed head: conflicting finality"
            );
            out.push(Action::SafetyViolation { committed: self.committed_hash, attempted: b_hash });
            return;
        }
        path.reverse();
        let mut committed = Vec::with_capacity(path.len());
        for (h, qc) in path {
            let e = &self.tree[&h];
            committed.push(CommittedBlock {
                block: e.block.clone(),
                pruned: Vec::new(),
                qc,
                receipts: e.receipts.clone(),
                // The ledger *after* this block holds exactly this block's deposits:
                // `apply_transactions` clears the list when a block starts.
                deposits: e.ledger_after.deposits().to_vec(),
            });
        }
        // The first block of an epoch fixes that epoch's set for good: record it while its
        // branch is still in the tree, so a later replay can verify its QCs (spec §8).
        let epoch_blocks = self.cfg.epoch_blocks.max(1);
        let mut recorded = Vec::new();
        for cb in &committed {
            let height = cb.block.height();
            if height == 0 || height % epoch_blocks != 0 {
                continue;
            }
            let epoch = self.epoch(height);
            if self.epoch_sets.get(epoch).is_some() {
                continue;
            }
            let Some(set) = self.set_for_height(height, &cb.block.parent()) else {
                // The node persists this for replay; losing it means old QCs become unverifiable.
                tracing::error!("committed block {height} starts epoch {epoch} with no derivable set");
                continue;
            };
            self.epoch_sets.insert(epoch, set.clone());
            recorded.push(Action::RecordEpochSet(epoch, set));
        }
        let head = committed.last().expect("non-empty");
        self.committed_height = head.block.height();
        self.committed_hash = head.block.hash();
        self.head_qc = head.qc.clone();
        self.committed_ledger = self.tree[&self.committed_hash].ledger_after.clone();
        self.epoch_sets.forget_before(self.epoch(self.committed_height).saturating_sub(EPOCH_SETS_KEPT));
        self.prune();
        self.not_held.clear();
        self.unobtainable.clear();
        self.refresh_current_set();
        out.extend(recorded);
        out.push(Action::Commit(committed));
        // What is certified above the new head, after the prune (audit v5, CON-4) — written
        // after the commit, so a crash between the two leaves a set that starts at the new head.
        out.push(Action::PersistPending(self.certified_chain_blocks()));
    }

    fn prune(&mut self) {
        let h = self.committed_height;
        let keep = self.committed_hash;
        self.tree.retain(|hash, e| *hash == keep || e.block.height() > h);
        self.drop_unreachable();
        self.orphans.retain(|_, v| {
            v.retain(|b| b.height() > h);
            !v.is_empty()
        });
        self.orphan_count = self.orphans.values().map(|v| v.len()).sum();
        // The equivocation record follows the tree: entries at or under the committed head's
        // view are decided, and a pruned dead branch's entries go with its blocks.
        let head_view = self.tree.get(&keep).map(|e| e.block.view()).unwrap_or(0);
        let tree = &self.tree;
        self.proposed.retain(|(view, _), hash| *view > head_view && tree.contains_key(hash));
    }

    /// Drop every tree entry that no longer descends from the committed head, and the derived
    /// sets whose epoch-start parent went with them (an epoch whose first block has committed,
    /// so `epoch_sets` answers for it).
    fn drop_unreachable(&mut self) {
        let keep = self.committed_hash;
        let mut alive: std::collections::HashSet<Hash> = std::collections::HashSet::new();
        alive.insert(keep);
        let mut changed = true;
        while changed {
            changed = false;
            for (hash, e) in &self.tree {
                if !alive.contains(hash) && alive.contains(&e.block.parent()) {
                    alive.insert(*hash);
                    changed = true;
                }
            }
        }
        self.tree.retain(|hash, _| alive.contains(hash));
        let tree = &self.tree;
        self.derived().retain(|(_, start), _| tree.contains_key(start));
    }

    /// The blocks a full tree must keep (audit v4, CON-3): the committed head, and the chains
    /// from the high QC's block and the locked block down to it — what the next honest proposal
    /// extends, and what the vote rule checks against. Everything else is uncertified
    /// speculation a peer can re-send.
    fn certified_chain(&self) -> std::collections::HashSet<Hash> {
        let mut keep = std::collections::HashSet::new();
        keep.insert(self.committed_hash);
        for start in [self.high_qc.block_hash, self.locked_qc.block_hash] {
            let mut cur = start;
            while let Some(e) = self.tree.get(&cur) {
                if !keep.insert(cur) {
                    break;
                }
                cur = e.block.parent();
            }
        }
        keep
    }

    /// Make room in a full tree: evict blocks off the certified chain, oldest view first, until
    /// the tree is under `max_tree_blocks` — then whatever descended from an evicted block, since
    /// it no longer reaches the head. Their `proposed` entries go with them. A tree that is all
    /// certified chain evicts nothing, and the caller refuses with `TreeFull` as before.
    fn evict_for_room(&mut self) {
        let keep = self.certified_chain();
        let mut candidates: Vec<(u64, Hash)> =
            self.tree.iter().filter(|(h, _)| !keep.contains(*h)).map(|(h, e)| (e.block.view(), *h)).collect();
        candidates.sort();
        let mut evicted = 0usize;
        for (_, h) in candidates {
            if self.tree.len() < self.cfg.max_tree_blocks {
                break;
            }
            self.tree.remove(&h);
            evicted += 1;
        }
        if evicted == 0 {
            return;
        }
        self.drop_unreachable();
        let tree = &self.tree;
        self.proposed.retain(|_, hash| tree.contains_key(hash));
        tracing::warn!(
            evicted,
            held = self.tree.len(),
            "speculative tree full: evicted off-chain blocks, oldest view first (audit v4 CON-3)"
        );
    }

    fn extends_locked(&self, block: &Block) -> bool {
        let locked_hash = self.locked_qc.block_hash;
        let Some(locked) = self.tree.get(&locked_hash) else {
            // A locked block at or under the committed head's QC is committed (and pruned from the
            // tree): everything we hold descends from the head, so the promise is kept.
            //
            // A locked block *above* it that this replica does not hold is the CON-1b case: the
            // lock was restored from disk by `resume`, or the block was dropped, and this replica
            // cannot tell whether `block` descends from it. Answering "true" there would be voting
            // blind on a promise it cannot check, so it answers false and fetches the block; the
            // vote follows on the replay once the branch is known, or a newer justify releases the
            // lock on its own (`try_vote`'s first disjunct).
            return self.locked_qc.view <= self.head_qc.view;
        };
        let locked_height = locked.block.height();
        let mut cur = block.hash();
        loop {
            if cur == locked_hash {
                return true;
            }
            let Some(e) = self.tree.get(&cur) else { return false };
            if e.block.height() <= locked_height {
                return false;
            }
            cur = e.block.parent();
        }
    }

    fn try_vote(&mut self, block: &Block, out: &mut Vec<Action>) {
        let Some(signer) = &self.signer else { return };
        if block.view() <= self.last_voted_view || block.view() != self.view {
            return;
        }
        // A validator outside this block's epoch observes: its vote would be refused anyway, and
        // it keeps its signer so the next epoch's register can admit it again (spec §8).
        let in_set = self
            .shared_set_for_height(block.height(), &block.parent())
            .is_some_and(|s| s.contains(&signer.address()));
        if !in_set {
            return;
        }
        let safe = block.header.justify.view > self.locked_qc.view || self.extends_locked(block);
        if !safe {
            // Fetch the locked block when the lock is the reason we are silent and we do not hold
            // it: without this a restored lock would stall this replica until a newer QC arrives.
            if !self.tree.contains_key(&self.locked_qc.block_hash) && self.locked_qc.view > self.head_qc.view {
                out.push(Action::FetchBlock(self.locked_qc.block_hash));
            }
            return;
        }
        self.last_voted_view = block.view();
        out.push(Action::PersistSafety(self.safety_state()));
        let vote = Vote::sign(&self.cfg.domain, block.view(), block.hash(), signer);
        // Votes are broadcast and every validator assembles the QC locally
        // (see `on_vote`). Relaying only to the next leader would strand the
        // QC — and the finality pipeline behind it — whenever that leader is
        // unreachable. Count our own vote immediately.
        if let Ok(more) = self.on_vote(vote.clone()) {
            out.extend(more);
        }
        out.push(Action::Broadcast(ConsensusMessage::Vote(vote)));
    }

    /// Buffer a block whose parent is unknown. The caller receives
    /// `ConsensusError::UnknownParent(parent)` and is responsible for fetching it
    /// (or batch-syncing); once the parent arrives via `on_proposal` the orphan is replayed.
    fn add_orphan(&mut self, block: Block) {
        if self.orphan_count >= self.cfg.max_orphans {
            return;
        }
        let parent = block.parent();
        self.orphans.entry(parent).or_default().push(block);
        self.orphan_count += 1;
    }
}
