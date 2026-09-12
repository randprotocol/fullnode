use super::{Action, CommittedBlock, ConsensusConfig, ConsensusError, ConsensusMessage, EpochSets, NewView, SafetyState};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{Address, Hash, Keypair};
use crate::ledger::Ledger;
use crate::types::{Block, BlockHeader, QuorumCertificate, Transaction, ValidatorSet, Vote};
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
}

/// Chained HotStuff replica. Validators hold a `signer`; observing full nodes do not.
pub struct HotStuff {
    cfg: ConsensusConfig,
    signer: Option<Keypair>,
    executor: Arc<dyn ConfidentialExecutor>,

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
        Self::resume(cfg, signer, genesis_block, qc, genesis_ledger, None, epoch_sets, executor)
    }

    /// Resume from a committed head plus persisted safety state and the epoch sets storage holds.
    ///
    /// A signer whose key is not in the current set is kept: it observes — no votes, no proposals
    /// — until an epoch's register admits it again (spec §8), which is how a validator that
    /// unbonded below the minimum, or one that bonded mid-epoch, rejoins.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        cfg: ConsensusConfig,
        signer: Option<Keypair>,
        head: Block,
        head_qc: QuorumCertificate,
        head_ledger: Ledger,
        safety: Option<SafetyState>,
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
        // restart and the second new block is refused with `bundle time N is outside [0, 0]`.
        let head_hash = head.hash();
        let head_height = head.height();
        let mut head_ledger = head_ledger;
        head_ledger.set_height(head_height);
        head_ledger.set_timestamp_ms(head.header.timestamp_ms);
        let mut tree = HashMap::new();
        tree.insert(head_hash, Entry { block: head, ledger_after: head_ledger.clone(), receipts: Vec::new() });
        let (view, high_qc, locked_qc, last_voted_view) = match safety {
            Some(s) => {
                let view = s.view.max(head_qc.view.saturating_add(1));
                (view, head_qc.clone(), head_qc.clone(), s.last_voted_view)
            }
            None => (head_qc.view.saturating_add(1), head_qc.clone(), head_qc.clone(), 0),
        };
        let current = epoch_sets.shared(0).expect("epoch 0 is seeded above");
        let mut hs = HotStuff {
            cfg,
            signer,
            executor,
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
            pending_votes: BTreeMap::new(),
            new_views: BTreeMap::new(),
            epoch_sets,
            derived: Mutex::new(HashMap::new()),
            current,
            current_epoch: 0,
        };
        hs.refresh_current_set();
        if let Some(s) = &hs.signer {
            if !hs.current.contains(&s.address()) {
                tracing::info!("{} is not in the current validator set; observing until an epoch admits it", s.address());
            }
        }
        hs
    }

    // ---- accessors ---------------------------------------------------------

    pub fn view(&self) -> u64 {
        self.view
    }
    pub fn high_qc(&self) -> &QuorumCertificate {
        &self.high_qc
    }
    pub fn committed_height(&self) -> u64 {
        self.committed_height
    }
    pub fn committed_hash(&self) -> Hash {
        self.committed_hash
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
        let register = entry.ledger_after.derive_next_set();
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
        // A `high_qc` certifying a block we cannot obtain says nothing about the epoch; the
        // fallback resolves it, and `current_set_epoch_gap` reports nothing in the meantime.
        let Some(entry) = self.tree.get(&self.high_qc.block_hash) else { return };
        let next = entry.block.height() + 1;
        let epoch = self.epoch(next);
        match self.shared_set_for_height(next, &self.high_qc.block_hash) {
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
        let entry = self.tree.get(&self.high_qc.block_hash)?;
        let want = self.epoch(entry.block.height() + 1);
        (want != self.current_epoch).then_some(want)
    }

    pub fn leader(&self, view: u64) -> Address {
        self.current.leader(view)
    }
    pub fn is_leader(&self, view: u64) -> bool {
        self.address() == Some(self.leader(view))
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

    /// Action to arm the timer for the current view. Call once after construction.
    pub fn start(&mut self) -> Vec<Action> {
        let mut out = vec![self.schedule_timeout()];
        self.maybe_ready_to_propose(&mut out);
        out
    }

    /// Liveness escape hatch. If `high_qc` certifies a block this replica cannot obtain
    /// (every peer that had it is gone or unreachable), drop back to the highest QC whose
    /// block is known: the committed head. Safe: nothing past the head is committed, so no
    /// committed block can be contradicted; replicas locked on the abandoned branch simply
    /// withhold their vote until a newer QC releases their lock.
    /// Returns actions (possibly `ReadyToPropose`); an empty vec means nothing changed.
    pub fn fallback_high_qc(&mut self, unobtainable: &Hash) -> Vec<Action> {
        let mut out = Vec::new();
        if self.high_qc.block_hash != *unobtainable || self.tree.contains_key(unobtainable) {
            return out;
        }
        tracing::warn!(
            "high QC (view {}) certifies an unobtainable block {:?}; falling back to the committed head QC (view {})",
            self.high_qc.view,
            unobtainable,
            self.head_qc.view
        );
        self.high_qc = self.head_qc.clone();
        if self.locked_qc.view > self.head_qc.view && !self.tree.contains_key(&self.locked_qc.block_hash) {
            self.locked_qc = self.head_qc.clone();
        }
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
        if block.height() <= self.committed_height {
            return Err(ConsensusError::Stale(block.height()));
        }
        if !block.verify_signature() {
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
        if block.header.justify.block_hash != parent_hash {
            return Err(ConsensusError::JustifyParentMismatch);
        }
        // `justify` certifies the parent, so it is the parent's own epoch that voted for it.
        let Some(parent_set) = self.shared_set_for_height(parent_height, &grandparent) else {
            return Err(ConsensusError::UnknownEpochSet(self.epoch(parent_height)));
        };
        if !block.header.justify.verify(&parent_set, &self.cfg.genesis_hash) {
            return Err(ConsensusError::BadJustify);
        }
        if block.header.justify.view != parent_view && !block.header.justify.is_genesis() {
            return Err(ConsensusError::BadJustify);
        }
        let parent = &self.tree[&parent_hash];
        // The shielded chain reads no clock: `time` is bounded in block heights (spec §7
        // item 5), so a block's timestamp constrains nothing a replica must agree on. A
        // proposer still never moves it backwards (see `propose`).

        // Execute on top of the parent's state.
        if self.tree.len() >= self.cfg.max_tree_blocks {
            return Err(ConsensusError::TreeFull);
        }
        let mut ledger = parent.ledger_after.clone();
        let receipts = ledger.apply_block(&block, self.executor.as_ref())?;
        self.tree.insert(hash, Entry { block: block.clone(), ledger_after: ledger, receipts });
        self.refresh_current_set();

        // A valid proposal for view v moves us into view v.
        let justify = block.header.justify.clone();
        self.update_high_qc(&justify, &mut out);
        if block.view() > self.view {
            self.enter_view(block.view(), &mut out);
        }
        self.update_lock_and_commit(&block, &mut out);
        self.try_vote(&block, &mut out);
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
        if !vote.verify() {
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
        if !nv.verify() {
            return Err(ConsensusError::BadNewView);
        }
        if !nv.high_qc.verify(&self.set_for_qc(&nv.high_qc), &self.cfg.genesis_hash) {
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
                let mine = NewView::sign(view, self.high_qc.clone(), key);
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
            let nv = NewView::sign(next, self.high_qc.clone(), key);
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
        // a lagging clock would otherwise produce a block its peers reject.
        let timestamp_ms = now_ms.max(parent.block.header.timestamp_ms);
        let mut ledger = parent.ledger_after.clone();
        ledger.set_height(parent.block.height() + 1);
        // Select against the time this block will carry, so a validator
        // re-applying it through `apply_block` reaches the same verdict.
        ledger.set_timestamp_ms(timestamp_ms);
        let mut txs = Vec::with_capacity(candidates.len());
        let me = signer.address();
        for tx in candidates {
            // Apply on a trial clone: a transaction that fails part-way through
            // must not leave the cumulative ledger dirty for the next candidate
            // or for the state root committed to the header.
            let mut trial = ledger.clone();
            if trial.apply_tx(&tx, &me, self.executor.as_ref()).is_ok() {
                ledger = trial;
                txs.push(tx);
            }
        }
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
        let block = Block::sign(header, txs, signer);
        self.proposed_in_view = true;
        let mut out = vec![Action::Broadcast(ConsensusMessage::Proposal(block.clone()))];
        // The block may carry the parent's later time rather than this clock's,
        // so feed its own time as "now": a leader never rejects the proposal it
        // just built, and `timestamp_ms >= now_ms` makes this no weaker.
        out.extend(self.on_proposal(block, timestamp_ms)?);
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

    fn update_high_qc(&mut self, qc: &QuorumCertificate, _out: &mut Vec<Action>) {
        if qc.view > self.high_qc.view {
            self.high_qc = qc.clone();
            self.refresh_current_set();
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
            // b does not descend from our committed head: safety violation or we are behind.
            tracing::error!("commit path does not reach committed head; ignoring");
            return;
        }
        path.reverse();
        let mut committed = Vec::with_capacity(path.len());
        for (h, qc) in path {
            let e = &self.tree[&h];
            committed.push(CommittedBlock {
                block: e.block.clone(),
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
        self.refresh_current_set();
        out.extend(recorded);
        out.push(Action::Commit(committed));
    }

    fn prune(&mut self) {
        let h = self.committed_height;
        let keep = self.committed_hash;
        self.tree.retain(|hash, e| *hash == keep || e.block.height() > h);
        // Anything not descending from the committed head is dead.
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
        self.orphans.retain(|_, v| {
            v.retain(|b| b.height() > h);
            !v.is_empty()
        });
        self.orphan_count = self.orphans.values().map(|v| v.len()).sum();
        // A derived set whose epoch-start parent is gone is an epoch whose first block has
        // committed, so `epoch_sets` now answers for it.
        let tree = &self.tree;
        self.derived().retain(|(_, start), _| tree.contains_key(start));
    }

    fn extends_locked(&self, block: &Block) -> bool {
        let locked_hash = self.locked_qc.block_hash;
        let Some(locked) = self.tree.get(&locked_hash) else {
            // Locked block is committed (pruned) or unknown; everything we hold descends from the head.
            return true;
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
            return;
        }
        self.last_voted_view = block.view();
        out.push(Action::PersistSafety(self.safety_state()));
        let vote = Vote::sign(block.view(), block.hash(), signer);
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
