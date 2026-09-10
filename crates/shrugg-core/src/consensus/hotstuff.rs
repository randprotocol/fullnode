use super::{
    Action, CommittedBlock, ConsensusConfig, ConsensusError, ConsensusMessage, NewView, SafetyState,
    MAX_CLOCK_SKEW_MS,
};
use crate::confidential::ConfidentialExecutor;
use crate::crypto::{Address, Hash, Keypair};
use crate::ledger::{BlockError, Ledger};
use crate::types::{Block, BlockHeader, QuorumCertificate, Transaction, Vote};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

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
        Self::resume(cfg, signer, genesis_block, qc, genesis_ledger, None, executor)
    }

    /// Resume from a committed head plus persisted safety state.
    pub fn resume(
        cfg: ConsensusConfig,
        signer: Option<Keypair>,
        head: Block,
        head_qc: QuorumCertificate,
        head_ledger: Ledger,
        safety: Option<SafetyState>,
        executor: Arc<dyn ConfidentialExecutor>,
    ) -> HotStuff {
        if let Some(s) = &signer {
            assert!(cfg.validators.contains(&s.address()), "signer must be a validator");
        }
        // A loaded ledger carries no block time; bridge validation against the
        // tip would then see `now = 0` and treat every guardian set as fresh.
        let mut head_ledger = head_ledger;
        head_ledger.set_timestamp_ms(head.header.timestamp_ms);
        let head_hash = head.hash();
        let head_height = head.height();
        let mut tree = HashMap::new();
        tree.insert(head_hash, Entry { block: head, ledger_after: head_ledger.clone(), receipts: Vec::new() });
        let (view, high_qc, locked_qc, last_voted_view) = match safety {
            Some(s) => {
                let view = s.view.max(head_qc.view + 1);
                (view, head_qc.clone(), head_qc.clone(), s.last_voted_view)
            }
            None => (head_qc.view + 1, head_qc.clone(), head_qc.clone(), 0),
        };
        HotStuff {
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
        }
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
    pub fn leader(&self, view: u64) -> Address {
        self.cfg.validators.leader(view)
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
        self.maybe_ready_to_propose(&mut out);
        out
    }

    // ---- inbound -----------------------------------------------------------

    /// `now_ms` is the replica's wall clock, used only to bound how far ahead
    /// a bridged chain's block timestamp may be (see [`MAX_CLOCK_SKEW_MS`]).
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
        if block.height() <= self.committed_height {
            return Err(ConsensusError::Stale(block.height()));
        }
        if block.proposer() != self.leader(block.view()) {
            return Err(ConsensusError::WrongLeader(block.view()));
        }
        if !block.verify_signature() {
            return Err(ConsensusError::BadSignature);
        }
        if block.header.justify.block_hash != block.parent() {
            return Err(ConsensusError::JustifyParentMismatch);
        }
        if !block.header.justify.verify(&self.cfg.validators, &self.cfg.genesis_hash) {
            return Err(ConsensusError::BadJustify);
        }
        let parent_hash = block.parent();
        let Some(parent) = self.tree.get(&parent_hash) else {
            self.add_orphan(block);
            return Err(ConsensusError::UnknownParent(parent_hash));
        };
        if block.view() <= parent.block.view() {
            return Err(ConsensusError::ViewNotIncreasing { block: block.view(), parent: parent.block.view() });
        }
        if block.height() != parent.block.height() + 1 {
            return Err(ConsensusError::BadHeight { block: block.height(), parent: parent.block.height() });
        }
        if block.header.justify.view != parent.block.view() && !block.header.justify.is_genesis() {
            return Err(ConsensusError::BadJustify);
        }
        // On a bridged chain the timestamp is consensus input, so it is bounded
        // on both sides before we vote: never behind the parent (`apply_block`
        // enforces the same rule, but rejecting here keeps an invalid proposal
        // out of the tree without executing it), and never further than
        // `MAX_CLOCK_SKEW_MS` ahead of this replica's clock, so a leader can
        // neither revive an expired guardian set nor expire a live one. Chains
        // without a bridge keep their previous validity rules exactly.
        if parent.ledger_after.bridge().is_some() {
            let (parent_ts, block_ts) = (parent.block.header.timestamp_ms, block.header.timestamp_ms);
            if block_ts < parent_ts {
                return Err(BlockError::TimestampRewind { parent: parent_ts, block: block_ts }.into());
            }
            if block_ts > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
                return Err(ConsensusError::TimestampTooFarAhead { block: block_ts, now: now_ms });
            }
        }

        // Execute on top of the parent's state.
        let mut ledger = parent.ledger_after.clone();
        let receipts = ledger.apply_block(&block, self.executor.as_ref())?;
        self.tree.insert(hash, Entry { block: block.clone(), ledger_after: ledger, receipts });

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
        if !self.cfg.validators.contains(&voter) {
            return Err(ConsensusError::NotValidator);
        }
        if !self.is_leader(vote.view + 1) {
            return Err(ConsensusError::NotLeader);
        }
        if vote.view < self.high_qc.view || vote.view + 1 < self.view {
            return Ok(out); // stale
        }
        if !vote.verify() {
            return Err(ConsensusError::BadVote);
        }
        let key = (vote.view, vote.block_hash);
        let votes = self.pending_votes.entry(key).or_default();
        votes.insert(voter, vote);
        let stake: u128 = votes.keys().filter_map(|a| self.cfg.validators.get(a)).map(|v| v.stake).sum();
        if self.cfg.validators.has_quorum(stake) {
            let qc = QuorumCertificate { view: key.0, block_hash: key.1, votes: votes.values().cloned().collect() };
            self.pending_votes.remove(&key);
            self.consecutive_timeouts = 0;
            self.update_high_qc(&qc, &mut out);
            if qc.view + 1 > self.view {
                self.enter_view(qc.view + 1, &mut out);
            }
            self.maybe_ready_to_propose(&mut out);
        }
        Ok(out)
    }

    pub fn on_new_view(&mut self, nv: NewView) -> Result<Vec<Action>, ConsensusError> {
        let mut out = Vec::new();
        let sender = nv.sender_address();
        if !self.cfg.validators.contains(&sender) {
            return Err(ConsensusError::NotValidator);
        }
        if nv.view < self.view {
            return Ok(out);
        }
        if !nv.verify() {
            return Err(ConsensusError::BadNewView);
        }
        if !nv.high_qc.verify(&self.cfg.validators, &self.cfg.genesis_hash) {
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
                    self.new_views.entry(view).or_default().insert(mine.sender_address(), mine);
                }
            }
        }
        if !self.is_leader(view) {
            return Ok(out);
        }
        self.new_views.entry(view).or_default().insert(sender, nv);
        let stake: u128 = self.new_views[&view]
            .keys()
            .filter_map(|a| self.cfg.validators.get(a))
            .map(|v| v.stake)
            .sum();
        if self.cfg.validators.has_quorum(stake) {
            if view > self.view {
                self.enter_view(view, &mut out);
            }
            self.maybe_ready_to_propose(&mut out);
        }
        Ok(out)
    }

    /// Pacemaker: the timer for `view` fired.
    pub fn on_timeout(&mut self, view: u64) -> Vec<Action> {
        let mut out = Vec::new();
        if view != self.view {
            return out; // stale timer
        }
        self.consecutive_timeouts += 1;
        let next = self.view + 1;
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
            if ledger.apply_tx(&tx, &me, self.executor.as_ref()).is_ok() {
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
        }
    }

    /// Leader of the current view proposes once it holds a QC for view-1 or a
    /// quorum of NewView messages for this view, and knows the block to extend.
    fn maybe_ready_to_propose(&mut self, out: &mut Vec<Action>) {
        if self.signer.is_none() || self.proposed_in_view || !self.is_leader(self.view) {
            return;
        }
        let have_qc = self.high_qc.view + 1 == self.view;
        let have_new_views = self
            .new_views
            .get(&self.view)
            .map(|m| {
                let stake: u128 = m.keys().filter_map(|a| self.cfg.validators.get(a)).map(|v| v.stake).sum();
                self.cfg.validators.has_quorum(stake)
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
        // parent links are enforced to equal justify links, so this is a three-chain.
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
            committed.push(CommittedBlock { block: e.block.clone(), qc, receipts: e.receipts.clone() });
        }
        let head = committed.last().expect("non-empty");
        self.committed_height = head.block.height();
        self.committed_hash = head.block.hash();
        self.head_qc = head.qc.clone();
        self.committed_ledger = self.tree[&self.committed_hash].ledger_after.clone();
        self.prune();
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
        let safe = block.header.justify.view > self.locked_qc.view || self.extends_locked(block);
        if !safe {
            return;
        }
        self.last_voted_view = block.view();
        out.push(Action::PersistSafety(self.safety_state()));
        let vote = Vote::sign(block.view(), block.hash(), signer);
        let next_leader = self.leader(block.view() + 1);
        if Some(next_leader) == self.address() {
            if let Ok(more) = self.on_vote(vote) {
                out.extend(more);
            }
        } else {
            out.push(Action::SendTo(next_leader, ConsensusMessage::Vote(vote)));
        }
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
