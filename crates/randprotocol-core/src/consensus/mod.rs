//! Chained HotStuff BFT consensus.
//!
//! `HotStuff` is a pure state machine: feed it messages and timeouts, it
//! returns `Action`s for the node to execute (send, persist, commit, arm a
//! timer). No clocks, sockets, or disks live here, so it is tested with a
//! simulated network in `tests.rs`.

pub mod commit_rule;
mod hotstuff;
#[cfg(test)]
mod tests;

pub use crate::types::SigningDomain;
pub use hotstuff::{CoveredSource, GossipPrecheck, HotStuff};

/// B2 (bridge hardening spec §3): on a chain with a bridge, a validator does not vote for a block
/// whose timestamp runs more than this many milliseconds ahead of its own clock. A vote rule
/// only — replay of committed history reads no local clock and applies just the step rule
/// ([`crate::ledger::MAX_TIMESTAMP_STEP_MS`]).
pub const MAX_CLOCK_DRIFT_MS: u64 = 15_000;

/// Audit v4 (CON-3): a proposal whose view is more than this many views ahead of the replica's
/// current view is refused (`ConsensusError::ViewTooFarAhead`) and never stored — views advance
/// on QCs and NewViews, not on far-future proposals. Local acceptance policy, not a validity
/// rule: a block refused here is still valid to a replica whose view has caught up.
pub const PROPOSAL_VIEW_WINDOW: u64 = 8;

/// The most blocks one proposer keeps in a replica's orphan pool (CN-5, issue #46): a sixteenth
/// of the 256-block pool.
///
/// An honest proposer's orphans at a replica are its live proposals that overtook their parents
/// while the replica fetches or syncs, one per view it leads (CON-3's sibling bound) — so a
/// proposer with more than sixteen of them outstanding is one whose every rotation for the last
/// sixteen went unlinked, which on an 18-validator set is ~290 views, longer than the pool itself
/// could remember for all proposers together. At that depth the replica is batch-syncing anyway
/// (the pool is the shortcut for the last few blocks, never the catch-up path), so the cap costs
/// an honest proposer nothing. Without it one validator of the current set, which the leader
/// check admits, could fill all 256 slots with blocks on made-up parents just above the head —
/// the lowest heights, which the pool's evict-the-highest rule keeps — and every other
/// proposer's out-of-order block would be refused until those were pruned. A one-validator chain
/// is the corner: its replica buffers at most sixteen live blocks and syncs the rest.
pub const MAX_ORPHANS_PER_PROPOSER: usize = 16;

use crate::crypto::{Address, Hash, Keypair, PublicKey, Signature};
use crate::types::{Block, QuorumCertificate, ValidatorSet, Vote};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// Sent by a validator when its view times out, carrying its highest QC so
/// the next leader can extend the freshest certified block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewView {
    pub view: u64,
    pub high_qc: QuorumCertificate,
    pub sender: PublicKey,
    pub signature: Signature,
}

impl NewView {
    pub fn sign(domain: &SigningDomain, view: u64, high_qc: QuorumCertificate, key: &Keypair) -> NewView {
        let signature = key.sign(&domain.new_view_message(view, &high_qc).0);
        NewView { view, high_qc, sender: key.public_key().clone(), signature }
    }

    pub fn verify(&self, domain: &SigningDomain) -> bool {
        self.sender.verify(&domain.new_view_message(self.view, &self.high_qc).0, &self.signature)
    }

    pub fn sender_address(&self) -> Address {
        self.sender.address()
    }
}

/// A not-held counts toward releasing a lock only while its view is within this many views of
/// the asking replica's own (scan 2026-09-27, CN-3): old truthful words about a block are not
/// kept as evidence for ever. Generous against the stall it serves — a release round in the
/// 2026-09-24 ghost-lock state spans a few leader turns while views advance on timeouts — and
/// a bound on replay all the same.
pub const NOT_HELD_VIEW_WINDOW: u64 = 256;

/// A validator's signed word that it holds no block of a hash it was asked for (audit v4,
/// CON-4): the evidence a lock is released on. Over `rand-not-held-2 ‖ genesis ‖ hash ‖ view`
/// (big-endian, as a vote's), where `view` is the signer's own view when it answered, so an
/// attestation is bound to one chain, one block and one moment; the asker verifies it against
/// its current validator set, counts the signer's stake only when the word postdates its lock
/// (`view` above the locked QC's) and is recent (within [`NOT_HELD_VIEW_WINDOW`] of its own
/// view), and lowers its lock only once the signers hold a quorum — strictly more than two
/// thirds of the set's stake (audit v5; v0.5.4 released on a third, which a Byzantine minority
/// can supply alone) — so honest validators holding a third of the stake are among them.
/// Timeouts and unsigned `Block(None)` answers are fetch attempts, never evidence.
///
/// Scan 2026-09-27, CN-3: `rand-not-held-1` signed the genesis and the hash alone, so a word
/// asked for before the block had propagated — when nobody honest held it yet — stayed valid
/// for ever, and a harvester could replay a quorum of them against a later lock on that block.
/// A signer's view above the locked QC's means it had left the view the block was certified
/// in, after the certificate could form, and still did not hold it.
///
/// `view` is appended last and defaults on decode: the sync wire is CBOR (a map of named
/// fields), so a v0.5.8 peer's `rand-not-held-1` answer decodes here with `view` 0 — at or
/// under every lock, and under the old tag, so it counts nothing — and a v0.5.8 node ignores
/// the unknown field in ours and fails the old tag's signature check. See
/// `network::wire`'s decode test and `docs/deploy.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotHeld {
    pub hash: Hash,
    pub signer: PublicKey,
    pub signature: Signature,
    #[serde(default)]
    pub view: u64,
}

impl NotHeld {
    fn message(genesis: &Hash, hash: &Hash, view: u64) -> Vec<u8> {
        let mut m = Vec::with_capacity(72);
        m.extend_from_slice(genesis.as_bytes());
        m.extend_from_slice(hash.as_bytes());
        m.extend_from_slice(&view.to_be_bytes());
        Hash::digest_domain(b"rand-not-held-2", &m).0.to_vec()
    }

    pub fn sign(key: &Keypair, genesis: &Hash, hash: &Hash, view: u64) -> NotHeld {
        let signature = key.sign(&Self::message(genesis, hash, view));
        NotHeld { hash: *hash, signer: key.public_key().clone(), signature, view }
    }

    pub fn verify(&self, genesis: &Hash) -> bool {
        self.signer.verify(&Self::message(genesis, &self.hash, self.view), &self.signature)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMessage {
    Proposal(Block),
    Vote(Vote),
    NewView(NewView),
}

/// The most votes a replica remembers above its committed head ([`SafetyState::voted`]). Entries
/// at or under the head's view are dropped at every commit, so the record reaches this only on a
/// chain that certified a thousand blocks without committing one; the oldest views go first.
pub const MAX_VOTED_KEPT: usize = 1024;

/// Safety-critical state that must hit disk before the corresponding vote leaves the node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyState {
    pub view: u64,
    pub high_qc: QuorumCertificate,
    pub locked_qc: QuorumCertificate,
    pub last_voted_view: u64,
    /// The blocks this replica voted for above its committed head, `(view, block hash)` in view
    /// order, at most [`MAX_VOTED_KEPT`] (audit v6, CON-4). Written with the vote, before it
    /// leaves the node, so a replica that voted for a block and restarted before the block was
    /// certified locally — the pending set holds certified blocks only — still knows it voted
    /// for it, and does not sign a [`NotHeld`] for it. Appended last: a row written before the
    /// field existed is read with an empty record (`Storage::load_safety`).
    #[serde(default)]
    pub voted: Vec<(u64, Hash)>,
    /// The highest view this replica has signed a proposal for (audit v6, STAKE-1), on disk
    /// *before* the proposal leaves the node (`HotStuff::propose` emits the `PersistSafety` ahead
    /// of the `Broadcast`). `propose` refuses any view at or under it, so a leader that
    /// restarted mid-view — `resume` restores the view it was in, and its `proposed_in_view` was
    /// only memory — never signs a second, different header for a view it already proposed in:
    /// that is exactly the evidence `SlashEquivocation` punishes, and an honest validator must
    /// not be able to produce it by crashing. Appended last, read as 0 from an older row.
    #[serde(default)]
    pub last_proposed_view: u64,
}

impl SafetyState {
    /// The operator's offline override (audit v6, CON-4, decision D23): lower the persisted lock
    /// to the committed head's certificate. Returns whether there was a lock above the head to
    /// lower. This gives up the promise the lock was — not to vote for a branch that does not
    /// extend the locked block — so it is for a stopped validator whose locked block is lost for
    /// good, never for a running one; `rand-node safety release-lock` is the only caller and
    /// says so before it writes. The vote record and the view are kept: a released lock does
    /// not un-cast a vote.
    pub fn release_lock(&mut self, head_qc: &QuorumCertificate) -> bool {
        if self.locked_qc.view <= head_qc.view {
            return false;
        }
        self.locked_qc = head_qc.clone();
        true
    }
}

/// A finalized block together with the QC that certifies it.
/// One pruned bundle's attestation on the wire (block aggregation, spec §7's sealed form):
/// everything a joining node needs to accept the marker form in place of the raw proof — the
/// raw transaction's hash (unrecomputable once the proof bytes are gone, and what the tx_root
/// checks against), the proof's hash (what the sync-side skip vouches for), the `pv::NUM` (35)
/// public values and the declared shape (what the covering aggregate's admission reads).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedBundle {
    pub tx_hash: crate::crypto::Hash,
    pub proof_hash: crate::crypto::Hash,
    /// The `pv::NUM` public values (35 since constraint set 8), in `pv` order — a `Vec` for
    /// serde's array limit, always `pv::NUM` long.
    pub public_values: Vec<u64>,
    pub shape: crate::types::DeclaredShape,
}

impl PrunedBundle {
    /// The public values as the fixed array admission reads, or `None` when the wire list is
    /// not exactly `pv::NUM` words — the check every consumer of a peer's side table must make
    /// before indexing (deep scan 2026-09-24).
    pub fn public_values_array(&self) -> Option<[u64; crate::types::pv::NUM]> {
        self.public_values.as_slice().try_into().ok()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedBlock {
    pub block: Block,
    pub qc: QuorumCertificate,
    /// The sealed form's side table (spec §7): this block's pruned bundles, in transaction
    /// order, their transactions carrying the marker form. Empty on a raw block — the two
    /// forms share one wire type, and a block with no pruned bundles is raw by construction.
    #[serde(default)]
    pub pruned: Vec<PrunedBundle>,
    /// Receipts of the block's confidential calls, in transaction order.
    #[serde(default)]
    pub receipts: Vec<crate::program::CallReceipt>,
    /// Notes the *ledger* created while applying this block — a `Withdraw`'s deposit (spec §8),
    /// and S3's `BridgeAttest` — in the order they were appended to the commitment tree. They
    /// are not in `block.transactions`: the wire carries only a blinding and a public amount,
    /// and the commitment is computed by whoever applies the block.
    ///
    /// Never on the wire (`#[serde(skip)]`): a peer's copy would have to be re-derived to be
    /// trusted, and the node that applies the block has already derived it. Whoever fills this
    /// in is whoever executed the block; storage needs it to write the leaf at the index the
    /// ledger gave it.
    #[serde(skip)]
    pub deposits: Vec<crate::ledger::Deposit>,
    /// The aggregates the *ledger* paid while applying this block, with the payment it derived
    /// (`Ledger::paid_aggregates`). Filled and skipped on the wire exactly as `deposits`: storage
    /// writes `rand_getAggregate`'s payment facts from it.
    #[serde(skip)]
    pub aggregates: Vec<crate::ledger::aggregation::PaidAggregate>,
}

/// The validator sets of the epochs this replica has seen start, keyed by epoch (spec §8).
///
/// Epoch 0 is the genesis set; the set for epoch `e ≥ 1` is derived from the register as of the
/// last block of epoch `e − 1`, and is recorded here when the first block of the epoch commits.
/// The node persists it so replay and sync can verify a QC against the set of the epoch the
/// certified block belonged to, without re-deriving a register it no longer holds.
///
/// Sets are held behind an `Arc`: a 100-validator set is over a hundred kilobytes of Dilithium2
/// public keys, and consensus asks for one on every proposal and every vote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EpochSets {
    sets: BTreeMap<u64, Arc<ValidatorSet>>,
}

impl EpochSets {
    /// The sets a chain starts with: epoch 0 is the genesis set.
    pub fn new(genesis_set: ValidatorSet) -> EpochSets {
        let mut sets = EpochSets::default();
        sets.insert(0, genesis_set);
        sets
    }

    pub fn get(&self, epoch: u64) -> Option<&ValidatorSet> {
        self.sets.get(&epoch).map(|s| s.as_ref())
    }

    pub fn insert(&mut self, epoch: u64, set: ValidatorSet) {
        self.sets.insert(epoch, Arc::new(set));
    }

    /// Known epochs in order, for the node to persist.
    pub fn known(&self) -> impl Iterator<Item = (u64, &ValidatorSet)> {
        self.sets.iter().map(|(e, s)| (*e, s.as_ref()))
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Forget every epoch older than `oldest`, keeping epoch 0 (the genesis set, which answers
    /// for every height below the first boundary). A replica needs only the epochs its block
    /// tree can still reach; the durable copy is the node's, written from `RecordEpochSet`.
    pub(crate) fn forget_before(&mut self, oldest: u64) {
        self.sets.retain(|epoch, _| *epoch == 0 || *epoch >= oldest);
    }

    /// Shared handle to an epoch's set, the form consensus passes around.
    pub(crate) fn shared(&self, epoch: u64) -> Option<Arc<ValidatorSet>> {
        self.sets.get(&epoch).cloned()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Broadcast(ConsensusMessage),
    SendTo(Address, ConsensusMessage),
    /// Blocks are in height order and contiguous with the previously committed head.
    Commit(Vec<CommittedBlock>),
    /// The first block of `epoch` committed: persist the set that epoch runs with, so a later
    /// replay or sync can verify its QCs. Emitted immediately before the `Commit` that carries
    /// that block.
    RecordEpochSet(u64, ValidatorSet),
    /// Arm a timer; deliver `on_timeout(view)` when it fires.
    ScheduleTimeout { view: u64, duration: Duration },
    /// The node should gather transactions and call `propose(view, txs, now_ms)`.
    ReadyToPropose { view: u64 },
    /// The block to extend is unknown (e.g. after a restart); fetch it from peers
    /// and feed it to `on_proposal`. Unknown parents of incoming proposals are
    /// reported through `ConsensusError::UnknownParent` instead.
    FetchBlock(Hash),
    /// Persist before executing any later action in the same batch. (Until v0.5.5 this also
    /// carried the locked block for storage to keep beside the lock — audit v4, CON-4; the
    /// certified chain `PersistPending` carries always holds the locked block, so that key is
    /// read once more for a database v0.5.4 wrote and then retired.)
    PersistSafety(SafetyState),
    /// The certified blocks above the committed head, in height order — every block a QC this
    /// replica holds certifies, from the head's child up to the high QC's block (audit v5,
    /// CON-4). Storage writes the whole set under one key, replacing the previous; a restart
    /// hands it back to `resume`, which puts the blocks back in the tree, so the block a persisted
    /// high QC or lock names is never one this replica has to fetch after a whole-fleet restart.
    /// Emitted after the `Commit` it follows, so a crash between the two leaves a set that starts
    /// at the new head, which `resume` skips over.
    PersistPending(Vec<Block>),
    /// A three-chain committed a block that does not descend from this replica's committed head.
    /// Its answers about finality cannot be trusted from here on, so the node layer stops rather
    /// than serving them (audit v3, the CON-3 candidate: this used to be a log line and a
    /// `return`).
    ///
    /// What it does **not** do is detect conflicting finality in general (review M1). The tree
    /// holds only descendants of the committed head, so a genuinely conflicting branch shows up
    /// earlier and elsewhere — as an unknown parent, an orphan, or a refused sync batch — and this
    /// arm is reached only when the replica's own committed head is not where its tree says it is.
    /// It is the last check on an invariant, not a detector for a forked chain.
    SafetyViolation { committed: Hash, attempted: Hash },
    /// A leader signed two different headers for one view (audit v6, STAKE-1): the block this
    /// replica already holds for `(view, proposer)` and the second one it just refused
    /// (`ConsensusError::Equivocation`), each with the signature the block carried. Emitted only
    /// on a chain whose genesis has `staking.slashing`, and only while the first block is still
    /// in the tree; the node turns the pair into a `SlashEquivocation` transaction and pools it.
    /// Handed back through [`HotStuff::take_equivocations`], since the refusal itself is an
    /// error and carries no actions.
    Equivocation { first: Box<crate::types::actions::SignedHeader>, second: Box<crate::types::actions::SignedHeader> },
}

#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    pub chain_id: u64,
    /// The set of epoch 0. Every later epoch's set is derived from the register (spec §8).
    pub genesis_set: ValidatorSet,
    pub genesis_hash: Hash,
    /// What every vote, new-view and proposal is signed under (audit v4, consensus domain v1):
    /// from the genesis file's `consensus_domain`, v0 of `genesis_hash` when absent.
    pub domain: SigningDomain,
    /// Blocks per epoch, from genesis: `epoch(h) = h / epoch_blocks`.
    pub epoch_blocks: u64,
    pub base_timeout: Duration,
    pub max_timeout: Duration,
    /// Cap on buffered blocks whose parent is unknown.
    pub max_orphans: usize,
    /// Cap on the encoded bytes of the buffered blocks whose parent is unknown (scan sweep
    /// 2026-09-26, SW-1): the count cap alone let 256 blocks at the transport's size limit hold
    /// gigabytes.
    pub max_orphan_bytes: usize,
    /// Cap on the orphans one proposer holds (CN-5, issue #46). See [`MAX_ORPHANS_PER_PROPOSER`].
    pub max_orphans_per_proposer: usize,
    /// Cap on blocks held in the speculative tree (committed head plus
    /// uncommitted blocks). Each entry carries a full ledger clone, so an
    /// uncapped tree is a memory-exhaustion vector.
    pub max_tree_blocks: usize,
}

impl ConsensusConfig {
    /// `epoch_blocks` defaults to the protocol default; a node sets it from its genesis file,
    /// like the timeouts.
    pub fn new(chain_id: u64, genesis_set: ValidatorSet, genesis_hash: Hash) -> ConsensusConfig {
        ConsensusConfig {
            chain_id,
            genesis_set,
            domain: SigningDomain::v0(genesis_hash),
            genesis_hash,
            epoch_blocks: crate::ledger::staking::EPOCH_BLOCKS_DEFAULT,
            base_timeout: Duration::from_secs(1),
            max_timeout: Duration::from_secs(8),
            max_orphans: 256,
            max_orphan_bytes: 64 << 20,
            max_orphans_per_proposer: MAX_ORPHANS_PER_PROPOSER,
            max_tree_blocks: 512,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ConsensusError {
    #[error("proposer is not the leader for view {0}")]
    WrongLeader(u64),
    #[error("bad proposer signature")]
    BadSignature,
    #[error("invalid justify QC")]
    BadJustify,
    #[error("justify does not certify parent")]
    JustifyParentMismatch,
    #[error("block view {block} must exceed parent view {parent}")]
    ViewNotIncreasing { block: u64, parent: u64 },
    #[error("height {block} must be parent height {parent} + 1")]
    BadHeight { block: u64, parent: u64 },
    #[error("block is stale (height {0} already committed)")]
    Stale(u64),
    #[error("unknown parent {0}")]
    UnknownParent(Hash),
    #[error("execution failed: {0}")]
    Execution(#[from] crate::ledger::BlockError),
    #[error("not a validator")]
    NotValidator,
    #[error("no validator set known for epoch {0}")]
    UnknownEpochSet(u64),
    #[error("bad vote signature")]
    BadVote,
    #[error("bad new-view signature")]
    BadNewView,
    #[error("not the leader for this vote")]
    NotLeader,
    #[error("not ready to propose")]
    NotReady,
    #[error("view {view} is implausibly far ahead of the current view")]
    ViewOutOfRange { view: u64 },
    #[error("too many speculative blocks in memory")]
    TreeFull,
    /// The leader of `view` already proposed `first` for it and now signs a different block
    /// (audit v4, CON-3): the first block stays, the second is refused, both hashes are logged.
    #[error("leader equivocated in view {view}: already holds {first:?}, refused {second:?}")]
    Equivocation { view: u64, first: Hash, second: Hash },
    /// The proposal's view is more than [`PROPOSAL_VIEW_WINDOW`] views past this replica's.
    #[error("proposal for view {view} is more than {PROPOSAL_VIEW_WINDOW} views ahead of the current view {current}")]
    ViewTooFarAhead { view: u64, current: u64 },
    /// A block whose parent this replica does not hold, at a height the speculative tree could
    /// never reach from the committed head or at a view no higher than the committed head's
    /// (scan sweep 2026-09-26, SW-1): not kept as an orphan. A replica that far behind catches
    /// up through block sync.
    #[error("block at height {height}, view {view} with an unknown parent is outside the orphan range")]
    OrphanOutOfRange { height: u64, view: u64 },
}
