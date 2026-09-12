//! Chained HotStuff BFT consensus.
//!
//! `HotStuff` is a pure state machine: feed it messages and timeouts, it
//! returns `Action`s for the node to execute (send, persist, commit, arm a
//! timer). No clocks, sockets, or disks live here, so it is tested with a
//! simulated network in `tests.rs`.

mod hotstuff;
#[cfg(test)]
mod tests;

pub use hotstuff::HotStuff;

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
    fn message(view: u64, high_qc: &QuorumCertificate) -> Vec<u8> {
        let mut m = view.to_be_bytes().to_vec();
        m.extend_from_slice(&bincode::serialize(high_qc).expect("qc serializes"));
        Hash::digest_domain(b"shrugg-newview", &m).0.to_vec()
    }

    pub fn sign(view: u64, high_qc: QuorumCertificate, key: &Keypair) -> NewView {
        let signature = key.sign(&Self::message(view, &high_qc));
        NewView { view, high_qc, sender: key.public_key().clone(), signature }
    }

    pub fn verify(&self) -> bool {
        self.sender.verify(&Self::message(self.view, &self.high_qc), &self.signature)
    }

    pub fn sender_address(&self) -> Address {
        self.sender.address()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMessage {
    Proposal(Block),
    Vote(Vote),
    NewView(NewView),
}

/// Safety-critical state that must hit disk before the corresponding vote leaves the node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyState {
    pub view: u64,
    pub high_qc: QuorumCertificate,
    pub locked_qc: QuorumCertificate,
    pub last_voted_view: u64,
}

/// A finalized block together with the QC that certifies it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedBlock {
    pub block: Block,
    pub qc: QuorumCertificate,
    /// Receipts of the block's confidential calls, in transaction order.
    #[serde(default)]
    pub receipts: Vec<crate::program::CallReceipt>,
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
    /// Persist before executing any later action in the same batch.
    PersistSafety(SafetyState),
}

#[derive(Clone, Debug)]
pub struct ConsensusConfig {
    pub chain_id: u64,
    /// The set of epoch 0. Every later epoch's set is derived from the register (spec §8).
    pub genesis_set: ValidatorSet,
    pub genesis_hash: Hash,
    /// Blocks per epoch, from genesis: `epoch(h) = h / epoch_blocks`.
    pub epoch_blocks: u64,
    pub base_timeout: Duration,
    pub max_timeout: Duration,
    /// Cap on buffered blocks whose parent is unknown.
    pub max_orphans: usize,
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
            genesis_hash,
            epoch_blocks: crate::ledger::staking::EPOCH_BLOCKS_DEFAULT,
            base_timeout: Duration::from_secs(1),
            max_timeout: Duration::from_secs(8),
            max_orphans: 256,
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
}
