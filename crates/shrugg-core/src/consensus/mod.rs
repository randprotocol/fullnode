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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Broadcast(ConsensusMessage),
    SendTo(Address, ConsensusMessage),
    /// Blocks are in height order and contiguous with the previously committed head.
    Commit(Vec<CommittedBlock>),
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
    pub validators: ValidatorSet,
    pub genesis_hash: Hash,
    pub base_timeout: Duration,
    pub max_timeout: Duration,
    /// Cap on buffered blocks whose parent is unknown.
    pub max_orphans: usize,
}

impl ConsensusConfig {
    pub fn new(chain_id: u64, validators: ValidatorSet, genesis_hash: Hash) -> ConsensusConfig {
        ConsensusConfig {
            chain_id,
            validators,
            genesis_hash,
            base_timeout: Duration::from_secs(1),
            max_timeout: Duration::from_secs(8),
            max_orphans: 256,
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
    #[error("bad vote signature")]
    BadVote,
    #[error("bad new-view signature")]
    BadNewView,
    #[error("not the leader for this vote")]
    NotLeader,
    #[error("not ready to propose")]
    NotReady,
}
