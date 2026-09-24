//! Wire types exchanged between RAND nodes.

use randprotocol_core::consensus::{CommittedBlock, ConsensusMessage, NotHeld};
use randprotocol_core::{Block, Hash, Transaction};
use serde::{Deserialize, Serialize};

/// Periodic advertisement of a node's committed head.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub height: u64,
    pub head_hash: Hash,
    pub view: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GossipMessage {
    Consensus(ConsensusMessage),
    Transaction(Transaction),
    Status(Status),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Committed blocks `[from_height, from_height + max)` with their QCs.
    Blocks { from_height: u64, max: u32 },
    /// A single block (committed or still in the consensus tree) by hash.
    BlockByHash(Hash),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SyncResponse {
    Blocks(Vec<CommittedBlock>),
    Block(Option<Block>),
    /// A validator's signed word that it holds no block of the requested hash (audit v4, CON-4):
    /// the evidence a lock is released on. Appended last, so an older node's encodings are
    /// unchanged; one that cannot decode it counts the fetch as failed, as it would a timeout.
    NotHeld(NotHeld),
}
