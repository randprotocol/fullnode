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
    /// The lowest height this node still serves, other than genesis (history pruning spec §2);
    /// 0 on an archive. Appended last so an older node reads the fields it knows.
    pub floor: u64,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The roll caveat, pinned (history pruning spec §2): a v0.5.6 `Status` has three fields.
    #[derive(Serialize, Deserialize)]
    struct OldStatus {
        height: u64,
        head_hash: Hash,
        view: u64,
    }

    #[test]
    fn a_new_node_cannot_decode_an_old_status_and_an_old_node_reads_the_new_ones_prefix() {
        let old = bincode::serialize(&GossipMessage::Status(Status { height: 7, head_hash: Hash::ZERO, view: 9, floor: 0 })).unwrap();
        // Old shape from a new payload: bincode reads the prefix and ignores the tail.
        let as_old: (u32, OldStatus) = bincode::deserialize(&old).unwrap();
        assert_eq!(as_old.1.height, 7);
        // New shape from an old payload: four bytes short — refused, never misread.
        let short = bincode::serialize(&OldStatus { height: 7, head_hash: Hash::ZERO, view: 9 }).unwrap();
        let mut framed = bincode::serialize(&2u32).unwrap();
        framed.extend_from_slice(&short);
        assert!(bincode::deserialize::<GossipMessage>(&framed).is_err());
    }
}
