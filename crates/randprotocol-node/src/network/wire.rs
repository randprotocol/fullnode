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

#[allow(clippy::large_enum_variant)] // moved once, never stored in bulk: boxing buys nothing
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
    /// Since CN-3 (scan 2026-09-27) it carries the signer's view under `rand-not-held-2`; the
    /// sync wire is CBOR with named fields, so both directions still decode across the roll and
    /// neither counts the other's word (the decode test below pins it).
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
        let new_payload = bincode::serialize(&GossipMessage::Status(Status { height: 7, head_hash: Hash::ZERO, view: 9, floor: 0 })).unwrap();
        // Old shape from a new payload: bincode reads the prefix and ignores the tail.
        let as_old: (u32, OldStatus) = bincode::deserialize(&new_payload).unwrap();
        assert_eq!(as_old.1.height, 7);
        // New shape from an old payload: eight bytes short — refused, never misread.
        let short = bincode::serialize(&OldStatus { height: 7, head_hash: Hash::ZERO, view: 9 }).unwrap();
        let mut framed = bincode::serialize(&2u32).unwrap();
        framed.extend_from_slice(&short);
        assert!(bincode::deserialize::<GossipMessage>(&framed).is_err());
    }

    /// The v0.5.8 `NotHeld`: no view, signed under `rand-not-held-1 ‖ genesis ‖ hash`.
    #[derive(Serialize, Deserialize)]
    struct OldNotHeld {
        hash: Hash,
        signer: randprotocol_core::PublicKey,
        signature: randprotocol_core::Signature,
    }

    /// The v0.5.8 `SyncResponse`, variant for variant.
    #[derive(Serialize, Deserialize)]
    #[allow(dead_code)]
    enum OldSyncResponse {
        Blocks(Vec<CommittedBlock>),
        Block(Option<Block>),
        NotHeld(OldNotHeld),
    }

    fn old_not_held_message(genesis: &Hash, hash: &Hash) -> Vec<u8> {
        let mut m = genesis.as_bytes().to_vec();
        m.extend_from_slice(hash.as_bytes());
        Hash::digest_domain(b"rand-not-held-1", &m).0.to_vec()
    }

    /// The CN-3 roll, pinned (scan 2026-09-27): the sync wire is CBOR (`cbor4ii::serde`, what the
    /// codec reads and writes), whose structs are maps of named fields. A v0.5.8 node decodes a
    /// new `NotHeld` — the unknown `view` is skipped — and its `rand-not-held-1` check fails, so
    /// it counts nothing and asks the next peer, as for `Block(None)`; no decode failure, no
    /// penalty. A new node decodes a v0.5.8 answer with `view` 0, which fails the new tag and is
    /// at or under every lock, so it counts nothing either.
    #[test]
    fn a_not_held_decodes_across_the_roll_and_counts_on_neither_side() {
        let key = randprotocol_core::Keypair::from_seed([3; 32]).unwrap();
        let genesis = Hash::digest(b"genesis");
        let h = Hash::digest(b"a block");
        let cbor = |v: &SyncResponse| cbor4ii::serde::to_vec(Vec::new(), v).unwrap();

        // New answer, old reader.
        let new = NotHeld::sign(&key, &genesis, &h, 42);
        assert!(new.verify(&genesis));
        let as_old: OldSyncResponse = cbor4ii::serde::from_slice(&cbor(&SyncResponse::NotHeld(new.clone()))).unwrap();
        let OldSyncResponse::NotHeld(old) = as_old else { panic!("decoded as another variant") };
        assert_eq!(old.hash, h);
        assert!(!old.signer.verify(&old_not_held_message(&genesis, &old.hash), &old.signature), "the old tag refuses the new word");

        // Old answer, new reader.
        let old = OldNotHeld { hash: h, signer: key.public_key().clone(), signature: key.sign(&old_not_held_message(&genesis, &h)) };
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &OldSyncResponse::NotHeld(old)).unwrap();
        let SyncResponse::NotHeld(read) = cbor4ii::serde::from_slice::<SyncResponse>(&bytes).unwrap() else { panic!("decoded as another variant") };
        assert_eq!((read.hash, read.view), (h, 0));
        assert!(!read.verify(&genesis), "the new tag refuses the old word");
    }
}
