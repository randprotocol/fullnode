//! Wire types exchanged between RAND nodes.

use libp2p::PeerId;
use randprotocol_core::consensus::{CommittedBlock, ConsensusMessage, NotHeld};
use randprotocol_core::{Block, Hash, Keypair, PublicKey, Signature, Transaction};
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
    /// A validator's signed libp2p identity (audit v6, NET-1), on its own topic
    /// (`rand/{chain_id}/peers`). Appended last: bincode numbers variants by position, so the
    /// three above encode exactly as before, and a build without this variant is not subscribed
    /// to the topic that carries it.
    PeerBinding(PeerBinding),
}

/// The longest peer id a binding may carry. An Ed25519 identity — every node's — is 38 bytes;
/// the bound is what keeps a claimed id from being an arbitrary blob before it is parsed.
pub const MAX_PEER_ID_BYTES: usize = 64;

/// A validator's statement "my node's libp2p identity is `peer_id`", signed with its Dilithium2
/// validator key (audit v6, NET-1).
///
/// The identity is `derive_subkey("rand-p2p-identity")` of the validator's secret seed, so
/// nothing public — not the register, not the validator key — gives it: the validator has to say
/// it. A node that holds a binding from a validator of a set it knows reserves that peer
/// (`NetworkHandle::reserve_peer`), so the validator is admitted past the inbound cap.
///
/// Signed over `rand-peer-binding-1 ‖ genesis ‖ issued_ms ‖ peer_id`: the genesis hash keeps a
/// binding on its own chain, and `issued_ms` — the signer's clock — makes each announcement a
/// distinct message (gossipsub drops a repeat of identical bytes for a minute, at the publisher
/// too, so an unchanging binding could not be re-announced to a peer that just connected) and
/// orders them: a node keeps a validator's newest and ignores anything older, so a captured
/// binding cannot be replayed over a later one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerBinding {
    pub validator: PublicKey,
    /// `PeerId::to_bytes` of the identity bound.
    pub peer_id: Vec<u8>,
    /// When the validator signed this, in its own clock's milliseconds since the epoch.
    pub issued_ms: u64,
    pub signature: Signature,
}

impl PeerBinding {
    fn message(genesis: &Hash, peer_id: &[u8], issued_ms: u64) -> Vec<u8> {
        // Fixed-width fields first, the variable-length id last: no two inputs share an encoding.
        let mut m = Vec::with_capacity(40 + peer_id.len());
        m.extend_from_slice(genesis.as_bytes());
        m.extend_from_slice(&issued_ms.to_be_bytes());
        m.extend_from_slice(peer_id);
        Hash::digest_domain(b"rand-peer-binding-1", &m).0.to_vec()
    }

    pub fn sign(key: &Keypair, genesis: &Hash, peer: &PeerId, issued_ms: u64) -> PeerBinding {
        let peer_id = peer.to_bytes();
        let signature = key.sign(&Self::message(genesis, &peer_id, issued_ms));
        PeerBinding { validator: key.public_key().clone(), peer_id, issued_ms, signature }
    }

    /// The key, the signature and the id have the lengths a real one has. Checked before
    /// anything else reads them: serde puts no bound on either byte vector.
    pub fn well_formed(&self) -> bool {
        self.validator.as_bytes().len() == randprotocol_core::crypto::PUBLIC_KEY_LEN
            && self.signature.is_well_formed()
            && !self.peer_id.is_empty()
            && self.peer_id.len() <= MAX_PEER_ID_BYTES
    }

    /// The identity bound, or `None` when the bytes are not a peer id.
    pub fn peer(&self) -> Option<PeerId> {
        PeerId::from_bytes(&self.peer_id).ok()
    }

    pub fn verify(&self, genesis: &Hash) -> bool {
        self.validator.verify(&Self::message(genesis, &self.peer_id, self.issued_ms), &self.signature)
    }
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
    /// "This node's node-wide budget for serving batches is spent" (audit v6, SYNC-3): not
    /// "I have nothing", which the empty `Blocks` answer says and an asker backs a peer off for.
    /// The asker takes it elsewhere without a back-off. Appended last; a build without it cannot
    /// decode it and counts the request as failed (the decode test below pins it).
    Busy,
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

    /// The v0.6.7 `GossipMessage`, variant for variant.
    #[derive(Serialize, Deserialize)]
    #[allow(dead_code, clippy::large_enum_variant)]
    enum OldGossipMessage {
        Consensus(ConsensusMessage),
        Transaction(Transaction),
        Status(Status),
    }

    /// Audit v6, NET-1, the roll: `PeerBinding` is appended to `GossipMessage`, and bincode
    /// numbers variants by position, so every message a v0.6.7 node sends or reads encodes to
    /// the same bytes under both builds. The new variant itself is tag 3, which a v0.6.7 node
    /// cannot decode — and never has to, because it rides a topic (`rand/{chain_id}/peers`)
    /// that build is not subscribed to.
    #[test]
    fn the_peer_binding_variant_is_appended_so_the_first_three_encode_as_before() {
        let key = Keypair::from_seed([5; 32]).unwrap();
        let vote = randprotocol_core::Vote::sign(&randprotocol_core::consensus::SigningDomain::v0(Hash::digest(b"g")), 7, Hash::digest(b"block"), &key);
        let status = Status { height: 7, head_hash: Hash::digest(b"h"), view: 9, floor: 1 };
        let pairs = [
            (
                bincode::serialize(&GossipMessage::Consensus(ConsensusMessage::Vote(vote.clone()))).unwrap(),
                bincode::serialize(&OldGossipMessage::Consensus(ConsensusMessage::Vote(vote))).unwrap(),
            ),
            (
                bincode::serialize(&GossipMessage::Status(status.clone())).unwrap(),
                bincode::serialize(&OldGossipMessage::Status(status)).unwrap(),
            ),
        ];
        for (new, old) in &pairs {
            assert_eq!(new, old, "a shared variant's bytes moved");
            assert!(bincode::deserialize::<OldGossipMessage>(new).is_ok());
            assert!(bincode::deserialize::<GossipMessage>(old).is_ok());
        }
        // A transaction is the third shared variant: tag 1 under both, checked on the tag alone
        // (building one needs an executor).
        assert_eq!(bincode::serialize(&1u32).unwrap(), [1, 0, 0, 0]);

        let peer = PeerId::random();
        let binding = PeerBinding::sign(&key, &Hash::digest(b"genesis"), &peer, 1_000);
        let bytes = bincode::serialize(&GossipMessage::PeerBinding(binding.clone())).unwrap();
        assert_eq!(&bytes[..4], &[3, 0, 0, 0], "the new variant is the fourth");
        assert!(bincode::deserialize::<OldGossipMessage>(&bytes).is_err(), "an old node cannot read it; it is never sent one");
        let GossipMessage::PeerBinding(read) = bincode::deserialize::<GossipMessage>(&bytes).unwrap() else { panic!("decoded as another variant") };
        assert_eq!(read, binding);
    }

    /// A binding verifies for the chain, the identity and the moment it was signed over, and
    /// for nothing else (audit v6, NET-1).
    #[test]
    fn a_peer_binding_verifies_only_for_what_was_signed() {
        let key = Keypair::from_seed([5; 32]).unwrap();
        let genesis = Hash::digest(b"genesis");
        let peer = PeerId::random();
        let b = PeerBinding::sign(&key, &genesis, &peer, 1_000);
        assert!(b.well_formed());
        assert_eq!(b.peer(), Some(peer));
        assert!(b.verify(&genesis));
        assert!(!b.verify(&Hash::digest(b"another chain")), "another genesis");
        let mut other_peer = b.clone();
        other_peer.peer_id = PeerId::random().to_bytes();
        assert!(!other_peer.verify(&genesis), "another identity under the same signature");
        let mut later = b.clone();
        later.issued_ms += 1;
        assert!(!later.verify(&genesis), "another moment under the same signature");
        let mut other_key = b.clone();
        other_key.validator = Keypair::from_seed([6; 32]).unwrap().public_key().clone();
        assert!(!other_key.verify(&genesis), "another validator's key");

        // The shape checks: a short key, a short signature, an empty or oversized id, and bytes
        // that are no peer id.
        let mut short_sig = b.clone();
        short_sig.signature = bincode::deserialize(&bincode::serialize(&vec![0u8; 10]).unwrap()).unwrap();
        assert!(!short_sig.well_formed());
        let mut short_key = b.clone();
        short_key.validator = bincode::deserialize(&bincode::serialize(&vec![0u8; 10]).unwrap()).unwrap();
        assert!(!short_key.well_formed());
        let mut empty = b.clone();
        empty.peer_id = vec![];
        assert!(!empty.well_formed());
        let mut huge = b.clone();
        huge.peer_id = vec![0; MAX_PEER_ID_BYTES + 1];
        assert!(!huge.well_formed());
        let mut junk = b;
        junk.peer_id = vec![0xff; 20];
        assert!(junk.well_formed() && junk.peer().is_none());
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

    /// Audit v6, SYNC-3, the roll: `Busy` is appended, so the three answers a v0.6.7 node knows
    /// encode as before on the CBOR sync wire, and a v0.6.7 node reading `Busy` fails to decode
    /// it — `read_response` returns an `InvalidData` error, libp2p reports `OutboundFailure::Io`,
    /// and that node treats it as a failed batch request (a back-off of the peer, a halved next
    /// batch), which is more than the empty answer it used to get costs it (a back-off alone).
    #[test]
    fn busy_is_appended_and_an_old_node_reads_it_as_a_failed_request() {
        let cbor = |v: &SyncResponse| cbor4ii::serde::to_vec(Vec::new(), v).unwrap();
        let old_cbor = |v: &OldSyncResponse| cbor4ii::serde::to_vec(Vec::new(), v).unwrap();
        assert_eq!(cbor(&SyncResponse::Blocks(vec![])), old_cbor(&OldSyncResponse::Blocks(vec![])));
        assert_eq!(cbor(&SyncResponse::Block(None)), old_cbor(&OldSyncResponse::Block(None)));
        let busy = cbor(&SyncResponse::Busy);
        assert!(cbor4ii::serde::from_slice::<OldSyncResponse>(&busy).is_err(), "an old node cannot decode busy");
        assert!(matches!(cbor4ii::serde::from_slice::<SyncResponse>(&busy).unwrap(), SyncResponse::Busy));
        assert!(busy.len() < 16, "a few bytes on the wire");
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
