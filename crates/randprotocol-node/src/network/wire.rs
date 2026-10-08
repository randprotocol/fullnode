//! Wire types exchanged between RAND nodes.

use libp2p::PeerId;
use randprotocol_core::consensus::{CommittedBlock, ConsensusMessage, NotHeld};
use randprotocol_core::{Block, BlockHeader, Hash, Keypair, PublicKey, Signature, Transaction};
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
    /// A proposal with its body elided (spec 2026-10-08 §3.1): the header and the leader's
    /// signature — everything `Block::hash` and `Block::verify_signature` need — and the
    /// transaction hashes in block order. The receiver rebuilds the block from transactions it
    /// already holds and fetches the rest by hash (`SyncRequest::Transactions`). Appended last,
    /// so the four variants above encode as before; a build without it cannot decode it, which
    /// is why the roll is a flag day (§7).
    CompactProposal(CompactBlock),
}

/// The wire form of a proposal (spec 2026-10-08 §3.1). `tx_hashes` is in block order; the
/// signed header's `tx_root` commits to it, so the list is checked before anything is fetched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactBlock {
    pub header: BlockHeader,
    pub signature: Signature,
    pub tx_hashes: Vec<Hash>,
}

/// The most hashes one `SyncRequest::Transactions` carries: 16 KB, under the request limit, and
/// at most four requests for a block at the transaction cap.
pub const TX_FETCH_BATCH: usize = 512;

impl CompactBlock {
    pub fn of(block: &Block) -> CompactBlock {
        CompactBlock {
            header: block.header.clone(),
            signature: block.signature.clone(),
            tx_hashes: block.transactions.iter().map(|t| t.hash()).collect(),
        }
    }

    /// The block this compact form elided, given its transactions in order. The caller has
    /// checked that each transaction hashes to the hash at its position (`compact::rebuild`).
    pub fn into_block(self, transactions: Vec<Transaction>) -> Block {
        Block { header: self.header, transactions, signature: self.signature }
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
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
    /// Transactions by hash (spec 2026-10-08 §3.2), at most [`TX_FETCH_BATCH`]: what a compact
    /// proposal named that this node does not hold. Appended last; an older node cannot decode
    /// it and reports an inbound failure.
    Transactions(Vec<Hash>),
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
    /// The transactions this node holds of the hashes asked (any order; absent ones omitted, so
    /// the asker moves to the next peer for the rest). Appended last.
    Transactions(Vec<Transaction>),
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

    /// The pre-compact `SyncRequest`, variant for variant.
    #[derive(Serialize, Deserialize)]
    #[allow(dead_code)]
    enum OldSyncRequest {
        Blocks { from_height: u64, max: u32 },
        BlockByHash(Hash),
    }

    /// Spec 2026-10-08 §3.1: `CompactProposal` is appended, so the four existing variants
    /// encode as before and the new one is tag 4; a build without it cannot decode it (the
    /// flag-day roll, §7).
    #[test]
    fn the_compact_proposal_variant_is_appended_as_the_fifth() {
        let ks = keys(4);
        let b = block(3, &ks);
        let compact = CompactBlock::of(&b);
        assert_eq!(compact.tx_hashes.len(), b.transactions.len());
        assert_eq!(compact.hash(), b.hash());
        let bytes = bincode::serialize(&GossipMessage::CompactProposal(compact.clone())).unwrap();
        assert_eq!(&bytes[..4], &[4, 0, 0, 0], "the new variant is the fifth");
        assert!(bincode::deserialize::<OldGossipMessage>(&bytes).is_err(), "an old node cannot read it");
        let GossipMessage::CompactProposal(read) = bincode::deserialize::<GossipMessage>(&bytes).unwrap() else { panic!("another variant") };
        assert_eq!(read.header, compact.header);
        assert_eq!(read.tx_hashes, compact.tx_hashes);
        // The rebuild is the block, byte for byte.
        assert_eq!(read.into_block(b.transactions.clone()), b);
        // A status still encodes as before (the shared variants did not move).
        let status = Status { height: 7, head_hash: Hash::digest(b"h"), view: 9, floor: 1 };
        assert_eq!(
            bincode::serialize(&GossipMessage::Status(status.clone())).unwrap(),
            bincode::serialize(&OldGossipMessage::Status(status)).unwrap()
        );
    }

    /// Spec 2026-10-08 §1, §9: the size of a compact proposal at the shape the spec sizes
    /// against — a 26-validator set whose justify carries every vote, and 2 000 transaction
    /// hashes. Bounded and printed so `docs/node-hardware.md` can quote the number: the header
    /// and justify are fixed cost, each transaction adds exactly its 32-byte hash.
    #[test]
    fn a_compact_proposal_at_26_validators_and_2000_hashes_is_its_header_plus_32_bytes_a_hash() {
        let ks = keys(26);
        let b = block(9, &ks);
        let empty = bincode::serialized_size(&GossipMessage::CompactProposal(CompactBlock::of(&b))).unwrap();
        let mut compact = CompactBlock::of(&b);
        compact.tx_hashes = (0..2_000u32).map(|i| Hash::digest(&i.to_be_bytes())).collect();
        let frame = bincode::serialized_size(&GossipMessage::CompactProposal(compact)).unwrap();
        assert_eq!(frame - empty, 2_000 * 32, "each hash is 32 bytes on the wire");
        assert_eq!(b.header.justify.votes.len(), 26);
        let four_block = block(9, &keys(4));
        assert_eq!(four_block.header.justify.votes.len(), 4, "the four-validator frame carries four justify votes");
        let four = bincode::serialized_size(&GossipMessage::CompactProposal(CompactBlock::of(&four_block))).unwrap();
        println!("compact proposal, 26 justify votes: {empty} bytes with no hashes, {frame} bytes with 2000 hashes; 4 justify votes, no hashes: {four} bytes");
        assert!(frame < 256 * 1024, "a 2 000-transaction compact proposal is {frame} bytes");
    }

    /// Spec 2026-10-08 §3.2: the transaction fetch is appended on both CBOR enums; the
    /// existing variants encode as before, and an old node fails to decode the new ones.
    #[test]
    fn the_transaction_fetch_variants_are_appended() {
        let req = SyncRequest::Transactions(vec![Hash::digest(b"a"), Hash::digest(b"b")]);
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &req).unwrap();
        assert!(matches!(cbor4ii::serde::from_slice::<SyncRequest>(&bytes).unwrap(), SyncRequest::Transactions(v) if v.len() == 2));
        assert!(cbor4ii::serde::from_slice::<OldSyncRequest>(&bytes).is_err(), "an old node cannot decode it");
        let resp = SyncResponse::Transactions(vec![]);
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &resp).unwrap();
        assert!(matches!(cbor4ii::serde::from_slice::<SyncResponse>(&bytes).unwrap(), SyncResponse::Transactions(v) if v.is_empty()));
        assert!(cbor4ii::serde::from_slice::<OldSyncResponse>(&bytes).is_err());
        assert_eq!(
            cbor4ii::serde::to_vec(Vec::new(), &SyncRequest::BlockByHash(Hash::ZERO)).unwrap(),
            cbor4ii::serde::to_vec(Vec::new(), &OldSyncRequest::BlockByHash(Hash::ZERO)).unwrap()
        );
        // 512 hashes fit the 64 KiB request limit with room.
        let big = SyncRequest::Transactions(vec![Hash::ZERO; TX_FETCH_BATCH]);
        assert!((cbor4ii::serde::to_vec(Vec::new(), &big).unwrap().len() as u64) < super::super::SYNC_REQUEST_WIRE_LIMIT / 2);
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

    // ------------------------------------------- round trips, variant by variant

    use randprotocol_core::consensus::{NewView, SigningDomain};
    use randprotocol_core::types::block::{BlockHeader, QuorumCertificate, Vote};
    use randprotocol_core::Action;

    fn domain() -> SigningDomain {
        SigningDomain::v0(Hash::digest(b"g"))
    }

    fn qc(ks: &[Keypair], view: u64, hash: Hash) -> QuorumCertificate {
        QuorumCertificate { view, block_hash: hash, votes: ks.iter().map(|k| Vote::sign(&domain(), view, hash, k)).collect() }
    }

    /// An empty block at `height`, signed by `ks[0]`, with `ks.len()` votes in each QC.
    fn block(height: u64, ks: &[Keypair]) -> Block {
        let parent = Hash::digest(&height.to_be_bytes());
        let header = BlockHeader {
            height,
            view: height,
            parent,
            proposer: ks[0].public_key().clone(),
            timestamp_ms: height,
            tx_root: Hash::ZERO,
            state_root: parent,
            justify: qc(ks, height.saturating_sub(1), parent),
        };
        Block::sign(&domain(), header, vec![], &ks[0])
    }

    fn committed(height: u64, ks: &[Keypair]) -> CommittedBlock {
        let b = block(height, ks);
        let h = b.hash();
        CommittedBlock { block: b, pruned: Vec::new(), qc: qc(ks, height, h), receipts: Vec::new(), deposits: Vec::new(), aggregates: Vec::new() }
    }

    fn keys(n: u8) -> Vec<Keypair> {
        (1..=n).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect()
    }

    fn gossip_round_trip(msg: &GossipMessage) -> GossipMessage {
        let bytes = bincode::serialize(msg).expect("encodes");
        bincode::deserialize(&bytes).expect("decodes")
    }

    fn sync_response_round_trip(r: &SyncResponse) -> SyncResponse {
        let bytes = cbor4ii::serde::to_vec(Vec::new(), r).expect("encodes");
        cbor4ii::serde::from_slice(&bytes).expect("decodes")
    }

    fn sync_request_round_trip(r: &SyncRequest) -> SyncRequest {
        let bytes = cbor4ii::serde::to_vec(Vec::new(), r).expect("encodes");
        cbor4ii::serde::from_slice(&bytes).expect("decodes")
    }

    /// Every `GossipMessage` variant, including each `ConsensusMessage` shape, survives the
    /// bincode gossip wire with every field intact.
    #[test]
    fn every_gossip_variant_round_trips_through_bincode() {
        let ks = keys(3);
        let vote = Vote::sign(&domain(), 7, Hash::digest(b"block"), &ks[1]);
        match gossip_round_trip(&GossipMessage::Consensus(ConsensusMessage::Vote(vote.clone()))) {
            GossipMessage::Consensus(ConsensusMessage::Vote(v)) => assert_eq!(v, vote),
            other => panic!("decoded as {other:?}"),
        }
        let nv = NewView::sign(&domain(), 9, qc(&ks, 8, Hash::digest(b"hq")), &ks[2]);
        match gossip_round_trip(&GossipMessage::Consensus(ConsensusMessage::NewView(nv.clone()))) {
            GossipMessage::Consensus(ConsensusMessage::NewView(n)) => assert_eq!(n, nv),
            other => panic!("decoded as {other:?}"),
        }
        let b = block(4, &ks);
        match gossip_round_trip(&GossipMessage::Consensus(ConsensusMessage::Proposal(b.clone()))) {
            GossipMessage::Consensus(ConsensusMessage::Proposal(p)) => {
                assert_eq!(p, b);
                assert_eq!(p.hash(), b.hash(), "the hash is over the same bytes");
            }
            other => panic!("decoded as {other:?}"),
        }
        let tx = Transaction { chain_id: 7, bundle: None, action: Action::None };
        match gossip_round_trip(&GossipMessage::Transaction(tx.clone())) {
            GossipMessage::Transaction(t) => assert_eq!(t, tx),
            other => panic!("decoded as {other:?}"),
        }
        let status = Status { height: u64::MAX, head_hash: Hash::digest(b"h"), view: u64::MAX - 1, floor: 12 };
        match gossip_round_trip(&GossipMessage::Status(status.clone())) {
            GossipMessage::Status(s) => {
                assert_eq!((s.height, s.head_hash, s.view, s.floor), (status.height, status.head_hash, status.view, status.floor));
            }
            other => panic!("decoded as {other:?}"),
        }
        let binding = PeerBinding::sign(&ks[0], &Hash::digest(b"genesis"), &PeerId::random(), u64::MAX);
        match gossip_round_trip(&GossipMessage::PeerBinding(binding.clone())) {
            GossipMessage::PeerBinding(p) => {
                assert_eq!(p, binding);
                assert!(p.verify(&Hash::digest(b"genesis")), "the signature survives the trip");
            }
            other => panic!("decoded as {other:?}"),
        }
        let compact = CompactBlock::of(&b);
        match gossip_round_trip(&GossipMessage::CompactProposal(compact.clone())) {
            GossipMessage::CompactProposal(c) => {
                assert_eq!(c, compact);
                assert_eq!(c.hash(), b.hash(), "the hash is over the same header");
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    /// Every `SyncRequest` and `SyncResponse` variant survives the CBOR sync wire: the empty
    /// batch, a batch of real blocks, a hash, `Block(None)`, `Block(Some)`, a `NotHeld` that
    /// still verifies, `Busy`, and the transaction fetch.
    #[test]
    fn every_sync_variant_round_trips_through_cbor() {
        let ks = keys(2);
        match sync_request_round_trip(&SyncRequest::Blocks { from_height: u64::MAX, max: u32::MAX }) {
            SyncRequest::Blocks { from_height, max } => assert_eq!((from_height, max), (u64::MAX, u32::MAX)),
            other => panic!("decoded as {other:?}"),
        }
        match sync_request_round_trip(&SyncRequest::Blocks { from_height: 0, max: 0 }) {
            SyncRequest::Blocks { from_height, max } => assert_eq!((from_height, max), (0, 0)),
            other => panic!("decoded as {other:?}"),
        }
        let h = Hash::digest(b"wanted");
        match sync_request_round_trip(&SyncRequest::BlockByHash(h)) {
            SyncRequest::BlockByHash(got) => assert_eq!(got, h),
            other => panic!("decoded as {other:?}"),
        }

        match sync_response_round_trip(&SyncResponse::Blocks(vec![])) {
            SyncResponse::Blocks(v) => assert!(v.is_empty()),
            other => panic!("decoded as {other:?}"),
        }
        let batch = vec![committed(1, &ks), committed(2, &ks), committed(3, &ks)];
        match sync_response_round_trip(&SyncResponse::Blocks(batch.clone())) {
            SyncResponse::Blocks(v) => {
                assert_eq!(v, batch);
                assert!(v.iter().all(|cb| cb.deposits.is_empty()), "deposits are never on the wire");
            }
            other => panic!("decoded as {other:?}"),
        }
        match sync_response_round_trip(&SyncResponse::Block(None)) {
            SyncResponse::Block(None) => {}
            other => panic!("decoded as {other:?}"),
        }
        let b = block(5, &ks);
        match sync_response_round_trip(&SyncResponse::Block(Some(b.clone()))) {
            SyncResponse::Block(Some(got)) => assert_eq!(got, b),
            other => panic!("decoded as {other:?}"),
        }
        let genesis = Hash::digest(b"genesis");
        let nh = NotHeld::sign(&ks[0], &genesis, &h, 42);
        match sync_response_round_trip(&SyncResponse::NotHeld(nh.clone())) {
            SyncResponse::NotHeld(got) => {
                assert_eq!(got, nh);
                assert!(got.verify(&genesis));
            }
            other => panic!("decoded as {other:?}"),
        }
        assert!(matches!(sync_response_round_trip(&SyncResponse::Busy), SyncResponse::Busy));
        let hashes = vec![Hash::digest(b"x"), Hash::digest(b"y")];
        match sync_request_round_trip(&SyncRequest::Transactions(hashes.clone())) {
            SyncRequest::Transactions(got) => assert_eq!(got, hashes),
            other => panic!("decoded as {other:?}"),
        }
        let txs = vec![Transaction { chain_id: 7, bundle: None, action: Action::None }];
        match sync_response_round_trip(&SyncResponse::Transactions(txs.clone())) {
            SyncResponse::Transactions(got) => assert_eq!(got, txs),
            other => panic!("decoded as {other:?}"),
        }
    }

    /// A `CommittedBlock`'s `deposits` are `#[serde(skip)]`: a block that carried some encodes
    /// to the same bytes as one that carried none, and decodes with none.
    #[test]
    fn deposits_never_reach_the_sync_wire() {
        let ks = keys(1);
        let plain = committed(1, &ks);
        let with = CommittedBlock {
            deposits: vec![randprotocol_core::ledger::Deposit {
                index: 9,
                cm: [1; 8],
                envelope: randprotocol_core::notes::Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 8], to_sender: vec![3; 8], body: vec![4; 8] },
            }],
            ..plain.clone()
        };
        let a = cbor4ii::serde::to_vec(Vec::new(), &SyncResponse::Blocks(vec![plain])).unwrap();
        let b = cbor4ii::serde::to_vec(Vec::new(), &SyncResponse::Blocks(vec![with])).unwrap();
        assert_eq!(a, b);
    }

    /// Garbage, an empty buffer, and every proper prefix of a valid encoding are decode errors
    /// on both wires — never a panic, never a misread.
    #[test]
    fn garbage_and_truncated_bytes_are_errors_not_panics() {
        assert!(bincode::deserialize::<GossipMessage>(&[]).is_err());
        assert!(cbor4ii::serde::from_slice::<SyncRequest>(&[]).is_err());
        assert!(cbor4ii::serde::from_slice::<SyncResponse>(&[]).is_err());
        for len in [1usize, 3, 17, 64, 1000] {
            let junk = vec![0xffu8; len];
            assert!(bincode::deserialize::<GossipMessage>(&junk).is_err(), "{len} bytes of 0xff as gossip");
            assert!(cbor4ii::serde::from_slice::<SyncRequest>(&junk).is_err(), "{len} bytes of 0xff as a request");
            assert!(cbor4ii::serde::from_slice::<SyncResponse>(&junk).is_err(), "{len} bytes of 0xff as a response");
        }
        // All zeros: tag 0 is `Consensus`, tag 0 again is `Proposal`, and enough zeros *decode*
        // — as a block with an empty proposer key, empty votes and an empty signature, which is
        // what the consensus precheck (CN-4: key and signature lengths) exists to refuse. Too
        // few zeros are a short read. Neither panics.
        for len in [1usize, 3, 17, 64] {
            assert!(bincode::deserialize::<GossipMessage>(&vec![0u8; len]).is_err(), "{len} zero bytes as gossip");
        }
        match bincode::deserialize::<GossipMessage>(&vec![0u8; 1000]) {
            Ok(GossipMessage::Consensus(ConsensusMessage::Proposal(b))) => {
                assert!(b.header.proposer.as_bytes().is_empty(), "decodable, but with nothing a precheck would pass");
                assert!(b.header.justify.votes.is_empty());
            }
            other => panic!("{other:?}"),
        }

        let ks = keys(2);
        let key = &ks[0];
        let status = GossipMessage::Status(Status { height: 7, head_hash: Hash::digest(b"h"), view: 9, floor: 1 });
        let binding = GossipMessage::PeerBinding(PeerBinding::sign(key, &Hash::digest(b"genesis"), &PeerId::random(), 1));
        for msg in [status, binding] {
            let full = bincode::serialize(&msg).unwrap();
            for cut in 0..full.len() {
                assert!(bincode::deserialize::<GossipMessage>(&full[..cut]).is_err(), "a {cut}-byte prefix of {} decoded", full.len());
            }
        }
        let resp = SyncResponse::Blocks(vec![committed(1, &ks)]);
        let full = cbor4ii::serde::to_vec(Vec::new(), &resp).unwrap();
        // Every prefix of a sizeable message is a lot of decodes; step through it.
        for cut in (0..full.len()).step_by(97).chain([full.len() - 1]) {
            assert!(cbor4ii::serde::from_slice::<SyncResponse>(&full[..cut]).is_err(), "a {cut}-byte prefix of {} decoded", full.len());
        }
        let req = cbor4ii::serde::to_vec(Vec::new(), &SyncRequest::Blocks { from_height: 1, max: 2 }).unwrap();
        for cut in 0..req.len() {
            assert!(cbor4ii::serde::from_slice::<SyncRequest>(&req[..cut]).is_err());
        }
    }

    /// bincode numbers variants by position, so a tag past the last variant is a decode error:
    /// a message from a build that appended a sixth variant is refused, not misread as another.
    #[test]
    fn an_unknown_gossip_variant_tag_is_rejected() {
        let status = bincode::serialize(&Status { height: 7, head_hash: Hash::ZERO, view: 9, floor: 0 }).unwrap();
        for tag in [5u32, 6, 100, u32::MAX] {
            let mut framed = bincode::serialize(&tag).unwrap();
            framed.extend_from_slice(&status);
            assert!(bincode::deserialize::<GossipMessage>(&framed).is_err(), "tag {tag}");
        }
        // The five known tags, for contrast: tag 2 over that payload is a `Status`.
        let mut framed = bincode::serialize(&2u32).unwrap();
        framed.extend_from_slice(&status);
        assert!(matches!(bincode::deserialize::<GossipMessage>(&framed), Ok(GossipMessage::Status(s)) if s.height == 7));
    }

    /// CBOR names its variants, so a variant from the future is refused by name on both sync
    /// wires — and so is a known variant's name over the wrong payload shape.
    #[test]
    fn an_unknown_sync_variant_is_rejected() {
        #[derive(Serialize)]
        #[allow(dead_code)]
        enum FutureResponse {
            Blocks(Vec<CommittedBlock>),
            Block(Option<Block>),
            NotHeld(NotHeld),
            Busy,
            Transactions(Vec<Transaction>),
            Throttled { retry_ms: u64 },
            Gone,
        }
        for v in [FutureResponse::Throttled { retry_ms: 5 }, FutureResponse::Gone] {
            let bytes = cbor4ii::serde::to_vec(Vec::new(), &v).unwrap();
            assert!(cbor4ii::serde::from_slice::<SyncResponse>(&bytes).is_err());
        }
        #[derive(Serialize)]
        #[allow(dead_code)]
        enum FutureRequest {
            Blocks { from_height: u64, max: u32 },
            BlockByHash(Hash),
            Transactions(Vec<Hash>),
            Headers { from_height: u64 },
        }
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &FutureRequest::Headers { from_height: 1 }).unwrap();
        assert!(cbor4ii::serde::from_slice::<SyncRequest>(&bytes).is_err());
        // A known name over another shape: cbor4ii reads a unit variant whatever payload rides
        // beside it, so a future build's `Busy { retry_ms }` would still read as `Busy` here —
        // pinned, because it is the one direction in which this wire is lenient.
        #[derive(Serialize)]
        #[allow(dead_code)]
        enum WrongShape {
            Busy(u64),
        }
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &WrongShape::Busy(1)).unwrap();
        assert!(matches!(cbor4ii::serde::from_slice::<SyncResponse>(&bytes), Ok(SyncResponse::Busy)));
    }

    /// The other half of the CBOR roll property: a struct field a newer build appends is
    /// skipped by this one, as `view` was by v0.5.8 — so a `Blocks` request with an extra field
    /// still reads as the request it is.
    #[test]
    fn an_appended_cbor_field_is_skipped_by_an_older_reader() {
        #[derive(Serialize)]
        enum NewerRequest {
            Blocks { from_height: u64, max: u32, sealed: bool },
        }
        let bytes = cbor4ii::serde::to_vec(Vec::new(), &NewerRequest::Blocks { from_height: 3, max: 4, sealed: true }).unwrap();
        match cbor4ii::serde::from_slice::<SyncRequest>(&bytes) {
            Ok(SyncRequest::Blocks { from_height, max }) => assert_eq!((from_height, max), (3, 4)),
            other => panic!("{other:?}"),
        }
    }

    /// `Status` is four fixed-width little-endian fields in declaration order — 8 + 32 + 8 + 8
    /// bytes — which is what lets an older node read the prefix it knows and a newer one notice
    /// the missing tail (the roll test above). Pinned so a reordering is caught here, not on a
    /// fleet.
    #[test]
    fn status_is_four_fixed_width_fields_in_order() {
        let s = Status { height: 0x0102030405060708, head_hash: Hash::digest(b"h"), view: 0x1112131415161718, floor: 0x2122232425262728 };
        let bytes = bincode::serialize(&s).unwrap();
        assert_eq!(bytes.len(), 8 + randprotocol_core::crypto::HASH_LEN + 8 + 8);
        assert_eq!(&bytes[..8], &s.height.to_le_bytes());
        assert_eq!(&bytes[8..40], s.head_hash.as_bytes());
        assert_eq!(&bytes[40..48], &s.view.to_le_bytes());
        assert_eq!(&bytes[48..56], &s.floor.to_le_bytes());
        // Inside a `GossipMessage` it sits behind the 4-byte variant tag and nothing else.
        let framed = bincode::serialize(&GossipMessage::Status(s)).unwrap();
        assert_eq!(framed.len(), 4 + bytes.len());
        assert_eq!(&framed[4..], &bytes[..]);
    }

    /// Two bindings from one validator for two identities: each signature verifies only over its
    /// own id, so swapping them — the cheapest forgery, needing no key — fails both ways, and
    /// `peer()` names the identity actually bound.
    #[test]
    fn a_binding_for_peer_a_is_not_a_binding_for_peer_b() {
        let key = Keypair::from_seed([5; 32]).unwrap();
        let genesis = Hash::digest(b"genesis");
        let (a, b) = (PeerId::random(), PeerId::random());
        let for_a = PeerBinding::sign(&key, &genesis, &a, 1_000);
        let for_b = PeerBinding::sign(&key, &genesis, &b, 1_000);
        assert_eq!(for_a.peer(), Some(a));
        assert_eq!(for_b.peer(), Some(b));
        assert_ne!(for_a.signature, for_b.signature);
        let mut swapped_a = for_a.clone();
        swapped_a.signature = for_b.signature.clone();
        let mut swapped_b = for_b.clone();
        swapped_b.signature = for_a.signature.clone();
        assert!(!swapped_a.verify(&genesis));
        assert!(!swapped_b.verify(&genesis));
        // A's signature over B's id, kept by a node that trusted the id field: refused.
        let mut relabelled = for_a.clone();
        relabelled.peer_id = b.to_bytes();
        assert!(!relabelled.verify(&genesis));
        assert_eq!(relabelled.peer(), Some(b), "the id field alone says B; only the signature says otherwise");
    }

    /// The signed message puts the fixed-width fields first and the id last, so an id with a
    /// byte appended or removed is a different message, and nothing about the encoding lets two
    /// (genesis, issued_ms, id) triples collide.
    #[test]
    fn a_binding_is_bound_to_the_exact_id_bytes() {
        let key = Keypair::from_seed([5; 32]).unwrap();
        let genesis = Hash::digest(b"genesis");
        let peer = PeerId::random();
        let b = PeerBinding::sign(&key, &genesis, &peer, 1_000);
        let mut longer = b.clone();
        longer.peer_id.push(0);
        assert!(!longer.verify(&genesis), "a trailing byte");
        assert!(longer.well_formed());
        assert_eq!(longer.peer(), None, "and not a peer id any more");
        let mut shorter = b.clone();
        shorter.peer_id.pop();
        assert!(!shorter.verify(&genesis), "a byte short");
        let m1 = PeerBinding::message(&genesis, &b.peer_id, 1_000);
        let m2 = PeerBinding::message(&genesis, &longer.peer_id, 1_000);
        let m3 = PeerBinding::message(&Hash::digest(b"other"), &b.peer_id, 1_000);
        let m4 = PeerBinding::message(&genesis, &b.peer_id, 1_001);
        assert_eq!(m1.len(), randprotocol_core::crypto::HASH_LEN, "a digest, so the signature is over a fixed-width message");
        assert!(m1 != m2 && m1 != m3 && m1 != m4 && m2 != m3 && m3 != m4);
        assert_eq!(m1, PeerBinding::message(&genesis, &b.peer_id, 1_000), "deterministic");
    }

    /// The id bound (`MAX_PEER_ID_BYTES`) leaves room for every identity a node actually has:
    /// an Ed25519 peer id is 38 bytes. A blob of exactly the bound passes the shape check and
    /// is then found not to be a peer id, which is the order the node checks in.
    #[test]
    fn a_real_peer_id_fits_the_binding_bound_with_room() {
        // A node's identity is an Ed25519 key, inlined in its peer id (an identity multihash):
        // 38 bytes. `PeerId::random()` is a SHA-256 multihash — 34 — which is not what a node has.
        let peer = libp2p::identity::Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(peer.to_bytes().len(), 38);
        assert_eq!(PeerId::random().to_bytes().len(), 34);
        assert!(peer.to_bytes().len() < MAX_PEER_ID_BYTES);
        let key = Keypair::from_seed([5; 32]).unwrap();
        let b = PeerBinding::sign(&key, &Hash::digest(b"genesis"), &peer, 1);
        assert_eq!(b.peer_id.len(), 38);
        let mut at_bound = b.clone();
        at_bound.peer_id = vec![0xab; MAX_PEER_ID_BYTES];
        assert!(at_bound.well_formed());
        assert!(at_bound.peer().is_none());
        assert!(!at_bound.verify(&Hash::digest(b"genesis")));
    }

    /// A binding tampered with on the wire — any one byte of its encoding flipped — either fails
    /// to decode or fails to verify; it never decodes into a binding that verifies, and the
    /// decoder never panics on the flipped bytes.
    #[test]
    fn a_tampered_encoded_binding_never_verifies() {
        let key = Keypair::from_seed([5; 32]).unwrap();
        let genesis = Hash::digest(b"genesis");
        let b = PeerBinding::sign(&key, &genesis, &PeerId::random(), 77);
        let bytes = bincode::serialize(&GossipMessage::PeerBinding(b)).unwrap();
        // The encoding is a few KB (a Dilithium2 key and signature); flip a byte every 61.
        let mut other_variant = 0;
        for i in (0..bytes.len()).step_by(61) {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            match bincode::deserialize::<GossipMessage>(&t) {
                Ok(GossipMessage::PeerBinding(p)) => assert!(!p.verify(&genesis), "byte {i} flipped and it still verifies"),
                // A flip in the variant tag reads the bytes as another variant (bincode ignores a
                // trailing tail, which is what the `Status` roll test relies on): not a binding,
                // so nothing to verify — and the node reads a `Status` only from its forwarder.
                Ok(_) => other_variant += 1,
                Err(_) => {}
            }
        }
        assert_eq!(other_variant, 1, "only the tag byte can turn it into another variant");
    }
}
