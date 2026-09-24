//! Blocks, votes and quorum certificates.

use crate::crypto::{merkle_root, Address, Hash, Keypair, PublicKey, Signature};
use crate::types::transaction::Transaction;
use crate::types::validator::ValidatorSet;
use serde::{Deserialize, Serialize};

/// What a consensus signature is over (audit v4, consensus domain v1). Every vote, new-view
/// and proposal is signed under one of these, taken from the genesis file's `consensus_domain`:
///
/// - **version 0** (absent in the file; chain 14): exactly the pre-v0.5.4 messages —
///   `rand-vote ‖ view ‖ hash`, `rand-newview ‖ view ‖ bincode(high_qc)`, and the proposer
///   signs the block's `rand-block` header hash itself. `genesis` is carried but read only to
///   admit the genesis certificate.
/// - **version 1**: the genesis hash prepended under a fresh tag — `rand-vote-2 ‖ genesis ‖ …`,
///   `rand-newview-2 ‖ genesis ‖ …`, `rand-block-2 ‖ genesis ‖ bincode(header)` — so a
///   signature for one chain verifies under no other.
///
/// A block's *identity* (`Block::hash`, the `rand-block` header hash) is the same under every
/// version: the genesis hash is that very hash of the genesis block, so it cannot prefix itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningDomain {
    pub version: u32,
    pub genesis: Hash,
}

impl SigningDomain {
    /// The highest version this build signs and verifies.
    pub const MAX_VERSION: u32 = 1;

    pub fn v0(genesis: Hash) -> SigningDomain {
        SigningDomain { version: 0, genesis }
    }

    pub fn v1(genesis: Hash) -> SigningDomain {
        SigningDomain { version: 1, genesis }
    }

    /// `body` under the version's tag: bare in v0, prefixed by the genesis hash in v1.
    fn tagged(&self, v0_tag: &[u8], v1_tag: &[u8], body: &[u8]) -> Hash {
        if self.version == 0 {
            return Hash::digest_domain(v0_tag, body);
        }
        let mut m = Vec::with_capacity(32 + body.len());
        m.extend_from_slice(self.genesis.as_bytes());
        m.extend_from_slice(body);
        Hash::digest_domain(v1_tag, &m)
    }

    /// The digest a vote for `(view, block_hash)` signs.
    pub fn vote_message(&self, view: u64, block_hash: &Hash) -> Hash {
        self.tagged(b"rand-vote", b"rand-vote-2", &vote_message(view, block_hash))
    }

    /// The digest a new-view for `view` carrying `high_qc` (bincode) signs.
    pub fn new_view_message(&self, view: u64, high_qc: &QuorumCertificate) -> Hash {
        let mut body = view.to_be_bytes().to_vec();
        body.extend_from_slice(&bincode::serialize(high_qc).expect("qc serializes"));
        self.tagged(b"rand-newview", b"rand-newview-2", &body)
    }

    /// The digest a proposer signs for `header`: its own hash in v0, the tagged genesis-prefixed
    /// header bytes in v1.
    pub fn block_message(&self, header: &BlockHeader) -> Hash {
        if self.version == 0 {
            return header.hash();
        }
        let bytes = bincode::serialize(header).expect("BlockHeader serializes");
        self.tagged(b"rand-block", b"rand-block-2", &bytes)
    }
}

/// A signature by one validator over a (view, block hash) pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub view: u64,
    pub block_hash: Hash,
    pub voter: PublicKey,
    pub signature: Signature,
}

fn vote_message(view: u64, block_hash: &Hash) -> Vec<u8> {
    let mut m = Vec::with_capacity(8 + 32);
    m.extend_from_slice(&view.to_be_bytes());
    m.extend_from_slice(block_hash.as_bytes());
    m
}

impl Vote {
    pub fn sign(domain: &SigningDomain, view: u64, block_hash: Hash, key: &Keypair) -> Vote {
        let signature = key.sign(&domain.vote_message(view, &block_hash).0);
        Vote { view, block_hash, voter: key.public_key().clone(), signature }
    }

    pub fn voter_address(&self) -> Address {
        self.voter.address()
    }

    pub fn verify(&self, domain: &SigningDomain) -> bool {
        self.voter.verify(&domain.vote_message(self.view, &self.block_hash).0, &self.signature)
    }
}

/// Aggregation of votes from validators holding more than 2/3 of stake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub view: u64,
    pub block_hash: Hash,
    pub votes: Vec<Vote>,
}

impl QuorumCertificate {
    /// The certificate that justifies the genesis block.
    pub fn genesis(genesis_hash: Hash) -> QuorumCertificate {
        QuorumCertificate { view: 0, block_hash: genesis_hash, votes: Vec::new() }
    }

    pub fn is_genesis(&self) -> bool {
        self.view == 0 && self.votes.is_empty()
    }

    /// Verify every vote under `domain` and that the signers reach quorum stake. The domain's
    /// genesis hash admits the empty genesis QC.
    pub fn verify(&self, domain: &SigningDomain, validators: &ValidatorSet) -> bool {
        if self.is_genesis() {
            return self.block_hash == domain.genesis;
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut stake = 0u128;
        for v in &self.votes {
            if v.view != self.view || v.block_hash != self.block_hash {
                return false;
            }
            let addr = v.voter_address();
            let Some(val) = validators.get(&addr) else { return false };
            if !seen.insert(addr) {
                return false;
            }
            if !v.verify(domain) {
                return false;
            }
            stake += val.stake;
        }
        validators.has_quorum(stake)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub view: u64,
    pub parent: Hash,
    pub proposer: PublicKey,
    pub timestamp_ms: u64,
    pub tx_root: Hash,
    /// Ledger root after applying this block.
    pub state_root: Hash,
    /// QC certifying `parent`.
    pub justify: QuorumCertificate,
}

impl BlockHeader {
    pub fn hash(&self) -> Hash {
        let bytes = bincode::serialize(self).expect("BlockHeader serializes");
        Hash::digest_domain(b"rand-block", &bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub signature: Signature,
}

impl Block {
    pub fn tx_root(txs: &[Transaction]) -> Hash {
        let leaves: Vec<Hash> = txs.iter().map(|t| t.hash()).collect();
        merkle_root(&leaves)
    }

    pub fn sign(domain: &SigningDomain, header: BlockHeader, transactions: Vec<Transaction>, key: &Keypair) -> Block {
        let signature = key.sign(domain.block_message(&header).as_bytes());
        Block { header, transactions, signature }
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn height(&self) -> u64 {
        self.header.height
    }

    pub fn view(&self) -> u64 {
        self.header.view
    }

    pub fn parent(&self) -> Hash {
        self.header.parent
    }

    pub fn proposer(&self) -> Address {
        self.header.proposer.address()
    }

    pub fn verify_signature(&self, domain: &SigningDomain) -> bool {
        self.header.proposer.verify(domain.block_message(&self.header).as_bytes(), &self.signature)
    }

    pub fn verify_tx_root(&self) -> bool {
        Block::tx_root(&self.transactions) == self.header.tx_root
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Block serializes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Block, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::validator::Validator;

    fn key(n: u8) -> Keypair {
        Keypair::from_seed([n; 32]).unwrap()
    }

    fn vset(n: u8) -> ValidatorSet {
        ValidatorSet::new((1..=n).map(|i| Validator { public_key: key(i).public_key().clone(), stake: 1 }).collect())
    }

    fn header(k: &Keypair, genesis: Hash) -> BlockHeader {
        BlockHeader {
            height: 1,
            view: 7,
            parent: genesis,
            proposer: k.public_key().clone(),
            timestamp_ms: 0,
            tx_root: Block::tx_root(&[]),
            state_root: Hash::ZERO,
            justify: QuorumCertificate::genesis(genesis),
        }
    }

    /// Consensus domain v1 (audit v4): every signed consensus message carries the genesis hash,
    /// so a vote, a proposal or a certificate for one chain verifies under no other — and a v1
    /// signature is not a v0 one.
    #[test]
    fn a_v1_vote_for_one_chain_does_not_verify_under_another() {
        let k = key(1);
        let a = SigningDomain::v1(Hash([1; 32]));
        let b = SigningDomain::v1(Hash([2; 32]));
        let v = Vote::sign(&a, 7, Hash([3; 32]), &k);
        assert!(v.verify(&a));
        assert!(!v.verify(&b));
        assert!(!v.verify(&SigningDomain::v0(Hash([1; 32]))), "a v1 vote is not a v0 vote");
        let blk = Block::sign(&a, header(&k, Hash([1; 32])), vec![], &k);
        assert!(blk.verify_signature(&a));
        assert!(!blk.verify_signature(&b));
        assert!(!blk.verify_signature(&SigningDomain::v0(Hash([1; 32]))));
        let vs = vset(1);
        let qc = QuorumCertificate { view: 7, block_hash: Hash([3; 32]), votes: vec![v] };
        assert!(qc.verify(&a, &vs));
        assert!(!qc.verify(&b, &vs));
    }

    /// Domain 0 is chain 14: the bytes signed are exactly the pre-v0.5.4 ones, no genesis, and
    /// a block's identity is its `rand-block` header hash under every domain.
    #[test]
    fn domain_v0_signs_exactly_what_it_signed_before() {
        let k = key(1);
        let d = SigningDomain::v0(Hash([1; 32]));
        let v = Vote::sign(&d, 7, Hash([3; 32]), &k);
        let expected = Hash::digest_domain(b"rand-vote", &[&7u64.to_be_bytes()[..], &[3u8; 32][..]].concat());
        assert!(k.public_key().verify(&expected.0, &v.signature));
        assert!(v.verify(&d));
        assert!(v.verify(&SigningDomain::v0(Hash([9; 32]))), "v0 reads no genesis");
        let h = header(&k, Hash([1; 32]));
        let blk = Block::sign(&d, h.clone(), vec![], &k);
        assert!(k.public_key().verify(h.hash().as_bytes(), &blk.signature), "the proposer signed the header hash itself");
        assert_eq!(blk.hash(), h.hash());
        assert_eq!(Block::sign(&SigningDomain::v1(Hash([1; 32])), h.clone(), vec![], &k).hash(), h.hash(), "identity is domain-free");
    }

    #[test]
    fn vote_roundtrip() {
        let d = SigningDomain::v0(Hash::ZERO);
        let v = Vote::sign(&d, 3, Hash::digest(b"b"), &key(1));
        assert!(v.verify(&d));
        let mut bad = v.clone();
        bad.view = 4;
        assert!(!bad.verify(&d));
    }

    #[test]
    fn qc_requires_quorum_and_rejects_duplicates_and_outsiders() {
        let vs = vset(4);
        let h = Hash::digest(b"blk");
        let g = SigningDomain::v0(Hash::ZERO);
        let votes: Vec<Vote> = (1..=4).map(|i| Vote::sign(&g, 5, h, &key(i))).collect();
        let qc = |vs_: Vec<Vote>| QuorumCertificate { view: 5, block_hash: h, votes: vs_ };
        assert!(!qc(votes[..2].to_vec()).verify(&g, &vs));
        assert!(qc(votes[..3].to_vec()).verify(&g, &vs));
        assert!(qc(votes.clone()).verify(&g, &vs));
        // duplicate vote does not count twice
        assert!(!qc(vec![votes[0].clone(), votes[0].clone(), votes[1].clone()]).verify(&g, &vs));
        // outsider
        let outsider = Vote::sign(&g, 5, h, &key(9));
        assert!(!qc(vec![votes[0].clone(), votes[1].clone(), outsider]).verify(&g, &vs));
        // mismatched view inside a vote
        let mut wrong = votes[2].clone();
        wrong.view = 6;
        assert!(!qc(vec![votes[0].clone(), votes[1].clone(), wrong]).verify(&g, &vs));
    }

    #[test]
    fn genesis_qc_only_matches_genesis_hash() {
        let vs = vset(2);
        let g = Hash::digest(b"genesis");
        assert!(QuorumCertificate::genesis(g).verify(&SigningDomain::v0(g), &vs));
        assert!(!QuorumCertificate::genesis(g).verify(&SigningDomain::v0(Hash::ZERO), &vs));
    }

    #[test]
    fn block_signature_and_tx_root() {
        let k = key(1);
        let envelope = crate::notes::Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] };
        let tx = Transaction::mint(1, [7; 8], 0, [7; 8], envelope, 1, &k, &crate::confidential::StubExecutor);
        let header = BlockHeader {
            height: 1,
            view: 1,
            parent: Hash::ZERO,
            proposer: k.public_key().clone(),
            timestamp_ms: 0,
            tx_root: Block::tx_root(std::slice::from_ref(&tx)),
            state_root: Hash::ZERO,
            justify: QuorumCertificate::genesis(Hash::ZERO),
        };
        let d = SigningDomain::v0(Hash::ZERO);
        let b = Block::sign(&d, header, vec![tx], &k);
        assert!(b.verify_signature(&d));
        assert!(b.verify_tx_root());
        let mut tampered = b.clone();
        tampered.transactions.clear();
        assert!(!tampered.verify_tx_root());
        let back = Block::decode(&b.encode()).unwrap();
        assert_eq!(back.hash(), b.hash());
    }
}
