//! Blocks, votes and quorum certificates.

use crate::crypto::{merkle_root, Address, Hash, Keypair, PublicKey, Signature};
use crate::types::transaction::Transaction;
use crate::types::validator::ValidatorSet;
use serde::{Deserialize, Serialize};

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
    pub fn sign(view: u64, block_hash: Hash, key: &Keypair) -> Vote {
        let signature = key.sign(&Hash::digest_domain(b"shrugg-vote", &vote_message(view, &block_hash)).0);
        Vote { view, block_hash, voter: key.public_key().clone(), signature }
    }

    pub fn voter_address(&self) -> Address {
        self.voter.address()
    }

    pub fn verify(&self) -> bool {
        self.voter.verify(
            &Hash::digest_domain(b"shrugg-vote", &vote_message(self.view, &self.block_hash)).0,
            &self.signature,
        )
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

    /// Verify every vote and that the signers reach quorum stake. `genesis_hash`
    /// allows the empty genesis QC.
    pub fn verify(&self, validators: &ValidatorSet, genesis_hash: &Hash) -> bool {
        if self.is_genesis() {
            return self.block_hash == *genesis_hash;
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
            if !v.verify() {
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
        Hash::digest_domain(b"shrugg-block", &bytes)
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

    pub fn sign(header: BlockHeader, transactions: Vec<Transaction>, key: &Keypair) -> Block {
        let signature = key.sign(header.hash().as_bytes());
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

    pub fn verify_signature(&self) -> bool {
        self.header.proposer.verify(self.hash().as_bytes(), &self.signature)
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

    #[test]
    fn vote_roundtrip() {
        let v = Vote::sign(3, Hash::digest(b"b"), &key(1));
        assert!(v.verify());
        let mut bad = v.clone();
        bad.view = 4;
        assert!(!bad.verify());
    }

    #[test]
    fn qc_requires_quorum_and_rejects_duplicates_and_outsiders() {
        let vs = vset(4);
        let h = Hash::digest(b"blk");
        let votes: Vec<Vote> = (1..=4).map(|i| Vote::sign(5, h, &key(i))).collect();
        let g = Hash::ZERO;
        let qc = |vs_: Vec<Vote>| QuorumCertificate { view: 5, block_hash: h, votes: vs_ };
        assert!(!qc(votes[..2].to_vec()).verify(&vs, &g));
        assert!(qc(votes[..3].to_vec()).verify(&vs, &g));
        assert!(qc(votes.clone()).verify(&vs, &g));
        // duplicate vote does not count twice
        assert!(!qc(vec![votes[0].clone(), votes[0].clone(), votes[1].clone()]).verify(&vs, &g));
        // outsider
        let outsider = Vote::sign(5, h, &key(9));
        assert!(!qc(vec![votes[0].clone(), votes[1].clone(), outsider]).verify(&vs, &g));
        // mismatched view inside a vote
        let mut wrong = votes[2].clone();
        wrong.view = 6;
        assert!(!qc(vec![votes[0].clone(), votes[1].clone(), wrong]).verify(&vs, &g));
    }

    #[test]
    fn genesis_qc_only_matches_genesis_hash() {
        let vs = vset(2);
        let g = Hash::digest(b"genesis");
        assert!(QuorumCertificate::genesis(g).verify(&vs, &g));
        assert!(!QuorumCertificate::genesis(g).verify(&vs, &Hash::ZERO));
    }

    #[test]
    fn block_signature_and_tx_root() {
        let k = key(1);
        let envelope = crate::notes::Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] };
        let tx = Transaction::mint(1, [7; 8], envelope, 1, &k);
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
        let b = Block::sign(header, vec![tx], &k);
        assert!(b.verify_signature());
        assert!(b.verify_tx_root());
        let mut tampered = b.clone();
        tampered.transactions.clear();
        assert!(!tampered.verify_tx_root());
        let back = Block::decode(&b.encode()).unwrap();
        assert_eq!(back.hash(), b.hash());
    }
}
