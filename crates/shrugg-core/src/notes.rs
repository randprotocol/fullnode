//! Shielded-pool data types shared by the ledger, storage, RPC and wallet: fixed-width words,
//! envelopes, bundles, addresses and the commitment tree. No hash lives here: every Poseidon2
//! evaluation the pool needs is reached through `ConfidentialExecutor`, which keeps this crate
//! free of the zkVM's field-arithmetic crates.

use crate::confidential::ConfidentialExecutor;
use serde::{Deserialize, Serialize};

pub type Word8 = [u32; 8];
pub const DEPTH: usize = 32;
pub const MAX_ENVELOPE_BYTES: usize = 2048;
/// ML-KEM-768 encapsulation key length (FIPS 203).
pub const KEM_EK_BYTES: usize = 1184;
pub const ADDRESS_PREFIX: &str = "shrugg1";

/// The 32 little-endian bytes of a word octet.
pub fn word8_to_bytes(w: &Word8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, x) in w.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
    out
}

/// The inverse of [`word8_to_bytes`]; `None` unless `b` is exactly 32 bytes.
pub fn word8_from_bytes(b: &[u8]) -> Option<Word8> {
    if b.len() != 32 {
        return None;
    }
    Some(std::array::from_fn(|i| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap())))
}

/// 64 lower-case hex characters over the little-endian bytes.
pub fn word8_to_hex(w: &Word8) -> String {
    hex::encode(word8_to_bytes(w))
}

/// The inverse of [`word8_to_hex`]; `None` unless `s` is 64 hex characters.
pub fn word8_from_hex(s: &str) -> Option<Word8> {
    word8_from_bytes(&hex::decode(s).ok()?)
}

/// What travels with a created note besides its commitment. The chain checks nothing about it;
/// it exists so the right keys can open the note later (`shrugg-zkvm`'s vendored `viewing.rs`
/// seals and opens it; this is the same four-part layout).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub kem_ct: Vec<u8>,
    pub to_receiver: Vec<u8>,
    pub to_sender: Vec<u8>,
    pub body: Vec<u8>,
}

impl Envelope {
    /// Total wire size of the four parts.
    pub fn len(&self) -> usize {
        self.kem_ct.len() + self.to_receiver.len() + self.to_sender.len() + self.body.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A shielded 2-in-2-out bundle (spec §3). Every field is public chain data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub anchor: Word8,
    pub nullifiers: [Word8; 2],
    pub commitments: [Word8; 2],
    pub fee: u64,
    pub burn: u64,
    pub asset: u32,
    /// Block height the sender targeted; copied into both output notes by the guest.
    pub time: u32,
    /// `envelopes[i]` is sealed against `commitments[i]`.
    pub envelopes: [Envelope; 2],
    /// `postcard(rand_zkvm::Proof)` of the `bundle` guest.
    pub proof: Vec<u8>,
}

/// The public preimage of a bundle digest, minus the taint word the verifier fixes to zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BundleDigestInput {
    pub anchor: Word8,
    pub nullifiers: [Word8; 2],
    pub commitments: [Word8; 2],
    pub fee: u64,
    pub burn: u64,
    pub asset: u32,
    pub time: u32,
}

impl Bundle {
    /// The public fields the bundle digest commits to, in spec order.
    pub fn digest_input(&self) -> BundleDigestInput {
        BundleDigestInput {
            anchor: self.anchor,
            nullifiers: self.nullifiers,
            commitments: self.commitments,
            fee: self.fee,
            burn: self.burn,
            asset: self.asset,
            time: self.time,
        }
    }
}

/// A shielded address: the note owner field `pk` plus the ML-KEM-768 encapsulation key
/// envelopes are sealed to. Text form: `shrugg1` + base58(pk bytes || kem_ek).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAddress {
    pub pk: Word8,
    pub kem_ek: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum AddressError {
    #[error("shielded address must start with {ADDRESS_PREFIX}")]
    Prefix,
    #[error("shielded address is not base58")]
    Base58,
    #[error("shielded address decodes to {0} bytes, expected {expected}", expected = 32 + KEM_EK_BYTES)]
    Length(usize),
}

impl ShieldedAddress {
    #[allow(clippy::inherent_to_string_shadow_display)]
    pub fn to_string(&self) -> String {
        let mut raw = word8_to_bytes(&self.pk).to_vec();
        raw.extend_from_slice(&self.kem_ek);
        format!("{ADDRESS_PREFIX}{}", bs58::encode(raw).into_string())
    }

    pub fn parse(s: &str) -> Result<ShieldedAddress, AddressError> {
        let rest = s.strip_prefix(ADDRESS_PREFIX).ok_or(AddressError::Prefix)?;
        let raw = bs58::decode(rest).into_vec().map_err(|_| AddressError::Base58)?;
        if raw.len() != 32 + KEM_EK_BYTES {
            return Err(AddressError::Length(raw.len()));
        }
        Ok(ShieldedAddress { pk: word8_from_bytes(&raw[..32]).unwrap(), kem_ek: raw[32..].to_vec() })
    }
}

impl std::fmt::Display for ShieldedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&ShieldedAddress::to_string(self))
    }
}

/// The append-only depth-32 commitment tree as a frontier: the left sibling kept at each
/// level of the rightmost path, plus the empty-subtree digests. `O(DEPTH)` per append and
/// `O(DEPTH)` state, so a chain never materializes its leaves in consensus state. Leaves are
/// `Word8`; `empty[0]` is the all-zero leaf, `empty[d] = H(NODE, empty[d-1], empty[d-1])` —
/// exactly the research crate's `ledger::CommitmentTree`, so a witness built from the
/// `FullTree` below verifies inside the `bundle` guest's `MERKLE_VERIFY`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentTree {
    next_index: u64,
    /// `frontier[d]` is the node at depth `d` on the rightmost path that a later right child
    /// will read as its left sibling. Between appends it may still hold a partially padded
    /// subtree root: `append` overwrites `frontier[d]` on every leaf whose bit `d` is 0, so by
    /// the time a leaf with bit `d` = 1 reads it, the left subtree below it is complete.
    frontier: Vec<Option<Word8>>,
    empty: Vec<Word8>,
    root: Word8,
}

fn empty_digests(h: &dyn ConfidentialExecutor) -> Vec<Word8> {
    let mut empty = vec![[0u32; 8]; DEPTH + 1];
    for d in 1..=DEPTH {
        empty[d] = h.node_hash(&empty[d - 1], &empty[d - 1]);
    }
    empty
}

impl CommitmentTree {
    pub fn new(h: &dyn ConfidentialExecutor) -> CommitmentTree {
        let empty = empty_digests(h);
        CommitmentTree { next_index: 0, frontier: vec![None; DEPTH], root: empty[DEPTH], empty }
    }

    /// The root of a tree with no leaves.
    pub fn empty_root(h: &dyn ConfidentialExecutor) -> Word8 {
        empty_digests(h)[DEPTH]
    }

    pub fn root(&self) -> Word8 {
        self.root
    }

    /// The index the next appended leaf gets, i.e. the number of leaves so far.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Append `cm` as the next leaf and return its index. Panics if the tree is full (2^32 leaves).
    pub fn append(&mut self, cm: Word8, h: &dyn ConfidentialExecutor) -> u64 {
        assert!(self.next_index < (1u64 << DEPTH), "commitment tree is full");
        let index = self.next_index;
        let mut node = cm;
        let mut pos = index;
        for d in 0..DEPTH {
            if pos & 1 == 0 {
                // `node` is a left child whose right sibling is still empty; it becomes the left
                // sibling of the next leaf's path at this depth.
                self.frontier[d] = Some(node);
                node = h.node_hash(&node, &self.empty[d]);
            } else {
                let left = self.frontier[d].expect("a right child always has a completed left sibling");
                node = h.node_hash(&left, &node);
            }
            pos >>= 1;
        }
        self.root = node;
        self.next_index = index + 1;
        index
    }
}

/// Every level materialized — the reference for `CommitmentTree` and the witness source for
/// `shrugg_getWitness` and the cluster tests. `O(leaves)` memory and hashing.
#[derive(Clone, Debug)]
pub struct FullTree {
    levels: Vec<Vec<Word8>>,
    empty: Vec<Word8>,
}

impl FullTree {
    pub fn new(leaves: Vec<Word8>, h: &dyn ConfidentialExecutor) -> FullTree {
        let empty = empty_digests(h);
        let mut levels = vec![leaves];
        for d in 0..DEPTH {
            let cur = &levels[d];
            let next: Vec<Word8> = if cur.is_empty() {
                Vec::new()
            } else {
                cur.chunks(2).map(|p| h.node_hash(&p[0], if p.len() == 2 { &p[1] } else { &empty[d] })).collect()
            };
            levels.push(next);
        }
        FullTree { levels, empty }
    }

    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn root(&self) -> Word8 {
        self.levels[DEPTH].first().copied().unwrap_or(self.empty[DEPTH])
    }

    /// Sibling per level, leaf level first — the layout `notes::bundle_inputs` (in the vendored
    /// research note layer, `shrugg_zkvm::notes`, arriving in Task 2) expects.
    pub fn path(&self, index: u64) -> Option<[Word8; DEPTH]> {
        if index >= self.len() as u64 {
            return None;
        }
        let mut path = [[0u32; 8]; DEPTH];
        let mut pos = index as usize;
        for (d, sib) in path.iter_mut().enumerate() {
            let s = pos ^ 1;
            *sib = self.levels[d].get(s).copied().unwrap_or(self.empty[d]);
            pos >>= 1;
        }
        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::StubExecutor;

    #[test]
    fn word8_bytes_are_little_endian_and_roundtrip() {
        let w: Word8 = [1, 2, 3, 4, 5, 6, 7, 0x8000_0000];
        let b = word8_to_bytes(&w);
        assert_eq!(&b[..4], &[1, 0, 0, 0]);
        assert_eq!(&b[28..], &[0, 0, 0, 0x80]);
        assert_eq!(word8_from_bytes(&b), Some(w));
        assert_eq!(word8_from_bytes(&b[..31]), None);
        assert_eq!(word8_from_hex(&word8_to_hex(&w)), Some(w));
        assert_eq!(word8_from_hex("zz"), None);
    }

    #[test]
    fn envelope_len_sums_every_part() {
        let e = Envelope { kem_ct: vec![0; 1088], to_receiver: vec![0; 60], to_sender: vec![0; 60], body: vec![0; 140] };
        assert_eq!(e.len(), 1348);
        assert!(e.len() <= MAX_ENVELOPE_BYTES);
    }

    #[test]
    fn shielded_address_roundtrips_and_rejects_bad_input() {
        let a = ShieldedAddress { pk: [9; 8], kem_ek: vec![7; KEM_EK_BYTES] };
        let s = a.to_string();
        assert!(s.starts_with(ADDRESS_PREFIX));
        assert_eq!(ShieldedAddress::parse(&s).unwrap(), a);
        assert_eq!(ShieldedAddress::parse("abc").unwrap_err(), AddressError::Prefix);
        assert_eq!(ShieldedAddress::parse("shrugg10OIl").unwrap_err(), AddressError::Base58);
        let short = format!("{ADDRESS_PREFIX}{}", bs58::encode([1u8; 40]).into_string());
        assert_eq!(ShieldedAddress::parse(&short).unwrap_err(), AddressError::Length(40));
    }

    /// Naive reference: hash every level over the padded leaf list.
    fn naive_root(leaves: &[Word8], h: &dyn ConfidentialExecutor) -> Word8 {
        let mut empty = vec![[0u32; 8]; DEPTH + 1];
        for d in 1..=DEPTH {
            empty[d] = h.node_hash(&empty[d - 1], &empty[d - 1]);
        }
        let mut level: Vec<Word8> = leaves.to_vec();
        for d in 0..DEPTH {
            if level.is_empty() {
                return empty[DEPTH];
            }
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                let r = if pair.len() == 2 { pair[1] } else { empty[d] };
                next.push(h.node_hash(&pair[0], &r));
            }
            level = next;
        }
        level[0]
    }

    fn leaf(i: u32) -> Word8 { [i, i + 1, i + 2, i + 3, 0, 0, 0, 0] }

    #[test]
    fn frontier_tree_matches_the_naive_tree_for_every_size() {
        let h = StubExecutor;
        let mut t = CommitmentTree::new(&h);
        assert_eq!(t.root(), naive_root(&[], &h));
        assert_eq!(t.root(), CommitmentTree::empty_root(&h));
        let mut leaves = Vec::new();
        for i in 0..40u32 {
            let idx = t.append(leaf(i), &h);
            assert_eq!(idx, i as u64);
            leaves.push(leaf(i));
            assert_eq!(t.root(), naive_root(&leaves, &h), "size {}", i + 1);
            assert_eq!(t.next_index(), leaves.len() as u64);
        }
        let bytes = bincode::serialize(&t).unwrap();
        let back: CommitmentTree = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn full_tree_paths_recompute_the_root() {
        let h = StubExecutor;
        let leaves: Vec<Word8> = (0..13u32).map(leaf).collect();
        let full = FullTree::new(leaves.clone(), &h);
        assert_eq!(full.root(), naive_root(&leaves, &h));
        for (index, l) in leaves.iter().enumerate() {
            let path = full.path(index as u64).unwrap();
            let mut node = *l;
            let mut pos = index;
            for sib in path.iter() {
                node = if pos & 1 == 0 { h.node_hash(&node, sib) } else { h.node_hash(sib, &node) };
                pos >>= 1;
            }
            assert_eq!(node, full.root(), "leaf {index}");
        }
        assert!(full.path(13).is_none());
    }
}
