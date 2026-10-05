//! The incremental nullifier root (spec 2026-10-05 §4): a Merkle Mountain Range over
//! nullifiers in insertion order. `O(log n)` state — the peaks and a count — and `O(log n)` per
//! append, where the sorted root `state_root_leaves` computes today is `O(n)` per block. The
//! leaf hash is the sorted root's leaf hash; the node and root domains are this range's own.
//! Insertion order is block order, action order, nullifier slot order (`apply_bundle_notes`).

use crate::crypto::Hash;
use crate::notes::{word8_to_bytes, Word8};
use serde::{Deserialize, Serialize};

pub const ROOT_DOMAIN: &[u8] = b"rand-nullifier-mmr-1";
const NODE_DOMAIN: &[u8] = b"rand-nullifier-mmr-node";

/// The sorted root's leaf hash, unchanged, so the two roots commit the same leaves.
pub fn leaf(nf: &Word8) -> Hash {
    Hash::digest_domain(b"rand-nullifier-leaf", &word8_to_bytes(nf))
}

pub fn node(left: &Hash, right: &Hash) -> Hash {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left.as_bytes());
    buf[32..].copy_from_slice(right.as_bytes());
    Hash::digest_domain(NODE_DOMAIN, &buf)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierMmr {
    /// Peaks of the perfect subtrees, largest first — one per set bit of `count`, high bit first.
    peaks: Vec<Hash>,
    count: u64,
}

impl NullifierMmr {
    pub fn new() -> NullifierMmr {
        NullifierMmr::default()
    }

    /// Append one leaf: the binary-counter step. Each trailing 1 bit of the old count is a peak
    /// of the same height as the new node, merged right-to-left.
    pub fn append(&mut self, nf: &Word8) {
        let mut acc = leaf(nf);
        let mut c = self.count;
        while c & 1 == 1 {
            let left = self.peaks.pop().expect("a set bit has a peak");
            acc = node(&left, &acc);
            c >>= 1;
        }
        self.peaks.push(acc);
        self.count += 1;
    }

    /// `blake3(ROOT_DOMAIN ‖ count_be(8) ‖ bag)`, bag folding the peaks from the smallest:
    /// `bag = node(peak_i, bag_{i+1})`, `bag_last = peak_last`. Empty: the count alone.
    pub fn root(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 + 32);
        buf.extend_from_slice(&self.count.to_be_bytes());
        if let Some((last, others)) = self.peaks.split_last() {
            let bag = others.iter().rev().fold(*last, |acc, p| node(p, &acc));
            buf.extend_from_slice(bag.as_bytes());
        }
        Hash::digest_domain(ROOT_DOMAIN, &buf)
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn peaks(&self) -> &[Hash] {
        &self.peaks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The range's encoding pinned on 2026-10-05 (leaves `[1,0,..]`, `[2,0,..]`, `[3,0,..]`); it
    /// must never change without a new domain.
    #[test]
    fn three_leaves_have_a_pinned_root() {
        let mut m = NullifierMmr::new();
        for n in 1..=3u32 {
            m.append(&[n, 0, 0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(m.root().to_hex(), "42b5ff7f228089ac1ba898af04b324abc677f31afb120dc8347adc981466d132");
    }

    fn nf(n: u32) -> Word8 { [n, n, 0, 0, 0, 0, 0, 1] }

    /// The root computed from scratch: the leaves split into perfect trees by the binary
    /// decomposition of the count, left to right, bagged from the right.
    fn reference_root(nfs: &[Word8]) -> Hash {
        fn perfect(leaves: &[Hash]) -> Hash {
            if leaves.len() == 1 { return leaves[0]; }
            let (l, r) = leaves.split_at(leaves.len() / 2);
            node(&perfect(l), &perfect(r))
        }
        let leaves: Vec<Hash> = nfs.iter().map(leaf).collect();
        let mut peaks = Vec::new();
        let mut rest = &leaves[..];
        let mut bit = 63;
        while !rest.is_empty() {
            let size = 1usize << bit;
            if rest.len() >= size { let (p, r) = rest.split_at(size); peaks.push(perfect(p)); rest = r; }
            if bit == 0 { break; }
            bit -= 1;
        }
        let mut buf = (nfs.len() as u64).to_be_bytes().to_vec();
        if let Some((last, others)) = peaks.split_last() {
            let bag = others.iter().rev().fold(*last, |acc, p| node(p, &acc));
            buf.extend_from_slice(bag.as_bytes());
        }
        Hash::digest_domain(ROOT_DOMAIN, &buf)
    }

    #[test]
    fn the_range_root_is_the_reference_root_for_every_count_to_70() {
        let mut m = NullifierMmr::new();
        let mut all = Vec::new();
        assert_eq!(m.root(), reference_root(&[]), "empty");
        for n in 0..70u32 {
            all.push(nf(n));
            m.append(&nf(n));
            assert_eq!(m.count(), all.len() as u64);
            assert_eq!(m.root(), reference_root(&all), "{} leaves", all.len());
            assert_eq!(m.peaks().len() as u32, (all.len() as u64).count_ones(), "one peak per set bit");
        }
    }

    #[test]
    fn order_matters_and_equal_sequences_agree() {
        let mut a = NullifierMmr::new();
        let mut b = NullifierMmr::new();
        for n in 0..9u32 { a.append(&nf(n)); b.append(&nf(n)); }
        assert_eq!(a, b);
        assert_eq!(a.root(), b.root());
        let mut c = NullifierMmr::new();
        for n in (0..9u32).rev() { c.append(&nf(n)); }
        assert_ne!(a.root(), c.root(), "a permutation is a different range");
    }

    #[test]
    fn the_root_binds_the_count_and_survives_a_serde_round_trip() {
        let mut a = NullifierMmr::new();
        a.append(&nf(1));
        let bytes = bincode::serialize(&a).unwrap();
        let back: NullifierMmr = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back, a);
        assert_eq!(back.root(), a.root());
        let empty = NullifierMmr::new();
        assert_ne!(empty.root(), Hash::ZERO);
        assert_ne!(empty.root(), a.root());
    }
}
