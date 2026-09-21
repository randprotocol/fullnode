//! The wallet's own copy of the commitment tree, and the per-note witnesses it computes from it
//! (audit v3 PRIV-1).
//!
//! Today a wallet about to spend asks the node for the Merkle witness of exactly the leaves it
//! spends (`rand_getWitness` per input), which tells the operator precisely which leaves are its
//! own. The scan already reads every leaf (`rand_getCommitments` hands them to everyone), so the
//! wallet can keep the tree itself instead: an incremental frontier over the same arithmetic as
//! `randprotocol-core`'s `notes::CommitmentTree` (`empty[0]` the all-zero leaf,
//! `empty[d] = H(NODE, empty[d-1], empty[d-1])`, root at level 32), plus one Zcash-style
//! incremental witness per owned note, advanced on every append. `rand_getWitness` then never
//! leaves the wallet, and the only tree question a send still asks is `rand_getAnchor`, which
//! names no leaf.
//!
//! The whole thing is a cache: like every other row of the note store it is rebuilt by
//! rescanning, and a store written before it existed comes back with `scanned_index = 0` so the
//! next scan rebuilds it once (`wallet::NoteStore`).

use randprotocol_core::notes::{word8_from_hex, word8_to_hex, Word8, DEPTH};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How many block-end roots are kept. The send path anchors at the freshest one that matches the
/// live tree; the couple kept behind it cover a node that cannot answer for the freshest (a
/// sync-gap in its anchor table). The chain's own window is 256 blocks, so anything older is
/// useless anyway.
pub const CHECKPOINTS_KEPT: usize = 4;

/// One owned note's Merkle path, kept current by every append: the note's leaf position and the
/// 32 siblings, leaf level first, as of the tree's last append — exactly the layout the hidden
/// guest's `MERKLE_VERIFY` reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalWitness {
    /// The note's leaf index (also the map key; repeated so a decoded value stands alone).
    pub position: u64,
    /// Siblings leaf-first, as of the last append.
    #[serde(with = "hex_path")]
    pub path: [Word8; DEPTH],
}

/// The commitment tree as a frontier plus watched witnesses. Append-only, `O(DEPTH)` state for
/// the tree itself and `O(DEPTH)` per owned note.
///
/// Invariants (all pinned by the tests below against `randprotocol_zkvm::ledger::CommitmentTree`,
/// the reference full tree):
///
/// - `next_index` is the number of leaves, and appends are contiguous: leaf `i` may be appended
///   only when `next_index == i` (the caller keys re-offers on this, so a rescan never
///   double-appends).
/// - `frontier[d]` is the node at depth `d` on the rightmost path that a later right child reads
///   as its left sibling — the same frontier arithmetic as `notes::CommitmentTree`.
/// - `witnesses[index]` holds the path of leaf `index` against the tree's **current** root: every
///   append advances every witness at exactly one level.
/// - `checkpoints` maps block height -> the tree's root at that block's end, recorded only once
///   the block is provably complete (see `checkpoint`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalTree {
    /// The left sibling kept at each level of the rightmost path; `None` where no append has
    /// needed one yet.
    #[serde(with = "hex_frontier")]
    frontier: [Option<Word8>; DEPTH],
    next_index: u64,
    /// The owned notes' witnesses, by leaf index. Only unspent owned notes need one; a note that
    /// stops being spendable is dropped with [`LocalTree::forget`].
    witnesses: BTreeMap<u64, IncrementalWitness>,
    /// The newest few block-end roots, keyed by height: what a send anchors against.
    #[serde(default)]
    checkpoints: BTreeMap<u64, HexWord8>,
}

/// A `Word8` that serialises as 64 hex characters (the note store's JSON idiom).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct HexWord8(#[serde(with = "hex_word8")] Word8);

mod hex_word8 {
    use super::*;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(w: &Word8, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&word8_to_hex(w))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Word8, D::Error> {
        let s = String::deserialize(d)?;
        word8_from_hex(&s).ok_or_else(|| serde::de::Error::custom("expected 64 hex characters"))
    }
}

mod hex_path {
    use super::*;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(path: &[Word8; DEPTH], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(path.iter().map(word8_to_hex))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[Word8; DEPTH], D::Error> {
        let words = Vec::<String>::deserialize(d)?;
        let path: [Word8; DEPTH] = words
            .iter()
            .map(|s| word8_from_hex(s).ok_or_else(|| serde::de::Error::custom("expected 64 hex characters")))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|v: Vec<_>| serde::de::Error::custom(format!("a witness path is {DEPTH} levels, got {}", v.len())))?;
        Ok(path)
    }
}

mod hex_frontier {
    use super::*;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(frontier: &[Option<Word8>; DEPTH], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(frontier.iter().map(|slot| slot.as_ref().map(word8_to_hex)))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[Option<Word8>; DEPTH], D::Error> {
        let slots = Vec::<Option<String>>::deserialize(d)?;
        let mut words: Vec<Option<Word8>> = Vec::with_capacity(slots.len());
        for slot in &slots {
            words.push(match slot {
                None => None,
                Some(s) => Some(word8_from_hex(s).ok_or_else(|| serde::de::Error::custom("expected 64 hex characters"))?),
            });
        }
        words
            .try_into()
            .map_err(|v: Vec<_>| serde::de::Error::custom(format!("the frontier is {DEPTH} levels, got {}", v.len())))
    }
}

/// `empty[0]` is the all-zero leaf and `empty[d] = h(empty[d-1], empty[d-1])` — the exact
/// arithmetic of `notes::CommitmentTree` and of the guest's `MERKLE_VERIFY`.
fn empty_digests(h: &dyn Fn(&Word8, &Word8) -> Word8) -> [Word8; DEPTH + 1] {
    let mut empty = [[0u32; 8]; DEPTH + 1];
    for d in 1..=DEPTH {
        empty[d] = h(&empty[d - 1], &empty[d - 1]);
    }
    empty
}

impl LocalTree {
    /// The index the next appended leaf gets, i.e. the number of leaves so far.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Append `cm` as the next leaf; when `mine`, start a witness for it.
    ///
    /// The caller keys on the index: this appends at `next_index` unconditionally, so a re-offer
    /// (the scan's recovery pass re-reads leaves from 0) must skip leaves below `next_index`
    /// rather than append them again — a double append would corrupt every root from here on.
    ///
    /// Every watched witness is advanced at exactly one level: the level of the subtree the new
    /// leaf extends. That is the highest level at which the leaf's index and the note's position
    /// differ — the new leaf is always the rightmost, so at that level the note's sibling subtree
    /// is the one the leaf just landed in, and the subtree's new partial root is the sibling's
    /// new value.
    pub fn append(&mut self, cm: Word8, mine: bool, h: &dyn Fn(&Word8, &Word8) -> Word8) {
        assert!(self.next_index < (1u64 << DEPTH), "commitment tree is full");
        let index = self.next_index;
        let empty = empty_digests(h);

        // The new note's own path, from the frontier as it stands *before* this append: where the
        // leaf is a left child its right sibling is still empty; where it is a right child its
        // left sibling is the completed subtree the frontier holds.
        let fresh = mine.then(|| {
            let mut path = [[0u32; 8]; DEPTH];
            let mut pos = index;
            for (d, sib) in path.iter_mut().enumerate() {
                *sib = if pos & 1 == 0 { empty[d] } else { self.frontier[d].expect("a right child always has a completed left sibling") };
                pos >>= 1;
            }
            path
        });

        // The climb: `node` enters each level as the new root of the subtree the leaf sits in at
        // that level (`partials`), then folds up with the empty subtree or the left sibling.
        let mut node = cm;
        let mut partials = [cm; DEPTH];
        let mut pos = index;
        for d in 0..DEPTH {
            partials[d] = node;
            if pos & 1 == 0 {
                self.frontier[d] = Some(node);
                node = h(&node, &empty[d]);
            } else {
                let left = self.frontier[d].expect("a right child always has a completed left sibling");
                node = h(&left, &node);
            }
            pos >>= 1;
        }

        // Advance every watched witness at the one level this append moves for it.
        for (p, w) in self.witnesses.iter_mut() {
            let diff = index ^ *p;
            debug_assert!(diff != 0, "a watched note cannot sit at the index being appended");
            // The highest level at which the two indices differ. The new leaf is the rightmost,
            // so at that level it is the note's sibling subtree that grew: the note is in the
            // left half and the new leaf in the right.
            let d = (u64::BITS - diff.leading_zeros() - 1) as usize;
            w.path[d] = partials[d];
        }

        if let Some(path) = fresh {
            self.witnesses.insert(index, IncrementalWitness { position: index, path });
        }
        self.next_index = index + 1;
    }

    /// The tree's current root, recomputed from the frontier in `O(DEPTH)` hashes: the peaks of
    /// the filled region (one per set bit of `next_index`, each a complete subtree the frontier
    /// holds) folded left to right, the running right side padded with the empty digests between
    /// peaks and up to the root level.
    pub fn root(&self, h: &dyn Fn(&Word8, &Word8) -> Word8) -> Word8 {
        let empty = empty_digests(h);
        // `acc` is a subtree root and the level it sits at. A peak at level `d` combined with the
        // right side (itself padded up to level `d`) yields a value at level `d + 1` — the level
        // bookkeeping is what the padding below counts from.
        let mut acc: Option<(Word8, usize)> = None;
        for d in 0..DEPTH {
            if (self.next_index >> d) & 1 == 1 {
                let peak = self.frontier[d].expect("a set bit of the leaf count has its subtree in the frontier");
                acc = Some(match acc {
                    None => (peak, d),
                    Some((right, level)) => {
                        let mut right = right;
                        for lvl in level..d {
                            right = h(&right, &empty[lvl]);
                        }
                        (h(&peak, &right), d + 1)
                    }
                });
            }
        }
        match acc {
            Some((mut root, level)) => {
                for lvl in level..DEPTH {
                    root = h(&root, &empty[lvl]);
                }
                root
            }
            None => empty[DEPTH],
        }
    }

    /// The witness of leaf `index` against the current root — `Some` only for a leaf appended
    /// with `mine` and not since [`LocalTree::forget`]ten.
    pub fn path(&self, index: u64) -> Option<[Word8; DEPTH]> {
        self.witnesses.get(&index).map(|w| w.path)
    }

    /// Drop the witness of leaf `index`: a note that stops being spendable-owned (the chain
    /// published its nullifier) never needs its path again, and the map should not grow with the
    /// wallet's history.
    pub fn forget(&mut self, index: u64) {
        self.witnesses.remove(&index);
    }

    /// Record the tree's current root as the root at the end of block `height`.
    ///
    /// The caller (the scan) promises `height` is a **complete** block end: the tree already
    /// holds every leaf of every block at or below it. Rows arrive in index order, which is
    /// height order, so seeing a row of height `h` proves exactly that for blocks below `h`, and
    /// a scan that has paged the leaves to empty proves it for the last leaf's own block. Nothing
    /// else is recorded: a page that ends mid-block must not checkpoint, and the tip still
    /// accepting leaves must never be one.
    ///
    /// Monotone: a height at or below the newest one recorded is a no-op, so the recovery pass
    /// re-offering old rows cannot move a checkpoint backwards. Bounded to the newest
    /// [`CHECKPOINTS_KEPT`] — the send path uses the freshest that matches, and the chain's own
    /// anchor window makes anything older useless.
    pub fn checkpoint(&mut self, height: u64, h: &dyn Fn(&Word8, &Word8) -> Word8) {
        if self.checkpoints.keys().next_back().is_some_and(|newest| *newest >= height) {
            return;
        }
        let root = self.root(h);
        self.checkpoints.insert(height, HexWord8(root));
        while self.checkpoints.len() > CHECKPOINTS_KEPT {
            let oldest = *self.checkpoints.keys().next().expect("non-empty");
            self.checkpoints.remove(&oldest);
        }
    }

    /// The recorded block-end roots, newest first — what a send tries as anchors, in order.
    pub fn checkpoints_newest(&self) -> impl Iterator<Item = (u64, Word8)> + '_ {
        self.checkpoints.iter().rev().map(|(h, r)| (*h, r.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::confidential::ConfidentialExecutor;
    use randprotocol_zkvm::executor::ZkExecutor;
    use randprotocol_zkvm::machine::FriProfile;

    /// The executor's `node_hash`, as the wallet folds it.
    fn test_hash() -> impl Fn(&Word8, &Word8) -> Word8 {
        let ex = ZkExecutor::new(FriProfile::Test);
        move |left: &Word8, right: &Word8| ex.node_hash(left, right)
    }

    /// A deterministic pseudo-random leaf (xorshift over the index), so the test is repeatable.
    fn leaf(i: u64) -> Word8 {
        let mut x = i.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        std::array::from_fn(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 11) as u32
        })
    }

    /// Fold a leaf-first path against a root — the guest's `MERKLE_VERIFY` arithmetic.
    fn verifies(cm: &Word8, index: u64, path: &[Word8; DEPTH], root: &Word8, h: &dyn Fn(&Word8, &Word8) -> Word8) -> bool {
        let mut node = *cm;
        let mut pos = index;
        for sib in path.iter() {
            node = if pos & 1 == 0 { h(&node, sib) } else { h(sib, &node) };
            pos >>= 1;
        }
        node == *root
    }

    /// The plan's pinned test: 1000 leaves, 20 of them watched; every watched path and every root
    /// equals the reference full tree's (`randprotocol_zkvm::ledger::CommitmentTree`, the O(n)
    /// rebuild the node serves witnesses from) — checked as the tree grows, not only at the end,
    /// so a witness cannot be right by accident at the final size alone.
    #[test]
    fn local_paths_match_a_full_rebuild() {
        let h = test_hash();
        let mut local = LocalTree::default();
        let mut reference = randprotocol_zkvm::ledger::CommitmentTree::new();
        let mine: Vec<u64> = (0..1000u64).step_by(50).collect();
        for i in 0..1000u64 {
            let cm = leaf(i);
            local.append(cm, mine.contains(&i), &h);
            reference.append(cm);
            // The root matches the reference's, at every size.
            assert_eq!(local.root(&h), reference.root(), "root after {} leaves", i + 1);
            // And every watched path matches too, at every hundredth size.
            if i % 100 == 99 {
                for &m in mine.iter().filter(|&&m| m <= i) {
                    assert_eq!(local.path(m), Some(reference.path(m as usize)), "path of leaf {m} after {} leaves", i + 1);
                }
            }
        }
        assert_eq!(local.next_index(), 1000);
        let root = reference.root();
        for &i in &mine {
            assert_eq!(local.path(i), Some(reference.path(i as usize)), "path of leaf {i}");
            assert!(verifies(&leaf(i), i, &local.path(i).unwrap(), &root, &h), "path of {i} verifies");
        }
        // A leaf that was never watched has no witness; one past the end neither.
        assert_eq!(local.path(1), None);
        assert_eq!(local.path(1000), None);
    }

    /// A watched path stays right as the tree grows past the note, however the appends interleave.
    #[test]
    fn a_witness_tracks_the_tree_as_it_grows() {
        let h = test_hash();
        let mut local = LocalTree::default();
        let mut reference = randprotocol_zkvm::ledger::CommitmentTree::new();
        for i in 0..7u64 {
            local.append(leaf(i), i == 3, &h);
            reference.append(leaf(i));
        }
        assert_eq!(local.path(3), Some(reference.path(3)));
        // Grow well past the note: the path must follow, level by level.
        for i in 7..300u64 {
            local.append(leaf(i), false, &h);
            reference.append(leaf(i));
        }
        assert_eq!(local.path(3), Some(reference.path(3)));
        assert_eq!(local.root(&h), reference.root());
    }

    #[test]
    fn forget_drops_the_witness_but_not_the_leaf() {
        let h = test_hash();
        let mut local = LocalTree::default();
        let mut reference = randprotocol_zkvm::ledger::CommitmentTree::new();
        for i in 0..10u64 {
            local.append(leaf(i), i % 2 == 0, &h);
            reference.append(leaf(i));
        }
        local.forget(4);
        assert_eq!(local.path(4), None, "forgotten");
        assert_eq!(local.path(6), Some(reference.path(6)), "the rest stay");
        assert_eq!(local.root(&h), reference.root(), "the leaf is still in the tree");
        // And the tree keeps growing correctly around the gap.
        for i in 10..40u64 {
            local.append(leaf(i), false, &h);
            reference.append(leaf(i));
        }
        assert_eq!(local.path(6), Some(reference.path(6)));
        assert_eq!(local.root(&h), reference.root());
    }

    #[test]
    fn checkpoints_are_monotone_bounded_and_hold_the_root_at_the_block_end() {
        let h = test_hash();
        let mut local = LocalTree::default();
        // Two leaves in block 1, one in block 3; checkpoint as the scan's rules dictate.
        local.append(leaf(0), false, &h);
        local.append(leaf(1), true, &h);
        local.checkpoint(1, &h);
        let at_1 = local.root(&h);
        local.append(leaf(2), false, &h);
        local.checkpoint(3, &h);
        let at_3 = local.root(&h);
        // Stale and repeated checkpoints are no-ops.
        local.append(leaf(3), false, &h);
        local.checkpoint(3, &h);
        local.checkpoint(2, &h);
        let got: Vec<(u64, Word8)> = local.checkpoints_newest().collect();
        assert_eq!(got, vec![(3, at_3), (1, at_1)]);
        // The root recorded at 1 is the tree with exactly blocks <= 1 in it: paths then and now
        // differ, the recorded one matches a rebuild of the first two leaves alone.
        let mut first_two = randprotocol_zkvm::ledger::CommitmentTree::new();
        first_two.append(leaf(0));
        first_two.append(leaf(1));
        assert_eq!(at_1, first_two.root());
        // Bounded: more than CHECKPOINTS_KEPT checkpoints evicts the oldest.
        for height in 4..10u64 {
            local.append(leaf(height + 10), false, &h);
            local.checkpoint(height, &h);
        }
        let kept: Vec<u64> = local.checkpoints_newest().map(|(h, _)| h).collect();
        assert_eq!(kept.len(), CHECKPOINTS_KEPT);
        assert_eq!(kept[0], 9, "the freshest is first");
        assert!(!kept.contains(&3), "the oldest are evicted");
    }

    #[test]
    fn the_tree_roundtrips_through_json_and_still_verifies() {
        let h = test_hash();
        let mut local = LocalTree::default();
        for i in 0..50u64 {
            local.append(leaf(i), i % 7 == 0, &h);
        }
        local.checkpoint(9, &h);
        for i in 50..64u64 {
            local.append(leaf(i), i % 7 == 0, &h);
        }
        local.checkpoint(12, &h);
        let back: LocalTree = serde_json::from_str(&serde_json::to_string(&local).unwrap()).unwrap();
        assert_eq!(back, local);
        assert_eq!(back.root(&h), local.root(&h));
        for i in (0..64u64).filter(|i| i % 7 == 0) {
            assert_eq!(back.path(i), local.path(i));
            assert!(verifies(&leaf(i), i, &back.path(i).unwrap(), &back.root(&h), &h));
        }
        assert_eq!(back.checkpoints_newest().count(), 2);
    }

    #[test]
    fn an_empty_tree_has_the_empty_root_and_no_witnesses() {
        let h = test_hash();
        let local = LocalTree::default();
        assert_eq!(local.next_index(), 0);
        assert_eq!(local.root(&h), randprotocol_zkvm::ledger::CommitmentTree::new().root());
        assert_eq!(local.path(0), None);
        assert_eq!(local.checkpoints_newest().count(), 0);
    }
}
