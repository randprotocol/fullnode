//! A set of words with a committed base shared by every clone and an owned delta
//! (`docs/superpowers/specs/2026-10-05-validator-hot-path-design.md` §5). The ledger's
//! `commitments` and `nullifiers` hold every entry the chain ever produced, and the ledger is
//! cloned per speculative block, per trial apply and per block apply; before this type each
//! clone copied both sets (28 ms at 10⁶ entries, audit v6). Now a clone copies the delta.
//!
//! The base is written by `commit` (drain the delta in) and `detach` (a private copy) only, and
//! `HotStuff` is the only caller of either: at commit, after the tree keeps only descendants of
//! the new head, so every surviving clone already holds the committed delta and `absorb` drops
//! it as redundant. Sound because consensus state is `base ∪ delta` and a commit moves entries
//! between the two halves of the chain's own ancestors, never adds one.

use crate::notes::Word8;
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default)]
pub struct SharedSet {
    /// The committed entries. Shared by every clone of a lineage; written only by [`Self::commit`]
    /// and replaced only by [`Self::detach`].
    base: Arc<RwLock<BTreeSet<Word8>>>,
    /// Entries this value inserted (or inherited from the clone it was made from) since the base.
    added: BTreeSet<Word8>,
}

impl SharedSet {
    pub fn new() -> SharedSet {
        SharedSet::default()
    }

    pub fn from_set(set: BTreeSet<Word8>) -> SharedSet {
        SharedSet { base: Arc::new(RwLock::new(set)), added: BTreeSet::new() }
    }

    fn base(&self) -> std::sync::RwLockReadGuard<'_, BTreeSet<Word8>> {
        // A poisoned lock means a panic while draining a delta in; there is no state to recover.
        self.base.read().unwrap_or_else(|e| e.into_inner())
    }

    pub fn contains(&self, x: &Word8) -> bool {
        self.added.contains(x) || self.base().contains(x)
    }

    /// `true` if `x` was absent from both halves and is now in the delta.
    pub fn insert(&mut self, x: Word8) -> bool {
        if self.base().contains(&x) {
            return false;
        }
        self.added.insert(x)
    }

    /// Exact: the base plus the delta entries the base does not hold. Between a lineage's
    /// `commit` and this clone's `absorb` the two can overlap; the count does not double.
    pub fn len(&self) -> usize {
        let base = self.base();
        base.len() + self.added.iter().filter(|x| !base.contains(*x)).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The delta's size: what a clone of this value copies.
    pub fn added_len(&self) -> usize {
        self.added.len()
    }

    /// A full copy of base and delta together.
    pub fn snapshot(&self) -> BTreeSet<Word8> {
        let mut out = self.base().clone();
        out.extend(self.added.iter().copied());
        out
    }

    /// Every entry once, ascending: a merge of the two sorted halves.
    pub fn for_each_sorted(&self, mut f: impl FnMut(&Word8)) {
        let base = self.base();
        let mut a = base.iter().peekable();
        let mut b = self.added.iter().peekable();
        loop {
            match (a.peek(), b.peek()) {
                (Some(x), Some(y)) => match x.cmp(y) {
                    std::cmp::Ordering::Less => {
                        f(x);
                        a.next();
                    }
                    std::cmp::Ordering::Greater => {
                        f(y);
                        b.next();
                    }
                    std::cmp::Ordering::Equal => {
                        f(x);
                        a.next();
                        b.next();
                    }
                },
                (Some(x), None) => {
                    f(x);
                    a.next();
                }
                (None, Some(y)) => {
                    f(y);
                    b.next();
                }
                (None, None) => return,
            }
        }
    }

    /// Drain the delta into the shared base: the commit step. O(delta); the base is not copied.
    pub fn commit(&mut self) {
        if self.added.is_empty() {
            return;
        }
        let mut base = self.base.write().unwrap_or_else(|e| e.into_inner());
        base.extend(std::mem::take(&mut self.added));
    }

    /// Drop delta entries the base has gained since: a surviving speculative clone after its
    /// ancestor committed. O(delta · log n).
    pub fn absorb(&mut self) {
        if self.added.is_empty() {
            return;
        }
        let base = self.base.read().unwrap_or_else(|e| e.into_inner());
        self.added.retain(|x| !base.contains(x));
    }

    /// A private copy of the base, so this value's lineage stops sharing with the one it was
    /// cloned from. O(state); `HotStuff::new` only.
    pub fn detach(&mut self) {
        let copy = self.base().clone();
        self.base = Arc::new(RwLock::new(copy));
    }
}

impl PartialEq for SharedSet {
    fn eq(&self, other: &SharedSet) -> bool {
        if Arc::ptr_eq(&self.base, &other.base) && self.added == other.added {
            return true;
        }
        self.len() == other.len() && self.snapshot() == other.snapshot()
    }
}

impl Eq for SharedSet {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};

    fn w(n: u32) -> Word8 { [n, 0, 0, 0, 0, 0, 0, 0] }

    #[test]
    fn a_clone_shares_the_base_and_owns_its_delta() {
        let mut a = SharedSet::from_set([w(1), w(2)].into_iter().collect());
        let mut b = a.clone();
        assert!(b.insert(w(3)));
        assert!(!a.contains(&w(3)), "the clone's insert is its own");
        assert!(b.contains(&w(1)), "the base is visible through the clone");
        assert!(!a.insert(w(2)), "a base entry is not inserted twice");
        assert_eq!((a.len(), b.len(), a.added_len(), b.added_len()), (2, 3, 0, 1));
    }

    #[test]
    fn commit_moves_the_delta_into_the_base_and_absorb_drops_what_the_base_gained() {
        let mut committed = SharedSet::from_set([w(1)].into_iter().collect());
        let mut child = committed.clone();
        child.insert(w(2));
        let mut grandchild = child.clone();
        grandchild.insert(w(3));
        // The child commits: its delta {2} becomes base.
        committed = child.clone();
        committed.commit();
        assert_eq!((committed.len(), committed.added_len()), (2, 0));
        // The grandchild's view is unchanged as a set, and its delta still holds the redundant 2
        // until it absorbs — len() is exact either way.
        assert_eq!((grandchild.len(), grandchild.added_len()), (3, 2));
        grandchild.absorb();
        assert_eq!((grandchild.len(), grandchild.added_len()), (3, 1));
        assert!(grandchild.contains(&w(2)) && grandchild.contains(&w(3)));
        // A clone taken before the commit and kept (the node's verify snapshot) still answers.
        assert!(child.contains(&w(2)) && !child.contains(&w(3)));
        assert_eq!(child.len(), 2);
    }

    #[test]
    fn detach_gives_a_private_base() {
        let a = SharedSet::from_set([w(1)].into_iter().collect());
        let mut b = a.clone();
        b.detach();
        b.insert(w(2));
        b.commit();
        assert!(!a.contains(&w(2)), "a's base did not move");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn sorted_iteration_merges_without_duplicates_and_equality_is_logical() {
        let mut s = SharedSet::from_set([w(5), w(1)].into_iter().collect());
        s.insert(w(3));
        let mut seen = Vec::new();
        s.for_each_sorted(|x| seen.push(*x));
        assert_eq!(seen, vec![w(1), w(3), w(5)]);
        let flat = SharedSet::from_set([w(1), w(3), w(5)].into_iter().collect());
        assert_eq!(s, flat, "equal as sets however the entries are split");
        assert_eq!(s.snapshot(), flat.snapshot());
    }

    /// Random insert/clone/commit/absorb programs across a family of clones, against a plain
    /// `BTreeSet` oracle per clone. Seeded, so a failure reproduces.
    #[test]
    fn random_programs_agree_with_a_btreeset_oracle() {
        for seed in 0..32u64 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let mut sets: Vec<(SharedSet, std::collections::BTreeSet<Word8>)> = vec![(SharedSet::new(), Default::default())];
            for _ in 0..400 {
                let i = rng.gen_range(0..sets.len());
                match rng.gen_range(0..10) {
                    0..=5 => {
                        let x = w(rng.gen_range(0..64));
                        let (s, o) = &mut sets[i];
                        assert_eq!(s.insert(x), o.insert(x), "seed {seed}");
                    }
                    6 => {
                        let c = sets[i].clone();
                        if sets.len() < 6 { sets.push(c); }
                    }
                    7 => {
                        // Commit i, then absorb every clone (what HotStuff does): only clones
                        // that are supersets of i stay consistent, so make them so first.
                        let committed = sets[i].1.clone();
                        for (s, o) in sets.iter_mut() {
                            for x in &committed { if o.insert(*x) { s.insert(*x); } }
                        }
                        sets[i].0.commit();
                        for (s, _) in sets.iter_mut() { s.absorb(); }
                    }
                    8 => sets[i].0.detach(),
                    _ => {
                        let x = w(rng.gen_range(0..64));
                        let (s, o) = &sets[i];
                        assert_eq!(s.contains(&x), o.contains(&x), "seed {seed}");
                    }
                }
                for (s, o) in &sets {
                    assert_eq!(s.len(), o.len(), "seed {seed}: len");
                    assert_eq!(s.snapshot(), *o, "seed {seed}: contents");
                }
            }
        }
    }
}
