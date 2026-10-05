//! A set of words with a committed base shared by every clone and an owned delta
//! (`docs/superpowers/specs/2026-10-05-validator-hot-path-design.md` §5). The ledger's
//! `commitments` and `nullifiers` hold every entry the chain ever produced, and the ledger is
//! cloned per speculative block, per trial apply and per block apply; before this type each
//! clone copied both sets (28 ms at 10⁶ entries, audit v6). Now a clone copies the delta.
//!
//! The base is written by `commit` (drain the delta in) and `detach` (a private copy) only, and
//! `HotStuff` is the only caller of either.
//!
//! Invariant: a `SharedSet` is not a value type across commits. A clone that shares the base
//! sees every entry its lineage commits later, so the logical set of a live clone can grow
//! without the clone being touched. That is sound only under a precondition `HotStuff` enforces:
//! at commit, every set still held either descends from the committed block (a tree entry after
//! the prune, which already holds the committed delta, so `absorb` drops it as redundant) or is a
//! read-only snapshot used for membership only (the node's verify snapshot, a clone of the tip),
//! for which gaining the committed entries is harmless. Under that precondition a commit moves
//! entries between the two halves of the chain's own ancestors and never adds one a holder
//! could not already derive.

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
        len_of(&self.base(), &self.added)
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

    /// Every entry once, ascending: a merge of the two sorted halves. `f` must not touch this
    /// set: the base's read guard is held while it runs, and a recursive read with a queued
    /// writer can deadlock under std's `RwLock`.
    pub fn for_each_sorted(&self, f: impl FnMut(&Word8)) {
        let base = self.base();
        merged(&base, &self.added).for_each(f);
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

/// [`SharedSet::len`] under a guard the caller already holds.
fn len_of(base: &BTreeSet<Word8>, added: &BTreeSet<Word8>) -> usize {
    base.len() + added.iter().filter(|x| !base.contains(*x)).count()
}

/// Every entry of `base ∪ added` once, ascending: a merge of the two sorted halves, an entry in
/// both yielded once. Lazy and allocation-free; [`SharedSet::for_each_sorted`] and the
/// [`PartialEq`] walk both read the set through it.
fn merged<'a>(base: &'a BTreeSet<Word8>, added: &'a BTreeSet<Word8>) -> impl Iterator<Item = &'a Word8> + 'a {
    let mut a = base.iter().peekable();
    let mut b = added.iter().peekable();
    std::iter::from_fn(move || match (a.peek(), b.peek()) {
        (Some(x), Some(y)) => match x.cmp(y) {
            std::cmp::Ordering::Less => a.next(),
            std::cmp::Ordering::Greater => b.next(),
            std::cmp::Ordering::Equal => {
                b.next();
                a.next()
            }
        },
        (Some(_), None) => a.next(),
        (None, Some(_)) => b.next(),
        (None, None) => None,
    })
}

/// Logical equality: the same entries, however they are split between base and delta.
///
/// No-allocation contract (final review F2): this runs on the startup path (`verify_chain`
/// compares the stored ledger with the replayed one) over sets of 10⁷–10⁸ entries, so it never
/// copies either set. It takes each base's read guard once — one guard when the two share a
/// base, else both, in `Arc::as_ptr` address order so two concurrent comparisons cannot lock in
/// opposite orders — holds them for the walk, compares the exact lengths, then walks the two
/// merged sorted streams in lockstep.
impl PartialEq for SharedSet {
    fn eq(&self, other: &SharedSet) -> bool {
        let same_base = Arc::ptr_eq(&self.base, &other.base);
        if same_base && self.added == other.added {
            return true;
        }
        if same_base {
            let base = self.base();
            return len_of(&base, &self.added) == len_of(&base, &other.added)
                && merged(&base, &self.added).eq(merged(&base, &other.added));
        }
        let self_first = Arc::as_ptr(&self.base) < Arc::as_ptr(&other.base);
        let (first, second) = if self_first { (self, other) } else { (other, self) };
        let first_guard = first.base();
        let second_guard = second.base();
        let (mine, theirs) = if self_first { (&first_guard, &second_guard) } else { (&second_guard, &first_guard) };
        len_of(mine, &self.added) == len_of(theirs, &other.added)
            && merged(mine, &self.added).eq(merged(theirs, &other.added))
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

    /// Equality is the allocation-free merge walk (final review F2): the same entries split
    /// differently between base and delta compare equal, in either argument order, both across
    /// bases and over one shared base; a one-entry difference compares unequal.
    #[test]
    fn equality_walks_the_merged_halves_however_they_are_split() {
        // Base {1,2}, delta {3,4} against base {1}, delta {2,3,4}: different bases.
        let mut a = SharedSet::from_set([w(1), w(2)].into_iter().collect());
        a.insert(w(3));
        a.insert(w(4));
        let mut b = SharedSet::from_set([w(1)].into_iter().collect());
        for n in [2, 3, 4] {
            b.insert(w(n));
        }
        assert!(a == b && b == a, "equal across bases");
        // One shared base, different deltas holding the same entries: a clone that committed
        // part of its delta, seen against an earlier clone that still holds it in its delta.
        let mut c = SharedSet::from_set([w(1)].into_iter().collect());
        let mut d = c.clone();
        d.insert(w(2));
        c.insert(w(2));
        c.commit();
        // `d` shares `c`'s base, which now holds 2, and still carries 2 in its delta.
        assert!(Arc::ptr_eq(&c.base, &d.base) && c.added != d.added);
        assert!(c == d && d == c, "equal over one shared base");
        // One entry apart: unequal across bases (same length, different entry, and length).
        let mut e = SharedSet::from_set([w(1), w(2)].into_iter().collect());
        e.insert(w(3));
        e.insert(w(5));
        assert!(a != e && e != a, "same length, one entry different");
        let mut f = b.clone();
        f.insert(w(6));
        assert!(a != f && f != a, "one entry more");
        // And over one shared base.
        let mut g = d.clone();
        g.insert(w(7));
        assert!(d != g && g != d, "one entry more over a shared base");
    }

    /// Random insert/clone/commit/absorb programs across a family of clones, against a plain
    /// `BTreeSet` oracle per clone. Seeded, so a failure reproduces.
    #[test]
    fn random_programs_agree_with_a_btreeset_oracle() {
        for seed in 0..32u64 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            // (set, oracle, sharing group): `.clone()` keeps the group, `detach` starts a new one.
            let mut sets: Vec<(SharedSet, std::collections::BTreeSet<Word8>, u32)> = vec![(SharedSet::new(), Default::default(), 0)];
            let mut next_group = 1u32;
            for _ in 0..400 {
                let i = rng.gen_range(0..sets.len());
                match rng.gen_range(0..11) {
                    0..=5 => {
                        let x = w(rng.gen_range(0..64));
                        let (s, o, _) = &mut sets[i];
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
                        for (s, o, _) in sets.iter_mut() {
                            for x in &committed { if o.insert(*x) { s.insert(*x); } }
                        }
                        sets[i].0.commit();
                        for (s, _, _) in sets.iter_mut() { s.absorb(); }
                    }
                    8 => {
                        // Commit i without pre-inserting: every clone sharing i's base now sees
                        // the committed entries, so its oracle gains them (not a superset case).
                        let delta = sets[i].0.added.clone();
                        let group = sets[i].2;
                        sets[i].0.commit();
                        for (_, o, g) in sets.iter_mut() {
                            if *g == group { o.extend(delta.iter().copied()); }
                        }
                    }
                    9 => {
                        sets[i].0.detach();
                        sets[i].2 = next_group;
                        next_group += 1;
                    }
                    _ => {
                        let x = w(rng.gen_range(0..64));
                        let (s, o, _) = &sets[i];
                        assert_eq!(s.contains(&x), o.contains(&x), "seed {seed}");
                    }
                }
                for (s, o, _) in &sets {
                    assert_eq!(s.len(), o.len(), "seed {seed}: len");
                    assert_eq!(s.snapshot(), *o, "seed {seed}: contents");
                }
                // The merge-walk equality agrees with the oracles' pairwise.
                for (s, o, _) in &sets {
                    for (t, p, _) in &sets {
                        assert_eq!(s == t, o == p, "seed {seed}: equality");
                    }
                }
            }
        }
    }
}
