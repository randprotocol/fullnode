//! The receiver registry (short-address spec §§5–7): an append-only set of `(pk, kem_ek)`
//! records keyed by their own hash, the receiver id, and committed to by a depth-256 sparse
//! Merkle tree whose root is a state-root component.
//!
//! The ledger holds only `receivers_root`, `receivers_count` and the pending set — the ids its
//! branch registered above the last commit (spec §6.5). The records and the tree live in the
//! node's store, which answers through a [`ReceiverSource`]. The store is never trusted: every
//! answer is a Merkle proof the ledger checks against the root it already holds, and the new
//! root is computed from the proof alone (R6). A store that is torn, stale or lying can make a
//! node refuse a block; it cannot make one accept a wrong registration.
//!
//! A record proves itself — its id is its hash — so there is no signature, no version and no
//! expiry, and anybody may register any record (spec §8).

use super::{Ledger, TxError};
use crate::address::{pk_is_canonical, ReceiverId};
use crate::crypto::Hash;
use crate::notes::{Word8, KEM_EK_BYTES};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

/// A record's size on the wire and in the fee: `pk` (32 bytes) then `kem_ek`.
pub const RECORD_BYTES: usize = 32 + KEM_EK_BYTES;
/// Registrations per block unless genesis says otherwise (spec §7.4).
pub const DEFAULT_MAX_PER_BLOCK: u32 = 64;
const LEAF_DOMAIN: &[u8] = b"rand-receiver-leaf-2";
const NODE_DOMAIN: &[u8] = b"rand-receiver-node-1";
const DEPTH: usize = 256;

/// The genesis `receivers` section's parameters (spec §7.5). Its presence is the gate: a
/// chain without it refuses `RegisterReceiver` by name and keeps chain 13's state root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiversConfig {
    pub max_per_block: u32,
}

/// One registered record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiverRecord {
    pub pk: Word8,
    #[serde(with = "crate::crypto::wire_bytes")]
    pub kem_ek: Vec<u8>,
}

impl ReceiverRecord {
    pub fn id(&self) -> ReceiverId {
        ReceiverId::of(&self.pk, &self.kem_ek)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum ReceiverError {
    #[error("this chain has no receiver registry (no genesis receivers section)")]
    Disabled,
    #[error("a receiver record's kem_ek is {0} bytes, expected {KEM_EK_BYTES}")]
    BadRecordLength(usize),
    #[error("the record's pk is not canonical")]
    NonCanonicalPk,
    #[error("more than {max} registrations in one block")]
    TooManyInBlock { max: u32 },
    #[error("receiver {0} is already registered")]
    Exists(ReceiverId),
    /// The node's store could not answer (a node without a source, or a torn store). Never a
    /// verdict on the transaction: another node, or this one after a resync, may answer.
    #[error("no receiver proof available")]
    SourceUnavailable,
    /// The store answered with a proof that does not verify against the ledger's root.
    #[error("the receiver proof does not verify against the registry root")]
    BadProof,
}

// ---- the sparse Merkle tree ---------------------------------------------------------------

/// `leaf(id, seq) = BLAKE3("rand-receiver-leaf-2" || id || seq_be8)`.
pub fn leaf(id: &ReceiverId, seq: u64) -> Hash {
    let mut b = id.0.to_vec();
    b.extend_from_slice(&seq.to_be_bytes());
    Hash::digest_domain(LEAF_DOMAIN, &b)
}

fn node(l: &Hash, r: &Hash) -> Hash {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(l.as_bytes());
    b[32..].copy_from_slice(r.as_bytes());
    Hash::digest_domain(NODE_DOMAIN, &b)
}

/// `empty[h]`, the root of an empty subtree of height `h`; `empty[0]` is 32 zero bytes.
fn empty(h: usize) -> Hash {
    static TABLE: OnceLock<Vec<Hash>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = vec![Hash::ZERO];
        for i in 1..=DEPTH {
            t.push(node(&t[i - 1], &t[i - 1]));
        }
        t
    })[h]
}

/// The empty registry's root.
pub fn empty_root() -> Hash {
    empty(DEPTH)
}

/// Bit `i` of `id`, most significant first.
fn bit(id: &[u8; 32], i: usize) -> bool {
    (id[i / 8] >> (7 - i % 8)) & 1 == 1
}

fn set_bit(id: &mut [u8; 32], i: usize, v: bool) {
    let m = 1 << (7 - i % 8);
    if v {
        id[i / 8] |= m
    } else {
        id[i / 8] &= !m
    }
}

/// A non-membership (or membership) proof: the 256 siblings on the path from the root to the
/// leaf at `id`, top first, with the ones equal to `empty[h]` elided and marked by a clear bit
/// in `present` (bit `d` for the sibling at depth `d + 1`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtProof {
    pub present: [u8; 32],
    pub siblings: Vec<Hash>,
}

/// What a source answers for one id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiverProof {
    /// The id has no record: a proof that its leaf is empty.
    Absent(SmtProof),
    /// The id is registered at `seq`: a proof of that leaf.
    Present { seq: u64, proof: SmtProof },
}

impl SmtProof {
    /// The root this proof gives with `value` at `id`'s leaf; `None` if malformed.
    pub fn root_with(&self, id: &ReceiverId, value: Hash) -> Option<Hash> {
        let want = self
            .present
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum::<usize>();
        if want != self.siblings.len() {
            return None;
        }
        let mut sib = self.siblings.iter().rev();
        let mut h = value;
        for d in (0..DEPTH).rev() {
            // The sibling of the node at depth d + 1 (height 255 − d).
            let s = if bit(&self.present, d) {
                *sib.next()?
            } else {
                empty(DEPTH - 1 - d)
            };
            h = if bit(&id.0, d) {
                node(&s, &h)
            } else {
                node(&h, &s)
            };
        }
        Some(h)
    }
}

/// The leaves a proof is computed over, as `(id, seq)` in id order.
pub trait LeafView {
    /// The first leaf with an id in `lo..=hi`, and whether there is another after it.
    fn first_two(&self, lo: &[u8; 32], hi: &[u8; 32]) -> (Option<([u8; 32], u64)>, bool);
}

/// The root of the subtree at `depth` whose ids share `prefix`'s first `depth` bits.
fn subtree(view: &dyn LeafView, depth: usize, prefix: &[u8; 32]) -> Hash {
    let (mut lo, mut hi) = (*prefix, *prefix);
    for i in depth..DEPTH {
        set_bit(&mut lo, i, false);
        set_bit(&mut hi, i, true);
    }
    match view.first_two(&lo, &hi) {
        (None, _) => empty(DEPTH - depth),
        (Some((id, seq)), false) => {
            // One leaf below: fold it up with empty siblings.
            let mut h = leaf(&ReceiverId(id), seq);
            for d in (depth..DEPTH).rev() {
                let e = empty(DEPTH - 1 - d);
                h = if bit(&id, d) {
                    node(&e, &h)
                } else {
                    node(&h, &e)
                };
            }
            h
        }
        (Some(_), true) => {
            let (mut l, mut r) = (lo, lo);
            set_bit(&mut l, depth, false);
            set_bit(&mut r, depth, true);
            node(&subtree(view, depth + 1, &l), &subtree(view, depth + 1, &r))
        }
    }
}

/// The root of the tree over `view`.
pub fn root(view: &dyn LeafView) -> Hash {
    subtree(view, 0, &[0u8; 32])
}

/// The proof for `id`'s leaf over `view`, whatever it holds there.
///
/// Recomputes each sibling subtree from the view: O(records × depth) hashes per proof at worst.
/// Fine for a test network's registry; a store that keeps its interior nodes is the obvious
/// follow-up once a registry is large (the proof format does not change).
pub fn prove(view: &dyn LeafView, id: &ReceiverId) -> SmtProof {
    let mut present = [0u8; 32];
    let mut siblings = Vec::new();
    for d in 0..DEPTH {
        let mut p = id.0;
        set_bit(&mut p, d, !bit(&id.0, d));
        let s = subtree(view, d + 1, &p);
        if s != empty(DEPTH - 1 - d) {
            set_bit(&mut present, d, true);
            siblings.push(s);
        }
    }
    SmtProof { present, siblings }
}

/// The answer a store gives for `id` over `view`: present at its seq, or absent.
pub fn lookup(view: &dyn LeafView, id: &ReceiverId) -> ReceiverProof {
    let proof = prove(view, id);
    match view.first_two(&id.0, &id.0).0 {
        Some((_, seq)) => ReceiverProof::Present { seq, proof },
        None => ReceiverProof::Absent(proof),
    }
}

// ---- the source ---------------------------------------------------------------------------

/// Where the ledger gets its proofs (spec §6.4). The view a ledger asks about is *the records
/// with `seq < count`*, of which the ones at or above what the store has committed are in
/// `pending` (spec §6.5) — so a store holding the committed chain answers for any ledger on it:
/// the tip, a speculative block above it, or an old one being replayed.
pub trait ReceiverSource: Send + Sync {
    fn lookup(
        &self,
        count: u64,
        pending: &[(ReceiverId, u64)],
        id: &ReceiverId,
    ) -> Option<ReceiverProof>;
}

/// A ledger's handle on its source: cloned with the ledger, never compared or hashed.
#[derive(Clone)]
pub struct SourceHandle(pub Arc<dyn ReceiverSource>);

impl std::fmt::Debug for SourceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceiverSource")
    }
}

/// The view over a committed `id -> seq` map cut at `count`, plus the pending entries the map
/// does not have yet.
pub struct SeqView<'a> {
    pub committed: &'a BTreeMap<[u8; 32], u64>,
    pub count: u64,
    pub extra: BTreeMap<[u8; 32], u64>,
}

impl<'a> SeqView<'a> {
    /// `committed` holds seqs `0..committed.len()`; `pending` entries at or above that are the
    /// branch's uncommitted registrations.
    pub fn new(
        committed: &'a BTreeMap<[u8; 32], u64>,
        count: u64,
        pending: &[(ReceiverId, u64)],
    ) -> SeqView<'a> {
        let n = committed.len() as u64;
        let extra = pending
            .iter()
            .filter(|(_, s)| *s >= n && *s < count)
            .map(|(id, s)| (id.0, *s))
            .collect();
        SeqView {
            committed,
            count,
            extra,
        }
    }
}

impl LeafView for SeqView<'_> {
    fn first_two(&self, lo: &[u8; 32], hi: &[u8; 32]) -> (Option<([u8; 32], u64)>, bool) {
        let a = self
            .committed
            .range(*lo..=*hi)
            .filter(|(_, s)| **s < self.count)
            .take(2);
        let b = self.extra.range(*lo..=*hi).take(2);
        let mut all: Vec<([u8; 32], u64)> = a.chain(b).map(|(k, v)| (*k, *v)).collect();
        all.sort();
        (all.first().copied(), all.len() > 1)
    }
}

/// An in-memory registry: genesis, tests, and anything else without a store.
#[derive(Clone, Debug, Default)]
pub struct MemoryReceivers {
    pub seqs: BTreeMap<[u8; 32], u64>,
}

impl MemoryReceivers {
    pub fn insert(&mut self, id: ReceiverId) -> u64 {
        let seq = self.seqs.len() as u64;
        self.seqs.insert(id.0, seq);
        seq
    }
}

impl ReceiverSource for std::sync::RwLock<MemoryReceivers> {
    fn lookup(
        &self,
        count: u64,
        pending: &[(ReceiverId, u64)],
        id: &ReceiverId,
    ) -> Option<ReceiverProof> {
        let m = self.read().ok()?;
        Some(lookup(&SeqView::new(&m.seqs, count, pending), id))
    }
}

// ---- the rules (spec §7.2) ----------------------------------------------------------------

/// Step 1: the record's length, before anything touches it.
pub fn check_size(kem_ek: &[u8]) -> Result<(), ReceiverError> {
    if kem_ek.len() != KEM_EK_BYTES {
        return Err(ReceiverError::BadRecordLength(kem_ek.len()));
    }
    Ok(())
}

/// Steps 1, 3, 5 and 6: the gate, canonicity, the per-block cap, and the proof of absence
/// verified against the ledger's own root. Returns the id and the root after insertion, which
/// `apply` installs without asking the store again.
pub fn validate(l: &Ledger, pk: &Word8, kem_ek: &[u8]) -> Result<(ReceiverId, Hash), TxError> {
    let cfg = l.receivers.as_ref().ok_or(ReceiverError::Disabled)?;
    check_size(kem_ek)?;
    if !pk_is_canonical(pk) {
        return Err(ReceiverError::NonCanonicalPk.into());
    }
    if l.receivers_in_block >= cfg.max_per_block {
        return Err(ReceiverError::TooManyInBlock {
            max: cfg.max_per_block,
        }
        .into());
    }
    let id = ReceiverId::of(pk, kem_ek);
    // C-16: an id this branch registered above the last commit needs no store round trip.
    if l.receivers_pending.iter().any(|(p, _)| *p == id) {
        return Err(ReceiverError::Exists(id).into());
    }
    let source = l
        .receiver_source
        .as_ref()
        .ok_or(ReceiverError::SourceUnavailable)?;
    match source
        .0
        .lookup(l.receivers_count, &l.receivers_pending, &id)
        .ok_or(ReceiverError::SourceUnavailable)?
    {
        ReceiverProof::Present { seq, proof } => {
            // Even "already registered" is checked against the root: a store cannot make a
            // node refuse a fresh registration by claiming it exists.
            if seq < l.receivers_count
                && proof.root_with(&id, leaf(&id, seq)) == Some(l.receivers_root)
            {
                Err(ReceiverError::Exists(id).into())
            } else {
                Err(ReceiverError::BadProof.into())
            }
        }
        ReceiverProof::Absent(proof) => {
            if proof.root_with(&id, Hash::ZERO) != Some(l.receivers_root) {
                return Err(ReceiverError::BadProof.into());
            }
            let new_root = proof
                .root_with(&id, leaf(&id, l.receivers_count))
                .ok_or(ReceiverError::BadProof)?;
            Ok((id, new_root))
        }
    }
}

/// C-6: install what `validate` computed.
pub fn apply(l: &mut Ledger, id: ReceiverId, new_root: Hash) {
    let seq = l.receivers_count;
    l.receivers_root = new_root;
    l.receivers_count = seq + 1;
    l.receivers_pending.push((id, seq));
    l.receivers_in_block += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    fn id(n: u8) -> ReceiverId {
        ReceiverId(Hash::digest(&[n]).0)
    }

    /// A reference root: every level of the full depth-256 tree over the sparse leaves, level
    /// by level, keyed by prefix.
    fn reference_root(leaves: &[(ReceiverId, u64)]) -> Hash {
        let mut level: BTreeMap<Vec<bool>, Hash> = leaves
            .iter()
            .map(|(i, s)| ((0..DEPTH).map(|b| bit(&i.0, b)).collect(), leaf(i, *s)))
            .collect();
        for h in 0..DEPTH {
            let mut next: BTreeMap<Vec<bool>, Hash> = BTreeMap::new();
            for (path, _) in level.iter() {
                let parent: Vec<bool> = path[..path.len() - 1].to_vec();
                if next.contains_key(&parent) {
                    continue;
                }
                let mut l = parent.clone();
                l.push(false);
                let mut r = parent.clone();
                r.push(true);
                let lh = level.get(&l).copied().unwrap_or(empty(h));
                let rh = level.get(&r).copied().unwrap_or(empty(h));
                next.insert(parent, node(&lh, &rh));
            }
            level = next;
        }
        level.get(&Vec::new()).copied().unwrap_or(empty(DEPTH))
    }

    #[test]
    fn the_spec_leaf_vector_reproduces() {
        let id = ReceiverId(
            hex::decode("2c3bb9f942d0d66b095dd7491db1153de6d8f08dc411c89def38717863ecf0d4")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            hex::encode(leaf(&id, 0).as_bytes()),
            "9a28860060f9a80b9c0b72e50a084e8c894184b4c89f134a17a81e63dd333cf2"
        );
    }

    #[test]
    fn roots_match_a_reference_for_0_1_2_and_many_leaves() {
        for n in [0usize, 1, 2, 3, 40] {
            let mut m = MemoryReceivers::default();
            let leaves: Vec<(ReceiverId, u64)> = (0..n)
                .map(|i| (id(i as u8), m.insert(id(i as u8))))
                .collect();
            let view = SeqView::new(&m.seqs, n as u64, &[]);
            assert_eq!(root(&view), reference_root(&leaves), "n = {n}");
        }
        assert_eq!(root(&SeqView::new(&BTreeMap::new(), 0, &[])), empty_root());
    }

    #[test]
    fn absence_verifies_before_insertion_and_fails_after() {
        let mut m = MemoryReceivers::default();
        for i in 0..10 {
            m.insert(id(i));
        }
        let before = root(&SeqView::new(&m.seqs, 10, &[]));
        let new = id(200);
        let ReceiverProof::Absent(p) = lookup(&SeqView::new(&m.seqs, 10, &[]), &new) else {
            panic!("absent")
        };
        assert_eq!(p.root_with(&new, Hash::ZERO), Some(before));
        let after = p.root_with(&new, leaf(&new, 10)).unwrap();
        m.insert(new);
        assert_eq!(
            root(&SeqView::new(&m.seqs, 11, &[])),
            after,
            "the proof alone gives the new root"
        );
        // Now present, and its membership proof verifies against the new root only.
        let ReceiverProof::Present { seq, proof } = lookup(&SeqView::new(&m.seqs, 11, &[]), &new)
        else {
            panic!("present")
        };
        assert_eq!(seq, 10);
        assert_eq!(proof.root_with(&new, leaf(&new, 10)), Some(after));
        assert_ne!(proof.root_with(&new, leaf(&new, 10)), Some(before));
    }

    #[test]
    fn a_view_cut_at_count_is_the_old_registry_and_pending_extends_it() {
        let mut m = MemoryReceivers::default();
        for i in 0..5 {
            m.insert(id(i));
        }
        let at3 = root(&SeqView::new(&m.seqs, 3, &[]));
        let mut small = MemoryReceivers::default();
        for i in 0..3 {
            small.insert(id(i));
        }
        assert_eq!(
            at3,
            root(&SeqView::new(&small.seqs, 3, &[])),
            "a count cuts the committed map by seq"
        );
        // A branch two registrations above a store that has only three.
        let pending = [(id(3), 3), (id(4), 4)];
        assert_eq!(
            root(&SeqView::new(&small.seqs, 5, &pending)),
            root(&SeqView::new(&m.seqs, 5, &[]))
        );
        // Pending entries the store already has are ignored, not doubled.
        assert_eq!(
            root(&SeqView::new(&m.seqs, 5, &pending)),
            root(&SeqView::new(&m.seqs, 5, &[]))
        );
    }

    #[test]
    fn a_source_answers_through_the_rwlock() {
        let src = RwLock::new(MemoryReceivers::default());
        assert!(matches!(
            src.lookup(0, &[], &id(1)),
            Some(ReceiverProof::Absent(_))
        ));
    }
}
