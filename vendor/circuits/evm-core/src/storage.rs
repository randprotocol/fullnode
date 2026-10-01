//! The contract storage tree (Task 2 of the M4.3 plan): a depth-32 sparse binary Merkle tree
//! over 256-bit slots, hashed with the domain-tagged Poseidon2 sponge the note layer already
//! uses, so `SLOAD`/`SSTORE` are the note tree's `MERKLE_VERIFY` in Rust rather than a Keccak
//! walk.
//!
//! The guest never holds the tree: it holds the pre-state root and one [`Witness`] per slot the
//! run touches (value plus 32 siblings, bottom-up, supplied through the input vector). A witness
//! is verified against the current root the first time its slot is used; a slot the bytecode
//! touches without a witness is [`StorageError::NoWitness`], which the interpreter turns into an
//! exceptional halt.
//!
//! **Leaf position** is the top 32 bits, big-endian, of `keccak256(slot as 32 big-endian bytes)`
//! read as a `u32` whose bit `i` (LSB first) chooses left (0) or right (1) at level `i` — the
//! note tree's `emit_merkle_verify` convention exactly.
//!
//! **At most one witness per leaf position** ([`StorageTree::push`]): a second witness at a
//! position already taken is [`StorageError::DuplicateIndex`], which the ABI turns into a parse
//! error (status 2, `post_root = pre_root`). Two *distinct* slots ground into one 32-bit position
//! would otherwise both verify whenever the position is empty — both leaves are the canonical
//! `H(STORAGE_LEAF, [0; 16])` under identical siblings — and then a call that read both before
//! writing both would bind a `post_root` holding only the second store while the interpreter
//! carried on believing in the first. Refusing the pair at the input is what makes a position
//! collision the fail-closed griefing the spec claims and never a divergence between the bound
//! root and the run.
//!
//! **The leaf is canonical in the value** ([`leaf_hash`]): a zero value hashes to the one
//! `H(STORAGE_LEAF, [0; 16])` whatever the slot is, so an absent slot, a never-written slot and a
//! slot written back to zero are indistinguishable and the root is history-independent.
//!
//! **Multi-slot updates** are the part independent witnesses get wrong: as soon as one leaf
//! changes, every other witness's sibling at the level where its path diverges from the updated
//! one is stale. [`StorageTree::store`] refreshes exactly those, level by level, so a witness
//! stays valid against the new root whether or not it had already been verified.

use crate::u256::U256;
use crate::{hash_pair, keccak256, Host};

/// Depth of the storage tree: `notes::DEPTH`.
pub const DEPTH: usize = 32;
/// The most slots one call may touch (plan's Global Constraints).
pub const MAX_WITNESSES: usize = 16;

/// `notes::domain::STORAGE_LEAF` — a storage leaf, `[slot(8), value(8)]`. Mirrored here because
/// `evm-core` cannot depend on `research`; `tests/evm_storage.rs` asserts the two agree.
pub const STORAGE_LEAF_DOMAIN: u32 = 12;
/// `notes::domain::NODE` — a tree node, `[left(8), right(8)]`, shared with the commitment tree.
pub const NODE_DOMAIN: u32 = 7;
/// `notes::domain::EVM_OUT` — the guest's 40-word public-output preimage (used in Task 4).
pub const EVM_OUT_DOMAIN: u32 = 13;

/// A Merkle witness for one slot: its value in the pre-state and the 32 sibling hashes from the
/// leaf up. `verified` is the guest's own bookkeeping, not part of the input — it is set once the
/// witness has been checked against the root, and stays set across stores because
/// [`StorageTree::store`] refreshes the siblings the update invalidated.
#[derive(Clone, Copy)]
pub struct Witness {
    pub slot: U256,
    pub value: U256,
    pub siblings: [[u32; 8]; DEPTH],
    pub verified: bool,
}

impl Witness {
    /// The padding a [`StorageTree`]'s unused slots hold. Never verified and never found by
    /// `find`, which only searches the first `n`.
    const EMPTY: Witness =
        Witness { slot: U256::ZERO, value: U256::ZERO, siblings: [[0; 8]; DEPTH], verified: false };
}

/// Why a storage access failed. Every variant is an exceptional halt for the interpreter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StorageError {
    /// The bytecode touched a slot no witness was supplied for.
    NoWitness,
    /// A supplied witness does not hash to the current root.
    BadWitness,
    /// More than [`MAX_WITNESSES`] witnesses were pushed.
    TooMany,
    /// Two witnesses claim one leaf position — the same slot twice, or two slots ground into one
    /// 32-bit index. Refused at [`StorageTree::push`]: see the module doc.
    DuplicateIndex,
}

/// The guest's view of contract storage: a root and up to [`MAX_WITNESSES`] witnesses.
///
/// Every field is private and [`push`](StorageTree::push) is the only way a witness gets in,
/// because `indices` — each witness's leaf position, cached so `store` does no Keccak per witness
/// per level — has to stay in step with the witness beside it. With public fields, building a tree
/// by assignment (`t.witnesses[0] = w; t.n = 1;`) would leave a stale `indices[0] = 0` and fold the
/// witness down the wrong path; `push` computes the index from the witness's own slot, so the two
/// cannot come apart. Read access is [`root`](StorageTree::root), [`len`](StorageTree::len) and
/// [`witness`](StorageTree::witness).
pub struct StorageTree {
    root: [u32; 8],
    witnesses: [Witness; MAX_WITNESSES],
    n: usize,
    /// `slot_index` of each pushed witness, cached at `push` so `store` does no Keccak per
    /// witness per level (16 × 32 of them otherwise).
    indices: [u32; MAX_WITNESSES],
}

impl StorageTree {
    /// An empty tree with a zero root: a valid, unused value, and a `const` so a `static` holding
    /// one (the guest's `abi::Workspace` in `.bss`) costs no image bytes. [`reset`](Self::reset)
    /// gives it the pre-state root of an actual call.
    pub const ZERO: StorageTree = StorageTree {
        root: [0; 8],
        witnesses: [Witness::EMPTY; MAX_WITNESSES],
        n: 0,
        indices: [0; MAX_WITNESSES],
    };

    pub fn new(pre_root: [u32; 8]) -> Self {
        StorageTree { root: pre_root, witnesses: [Witness::EMPTY; MAX_WITNESSES], n: 0, indices: [0; MAX_WITNESSES] }
    }

    /// Re-arm a tree in place for a new call: the given pre-state root, no witnesses. The witness
    /// array is left as it is — nothing reads past `n`, and `push` overwrites each slot it uses —
    /// so this is O(1) rather than 17 KiB of stores, which matters in the guest.
    pub fn reset(&mut self, pre_root: [u32; 8]) {
        self.root = pre_root;
        self.n = 0;
    }

    /// The current root: the pre-state root until the first [`store`](StorageTree::store), the
    /// post-state root after the last one. The public output binds both.
    pub fn root(&self) -> [u32; 8] {
        self.root
    }

    /// How many witnesses were pushed.
    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// The `i`th pushed witness. Panics if `i >= len()`.
    pub fn witness(&self, i: usize) -> &Witness {
        assert!(i < self.n);
        &self.witnesses[i]
    }

    /// Take a witness, computing its leaf position from its own slot. The index is never supplied
    /// from outside, which is what keeps `indices` honest.
    ///
    /// Two witnesses at one leaf position are [`StorageError::DuplicateIndex`] — the module doc
    /// says why the alternative is a forgery rather than griefing. Nothing legitimate is refused:
    /// the same slot twice is redundant (`find` would only ever see the first), and two distinct
    /// slots at one position can both be valid only while both are zero, which the known
    /// limitation already gives up on.
    pub fn push<H: Host>(&mut self, h: &mut H, w: Witness) -> Result<(), StorageError> {
        if self.n == MAX_WITNESSES {
            return Err(StorageError::TooMany);
        }
        let idx = slot_index(h, &w.slot);
        for j in 0..self.n {
            if self.indices[j] == idx {
                return Err(StorageError::DuplicateIndex);
            }
        }
        self.indices[self.n] = idx;
        self.witnesses[self.n] = w;
        self.n += 1;
        Ok(())
    }

    fn find(&self, slot: &U256) -> Option<usize> {
        (0..self.n).find(|&i| self.witnesses[i].slot == *slot)
    }

    /// Hash the witness's leaf up its path and compare with the current root. Idempotent: a
    /// witness already verified is not re-hashed, which is what makes a `load` after a `store`
    /// free — the store kept every other witness's siblings current.
    fn verify<H: Host>(&mut self, h: &mut H, i: usize) -> Result<(), StorageError> {
        if self.witnesses[i].verified {
            return Ok(());
        }
        let idx = self.indices[i];
        let mut cur = leaf_hash(h, &self.witnesses[i].slot, &self.witnesses[i].value);
        for l in 0..DEPTH {
            let sib = self.witnesses[i].siblings[l];
            cur = if (idx >> l) & 1 == 0 { node_hash(h, &cur, &sib) } else { node_hash(h, &sib, &cur) };
        }
        if cur != self.root {
            return Err(StorageError::BadWitness);
        }
        self.witnesses[i].verified = true;
        Ok(())
    }

    /// `SLOAD`: find the witness, verify it against the current root the first time it is used,
    /// return the value.
    pub fn load<H: Host>(&mut self, h: &mut H, slot: &U256) -> Result<U256, StorageError> {
        let i = self.find(slot).ok_or(StorageError::NoWitness)?;
        self.verify(h, i)?;
        Ok(self.witnesses[i].value)
    }

    /// `SSTORE`: load (which verifies), set the value, recompute the root along the path, and
    /// refresh the sibling every other witness holds at the level where its path diverges from
    /// this one. Returns the previous value (the gas schedule needs it).
    pub fn store<H: Host>(&mut self, h: &mut H, slot: &U256, value: U256) -> Result<U256, StorageError> {
        let i = self.find(slot).ok_or(StorageError::NoWitness)?;
        self.verify(h, i)?;
        let prev = self.witnesses[i].value;
        self.witnesses[i].value = value;
        let idx = self.indices[i];
        let mut cur = leaf_hash(h, slot, &value);
        for l in 0..DEPTH {
            // `cur` is this path's node at level `l`. Any other witness whose path agrees with
            // ours strictly above level `l` and differs at level `l` has that very node as its
            // sibling at level `l` — and it is the only sibling of its path this update touched.
            // With one witness there is no other path at all (the common case for a one-slot call),
            // so the scan is skipped rather than run `DEPTH` times over nothing.
            if self.n > 1 {
                for j in 0..self.n {
                    if j == i {
                        continue;
                    }
                    let jdx = self.indices[j];
                    let same_above = l == DEPTH - 1 || (idx >> (l + 1)) == (jdx >> (l + 1));
                    let differs_here = ((idx >> l) & 1) != ((jdx >> l) & 1);
                    if same_above && differs_here {
                        self.witnesses[j].siblings[l] = cur;
                    }
                }
            }
            let sib = self.witnesses[i].siblings[l];
            cur = if (idx >> l) & 1 == 0 { node_hash(h, &cur, &sib) } else { node_hash(h, &sib, &cur) };
        }
        self.root = cur;
        Ok(prev)
    }
}

/// The leaf position of `slot`: the top 32 bits, big-endian, of `keccak256(slot)`.
pub fn slot_index<H: Host>(h: &mut H, slot: &U256) -> u32 {
    let k = keccak256(h, &slot.to_be_bytes());
    u32::from_be_bytes([k[0], k[1], k[2], k[3]])
}

/// `H(STORAGE_LEAF, [slot(8), value(8)])`, canonical in the value: a zero value gives the one
/// `H(STORAGE_LEAF, [0; 16])` whatever the slot, so an absent slot, a never-written slot and a
/// slot written back to zero hash alike and the root is history-independent. Every leaf the host
/// builder and this crate compute — witnesses, verification, loads, stores and the default
/// subtrees of an empty tree — goes through this one function.
pub fn leaf_hash<H: Host>(h: &mut H, slot: &U256, value: &U256) -> [u32; 8] {
    if value.is_zero() {
        return hash_pair(h, STORAGE_LEAF_DOMAIN, &[0; 8], &[0; 8]);
    }
    hash_pair(h, STORAGE_LEAF_DOMAIN, &slot.0, &value.0)
}

/// `H(NODE, [left(8), right(8)])` — the commitment tree's node hash exactly.
pub fn node_hash<H: Host>(h: &mut H, l: &[u32; 8], r: &[u32; 8]) -> [u32; 8] {
    hash_pair(h, NODE_DOMAIN, l, r)
}
