//! The contract storage tree (Task 2 of the M4.3 plan): a sparse binary Merkle tree of depth
//! [`DEPTH`] (64 in storage layout 2, the default; 32 in layout 1, the `storage-v1` feature — see
//! [`LAYOUT_VERSION`]) over 256-bit slots, hashed with the domain-tagged Poseidon2 sponge the note layer already
//! uses, so `SLOAD`/`SSTORE` are the note tree's `MERKLE_VERIFY` in Rust rather than a Keccak
//! walk.
//!
//! The guest never holds the tree: it holds the pre-state root and one [`Witness`] per slot the
//! run touches (value plus [`DEPTH`] siblings, bottom-up, supplied through the input vector). A witness
//! is verified against the current root the first time its slot is used; a slot the bytecode
//! touches without a witness is [`StorageError::NoWitness`], which the interpreter turns into an
//! exceptional halt.
//!
//! **Leaf position** is the top [`DEPTH`] bits, big-endian, of `keccak256(slot as 32 big-endian
//! bytes)` read as an integer whose bit `i` (LSB first) chooses left (0) or right (1) at level `i`
//! — the note tree's `emit_merkle_verify` convention exactly. In layout 1 that was 32 bits, and a
//! slot landing on a *chosen* victim slot's position cost about 2^32 Keccaks (ZKVM-105); in layout
//! 2 it is 64 bits and costs about 2^64.
//!
//! **At most one witness per leaf position** ([`StorageTree::push`]): a second witness at a
//! position already taken is [`StorageError::DuplicateIndex`], which the ABI turns into a parse
//! error (status 2, `post_root = pre_root`). Two *distinct* slots ground into one position
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

use crate::u256::{words_eq, U256};
use crate::{hash_pair, keccak256, Host};

/// Words in the Merkle walk's sliding buffer ([`StorageTree::walk`]): one 17-word sponge message,
/// and nine more words for every level the window slides down.
const SCRATCH_WORDS: usize = 17 + 9 * DEPTH;

/// The storage layout this build of the crate implements, bound as the first word of the public
/// output's preimage (`abi`), so a root is never read under the wrong layout:
///
/// * **1** — depth 32, the leaf position the top 32 bits of `keccak256(slot)`. Built only with
///   the `storage-v1` feature (`guests-compiled/evm-v1`), for contracts whose storage was rooted
///   under it.
/// * **2** — depth 64, the top 64 bits. The default.
///
/// A layout is a property of the *image*: each has its own `hc`, a chain admits both side by
/// side, and a contract's record says which layout its root is under (`docs/04-guests.md`).
#[cfg(not(feature = "storage-v1"))]
pub const LAYOUT_VERSION: u32 = 2;
#[cfg(feature = "storage-v1")]
pub const LAYOUT_VERSION: u32 = 1;

/// Depth of the storage tree, and the width in bits of a leaf position.
#[cfg(not(feature = "storage-v1"))]
pub const DEPTH: usize = 64;
#[cfg(feature = "storage-v1")]
pub const DEPTH: usize = 32;

/// The most slots one call may touch. 16 through layout 1's first image; 32 since ZKVM-105.
pub const MAX_WITNESSES: usize = 32;

/// `notes::domain::STORAGE_LEAF` — a storage leaf, `[slot(8), value(8)]`. Mirrored here because
/// `evm-core` cannot depend on `research`; `tests/evm_storage.rs` asserts the two agree.
pub const STORAGE_LEAF_DOMAIN: u32 = 12;
/// `notes::domain::NODE` — a tree node, `[left(8), right(8)]`, shared with the commitment tree.
pub const NODE_DOMAIN: u32 = 7;
/// `notes::domain::EVM_OUT` — the guest's 40-word public-output preimage (used in Task 4).
pub const EVM_OUT_DOMAIN: u32 = 13;

/// A Merkle witness for one slot: its value in the pre-state and the [`DEPTH`] sibling hashes from
/// the leaf up. `verified` is the guest's own bookkeeping, not part of the input — it is set once the
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
    /// index. Refused at [`StorageTree::push`]: see the module doc.
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
    /// witness per level.
    indices: [u64; MAX_WITNESSES],
    /// The Merkle walk's buffer ([`walk`](Self::walk)). Here rather than on the stack so that the
    /// guest pays nothing to zero it: it is `.bss`, and every word a sponge call reads is written
    /// by the walk first.
    scratch: [u32; SCRATCH_WORDS],
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
        scratch: [0; SCRATCH_WORDS],
    };

    pub fn new(pre_root: [u32; 8]) -> Self {
        StorageTree { root: pre_root, ..StorageTree::ZERO }
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

    /// [`push`](Self::push) for a witness still on the input tape: its slot, value and siblings
    /// are read word by word from `next` **into place** — `slot(8) ‖ value(8) ‖ sibling_0(8) ‖ …`,
    /// the input vector's own order — with the same refusals as `push`. Building a [`Witness`]
    /// and handing it to `push` moves about 2 KiB twice, a `memcpy` call that cost 5 168 guest
    /// cycles per witness (ZKVM-117); this moves nothing.
    ///
    /// A refused witness leaves the tree as it was (its words have been read and are ignored).
    pub fn read_witness<H: Host, F: FnMut() -> u32>(&mut self, h: &mut H, mut next: F) -> Result<(), StorageError> {
        if self.n == MAX_WITNESSES {
            return Err(StorageError::TooMany);
        }
        let w = &mut self.witnesses[self.n];
        let mut k = 0;
        while k < 8 {
            w.slot.0[k] = next();
            k += 1;
        }
        let mut k = 0;
        while k < 8 {
            w.value.0[k] = next();
            k += 1;
        }
        let mut l = 0;
        while l < DEPTH {
            let sib = &mut w.siblings[l];
            let mut k = 0;
            while k < 8 {
                sib[k] = next();
                k += 1;
            }
            l += 1;
        }
        w.verified = false;
        let idx = slot_index(h, &self.witnesses[self.n].slot);
        for j in 0..self.n {
            if self.indices[j] == idx {
                return Err(StorageError::DuplicateIndex);
            }
        }
        self.indices[self.n] = idx;
        self.n += 1;
        Ok(())
    }

    fn find(&self, slot: &U256) -> Option<usize> {
        (0..self.n).find(|&i| self.witnesses[i].slot == *slot)
    }

    /// Hash witness `i`'s leaf (its slot with `value`) up its path and return the root that gives.
    /// With `refresh`, every *other* witness's sibling at the level where its path diverges from
    /// this one is replaced by this path's node there (`diverges[j]`, `u8::MAX` for none) — what a
    /// store needs.
    ///
    /// **The walk hashes in place, in a window that slides down a buffer** (ZKVM-117). A node is
    /// `POSEIDON2` over 17 words `[NODE, left(8), right(8)]`, and the syscall leaves the digest in
    /// the first eight words of its message. So the next level's message is laid *around* the
    /// digest instead of copying it: if the path's node is the left child, the window moves down
    /// one word — the digest is already where `left` goes — and if it is the right child, down
    /// nine. Each level then writes only the domain word and the sibling. The first cut built a
    /// fresh 17-word message per level and copied the digest out and back in (`hash_pair`), which
    /// with the call overhead was about 207 guest cycles a level against the syscall's own 8.
    fn walk<H: Host>(&mut self, h: &mut H, i: usize, value: &U256, diverges: Option<&[u8; MAX_WITNESSES]>) -> [u32; 8] {
        let buf = &mut self.scratch;
        // The leaf: `[STORAGE_LEAF, slot(8), value(8)]`, all zeros for a zero value (canonical).
        let mut p = SCRATCH_WORDS - 17;
        {
            let w: &mut [u32; 17] = (&mut buf[p..p + 17]).try_into().unwrap();
            w[0] = STORAGE_LEAF_DOMAIN;
            let zero = value.is_zero();
            let slot = &self.witnesses[i].slot.0;
            let mut k = 0;
            while k < 8 {
                w[1 + k] = if zero { 0 } else { slot[k] };
                w[9 + k] = if zero { 0 } else { value.0[k] };
                k += 1;
            }
            h.poseidon2(w, 17);
        }
        // The path's bits come off the bottom of a running copy: a 64-bit shift by one is a few
        // instructions on the 32-bit guest, where `idx >> l` is a library call per level.
        let mut bits = self.indices[i];
        let mut l = 0;
        while l < DEPTH {
            if let Some(d) = diverges {
                let mut j = 0;
                while j < self.n {
                    if d[j] as usize == l {
                        let mut k = 0;
                        while k < 8 {
                            self.witnesses[j].siblings[l][k] = buf[p + k];
                            k += 1;
                        }
                    }
                    j += 1;
                }
            }
            let sib = &self.witnesses[i].siblings[l];
            // Left child: the digest at `p..p+8` becomes `left` of a window one word lower.
            // Right child: it becomes `right` of a window nine words lower.
            let at = if bits & 1 == 0 {
                p -= 1;
                9
            } else {
                p -= 9;
                1
            };
            let w: &mut [u32; 17] = (&mut buf[p..p + 17]).try_into().unwrap();
            w[0] = NODE_DOMAIN;
            let mut k = 0;
            while k < 8 {
                w[at + k] = sib[k];
                k += 1;
            }
            h.poseidon2(w, 17);
            bits >>= 1;
            l += 1;
        }
        let mut out = [0u32; 8];
        let mut k = 0;
        while k < 8 {
            out[k] = buf[p + k];
            k += 1;
        }
        out
    }

    /// Hash the witness's leaf up its path and compare with the current root. Idempotent: a
    /// witness already verified is not re-hashed, which is what makes a `load` after a `store`
    /// free — the store kept every other witness's siblings current.
    fn verify<H: Host>(&mut self, h: &mut H, i: usize) -> Result<(), StorageError> {
        if self.witnesses[i].verified {
            return Ok(());
        }
        let value = self.witnesses[i].value;
        if !words_eq(&self.walk(h, i, &value, None), &self.root) {
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
        // Another witness's path agrees with this one strictly above some level and differs at
        // it: the highest set bit of the two positions' XOR. Its sibling at exactly that level is
        // this path's node there, and that is the only sibling of its path this update touches.
        // The level is found once per witness here, so the walk below compares a byte per witness
        // per level rather than shifting two 64-bit positions.
        let mut diverges = [0u8; MAX_WITNESSES];
        if self.n > 1 {
            for j in 0..self.n {
                // Positions are distinct (`push`), so the XOR is non-zero for every `j != i`; for
                // `j == i` it is zero and the level is set past the top, where nothing matches.
                let x = idx ^ self.indices[j];
                diverges[j] = if x == 0 { u8::MAX } else { (63 - x.leading_zeros()) as u8 };
            }
        }
        self.root = self.walk(h, i, &value, if self.n > 1 { Some(&diverges) } else { None });
        Ok(prev)
    }
}

/// The leaf position of `slot`: the top [`DEPTH`] bits, big-endian, of `keccak256(slot)`.
pub fn slot_index<H: Host>(h: &mut H, slot: &U256) -> u64 {
    let k = keccak256(h, &slot.to_be_bytes());
    let top = u64::from_be_bytes([k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]]);
    top >> (64 - DEPTH)
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
