//! The host side of the EVM guest (M4.3): the [`evm_core::Host`] implementation `evm-core` is
//! generic over, and the sparse storage-tree builder that produces the witnesses the guest
//! consumes.
//!
//! `evm-core` is `no_std` and cannot depend on this crate, so it carries its own copies of the
//! Keccak padding, the domain-tagged sponge wrapper and the storage-tree hashes. Everything here
//! is the reference those copies are checked against, from the same primitives the guest's
//! syscalls compute (`keccak::keccak_f`, `hash::sponge_hash`) — `tests/evm_storage.rs` asserts
//! host and guest agree on every index, leaf and root.
//!
//! The tree is [`DEPTH`] = 64 levels (storage layout 2; 32 under layout 1, [`layout_depth`]) of the
//! commitment tree's own node hash over storage leaves: position is the top `DEPTH` bits,
//! big-endian, of `keccak256(slot as 32 big-endian bytes)`,
//! whose bit `i` (LSB first) chooses left/right at level `i` — `asm::emit_merkle_verify`'s
//! convention. The leaf is canonical in the value, so the empty tree has a well-defined root and
//! writing a slot back to zero restores it ([`leaf_hash`]).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use evm_core::abi::{run_call_with, Statement, Workspace};
use evm_core::interp::{Env, Outcome};
use evm_core::u256::U256;

use crate::hash::sponge_hash;
use crate::keccak;
use crate::notes::{self, domain, Word8};

/// [`evm_core::Host`] over this crate's reference primitives: the Keccak-f[1600] permutation the
/// `KECCAK` syscall computes and the Poseidon2 sponge the `POSEIDON2` syscall computes. Every
/// `evm-core` function is therefore exercised natively on exactly the arithmetic the guest will
/// see in-circuit.
pub struct HostRef;

impl evm_core::Host for HostRef {
    fn keccak_f(&mut self, state: &mut [u32; 50]) {
        let mut lanes = keccak::words_to_state(state);
        keccak::keccak_f(&mut lanes);
        *state = keccak::state_to_words(&lanes);
    }
    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        let digest = sponge_hash(&words[..n]);
        words[..8].copy_from_slice(&digest);
    }
    /// No public segment: every word reads 0, which is no context version, so every
    /// block-context opcode traps (`evm_core::block`) — what a version-1 context gives. A call
    /// with a segment runs over [`HostPublic`].
    fn read_public(&mut self, _idx: u32) -> u32 {
        0
    }
}

/// [`HostRef`] with a public segment: what the guest's `READ_PUBLIC` returns, for the
/// block-context opcodes (`evm_core::block`). A read past the segment panics: in the guest it can
/// never be satisfied, so such a run has no proof, and a test that reaches one has built the
/// wrong segment.
pub struct HostPublic<'a>(pub &'a [u32]);

impl evm_core::Host for HostPublic<'_> {
    fn keccak_f(&mut self, state: &mut [u32; 50]) {
        HostRef.keccak_f(state)
    }
    fn poseidon2(&mut self, words: &mut [u32], n: usize) {
        HostRef.poseidon2(words, n)
    }
    fn read_public(&mut self, idx: u32) -> u32 {
        match self.0.get(idx as usize) {
            Some(&w) => w,
            None => panic!("READ_PUBLIC({idx}) past a {}-word segment: no proof", self.0.len()),
        }
    }
}

/// The block facts of an `InvokeAt`'s version-2 context (fullnode `BlockFacts`, issue #168), on
/// chain `chain_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockFacts {
    pub height: u64,
    pub timestamp_ms: u64,
    pub chain_id: u64,
    pub basefee: u64,
    /// The beacon's 32 bytes after the block's reveal; `None` on a chain without the beacon.
    pub randomness: Option<[u8; 32]>,
}

impl BlockFacts {
    /// The 17 block words the ledger puts at context words 11..28 (`BlockFacts::context_words`):
    /// four u64s low word first, the randomness flag, then the beacon value as eight
    /// little-endian words (all zero, and the flag 0, without one).
    pub fn words(&self) -> [u32; 17] {
        let mut w = [0u32; 17];
        for (k, v) in [self.height, self.timestamp_ms / 1000, self.chain_id, self.basefee].into_iter().enumerate() {
            w[2 * k] = v as u32;
            w[2 * k + 1] = (v >> 32) as u32;
        }
        if let Some(r) = &self.randomness {
            w[8] = 1;
            for i in 0..8 {
                w[9 + i] = u32::from_le_bytes(r[4 * i..4 * i + 4].try_into().unwrap());
            }
        }
        w
    }

    /// An invoke's public segment for an EVM program (deploy-time public input empty):
    /// `binding(8) ‖ context`, the context version 2 over a transition with no cells and no
    /// payouts — header words 1..=10 all zero, then these 17 words.
    pub fn segment(&self, binding: &Word8) -> Vec<u32> {
        let mut s = binding.to_vec();
        s.push(evm_core::block::CONTEXT_VERSION_BLOCK);
        s.extend_from_slice(&[0; 10]);
        s.extend_from_slice(&self.words());
        s
    }
}

/// A version-1 context's segment for an EVM program, `binding(8) ‖ [1, 0 × 10]`: an ordinary
/// `Invoke` with no cells and no payouts.
pub fn v1_segment(binding: &Word8) -> Vec<u32> {
    let mut s = binding.to_vec();
    s.push(1);
    s.extend_from_slice(&[0; 10]);
    s
}

/// The storage layouts (ZKVM-105): the tree's depth, which is also the width in bits of a leaf
/// position. Layout 1 is depth 32, layout 2 depth 64; `evm_core::storage::LAYOUT_VERSION` is the
/// one this build of `evm-core` runs natively (2), and `evm-v1.bin` is layout 1's image.
pub const fn layout_depth(layout: u32) -> usize {
    match layout {
        1 => 32,
        2 => 64,
        _ => panic!("no such storage layout"),
    }
}

/// The current layout's depth: `evm_core::storage::DEPTH`, 64.
pub const DEPTH: usize = evm_core::storage::DEPTH;

/// The leaf position of `slot` in the current layout: the top 64 bits, big-endian, of
/// `keccak256(slot)`, read as an integer whose bit `i` chooses left (0) or right (1) at level `i`.
pub fn slot_index(slot: &U256) -> u64 {
    slot_index_at(slot, DEPTH)
}

/// The leaf position of `slot` in a tree of the given depth: the top `depth` bits of
/// `keccak256(slot)`. `depth = 32` is layout 1's position.
pub fn slot_index_at(slot: &U256, depth: usize) -> u64 {
    assert!((1..=64).contains(&depth));
    let k = keccak::keccak256(&slot.to_be_bytes());
    u64::from_be_bytes([k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]]) >> (64 - depth)
}

/// `H(STORAGE_LEAF, [slot(8), value(8)])`, **canonical in the value**: a zero value gives the one
/// `H(STORAGE_LEAF, [0; 16])` whatever the slot is. So an absent slot, a never-written slot and a
/// slot written back to zero are the same leaf; the storage root is history-independent and the
/// empty tree's root is just this leaf lifted `DEPTH` levels ([`empty_root`]). Every leaf on both sides
/// — witnesses, verification, loads, stores and the default subtrees — goes through this function
/// or its `evm_core::storage::leaf_hash` twin.
pub fn leaf_hash(slot: &U256, value: &U256) -> Word8 {
    let mut msg = [0u32; 16];
    if !value.is_zero() {
        msg[..8].copy_from_slice(&slot.0);
        msg[8..].copy_from_slice(&value.0);
    }
    notes::hash(domain::STORAGE_LEAF, &msg)
}

/// `H(NODE, [left(8), right(8)])` — the commitment tree's node hash exactly.
fn node_hash(l: &Word8, r: &Word8) -> Word8 {
    let mut msg = [0u32; 16];
    msg[..8].copy_from_slice(l);
    msg[8..].copy_from_slice(r);
    notes::hash(domain::NODE, &msg)
}

/// `defaults()[l]` is the root of an empty subtree of depth `l`: `defaults()[0]` is the zero-value
/// leaf and `defaults()[l] = H(NODE, defaults()[l-1], defaults()[l-1])`. Computed once, to depth
/// 64 — the sponge hashes are the same for every tree of every layout, and `SparseTree` consults
/// the table at every level where a subtree holds nothing.
fn defaults() -> &'static [Word8; 65] {
    static TABLE: OnceLock<[Word8; 65]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut d = [[0u32; 8]; 65];
        d[0] = leaf_hash(&U256::ZERO, &U256::ZERO);
        for l in 1..=64 {
            d[l] = node_hash(&d[l - 1], &d[l - 1]);
        }
        d
    })
}

/// The root of the current layout's tree with no slot written: `defaults()[DEPTH]`.
pub fn empty_root() -> Word8 {
    defaults()[DEPTH]
}

/// The host's contract storage: the written slots, keyed by leaf position, with empty subtrees
/// standing in for everything else. Builds the roots and the witnesses the guest verifies.
///
/// A tree has a depth: [`new`](SparseTree::new) is the current layout's (64),
/// [`with_depth`](SparseTree::with_depth) any other — 32 for layout 1's image, and for
/// [`migrate`](SparseTree::migrate).
#[derive(Clone, Debug)]
pub struct SparseTree {
    depth: usize,
    /// Leaf position → (slot, value). Only non-zero values are held: a zero value is the default
    /// leaf, so storing one is removing the entry (and both hash the same).
    entries: BTreeMap<u64, (U256, U256)>,
}

impl Default for SparseTree {
    fn default() -> Self {
        SparseTree::new()
    }
}

impl SparseTree {
    pub fn new() -> Self {
        SparseTree::with_depth(DEPTH)
    }

    /// An empty tree of the given depth (1..=64): 32 is storage layout 1, 64 layout 2.
    pub fn with_depth(depth: usize) -> Self {
        assert!((1..=64).contains(&depth));
        SparseTree { depth, entries: BTreeMap::new() }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The same slots and values in a tree of another depth: the one-time re-rooting a contract's
    /// storage needs to move from layout 1 to layout 2 (`docs/04-guests.md`). The host does it
    /// from the slots it holds; nothing is proved.
    pub fn migrate(&self, depth: usize) -> SparseTree {
        let mut t = SparseTree::with_depth(depth);
        for (slot, value) in self.entries.values() {
            t.insert(*slot, *value);
        }
        t
    }

    /// Write `value` at `slot`. A zero value removes the entry, which is the same tree either way
    /// because the leaf is canonical in the value.
    ///
    /// Panics if two distinct slots collide on one leaf position — a 2^-depth-per-pair event that
    /// would otherwise silently drop a slot, and the tests would rather see it than debug a root.
    /// [`try_insert`](Self::try_insert) reports it instead.
    pub fn insert(&mut self, slot: U256, value: U256) {
        if let Err(held) = self.try_insert(slot, value) {
            panic!("the leaf position of slot {slot:?} is already held by a different slot, {held:?}");
        }
    }

    /// [`insert`](Self::insert), returning the slot that already holds the position instead of
    /// panicking — how a depth-32 tree shows a ground collision.
    pub fn try_insert(&mut self, slot: U256, value: U256) -> Result<(), U256> {
        let idx = slot_index_at(&slot, self.depth);
        if let Some((held, _)) = self.entries.get(&idx) {
            if *held != slot {
                return Err(*held);
            }
        }
        if value.is_zero() {
            self.entries.remove(&idx);
        } else {
            self.entries.insert(idx, (slot, value));
        }
        Ok(())
    }

    /// The hash of the subtree at level `level` whose nodes all share the leaf-position prefix
    /// `prefix = index >> level`. Empty subtrees short-circuit to the default table, so the walk
    /// costs `O(entries × depth)` hashes rather than `O(2^depth)`. (`u128` so that `level = 64`,
    /// the root of a depth-64 tree, is a shift like any other.)
    fn node_at(&self, level: usize, prefix: u128) -> Word8 {
        let Some((_, (slot, value))) = self.entries.iter().find(|(i, _)| (**i as u128) >> level == prefix) else {
            return defaults()[level];
        };
        if level == 0 {
            return leaf_hash(slot, value);
        }
        let l = self.node_at(level - 1, prefix << 1);
        let r = self.node_at(level - 1, (prefix << 1) | 1);
        node_hash(&l, &r)
    }

    pub fn root(&self) -> Word8 {
        self.node_at(self.depth, 0)
    }

    /// The witness for `slot`: its value (zero if the slot was never written) and, for each level
    /// `l = 0..depth`, the hash of the sibling subtree of the path's node at that level, bottom-up.
    ///
    /// Panics, like [`insert`](Self::insert), if a *different* slot holds this leaf position:
    /// `entries` is keyed by position, so without the check the colliding slot's value and leaf
    /// would be handed back as this slot's — a witness that cannot verify, presented as if it
    /// could. `insert` already makes that state unreachable through this type; the assert is here
    /// so it stays unreachable rather than being unreachable by argument.
    pub fn witness(&self, slot: &U256) -> Witness {
        let idx = slot_index_at(slot, self.depth);
        if let Some((held, _)) = self.entries.get(&idx) {
            assert_eq!(held, slot, "leaf position {idx} is held by a different slot");
        }
        let value = self.entries.get(&idx).map(|(_, v)| *v).unwrap_or(U256::ZERO);
        let siblings = (0..self.depth).map(|l| self.node_at(l, ((idx as u128) >> l) ^ 1)).collect();
        Witness { slot: *slot, value, siblings }
    }
}

/// One slot's Merkle witness against a `SparseTree`'s root: the value and one sibling per level
/// from the leaf up (the tree's depth of them). `evm_core::storage::Witness` is the guest's copy,
/// plus its own `verified` flag.
#[derive(Clone, PartialEq, Debug)]
pub struct Witness {
    pub slot: U256,
    pub value: U256,
    pub siblings: Vec<Word8>,
}

impl Witness {
    /// The input-vector encoding: `slot(8) ‖ value(8) ‖ sibling_0(8) ‖ … `, 528 words in the
    /// current layout (272 in layout 1). 256-bit values are their own little-endian limbs, so
    /// nothing is byte-swapped.
    pub fn words(&self) -> Vec<u32> {
        let mut w = Vec::with_capacity(16 + 8 * self.siblings.len());
        w.extend_from_slice(&self.slot.0);
        w.extend_from_slice(&self.value.0);
        for sib in &self.siblings {
            w.extend_from_slice(sib);
        }
        w
    }
}

/// Words per witness in the current layout's input vector: slot 8 + value 8 + `DEPTH` × 8
/// siblings.
pub const WITNESS_WORDS: usize = 16 + DEPTH * 8;

/// One call to the EVM guest, host side: everything the input vector holds, plus the storage tree
/// the witnesses come from. [`input_words`](EvmCall::input_words) encodes it as the machine's
/// private input and [`expected`](EvmCall::expected) says what the guest must output — the pair
/// `tests/evm_abi.rs` checks against each other and against digests recomputed from this crate's
/// own primitives.
pub struct EvmCall {
    pub code: Vec<u8>,
    pub calldata: Vec<u8>,
    pub address: U256,
    pub caller: U256,
    pub callvalue: U256,
    pub gas_limit: u64,
    /// The eight words the consuming chain binds its replay protection to (a transaction hash, a
    /// nonce and chain id). The guest carries them into the public output and nothing else.
    pub context: Word8,
    /// The pre-state storage. `witness(slot)` against this is what the guest verifies.
    pub tree: SparseTree,
    /// The slots a witness is supplied for, in the order they appear in the vector. A slot the
    /// bytecode touches without one is an exceptional halt, so this is the call's access list.
    pub touched: Vec<U256>,
}

impl EvmCall {
    /// The input vector, exactly as the plan's Global Constraints lay it out:
    /// `[n_code, code…, n_calldata, calldata…, address(8), caller(8), callvalue(8), gas_limit(1),
    /// context(8), pre_root(8), n_witnesses(1), witness…]`, byte strings packed 4 per word little-endian and
    /// zero-padded, 256-bit values as their own little-endian limbs, each witness
    /// [`WITNESS_WORDS`] long.
    ///
    /// Panics on a gas limit above `u32::MAX`, which the single `gas_limit` word cannot carry —
    /// a test's own constant, not prover-supplied, so an assert is the right choke point here.
    ///
    /// Panics, too, if two `touched` slots share a leaf position (the same slot listed twice, or a
    /// ground collision): the guest refuses such a vector at `StorageTree::push`
    /// (`ParseError::DuplicateWitnessIndex` → status 2), so a fixture that built one would be
    /// testing the malformed path while looking like a real call. A test that *means* to exercise
    /// the rejection splices the duplicate into the word vector itself.
    pub fn input_words(&self) -> Vec<u32> {
        let depth = self.tree.depth();
        let mut idxs: Vec<u64> = self.touched.iter().map(|s| slot_index_at(s, depth)).collect();
        let n = idxs.len();
        idxs.sort_unstable();
        idxs.dedup();
        assert_eq!(idxs.len(), n, "two touched slots share one leaf position");
        let mut w = Vec::new();
        push_bytes(&mut w, &self.code);
        push_bytes(&mut w, &self.calldata);
        w.extend_from_slice(&self.address.0);
        w.extend_from_slice(&self.caller.0);
        w.extend_from_slice(&self.callvalue.0);
        assert!(self.gas_limit <= u32::MAX as u64, "the layout's gas_limit is one word");
        w.push(self.gas_limit as u32);
        w.extend_from_slice(&self.context);
        w.extend_from_slice(&self.tree.root());
        w.push(self.touched.len() as u32);
        for slot in &self.touched {
            w.extend_from_slice(&self.tree.witness(slot).words());
        }
        w
    }

    /// Run `evm-core` natively over [`HostRef`] and return the eight public output words, the
    /// interpreter's outcome, and the post-state tree.
    ///
    /// The post-state tree is this call's `tree` with every witness's final value written back —
    /// for a successful call only: a revert or an exceptional halt changes no state, however far
    /// the interpreter's own tree got before it failed. When the call did succeed, the host tree's
    /// root and the guest's witness-updated root are asserted equal, which is the one check that
    /// `StorageTree::store`'s sibling refresh and `SparseTree`'s rebuild agree.
    pub fn expected(&self) -> ([u32; 8], Outcome, SparseTree) {
        self.expected_over(&mut HostRef)
    }

    /// [`expected`](EvmCall::expected) with `public` as the public segment the guest reads the
    /// block-context words from (`evm_core::block`): an invoke's `binding ‖ context`,
    /// [`BlockFacts::segment`] or [`v1_segment`].
    pub fn expected_on(&self, public: &[u32]) -> ([u32; 8], Outcome, SparseTree) {
        self.expected_over(&mut HostPublic(public))
    }

    fn expected_over<H: evm_core::Host>(&self, h: &mut H) -> ([u32; 8], Outcome, SparseTree) {
        assert_eq!(self.tree.depth(), DEPTH, "evm-core runs the current layout natively; a layout-1 call goes through evm-v1.bin");
        let words = self.input_words();
        // The guest keeps this in `.bss`; a host test boxes it (146 KiB is not for a frame).
        let mut ws = Box::new(Workspace::ZERO);
        let (out, o) = run_call_with(h, &mut ws, |i| words[i as usize], words.len() as u32);
        let mut post = self.tree.clone();
        if o.status() == 1 {
            for i in 0..ws.input.storage.len() {
                let w = ws.input.storage.witness(i);
                post.insert(w.slot, w.value);
            }
            assert_eq!(
                post.root(),
                ws.input.storage.root(),
                "the host tree and the guest's witnesses disagree on the post-state root"
            );
        }
        (out, o, post)
    }

    /// The call's environment as `evm-core` takes it.
    pub fn env(&self) -> Env {
        Env {
            address: self.address,
            caller: self.caller,
            callvalue: self.callvalue,
            gas_limit: self.gas_limit,
        }
    }

    /// `evm_core::abi::public_output` for this call's calldata, environment and context over the
    /// given code, roots and outcome — the guest's own function, for tests that vary one of the
    /// four. [`EvmStatement`] is the independent recomputation.
    pub fn output_for(&self, code: &[u8], pre_root: &Word8, post_root: &Word8, o: &Outcome) -> [u32; 8] {
        let env = self.env();
        let s = Statement {
            code,
            codehash: None,
            calldata: &self.calldata,
            env: &env,
            context: &self.context,
            pre_root,
            post_root,
        };
        evm_core::abi::public_output(&mut HostRef, &s, o)
    }
}

/// One log as a verifier holds it: the topics and the data, in full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmLog {
    pub topics: Vec<U256>,
    pub data: Vec<u8>,
}

/// **The verifier's side of the EVM guest's public output** (ZKVM-103, ZKVM-104): what a chain
/// that means to apply a call holds, and the eight output words a proof of exactly that call must
/// carry. Computed from this crate's own Keccak and sponge, never from `evm-core`.
///
/// This is where authorisation is enforced. The guest binds `caller`, `address`, `callvalue`, the
/// calldata, `gas_limit` and `context` into the digest but cannot know whether the caller agreed;
/// the chain fills those six fields **from the transaction it authenticated** (the spender its
/// signature or spend authority names, the calldata that spender signed, its own nonce or
/// transaction hash in `context`) and accepts the proof only if
/// [`accepts`](EvmStatement::accepts) holds. A proof made with any other caller — by a prover who
/// holds the storage witnesses and nothing else — has other output words and is refused.
///
/// For a status other than 1 the chain sets `post_root = pre_root` and no logs, and for a status
/// of 2 no return data and `gas_used = gas_limit`: [`output_words`](EvmStatement::output_words)
/// hashes the fields exactly as given and applies no rule of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmStatement {
    /// The storage layout both roots are under (`evm_core::storage::LAYOUT_VERSION`): 1 for
    /// `evm-v1.bin`'s depth-32 tree, 2 for `evm.bin`'s depth-64 one. A chain keeps it in the
    /// contract's record beside the root, and admits the image of that layout for the contract.
    pub layout: u32,
    /// `keccak256` of the contract's runtime bytecode.
    pub codehash: [u8; 32],
    pub pre_root: Word8,
    pub post_root: Word8,
    pub return_data: Vec<u8>,
    pub logs: Vec<EvmLog>,
    pub address: U256,
    pub caller: U256,
    pub callvalue: U256,
    pub calldata: Vec<u8>,
    pub context: Word8,
    pub gas_limit: u32,
    pub gas_used: u32,
}

impl EvmStatement {
    /// `keccak256(be32(n_logs) ‖ per log: be32(n_topics) ‖ topics ‖ keccak256(data))`.
    pub fn logs_hash(&self) -> [u8; 32] {
        let mut msg = (self.logs.len() as u32).to_be_bytes().to_vec();
        for log in &self.logs {
            msg.extend_from_slice(&(log.topics.len() as u32).to_be_bytes());
            for t in &log.topics {
                msg.extend_from_slice(&t.to_be_bytes());
            }
            msg.extend_from_slice(&keccak::keccak256(&log.data));
        }
        keccak::keccak256(&msg)
    }

    /// The 83-word `EVM_OUT` preimage.
    pub fn preimage(&self) -> Vec<u32> {
        let pack = |h: [u8; 32]| -> Word8 {
            std::array::from_fn(|i| u32::from_le_bytes([h[4 * i], h[4 * i + 1], h[4 * i + 2], h[4 * i + 3]]))
        };
        let mut msg = Vec::with_capacity(83);
        msg.push(self.layout);
        msg.extend_from_slice(&pack(self.codehash));
        msg.extend_from_slice(&self.pre_root);
        msg.extend_from_slice(&self.post_root);
        msg.extend_from_slice(&pack(keccak::keccak256(&self.return_data)));
        msg.extend_from_slice(&pack(self.logs_hash()));
        msg.extend_from_slice(&self.address.0);
        msg.extend_from_slice(&self.caller.0);
        msg.extend_from_slice(&self.callvalue.0);
        msg.extend_from_slice(&pack(keccak::keccak256(&self.calldata)));
        msg.extend_from_slice(&self.context);
        msg.push(self.gas_limit);
        msg.push(self.gas_used);
        msg
    }

    /// The eight output words a proof of this statement carries: `status`, then words 0..6 of
    /// `hash(EVM_OUT, preimage)`.
    pub fn output_words(&self, status: u32) -> [u32; 8] {
        let d = notes::hash(domain::EVM_OUT, &self.preimage());
        let mut out = [0u32; 8];
        out[0] = status;
        out[1..8].copy_from_slice(&d[..7]);
        out
    }

    /// Whether a proof's eight output words are a proof of this statement with this status — the
    /// check a chain makes after `Machine::verify`, and the one that refuses a call the statement's
    /// `caller` did not make.
    pub fn accepts(&self, status: u32, outputs: &[u32; 8]) -> bool {
        self.output_words(status) == *outputs
    }
}

/// `transferOwnership` in sixteen bytes, for the authorisation tests: slot 0 holds the owner, and
/// the call replaces it with `CALLDATALOAD(0)` if `CALLER` is the owner and reverts otherwise —
/// `CALLER PUSH0 SLOAD EQ PUSH1 10 JUMPI PUSH0 PUSH0 REVERT JUMPDEST PUSH0 CALLDATALOAD PUSH0
/// SSTORE STOP`. The smallest contract whose only guard is `msg.sender`.
pub const OWNABLE_CODE: [u8; 16] =
    [0x33, 0x5f, 0x54, 0x14, 0x60, 0x0a, 0x57, 0x5f, 0x5f, 0xfd, 0x5b, 0x5f, 0x35, 0x5f, 0x55, 0x00];

/// A call to [`OWNABLE_CODE`] owned by `owner`, made as `caller`, handing ownership to `to`.
pub fn ownable_transfer(owner: U256, caller: U256, to: U256, context: Word8) -> EvmCall {
    let mut tree = SparseTree::new();
    tree.insert(U256::ZERO, owner);
    EvmCall {
        code: OWNABLE_CODE.to_vec(),
        calldata: to.to_be_bytes().to_vec(),
        address: TOKEN,
        caller,
        callvalue: U256::ZERO,
        gas_limit: 100_000,
        context,
        tree,
        touched: vec![U256::ZERO],
    }
}

/// Append a byte string in the input layout: its length, then `ceil(n/4)` words holding four bytes
/// each little-endian, the last zero-padded.
fn push_bytes(w: &mut Vec<u32>, bytes: &[u8]) {
    w.push(bytes.len() as u32);
    for chunk in bytes.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        w.push(u32::from_le_bytes(word));
    }
}

// ---------------------------------------------------------------------------------------------
// The ERC-20 fixtures (Task 5): the committed runtime bytecode, Solidity's storage layout, the
// call encoding, and the pre-state a `transfer` needs. `tests/e2e.rs`'s M4.3 exit test runs these
// through the compiled guest; nothing here is used by the machine itself.
// ---------------------------------------------------------------------------------------------

/// The token holder the fixtures start with a balance: the 20-byte address `0x1111…11`, right
/// aligned in a 256-bit word as the EVM keeps an address.
pub const ALICE: U256 = U256([0x1111_1111, 0x1111_1111, 0x1111_1111, 0x1111_1111, 0x1111_1111, 0, 0, 0]);
/// The counterparty: the 20-byte address `0x2222…22`.
pub const BOB: U256 = U256([0x2222_2222, 0x2222_2222, 0x2222_2222, 0x2222_2222, 0x2222_2222, 0, 0, 0]);
/// The contract's own address (`0x0…c0de`). Never observed by this bytecode — the ERC-20 uses no
/// `ADDRESS` — but the layout carries it, so the fixtures name it rather than passing zero.
pub const TOKEN: U256 = U256([0xc0de, 0, 0, 0, 0, 0, 0, 0]);

/// `_balances`'s slot in `ERC20.sol` (OpenZeppelin v4's layout).
pub const SLOT_BALANCES: u32 = 0;
/// `_allowances`'s slot.
pub const SLOT_ALLOWANCES: u32 = 1;
/// `_totalSupply`'s slot — a plain `uint256`, so the slot *is* the storage key.
pub const SLOT_TOTAL_SUPPLY: u32 = 2;

/// The gas the fixtures give a call. A `transfer` costs ~50k (two `SLOAD`s at 2 100, an `SSTORE`
/// at 2 900 over a non-zero balance and one at 20 000 over a zero one); a round number well above
/// it keeps the figure from being a moving part of the test.
const FIXTURE_GAS: u64 = 1_000_000;

/// The ERC-20's **runtime** bytecode: `guests-compiled/evm/contracts/erc20.runtime.hex`, compiled
/// once by the pinned `solc` that file's `SOLC.md` records. There is no constructor to run — the
/// state a deployment would have written is seeded as witnesses instead ([`erc20_transfer`]).
pub fn erc20_code() -> Vec<u8> {
    const HEX: &str = include_str!("../guests-compiled/evm/contracts/erc20.runtime.hex");
    unhex(HEX.trim())
}

/// Decodes a lowercase hex string. Two lines rather than a runtime dependency on `hex` (which is a
/// dev-dependency here, and so cannot appear in the library): the only input is a committed file.
fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex string has an odd length");
    let nibble = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not lowercase hex: {:?}", c as char),
    };
    s.as_bytes().chunks(2).map(|p| (nibble(p[0]) << 4) | nibble(p[1])).collect()
}

/// Solidity's storage key for `m[key]` where `m` is at slot `base`:
/// `keccak256(key as 32 big-endian bytes ‖ base as 32 big-endian bytes)`.
pub fn mapping_slot(key: &U256, base: u32) -> U256 {
    let mut msg = [0u8; 64];
    msg[..32].copy_from_slice(&key.to_be_bytes());
    msg[32..].copy_from_slice(&U256::from_u32(base).to_be_bytes());
    U256::from_be_bytes(&keccak::keccak256(&msg))
}

/// Solidity's storage key for a nested `m[k1][k2]` where `m` is at slot `base`: the inner
/// mapping's own base is [`mapping_slot`]`(k1, base)`, so this is
/// `keccak256(k2 ‖ mapping_slot(k1, base))` — `_allowances[owner][spender]` is
/// `mapping_slot2(&owner, &spender, SLOT_ALLOWANCES)`.
pub fn mapping_slot2(k1: &U256, k2: &U256, base: u32) -> U256 {
    let mut msg = [0u8; 64];
    msg[..32].copy_from_slice(&k2.to_be_bytes());
    msg[32..].copy_from_slice(&mapping_slot(k1, base).to_be_bytes());
    U256::from_be_bytes(&keccak::keccak256(&msg))
}

/// A function's 4-byte selector: the first four bytes of `keccak256` of its canonical signature,
/// e.g. `selector("transfer(address,uint256)")`.
pub fn selector(sig: &str) -> [u8; 4] {
    let k = keccak::keccak256(sig.as_bytes());
    [k[0], k[1], k[2], k[3]]
}

/// Calldata for a call to `sig` with 256-bit arguments: the selector then each argument as 32
/// big-endian bytes — the ABI encoding for the static types this ERC-20 takes (`address`,
/// `uint256`), an address being its 20 bytes right-aligned already.
pub fn abi_call(sig: &str, args: &[U256]) -> Vec<u8> {
    let mut cd = selector(sig).to_vec();
    for a in args {
        cd.extend_from_slice(&a.to_be_bytes());
    }
    cd
}

/// `from` transfers `amount` to `to` on an ERC-20 whose pre-state holds each `(holder, balance)`
/// in `balances` and their sum as `_totalSupply`.
///
/// The witnesses supplied are exactly the two balance slots the call touches (`_totalSupply` is
/// seeded but never read by `transfer`, so it gets no witness — a slot the bytecode *did* touch
/// without one would be an exceptional halt). The other fixtures in the exit test reuse this
/// builder and replace `calldata`/`touched` for the function they exercise.
pub fn erc20_transfer(from: U256, to: U256, amount: U256, balances: &[(U256, U256)]) -> EvmCall {
    let mut tree = SparseTree::new();
    let mut supply = U256::ZERO;
    for (holder, balance) in balances {
        tree.insert(mapping_slot(holder, SLOT_BALANCES), *balance);
        supply = supply.add(balance);
    }
    tree.insert(U256::from_u32(SLOT_TOTAL_SUPPLY), supply);
    EvmCall {
        code: erc20_code(),
        calldata: abi_call("transfer(address,uint256)", &[to, amount]),
        address: TOKEN,
        caller: from,
        callvalue: U256::ZERO,
        gas_limit: FIXTURE_GAS,
        context: [0; 8],
        tree,
        touched: vec![mapping_slot(&from, SLOT_BALANCES), mapping_slot(&to, SLOT_BALANCES)],
    }
}
