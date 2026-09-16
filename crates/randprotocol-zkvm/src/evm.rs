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
//! The tree is `notes::DEPTH = 32` levels of the commitment tree's own node hash over storage
//! leaves: position is the top 32 bits, big-endian, of `keccak256(slot as 32 big-endian bytes)`,
//! whose bit `i` (LSB first) chooses left/right at level `i` — `asm::emit_merkle_verify`'s
//! convention. The leaf is canonical in the value, so the empty tree has a well-defined root and
//! writing a slot back to zero restores it ([`leaf_hash`]).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use evm_core::abi::{run_call_with, Workspace};
use evm_core::interp::Outcome;
use evm_core::u256::U256;

use crate::hash::sponge_hash;
use crate::keccak;
use crate::notes::{self, domain, Word8, DEPTH};

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
}

/// The leaf position of `slot`: the top 32 bits, big-endian, of `keccak256(slot)`, read as a `u32`
/// whose bit `i` chooses left (0) or right (1) at level `i`.
pub fn slot_index(slot: &U256) -> u32 {
    let k = keccak::keccak256(&slot.to_be_bytes());
    u32::from_be_bytes([k[0], k[1], k[2], k[3]])
}

/// `H(STORAGE_LEAF, [slot(8), value(8)])`, **canonical in the value**: a zero value gives the one
/// `H(STORAGE_LEAF, [0; 16])` whatever the slot is. So an absent slot, a never-written slot and a
/// slot written back to zero are the same leaf; the storage root is history-independent and the
/// empty tree's root is just this leaf lifted 32 levels ([`empty_root`]). Every leaf on both sides
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
/// leaf and `defaults()[l] = H(NODE, defaults()[l-1], defaults()[l-1])`. Computed once — the 32
/// sponge hashes are the same for every tree, and `SparseTree` consults the table at every level
/// where a subtree holds nothing.
fn defaults() -> &'static [Word8; DEPTH + 1] {
    static TABLE: OnceLock<[Word8; DEPTH + 1]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut d = [[0u32; 8]; DEPTH + 1];
        d[0] = leaf_hash(&U256::ZERO, &U256::ZERO);
        for l in 1..=DEPTH {
            d[l] = node_hash(&d[l - 1], &d[l - 1]);
        }
        d
    })
}

/// The root of the tree with no slot written: `defaults()[DEPTH]`.
pub fn empty_root() -> Word8 {
    defaults()[DEPTH]
}

/// The host's contract storage: the written slots, keyed by leaf position, with empty subtrees
/// standing in for everything else. Builds the roots and the witnesses the guest verifies.
#[derive(Clone, Debug, Default)]
pub struct SparseTree {
    /// Leaf position → (slot, value). Only non-zero values are held: a zero value is the default
    /// leaf, so storing one is removing the entry (and both hash the same).
    entries: BTreeMap<u32, (U256, U256)>,
}

impl SparseTree {
    pub fn new() -> Self {
        SparseTree::default()
    }

    /// Write `value` at `slot`. A zero value removes the entry, which is the same tree either way
    /// because the leaf is canonical in the value.
    ///
    /// Panics if two distinct slots collide on one leaf position — a 2^-32-per-pair event that
    /// would otherwise silently drop a slot, and the tests would rather see it than debug a root.
    pub fn insert(&mut self, slot: U256, value: U256) {
        let idx = slot_index(&slot);
        if value.is_zero() {
            self.entries.remove(&idx);
            return;
        }
        if let Some((held, _)) = self.entries.get(&idx) {
            assert_eq!(*held, slot, "leaf position {idx} is already held by a different slot");
        }
        self.entries.insert(idx, (slot, value));
    }

    /// The hash of the subtree at level `level` whose nodes all share the leaf-position prefix
    /// `prefix = index >> level`. Empty subtrees short-circuit to the default table, so the walk
    /// costs `O(entries × DEPTH)` hashes rather than `O(2^DEPTH)`.
    fn node_at(&self, level: usize, prefix: u64) -> Word8 {
        let Some((_, (slot, value))) = self.entries.iter().find(|(i, _)| (**i as u64) >> level == prefix) else {
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
        self.node_at(DEPTH, 0)
    }

    /// The witness for `slot`: its value (zero if the slot was never written) and, for each level
    /// `l = 0..DEPTH`, the hash of the sibling subtree of the path's node at that level, bottom-up.
    ///
    /// Panics, like [`insert`](Self::insert), if a *different* slot holds this leaf position:
    /// `entries` is keyed by position, so without the check the colliding slot's value and leaf
    /// would be handed back as this slot's — a witness that cannot verify, presented as if it
    /// could. `insert` already makes that state unreachable through this type; the assert is here
    /// so it stays unreachable rather than being unreachable by argument.
    pub fn witness(&self, slot: &U256) -> Witness {
        let idx = slot_index(slot);
        if let Some((held, _)) = self.entries.get(&idx) {
            assert_eq!(held, slot, "leaf position {idx} is held by a different slot");
        }
        let value = self.entries.get(&idx).map(|(_, v)| *v).unwrap_or(U256::ZERO);
        let siblings = std::array::from_fn(|l| self.node_at(l, ((idx as u64) >> l) ^ 1));
        Witness { slot: *slot, value, siblings }
    }
}

/// One slot's Merkle witness against a `SparseTree`'s root: the value and `DEPTH` siblings from
/// the leaf up. `evm_core::storage::Witness` is the guest's copy, plus its own `verified` flag.
#[derive(Clone, PartialEq, Debug)]
pub struct Witness {
    pub slot: U256,
    pub value: U256,
    pub siblings: [Word8; DEPTH],
}

impl Witness {
    /// The input-vector encoding: `slot(8) ‖ value(8) ‖ sibling_0(8) ‖ … ‖ sibling_31(8)`, 272
    /// words. 256-bit values are their own little-endian limbs, so nothing is byte-swapped.
    pub fn words(&self) -> Vec<u32> {
        let mut w = Vec::with_capacity(WITNESS_WORDS);
        w.extend_from_slice(&self.slot.0);
        w.extend_from_slice(&self.value.0);
        for sib in &self.siblings {
            w.extend_from_slice(sib);
        }
        w
    }
}

/// Words per witness in the input vector: slot 8 + value 8 + `DEPTH` × 8 siblings.
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
    /// The pre-state storage. `witness(slot)` against this is what the guest verifies.
    pub tree: SparseTree,
    /// The slots a witness is supplied for, in the order they appear in the vector. A slot the
    /// bytecode touches without one is an exceptional halt, so this is the call's access list.
    pub touched: Vec<U256>,
}

impl EvmCall {
    /// The input vector, exactly as the plan's Global Constraints lay it out:
    /// `[n_code, code…, n_calldata, calldata…, address(8), caller(8), callvalue(8), gas_limit(1),
    /// pre_root(8), n_witnesses(1), witness…]`, byte strings packed 4 per word little-endian and
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
        let mut idxs: Vec<u32> = self.touched.iter().map(slot_index).collect();
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
        let words = self.input_words();
        // The guest keeps this in `.bss`; a host test boxes it (146 KiB is not for a frame).
        let mut ws = Box::new(Workspace::ZERO);
        let (out, o) =
            run_call_with(&mut HostRef, &mut ws, |i| words[i as usize], words.len() as u32);
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
        tree,
        touched: vec![mapping_slot(&from, SLOT_BALANCES), mapping_slot(&to, SLOT_BALANCES)],
    }
}
