//! The EVM interpreter (Task 3 of the M4.3 plan): hand-assembled programs for the semantics the
//! ERC-20 subset needs, and a differential test against `revm` over random straight-line
//! arithmetic programs.
//!
//! The hand-written programs pin the things an oracle cannot reach from bytecode alone — the gas
//! total, the storage root after a `SSTORE`, the `NoWitness` halt, the log topics kept across a
//! `REVERT` — and `revm` pins the 100-odd opcode semantics that are far too easy to get subtly
//! wrong by hand (`SDIV`/`SMOD` truncation, `SAR`'s sign fill, `BYTE`/`SIGNEXTEND` index
//! direction, the shifts at counts ≥ 256).

use evm_core::interp::{Buffers, Env, Halt, Interpreter, Outcome, MAX_CALLDATA_BYTES, MAX_CODE_BYTES};
use evm_core::storage::StorageTree;
use evm_core::u256::U256;
use shrugg_zkvm::evm::{empty_root, HostRef, SparseTree};

fn env() -> Env {
    Env {
        address: U256::from_u32(0xaaaa),
        caller: U256::from_u32(0xcafe),
        callvalue: U256::ZERO,
        gas_limit: 1_000_000,
    }
}

fn run(code: &[u8], calldata: &[u8]) -> Outcome {
    let mut h = HostRef;
    let mut st = StorageTree::new(empty_root());
    // The interpreter borrows its ~100 KiB of working arrays (Task 4's in-place path), so the test
    // owns one `Buffers` per run; the guest keeps a single one in `.bss`.
    let mut b = Box::new(Buffers::ZERO);
    Interpreter::new(&mut h, code, calldata, env(), &mut st, &mut b).run()
}

/// Run against a host-built tree, pushing a witness for each of `slots`. Returns the outcome and
/// the guest's root afterwards, which is the post-state root the public output binds.
fn run_with(code: &[u8], calldata: &[u8], tree: &SparseTree, slots: &[U256]) -> (Outcome, [u32; 8]) {
    let mut h = HostRef;
    let mut st = StorageTree::new(tree.root());
    for s in slots {
        let w = tree.witness(s);
        st.push(
            &mut h,
            evm_core::storage::Witness {
                slot: w.slot,
                value: w.value,
                siblings: w.siblings,
                verified: false,
            },
        )
        .unwrap();
    }
    let mut b = Box::new(Buffers::ZERO);
    let o = Interpreter::new(&mut h, code, calldata, env(), &mut st, &mut b).run();
    let root = st.root();
    (o, root)
}

fn ret_u256(o: &Outcome) -> U256 {
    assert_eq!(o.ret_len, 32);
    U256::from_be_slice(&o.ret[..32])
}

/// `PUSHn` of `v`: the smallest push that holds it.
fn push(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let s = b.iter().position(|&x| x != 0).unwrap_or(7);
    let mut out = vec![0x60 + (7 - s) as u8];
    out.extend_from_slice(&b[s..]);
    out
}

/// RETURN the top of the stack: `MSTORE(0, top); RETURN(0, 32)`.
fn ret_top() -> Vec<u8> {
    vec![0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]
}

#[test]
fn add_and_return() {
    let mut c = push(2);
    c.extend(push(3));
    c.push(0x01);
    c.extend(ret_top());
    let o = run(&c, &[]);
    assert_eq!(o.halt, Halt::Return);
    assert_eq!(ret_u256(&o), U256::from_u32(5));
    // PUSH1 PUSH1 ADD PUSH0 MSTORE(3 + mem 3) PUSH1 PUSH0 RETURN(0 + no expansion)
    assert_eq!(o.gas_used, 3 + 3 + 3 + 2 + 3 + 3 + 3 + 2 + 0);
}

#[test]
fn jumps_need_a_jumpdest_and_push_data_is_not_one() {
    // JUMP to a JUMPDEST at 4: PUSH1 4 JUMP INVALID JUMPDEST STOP
    let ok = [0x60, 0x04, 0x56, 0xfe, 0x5b, 0x00];
    assert_eq!(run(&ok, &[]).halt, Halt::Stop);
    // JUMP to 4, which is the 0x5b *inside* PUSH1's data: PUSH1 4 JUMP PUSH1 0x5b STOP
    let bad = [0x60, 0x04, 0x56, 0x60, 0x5b, 0x00];
    assert_eq!(run(&bad, &[]).halt, Halt::BadJump);
    // JUMP to 3, which is that PUSH1's own opcode and not a JUMPDEST either
    assert_eq!(run(&[0x60, 0x03, 0x56, 0x60, 0x5b, 0x00], &[]).halt, Halt::BadJump);
    // JUMPI not taken falls through
    let fall = [0x5f, 0x60, 0x06, 0x57, 0x60, 0x01, 0x5b, 0x00];
    assert_eq!(run(&fall, &[]).halt, Halt::Stop);
    // JUMPI not taken does not even look at its destination, which may be nonsense
    assert_eq!(run(&[0x5f, 0x60, 0xff, 0x57, 0x00], &[]).halt, Halt::Stop);
    // JUMPI taken to a bad destination is a bad jump
    assert_eq!(run(&[0x60, 0x01, 0x60, 0xff, 0x57, 0x00], &[]).halt, Halt::BadJump);
    // a jump past the end of the code is a bad jump, not a stop
    assert_eq!(run(&[0x60, 0x20, 0x56], &[]).halt, Halt::BadJump);
    // running off the end of the code is a STOP
    assert_eq!(run(&[0x60, 0x01], &[]).halt, Halt::Stop);
}

#[test]
fn stack_limits_out_of_gas_invalid_and_traps() {
    let mut deep = Vec::new();
    for _ in 0..1025 {
        deep.push(0x5f);
    }
    assert_eq!(run(&deep, &[]).halt, Halt::StackOverflow);
    // 1024 of them is exactly the limit
    assert_eq!(run(&deep[..1024], &[]).halt, Halt::Stop);
    assert_eq!(run(&[0x01], &[]).halt, Halt::StackUnderflow);
    assert_eq!(run(&[0xfe], &[]).halt, Halt::Invalid);
    assert_eq!(run(&[0x42], &[]).halt, Halt::Trap(0x42)); // TIMESTAMP is out of scope
    assert_eq!(run(&[0xf1], &[]).halt, Halt::Trap(0xf1)); // CALL
    assert_eq!(run(&[0x5e], &[]).halt, Halt::Trap(0x5e)); // MCOPY
    let mut h = HostRef;
    let mut st = StorageTree::new(empty_root());
    let mut e = env();
    e.gas_limit = 4;
    let mut b = Box::new(Buffers::ZERO);
    let o = Interpreter::new(&mut h, &[0x60, 0x01, 0x60, 0x01, 0x01], &[], e, &mut st, &mut b).run(); // 3 + 3 > 4
    assert_eq!(o.halt, Halt::OutOfGas);
    assert_eq!(o.gas_used, 4);
    // an outcome that is not Return/Revert has empty return data and no logs
    assert_eq!(o.ret_len, 0);
    assert_eq!(o.n_logs, 0);
}

#[test]
fn calldata_memory_and_keccak() {
    // return keccak256(calldata[0..4])
    let mut c = vec![0x60, 0x04, 0x5f, 0x5f, 0x37]; // CALLDATACOPY(mem 0, cd 0, 4)
    c.extend([0x60, 0x04, 0x5f, 0x20]); // KECCAK256(0, 4)
    c.extend(ret_top());
    let o = run(&c, &[0xde, 0xad, 0xbe, 0xef, 0x99]);
    assert_eq!(ret_u256(&o).to_be_bytes(), shrugg_zkvm::keccak::keccak256(&[0xde, 0xad, 0xbe, 0xef]));
    // CALLDATALOAD past the end is zero-padded; CALLDATASIZE is the byte count
    let mut c2 = vec![0x60, 0x03, 0x35];
    c2.extend(ret_top());
    let mut want = [0u8; 32];
    want[0] = 4;
    want[1] = 5;
    assert_eq!(ret_u256(&run(&c2, &[1, 2, 3, 4, 5])), U256::from_be_bytes(&want));
    let mut c3 = vec![0x36];
    c3.extend(ret_top());
    assert_eq!(ret_u256(&run(&c3, &[1, 2, 3, 4, 5])), U256::from_u32(5));
    // MSTORE8 writes one byte; MSIZE rounds up to 32
    let mut c4 = vec![0x60, 0xab, 0x60, 0x1f, 0x53, 0x59];
    c4.extend(ret_top());
    assert_eq!(ret_u256(&run(&c4, &[])), U256::from_u32(32));
    // CODESIZE and CODECOPY, which pads past the end of the code with zeros
    let mut c5 = vec![0x38];
    c5.extend(ret_top());
    assert_eq!(ret_u256(&run(&c5, &[])), U256::from_u32(7));
    // CODECOPY(mem 0, code 2, 32) of a 7-byte program: 5 bytes of code then 27 zeros
    let c6 = [0x60, 0x20, 0x60, 0x02, 0x5f, 0x39, 0x60, 0x20, 0x5f, 0xf3];
    let o6 = run(&c6, &[]);
    assert_eq!(o6.halt, Halt::Return);
    let mut want6 = [0u8; 32];
    want6[..8].copy_from_slice(&c6[2..10]);
    assert_eq!(&o6.ret[..32], &want6);
    // RETURNDATASIZE is always 0 and RETURNDATACOPY of nothing is a no-op; of anything, a trap
    let mut c7 = vec![0x3d];
    c7.extend(ret_top());
    assert_eq!(ret_u256(&run(&c7, &[])), U256::ZERO);
    assert_eq!(run(&[0x5f, 0x5f, 0x5f, 0x3e, 0x00], &[]).halt, Halt::Stop);
    assert_eq!(run(&[0x60, 0x01, 0x5f, 0x5f, 0x3e], &[]).halt, Halt::Trap(0x3e));
    // a memory range past MAX_MEMORY_BYTES is an exceptional halt, not an expansion
    assert_eq!(run(&[0x5f, 0x61, 0xff, 0xe0, 0x52], &[]).halt, Halt::Stop); // 0xffe0 + 32 = 64 KiB
    assert_eq!(run(&[0x5f, 0x61, 0xff, 0xe1, 0x52], &[]).halt, Halt::OutOfBounds); // one past it
    assert_eq!(run(&[0x5f, 0x62, 0x01, 0x00, 0x00, 0x52], &[]).halt, Halt::OutOfBounds);
    // but a zero-length range touches nothing whatever its offset: RETURN(2^32 - 1, 0) returns
    let z = [0x5f, 0x63, 0xff, 0xff, 0xff, 0xff, 0xf3];
    let oz = run(&z, &[]);
    assert_eq!(oz.halt, Halt::Return);
    assert_eq!(oz.ret_len, 0);
    assert_eq!(oz.gas_used, 2 + 3 + 0);
    // and it does not expand memory either: MSIZE after LOG0(2^32 - 1, 0) is still 0
    let mut z2 = vec![0x5f, 0x63, 0xff, 0xff, 0xff, 0xff, 0xa0, 0x59];
    z2.extend(ret_top());
    assert_eq!(ret_u256(&run(&z2, &[])), U256::ZERO);
}

#[test]
fn address_caller_callvalue_pc_msize_and_gas() {
    let mut c = vec![0x30];
    c.extend(ret_top());
    assert_eq!(ret_u256(&run(&c, &[])), U256::from_u32(0xaaaa));
    let mut c = vec![0x33];
    c.extend(ret_top());
    assert_eq!(ret_u256(&run(&c, &[])), U256::from_u32(0xcafe));
    let mut c = vec![0x34];
    c.extend(ret_top());
    assert_eq!(ret_u256(&run(&c, &[])), U256::ZERO);
    // PC pushes the PC opcode's own offset
    let mut c = vec![0x5f, 0x50, 0x58];
    c.extend(ret_top());
    assert_eq!(ret_u256(&run(&c, &[])), U256::from_u32(2));
    // MSIZE before any memory access is 0
    let mut c = vec![0x59];
    c.extend(ret_top());
    assert_eq!(ret_u256(&run(&c, &[])), U256::ZERO);
    // GAS is the gas left *after* charging its own 2
    let mut c = vec![0x5a];
    c.extend(ret_top());
    assert_eq!(ret_u256(&run(&c, &[])), U256::from_u64(1_000_000 - 2));
}

#[test]
fn sload_sstore_and_the_root_moves() {
    let mut t = SparseTree::new();
    t.insert(U256::from_u32(1), U256::from_u32(41));
    // SSTORE(1, SLOAD(1) + 1); RETURN SLOAD(1)
    let c = [
        0x60, 0x01, 0x54, 0x60, 0x01, 0x01, 0x60, 0x01, 0x55, 0x60, 0x01, 0x54, 0x5f, 0x52, 0x60,
        0x20, 0x5f, 0xf3,
    ];
    let (o, root) = run_with(&c, &[], &t, &[U256::from_u32(1)]);
    assert_eq!(o.halt, Halt::Return);
    assert_eq!(ret_u256(&o), U256::from_u32(42));
    t.insert(U256::from_u32(1), U256::from_u32(42));
    assert_eq!(root, t.root());
    assert_eq!(o.gas_used, 3 + 2100 + 3 + 3 + 3 + 2900 + 3 + 2100 + 2 + 6 + 3 + 2 + 0);
    // touching a slot without a witness is an exceptional halt, not a zero read
    let (o2, _) = run_with(&[0x60, 0x02, 0x54], &[], &t, &[U256::from_u32(1)]);
    assert_eq!(o2.halt, Halt::NoWitness);
}

#[test]
fn a_first_write_to_an_empty_slot_costs_twenty_thousand() {
    let t = SparseTree::new();
    // SSTORE(7, 1) then STOP — the pre-value is zero and the new value is not
    let c = [0x60, 0x01, 0x60, 0x07, 0x55, 0x00];
    let (o, root) = run_with(&c, &[], &t, &[U256::from_u32(7)]);
    assert_eq!(o.halt, Halt::Stop);
    assert_eq!(o.gas_used, 3 + 3 + 20_000 + 0);
    let mut want = SparseTree::new();
    want.insert(U256::from_u32(7), U256::from_u32(1));
    assert_eq!(root, want.root());
    // writing zero over zero is the cheap case, and the root does not move
    let c0 = [0x5f, 0x60, 0x07, 0x55, 0x00];
    let (o0, root0) = run_with(&c0, &[], &t, &[U256::from_u32(7)]);
    assert_eq!(o0.gas_used, 2 + 3 + 2900 + 0);
    assert_eq!(root0, t.root());
}

#[test]
fn logs_keep_topics_and_drop_data_and_revert_keeps_its_data() {
    // LOG2(mem 0..32, topic1 = 7, topic2 = 9); then REVERT(0, 32) with mem[0..32] = 0x55
    let mut c = vec![0x60, 0x55, 0x5f, 0x52]; // MSTORE(0, 0x55)
    c.extend([0x60, 0x09, 0x60, 0x07, 0x60, 0x20, 0x5f, 0xa2]); // LOG2 offset 0 size 32 topics 7, 9
    c.extend([0x60, 0x20, 0x5f, 0xfd]);
    let o = run(&c, &[]);
    assert_eq!(o.halt, Halt::Revert);
    assert_eq!(o.n_logs, 1);
    assert_eq!(o.logs[0].n_topics, 2);
    assert_eq!(o.logs[0].topics[0], U256::from_u32(7));
    assert_eq!(o.logs[0].topics[1], U256::from_u32(9));
    assert_eq!(ret_u256(&o), U256::from_u32(0x55));
    // gas: PUSH1 PUSH0 MSTORE(3 + mem 3) PUSH1 PUSH1 PUSH1 PUSH0 LOG2(375 + 750 + 8·32) PUSH1
    // PUSH0 REVERT(0)
    assert_eq!(o.gas_used, 3 + 2 + 6 + 3 + 3 + 3 + 2 + (375 + 750 + 256) + 3 + 2 + 0);
    // LOG0 with no topics, and a ninth log is an exceptional halt (MAX_LOGS = 8)
    let mut c0 = Vec::new();
    for _ in 0..8 {
        c0.extend([0x5f, 0x5f, 0xa0]); // LOG0(0, 0)
    }
    c0.push(0x00);
    let o0 = run(&c0, &[]);
    assert_eq!(o0.halt, Halt::Stop);
    assert_eq!(o0.n_logs, 8);
    assert_eq!(o0.logs[0].n_topics, 0);
    let mut c9 = Vec::new();
    for _ in 0..9 {
        c9.extend([0x5f, 0x5f, 0xa0]);
    }
    assert_eq!(run(&c9, &[]).halt, Halt::OutOfBounds);
}

#[test]
fn return_data_longer_than_the_limit_is_an_exceptional_halt() {
    // RETURN(0, 1024) is the limit; RETURN(0, 1056) is over it
    let ok = [0x61, 0x04, 0x00, 0x5f, 0xf3];
    let o = run(&ok, &[]);
    assert_eq!(o.halt, Halt::Return);
    assert_eq!(o.ret_len, 1024);
    let over = [0x61, 0x04, 0x20, 0x5f, 0xf3];
    assert_eq!(run(&over, &[]).halt, Halt::OutOfBounds);
    // and the same for REVERT
    assert_eq!(run(&[0x61, 0x04, 0x20, 0x5f, 0xfd], &[]).halt, Halt::OutOfBounds);
}

#[test]
fn dup_swap_and_push_padding() {
    // DUP2 of [1, 2] (2 on top) gives 1
    let mut c = vec![0x60, 0x01, 0x60, 0x02, 0x81];
    c.extend(ret_top());
    assert_eq!(ret_u256(&run(&c, &[])), U256::from_u32(1));
    // SWAP1 of [1, 2] puts 1 on top
    let mut c = vec![0x60, 0x01, 0x60, 0x02, 0x90];
    c.extend(ret_top());
    assert_eq!(ret_u256(&run(&c, &[])), U256::from_u32(1));
    // DUP16 needs 16 items, SWAP16 needs 17
    let mut deep = Vec::new();
    for i in 1..=16u8 {
        deep.extend([0x60, i]);
    }
    let mut c = deep.clone();
    c.push(0x8f); // DUP16 → the bottom item, 1
    c.extend(ret_top());
    assert_eq!(ret_u256(&run(&c, &[])), U256::from_u32(1));
    let mut c = deep.clone();
    c.push(0x9f); // SWAP16 with only 16 items underflows
    assert_eq!(run(&c, &[]).halt, Halt::StackUnderflow);
    // PUSH32 whose data runs off the end of the code is zero-padded on the right
    let c = [0x7f, 0xaa, 0xbb];
    let o = run(&c, &[]);
    assert_eq!(o.halt, Halt::Stop);
    let mut c2 = vec![0x7f, 0xaa, 0xbb];
    c2.extend([0u8; 30]);
    c2.extend(ret_top());
    let mut want = [0u8; 32];
    want[0] = 0xaa;
    want[1] = 0xbb;
    assert_eq!(ret_u256(&run(&c2, &[])), U256::from_be_bytes(&want));
}

/// A program that moves the storage root and emits a log if it runs at all: `SSTORE(1, 1)`,
/// `LOG0(0, 0)`, `STOP`. Used by the two over-long-input tests, where it must *not* run.
fn sstore_and_log() -> Vec<u8> {
    vec![0x60, 0x01, 0x60, 0x01, 0x55, 0x5f, 0x5f, 0xa0, 0x00]
}

/// Both lengths come out of the prover-supplied input vector, so an over-long one has to be an
/// exceptional halt the proof reports. A panic would be an abort in the guest — no proof at all —
/// and the `assert!`s this replaced were exactly that.
#[test]
fn code_longer_than_the_cap_is_an_exceptional_halt_not_a_panic() {
    let mut t = SparseTree::new();
    t.insert(U256::from_u32(1), U256::from_u32(41));
    let pre = t.root();
    // The root-moving program, padded one byte past EIP-170. The padding is JUMPDESTs, which the
    // program never reaches but the bitmap scan would: without the cap in `new`, byte 24 576 sets a
    // bit one word past the 768-word bitmap, which is an index-out-of-bounds panic of its own.
    let mut over = sstore_and_log();
    over.resize(MAX_CODE_BYTES + 1, 0x5b);
    let (o, root) = run_with(&over, &[], &t, &[U256::from_u32(1)]);
    assert_eq!(o.status(), 2);
    assert_eq!(o.halt, Halt::OutOfBounds);
    assert_eq!(o.gas_used, 0);
    assert_eq!(o.ret_len, 0);
    assert_eq!(o.n_logs, 0);
    assert_eq!(root, pre, "the pre-state root must not move");
    // exactly the cap still runs, JUMPDEST bitmap included out to the last byte
    let at = vec![0x5b; MAX_CODE_BYTES];
    let oa = run(&at, &[]);
    assert_eq!(oa.halt, Halt::Stop);
    assert_eq!(oa.gas_used, MAX_CODE_BYTES as u64);
}

#[test]
fn calldata_longer_than_the_cap_is_an_exceptional_halt_not_a_panic() {
    let mut t = SparseTree::new();
    t.insert(U256::from_u32(1), U256::from_u32(41));
    let pre = t.root();
    let over = vec![7u8; MAX_CALLDATA_BYTES + 1];
    let (o, root) = run_with(&sstore_and_log(), &over, &t, &[U256::from_u32(1)]);
    assert_eq!(o.status(), 2);
    assert_eq!(o.halt, Halt::OutOfBounds);
    assert_eq!(o.gas_used, 0);
    assert_eq!(o.ret_len, 0);
    assert_eq!(o.n_logs, 0);
    assert_eq!(root, pre, "the pre-state root must not move");
    // exactly the cap still runs, and CALLDATASIZE sees all of it
    let mut c = vec![0x36];
    c.extend(ret_top());
    let at = vec![7u8; MAX_CALLDATA_BYTES];
    assert_eq!(ret_u256(&run(&c, &at)), U256::from_u32(MAX_CALLDATA_BYTES as u32));
}

/// The plan's scope, opcode by opcode: every byte on the list must *not* trap (whatever else it
/// does on an empty stack), and every byte off it must trap with its own value — except `0xfe`,
/// which is `Invalid`. Without this, an opcode quietly missing from the dispatch would look like a
/// deliberate trap and only surface when the ERC-20's bytecode hit it in Task 5.
#[test]
fn exactly_the_planned_opcodes_are_supported() {
    const SUPPORTED: &[u8] = &[
        0x00, // STOP
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, // arithmetic
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, // comparison
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, // bitwise
        0x20, // KECCAK256
        0x30, 0x33, 0x34, // ADDRESS, CALLER, CALLVALUE
        0x35, 0x36, 0x37, // CALLDATALOAD, CALLDATASIZE, CALLDATACOPY
        0x38, 0x39, // CODESIZE, CODECOPY
        0x3d, 0x3e, // RETURNDATASIZE, RETURNDATACOPY (zero length only)
        0x50, 0x51, 0x52, 0x53, // POP, MLOAD, MSTORE, MSTORE8
        0x54, 0x55, // SLOAD, SSTORE
        0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, // JUMP, JUMPI, PC, MSIZE, GAS, JUMPDEST
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, // LOG0–LOG4
        0xf3, 0xfd, // RETURN, REVERT
    ];
    for op in 0u16..=0xff {
        let op = op as u8;
        let supported = SUPPORTED.contains(&op)
            || (0x5f..=0x7f).contains(&op) // PUSH0–PUSH32
            || (0x80..=0x9f).contains(&op); // DUP1–DUP16, SWAP1–SWAP16
        let halt = run(&[op], &[]).halt;
        if op == 0xfe {
            assert_eq!(halt, Halt::Invalid);
        } else if supported {
            assert_ne!(halt, Halt::Trap(op), "opcode {op:#04x} is in scope but traps");
        } else {
            assert_eq!(halt, Halt::Trap(op), "opcode {op:#04x} is out of scope but does not trap");
        }
    }
}

#[test]
fn memory_expansion_is_quadratic() {
    // MSTORE(0xff00, 0) touches bytes 0..0xff20, which is 2041 whole words.
    let c = [0x5f, 0x61, 0xff, 0x00, 0x52, 0x00];
    let o = run(&c, &[]);
    assert_eq!(o.halt, Halt::Stop);
    let w = 2041u64;
    // PUSH0 PUSH2 MSTORE(3 + 3w + w²/512) STOP
    assert_eq!(o.gas_used, 2 + 3 + 3 + (3 * w + w * w / 512));
    // and the same total from the oracle, so the formula is not just self-consistent
    assert_eq!(o.gas_used, revm_run(&c, &[]).gas_used);
}

/// Differential test against `revm`: random straight-line programs over the arithmetic,
/// comparison, bitwise and stack opcodes, each ending in `ret_top()`. Both sides get the same code
/// and calldata, the same gas limit and the Shanghai spec; the return value and the status must
/// agree.
///
/// Underflow, overflow and out-of-gas all map to status 2 on both sides, so a program that
/// underflows on both is a pass — that is intended. The point is that *when* one side returns,
/// both return the same 32 bytes.
#[test]
fn random_arithmetic_programs_agree_with_revm() {
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(47);
    const OPS: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x80, 0x81, 0x90, 0x91, 0x50,
    ];
    let mut returned = 0;
    for _ in 0..500 {
        let mut code = Vec::new();
        for _ in 0..rng.random_range(4..12) {
            let w: Vec<u8> = (0..rng.random_range(1..33)).map(|_| rng.random()).collect();
            code.push(0x60 + (w.len() - 1) as u8);
            code.extend(w);
        }
        for _ in 0..rng.random_range(3..20) {
            code.push(OPS[rng.random_range(0..OPS.len())]);
        }
        code.extend(ret_top());
        let ours = run(&code, &[]);
        let theirs = revm_run(&code, &[]);
        assert_eq!(ours.status(), theirs.status, "code {}", hex::encode(&code));
        if ours.halt == Halt::Return {
            assert_eq!(&ours.ret[..ours.ret_len], &theirs.ret[..], "code {}", hex::encode(&code));
            assert_eq!(ours.gas_used, theirs.gas_used, "gas, code {}", hex::encode(&code));
            returned += 1;
        }
    }
    // A run where nothing ever returned would pass the assertions above vacuously. Most of the
    // rest underflow: 3–19 opcodes over 4–11 operands empties the stack more often than not, and
    // `random_small_operand_programs_agree_with_revm` is the shape where every program returns.
    assert!(returned > 150, "only {returned} of 500 programs returned");
}

/// The same differential, but with small operands so that every program returns: one byte of
/// operand per push keeps the stack deep enough for `ret_top()` and exercises the small-value
/// paths (`DIV` by a one-byte divisor, `EXP` with a one-byte exponent, `SIGNEXTEND` of a real
/// index) that random 32-byte words almost never reach.
#[test]
fn random_small_operand_programs_agree_with_revm() {
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    const OPS: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    ];
    let mut returned = 0;
    for _ in 0..500 {
        let mut code = Vec::new();
        for _ in 0..24 {
            code.extend([0x60, rng.random::<u8>()]);
        }
        for _ in 0..rng.random_range(3..12) {
            code.push(OPS[rng.random_range(0..OPS.len())]);
        }
        code.extend(ret_top());
        let ours = run(&code, &[]);
        let theirs = revm_run(&code, &[]);
        assert_eq!(ours.status(), theirs.status, "code {}", hex::encode(&code));
        if ours.halt == Halt::Return {
            assert_eq!(&ours.ret[..ours.ret_len], &theirs.ret[..], "code {}", hex::encode(&code));
            assert_eq!(ours.gas_used, theirs.gas_used, "gas, code {}", hex::encode(&code));
            returned += 1;
        }
    }
    assert_eq!(returned, 500);
}

/// A third differential shape: the memory, calldata and control-flow opcodes, where a wrong
/// zero-pad or a wrong jumpdest bitmap shows up as a different 32 bytes rather than a different
/// status. `MSTORE8`/`MLOAD`/`CALLDATALOAD`/`CALLDATACOPY`/`CODECOPY`/`KECCAK256` over small
/// offsets, plus `MSIZE` and `PC`.
#[test]
fn random_memory_programs_agree_with_revm() {
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(2029);
    let calldata: Vec<u8> = (0..37).map(|i| (i * 7 + 1) as u8).collect();
    let mut returned = 0;
    for _ in 0..400 {
        let mut code = Vec::new();
        for _ in 0..rng.random_range(4..14) {
            // a small offset or length, then one of the memory/env opcodes
            code.extend([0x60, rng.random_range(0..96u8)]);
            code.extend([0x60, rng.random_range(0..96u8)]);
            code.extend([0x60, rng.random_range(0..96u8)]);
            const MEM: &[u8] = &[
                0x51, 0x52, 0x53, 0x59, 0x58, 0x35, 0x36, 0x37, 0x38, 0x39, 0x20, 0x50, 0x80, 0x90,
            ];
            code.push(MEM[rng.random_range(0..MEM.len())]);
        }
        code.extend(ret_top());
        let ours = run(&code, &calldata);
        let theirs = revm_run(&code, &calldata);
        assert_eq!(ours.status(), theirs.status, "code {}", hex::encode(&code));
        if ours.halt == Halt::Return {
            assert_eq!(&ours.ret[..ours.ret_len], &theirs.ret[..], "code {}", hex::encode(&code));
            assert_eq!(ours.gas_used, theirs.gas_used, "gas, code {}", hex::encode(&code));
            returned += 1;
        }
    }
    assert!(returned > 200, "only {returned} of 400 programs returned");
}

/// What `revm` reports for one bare-interpreter run, reduced to what the plan's status word and
/// public output bind.
struct RevmOutcome {
    status: u32,
    ret: Vec<u8>,
    gas_used: u64,
}

/// One `revm` bare-interpreter run over `code` with `calldata`, the same 1 000 000 gas limit and
/// the Shanghai spec, against `DummyHost` (no state, no calls — the programs here touch none).
/// `InstructionResult` is mapped to a status exactly as `Outcome::status` does: `Stop`/`Return` →
/// 1, `Revert` → 0, everything else → 2.
fn revm_run(code: &[u8], calldata: &[u8]) -> RevmOutcome {
    use revm::bytecode::Bytecode;
    use revm::context_interface::host::DummyHost;
    use revm::interpreter::instructions::gas_table_spec;
    use revm::interpreter::interpreter::{EthInterpreter, ExtBytecode};
    use revm::interpreter::{
        instruction_table, CallInput, InputsImpl, InstructionResult, Interpreter as RevmInterp,
        InterpreterAction, SharedMemory,
    };
    use revm::primitives::{hardfork::SpecId, Address, Bytes, U256 as RU256};

    const SPEC: SpecId = SpecId::SHANGHAI;
    let e = env();
    let addr = |v: &U256| Address::from_slice(&v.to_be_bytes()[12..]);
    let inputs = InputsImpl {
        target_address: addr(&e.address),
        bytecode_address: None,
        caller_address: addr(&e.caller),
        input: CallInput::Bytes(Bytes::from(calldata.to_vec())),
        call_value: RU256::from_be_bytes(e.callvalue.to_be_bytes()),
        depth: 0,
    };
    let mut interp = RevmInterp::<EthInterpreter>::new(
        SharedMemory::new(),
        ExtBytecode::new(Bytecode::new_raw(Bytes::from(code.to_vec()))),
        inputs,
        false,
        SPEC,
        e.gas_limit,
    );
    let mut host = DummyHost::new(SPEC);
    let table = instruction_table::<EthInterpreter, DummyHost>();
    let gas = gas_table_spec(SPEC);
    let InterpreterAction::Return(r) = interp.run_plain(&table, &gas, &mut host) else {
        panic!("the differential programs make no calls, so the action is always Return");
    };
    let status = match r.result {
        InstructionResult::Stop | InstructionResult::Return => 1,
        InstructionResult::Revert => 0,
        _ => 2,
    };
    RevmOutcome { status, ret: r.output.to_vec(), gas_used: r.gas.total_gas_spent() }
}
