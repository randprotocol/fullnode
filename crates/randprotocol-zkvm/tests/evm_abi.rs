//! The input layout and the public output (Task 4 of the M4.3 plan).
//!
//! Two sides of one encoding: `EvmCall::input_words` builds the word vector the machine's
//! `READ_INPUT` serves, and `evm_core::abi` decodes it back, runs it and produces the eight
//! public output words. Every digest here is recomputed independently from this crate's own
//! primitives (`keccak::keccak256`, `notes::hash`), never from `evm_core`'s copies, so an
//! agreement is evidence rather than a tautology.

use std::ffi::c_void;

use evm_core::abi::{
    decode_input, hash_words, logs_hash, run_call, run_call_with,
    run_call_with_executor, InputCursor, ParseError, Workspace,
};
use evm_core::ffi::{evm_keccak256, evm_sload, evm_sstore, halt_code, halt_from_code, HostBox};
use evm_core::interp::{
    Buffers, Env, Halt, Interpreter, Log, Outcome, MAX_CALLDATA_BYTES, MAX_CODE_BYTES, MAX_LOGS,
    MAX_RETURN_BYTES,
};
use evm_core::storage::{StorageError, StorageTree, MAX_WITNESSES};
use evm_core::u256::U256;
use randprotocol_zkvm::evm::{
    erc20_transfer, selector, EvmCall, EvmLog, EvmStatement, HostRef, SparseTree, ALICE, BOB, WITNESS_WORDS,
};
use randprotocol_zkvm::keccak::keccak256;
use randprotocol_zkvm::notes::{domain, hash, Word8};

/// `PUSH1 1; SLOAD; PUSH1 1; ADD; PUSH1 1; SSTORE; PUSH1 1; SLOAD; PUSH0; MSTORE; PUSH1 32;
/// PUSH0; RETURN` — reads slot 1 (41), writes 42 back and returns it. 18 bytes.
fn sample() -> EvmCall {
    let mut tree = SparseTree::new();
    tree.insert(U256::from_u32(1), U256::from_u32(41));
    EvmCall {
        code: vec![
            0x60, 0x01, 0x54, 0x60, 0x01, 0x01, 0x60, 0x01, 0x55, 0x60, 0x01, 0x54, 0x5f, 0x52,
            0x60, 0x20, 0x5f, 0xf3,
        ],
        calldata: vec![1, 2, 3],
        address: U256::from_u32(0xaaaa),
        caller: U256::from_u32(0xcafe),
        callvalue: U256::ZERO,
        gas_limit: 100_000,
        context: [0xc0, 1, 2, 3, 4, 5, 6, 7],
        tree,
        touched: vec![U256::from_u32(1)],
    }
}

/// `SSTORE(1, 99); LOG1(0, 0, 0x1234)` — a store that moves the root and a log, so appending a
/// `REVERT` or an `INVALID` to this gives an outcome whose *interpreter* state moved and whose
/// *public output* must not.
fn store_and_log() -> Vec<u8> {
    vec![
        0x60, 0x63, // PUSH1 99   (value)
        0x60, 0x01, // PUSH1 1    (slot)
        0x55, // SSTORE
        0x61, 0x12, 0x34, // PUSH2 0x1234 (topic)
        0x5f, 0x5f, // PUSH0 PUSH0 (size, offset)
        0xa1, // LOG1
    ]
}

/// The 83-word preimage of the `EVM_OUT` digest, recomputed here from this crate's primitives:
/// the storage layout, the five hashes and roots, then the call `c`'s address, caller, call value, calldata hash and
/// context, its gas limit, and `gas_used`.
fn digest(c: &EvmCall, gas_used: u64, code: &[u8], pre: Word8, post: Word8, ret: &[u8], logs: &[u8]) -> Word8 {
    let mut msg = vec![2]; // the storage layout: evm-core's, natively
    for part in [
        words(&keccak256(code)),
        pre,
        post,
        words(&keccak256(ret)),
        words(&keccak256(logs)),
        c.address.0,
        c.caller.0,
        c.callvalue.0,
        words(&keccak256(&c.calldata)),
        c.context,
    ] {
        msg.extend_from_slice(&part);
    }
    msg.push(c.gas_limit as u32);
    msg.push(gas_used as u32);
    assert_eq!(msg.len(), 83);
    hash(domain::EVM_OUT, &msg)
}

/// The call every vector that does not parse is bound to: nothing at all.
fn no_call() -> EvmCall {
    EvmCall {
        code: vec![],
        calldata: vec![],
        address: U256::ZERO,
        caller: U256::ZERO,
        callvalue: U256::ZERO,
        gas_limit: 0,
        context: [0; 8],
        tree: SparseTree::new(),
        touched: vec![],
    }
}

/// `word[i] = LE(bytes[4i..4i+4])` — the host's own copy of the packing, to check `hash_words`.
fn words(h: &[u8; 32]) -> Word8 {
    std::array::from_fn(|i| u32::from_le_bytes([h[4 * i], h[4 * i + 1], h[4 * i + 2], h[4 * i + 3]]))
}

/// The eight output words for a digest: status, then words 0..6.
fn out_words(status: u32, d: Word8) -> [u32; 8] {
    let mut o = [0u32; 8];
    o[0] = status;
    o[1..8].copy_from_slice(&d[..7]);
    o
}

/// `keccak256(be32(0))` — the empty log set's preimage, which every non-success status binds.
fn no_logs() -> Vec<u8> {
    0u32.to_be_bytes().to_vec()
}

fn decoded(w: &[u32]) -> Box<Workspace> {
    let mut ws = Box::new(Workspace::ZERO);
    let mut c = InputCursor::new(|i| w[i as usize], w.len() as u32);
    decode_input(&mut HostRef, &mut ws.input, &mut c).expect("the sample vector parses");
    ws
}

/// The in-place construction path, as a size invariant: the guest's stack is 64 KiB
/// (`guest-sdk/guest.ld`) and a `Workspace` is more than twice that, so it lives in `.bss` and
/// everything that touches it must be small enough to sit in a frame. A field added to the
/// `Interpreter` rather than to `Buffers` trips this.
#[test]
fn nothing_large_is_ever_a_stack_value() {
    use std::mem::size_of;
    assert!(size_of::<Workspace>() > 140_000, "{}", size_of::<Workspace>());
    assert!(size_of::<Interpreter<'static, HostRef>>() <= 4_096, "{}", size_of::<Interpreter<'static, HostRef>>());
    assert!(size_of::<Outcome>() <= 4_096, "{}", size_of::<Outcome>());
    assert!(size_of::<InputCursor<fn(u32) -> u32>>() <= 64);
}

#[test]
fn the_input_layout_is_what_the_constraints_say() {
    let c = sample();
    let w = c.input_words();
    assert_eq!(w[0], 18);
    assert_eq!(w[1], u32::from_le_bytes([0x60, 0x01, 0x54, 0x60]));
    let after_code = 1 + 5; // 18 bytes → 5 words, the last zero-padded
    assert_eq!(w[after_code - 1], u32::from_le_bytes([0x5f, 0xf3, 0, 0]));
    assert_eq!(w[after_code], 3);
    assert_eq!(w[after_code + 1], u32::from_le_bytes([1, 2, 3, 0]));
    let p = after_code + 2;
    assert_eq!(&w[p..p + 8], &c.address.0);
    assert_eq!(&w[p + 8..p + 16], &c.caller.0);
    assert_eq!(&w[p + 16..p + 24], &c.callvalue.0);
    assert_eq!(w[p + 24], 100_000);
    assert_eq!(&w[p + 25..p + 33], &c.context);
    let p = p + 8; // the context
    assert_eq!(&w[p + 25..p + 33], &c.tree.root());
    assert_eq!(w[p + 33], 1);
    // A witness is 528 words — slot 8 + value 8 + 64 siblings × 8 (272, 32 siblings, in layout 1).
    assert_eq!(WITNESS_WORDS, 528);
    assert_eq!(w.len(), p + 34 + 528);
    let wit = c.tree.witness(&U256::from_u32(1));
    assert_eq!(&w[p + 34..p + 42], &wit.slot.0);
    assert_eq!(&w[p + 42..p + 50], &wit.value.0);
    assert_eq!(&w[p + 50..p + 58], &wit.siblings[0]);
    assert_eq!(&w[w.len() - 8..], &wit.siblings[63]);

    // and the guest decodes exactly those fields back
    let ws = decoded(&w);
    let inp = &ws.input;
    assert_eq!(&inp.code[..inp.code_len], &c.code[..]);
    assert_eq!(inp.calldata_len, 3);
    assert_eq!(&inp.calldata[..3], &[1, 2, 3]);
    assert_eq!(inp.env.address, c.address);
    assert_eq!(inp.env.caller, c.caller);
    assert_eq!(inp.env.callvalue, c.callvalue);
    assert_eq!(inp.env.gas_limit, 100_000);
    assert_eq!(inp.context, c.context);
    assert_eq!(inp.pre_root, c.tree.root());
    assert_eq!(inp.storage.root(), c.tree.root());
    assert_eq!(inp.storage.len(), 1);
    assert_eq!(inp.storage.witness(0).slot, wit.slot);
    assert_eq!(inp.storage.witness(0).value, wit.value);
    assert_eq!(inp.storage.witness(0).siblings.to_vec(), wit.siblings);
}

#[test]
fn the_public_output_binds_code_roots_return_data_and_logs() {
    let c = sample();
    let (out, o, post) = c.expected();
    assert_eq!(o.halt, Halt::Return);
    assert_eq!(out[0], 1);
    assert_eq!(&o.ret[..o.ret_len], &U256::from_u32(42).to_be_bytes());
    assert_ne!(post.root(), c.tree.root(), "the store moved the root");

    // the digest, recomputed here from this crate's keccak and sponge
    let d = digest(&c, o.gas_used, &c.code, c.tree.root(), post.root(), &o.ret[..o.ret_len], &no_logs());
    assert_eq!(out, out_words(1, d));
    assert_eq!(c.output_for(&c.code, &c.tree.root(), &post.root(), &o), out);
    assert_eq!(hash_words(&keccak256(&c.code)), words(&keccak256(&c.code)));

    // run_call over the input words reproduces the same eight words end to end
    let w = c.input_words();
    let mut ws = Box::new(Workspace::ZERO);
    assert_eq!(run_call(&mut HostRef, &mut ws, |i| w[i as usize], w.len() as u32), out);

    // every field is load-bearing: changing any one of the five changes the digest
    let other: Word8 = [9; 8];
    assert_ne!(out_words(1, digest(&c, o.gas_used, &c.code[..17], c.tree.root(), post.root(), &o.ret[..o.ret_len], &no_logs())), out);
    assert_ne!(out_words(1, digest(&c, o.gas_used, &c.code, other, post.root(), &o.ret[..o.ret_len], &no_logs())), out);
    assert_ne!(out_words(1, digest(&c, o.gas_used, &c.code, c.tree.root(), other, &o.ret[..o.ret_len], &no_logs())), out);
    assert_ne!(out_words(1, digest(&c, o.gas_used, &c.code, c.tree.root(), post.root(), &[], &no_logs())), out);
    assert_ne!(out_words(1, digest(&c, o.gas_used, &c.code, c.tree.root(), post.root(), &o.ret[..o.ret_len], &[])), out);

    // the digest binds the calldata itself, not only its effects (ZKVM-103): `sample()` never
    // reads calldata, and a different calldata is still a different output.
    let mut other_cd = sample();
    other_cd.calldata[0] ^= 1;
    assert_ne!(other_cd.expected().0, out);
    assert_ne!(other_cd.input_words(), w);

    // a contract that returns CALLDATALOAD(0) must see the change
    let reader = |cd: Vec<u8>| {
        let mut r = sample();
        r.code = vec![0x5f, 0x35, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]; // PUSH0 CALLDATALOAD PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
        r.calldata = cd;
        r
    };
    let a = reader(vec![1, 2, 3]).expected();
    let b = reader(vec![1, 2, 4]).expected();
    assert_eq!(a.1.status(), 1);
    assert_ne!(a.0, b.0);
}

#[test]
fn logs_are_hashed_as_a_counted_list_of_topic_lists() {
    // LOG2(0, 0, 0x11, 0x22) then LOG0(0, 0), then STOP
    let mut c = sample();
    c.code = vec![
        0x60, 0x22, 0x60, 0x11, 0x5f, 0x5f, 0xa2, // PUSH1 0x22 PUSH1 0x11 PUSH0 PUSH0 LOG2
        0x5f, 0x5f, 0xa0, // PUSH0 PUSH0 LOG0
        0x00,
    ];
    let (out, o, post) = c.expected();
    assert_eq!(out[0], 1);
    assert_eq!(o.n_logs, 2);
    assert_eq!(o.logs[0].n_topics, 2);
    assert_eq!(o.logs[0].topics[0], U256::from_u32(0x11));
    assert_eq!(o.logs[0].topics[1], U256::from_u32(0x22));
    assert_eq!(o.logs[1].n_topics, 0);

    let mut msg = Vec::new();
    msg.extend_from_slice(&2u32.to_be_bytes());
    msg.extend_from_slice(&2u32.to_be_bytes());
    msg.extend_from_slice(&U256::from_u32(0x11).to_be_bytes());
    msg.extend_from_slice(&U256::from_u32(0x22).to_be_bytes());
    msg.extend_from_slice(&keccak256(&[])); // no data: the hash of the empty string
    msg.extend_from_slice(&0u32.to_be_bytes());
    msg.extend_from_slice(&keccak256(&[]));
    assert_eq!(logs_hash(&mut HostRef, &o), keccak256(&msg));
    assert_eq!(out, out_words(1, digest(&c, o.gas_used, &c.code, c.tree.root(), post.root(), &[], &msg)));
    // topic order matters: the same two topics the other way round is a different output
    let mut swapped = c;
    swapped.code[1] = 0x11;
    swapped.code[3] = 0x22;
    let (out_s, o_s, _) = swapped.expected();
    assert_eq!(o_s.logs[0].topics[0], U256::from_u32(0x22));
    assert_ne!(out_s, out);
    // and so is the same topics under one log instead of two
    let mut one = swapped;
    one.code.drain(7..10);
    let (out_o, o_o, _) = one.expected();
    assert_eq!(o_o.n_logs, 1);
    assert_ne!(out_o, out_s);
}

#[test]
fn a_revert_binds_the_pre_root_the_revert_data_and_no_logs() {
    let mut c = sample();
    c.code = store_and_log();
    c.code.extend_from_slice(&[0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xfd]); // MSTORE(0, 42); REVERT(0, 32)
    let (out, o, post) = c.expected();
    assert_eq!(out[0], 0);
    assert_eq!(o.halt, Halt::Revert);
    // Ruling 3: the interpreter keeps the log it emitted before the revert …
    assert_eq!(o.n_logs, 1);
    assert_eq!(&o.ret[..o.ret_len], &U256::from_u32(42).to_be_bytes());
    // … and the output binds neither it nor the moved root
    assert_eq!(post.root(), c.tree.root());
    let d = digest(&c, o.gas_used, &c.code, c.tree.root(), c.tree.root(), &o.ret[..o.ret_len], &no_logs());
    assert_eq!(out, out_words(0, d));
    // the store really did move the guest's root, so the collapse above is doing work
    let mut moved = c.tree.clone();
    moved.insert(U256::from_u32(1), U256::from_u32(99));
    assert_ne!(moved.root(), c.tree.root());
    assert_ne!(out_words(0, digest(&c, o.gas_used, &c.code, c.tree.root(), moved.root(), &o.ret[..o.ret_len], &no_logs())), out);
    // and the emitted log is really dropped
    let mut one_log = Vec::new();
    one_log.extend_from_slice(&1u32.to_be_bytes());
    one_log.extend_from_slice(&1u32.to_be_bytes());
    one_log.extend_from_slice(&U256::from_u32(0x1234).to_be_bytes());
    one_log.extend_from_slice(&keccak256(&[]));
    assert_ne!(out_words(0, digest(&c, o.gas_used, &c.code, c.tree.root(), c.tree.root(), &o.ret[..o.ret_len], &one_log)), out);
    assert_eq!(logs_hash(&mut HostRef, &o), keccak256(&no_logs()));
}

#[test]
fn an_exceptional_halt_binds_the_pre_root_no_logs_and_no_return_data() {
    let mut c = sample();
    c.code = store_and_log();
    c.code.push(0xfe); // INVALID
    let (out, o, post) = c.expected();
    assert_eq!(out[0], 2);
    assert_eq!(o.halt, Halt::Invalid);
    assert_eq!(o.n_logs, 1);
    assert_eq!(o.ret_len, 0);
    assert_eq!(post.root(), c.tree.root());
    assert_eq!(out, out_words(2, digest(&c, o.gas_used, &c.code, c.tree.root(), c.tree.root(), &[], &no_logs())));

    // status 2 binds empty return data even for an outcome that carries some — unreachable
    // through the interpreter (only RETURN/REVERT fill `ret`, and both are status 1 or 0), so
    // `public_output` is exercised directly.
    let mut forged = Outcome {
        halt: Halt::Invalid,
        gas_used: 1,
        ret: [0; MAX_RETURN_BYTES],
        ret_len: 32,
        logs: [Log::EMPTY; MAX_LOGS],
        n_logs: 0,
    };
    forged.ret[..32].copy_from_slice(&U256::from_u32(7).to_be_bytes());
    let pre = c.tree.root();
    assert_eq!(
        c.output_for(&c.code, &pre, &pre, &forged),
        out_words(2, digest(&c, forged.gas_used, &c.code, pre, pre, &[], &no_logs()))
    );
    // and it binds the pre-root however the post-root argument is spelled
    assert_eq!(
        c.output_for(&c.code, &pre, &[7; 8], &forged),
        c.output_for(&c.code, &pre, &pre, &forged)
    );
}

#[test]
fn a_malformed_input_vector_is_an_exceptional_halt_not_a_panic() {
    // the canonical malformed output: no code, zero roots, no return data, no logs. A verifier
    // recomputing the digest from a real (codehash, pre_root) never matches it, so the proof is
    // rejected rather than applied as a no-op — which is what a prover-supplied vector that does
    // not even parse deserves.
    let malformed = out_words(2, digest(&no_call(), 0, &[], [0; 8], [0; 8], &[], &no_logs()));

    let run = |w: &Vec<u32>| {
        let mut ws = Box::new(Workspace::ZERO);
        let (out, o) = run_call_with(&mut HostRef, &mut ws, |i| w[i as usize], w.len() as u32);
        (out, o.status(), o.halt, o.gas_used, o.ret_len, o.n_logs)
    };
    let parse = |w: &Vec<u32>| {
        let mut ws = Box::new(Workspace::ZERO);
        let mut c = InputCursor::new(|i| w[i as usize], w.len() as u32);
        decode_input(&mut HostRef, &mut ws.input, &mut c).expect_err("must not parse")
    };

    // 1. code above EIP-170's cap
    let mut long_code = sample();
    long_code.code = vec![0x5b; MAX_CODE_BYTES + 1];
    let w = long_code.input_words();
    assert_eq!(parse(&w), ParseError::CodeTooLong);
    assert_eq!(run(&w), (malformed, 2, Halt::OutOfBounds, 0, 0, 0));

    // 2. calldata above its cap
    let mut long_cd = sample();
    long_cd.calldata = vec![7; MAX_CALLDATA_BYTES + 1];
    let w = long_cd.input_words();
    assert_eq!(parse(&w), ParseError::CalldataTooLong);
    assert_eq!(run(&w), (malformed, 2, Halt::OutOfBounds, 0, 0, 0));

    // 3. more witnesses than the tree holds room for
    let c = sample();
    let mut w = c.input_words();
    let n_at = w.len() - 1 - WITNESS_WORDS;
    assert_eq!(w[n_at], 1);
    w[n_at] = MAX_WITNESSES as u32 + 1;
    assert_eq!(parse(&w), ParseError::TooManyWitnesses);
    assert_eq!(run(&w), (malformed, 2, Halt::OutOfBounds, 0, 0, 0));

    // 4. a witness count that overruns the vector (one witness declared, none supplied)
    let mut w = c.input_words();
    w.truncate(n_at + 1);
    assert_eq!(parse(&w), ParseError::Truncated);
    assert_eq!(run(&w), (malformed, 2, Halt::OutOfBounds, 0, 0, 0));

    // 5. a vector truncated inside the last witness, and one that ends before the root
    for cut in [1, WITNESS_WORDS, WITNESS_WORDS + 10] {
        let mut w = c.input_words();
        w.truncate(w.len() - cut);
        assert_eq!(parse(&w), ParseError::Truncated, "cut of {cut} words");
        assert_eq!(run(&w), (malformed, 2, Halt::OutOfBounds, 0, 0, 0));
    }

    // 6. an empty vector: not even the code length is there
    assert_eq!(parse(&vec![]), ParseError::Truncated);
    assert_eq!(run(&vec![]), (malformed, 2, Halt::OutOfBounds, 0, 0, 0));

    // 7. two witnesses at one leaf position. `EvmCall::input_words` refuses to build this (a
    //    ground collision is 2^32 work, so the duplicate is spliced in by hand: the sample's one
    //    witness, declared twice), because accepting it is a forgery and not griefing — see
    //    `evm_core::storage`'s module doc and `tests/evm_storage.rs`.
    let mut w = c.input_words();
    let wit_words = w[n_at + 1..].to_vec();
    assert_eq!(wit_words.len(), WITNESS_WORDS);
    w[n_at] = 2;
    w.extend_from_slice(&wit_words);
    assert_eq!(parse(&w), ParseError::DuplicateWitnessIndex);
    assert_eq!(run(&w), (malformed, 2, Halt::OutOfBounds, 0, 0, 0));
    // the same vector with the second witness at a *different* position parses and runs
    let mut ok = sample();
    ok.tree.insert(U256::from_u32(2), U256::from_u32(7));
    ok.touched = vec![U256::from_u32(1), U256::from_u32(2)];
    let w = ok.input_words();
    assert_eq!(w[w.len() - 1 - 2 * WITNESS_WORDS], 2);
    let mut ws = Box::new(Workspace::ZERO);
    let mut cur = InputCursor::new(|i| w[i as usize], w.len() as u32);
    decode_input(&mut HostRef, &mut ws.input, &mut cur).expect("two distinct positions parse");
    assert_eq!(ws.input.storage.len(), 2);

    // the belt to the interpreter's braces: at the caps everything still parses and runs
    let mut at_cap = sample();
    at_cap.code = vec![0x5b; MAX_CODE_BYTES]; // 24 576 JUMPDESTs, then off the end = STOP
    at_cap.calldata = vec![7; MAX_CALLDATA_BYTES];
    at_cap.gas_limit = 1_000_000;
    let (out, o, _) = at_cap.expected();
    assert_eq!(out[0], 1);
    assert_eq!(o.halt, Halt::Stop);
    assert_eq!(o.gas_used, MAX_CODE_BYTES as u64);
}

#[test]
fn one_workspace_runs_two_calls_without_leaking_state() {
    // The guest keeps a single `Workspace` in `.bss`; the host test reuses one across calls, which
    // is the same reset path. A second run must produce exactly what a fresh workspace does.
    let a = sample();
    let mut b = sample();
    b.code = vec![
        0x60, 0x40, 0x60, 0x20, 0x52, // MSTORE(0x20, 0x40) — memory a fresh run must not see
        0x5f, 0x51, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3, // RETURN(MLOAD(0))
    ];
    let (wa, wb) = (a.input_words(), b.input_words());
    let mut ws = Box::new(Workspace::ZERO);
    let first = run_call(&mut HostRef, &mut ws, |i| wb[i as usize], wb.len() as u32);
    let second = run_call(&mut HostRef, &mut ws, |i| wa[i as usize], wa.len() as u32);
    let third = run_call(&mut HostRef, &mut ws, |i| wb[i as usize], wb.len() as u32);
    assert_eq!(first, b.expected().0);
    assert_eq!(second, a.expected().0);
    assert_eq!(third, first);
    assert_ne!(first, second);

    // the jumpdest bitmap too: a run whose byte 4 is a JUMPDEST, then one whose byte 4 is not.
    let mut jd = sample();
    jd.code = vec![0x60, 0x04, 0x56, 0x00, 0x5b, 0x00]; // PUSH1 4; JUMP; STOP; JUMPDEST; STOP
    let mut no_jd = sample();
    // … and one whose byte 4 is a STOP, so a stale bitmap bit would let the jump *succeed*
    no_jd.code = vec![0x60, 0x04, 0x56, 0x00, 0x00];
    let (wj, wn) = (jd.input_words(), no_jd.input_words());
    assert_eq!(run_call(&mut HostRef, &mut ws, |i| wj[i as usize], wj.len() as u32)[0], 1);
    assert_eq!(run_call(&mut HostRef, &mut ws, |i| wn[i as usize], wn.len() as u32)[0], 2);
    assert_eq!(no_jd.expected().1.halt, Halt::BadJump);
}

// ---- evm2rv Task 1: the executor hook and the storage FFI ----

/// The interpreter as an `Executor`.
fn interp_exec(h: &mut HostRef, code: &[u8], cd: &[u8], env: Env, st: &mut StorageTree, b: &mut Buffers) -> Outcome {
    Interpreter::new(h, code, cd, env, st, b).run()
}

/// (a) The executor hook with the interpreter as the executor is `run_call_with`, on the ERC-20
/// `transfer` vector — the same eight words, the same outcome, the same post-state tree, and the
/// executor sees exactly the decoded call — and on a revert and an exceptional halt, whose outputs
/// the shared `public_output` rules collapse. A malformed vector never reaches the executor.
#[test]
fn the_executor_hook_with_the_interpreter_is_run_call_with() {
    use randprotocol_zkvm::evm::{erc20_transfer, ALICE, BOB};
    let call = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let w = call.input_words();

    let mut ws_ref = Box::new(Workspace::ZERO);
    let (out_ref, o_ref) = run_call_with(&mut HostRef, &mut ws_ref, |i| w[i as usize], w.len() as u32);
    assert_eq!(out_ref[0], 1, "the transfer succeeds");

    let mut calls = 0;
    let mut exec = |h: &mut HostRef, code: &[u8], cd: &[u8], env: Env, st: &mut StorageTree, b: &mut Buffers| {
        calls += 1;
        assert_eq!(code, &call.code[..]);
        assert_eq!(cd, &call.calldata[..]);
        assert_eq!(env.address, call.address);
        assert_eq!(env.caller, call.caller);
        assert_eq!(env.callvalue, call.callvalue);
        assert_eq!(env.gas_limit, call.gas_limit);
        assert_eq!(st.root(), call.tree.root());
        interp_exec(h, code, cd, env, st, b)
    };
    let mut ws = Box::new(Workspace::ZERO);
    let (out, o) = run_call_with_executor(&mut HostRef, &mut ws, |i| w[i as usize], w.len() as u32, &mut exec);
    assert_eq!(calls, 1);
    assert_eq!(out, out_ref);
    assert_eq!(out, call.expected().0);
    assert_eq!((o.halt, o.gas_used, &o.ret[..o.ret_len], o.n_logs), (o_ref.halt, o_ref.gas_used, &o_ref.ret[..o_ref.ret_len], o_ref.n_logs));
    assert_eq!(o.logs, o_ref.logs);
    assert_eq!(ws.input.storage.root(), ws_ref.input.storage.root());
    assert_ne!(ws.input.storage.root(), call.tree.root(), "the transfer moved the root");

    // a revert and an exceptional halt after a store and a log: the same collapsed outputs
    for tail in [vec![0x60, 0x2a, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xfd], vec![0xfe]] {
        let mut c = sample();
        c.code = store_and_log();
        c.code.extend_from_slice(&tail);
        let w = c.input_words();
        let mut ws = Box::new(Workspace::ZERO);
        let (out, o) = run_call_with_executor(&mut HostRef, &mut ws, |i| w[i as usize], w.len() as u32, &mut interp_exec);
        let (want, o_want, _) = c.expected();
        assert_eq!(out, want);
        assert_ne!(out[0], 1);
        assert_eq!((o.halt, o.gas_used, o.n_logs), (o_want.halt, o_want.gas_used, o_want.n_logs));
    }

    // a malformed vector never reaches the executor and is the canonical malformed output
    let mut bad = w.clone();
    bad.truncate(w.len() - 1);
    let mut never = |_: &mut HostRef, _: &[u8], _: &[u8], _: Env, _: &mut StorageTree, _: &mut Buffers| -> Outcome {
        panic!("the executor ran on a vector that does not parse")
    };
    let mut ws = Box::new(Workspace::ZERO);
    let (out, o) = run_call_with_executor(&mut HostRef, &mut ws, |i| bad[i as usize], bad.len() as u32, &mut never);
    assert_eq!(out, out_words(2, digest(&no_call(), 0, &[], [0; 8], [0; 8], &[], &no_logs())));
    assert_eq!((o.halt, o.gas_used), (Halt::OutOfBounds, 0));
}

/// (b) `evm_sload`/`evm_sstore` through the C ABI on a two-slot tree match `StorageTree::load`/
/// `store` step for step — values, roots and refusals — and `evm_keccak256` is `keccak256`.
#[test]
fn the_storage_and_keccak_ffi_match_the_storage_tree() {
    let mut c = sample();
    c.tree.insert(U256::from_u32(2), U256::from_u32(7));
    c.touched = vec![U256::from_u32(1), U256::from_u32(2)];
    let w = c.input_words();
    let mut direct = decoded(&w);
    let mut via = decoded(&w);
    assert_eq!(via.input.storage.len(), 2);

    let mut host = HostRef;
    let mut hb = HostBox(&mut host);
    let hp = &mut hb as *mut HostBox as *mut c_void;
    let tp = &mut via.input.storage as *mut StorageTree;

    let sload = |slot: U256| -> (u32, U256) {
        let mut out = [0u32; 8];
        let code = unsafe { evm_sload(tp, hp, slot.0.as_ptr(), out.as_mut_ptr()) };
        (code, U256(out))
    };
    let sstore = |slot: U256, value: U256| -> u32 { unsafe { evm_sstore(tp, hp, slot.0.as_ptr(), value.0.as_ptr()) } };

    let (one, two, three) = (U256::from_u32(1), U256::from_u32(2), U256::from_u32(3));
    assert_eq!(sload(one), (0, direct.input.storage.load(&mut HostRef, &one).unwrap()));
    assert_eq!(sload(one).1, U256::from_u32(41));
    assert_eq!(sload(two), (0, direct.input.storage.load(&mut HostRef, &two).unwrap()));
    assert_eq!(sstore(two, U256::from_u32(99)), 0);
    direct.input.storage.store(&mut HostRef, &two, U256::from_u32(99)).unwrap();
    assert_eq!(unsafe { (*tp).root() }, direct.input.storage.root());
    assert_ne!(direct.input.storage.root(), c.tree.root(), "the store moved the root");
    // the other witness's sibling was refreshed, so slot 1 still loads against the new root
    assert_eq!(sload(one), (0, direct.input.storage.load(&mut HostRef, &one).unwrap()));
    assert_eq!(sstore(one, U256::ZERO), 0);
    direct.input.storage.store(&mut HostRef, &one, U256::ZERO).unwrap();
    assert_eq!(sload(two), (0, U256::from_u32(99)));
    assert_eq!(sload(one), (0, U256::ZERO));
    assert_eq!(unsafe { (*tp).root() }, direct.input.storage.root());
    let mut post = c.tree.clone();
    post.insert(one, U256::ZERO);
    post.insert(two, U256::from_u32(99));
    assert_eq!(direct.input.storage.root(), post.root());

    // a slot with no witness is NoWitness, as a halt code; nothing moves
    let before = unsafe { (*tp).root() };
    assert_eq!(direct.input.storage.load(&mut HostRef, &three), Err(StorageError::NoWitness));
    assert_eq!(sload(three).0, halt_code(Halt::NoWitness));
    assert_eq!(sstore(three, one), halt_code(Halt::NoWitness));
    assert_eq!(unsafe { (*tp).root() }, before);

    // a witness that does not hash to the root is BadWitness
    let mut forged = w.clone();
    let n_at = forged.len() - 1 - 2 * WITNESS_WORDS;
    forged[n_at - 8] ^= 1; // pre_root's first word
    let mut bad = decoded(&forged);
    assert_eq!(bad.input.storage.load(&mut HostRef, &one), Err(StorageError::BadWitness));
    let mut bad2 = decoded(&forged);
    let bp = &mut bad2.input.storage as *mut StorageTree;
    let mut out = [0u32; 8];
    assert_eq!(unsafe { evm_sload(bp, hp, one.0.as_ptr(), out.as_mut_ptr()) }, halt_code(Halt::BadWitness));
    assert_eq!(unsafe { evm_sstore(bp, hp, one.0.as_ptr(), two.0.as_ptr()) }, halt_code(Halt::BadWitness));

    // the halt codes are a bijection on the halts, and 0 is none of them
    let all = [
        Halt::Stop, Halt::Return, Halt::Revert, Halt::OutOfGas, Halt::StackUnderflow, Halt::StackOverflow,
        Halt::BadJump, Halt::Invalid, Halt::Trap(0x0c), Halt::NoWitness, Halt::BadWitness, Halt::OutOfBounds,
    ];
    for h in all {
        let arg = if let Halt::Trap(op) = h { op as u32 } else { 0 };
        assert_ne!(halt_code(h), 0);
        assert_eq!(halt_from_code(halt_code(h), arg), Some(h));
    }
    assert_eq!(halt_from_code(0, 0), None);
    assert_eq!(halt_from_code(99, 0), None);

    // keccak256 through the FFI, at the empty message, a sub-rate one and a multi-block one
    for n in [0usize, 5, 135, 136, 137, 1296] {
        let msg: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
        let mut out = [0u8; 32];
        unsafe { evm_keccak256(hp, msg.as_ptr(), n as u32, out.as_mut_ptr()) };
        assert_eq!(out, keccak256(&msg), "{n} bytes");
    }
    let mut out = [0u8; 32];
    unsafe { evm_keccak256(hp, std::ptr::null(), 0, out.as_mut_ptr()) };
    assert_eq!(out, keccak256(&[]));
}


// ---- ZKVM-103 / ZKVM-104: who called, with what, at what cost, emitting which data -----------

/// The statement a chain holds for a call it authenticated and the outcome it expects to apply:
/// every field from the call and the host's own post-state, none from the guest's output.
fn statement_of(c: &EvmCall, o: &Outcome, post: &SparseTree, logs: Vec<EvmLog>) -> EvmStatement {
    let status = o.status();
    EvmStatement {
        layout: 2,
        codehash: keccak256(&c.code),
        pre_root: c.tree.root(),
        post_root: if status == 1 { post.root() } else { c.tree.root() },
        return_data: if status == 2 { vec![] } else { o.ret[..o.ret_len].to_vec() },
        logs: if status == 1 { logs } else { vec![] },
        address: c.address,
        caller: c.caller,
        callvalue: c.callvalue,
        calldata: c.calldata.clone(),
        context: c.context,
        gas_limit: c.gas_limit as u32,
        gas_used: o.gas_used as u32,
    }
}

/// The ERC-20's `Transfer(from, to, amount)` as a verifier writes it down: three topics, and the
/// amount as the 32 bytes of data.
fn transfer_log(from: U256, to: U256, amount: u32) -> EvmLog {
    let sig = keccak256(b"Transfer(address,address,uint256)");
    EvmLog {
        topics: vec![U256::from_be_bytes(&sig), from, to],
        data: U256::from_u32(amount).to_be_bytes().to_vec(),
    }
}

/// A third address, holding no tokens and no authority over anyone else's.
const MALLORY: U256 = U256([0x3333_3333, 0x3333_3333, 0x3333_3333, 0x3333_3333, 0x3333_3333, 0, 0, 0]);

/// **ZKVM-103's forgery.** Mallory holds the storage witnesses (they are public state) and no
/// authority over Alice. She runs `transfer(MALLORY, 250)` with `caller = ALICE` — the guest has
/// no way to refuse, and the run is a correct execution: status 1, Alice's balance down, Mallory's
/// up. The chain authenticated *Mallory* as the sender of this transaction, so the statement it
/// checks the proof against names her as the caller, and the guest's output does not match it.
/// Before the caller was in the digest there was no field to compare: the proof was accepted.
#[test]
fn a_transfer_proved_for_a_caller_who_did_not_authorise_it_is_refused() {
    let balances = [(ALICE, U256::from_u32(1000))];
    // What the prover ran: Alice as the caller, without Alice.
    let forged = erc20_transfer(ALICE, MALLORY, U256::from_u32(250), &balances);
    let (out, o, post) = forged.expected();
    assert_eq!(out[0], 1, "the forged call is a correct execution");
    assert_eq!(o.n_logs, 1);
    let logs = vec![transfer_log(ALICE, MALLORY, 250)];

    // The statement for the call as run does describe the output — the digest is what we say.
    let as_run = statement_of(&forged, &o, &post, logs.clone());
    assert!(as_run.accepts(1, &out));

    // The chain's statement: the same contract, calldata and roots, and the caller it
    // authenticated — Mallory. Refused.
    let mut authorised = as_run.clone();
    authorised.caller = MALLORY;
    assert!(!authorised.accepts(1, &out), "a transfer out of Alice proved without Alice was accepted");

    // And what Mallory can honestly prove as herself is a revert that moves nothing.
    let mut honest = erc20_transfer(MALLORY, MALLORY, U256::from_u32(250), &balances);
    honest.touched = forged.touched.clone();
    let (out_h, o_h, post_h) = honest.expected();
    assert_eq!(out_h[0], 0, "Mallory has no balance: the transfer reverts");
    assert_eq!(post_h.root(), honest.tree.root());
    assert!(statement_of(&honest, &o_h, &post_h, vec![]).accepts(0, &out_h));
}

/// Every call field is load-bearing: a proof for a different contract address, call value,
/// calldata (the recipient or the amount), gas limit or context (a replay under another nonce) is
/// a proof of another statement.
#[test]
fn the_public_output_binds_address_callvalue_calldata_gas_limit_and_context() {
    let c = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let (out, o, post) = c.expected();
    assert_eq!(out[0], 1);
    let s = statement_of(&c, &o, &post, vec![transfer_log(ALICE, BOB, 250)]);
    assert!(s.accepts(1, &out));
    assert_eq!(s.preimage().len(), 83);
    assert_eq!(s.preimage()[0], evm_core::storage::LAYOUT_VERSION);
    // the guest's own function and the independent statement agree on the whole digest
    assert_eq!(c.output_for(&c.code, &c.tree.root(), &post.root(), &o), s.output_words(1));

    let refused = |f: &dyn Fn(&mut EvmStatement)| {
        let mut t = s.clone();
        f(&mut t);
        !t.accepts(1, &out)
    };
    assert!(refused(&|t| t.layout = 1), "the storage layout");
    assert!(refused(&|t| t.address = BOB), "address");
    assert!(refused(&|t| t.caller = BOB), "caller");
    assert!(refused(&|t| t.callvalue = U256::from_u32(1)), "callvalue");
    assert!(refused(&|t| *t.calldata.last_mut().unwrap() ^= 1), "calldata: the amount");
    assert!(refused(&|t| t.calldata[35] ^= 1), "calldata: the recipient");
    assert!(refused(&|t| t.calldata.push(0)), "calldata: its length");
    assert!(refused(&|t| t.context[0] ^= 1), "context: a replay under another nonce");
    assert!(refused(&|t| t.context[7] ^= 1 << 31), "context: its last word");
    assert!(refused(&|t| t.gas_limit += 1), "gas_limit");
    assert!(refused(&|t| t.gas_used += 1), "gas_used");
    assert!(refused(&|t| t.gas_used -= 1), "gas_used");
    assert!(!s.accepts(0, &out), "status");

    // the same from the guest's side: each field changed in the *input* moves the output
    let moved = |f: &dyn Fn(&mut EvmCall)| {
        let mut d = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
        f(&mut d);
        d.expected().0 != out
    };
    assert!(moved(&|d| d.address = BOB));
    assert!(moved(&|d| d.callvalue = U256::from_u32(1)));
    assert!(moved(&|d| d.context = [1, 0, 0, 0, 0, 0, 0, 0]));
    assert!(moved(&|d| d.gas_limit += 1));
    assert_eq!(&c.calldata[..4], &selector("transfer(address,uint256)"));
}

/// **ZKVM-104, the log data.** The amount of a `Transfer` is the log's data, not a topic. Two
/// runs that emit the same topics over data differing in one byte have different outputs, and the
/// statement binds the data byte for byte.
#[test]
fn one_byte_of_log_data_changes_the_public_output() {
    // MSTORE8(0, calldata[0]); LOG1(offset 0, size 1, topic 0x1234); STOP
    let code = vec![
        0x5f, 0x35, 0x60, 0xf8, 0x1c, // PUSH0 CALLDATALOAD PUSH1 248 SHR  -> calldata[0]
        0x5f, 0x53, // PUSH0 MSTORE8
        0x61, 0x12, 0x34, 0x60, 0x01, 0x5f, 0xa1, // PUSH2 0x1234 PUSH1 1 PUSH0 LOG1
        0x00,
    ];
    let run = |byte: u8| {
        let mut c = sample();
        c.code = code.clone();
        c.calldata = vec![byte];
        c.touched = vec![];
        let (out, o, post) = c.expected();
        assert_eq!(out[0], 1);
        assert_eq!(o.n_logs, 1);
        assert_eq!(o.logs[0].data_hash, keccak256(&[byte]));
        (c, out, o, post)
    };
    let (c7, out7, o7, post7) = run(7);
    let log = |byte: u8| vec![EvmLog { topics: vec![U256::from_u32(0x1234)], data: vec![byte] }];
    let s7 = statement_of(&c7, &o7, &post7, log(7));
    assert!(s7.accepts(1, &out7));
    // the verifier's log with one data byte changed is another statement …
    let mut s = s7.clone();
    s.logs = log(6);
    assert!(!s.accepts(1, &out7), "the log's data is not bound");
    // … and so is the log with no data at all, or one byte more
    s.logs = vec![EvmLog { topics: vec![U256::from_u32(0x1234)], data: vec![] }];
    assert!(!s.accepts(1, &out7));
    s.logs = vec![EvmLog { topics: vec![U256::from_u32(0x1234)], data: vec![7, 0] }];
    assert!(!s.accepts(1, &out7));

    // The same seen through `logs_hash` alone, with everything else in the digest equal: the
    // two outcomes differ only in the data hash.
    let (_, _, o6, _) = run(6);
    assert_eq!(o6.logs[0].topics, o7.logs[0].topics);
    assert_eq!(o6.gas_used, o7.gas_used);
    assert_ne!(logs_hash(&mut HostRef, &o6), logs_hash(&mut HostRef, &o7));

    // the ERC-20: the Transfer's amount is bound through its data
    let c = erc20_transfer(ALICE, BOB, U256::from_u32(250), &[(ALICE, U256::from_u32(1000))]);
    let (out, o, post) = c.expected();
    assert!(statement_of(&c, &o, &post, vec![transfer_log(ALICE, BOB, 250)]).accepts(1, &out));
    assert!(!statement_of(&c, &o, &post, vec![transfer_log(ALICE, BOB, 251)]).accepts(1, &out));
}

/// **ZKVM-104, the gas.** `gas_used` in the public output is the interpreter's own figure on the
/// ERC-20 vectors: a success, a revert, and an exceptional halt (which consumes the whole limit).
#[test]
fn gas_used_in_the_public_output_is_the_interpreters() {
    let balances = [(ALICE, U256::from_u32(1000))];
    // a transfer that succeeds
    let ok = erc20_transfer(ALICE, BOB, U256::from_u32(250), &balances);
    let (out, o, post) = ok.expected();
    assert_eq!(out[0], 1);
    assert!(o.gas_used > 21_000 && o.gas_used < ok.gas_limit, "{}", o.gas_used);
    let s = statement_of(&ok, &o, &post, vec![transfer_log(ALICE, BOB, 250)]);
    assert_eq!(s.gas_used as u64, o.gas_used);
    assert!(s.accepts(1, &out));
    // a transfer over the balance: a revert, which leaves gas on the table and still binds it
    let over = erc20_transfer(ALICE, BOB, U256::from_u32(1001), &balances);
    let (out_r, o_r, post_r) = over.expected();
    assert_eq!(out_r[0], 0);
    assert!(o_r.gas_used > 0 && o_r.gas_used < over.gas_limit);
    let s_r = statement_of(&over, &o_r, &post_r, vec![]);
    assert!(s_r.accepts(0, &out_r));
    let mut wrong = s_r.clone();
    wrong.gas_used = o.gas_used as u32;
    assert!(!wrong.accepts(0, &out_r));
    // out of gas: status 2, and the gas bound is the whole limit
    let mut starved = erc20_transfer(ALICE, BOB, U256::from_u32(250), &balances);
    starved.gas_limit = 5_000;
    let (out_s, o_s, post_s) = starved.expected();
    assert_eq!(out_s[0], 2);
    assert_eq!(o_s.gas_used, 5_000);
    let s_s = statement_of(&starved, &o_s, &post_s, vec![]);
    assert_eq!(s_s.gas_used, s_s.gas_limit);
    assert!(s_s.accepts(2, &out_s));
}

/// ZKVM-117: a statement that already knows the code's hash (`Statement::codehash`, what a
/// translated contract's shim passes once its code guard has passed) gives the same eight words as
/// one that hashes the code — and the value is taken at its word: a different hash is a different
/// digest, never silently corrected.
#[test]
fn a_known_codehash_is_the_hash_of_the_code_or_another_statement() {
    use evm_core::abi::{public_output, Statement};
    let c = sample();
    let (out, o, post) = c.expected();
    let env = c.env();
    let (pre, post) = (c.tree.root(), post.root());
    let statement = |codehash| Statement {
        code: &c.code,
        codehash,
        calldata: &c.calldata,
        env: &env,
        context: &c.context,
        pre_root: &pre,
        post_root: &post,
    };
    assert_eq!(public_output(&mut HostRef, &statement(None), &o), out);
    let known = hash_words(&keccak256(&c.code));
    assert_eq!(public_output(&mut HostRef, &statement(Some(known)), &o), out);
    let mut wrong = known;
    wrong[3] ^= 1;
    assert_ne!(public_output(&mut HostRef, &statement(Some(wrong)), &o), out);
}
