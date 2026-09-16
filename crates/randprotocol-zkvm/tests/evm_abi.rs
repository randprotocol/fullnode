//! The input layout and the public output (Task 4 of the M4.3 plan).
//!
//! Two sides of one encoding: `EvmCall::input_words` builds the word vector the machine's
//! `READ_INPUT` serves, and `evm_core::abi` decodes it back, runs it and produces the eight
//! public output words. Every digest here is recomputed independently from this crate's own
//! primitives (`keccak::keccak256`, `notes::hash`), never from `evm_core`'s copies, so an
//! agreement is evidence rather than a tautology.

use evm_core::abi::{
    decode_input, hash_words, logs_hash, public_output, run_call, run_call_with, InputCursor,
    ParseError, Workspace,
};
use evm_core::interp::{Halt, Interpreter, Log, Outcome, MAX_CALLDATA_BYTES, MAX_CODE_BYTES, MAX_LOGS, MAX_RETURN_BYTES};
use evm_core::storage::MAX_WITNESSES;
use evm_core::u256::U256;
use randprotocol_zkvm::evm::{EvmCall, HostRef, SparseTree, WITNESS_WORDS};
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

/// The 40-word preimage of the `EVM_OUT` digest, recomputed here from this crate's primitives.
fn digest(code: &[u8], pre: Word8, post: Word8, ret: &[u8], logs: &[u8]) -> Word8 {
    let mut msg = Vec::new();
    for part in [words(&keccak256(code)), pre, post, words(&keccak256(ret)), words(&keccak256(logs))]
    {
        msg.extend_from_slice(&part);
    }
    assert_eq!(msg.len(), 40);
    hash(domain::EVM_OUT, &msg)
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
    assert_eq!(&w[p + 25..p + 33], &c.tree.root());
    assert_eq!(w[p + 33], 1);
    // Ruling 2: a witness is 272 words — slot 8 + value 8 + 32 siblings × 8.
    assert_eq!(WITNESS_WORDS, 272);
    assert_eq!(w.len(), p + 34 + 272);
    let wit = c.tree.witness(&U256::from_u32(1));
    assert_eq!(&w[p + 34..p + 42], &wit.slot.0);
    assert_eq!(&w[p + 42..p + 50], &wit.value.0);
    assert_eq!(&w[p + 50..p + 58], &wit.siblings[0]);
    assert_eq!(&w[w.len() - 8..], &wit.siblings[31]);

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
    assert_eq!(inp.pre_root, c.tree.root());
    assert_eq!(inp.storage.root(), c.tree.root());
    assert_eq!(inp.storage.len(), 1);
    assert_eq!(inp.storage.witness(0).slot, wit.slot);
    assert_eq!(inp.storage.witness(0).value, wit.value);
    assert_eq!(inp.storage.witness(0).siblings, wit.siblings);
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
    let d = digest(&c.code, c.tree.root(), post.root(), &o.ret[..o.ret_len], &no_logs());
    assert_eq!(out, out_words(1, d));
    assert_eq!(public_output(&mut HostRef, &c.code, &c.tree.root(), &post.root(), &o), out);
    assert_eq!(hash_words(&keccak256(&c.code)), words(&keccak256(&c.code)));

    // run_call over the input words reproduces the same eight words end to end
    let w = c.input_words();
    let mut ws = Box::new(Workspace::ZERO);
    assert_eq!(run_call(&mut HostRef, &mut ws, |i| w[i as usize], w.len() as u32), out);

    // every field is load-bearing: changing any one of the five changes the digest
    let other: Word8 = [9; 8];
    assert_ne!(out_words(1, digest(&c.code[..17], c.tree.root(), post.root(), &o.ret[..o.ret_len], &no_logs())), out);
    assert_ne!(out_words(1, digest(&c.code, other, post.root(), &o.ret[..o.ret_len], &no_logs())), out);
    assert_ne!(out_words(1, digest(&c.code, c.tree.root(), other, &o.ret[..o.ret_len], &no_logs())), out);
    assert_ne!(out_words(1, digest(&c.code, c.tree.root(), post.root(), &[], &no_logs())), out);
    assert_ne!(out_words(1, digest(&c.code, c.tree.root(), post.root(), &o.ret[..o.ret_len], &[])), out);

    // the digest binds calldata only through its effects. `sample()` never reads calldata, so a
    // different calldata gives the *same* digest — the input words differ, and `H_IN` binds them.
    let mut same = sample();
    same.calldata[0] ^= 1;
    assert_eq!(same.expected().0, out);
    assert_ne!(same.input_words(), w);

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
    msg.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(logs_hash(&mut HostRef, &o), keccak256(&msg));
    assert_eq!(out, out_words(1, digest(&c.code, c.tree.root(), post.root(), &[], &msg)));
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
    let d = digest(&c.code, c.tree.root(), c.tree.root(), &o.ret[..o.ret_len], &no_logs());
    assert_eq!(out, out_words(0, d));
    // the store really did move the guest's root, so the collapse above is doing work
    let mut moved = c.tree.clone();
    moved.insert(U256::from_u32(1), U256::from_u32(99));
    assert_ne!(moved.root(), c.tree.root());
    assert_ne!(out_words(0, digest(&c.code, c.tree.root(), moved.root(), &o.ret[..o.ret_len], &no_logs())), out);
    // and the emitted log is really dropped
    let mut one_log = Vec::new();
    one_log.extend_from_slice(&1u32.to_be_bytes());
    one_log.extend_from_slice(&1u32.to_be_bytes());
    one_log.extend_from_slice(&U256::from_u32(0x1234).to_be_bytes());
    assert_ne!(out_words(0, digest(&c.code, c.tree.root(), c.tree.root(), &o.ret[..o.ret_len], &one_log)), out);
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
    assert_eq!(out, out_words(2, digest(&c.code, c.tree.root(), c.tree.root(), &[], &no_logs())));

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
        public_output(&mut HostRef, &c.code, &pre, &pre, &forged),
        out_words(2, digest(&c.code, pre, pre, &[], &no_logs()))
    );
    // and it binds the pre-root however the post-root argument is spelled
    assert_eq!(
        public_output(&mut HostRef, &c.code, &pre, &[7; 8], &forged),
        public_output(&mut HostRef, &c.code, &pre, &pre, &forged)
    );
}

#[test]
fn a_malformed_input_vector_is_an_exceptional_halt_not_a_panic() {
    // the canonical malformed output: no code, zero roots, no return data, no logs. A verifier
    // recomputing the digest from a real (codehash, pre_root) never matches it, so the proof is
    // rejected rather than applied as a no-op — which is what a prover-supplied vector that does
    // not even parse deserves.
    let malformed = out_words(2, digest(&[], [0; 8], [0; 8], &[], &no_logs()));

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
