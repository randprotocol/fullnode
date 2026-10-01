//! The input layout and the public output digest (Task 4 of the M4.3 plan): everything between the
//! machine's `READ_INPUT`/`WRITE_OUTPUT` syscalls and the interpreter. [`run_call`] is the whole
//! guest — decode the input vector, run, produce the eight output words — so the binary Task 5
//! commits is a wrapper around this one function.
//!
//! # The input vector
//!
//! `READ_INPUT` word indices, in order, byte strings packed 4 per word little-endian and
//! zero-padded, 256-bit values as their own eight little-endian limbs (so nothing is
//! byte-swapped), an address as its 20 bytes right-aligned in a 256-bit word:
//!
//! ```text
//! [n_code, code…, n_calldata, calldata…, address(8), caller(8), callvalue(8), gas_limit(1),
//!  pre_root(8), n_witnesses(1), witness…]        witness = [slot(8), value(8), sibling_0(8), …, sibling_31(8)]   (272 words)
//! ```
//!
//! # The public output
//!
//! `out0 = status` (1 success, 0 revert, 2 exceptional halt) and `out1..out7` = words 0..6 of
//!
//! ```text
//! hash(EVM_OUT, [codehash(8) ‖ pre_root(8) ‖ post_root(8) ‖ return_hash(8) ‖ logs_hash(8)])
//! ```
//!
//! — 40 words through the domain-tagged Poseidon2 sponge, a 224-bit binding of the contract, both
//! state roots, the return data and the logs. `codehash = keccak256(runtime bytecode)`,
//! `return_hash = keccak256(return data)`,
//! `logs_hash = keccak256(be32(n_logs) ‖ per log: be32(n_topics) ‖ topics as 32 big-endian bytes)`,
//! each 32-byte hash packed into eight words as `word[i] = LE(bytes[4i..4i+4])`.
//!
//! A status other than 1 binds `post_root = pre_root` and an **empty** log set, and a status of 2
//! binds empty return data as well — [`public_output`] is the one place that rule lives. The
//! interpreter's own [`Outcome`] still carries the logs a reverted run emitted (plan Ruling 3), so
//! a host test can see what the bytecode did; nothing but this module decides what is *bound*.
//!
//! # The guest pattern
//!
//! The whole run's state — the decoded input (46 KiB: code, calldata, the witness tree) and the
//! interpreter's working arrays (100 KiB) — is one [`Workspace`], which the guest keeps in `.bss`
//! and lends out. Nothing here is ever a stack local: the guest's stack is 64 KiB
//! (`guest-sdk/guest.ld`) and a `Workspace` is more than twice that.
//!
//! ```ignore
//! static mut W: Workspace = Workspace::ZERO;          // all-zero, so `.bss`: no image bytes
//!
//! #[no_mangle]
//! pub extern "C" fn main() -> ! {
//!     let w = unsafe { &mut *core::ptr::addr_of_mut!(W) };
//!     // `u32::MAX` is the honest bound: a READ_INPUT past the `n_in` committed to `H_IN` is
//!     // unsatisfiable in-circuit (M4.1), so a truncated vector yields *no proof at all* rather
//!     // than a short read — fail-closed, and the machine is the length check. See `InputCursor`.
//!     let out = run_call(&mut Syscalls, w, guest_sdk::read_input, u32::MAX);
//!     for (slot, word) in out.iter().enumerate() {
//!         guest_sdk::write_output(slot as u32, *word);
//!     }
//!     guest_sdk::halt()
//! }
//! ```

use crate::interp::{
    Buffers, Env, Halt, Interpreter, Log, Outcome, MAX_CALLDATA_BYTES, MAX_CODE_BYTES, MAX_LOGS,
    MAX_RETURN_BYTES, MAX_TOPICS,
};
use crate::storage::{StorageError, StorageTree, Witness, EVM_OUT_DOMAIN, MAX_WITNESSES};
use crate::u256::U256;
use crate::{dhash, keccak256, Host};

/// Words in the public-output digest's preimage: five 8-word hashes and roots.
const OUT_WORDS: usize = 40;

/// The most bytes [`logs_hash`] hashes: `be32(n_logs)` plus, per log, `be32(n_topics)` and four
/// 32-byte topics.
const LOGS_MAX_BYTES: usize = 4 + MAX_LOGS * (4 + MAX_TOPICS * 32);

/// Why an input vector is not a call. Every one of these is status 2 with the canonical malformed
/// output ([`run_call`]); none of them is a panic, because every length involved is
/// prover-supplied and a panicking guest aborts without producing a proof at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// The vector ends before the layout does — including a `n_witnesses` that overruns it.
    Truncated,
    /// `n_code` above [`MAX_CODE_BYTES`] (EIP-170).
    CodeTooLong,
    /// `n_calldata` above [`MAX_CALLDATA_BYTES`].
    CalldataTooLong,
    /// `n_witnesses` above [`MAX_WITNESSES`].
    TooManyWitnesses,
    /// Two witnesses claim one leaf position (`StorageError::DuplicateIndex`): the same slot
    /// twice, or two slots ground into one 32-bit index. `storage`'s module doc says why this has
    /// to be refused here rather than tolerated.
    DuplicateWitnessIndex,
}

/// Reads the input vector through a `read(idx) -> u32` closure, so the same code runs on the host
/// (over a slice) and in the guest (over the `READ_INPUT` syscall).
///
/// `len` is how many words the reader can supply. A read at or past it is **not** attempted — the
/// closure is never called out of range — and sets the truncation flag instead, which
/// [`decode_input`] turns into [`ParseError::Truncated`].
///
/// In the guest `len` is `u32::MAX`, and that is a bound, not a missing one: since M4.1 every
/// `READ_INPUT` is bound to the proof's `H_IN` commitment over the *whole* input vector, and an
/// index at or past the committed `n_in` is **unsatisfiable in-circuit** — no witness makes such a
/// row's constraints hold (`guest-sdk/src/lib.rs`'s `read_input` doc comment;
/// `research/src/tables/cpu.rs`'s indigest/`INPUT_READ` rules). So a prover who truncates the
/// vector cannot produce a proof at all, which is fail-closed: the failure is "no proof", never "a
/// proof of a call that read zeros". The host is the case that needs `len`, where the reader is a
/// slice and a short vector has to become a [`ParseError`] rather than a panic.
pub struct InputCursor<F: FnMut(u32) -> u32> {
    read: F,
    pos: u32,
    len: u32,
    truncated: bool,
}

impl<F: FnMut(u32) -> u32> InputCursor<F> {
    pub fn new(read: F, len: u32) -> Self {
        InputCursor { read, pos: 0, len, truncated: false }
    }

    /// The next word, or 0 with the truncation flag set once the vector is exhausted.
    pub fn word(&mut self) -> u32 {
        if self.pos >= self.len {
            self.truncated = true;
            return 0;
        }
        let w = (self.read)(self.pos);
        self.pos += 1;
        w
    }

    /// The next eight words — a hash, a root or a sibling, in the machine's word order.
    pub fn word8(&mut self) -> [u32; 8] {
        let mut out = [0u32; 8];
        for w in out.iter_mut() {
            *w = self.word();
        }
        out
    }

    /// The next 256-bit value: eight words, least significant limb first.
    pub fn u256(&mut self) -> U256 {
        U256(self.word8())
    }

    /// The next byte string: a length word, then `ceil(n/4)` words unpacked little-endian into
    /// `out[..n]`. Returns `n`, or `None` when `n > out.len()` — a cap the caller maps to its own
    /// [`ParseError`], never a panic (the brief's sketch panicked; plan Ruling on parse errors).
    /// The four bytes of each word are written out one at a time rather than through a
    /// `copy_from_slice` of a 1..4-byte chunk: the slice copy compiles to a `memcpy` *call* per
    /// word in the guest, which cost ~29 cycles a byte — 37 489 cycles to decode the ERC-20's
    /// 1 296 bytes of code, a third of M4.3's first-cut budget (measurement in the plan's Task 5
    /// report). Explicit byte stores make it ~2. They cannot be word stores: `out`'s alignment is
    /// 1, and a misaligned store is a constraint violation in this machine (`docs/01-isa.md`).
    #[inline(never)]
    pub fn bytes(&mut self, out: &mut [u8]) -> Option<usize> {
        let n = self.word() as usize;
        if n > out.len() {
            return None;
        }
        let dst = &mut out[..n];
        let mut chunks = dst.chunks_exact_mut(4);
        for chunk in &mut chunks {
            let w = self.word();
            chunk[0] = w as u8;
            chunk[1] = (w >> 8) as u8;
            chunk[2] = (w >> 16) as u8;
            chunk[3] = (w >> 24) as u8;
        }
        let tail = chunks.into_remainder();
        if !tail.is_empty() {
            let w = self.word();
            for (k, byte) in tail.iter_mut().enumerate() {
                *byte = (w >> (8 * k)) as u8;
            }
        }
        Some(n)
    }

    /// Whether a read ran past the end of the vector.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Everything one call needs, decoded from the input layout: static buffers, no allocation. Part of
/// the guest's [`Workspace`], never a value on the stack (46 KiB).
///
/// `code[..code_len]` and `calldata[..calldata_len]` are the real bytes; whatever a previous call
/// left past those lengths is never read.
pub struct CallInput {
    pub code: [u8; MAX_CODE_BYTES],
    pub code_len: usize,
    pub calldata: [u8; MAX_CALLDATA_BYTES],
    pub calldata_len: usize,
    pub env: Env,
    pub pre_root: [u32; 8],
    pub storage: StorageTree,
}

impl CallInput {
    /// All zeros: an empty call, and a `const` so a `static` holding one lands in `.bss`.
    pub const ZERO: CallInput = CallInput {
        code: [0; MAX_CODE_BYTES],
        code_len: 0,
        calldata: [0; MAX_CALLDATA_BYTES],
        calldata_len: 0,
        env: Env {
            address: U256::ZERO,
            caller: U256::ZERO,
            callvalue: U256::ZERO,
            gas_limit: 0,
        },
        pre_root: [0; 8],
        storage: StorageTree::ZERO,
    };
}

/// All the static state one call needs: the decoded input and the interpreter's working buffers,
/// ~146 KiB in one place. The guest keeps exactly one in `.bss` (`static mut W: Workspace =
/// Workspace::ZERO;`) and passes `&mut` into [`run_call`]; a host test boxes one. Reusing a
/// workspace is sound — [`decode_input`] and `Interpreter::new` reset everything a new call must
/// not inherit — and `tests/evm_abi.rs` runs two calls through one workspace to prove it.
pub struct Workspace {
    pub input: CallInput,
    pub bufs: Buffers,
}

impl Workspace {
    pub const ZERO: Workspace = Workspace { input: CallInput::ZERO, bufs: Buffers::ZERO };
}

/// Decode the input vector into `dst`, in place. The host is needed because each witness's leaf
/// position is a Keccak of its slot (`StorageTree::push` caches it).
///
/// Refuses, rather than trusting, everything the layout leaves to the prover: a code or calldata
/// length above its cap, more than [`MAX_WITNESSES`] witnesses, two witnesses at one leaf position
/// (`storage`'s module doc: the both-empty collision would otherwise let the bound `post_root` and
/// the interpreter's own view come apart), and a vector that ends before the
/// layout does (which is also how a `n_witnesses` overrunning the vector shows up). The
/// interpreter refuses the two length caps a second time, from its own side
/// (`Interpreter::new`'s deferred halt): belt and braces on the one input a contract's own code
/// cannot bound.
pub fn decode_input<H: Host, F: FnMut(u32) -> u32>(
    h: &mut H,
    dst: &mut CallInput,
    c: &mut InputCursor<F>,
) -> Result<(), ParseError> {
    dst.code_len = c.bytes(&mut dst.code).ok_or(ParseError::CodeTooLong)?;
    dst.calldata_len = c.bytes(&mut dst.calldata).ok_or(ParseError::CalldataTooLong)?;
    dst.env = Env {
        address: c.u256(),
        caller: c.u256(),
        callvalue: c.u256(),
        gas_limit: c.word() as u64,
    };
    dst.pre_root = c.word8();
    let n = c.word() as usize;
    if n > MAX_WITNESSES {
        return Err(ParseError::TooManyWitnesses);
    }
    dst.storage.reset(dst.pre_root);
    for _ in 0..n {
        let w = Witness {
            slot: c.u256(),
            value: c.u256(),
            siblings: core::array::from_fn(|_| c.word8()),
            verified: false,
        };
        // `n <= MAX_WITNESSES` was checked above, so `TooMany` cannot happen; the reachable
        // rejection is a second witness at a leaf position already taken.
        match dst.storage.push(h, w) {
            Ok(()) => {}
            Err(StorageError::DuplicateIndex) => return Err(ParseError::DuplicateWitnessIndex),
            Err(_) => return Err(ParseError::TooManyWitnesses),
        }
    }
    // Checked once, at the end. Nothing above branches on anything but a length, and a read past
    // the end yields zero, so a truncated vector can only have produced *shorter* fields — never a
    // misread one — and there is no need to test the flag after every field.
    if c.truncated() {
        return Err(ParseError::Truncated);
    }
    Ok(())
}

/// `word[i] = LE(bytes[4i..4i+4])` — how a 32-byte Keccak digest enters a sponge message, the
/// packing `guest_sdk::keccak256`'s test guest uses.
pub fn hash_words(h: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|i| u32::from_le_bytes([h[4 * i], h[4 * i + 1], h[4 * i + 2], h[4 * i + 3]]))
}

/// `keccak256(be32(n_logs) ‖ per log: be32(n_topics) ‖ topics as 32 big-endian bytes each)` — the
/// data of a log is dropped (the plan's ruling), only its topics are bound.
///
/// **An outcome that is not a success hashes the empty log set** (`be32(0)`), whatever the
/// interpreter recorded: a reverted or halted call changes nothing, so it publishes nothing. The
/// interpreter deliberately keeps those logs in its `Outcome` (plan Ruling 3) and this is where
/// they are dropped.
pub fn logs_hash<H: Host>(h: &mut H, o: &Outcome) -> [u8; 32] {
    let n = if o.status() == 1 { o.n_logs } else { 0 };
    let mut msg = [0u8; LOGS_MAX_BYTES];
    let mut p = 0;
    msg[p..p + 4].copy_from_slice(&(n as u32).to_be_bytes());
    p += 4;
    for log in o.logs.iter().take(n) {
        msg[p..p + 4].copy_from_slice(&(log.n_topics as u32).to_be_bytes());
        p += 4;
        for topic in log.topics.iter().take(log.n_topics as usize) {
            msg[p..p + 32].copy_from_slice(&topic.to_be_bytes());
            p += 32;
        }
    }
    keccak256(h, &msg[..p])
}

/// The eight public output words: `out[0] = status`, `out[1..8]` = words 0..6 of
/// `hash(EVM_OUT, [codehash ‖ pre_root ‖ post_root ‖ return_hash ‖ logs_hash])`.
///
/// The **one** place the status rules are applied, so no caller can publish a digest that claims a
/// state change a failed call did not make: a status other than 1 binds `post_root = pre_root` (the
/// `post_root` argument is then ignored, and [`run_call`] simply hands over whatever root the run
/// left behind) and an empty log set; a status of 2 binds empty return data as well, a status of 0
/// the revert data.
pub fn public_output<H: Host>(
    h: &mut H,
    code: &[u8],
    pre_root: &[u32; 8],
    post_root: &[u32; 8],
    o: &Outcome,
) -> [u32; 8] {
    let status = o.status();
    let post = if status == 1 { post_root } else { pre_root };
    let ret: &[u8] = if status == 2 { &[] } else { &o.ret[..o.ret_len] };
    let mut msg = [0u32; OUT_WORDS];
    msg[0..8].copy_from_slice(&hash_words(&keccak256(h, code)));
    msg[8..16].copy_from_slice(pre_root);
    msg[16..24].copy_from_slice(post);
    msg[24..32].copy_from_slice(&hash_words(&keccak256(h, ret)));
    msg[32..40].copy_from_slice(&hash_words(&logs_hash(h, o)));
    let d = dhash(h, EVM_OUT_DOMAIN, &msg);
    let mut out = [0u32; 8];
    out[0] = status;
    out[1..8].copy_from_slice(&d[..7]);
    out
}

/// The whole guest: decode the input vector, run the call, produce the eight public output words.
///
/// Nothing large is constructed here — the input and the interpreter's buffers are `w`'s, and the
/// `Interpreter` itself borrows them — so this runs in a small frame on the guest's 64 KiB stack.
/// See the module docs for the `static mut` pattern and for what `len` means.
pub fn run_call<H: Host, F: FnMut(u32) -> u32>(
    h: &mut H,
    w: &mut Workspace,
    read: F,
    len: u32,
) -> [u32; 8] {
    run_call_with(h, w, read, len).0
}

/// [`run_call`] plus the [`Outcome`] behind the digest, and leaving the post-state
/// [`StorageTree`] in `w.input.storage` — what a host test needs to check the output against its
/// own idea of the call (`EvmCall::expected`). The guest uses [`run_call`].
pub fn run_call_with<H: Host, F: FnMut(u32) -> u32>(
    h: &mut H,
    w: &mut Workspace,
    read: F,
    len: u32,
) -> ([u32; 8], Outcome) {
    let mut c = InputCursor::new(read, len);
    if decode_input(h, &mut w.input, &mut c).is_err() {
        // A vector that does not parse is not a call, so there is nothing to bind: the output is
        // the one canonical malformed value — status 2 over no code, a zero pre-root and post-root,
        // no return data and no logs. A verifier recomputing the digest from the contract and root
        // it meant to run gets something else and rejects the proof, which is the right answer to a
        // prover-supplied vector that is not even well formed (as against a well-formed call that
        // halts, whose status-2 output a chain can accept as "nothing happened").
        let o = Outcome {
            halt: Halt::OutOfBounds,
            gas_used: 0,
            ret: [0; MAX_RETURN_BYTES],
            ret_len: 0,
            logs: [Log::EMPTY; MAX_LOGS],
            n_logs: 0,
        };
        let out = public_output(h, &[], &[0; 8], &[0; 8], &o);
        return (out, o);
    }
    let i = &mut w.input;
    let o = Interpreter::new(
        h,
        &i.code[..i.code_len],
        &i.calldata[..i.calldata_len],
        i.env,
        &mut i.storage,
        &mut w.bufs,
    )
    .run();
    // The interpreter's tree is the post-state root of a call that succeeded. A revert or an
    // exceptional halt binds the *pre*-state root instead, however far the tree moved before the
    // failure — `public_output` is the single place that rule is applied, so the root handed over
    // here is simply whatever the run left behind.
    let out = public_output(h, &i.code[..i.code_len], &i.pre_root, &i.storage.root(), &o);
    (out, o)
}

// ---- The executor path (`evm2rv`) ----------------------------------------------------------
//
// Everything below is new code that the interpreter's guest never calls, appended *after* the
// interpreter's path rather than woven into it, and the module docs above are left as they were:
// the `evm` guest's image embeds this file's source lines (each bounds-check panic location), so
// moving any line above this point moves the pinned `bin/evm.bin` with no code change at all —
// measured: a twelve-line module-doc addition at the top did exactly that.
//
// The executor path takes the interpreter's input vector exactly — no extra words. The environment
// values the interpreter lacks are not inputs at all: a `READ_INPUT` word is bound only to the
// salted `H_IN`, which a verifier cannot open, so it cannot carry a chain fact (a timestamp, a
// chain id) a prover could not forge. `evm2rv` bakes `CHAINID` into the translated code (bound by
// the image hash), reads `ORIGIN` as `CALLER`, and traps on the rest as the interpreter does.

/// What runs the decoded call in place of the interpreter: given the host, the code, the calldata,
/// the environment, the witness tree and the working buffers, produce the [`Outcome`]. It must
/// leave the post-state in the tree, as the interpreter does — the public output binds
/// `tree.root()` after it returns.
pub type Executor<'a, H> =
    &'a mut dyn FnMut(&mut H, &[u8], &[u8], Env, &mut StorageTree, &mut Buffers) -> Outcome;

/// [`run_call_with`] with the interpreter replaced by `exec`: decode the same input vector, run
/// `exec` over it, and produce the eight public output words by the same [`public_output`] rules
/// (the code hash in `EVM_OUT` is the hash of the vector's code, as for the interpreter). With
/// `Interpreter::new(h, code, calldata, env, tree, bufs).run()` as `exec` the result is exactly
/// [`run_call_with`]'s.
///
/// A vector that does not parse never reaches `exec` and gives the canonical malformed output, as
/// in [`run_call_with`].
///
/// This is `evm2rv`'s entry point: a translated contract's shim calls it with the compiled code as
/// the executor. The interpreter's guest calls [`run_call`], and [`run_call_with`] is deliberately
/// left as it was rather than rewritten over this function, so the pinned `evm` image is untouched.
pub fn run_call_with_executor<H: Host, F: FnMut(u32) -> u32>(
    h: &mut H,
    w: &mut Workspace,
    read: F,
    len: u32,
    exec: Executor<'_, H>,
) -> ([u32; 8], Outcome) {
    let mut c = InputCursor::new(read, len);
    if decode_input(h, &mut w.input, &mut c).is_err() {
        return malformed(h);
    }
    let i = &mut w.input;
    let o = exec(
        h,
        &i.code[..i.code_len],
        &i.calldata[..i.calldata_len],
        i.env,
        &mut i.storage,
        &mut w.bufs,
    );
    let out = public_output(h, &i.code[..i.code_len], &i.pre_root, &i.storage.root(), &o);
    (out, o)
}

/// The canonical malformed output and its outcome — [`run_call_with`]'s parse-failure branch,
/// repeated here for [`run_call_with_executor`] rather than shared, so the interpreter's function
/// (and the pinned image built from it) stays exactly as it was.
fn malformed<H: Host>(h: &mut H) -> ([u32; 8], Outcome) {
    let o = Outcome {
        halt: Halt::OutOfBounds,
        gas_used: 0,
        ret: [0; MAX_RETURN_BYTES],
        ret_len: 0,
        logs: [Log::EMPTY; MAX_LOGS],
        n_logs: 0,
    };
    let out = public_output(h, &[], &[0; 8], &[0; 8], &o);
    (out, o)
}
