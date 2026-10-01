//! The input layout and the public output digest: everything between the machine's
//! `READ_PUBLIC`/`READ_INPUT`/`WRITE_OUTPUT` syscalls and the interpreter. [`run_call`] is the
//! whole guest — decode the two input vectors, load, run, produce the eight output words — so the
//! committed binary is a wrapper around this one function.
//!
//! # The two input vectors
//!
//! The ELF is **public** and the instruction is **private**, so the call arrives on two tapes —
//! `READ_PUBLIC` word indices and `READ_INPUT` word indices — each byte string packed four per
//! word little-endian and zero-padded:
//!
//! ```text
//! public:  [n_elf, elf bytes…]
//! private: [n_input, input bytes…]
//! ```
//!
//! # The public output
//!
//! `out0 = status` and `out1..out7` = words 0..6 of
//!
//! ```text
//! hash(SBPF_OUT, [input_hash(8) ‖ output_hash(8)])
//! ```
//!
//! — 16 words through the domain-tagged Poseidon2 sponge, a 224-bit binding of the instruction the
//! program was given and the state it left behind. **There is no `program_hash`**: the ELF is in
//! the public segment, so the proof's unsalted `H_PUB` already binds it word for word and the chain
//! checks that digest against the ELF it published (`Machine::verify_public`) — hashing the ELF a
//! second time in-circuit bought nothing and cost 1 698 SHA-256 compressions.
//!
//! `input_hash` is [`canonical_input_hash`] over the instruction — the unpadded encoding of spec
//! §9.4, not `sha256` of the aligned region, whose 10 240 bytes of realloc headroom per account
//! were 98 % of what was hashed. What the encoding leaves out, [`check_region`] pins to a fixed
//! value at entry — zero for the padding, `{0, 1}` for the flag bytes — so every byte the running
//! program can read is either hashed or pinned.
//! `output_hash` is [`output_hash`] over the accounts. The account list's *shape* is bound too: the
//! preimage carries each entry's raw marker byte, so a duplicate entry and a repeated full entry
//! are different calls even when every account field matches. Each
//! 32-byte digest is packed into eight words as `word[i] = LE(bytes[4i..4i+4])`, and both go
//! through the chip, which is what puts the SHA-256 table on the exit test's own path.
//!
//! The status word is the plan's: `1` = the program returned `r0 == 0`, `0` = it returned something
//! else (a `ProgramError`, whose code is *not* published — the seven digest words are spoken for),
//! `2` = an exceptional halt. A status other than 1 binds the **pre**-state as the output hash:
//! nothing happened. [`run_call_with`] is the one place that rule lives, and it enforces it by
//! hashing the account region once before the run and reusing that digest, so a failed run cannot
//! publish a state change it made part-way through and then abandoned.
//!
//! # The guest pattern
//!
//! The whole run's state — the decoded input (304 KiB) plus the 32 KiB stack and 32 KiB heap — is
//! one [`Workspace`], which the guest keeps in `.bss` and lends out. Nothing here is ever a stack
//! local: the guest's stack is 64 KiB (`guest-sdk/guest.ld`) and a `Workspace` is five times that.
//! This crate is `#![forbid(unsafe_code)]`, so the `static mut` cell is the guest binary's (M4.3's
//! `evm` guest does the same):
//!
//! ```ignore
//! static mut W: Workspace = Workspace::ZERO;          // all-zero, so `.bss`: no image bytes
//!
//! #[no_mangle]
//! pub extern "C" fn main() -> ! {
//!     let w = unsafe { &mut *core::ptr::addr_of_mut!(W) };
//!     // A read past either segment's committed length is unsatisfiable in-circuit (M4.1's `H_IN`,
//!     // and `H_PUB`), so the machine is the bound on both and `u32::MAX` is the honest `len` for
//!     // each.
//!     let out = run_call(
//!         &mut Syscalls,
//!         w,
//!         guest_sdk::read_public,
//!         u32::MAX,
//!         guest_sdk::read_input,
//!         u32::MAX,
//!     );
//!     for (slot, word) in out.iter().enumerate() {
//!         guest_sdk::write_output(slot as u32, *word);
//!     }
//!     guest_sdk::halt()
//! }
//! ```

use crate::elf;
use crate::interp::{Halt, Vm};
use crate::memory::{Memory, HEAP_BYTES, STACK_BYTES};
use crate::{dhash, hash_words, Host, Sha256};

/// The largest ELF the public vector may carry (the plan's number).
pub const MAX_ELF_BYTES: usize = 262_144;
/// The largest serialized instruction the private vector may carry.
///
/// **Measured, not the plan's 16 KiB** (Task 6). The aligned format leaves
/// [`MAX_PERMITTED_DATA_INCREASE`] = 10 240 bytes of realloc headroom after *every* account's data,
/// and the entrypoint's deserializer skips exactly that much unconditionally, so it cannot be
/// trimmed: an account costs ~10 336 bytes plus its data whatever the data is. The plan's own exit
/// test — an SPL Token `Transfer`, three accounts — is 31 401 bytes, so 16 384 could not have held
/// it. 49 152 (48 KiB) holds four accounts (41 825 bytes for a Transfer plus the mint) with room
/// over. The cap costs `.bss` only: `decode_input` copies `n_input` bytes and the interpreter is
/// handed `input[..input_len]`, so a generous cap is not a cycle.
pub const MAX_INPUT_BYTES: usize = 49_152;
/// `notes::domain::SBPF_OUT`, mirrored here so the guest and the host agree without a dependency.
pub const SBPF_OUT_DOMAIN: u32 = 14;

/// Accounts a call may carry. Solana's own per-transaction limit is 64; a serialized input claiming
/// more is **refused** at entry ([`check_region`]) rather than clamped, so the count the digest
/// carries is always the count that was walked. The walks themselves still stop here, because
/// [`output_hash`] must stay total over a post-state region the program may have scribbled on.
pub const MAX_ACCOUNTS: usize = 64;

/// Bytes of realloc headroom the aligned format leaves after every account's data
/// (`solana_program::entrypoint::MAX_PERMITTED_DATA_INCREASE`).
pub const MAX_PERMITTED_DATA_INCREASE: usize = 10_240;

/// The marker byte of an account that is not a duplicate of an earlier one.
const NON_DUP_MARKER: u8 = 0xff;

/// Words in the public-output digest's preimage: two eight-word SHA-256 digests.
const OUT_WORDS: usize = 16;

/// Why a pair of input vectors is not a call. Every one of these is status 2 with the canonical
/// malformed output ([`run_call_with`]); none is a panic, because every length involved is
/// prover-supplied and a panicking guest aborts without producing a proof at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// One of the two vectors ends before its layout does.
    Truncated,
    /// `n_elf` above [`MAX_ELF_BYTES`].
    ElfTooLong,
    /// `n_input` above [`MAX_INPUT_BYTES`].
    InputTooLong,
    /// The instruction region is not the canonical aligned encoding the Solana runtime produces:
    /// an account count above [`MAX_ACCOUNTS`], a non-zero byte where the runtime guarantees zeros
    /// (the `original_data_len` slot, the realloc headroom, the alignment padding, a duplicate
    /// entry's seven padding bytes), an account list that does not walk to its own end, or a tail
    /// that is not exactly `instruction_data_len ‖ instruction data ‖ program_id`. See
    /// [`check_region`].
    MalformedRegion,
}

/// Reads one input vector through a `read(idx) -> u32` closure, so the same code runs on the host
/// (over a slice) and in the guest (over the `READ_PUBLIC` or `READ_INPUT` syscall). A call has one
/// cursor per segment: the public one carries the ELF, the private one the instruction.
///
/// `len` is how many words the reader can supply. A read at or past it is **not** attempted — the
/// closure is never called out of range — and sets the truncation flag instead. In the guest `len`
/// is `u32::MAX` for both: a read beyond the length committed to `H_IN` (private) or `H_PUB`
/// (public) cannot be satisfied by any witness, so the machine refuses an overrun before this ever
/// could.
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

    /// The next byte string: a length word, then `ceil(n/4)` words unpacked little-endian into
    /// `out[..n]`. Returns `n`, or `None` when `n > out.len()` — a cap the caller maps to its own
    /// [`ParseError`], and which is checked *before* any word of the string is read, so an absurd
    /// length costs nothing.
    ///
    /// The whole-word bulk is split from the 1–3 byte tail so the copy's width is a **constant** 4:
    /// a `copy_from_slice` whose length is only known at run time compiles to a
    /// `compiler_builtins::mem::memcpy` call on `riscv32im`, and its byte-at-a-time loop costs
    /// ~9.5 cycles a byte. Reading the SPL Token exit test's 37 609-word vector through the old
    /// single loop took 978 000 cycles, 25 % of the whole run (`docs/04-guests.md`).
    pub fn bytes(&mut self, out: &mut [u8]) -> Option<usize> {
        let n = self.word() as usize;
        if n > out.len() {
            return None;
        }
        let full = n / 4;
        for i in 0..full {
            let w = self.word().to_le_bytes();
            out[4 * i..4 * i + 4].copy_from_slice(&w);
        }
        let rest = n - 4 * full;
        if rest != 0 {
            let w = self.word().to_le_bytes();
            out[4 * full..n].copy_from_slice(&w[..rest]);
        }
        Some(n)
    }

    /// Whether a read ran past the end of the vector.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// One call's decoded input: the ELF and the serialized instruction, in static buffers. Part of the
/// guest's [`Workspace`], never a value on the stack (304 KiB).
pub struct CallInput {
    pub elf: [u8; MAX_ELF_BYTES],
    pub elf_len: usize,
    pub input: [u8; MAX_INPUT_BYTES],
    pub input_len: usize,
}

impl CallInput {
    /// All zeros: an empty call, and a `const` so a `static` holding one lands in `.bss`.
    pub const ZERO: CallInput = CallInput {
        elf: [0; MAX_ELF_BYTES],
        elf_len: 0,
        input: [0; MAX_INPUT_BYTES],
        input_len: 0,
    };
}

/// All the static state one call needs: the decoded input, the sBPF stack and the sBPF heap — about
/// 368 KiB in one place. The guest keeps exactly one in `.bss` and passes `&mut` into [`run_call`];
/// a host test boxes one. Reusing a workspace is sound: [`decode_input`] resets the two lengths and
/// [`run_call_with`] zeroes the stack and heap, so nothing carries over from a previous call.
pub struct Workspace {
    pub input: CallInput,
    pub stack: [u8; STACK_BYTES],
    pub heap: [u8; HEAP_BYTES],
}

impl Workspace {
    pub const ZERO: Workspace =
        Workspace { input: CallInput::ZERO, stack: [0; STACK_BYTES], heap: [0; HEAP_BYTES] };
}

/// Decodes the two input vectors into `dst`, in place — the ELF from the **public** cursor, the
/// serialized instruction from the **private** one.
///
/// Refuses, rather than trusting, everything either layout leaves to the prover: either length
/// above its cap, and a vector that ends before its layout does. Checked once at the end, as
/// M4.3's `decode_input` is: nothing here branches on anything but a length and a read past the end
/// yields zero, so a truncated vector can only have produced *shorter* fields, never misread ones.
/// Truncation of *either* segment is the same `Truncated`: neither vector is a call without the
/// other.
pub fn decode_input<FP: FnMut(u32) -> u32, FS: FnMut(u32) -> u32>(
    dst: &mut CallInput,
    elf_c: &mut InputCursor<FP>,
    in_c: &mut InputCursor<FS>,
) -> Result<(), ParseError> {
    dst.elf_len = 0;
    dst.input_len = 0;
    dst.elf_len = elf_c.bytes(&mut dst.elf).ok_or(ParseError::ElfTooLong)?;
    dst.input_len = in_c.bytes(&mut dst.input).ok_or(ParseError::InputTooLong)?;
    if elf_c.truncated() || in_c.truncated() {
        return Err(ParseError::Truncated);
    }
    // Refuse, rather than hash around, a region that is not the canonical aligned encoding: see
    // [`check_region`] for why every byte of it has to be either hashed or pinned to zero.
    check_region(&dst.input[..dst.input_len])
}

/// One account entry's offsets inside the serialized region, as [`AccountWalk`] resolves them: a
/// duplicate entry carries the offsets of the account it duplicates, so nothing downstream has to
/// know which kind of entry it came from. `owner` immediately follows `key`.
#[derive(Clone, Copy)]
struct Entry {
    /// The byte the entry physically carries at its own offset: [`NON_DUP_MARKER`] for a full
    /// entry, the duplicated entry's ordinal for a duplicate. It belongs to the **position**, not
    /// to the account, so a duplicate's copy carries its own marker rather than the original's —
    /// which is the whole point of hashing it: `[A, A_dup(0)]` and a region with two full entries
    /// of `A` hand the program different aliasing (one shared buffer versus two) while every
    /// account field is identical.
    marker: u8,
    /// `is_signer`, `is_writable`, `executable` — three consecutive bytes.
    flags_at: usize,
    /// `key` (32 bytes), immediately followed by `owner` (32 bytes).
    key_at: usize,
    lamports: u64,
    data_at: usize,
    data_len: usize,
    /// The account's `rent_epoch`, which sits after the realloc headroom and the alignment padding.
    /// A running program reads it through its `AccountInfo`, so the canonical preimage binds it.
    rent_epoch: u64,
}

const ZERO_ENTRY: Entry = Entry {
    marker: 0,
    flags_at: 0,
    key_at: 0,
    lamports: 0,
    data_at: 0,
    data_len: 0,
    rent_epoch: 0,
};

/// The one walk over the *aligned* serialized-instruction format
/// (`solana_program::entrypoint::deserialize`'s layout). [`output_hash`] and
/// [`canonical_input_hash`] both drive it and differ only in which fields they hash, so the two can
/// never drift on how a duplicate entry resolves — which is the part that is easy to get silently
/// wrong.
///
/// A duplicate's marker byte is an index into **all** entries seen so far, duplicates included —
/// the same index space `deserialize` pushes into, since it does
/// `accounts.push(accounts[dup_info].clone())` over a `Vec` that already holds its own duplicates
/// (and so does this crate's host twin, `rand_zkvm::sbpf::deserialize_accounts`). Indexing anything
/// else silently reads the wrong account: `[A, A, B, C, B]`'s last entry carries the byte 2, which
/// is `B` among all entries but `C` among the non-duplicate ones.
///
/// Total by construction: a region that is not a serialized instruction, or that ends before its
/// own account count does, yields the prefix the walk got through and then stops for good
/// ([`AccountWalk::end`] returns `None`, so no caller mistakes the stopping point for the start of
/// the instruction data). Totality is what lets [`output_hash`] run over a *post*-state the program
/// has scribbled on; the entry-time refusals live in [`check_region`], not here.
struct AccountWalk<'a> {
    input: &'a [u8],
    off: usize,
    /// Entries still to produce: the region's own count, clamped at [`MAX_ACCOUNTS`] so the walk
    /// stays total. A region claiming more than that is *refused* by [`check_region`] before any of
    /// this runs — the clamp is a bound on the loop, never a reinterpretation of the count.
    left: usize,
    /// Where each entry's fields sit, indexed by its **entry ordinal** — duplicates included.
    seen: [Entry; MAX_ACCOUNTS],
    n_entries: usize,
    stopped: bool,
    /// Whether to check the bytes the runtime guarantees are zero. Only [`check_region`] asks for
    /// it: the scan is ~41 KB for a four-account region and the two hashing walks must not pay it.
    check_pinned: bool,
    /// Set when a checking walk saw a byte the format does not admit: a non-zero where it pins a
    /// zero, or a flag byte above 1. The walk does not stop on it — the flag is the answer, so a
    /// caller that does not care is not affected.
    pinned_invalid: bool,
}

impl<'a> AccountWalk<'a> {
    /// The walk and the region's **exact** account count, as its own `u64` — not clamped. Read in
    /// `u64` because on the 32-bit target a count above `u32::MAX` would otherwise truncate into a
    /// small, plausible-looking number instead of being seen for what it is.
    fn new(input: &'a [u8]) -> (Self, u64) {
        Self::with_checking(input, false)
    }

    fn with_checking(input: &'a [u8], check_pinned: bool) -> (Self, u64) {
        let (off, claimed) = match read_u64(input, 0) {
            Some(n) => (8, n),
            None => (0, 0),
        };
        let w = AccountWalk {
            input,
            off,
            left: core::cmp::min(claimed, MAX_ACCOUNTS as u64) as usize,
            seen: [ZERO_ENTRY; MAX_ACCOUNTS],
            n_entries: 0,
            stopped: off == 0,
            check_pinned,
            pinned_invalid: false,
        };
        (w, claimed)
    }

    /// The next entry, or `None` once the count is exhausted or the region stops making sense.
    fn next(&mut self) -> Option<Entry> {
        if self.stopped || self.left == 0 {
            return None;
        }
        match self.step() {
            Some(e) => {
                self.left -= 1;
                Some(e)
            }
            None => {
                self.stopped = true;
                None
            }
        }
    }

    fn step(&mut self) -> Option<Entry> {
        let input = self.input;
        let off = self.off;
        let dup = *input.get(off)?;
        let entry = if dup == NON_DUP_MARKER {
            // marker, is_signer, is_writable, executable, then four bytes of `original_data_len`.
            let flags_at = off + 1;
            let key_at = off + 8;
            let lamports_at = key_at + 64;
            let data_len_at = lamports_at + 8;
            let lamports = read_u64(input, lamports_at)?;
            let data_len = usize::try_from(read_u64(input, data_len_at)?).ok()?;
            let data_at = data_len_at + 8;
            let data_end = data_at.checked_add(data_len)?;
            if data_end > input.len() {
                return None;
            }
            // The realloc headroom, then padding to the next eight-byte boundary, then
            // `rent_epoch`.
            let after = (data_end.checked_add(MAX_PERMITTED_DATA_INCREASE)?.checked_add(7)?) & !7;
            let rent_epoch = read_u64(input, after)?;
            if self.check_pinned {
                // The `original_data_len` slot and the realloc headroom plus the alignment padding:
                // bytes the runtime writes as zeros and nothing hashes.
                //
                // Pinning the `original_data_len` slot to zero is right for an *input* region:
                // agave's aligned serializer writes four zero bytes there, and it is the
                // program-side entrypoint deserializer that later stores `original_data_len` into
                // that slot — inside the guest's own memory, after the digest is taken. Nothing
                // hands the guest a region with it already filled in (the host serializer writes
                // zeros for exactly the same reason).
                self.check_zeros(off + 4, off + 8);
                self.check_zeros(data_end, after);
                // The three flag bytes are booleans: the format admits 0 and 1, the program reads
                // the raw byte, and the preimage hashes the normalised one — so anything else is
                // refused rather than normalised away.
                self.check_bools(flags_at, flags_at + 3);
            }
            self.off = after.checked_add(8)?;
            Entry { marker: dup, flags_at, key_at, lamports, data_at, data_len, rent_epoch }
        } else {
            // A duplicate: the index, then seven bytes of padding, and nothing else.
            if dup as usize >= self.n_entries {
                return None;
            }
            let mut entry = *self.seen.get(dup as usize)?;
            // The marker belongs to this position, not to the account being duplicated — including
            // when the entry it points at is itself a duplicate.
            entry.marker = dup;
            if self.check_pinned {
                self.check_zeros(off + 1, off + 8);
            }
            self.off = off + 8;
            entry
        };
        // Every entry is recorded at its own ordinal, so a later duplicate of a duplicate lands on
        // the same account either way.
        if self.n_entries < MAX_ACCOUNTS {
            self.seen[self.n_entries] = entry;
        }
        self.n_entries += 1;
        Some(entry)
    }

    /// The offset just past the last account entry — where `instruction_data_len` begins — or
    /// `None` if the walk stopped early or has not finished.
    fn end(&self) -> Option<usize> {
        if self.stopped || self.left != 0 {
            None
        } else {
            Some(self.off)
        }
    }

    /// Records whether every byte of `input[from..to]` is 0 or 1.
    fn check_bools(&mut self, from: usize, to: usize) {
        if let Some(bytes) = self.input.get(from..to) {
            for &b in bytes {
                if b > 1 {
                    self.pinned_invalid = true;
                }
            }
        }
    }

    /// Records whether `input[from..to]` is all zeros.
    ///
    /// Four bytes per iteration, ORed together rather than compared, so the loop is branch-free and
    /// pays its increment and test once per four bytes instead of once per byte — this scan covers
    /// ~41 KB for a four-account region, so its constant is the whole cost of the zero-pinning. It
    /// cannot use a wider *load*: the run starts at an offset the format does not align and
    /// `#![forbid(unsafe_code)]` rules out the realignment that would need.
    fn check_zeros(&mut self, from: usize, to: usize) {
        if let Some(bytes) = self.input.get(from..to) {
            let mut acc = 0u8;
            let mut chunks = bytes.chunks_exact(4);
            for c in &mut chunks {
                acc |= c[0] | c[1] | c[2] | c[3];
            }
            for &b in chunks.remainder() {
                acc |= b;
            }
            if acc != 0 {
                self.pinned_invalid = true;
            }
        }
    }
}

/// Whether a serialized instruction region is the canonical aligned encoding — the entry-time
/// refusal `decode_input` applies, and the reason every byte of an accepted region is either hashed
/// by [`canonical_input_hash`] or pinned to a fixed value here.
///
/// The unhashed bytes matter because the *program* can read them: `original_data_len`, the realloc
/// headroom and the alignment padding are all inside the region `r1` points at, so a prover free to
/// choose them could change what an honest-looking run does while the verifier's recomputed
/// `input_hash` still matched. The Solana runtime writes them as zeros, so pinning them costs an
/// honest caller nothing and closes the gap without hashing 40 960 bytes of padding again.
///
/// Refused, each as `ParseError::MalformedRegion`:
///
/// * an account count above [`MAX_ACCOUNTS`] — **never clamped**, so the count the preimage carries
///   is always the count the walk produced;
/// * a non-zero byte in the `original_data_len` slot, the realloc headroom, the alignment padding,
///   or a duplicate entry's seven padding bytes;
/// * a flag byte (`is_signer`, `is_writable`, `executable`) above 1 — the program reads the raw
///   byte, the preimage hashes the normalised one, so the two are kept equal by refusing the rest;
/// * an account list that does not walk to its own end (a truncated or self-contradictory entry);
/// * a tail that is not exactly `u64 instruction_data_len ‖ instruction data ‖ program_id(32)`,
///   ending at the region's last byte — trailing bytes are readable by the program too.
pub fn check_region(input: &[u8]) -> Result<(), ParseError> {
    let (mut w, claimed) = AccountWalk::with_checking(input, true);
    if claimed > MAX_ACCOUNTS as u64 {
        return Err(ParseError::MalformedRegion);
    }
    while w.next().is_some() {}
    let end = w.end().ok_or(ParseError::MalformedRegion)?;
    if w.pinned_invalid {
        return Err(ParseError::MalformedRegion);
    }
    let n = usize::try_from(read_u64(input, end).ok_or(ParseError::MalformedRegion)?)
        .map_err(|_| ParseError::MalformedRegion)?;
    let region_end = end
        .checked_add(8)
        .and_then(|o| o.checked_add(n))
        .and_then(|o| o.checked_add(32))
        .ok_or(ParseError::MalformedRegion)?;
    if region_end != input.len() {
        return Err(ParseError::MalformedRegion);
    }
    Ok(())
}

/// An entry's `key ‖ owner`.
///
/// **Precondition**: `e` came from [`AccountWalk::next`] over this same `input`, which produced it
/// only after `read_u64(input, key_at + 64 + 8)` succeeded — so the 64 bytes are always in range
/// and the `&[]` fallback is unreachable. It is a fallback rather than an `unwrap` because a
/// panicking guest aborts without producing a proof at all, and every offset here began as a
/// prover-supplied length.
fn entry_key_owner<'a>(input: &'a [u8], e: &Entry) -> &'a [u8] {
    debug_assert!(e.key_at + 64 <= input.len(), "the walk bounds-checks past key ‖ owner");
    e.key_at.checked_add(64).and_then(|end| input.get(e.key_at..end)).unwrap_or(&[])
}

/// An entry's `data`, exactly `data_len` bytes and no realloc headroom.
///
/// **Precondition**: as [`entry_key_owner`] — the walk checked `data_at + data_len <= input.len()`
/// before producing `e`, so the `&[]` fallback is unreachable.
fn entry_data<'a>(input: &'a [u8], e: &Entry) -> &'a [u8] {
    debug_assert!(e.data_at + e.data_len <= input.len(), "the walk bounds-checks the data");
    e.data_at.checked_add(e.data_len).and_then(|end| input.get(e.data_at..end)).unwrap_or(&[])
}

/// An entry's three flag bytes, normalised to 0 or 1 — `deserialize` reads them as `!= 0`, and this
/// keeps the digest total over a region nobody checked. For an *accepted* region the normalised
/// byte equals the raw one, because [`check_region`] refuses a flag byte above 1.
fn entry_flags(input: &[u8], e: &Entry) -> [u8; 3] {
    let mut f = [0u8; 3];
    for (i, slot) in f.iter_mut().enumerate() {
        *slot = u8::from(input.get(e.flags_at + i).copied().unwrap_or(0) != 0);
    }
    f
}

/// `(instruction_data_len, instruction data)` at `end`, the offset the account walk finished at.
/// A claimed length the region cannot hold contributes the length and no bytes — the length is
/// hashed either way, so two regions that disagree about it cannot collide.
fn instruction_tail<'a>(input: &'a [u8], end: Option<usize>) -> (u64, &'a [u8]) {
    let Some(off) = end else { return (0, &[]) };
    let Some(n) = read_u64(input, off) else { return (0, &[]) };
    let start = off + 8; // `read_u64` succeeded, so this is within the region
    let data = usize::try_from(n)
        .ok()
        .and_then(|n| start.checked_add(n))
        .and_then(|e| input.get(start..e))
        .unwrap_or(&[]);
    (n, data)
}

/// `sha256(for each account in order: lamports ‖ data_len ‖ data)`, each integer eight
/// little-endian bytes — the plan's `output_hash`, over whatever state the serialized input region
/// holds when it is called. Covers every account, writable or not.
///
/// The walk is [`AccountWalk`]: a duplicate account entry re-hashes the account it duplicates, at
/// the position it occupies, and a region that stops making sense hashes the prefix the walk got
/// through. Both the pre- and the post-state digest of a run go through this same walk, so a
/// malformed region still binds consistently — and a well-formed one is exactly the documented
/// preimage.
pub fn output_hash<H: Host>(h: &mut H, input: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    let (mut w, _) = AccountWalk::new(input);
    while let Some(e) = w.next() {
        s.update(h, &e.lamports.to_le_bytes());
        s.update(h, &(e.data_len as u64).to_le_bytes());
        s.update(h, entry_data(input, &e));
    }
    s.finish(h)
}

/// `input_hash`: SHA-256 over the **canonical** encoding of the instruction (design spec §9.4), not
/// over the aligned region the program is handed.
///
/// ```text
/// program_id(32) ‖ u64 n_accounts
///   per entry, in entry order: marker(1) ‖ key(32) ‖ owner(32) ‖ u64 lamports ‖ u64 data_len
///                              ‖ data ‖ is_signer ‖ is_writable ‖ executable ‖ u64 rent_epoch
/// ‖ u64 instruction_data_len ‖ instruction data
/// ```
///
/// `marker` is the byte the entry physically carries — `0xff` for a full entry, the duplicated
/// entry's ordinal for a duplicate — so the *shape* of the account list is bound, not just its
/// contents: two entries that resolve to the same account fields alias one buffer if the second is
/// a duplicate and two buffers if it is not, and the program can tell.
///
/// The aligned region leaves [`MAX_PERMITTED_DATA_INCREASE`] = 10 240 bytes of realloc headroom
/// after every account's data; for the SPL Token `Transfer` fixture that is 40 960 of 41 825 bytes,
/// so 640 of 654 SHA-256 compressions hashed nothing but zeros. The canonical encoding is 837
/// bytes and 14 compressions for the same call.
///
/// Every length prefix is load-bearing rather than decoration: without `n_accounts` and the
/// per-field `data_len`/`instruction_data_len` the concatenation is ambiguous between different
/// account splits, and without the instruction data the digest would not bind the instruction at
/// all — for the fixture, not the amount transferred. `n_accounts` is the region's **exact** `u64`
/// count, never a clamped one: a region claiming more than [`MAX_ACCOUNTS`] is refused outright by
/// [`check_region`], so the count in the preimage is always the count the walk produced.
///
/// Together with [`check_region`]'s pinning, every byte of an accepted region is either in this
/// preimage or provably a fixed value — including `rent_epoch`, which a running program reads
/// through its `AccountInfo` and which nothing else binds. The three flag bytes are hashed
/// normalised to 0/1, which loses nothing because [`check_region`] refuses any other value.
///
/// The walk is [`output_hash`]'s, entry for entry, so the two digests can never disagree about
/// which account a duplicate entry means.
pub fn canonical_input_hash<H: Host>(h: &mut H, input: &[u8], program_id: &[u8; 32]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(h, program_id);
    let (mut w, n_accounts) = AccountWalk::new(input);
    s.update(h, &n_accounts.to_le_bytes());
    while let Some(e) = w.next() {
        s.update(h, &[e.marker]);
        s.update(h, entry_key_owner(input, &e));
        s.update(h, &e.lamports.to_le_bytes());
        s.update(h, &(e.data_len as u64).to_le_bytes());
        s.update(h, entry_data(input, &e));
        s.update(h, &entry_flags(input, &e));
        s.update(h, &e.rent_epoch.to_le_bytes());
    }
    let (n, data) = instruction_tail(input, w.end());
    s.update(h, &n.to_le_bytes());
    s.update(h, data);
    s.finish(h)
}

/// The program id the serialized region ends with — the caller of [`canonical_input_hash`] gets it
/// from here, because the id is part of the instruction and nothing else in the guest knows it.
/// All zeros if the region does not carry one, which is exactly the malformed case
/// [`canonical_input_hash`] is already total over.
pub fn program_id(input: &[u8]) -> [u8; 32] {
    program_id_opt(input).unwrap_or([0u8; 32])
}

fn program_id_opt(input: &[u8]) -> Option<[u8; 32]> {
    let (mut w, _) = AccountWalk::new(input);
    while w.next().is_some() {}
    let off = w.end()?;
    let n = usize::try_from(read_u64(input, off)?).ok()?;
    let at = off.checked_add(8)?.checked_add(n)?;
    let bytes = input.get(at..at.checked_add(32)?)?;
    let mut id = [0u8; 32];
    id.copy_from_slice(bytes);
    Some(id)
}

fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    Some(u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]))
}

/// The eight public output words: `out[0] = status`, `out[1..8]` = words 0..6 of
/// `hash(SBPF_OUT, [input_hash ‖ output_hash])`.
///
/// There is no `program_hash` in the preimage: the ELF is read from the public segment, so `H_PUB`
/// binds it and the chain checks that against the ELF it published.
pub fn public_output<H: Host>(
    h: &mut H,
    status: u32,
    input_hash: &[u8; 32],
    output_hash: &[u8; 32],
) -> [u32; 8] {
    let mut msg = [0u32; OUT_WORDS];
    msg[0..8].copy_from_slice(&hash_words(input_hash));
    msg[8..16].copy_from_slice(&hash_words(output_hash));
    let d = dhash(h, SBPF_OUT_DOMAIN, &msg);
    let mut out = [0u32; 8];
    out[0] = status;
    out[1..8].copy_from_slice(&d[..7]);
    out
}

/// The whole guest: decode the public and private input vectors, load the ELF, run it, produce the
/// eight public output words. See the module docs for the `static mut` pattern and for what the two
/// `len`s mean.
pub fn run_call<H: Host, FP: FnMut(u32) -> u32, FS: FnMut(u32) -> u32>(
    h: &mut H,
    ws: &mut Workspace,
    read_public: FP,
    n_public: u32,
    read_private: FS,
    n_private: u32,
) -> [u32; 8] {
    run_call_with(h, ws, read_public, n_public, read_private, n_private).0
}

/// [`run_call`] plus the interpreter's own outcome — what a host test needs to check the output
/// against its own idea of the call (`rand_zkvm::sbpf::SbpfCall::expected`). The post-state of the
/// accounts is left in `ws.input.input[..input_len]`, so a caller can deserialize it. The guest
/// uses [`run_call`].
pub fn run_call_with<H: Host, FP: FnMut(u32) -> u32, FS: FnMut(u32) -> u32>(
    h: &mut H,
    ws: &mut Workspace,
    read_public: FP,
    n_public: u32,
    read_private: FS,
    n_private: u32,
) -> ([u32; 8], Result<u64, Halt>) {
    let mut elf_c = InputCursor::new(read_public, n_public);
    let mut in_c = InputCursor::new(read_private, n_private);
    if decode_input(&mut ws.input, &mut elf_c, &mut in_c).is_err() {
        // A vector that does not parse — or an instruction region that is not the canonical
        // aligned encoding ([`check_region`]) — is not a call, so there is nothing to bind: the
        // output is the one canonical malformed value, status 2 over two all-zero digests. A
        // verifier recomputing the digest from the instruction it meant to run gets something else
        // and rejects the proof, which is the right answer to a prover-supplied vector that is not
        // even well formed.
        let z = [0u8; 32];
        return (public_output(h, 2, &z, &z), Err(Halt::BadElf));
    }
    // Now split the workspace into its fields: the ELF buffer is borrowed by the loaded program for
    // as long as the run lasts, while the instruction region, the stack and the heap are the memory
    // it runs over.
    let Workspace { input: CallInput { elf, elf_len, input, input_len }, stack, heap } = ws;
    let elf_len = *elf_len;
    let input_len = *input_len;

    // No `program_hash`: the ELF came from the public segment, so `H_PUB` binds it (and the chain
    // checks `H_PUB` against the ELF it published) — hashing 108 600 bytes again in-circuit was
    // 1 698 of the guest's 2 368 SHA-256 compressions and bought nothing.
    let input_hash =
        canonical_input_hash(h, &input[..input_len], &program_id(&input[..input_len]));
    // The pre-state digest, taken before a single instruction runs: this is what a status of 0 or 2
    // binds, so a run that changed accounts and then failed publishes no change at all.
    let pre_output = output_hash(h, &input[..input_len]);

    // A fresh run gets a zero stack and heap whatever a previous one left behind, so two calls
    // through one workspace cannot differ by what the first one left in a frame — a determinism
    // hazard, since an sBPF program is free to read a stack slot it never wrote.
    //
    // For a guest that runs exactly one call this is 64 KiB of stores the `.bss` image already
    // guarantees (~16 000 RV32 `sw` cycles). If Task 6's tier turns out to be tight, this is the
    // first thing to drop — but only together with a note that a `Workspace` is then single-use.
    stack.fill(0);
    heap.fill(0);

    let result = match elf::load(&mut elf[..elf_len]) {
        Ok(program) => {
            let mem = Memory {
                text: program.text,
                text_va: program.text_va,
                rodata: program.rodata,
                rodata_base: program.rodata_va,
                stack,
                heap,
                input: &mut input[..input_len],
            };
            let mut vm = Vm::new(h, &program, mem);
            vm.run()
        }
        Err(e) => Err(e),
    };

    let status = match result {
        Ok(0) => 1,
        Ok(_) => 0,
        Err(_) => 2,
    };
    let post_output =
        if status == 1 { output_hash(h, &input[..input_len]) } else { pre_output };
    (public_output(h, status, &input_hash, &post_output), result)
}

/// What runs the loaded program over the interpreter's memory: `Vm::run` for the interpreter, a
/// translated program's entry point for `sbpf2rv`. Gets the loaded program (text, rodata, entry)
/// and the memory it runs over; returns what `Vm::run` returns.
pub type Executor<'a, H> = &'a mut dyn FnMut(&mut H, &elf::Program<'_>, Memory<'_>) -> Result<u64, Halt>;

/// [`run_call_with`], but the thing that runs the loaded program over the interpreter's `Memory` is
/// supplied by the caller instead of being `Vm::run` — the hook a translated `sbpf2rv` program's
/// entry point uses to run over this same harness (decode, the two digests, the stack/heap zeroing,
/// the status mapping) without going through the interpreter at all. The guest keeps using
/// [`run_call`]/[`run_call_with`], and their body is untouched and duplicated below rather than
/// factored through this function, so the pinned `sbpf` guest image cannot move by adding this.
pub fn run_call_with_executor<H: Host, FP: FnMut(u32) -> u32, FS: FnMut(u32) -> u32>(
    h: &mut H,
    ws: &mut Workspace,
    read_public: FP,
    n_public: u32,
    read_private: FS,
    n_private: u32,
    exec: Executor<'_, H>,
) -> ([u32; 8], Result<u64, Halt>) {
    let mut elf_c = InputCursor::new(read_public, n_public);
    let mut in_c = InputCursor::new(read_private, n_private);
    if decode_input(&mut ws.input, &mut elf_c, &mut in_c).is_err() {
        // Same malformed-vector answer as `run_call_with`: status 2, both digests zero, nothing to
        // bind.
        let z = [0u8; 32];
        return (public_output(h, 2, &z, &z), Err(Halt::BadElf));
    }
    let Workspace { input: CallInput { elf, elf_len, input, input_len }, stack, heap } = ws;
    let elf_len = *elf_len;
    let input_len = *input_len;

    let input_hash =
        canonical_input_hash(h, &input[..input_len], &program_id(&input[..input_len]));
    let pre_output = output_hash(h, &input[..input_len]);

    stack.fill(0);
    heap.fill(0);

    let result = match elf::load(&mut elf[..elf_len]) {
        Ok(program) => {
            let mem = Memory {
                text: program.text,
                text_va: program.text_va,
                rodata: program.rodata,
                rodata_base: program.rodata_va,
                stack,
                heap,
                input: &mut input[..input_len],
            };
            exec(h, &program, mem)
        }
        Err(e) => Err(e),
    };

    let status = match result {
        Ok(0) => 1,
        Ok(_) => 0,
        Err(_) => 2,
    };
    let post_output =
        if status == 1 { output_hash(h, &input[..input_len]) } else { pre_output };
    (public_output(h, status, &input_hash, &post_output), result)
}
