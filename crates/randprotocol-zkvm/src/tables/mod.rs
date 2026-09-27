//! The tables of the machine and the buses that connect them.
pub mod range;
pub mod nibble;
pub mod program;
pub mod memory;
pub mod alu;
pub mod cpu;
pub mod poseidon2;
pub mod input;
pub mod public;
pub mod keccak;
pub mod sha256;

pub type F = p3_goldilocks::Goldilocks;

/// The smallest log-height the prover gives a table that carries **private data** — `input` (the
/// private tape), `keccak` (every permuted state, i.e. the preimage) and `sha256` (every message
/// block and chaining state) — whenever that table exists at all. Audit COV-2 / INT-6 / ZKH-1.
///
/// The hiding PCS (`p3-fri` 0.7.0's `HidingFriPcs::commit`) blinds a height-`h` trace by
/// interleaving exactly `h` uniform random rows into it: each committed column is a polynomial of
/// degree `< 2h` whose coefficients hide `h` secret values behind `h` random ones. A proof
/// evaluates it at every distinct FRI query point the table's LDE is opened at (at most
/// `num_queries`) and at the two out-of-domain points `ζ` and `ζ·g` — `k ≤ num_queries + 2` linear
/// equations. While `k ≤ h` the random rows absorb all of them and the column is perfectly hidden;
/// past that the verifier learns `k − h` linear relations among the secret values themselves, and
/// at the tables' old minimal heights that was the whole column: a 4-word input tape is an 8-row
/// table (8 random unknowns against 82 equations — solved by Gaussian elimination), one keccak
/// permutation a 32-row block (a reviewer recovered a full 128-byte preimage from a production
/// proof), one sha256 compression a 64-row block (boolean and byte columns fall to lattice
/// reduction at `h = 64`).
///
/// So `h ≥ num_queries + 2`. The `Production` profile runs `80` queries (`FriProfile::
/// Production`, the whitepaper's FRI 80/8/20): `80 + 2 = 82 ≤ 128 = 2^7`, and `2^6 = 64 < 82`,
/// hence 7 — the smallest power of two that clears it. The `Test` profile's 16 queries need only
/// `2^5`; the floor is not profile-dependent because a declared height is part of the proof's
/// public shape (and, for a pinned guest, of what a chain compares it against), so it must be one
/// number whatever profile proves it. `tests/privacy_floor.rs` pins the arithmetic and counts the
/// distinct opened rows off a real production proof. **Raise this with the query count**: any
/// retune of `FriProfile::Production` past 126 queries needs 8.
///
/// It is prover-side only. The verifier's ranges already admit it (`keccak ∈ [5, t + 5]`,
/// `sha256 ∈ [6, min(t + 6, 20)]`, `input ∈ [2, 20]`, and a chain's call caps — keccak ≤ 12,
/// sha256 ≤ 13, input ≤ `t + 2` — are all ≥ 7 at the smallest tier, 10), so no constraint, key or
/// verifier changes and every proof made before the floor still verifies. `machine::TIERS[0]`
/// ≥ 5 is what keeps `input ≤ t + 2` true (`machine.rs` asserts it at compile time).
///
/// **Not the program table.** It carries the guest's control flow (`MULT`, how often each
/// instruction ran) and leaks it the same way below 64 words, but its height is pinned — a chain
/// compares a call's `program_log_height` against the deployed program record's — so flooring it
/// is a consensus change for the next genesis cut, not a prover choice. `docs/03-privacy.md`,
/// "What the trace heights leak", has the numbers.
pub const MIN_PRIVATE_TABLE_LOG_HEIGHT: u8 = 7;

/// Bus catalogue. A bus is a name; the batch verifier checks every bus balances.
pub mod bus {
    use p3_lookup::{LookupBus, PermutationCheckBus};
    /// cpu → program: (pc, 23 decoded fields). Program provides. Instruction-row fetches only.
    pub const PROGRAM: LookupBus<'static> = LookupBus::new("PROGRAM");
    /// cpu (digest rows) → program: (pc, word). Program provides — the M3.4 digest bus,
    /// separate from `PROGRAM` so a digest row's raw-word lookups never interact with an
    /// ordinary instruction fetch's multiplicity accounting.
    pub const PROGRAM_WORD: LookupBus<'static> = LookupBus::new("PROGRAM_WORD");
    /// cpu (real indigest rows only) → input: (idx, word), count 1 per absorbed real word.
    /// Input provides with count `IS_REAL` — the M4.1 input commitment bus, split from
    /// `INPUT_READ` (review round 1, C1) precisely so the two consumer classes (the mandatory
    /// digest absorption and however many times a guest actually reads an index) cannot trade
    /// budget with each other: set equality on this bus alone forces the real `input` rows to
    /// be exactly `{0, .., n_in-1}` with the words the digest actually absorbed, the same
    /// argument `program`'s `MULT_WORD = VALID` makes for `PROGRAM_WORD`.
    pub const INPUT_DIGEST: LookupBus<'static> = LookupBus::new("INPUT_DIGEST");
    /// cpu (SYS_READ rows) → input: (idx, word), count `MULT_READ` per real row. Input
    /// provides with count `IS_REAL * MULT_READ` — a free but LogUp-balance-checked witness
    /// value, unrelated to `INPUT_DIGEST`'s own count now that the two are split.
    pub const INPUT_READ: LookupBus<'static> = LookupBus::new("INPUT_READ");
    /// cpu (real `IS_PUBDIGEST` rows) → public: (idx, word), count 1 per absorbed word. The
    /// public table provides with count `IS_REAL`. Split from `PUBLIC_READ` for the reason
    /// `INPUT_DIGEST` is split from `INPUT_READ` (M4.1 review round 1, C1): LogUp balances per
    /// (idx, word) key, not per consumer class, so one bus would let a prover shrink the
    /// digest's absorbed set while a genuine read of the dropped index still succeeded.
    pub const PUBLIC_DIGEST: LookupBus<'static> = LookupBus::new("PUBLIC_DIGEST");
    /// cpu (`SYS_READ_PUB` rows) → public: (idx, word), count `MULT_READ` per real row.
    pub const PUBLIC_READ: LookupBus<'static> = LookupBus::new("PUBLIC_READ");
    /// cpu ↔ memory: (space, addr, ts, value, is_write). Multiset equality.
    pub const MEMORY: PermutationCheckBus<'static> = PermutationCheckBus::new("MEMORY");
    /// cpu → alu: (op, a, b, c). Alu provides.
    pub const ALU: LookupBus<'static> = LookupBus::new("ALU");
    /// x in [0,256). Range provides.
    pub const RANGE8: LookupBus<'static> = LookupBus::new("RANGE8");
    /// (a, b, a&b) with a,b in [0,16). Nibble provides.
    pub const AND4: LookupBus<'static> = LookupBus::new("AND4");
    pub const OR4: LookupBus<'static> = LookupBus::new("OR4");
    pub const XOR4: LookupBus<'static> = LookupBus::new("XOR4");
    /// (s, 2^s) for s < 32. Range provides.
    pub const POW2: LookupBus<'static> = LookupBus::new("POW2");
    /// (in0..7, out0..7): a width-8 Poseidon2 permutation. Poseidon2 table provides.
    pub const POSEIDON2: LookupBus<'static> = LookupBus::new("POSEIDON2");
    /// M4.2 — cpu (SYS_KECCAK rows) → keccak: (clk, ptr). The keccak table provides one entry
    /// per real 32-row block, on the block's last round row, with count `MULT`. The message is
    /// deliberately *just* the clk/ptr pair and not the 100 permuted words: the permutation's
    /// input and output never travel on this bus at all, they travel on `MEMORY` — the keccak
    /// chip sends its own 50 reads at `ts = 4·clk` and 50 writes at `ts = 4·clk + 1`, which is
    /// what actually ties the permutation to the guest's RAM. `(clk, ptr)` is only the handle
    /// that makes the cpu's syscall row and the chip's block the same event.
    pub const KECCAK: LookupBus<'static> = LookupBus::new("KECCAK");
    /// M4.4 — cpu (`SYS_SHA256` rows) → sha256: (clk, ptr). The sha256 table provides one entry
    /// per real 64-row block, on the block's first row, with count `IS_REAL * IS_FIRST` — there is
    /// no `MULT` witness on this chip, so a real block is claimed by construction. As on
    /// `KECCAK`, the message is deliberately *just* the clk/ptr pair: the 24 words the
    /// compression reads and the 8 it writes back never travel on this bus, they travel on
    /// `MEMORY`, sent by the sha256 chip itself (reads at `ts = 4*clk`, writes at `ts = 4*clk + 1`).
    /// `(clk, ptr)` is only the handle that makes the cpu's syscall row and the chip's block the
    /// same event.
    pub const SHA256: LookupBus<'static> = LookupBus::new("SHA256");
}

/// Split a u32 into four little-endian bytes as field elements.
pub fn limbs(x: u32) -> [F; 4] {
    use p3_field::PrimeCharacteristicRing;
    core::array::from_fn(|i| F::from_u32((x >> (8 * i)) & 0xff))
}

/// Next power of two ≥ n, at least `min`.
pub fn pad_height(n: usize, min: usize) -> usize {
    n.max(min).next_power_of_two()
}
