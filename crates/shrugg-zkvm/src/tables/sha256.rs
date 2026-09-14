//! SHA-256's compression function as a hand-written AIR: one row per round, in fixed 64-row
//! blocks with no idle rows, and a chip that owns its memory traffic. M4.4 Task 3.
//!
//! ## Block geometry
//!
//! `BLOCK = ROUNDS = 64`: row `t` of a block is round `t`, and the final add (`H ← H + v`) plus
//! the eight write-backs fit on the block's own rows because the post-round-63 working variables
//! are already spread over the last four rows (see "The final add" below). A compression is one
//! cpu cycle, so a 64-row block per cycle is also what bounds the table's height against the
//! tier (`sha256_log_height`, `machine::Tier::max_sha256_log_height` in Task 4).
//!
//! ## Column layout
//!
//! Preprocessed (period 64, `pre::WIDTH = 10`): `IS_FIRST` (row 0), `IS_LAST` (row 63),
//! `T_LT_16` (rows 0..16 — the rows whose `W` comes from memory rather than from the schedule),
//! `K` (this round's constant), `ROUND_IDX` (`t`, the message word's offset from `PTR`),
//! `TAIL + k` (a 4-wide one-hot over rows 60..63, the final add's rows) and `TAIL_COPY`
//! (rows 60..62, where the assembled `HOUT` is carried down to row 63).
//!
//! Main (`col::WIDTH = 466`):
//!
//! | columns | what |
//! |---|---|
//! | `IS_REAL`, `CLK`, `PTR` | 3 — block-constant; `PTR`'s `< 2^30` bound lives on the *cpu* side, the chip trusts the `SHA256` lookup |
//! | `A_BITS`, `B_BITS`, `C_BITS`, `E_BITS`, `F_BITS`, `G_BITS` | 6 × 32 — the working variables `a, b, c, e, f, g` entering this round, bit by bit (what `Σ0`, `Σ1`, `Ch` and `Maj` need) |
//! | `D`, `H` | 2 — `d` and `h` as whole words: neither feeds a bitwise function, both only ever get *added* |
//! | `ANEW_BITS`, `ENEW_BITS` | 2 × 32 — `a' = (T1 + T2) mod 2^32` and `e' = (d + T1) mod 2^32` |
//! | `A_CARRY`, `E_CARRY` | 2 × 3 bits — their carries (`≤ 6` and `≤ 5`) |
//! | `WNEW`, `WNEW_BITS`, `WNEW_CARRY` | 1 + 32 + 2 — `W[t]`, its bits, and the schedule's carry (`≤ 3`) |
//! | `PIPE` | 16 — a shift register: `col::pipe(k)` holds `W[t − k]` for `k = 1..=16` |
//! | `WM2_BITS`, `WM15_BITS` | 2 × 32 — the bits of `W[t−2]` and `W[t−15]`, which `σ1`/`σ0` need and the pipeline cannot supply (an AIR sees only `local` and `next`) |
//! | `S1`, `S0` | 2 — `σ1(W[t−2])` and `σ0(W[t−15])` as words |
//! | `HIN` | 8 — the incoming state, block-constant |
//! | `HOUT` | 8 — the outgoing state, assembled on rows 60..63 and written back from row 63 |
//! | `HOUTA_BITS`, `HOUTE_BITS`, `HOUTA_CARRY`, `HOUTE_CARRY` | 2 × 32 + 2 — the two final-add sums this tail row computes |
//!
//! `3 + 192 + 2 + 64 + 6 + 35 + 16 + 64 + 2 + 8 + 8 + 66 = 466`.
//!
//! ## Why there are no `RANGE8` lookups
//!
//! As in `tables::keccak`, every word this table puts on a bus is *derived from bits*, so the
//! chip needs no range lookups at all — and therefore contributes nothing to `RangeCounts` and
//! adds no `RANGE8` traffic to the batch. That is not a cosmetic choice: Goldilocks has
//! `p ≡ 1 (mod 2^32)`, so an unbounded intermediate is not merely ugly, it is a forgery — a
//! witness value of `p − k` is congruent to `−k + 1` rather than `−k` modulo `2^32`, which lets
//! a prover shift a sum's residue by one per wrap. Every value that enters an additive rule here
//! is therefore pinned to a bit decomposition of its own (`WNEW` to `WNEW_BITS`, `a'`/`e'` to
//! `ANEW_BITS`/`ENEW_BITS`, each write-back to `HOUTA_BITS`/`HOUTE_BITS`) and every carry is
//! spelled as bits, so every rule is an identity between integers in `[0, 8 · 2^32)` — far below
//! `p`, with no wraparound available.
//!
//! Two words need a little care, because they are the only state words row 0 does not already
//! decompose into bits: `d = HIN[3]` and `h = HIN[7]`. On rows 1..63 both are pinned by the
//! transition to `compose(C_BITS)` / `compose(G_BITS)` and so are bounded; on row 0 they are
//! bounded by *reusing the schedule's bit banks*, which are idle there (`WM2_BITS`/`WM15_BITS`
//! are only pinned to the pipeline on rows `t ≥ 16`, and `S1`/`S0` are read only by the schedule
//! rule, which is gated to the same rows). Row 0 pins `compose(WM2_BITS) = HIN[3]` and
//! `compose(WM15_BITS) = HIN[7]`: 64 free bit columns instead of 64 new ones.
//!
//! ## Degree
//!
//! Every rule is degree ≤ 3, gating included. The cubic ones are the ones that must be: the
//! three-way XOR inside `Σ0`, `Σ1`, `σ0` and `σ1`, and `Maj`'s `ab + bc + ca − 2abc`. The `σ`
//! values are given their own two columns (`S1`, `S0`) exactly so that the *gated* schedule
//! equation multiplies a preprocessed selector into a degree-2 expression rather than a cubic
//! one.
//!
//! The *instance's* measured maximum is 4: the 18 bus interactions below pack into 7 LogUp groups
//! whose fraction-pins carry a degree-2 `IS_REAL · selector` count, and that is where the fourth
//! degree comes from — not from any rule. It is free: the quotient is chunked by
//! `log2_ceil(degree + is_zk − 1)`, which is 2 at either 3 or 4, and the config's ceiling is 8.
//! `tests/tables.rs::alu_max_constraint_degree_is_pinned` pins both numbers.
//!
//! ## Padding
//!
//! The round constants and row selectors are *preprocessed* and periodic, so every block in the
//! trace — real or not — has to carry a genuine, self-consistent compression for the prover to
//! satisfy them. `sha256_trace` fills every padding block with the honest compression of the
//! all-zero state and the all-zero message block, marked only by `IS_REAL = 0` (AGENTS.md
//! invariant 2: with `IS_REAL` zero every bus count on the row is zero too, so a padding block
//! sends no memory traffic and provides no `SHA256` entry).
//!
//! Unlike `keccak`, this chip has no `MULT` column and so needs no `MULT = IS_REAL` rule: the
//! `SHA256` count *is* `IS_REAL · IS_FIRST`, so a real block is always claimed on the bus and the
//! "real but unpaid block permutes live guest RAM" forgery (`tables::keccak`'s rule 11) has no
//! witness to exploit. A padding block flipped to `IS_REAL = 1` provides a `(CLK, PTR)` entry no
//! cpu row looks up, and the `SHA256` bus does not balance.
//!
//! ## The chip's memory traffic
//!
//! `SYS_SHA256` reads the whole 24-word buffer at `PTR` and writes the eight new state words back
//! over words `16..24` (`emulator::CycleEvent::sha256_accesses`): reads at `ts = 4·CLK`, writes at
//! `ts = 4·CLK + 1`. This table, not the cpu table, sends all 32 on the `MEMORY` bus:
//!
//! * one message word per row over rows 0..16 — `W[t]` at `PTR + t`, gated by `T_LT_16`. One read
//!   per row rather than sixteen on row 0 because `W[t]` is the value row `t`'s own rules pin;
//!   the memory table orders accesses by `(key, ts)`, so reads sharing one `ts` at distinct
//!   addresses are fine (the keccak chip already spreads 50 of them over 25 rows).
//! * the eight state words on row 0, at `PTR + 16 + i`, gated by `IS_FIRST` — they are
//!   block-constant, so row 0 is where they are pinned to the working variables.
//! * the eight write-backs on row 63, at `PTR + 16 + i`, gated by `IS_LAST`.
//!
//! Counted as the AIR writes them (which is what the packed-lookup budget and the permutation
//! trace see) that is 17 `MEMORY` interactions on *every* row — 1 message-word read slot + 8 state
//! read slots + 8 write-back slots, each a separate send whose count is zero on the rows that carry
//! no such access — plus the single `SHA256` entry.
//!
//! Each state word's read and write-back share an address and sit on disjoint rows, so they *can*
//! be folded into one selector-weighted send (`keccak`'s technique). Measured, that is a loss:
//! pairing each `HIN` read with its `HOUT` write into one degree-2 send drops interactions
//! 18 → 10 per row but raises the packed LogUp groups 7 → 9; kept separate.
//!
//! ## The final add
//!
//! `HOUT[i] = HIN[i] + v_i mod 2^32`, where `v` is the post-round-63 working variables. All eight
//! of those are available *as bits* without new columns, because the a- and e-chains are shift
//! registers: `v = (a', a, b, c, e', e, f, g)` on row 63, and `a = a'(62)`, `b = a'(61)`,
//! `c = a'(60)`, `e = e'(62)`, `f = e'(61)`, `g = e'(60)`. So row `60 + k` computes exactly two of
//! the eight sums — `HOUT[3 − k]` from its own `ANEW_BITS` and `HOUT[7 − k]` from its own
//! `ENEW_BITS` — each with a bit decomposition of the *result* (which is what makes the written
//! word a genuine 32-bit word and pins the carry bit to the honest one). `TAIL_COPY` then carries
//! the eight assembled words down to row 63, where the write-backs are sent.
use super::{bus, F};
use crate::emulator::SPACE_RAM;
use crate::sha256::{schedule, K};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

/// Rounds per compression, and rows per block: there are no idle rows.
pub const ROUNDS: usize = crate::sha256::ROUNDS;
pub const BLOCK: usize = ROUNDS;
/// Words of the message block, and of the chaining state.
pub const BLOCK_WORDS: usize = crate::sha256::BLOCK_WORDS;
pub const STATE_WORDS: usize = crate::sha256::STATE_WORDS;
/// Bits per word.
pub const BITS: usize = 32;
/// Depth of the `W` shift register: the schedule reaches back to `W[t − 16]`.
pub const PIPE_DEPTH: usize = 16;
/// The rows the final add is spread over, and the first of them.
pub const TAIL_ROWS: usize = 4;
pub const FIRST_TAIL_ROW: usize = BLOCK - TAIL_ROWS;

/// One block is the floor *for a table that exists at all*. As for keccak (M4.2 Task 6), a proof
/// whose guest never calls `SHA256` carries no sha256 table at all and declares
/// `sha256_log_height = 0` — see `sha256_log_height`.
pub const MIN_LOG_HEIGHT: u8 = 6; // 1 << 6 == BLOCK
/// The flat defensive ceiling on a declared `sha256_log_height`, the analogue of
/// `tables::keccak::MAX_LOG_HEIGHT` and for exactly its reasons: the *tier* is the tighter and
/// more meaningful bound (a compression costs a cycle), but an untrusted `u8` must not be able
/// to size an absurd allocation before any other check can reject the proof. 2^20 rows is 16 384
/// compressions, ~1 MiB of hashed message, past anything this crate proves.
pub const MAX_LOG_HEIGHT: u8 = 20;

/// `max(6, log2_ceil(64 · n))` — one 64-row block per compression, rounded up to a power of two,
/// floored at a single block — **except** for `n == 0`, which is `0`.
///
/// `0` is not a height, it is the marker for "this proof has no sha256 table" (`machine::chips`,
/// Task 4). The table is ~466 columns and every FRI query opens a leaf of that width, so a
/// guest that never hashes should not pay for it; the `SHA256` bus then has no provider at all,
/// which is what makes a cpu row claiming `SYS_SHA256` unprovable.
pub fn sha256_log_height(n_compressions: usize) -> u8 {
    if n_compressions == 0 {
        return 0;
    }
    super::pad_height(BLOCK * n_compressions, BLOCK).trailing_zeros() as u8
}

pub mod pre {
    /// Row 0 of the block: the state reads, and the `SHA256` entry.
    pub const IS_FIRST: usize = 0;
    /// Row 63: the final add's last row, and the write-backs.
    pub const IS_LAST: usize = 1;
    /// Rows 0..16: the rows whose `W[t]` is read from memory instead of computed.
    pub const T_LT_16: usize = 2;
    /// This round's constant `K[t]`.
    pub const K: usize = 3;
    /// `t` — the message word's offset from `PTR` on the rows that read one.
    pub const ROUND_IDX: usize = 4;
    /// 4: a one-hot over rows 60..63, the rows the final add is spread over.
    pub const TAIL: usize = 5;
    /// Rows 60..62: where the assembled `HOUT` is carried down towards row 63.
    pub const TAIL_COPY: usize = TAIL + super::TAIL_ROWS; // 9
    pub const WIDTH: usize = TAIL_COPY + 1; // 10
}

pub mod col {
    use super::{BITS, PIPE_DEPTH, STATE_WORDS};
    pub const IS_REAL: usize = 0;
    pub const CLK: usize = 1;
    pub const PTR: usize = 2;
    /// `a` entering this round, bit `i` at `A_BITS + i`.
    pub const A_BITS: usize = 3;
    pub const B_BITS: usize = A_BITS + BITS; // 35
    pub const C_BITS: usize = B_BITS + BITS; // 67
    pub const E_BITS: usize = C_BITS + BITS; // 99
    pub const F_BITS: usize = E_BITS + BITS; // 131
    pub const G_BITS: usize = F_BITS + BITS; // 163
    /// `d` and `h` as whole words — neither feeds a bitwise function.
    pub const D: usize = G_BITS + BITS; // 195
    pub const H: usize = D + 1; // 196
    /// `a' = (T1 + T2) mod 2^32` and `e' = (d + T1) mod 2^32`, bit by bit.
    pub const ANEW_BITS: usize = H + 1; // 197
    pub const ENEW_BITS: usize = ANEW_BITS + BITS; // 229
    /// Their carries, 3 bits each (`≤ 6` and `≤ 5`).
    pub const A_CARRY: usize = ENEW_BITS + BITS; // 261
    pub const E_CARRY: usize = A_CARRY + 3; // 264
    /// `W[t]`: the schedule's output for `t ≥ 16`, the memory read's value for `t < 16`.
    pub const WNEW: usize = E_CARRY + 3; // 267
    pub const WNEW_BITS: usize = WNEW + 1; // 268
    /// The schedule sum's carry, 2 bits (`≤ 3`).
    pub const WNEW_CARRY: usize = WNEW_BITS + BITS; // 300
    /// The `W` shift register: `pipe(k)` holds `W[t − k]`.
    pub const PIPE: usize = WNEW_CARRY + 2; // 302
    /// Bits of `W[t − 2]` and `W[t − 15]` — on row 0, of `HIN[3]` and `HIN[7]` instead (the
    /// module doc's "Why there are no `RANGE8` lookups").
    pub const WM2_BITS: usize = PIPE + PIPE_DEPTH; // 318
    pub const WM15_BITS: usize = WM2_BITS + BITS; // 350
    /// `σ1(W[t − 2])` and `σ0(W[t − 15])`.
    pub const S1: usize = WM15_BITS + BITS; // 382
    pub const S0: usize = S1 + 1; // 383
    /// The incoming and outgoing chaining states.
    pub const HIN: usize = S0 + 1; // 384
    pub const HOUT: usize = HIN + STATE_WORDS; // 392
    /// The two final-add sums a tail row computes, and their carry bits.
    pub const HOUTA_BITS: usize = HOUT + STATE_WORDS; // 400
    pub const HOUTE_BITS: usize = HOUTA_BITS + BITS; // 432
    pub const HOUTA_CARRY: usize = HOUTE_BITS + BITS; // 464
    pub const HOUTE_CARRY: usize = HOUTA_CARRY + 1; // 465
    pub const WIDTH: usize = HOUTE_CARRY + 1; // 466

    /// The shift-register slot holding `W[t − k]`, `k = 1..=16`.
    pub const fn pipe(k: usize) -> usize {
        assert!(k >= 1 && k <= PIPE_DEPTH);
        PIPE + k - 1
    }

    /// `HOUT[k]` of a row, as the `u32` it is constrained to be — the trace tests' reader.
    pub fn hout_word(row: &[crate::tables::F], k: usize) -> u32 {
        use p3_field::PrimeField64;
        let x = row[HOUT + k].as_canonical_u64();
        debug_assert!(x < 1 << BITS, "HOUT[{k}] is not a 32-bit word: {x}");
        x as u32
    }
}

/// One compression: the cpu row's `CLK` and the syscall's `PTR`, plus the 24 words read from
/// `[PTR, PTR + 24)` as a message block and an incoming state. The outgoing state is not
/// carried — this table recomputes it, and `sha256_trace` `debug_assert`s the recomputation
/// against `sha256::compress`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sha256Event {
    pub clk: u32,
    pub ptr: u32,
    pub block: [u32; BLOCK_WORDS],
    pub h_in: [u32; STATE_WORDS],
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256Air;

impl<Fld: Field> BaseAir<Fld> for Sha256Air {
    fn width(&self) -> usize {
        col::WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        pre::WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        unreachable!("call Sha256Air::preprocessed_trace_at(height) instead")
    }
}

impl Sha256Air {
    /// Height is a property of the proof's declared `sha256_log_height`, not of this AIR — the
    /// same split `keccak::KeccakAir::preprocessed_trace_at` and `poseidon2`'s make.
    pub fn preprocessed_trace_at<Fld: Field>(height: usize) -> RowMajorMatrix<Fld> {
        assert_eq!(height % BLOCK, 0, "sha256 height must be a multiple of {BLOCK}");
        let mut v = Fld::zero_vec(height * pre::WIDTH);
        for block in 0..height / BLOCK {
            for t in 0..BLOCK {
                let base = (block * BLOCK + t) * pre::WIDTH;
                let row = &mut v[base..base + pre::WIDTH];
                if t == 0 {
                    row[pre::IS_FIRST] = Fld::ONE;
                }
                if t == BLOCK - 1 {
                    row[pre::IS_LAST] = Fld::ONE;
                }
                if t < BLOCK_WORDS {
                    row[pre::T_LT_16] = Fld::ONE;
                }
                row[pre::K] = Fld::from_u32(K[t]);
                row[pre::ROUND_IDX] = Fld::from_u32(t as u32);
                if t >= FIRST_TAIL_ROW {
                    row[pre::TAIL + (t - FIRST_TAIL_ROW)] = Fld::ONE;
                }
                if (FIRST_TAIL_ROW..BLOCK - 1).contains(&t) {
                    row[pre::TAIL_COPY] = Fld::ONE;
                }
            }
        }
        RowMajorMatrix::new(v, pre::WIDTH)
    }
}

/// The preprocessed trace for a declared `sha256_log_height` (the plan's Task 3 interface);
/// `Sha256Air::preprocessed_trace_at` takes a row count instead, as the other chips' do.
pub fn preprocessed_trace_at(log_height: u8) -> RowMajorMatrix<F> {
    Sha256Air::preprocessed_trace_at(1usize << log_height)
}

/// `a ⊕ b` for booleans, degree 2.
fn xor2<E: Clone + PrimeCharacteristicRing>(a: E, b: E) -> E {
    a.clone() + b.clone() - (a * b).double()
}

/// `a ⊕ b ⊕ c` for booleans, degree 3.
fn xor3<E: Clone + PrimeCharacteristicRing>(a: E, b: E, c: E) -> E {
    let ab = a.clone() * b.clone();
    let ac = a.clone() * c.clone();
    let bc = b.clone() * c.clone();
    a + b + c.clone() - (ab.clone() + ac + bc).double() + (ab * c).double().double()
}

/// `Σ_{i<32} 2^i · (x[(i+r0) mod 32] ⊕ x[(i+r1) mod 32] ⊕ x_third(i))`, where the third term is
/// `x[(i+r2) mod 32]` for a rotation (`shift == false`) and `x[i+r2]`, zero past bit 31, for a
/// right shift. That covers all four of SHA-256's bitwise mixers: `Σ0 = ROTR(2,13,22)`,
/// `Σ1 = ROTR(6,11,25)`, `σ0 = ROTR(7,18) ⊕ SHR(3)`, `σ1 = ROTR(17,19) ⊕ SHR(10)`.
fn mix_word<E: Clone + PrimeCharacteristicRing>(
    bit: &impl Fn(usize) -> E,
    r0: usize,
    r1: usize,
    r2: usize,
    shift: bool,
) -> E {
    (0..BITS)
        .map(|i| {
            let a = bit((i + r0) % BITS);
            let b = bit((i + r1) % BITS);
            let mixed = if shift {
                if i + r2 < BITS {
                    xor3(a, b, bit(i + r2))
                } else {
                    xor2(a, b)
                }
            } else {
                xor3(a, b, bit((i + r2) % BITS))
            };
            mixed * E::from_u32(1 << i)
        })
        .sum()
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Sha256Air
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let pcur = |i: usize| -> AB::Expr { p.current(i).unwrap().into() };
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let two32 = || AB::Expr::from_u64(1u64 << BITS);
        // `Σ_{i<32} 2^i · bits(i)` — a word from its bits, degree = the bits' own degree.
        let word = |base: usize| -> AB::Expr {
            (0..BITS).map(|i| v(base + i) * AB::Expr::from_u32(1 << i)).sum()
        };
        let small = |base: usize, n_bits: usize| -> AB::Expr {
            (0..n_bits).map(|i| v(base + i) * AB::Expr::from_u32(1 << i)).sum()
        };

        let is_first = pcur(pre::IS_FIRST);
        let is_last = pcur(pre::IS_LAST);
        let t_lt_16 = pcur(pre::T_LT_16);
        let t_ge_16 = one.clone() - t_lt_16.clone();
        let in_block = one.clone() - is_last.clone(); // this row's successor is in the same block
        let is_real = v(col::IS_REAL);

        // --- 1. IS_REAL boolean; IS_REAL/CLK/PTR/HIN are block-constant. -------------------
        // No cross-block coupling: a real block may follow a padding block and vice versa, as in
        // `keccak` and `poseidon2`.
        b.assert_bool(is_real.clone());
        {
            let mut t = b.when_transition();
            for i in [col::IS_REAL, col::CLK, col::PTR] {
                t.assert_zero(in_block.clone() * (n(i) - v(i)));
            }
            for i in 0..STATE_WORDS {
                t.assert_zero(in_block.clone() * (n(col::HIN + i) - v(col::HIN + i)));
            }
        }

        // --- 2. Every bit column is boolean. ------------------------------------------------
        // Unconditional, on every row of every block: this is what makes every `word(..)` below
        // a genuine integer in `[0, 2^32)` and every carry a genuine small integer, which is in
        // turn what keeps the additive rules from being satisfiable by a field wrap (see the
        // module doc — `p ≡ 1 mod 2^32`).
        for base in [
            col::A_BITS,
            col::B_BITS,
            col::C_BITS,
            col::E_BITS,
            col::F_BITS,
            col::G_BITS,
            col::ANEW_BITS,
            col::ENEW_BITS,
            col::WNEW_BITS,
            col::WM2_BITS,
            col::WM15_BITS,
            col::HOUTA_BITS,
            col::HOUTE_BITS,
        ] {
            for i in 0..BITS {
                b.assert_bool(v(base + i));
            }
        }
        for i in 0..3 {
            b.assert_bool(v(col::A_CARRY + i));
            b.assert_bool(v(col::E_CARRY + i));
        }
        for i in 0..2 {
            b.assert_bool(v(col::WNEW_CARRY + i));
        }
        b.assert_bool(v(col::HOUTA_CARRY));
        b.assert_bool(v(col::HOUTE_CARRY));

        // --- 3. Row 0: the working variables are the incoming state. ------------------------
        // `a = H0 .. h = H7`. `D`/`H` get a bit witness too, in the schedule's idle bit banks —
        // the module doc's "Why there are no RANGE8 lookups": they are the only two state words
        // row 0 does not otherwise decompose, and without a bound on them a prover could feed
        // the additive rules a "negative" field element and shift the digest.
        for (base, i) in [
            (col::A_BITS, 0),
            (col::B_BITS, 1),
            (col::C_BITS, 2),
            (col::E_BITS, 4),
            (col::F_BITS, 5),
            (col::G_BITS, 6),
        ] {
            b.assert_zero(is_first.clone() * (word(base) - v(col::HIN + i)));
        }
        b.assert_zero(is_first.clone() * (v(col::D) - v(col::HIN + 3)));
        b.assert_zero(is_first.clone() * (v(col::H) - v(col::HIN + 7)));
        b.assert_zero(is_first.clone() * (word(col::WM2_BITS) - v(col::HIN + 3)));
        b.assert_zero(is_first.clone() * (word(col::WM15_BITS) - v(col::HIN + 7)));

        // --- 4. `WNEW` is a 32-bit word. ----------------------------------------------------
        // On rows `t < 16` this is `W[t]`'s only pin besides the memory read that supplies it —
        // exactly the honest shape: the bus says what memory holds, the bits say it is a word.
        b.assert_eq(v(col::WNEW), word(col::WNEW_BITS));

        // --- 5. The two σ values. -----------------------------------------------------------
        // Ungated (they are read only by rule 7, which is gated): giving `σ1`/`σ0` their own
        // column is what keeps that gated rule at degree 2 instead of 4.
        let wm2 = |i: usize| v(col::WM2_BITS + i);
        let wm15 = |i: usize| v(col::WM15_BITS + i);
        b.assert_eq(v(col::S1), mix_word(&wm2, 17, 19, 10, true));
        b.assert_eq(v(col::S0), mix_word(&wm15, 7, 18, 3, true));

        // --- 6. The σ inputs are the pipeline's `W[t−2]` and `W[t−15]`, on the rows that use
        // them. On rows `t < 16` these banks are idle, and row 0 *borrows* them (rule 3) to bound
        // `HIN[3]`/`HIN[7]` — so neither this rule nor rule 7 may be ungated onto those rows
        // without giving those two words a bit bank of their own.
        b.assert_zero(t_ge_16.clone() * (word(col::WM2_BITS) - v(col::pipe(2))));
        b.assert_zero(t_ge_16.clone() * (word(col::WM15_BITS) - v(col::pipe(15))));

        // --- 7. The message schedule, on rows `t ≥ 16`. -------------------------------------
        // `W[t] = σ1(W[t−2]) + W[t−7] + σ0(W[t−15]) + W[t−16] mod 2^32`, all four addends `< 2^32`
        // so the carry is `≤ 3` (2 bits). On rows `t < 16` `W[t]` is the memory read's value
        // (rule 12) and this rule is off — fully gated, not "reads 0 = 0": the σ banks it consumes
        // are row 0's `HIN[3]`/`HIN[7]` witnesses there (rule 3, and rule 6's comment).
        b.assert_zero(
            t_ge_16
                * (v(col::WNEW) + two32() * small(col::WNEW_CARRY, 2)
                    - v(col::S1)
                    - v(col::pipe(7))
                    - v(col::S0)
                    - v(col::pipe(16))),
        );

        // --- 8. The round. ------------------------------------------------------------------
        // `T1 = h + Σ1(e) + Ch(e,f,g) + K + W`, `T2 = Σ0(a) + Maj(a,b,c)`,
        // `a' = T1 + T2 mod 2^32` (carry ≤ 6), `e' = d + T1 mod 2^32` (carry ≤ 5). Ungated: it
        // holds on every row of every block, padding included.
        let a_bit = |i: usize| v(col::A_BITS + i);
        let e_bit = |i: usize| v(col::E_BITS + i);
        let ch: AB::Expr = (0..BITS)
            .map(|i| {
                let (e, f, g) = (v(col::E_BITS + i), v(col::F_BITS + i), v(col::G_BITS + i));
                (e.clone() * f + (one.clone() - e) * g) * AB::Expr::from_u32(1 << i)
            })
            .sum();
        let maj: AB::Expr = (0..BITS)
            .map(|i| {
                let (a, bb, c) = (v(col::A_BITS + i), v(col::B_BITS + i), v(col::C_BITS + i));
                let ab = a.clone() * bb.clone();
                (ab.clone() + bb * c.clone() + c * a - (ab * v(col::C_BITS + i)).double())
                    * AB::Expr::from_u32(1 << i)
            })
            .sum();
        let t1 = v(col::H) + mix_word(&e_bit, 6, 11, 25, false) + ch + pcur(pre::K) + v(col::WNEW);
        b.assert_eq(
            word(col::ANEW_BITS) + two32() * small(col::A_CARRY, 3),
            t1.clone() + mix_word(&a_bit, 2, 13, 22, false) + maj,
        );
        b.assert_eq(word(col::ENEW_BITS) + two32() * small(col::E_CARRY, 3), v(col::D) + t1);

        // --- 9. The transition: the working variables and the `W` pipeline shift. ------------
        // `(a, b, c, d) ← (a', a, b, c)` and `(e, f, g, h) ← (e', e, f, g)`, each chain a shift
        // register whose oldest member (`d`, `h`) is only ever added and so needs no bits. The
        // `W` pipeline shifts the same way, with this row's `W[t]` entering at slot 1.
        {
            let mut t = b.when_transition();
            for i in 0..BITS {
                t.assert_zero(in_block.clone() * (n(col::A_BITS + i) - v(col::ANEW_BITS + i)));
                t.assert_zero(in_block.clone() * (n(col::B_BITS + i) - v(col::A_BITS + i)));
                t.assert_zero(in_block.clone() * (n(col::C_BITS + i) - v(col::B_BITS + i)));
                t.assert_zero(in_block.clone() * (n(col::E_BITS + i) - v(col::ENEW_BITS + i)));
                t.assert_zero(in_block.clone() * (n(col::F_BITS + i) - v(col::E_BITS + i)));
                t.assert_zero(in_block.clone() * (n(col::G_BITS + i) - v(col::F_BITS + i)));
            }
            t.assert_zero(in_block.clone() * (n(col::D) - word(col::C_BITS)));
            t.assert_zero(in_block.clone() * (n(col::H) - word(col::G_BITS)));
            t.assert_zero(in_block.clone() * (n(col::pipe(1)) - v(col::WNEW)));
            for k in 2..=PIPE_DEPTH {
                t.assert_zero(in_block.clone() * (n(col::pipe(k)) - v(col::pipe(k - 1))));
            }
        }

        // --- 10. The final add, on rows 60..63, and the carry-down to row 63. ---------------
        // Row `60 + k` owns two of the eight sums: `HOUT[3−k] = HIN[3−k] + a'` and
        // `HOUT[7−k] = HIN[7−k] + e'`, with `a'`/`e'` this row's own post-round variables (see
        // the module doc). The result is pinned to a bit decomposition, which is both the
        // 32-bit bound the write-back needs and what forces the carry bit to be the honest one.
        for k in 0..TAIL_ROWS {
            let sel = pcur(pre::TAIL + k);
            let ia = TAIL_ROWS - 1 - k;
            let ie = ia + 4;
            b.assert_zero(sel.clone() * (v(col::HOUT + ia) - word(col::HOUTA_BITS)));
            b.assert_zero(sel.clone() * (v(col::HOUT + ie) - word(col::HOUTE_BITS)));
            b.assert_zero(
                sel.clone()
                    * (v(col::HOUT + ia) + two32() * v(col::HOUTA_CARRY)
                        - v(col::HIN + ia)
                        - word(col::ANEW_BITS)),
            );
            b.assert_zero(
                sel * (v(col::HOUT + ie) + two32() * v(col::HOUTE_CARRY)
                    - v(col::HIN + ie)
                    - word(col::ENEW_BITS)),
            );
        }
        {
            let mut t = b.when_transition();
            let copy = pcur(pre::TAIL_COPY);
            for i in 0..STATE_WORDS {
                t.assert_zero(copy.clone() * (n(col::HOUT + i) - v(col::HOUT + i)));
            }
        }

        // --- 11. SHA256: exactly one entry per real block, on row 0. ------------------------
        // The count *is* `IS_REAL · IS_FIRST` — there is no `MULT` witness to leave at zero, so
        // a real block cannot be unclaimed (`tables::keccak`'s rule 11 discusses the forgery
        // that makes this matter for a chip that owns its memory traffic).
        bus::SHA256.table_entry(b, [v(col::CLK), v(col::PTR)], is_real.clone() * is_first.clone());

        // --- 12. The chip's own MEMORY traffic. ---------------------------------------------
        // Every message column is pinned on every row that sends one: `CLK`/`PTR` by rule 1 (and
        // the `SHA256` bus, which is what ties them to the cpu's own row), `WNEW` by rules 4/7,
        // `HIN` by rules 1/3, `HOUT` by rule 10.
        //
        // The state word `i` is read on row 0 and written back on row 63 at the *same address*,
        // and `IS_FIRST`/`IS_LAST` are disjoint rows, so the two accesses *can* be folded into one
        // selector-weighted send the way `keccak`'s rules 12/13 fold theirs. Measured, that is a
        // loss, not a win: pairing each `HIN` read with its `HOUT` write into one degree-2 send
        // drops interactions 18 → 10 per row but raises the packed LogUp groups 7 → 9 (the packer
        // folds degree-1 messages more aggressively than degree-2 ones), so they are kept separate.
        // Two sends per word, each with a degree-1 message and a degree-2 count.
        let space = AB::Expr::from_u32(SPACE_RAM);
        let ts_read = v(col::CLK) * AB::Expr::from_u8(4);
        let ts_write = v(col::CLK) * AB::Expr::from_u8(4) + one.clone();
        bus::MEMORY.send(
            b,
            [
                space.clone(),
                v(col::PTR) + pcur(pre::ROUND_IDX),
                ts_read.clone(),
                v(col::WNEW),
                AB::Expr::ZERO,
            ],
            Count::bounded(is_real.clone() * t_lt_16, 1),
        );
        for i in 0..STATE_WORDS {
            let addr = || v(col::PTR) + AB::Expr::from_u32((BLOCK_WORDS + i) as u32);
            bus::MEMORY.send(
                b,
                [space.clone(), addr(), ts_read.clone(), v(col::HIN + i), AB::Expr::ZERO],
                Count::bounded(is_real.clone() * is_first.clone(), 1),
            );
            bus::MEMORY.send(
                b,
                [space.clone(), addr(), ts_write.clone(), v(col::HOUT + i), one.clone()],
                Count::bounded(is_real.clone() * is_last.clone(), 1),
            );
        }
    }
}

fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
fn ch(e: u32, f: u32, g: u32) -> u32 {
    (e & f) ^ (!e & g)
}
fn maj(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

/// Write the 32 bits of `x` into `row[base .. base + 32]`, little-endian.
fn put_bits(row: &mut [F], base: usize, x: u32) {
    for i in 0..BITS {
        row[base + i] = F::from_bool((x >> i) & 1 == 1);
    }
}

/// Fills one 64-row block (`rows.len() == BLOCK * col::WIDTH`) with the honest round-by-round
/// compression of `(h_in, block)`, and `debug_assert`s the result against `sha256::compress`.
fn fill_block(
    rows: &mut [F],
    clk: u32,
    ptr: u32,
    block: &[u32; BLOCK_WORDS],
    h_in: &[u32; STATE_WORDS],
    is_real: bool,
) {
    let w = schedule(block);
    let (clk_f, ptr_f) = (F::from_u32(clk), F::from_u32(ptr));
    let mut var = *h_in; // the working variables `a..h` entering the current round

    for t in 0..BLOCK {
        let row = &mut rows[t * col::WIDTH..(t + 1) * col::WIDTH];
        if is_real {
            row[col::IS_REAL] = F::ONE;
        }
        row[col::CLK] = clk_f;
        row[col::PTR] = ptr_f;
        for (i, h) in h_in.iter().enumerate() {
            row[col::HIN + i] = F::from_u32(*h);
        }

        put_bits(row, col::A_BITS, var[0]);
        put_bits(row, col::B_BITS, var[1]);
        put_bits(row, col::C_BITS, var[2]);
        row[col::D] = F::from_u32(var[3]);
        put_bits(row, col::E_BITS, var[4]);
        put_bits(row, col::F_BITS, var[5]);
        put_bits(row, col::G_BITS, var[6]);
        row[col::H] = F::from_u32(var[7]);

        row[col::WNEW] = F::from_u32(w[t]);
        put_bits(row, col::WNEW_BITS, w[t]);
        for k in 1..=PIPE_DEPTH {
            if t >= k {
                row[col::pipe(k)] = F::from_u32(w[t - k]);
            }
        }

        // The σ bit banks: the schedule's two inputs on rows `t ≥ 16`; on row 0 the 32-bit
        // witnesses for `HIN[3]`/`HIN[7]` (the AIR's rule 3); idle in between.
        let (wm2, wm15) = if t >= BLOCK_WORDS {
            (w[t - 2], w[t - 15])
        } else if t == 0 {
            (h_in[3], h_in[7])
        } else {
            (0, 0)
        };
        put_bits(row, col::WM2_BITS, wm2);
        put_bits(row, col::WM15_BITS, wm15);
        row[col::S1] = F::from_u32(small_sigma1(wm2));
        row[col::S0] = F::from_u32(small_sigma0(wm15));
        if t >= BLOCK_WORDS {
            let sum = small_sigma1(wm2) as u64
                + w[t - 7] as u64
                + small_sigma0(wm15) as u64
                + w[t - 16] as u64;
            debug_assert_eq!(sum as u32, w[t], "sha256 fill_block: schedule disagrees at {t}");
            let carry = sum >> BITS;
            debug_assert!(carry < 4);
            for i in 0..2 {
                row[col::WNEW_CARRY + i] = F::from_bool((carry >> i) & 1 == 1);
            }
        }

        let t1 = var[7] as u64
            + big_sigma1(var[4]) as u64
            + ch(var[4], var[5], var[6]) as u64
            + K[t] as u64
            + w[t] as u64;
        let t2 = big_sigma0(var[0]) as u64 + maj(var[0], var[1], var[2]) as u64;
        let a_sum = t1 + t2;
        let e_sum = var[3] as u64 + t1;
        debug_assert!(a_sum >> BITS < 8 && e_sum >> BITS < 8);
        put_bits(row, col::ANEW_BITS, a_sum as u32);
        put_bits(row, col::ENEW_BITS, e_sum as u32);
        for i in 0..3 {
            row[col::A_CARRY + i] = F::from_bool(((a_sum >> BITS) >> i) & 1 == 1);
            row[col::E_CARRY + i] = F::from_bool(((e_sum >> BITS) >> i) & 1 == 1);
        }

        crate::sha256::round(&mut var, w[t], K[t]);
        debug_assert_eq!(var[0], a_sum as u32, "sha256 fill_block: a' disagrees at row {t}");
        debug_assert_eq!(var[4], e_sum as u32, "sha256 fill_block: e' disagrees at row {t}");
    }

    // The final add. `var` is now the post-round-63 working variables, i.e. `state'`.
    let h_out: [u32; STATE_WORDS] = core::array::from_fn(|i| h_in[i].wrapping_add(var[i]));
    debug_assert_eq!(
        h_out,
        {
            let mut s = *h_in;
            crate::sha256::compress(&mut s, block);
            s
        },
        "sha256 fill_block: the round-by-round trace disagrees with sha256::compress"
    );
    for k in 0..TAIL_ROWS {
        let t = FIRST_TAIL_ROW + k;
        let row = &mut rows[t * col::WIDTH..(t + 1) * col::WIDTH];
        for (i, h) in h_out.iter().enumerate() {
            row[col::HOUT + i] = F::from_u32(*h);
        }
        let (ia, ie) = (TAIL_ROWS - 1 - k, TAIL_ROWS - 1 - k + 4);
        put_bits(row, col::HOUTA_BITS, h_out[ia]);
        put_bits(row, col::HOUTE_BITS, h_out[ie]);
        row[col::HOUTA_CARRY] = F::from_bool(h_in[ia] as u64 + var[ia] as u64 >= 1 << BITS);
        row[col::HOUTE_CARRY] = F::from_bool(h_in[ie] as u64 + var[ie] as u64 >= 1 << BITS);
    }
}

/// One 64-row block per `Sha256Event`, in event order, followed by as many padding blocks
/// (the honest all-zero compression, `IS_REAL = 0`) as `1 << log_height` needs.
pub fn sha256_trace(events: &[Sha256Event], log_height: u8) -> RowMajorMatrix<F> {
    assert!(
        (MIN_LOG_HEIGHT..=MAX_LOG_HEIGHT).contains(&log_height),
        "sha256 log height {log_height} outside [{MIN_LOG_HEIGHT}, {MAX_LOG_HEIGHT}]"
    );
    let height = 1usize << log_height;
    let n_blocks = height / BLOCK;
    assert!(
        events.len() <= n_blocks,
        "sha256 table needs {} blocks for {} events, height {height}",
        events.len(),
        events.len()
    );
    let mut v = F::zero_vec(height * col::WIDTH);
    for blk in 0..n_blocks {
        let rows = &mut v[blk * BLOCK * col::WIDTH..(blk + 1) * BLOCK * col::WIDTH];
        match events.get(blk) {
            Some(ev) => fill_block(rows, ev.clk, ev.ptr, &ev.block, &ev.h_in, true),
            None => fill_block(rows, 0, 0, &[0u32; BLOCK_WORDS], &[0u32; STATE_WORDS], false),
        }
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
