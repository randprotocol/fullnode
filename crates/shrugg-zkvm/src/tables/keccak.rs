//! Keccak-f[1600] as a hand-written AIR: one row per round, in fixed 32-row blocks (24 round
//! rows + 8 idle rows), with Plonky3's own `keccak-air` column layout and a chip that owns its
//! memory traffic. M4.2 Task 3.
//!
//! ## Column layout
//!
//! Preprocessed (period 32, `pre::WIDTH = 99`): `IS_ROUND0 + r` (a 24-wide one-hot over the
//! round rows), `IS_FIRST` (row 0), `IS_LAST_ROUND` (row 23), `IS_IDLE` (rows 24..31),
//! `IS_IDLE0 + i` (an 8-wide one-hot over the idle rows), `RC0 + z` (bit `z` of this round's
//! ι constant, zero on idle rows).
//!
//! Main (`col::WIDTH = 2612`): `IS_REAL`, `MULT`, `CLK`, `PTR`; `IN` (100 16-bit limbs — the
//! permutation's input, copied down every row of the block); `A` (100 limbs — the state
//! *entering* this round, and on the idle rows the permutation's output); `C`/`C'` (2 × 5 × 64
//! bits — the column parities and `C' = C ⊕ D`); `A'` (25 × 64 bits — the post-θ state,
//! `A ⊕ D`); `A''` (100 limbs — post-ρπχ); `A''[0,0]`'s 64 bits; and `A'''[0,0]`'s 4 limbs
//! (post-ι). `4 + 100 + 100 + 320 + 320 + 1600 + 100 + 64 + 4 = 2612`.
//!
//! A lane is addressed `lane(x, y) = x + 5y` (the `[u64; 25]` order `keccak::words_to_state`
//! produces and `p3_keccak::KeccakF` permutes), a limb `l` covers bits `16l .. 16l+15`, and a
//! 32-bit word `w` is limbs `4·(w/2) + 2·(w%2)` (low) and `+1` (high) — exactly the packing
//! `keccak::state_to_words` uses.
//!
//! ## Why there are no RANGE8 lookups
//!
//! Every limb this table exposes is *derived from bits*: rule 5 reconstructs each `A` limb as
//! `Σ_{i<16} 2^i · xor3(A'[x,y][16l+i], C[x][16l+i], C'[x][16l+i])`, rule 7 each `A''` limb
//! from the χ of `A'` bits, rule 8 `A'''[0,0]`'s limbs from `A''[0,0]`'s bits ⊕ the round
//! constant. Every one of those bit columns is `assert_bool`'d, so a limb is a sum of 16
//! booleans times powers of two: a genuine 16-bit integer in a field far larger than 2^16, with
//! no wraparound available. `IN` inherits this through rule 2 (`IN = A` on the first row, where
//! rule 5 applies) and rule 1 (block-constant), and the idle rows' `A` through rules 9 and 10.
//! So the values this chip puts on the `MEMORY` bus (`lo + 2^16 · hi`) are true 32-bit words
//! without a single range lookup.
//!
//! ## Degree
//!
//! Every rule is degree ≤ 3, gating included. The three cubic rules are the ones that must be:
//! `xor3` (rule 4), the parity triple product (rule 6) and χ's `p ⊕ (¬q ∧ r)` (rule 7).
//!
//! Rules 4, 6, 7 and 8 are written *ungated*: on an idle row every bit column in them is zero
//! and each rule reads `0 = 0`, so gating them with `is_round` would only cost a degree. Rule 5
//! genuinely must be switched off on idle rows (there `A` holds the output while the bits are
//! zero), and it is — but as `is_round · A_limb = Σ …` rather than `is_round · (A_limb − Σ …)`,
//! which is the same statement on round rows (`is_round = 1`) at degree 3 instead of 4. On idle
//! rows the cheap form says `0 = Σ 2^i · xor3(AP, C, CP)`, which is **not** a zero-pin on those
//! bit columns: it pins `AP = C ⊕ CP` on the idle row (the honest filler satisfies it, since it
//! carries all three as zero). That is one more (harmless) relation on columns no bus message
//! and no transition constraint reads there — harmless, but a relation, not the absence of one.
//!
//! ## Padding
//!
//! The round selectors are *preprocessed* and periodic, so every block in the trace — real or
//! not — has to carry a genuine, self-consistent permutation trace for the prover to satisfy
//! them. `keccak_trace` fills every padding block with the honest permutation of the all-zero
//! state and marks it only by `IS_REAL = MULT = 0` (AGENTS.md invariant 2: with `IS_REAL` zero
//! every bus count on the row is zero too, so a padding block sends no memory traffic and
//! provides no `KECCAK` entry).
//!
//! The converse matters just as much here, and is the one place this AIR is deliberately
//! stricter than `poseidon2`'s: `MULT` is constrained *equal* to `IS_REAL` on the last round
//! row, so a real block must be claimed on the `KECCAK` bus rather than merely allowed to be.
//! See rule 11 in `eval` for the forgery that would otherwise be available — briefly, a chip
//! that owns its memory traffic makes a real-but-unpaid block an unrequested permutation of
//! live guest RAM, where an unpaid `poseidon2` block is simply inert.
//!
//! ## The chip's memory traffic
//!
//! The `KECCAK` syscall reads 50 words at `PTR` and writes the permuted 50 back
//! (`emulator::CycleEvent::keccak_accesses`): reads at `ts = 4·CLK`, writes at `ts = 4·CLK + 1`.
//! This table, not the cpu table, sends all 100 on the `MEMORY` bus. They are spread over the
//! block so that no row carries more than a handful of interactions: 2 reads on each of rows
//! 0..=24 (row `r` takes words `2r`, `2r+1`) and 7 writes on each idle row (idle row `i` takes
//! words `7i .. 7i+6`, clipped at word 49) — 100 messages per real block. The message columns
//! are selector-weighted sums over the rows that can carry that slot, so a slot is one
//! interaction covering the whole block, and on a row where the slot is idle its count is zero.
//!
//! Counted as the AIR writes them (which is what the packed-lookup budget sees), that is 9
//! `MEMORY` interactions on *every* row — the 2 read slots plus the 7 write slots, each a
//! separate `bus::MEMORY.send` whose count is zero on the rows that carry no such access —
//! plus the single `KECCAK` entry: 10 interactions per row.
use super::{bus, F};
use crate::emulator::SPACE_RAM;
use crate::keccak::{words_to_state, LANES, RC, ROT, WORDS};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub const ROUNDS: usize = crate::keccak::ROUNDS; // 24 round rows
pub const IDLE_ROWS: usize = 8;
pub const BLOCK: usize = ROUNDS + IDLE_ROWS; // 32
/// 16-bit limbs per 64-bit lane, and the total limb count of a state.
pub const LIMBS: usize = 4;
pub const N_LIMBS: usize = LANES * LIMBS; // 100
/// Bits per lane.
pub const BITS: usize = 64;
/// Reads per row, over rows `0..=ROUNDS` (25 rows × 2 = 50 words).
pub const READS_PER_ROW: usize = 2;
/// Writes per idle row (8 rows × 7 = 56 slots, clipped to the 50 real words).
pub const WRITES_PER_ROW: usize = 7;

/// One block is the floor *for a table that exists at all*: a trace with at least one event
/// needs at least one block. M4.2 (Task 6): a proof whose guest never calls `KECCAK` carries no
/// keccak table, declaring `keccak_log_height = 0` instead — see `keccak_log_height` below and
/// `machine::chips`.
pub const MIN_LOG_HEIGHT: u8 = 5; // 1 << 5 == BLOCK
/// The absolute ceiling on a declared `keccak_log_height`, the analogue of
/// `tables::program::MAX_LOG_HEIGHT` and `tables::input::MAX_LOG_HEIGHT` — 2^20 rows, i.e.
/// 32 768 permutation slots.
///
/// M4.2 (controller ruling 2) made the *tier* the keccak table's ceiling
/// (`machine::Tier::max_keccak_log_height`, `klh <= t + 5`), and for a while that was the only
/// one. It is the tighter bound at every tier but the largest, and it is the one that carries
/// the honest-shape argument (a permutation costs a cycle) — but it is not by itself a *cheap*
/// bound: at tier 20 it permits `klh = 25`, and a forged header declaring that (with
/// `degree_bits` edited to match) makes the verifier build a 2^25-row preprocessed keccak
/// trace — 99 columns of it, minutes of work — before anything else can reject the proof.
/// The two bounds are therefore not rival ceilings but different jobs: this one is the flat
/// defensive cap that keeps an untrusted `u8` from sizing an absurd allocation, the tier one
/// is the honest-shape relation. The enforced bound is `min(t + 5, MAX_LOG_HEIGHT)`, on both
/// sides — `machine::build_traces_salted` (as `ProveError::TooManyPermutations`) and
/// `machine::check_declared_heights` (as `VerifyError::KeccakHeight` for this cap,
/// `VerifyError::KeccakHeightExceedsTier` for the tier's).
///
/// 20 rather than something larger: 32 768 permutations is 4.2 MB of keccak input at 128 bytes
/// each, far past anything this crate proves (the largest tier the suite exercises is 12, whose
/// own ceiling is 17), and a 2^20-row 2 612-column trace is already ~22 GB of witness — the cap
/// only has to be unreachable-but-finite, and this is comfortably both.
pub const MAX_LOG_HEIGHT: u8 = 20;

/// `max(5, log2_ceil(32 · n_perms))` — one 32-row block per permutation, rounded up to a power
/// of two, floored at a single block — **except** for `n_perms == 0`, which is `0`.
///
/// M4.2 (Task 6): `0` is not a height, it is the marker for "this proof has no keccak table".
/// Through Task 5 a permutation-free guest still carried one 32-row padding block, and a
/// 2 612-column table costs ~1.91 MB of FRI leaf openings at the production profile no matter
/// how few rows it has (80 queries; ~705 KB at the 27 queries M4.2 measured —
/// `docs/03-privacy.md`) — so every proof on the chain, shielded bundle proofs included, paid for
/// a table it never used. `machine::chips` reads this value: `0` builds an eight-chip batch with
/// no keccak instance at all, anything else the nine-chip one. The `KECCAK` bus then has no
/// provider, which is exactly what makes a cpu row claiming `SYS_KECCAK` unprovable
/// (`tests/cheating.rs::a_keccak_syscall_without_a_keccak_table_is_rejected`).
pub fn keccak_log_height(n_perms: usize) -> u8 {
    if n_perms == 0 {
        return 0;
    }
    super::pad_height(BLOCK * n_perms, BLOCK).trailing_zeros() as u8
}

pub mod pre {
    use super::{IDLE_ROWS, ROUNDS};
    /// 24: one-hot over the round rows (`IS_ROUND0 + r` on row `r < 24`).
    pub const IS_ROUND0: usize = 0;
    /// Row 0 of the block.
    pub const IS_FIRST: usize = IS_ROUND0 + ROUNDS; // 24
    /// Row 23: the last round row, where the `KECCAK` entry is provided.
    pub const IS_LAST_ROUND: usize = IS_FIRST + 1; // 25
    /// Rows 24..31.
    pub const IS_IDLE: usize = IS_LAST_ROUND + 1; // 26
    /// 8: one-hot over the idle rows (`IS_IDLE0 + i` on row `24 + i`).
    pub const IS_IDLE0: usize = IS_IDLE + 1; // 27
    /// 64: bit `z` of `RC[r]` on round row `r`, zero on idle rows.
    pub const RC0: usize = IS_IDLE0 + IDLE_ROWS; // 35
    pub const WIDTH: usize = RC0 + super::BITS; // 99
}

pub mod col {
    use super::{BITS, LANES, N_LIMBS};
    pub const IS_REAL: usize = 0;
    pub const MULT: usize = 1;
    pub const CLK: usize = 2;
    pub const PTR: usize = 3;
    /// 100 limbs: the permutation input, copied down every row of the block.
    pub const IN0: usize = 4;
    /// 100 limbs: the state entering this round (`== IN` on `IS_FIRST`); on an idle row, the
    /// permutation's output.
    pub const A0: usize = IN0 + N_LIMBS; // 104
    /// 5×64 bits: column parities of `A`.
    pub const C0: usize = A0 + N_LIMBS; // 204
    /// 5×64 bits: `C' = C ⊕ D`.
    pub const CP0: usize = C0 + 5 * BITS; // 524
    /// 25×64 bits: `A' = A ⊕ D`, lane-major (`AP0 + 64·lane(x,y) + z`).
    pub const AP0: usize = CP0 + 5 * BITS; // 844
    /// 100 limbs: `A'' = χ(ρπ(A'))`.
    pub const APP0: usize = AP0 + LANES * BITS; // 2444
    /// 64 bits of lane (0,0) of `A''`.
    pub const APP00B0: usize = APP0 + N_LIMBS; // 2544
    /// 4 limbs: lane (0,0) after ι.
    pub const APPP00L0: usize = APP00B0 + BITS; // 2608
    pub const WIDTH: usize = APPP00L0 + super::LIMBS; // 2612
}

/// `[u64; 25]` lane index of the Keccak coordinate `(x, y)`.
const fn lane(x: usize, y: usize) -> usize {
    x + 5 * y
}
/// Limb `l` (bits `16l..16l+15`) of `A[x, y]`.
const fn a_col(x: usize, y: usize, l: usize) -> usize {
    col::A0 + LIMBS * lane(x, y) + l
}
/// Limb `l` of `A''[x, y]`.
const fn app_col(x: usize, y: usize, l: usize) -> usize {
    col::APP0 + LIMBS * lane(x, y) + l
}
/// Bit `z` of `A'[x, y]`.
const fn ap_col(x: usize, y: usize, z: usize) -> usize {
    col::AP0 + BITS * lane(x, y) + z
}
/// Bit `z` of `C[x]`.
const fn c_col(x: usize, z: usize) -> usize {
    col::C0 + BITS * x + z
}
/// Bit `z` of `C'[x]`.
const fn cp_col(x: usize, z: usize) -> usize {
    col::CP0 + BITS * x + z
}
/// The (low, high) limb columns of 32-bit word `w` of the limb block starting at `base`
/// (`col::IN0` or `col::A0`) — the `lo + 2^16·hi` packing `keccak::state_to_words` uses.
const fn word_cols(base: usize, w: usize) -> (usize, usize) {
    let c = base + LIMBS * (w / 2) + 2 * (w % 2);
    (c, c + 1)
}

/// `a ⊕ b ⊕ c` for booleans, degree 3.
fn xor3<E: Clone + PrimeCharacteristicRing>(a: E, b: E, c: E) -> E {
    let ab = a.clone() * b.clone();
    let ac = a.clone() * c.clone();
    let bc = b.clone() * c.clone();
    a + b + c.clone() - (ab.clone() + ac + bc).double() + (ab * c).double().double()
}

/// `p ⊕ (¬q ∧ r)` for booleans — χ's lane update — degree 3.
fn andn_xor<E: Clone + PrimeCharacteristicRing>(p: E, q: E, r: E) -> E {
    let t = (E::ONE - q) * r; // ¬q ∧ r
    p.clone() + t.clone() - (p * t).double()
}

/// `Σ_{i<16} 2^i · bits(i)` — one 16-bit limb from its bits, degree = the bits' own degree.
fn limb_from_bits<E: PrimeCharacteristicRing>(bits: impl Fn(usize) -> E) -> E {
    (0..16).map(|i| bits(i) * E::from_u32(1 << i)).sum()
}

/// The ρπ source of `B[x, y]`: `b(x, y, z) = A'[x'][y'][(z − ROT[x'][y']) mod 64]` with
/// `x' = (x + 3y) mod 5`, `y' = x` — Keccak's `B[y][2x+3y] = rot(A'[x][y], ROT[x][y])` inverted
/// so the consumer (χ) can name its own output coordinates.
///
/// Nesting order, since both tables here are `[[_; 5]; 5]` and the two conventions in the
/// literature differ: `ROT` is indexed `ROT[x][y]` — x (column) outermost, y (row) innermost —
/// the same coordinate order `lane(x, y) = x + 5y` uses, and the same order `fill_block`'s own
/// `bmat` reads it in (`ap[lane(xp, yp)].rotate_left(ROT[xp][yp])`). `keccak::ROT`'s own doc
/// comment is the authority; `tests/keccak.rs` pins `ROT[1][0] = 1` and `ROT[0][1] = 36`, the
/// asymmetric pair that tells the two conventions apart.
const fn rho_pi_src(x: usize, y: usize, z: usize) -> usize {
    let xp = (x + 3 * y) % 5;
    let yp = x;
    let rot = ROT[xp][yp] as usize;
    ap_col(xp, yp, (z + BITS - rot % BITS) % BITS)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakAir;

/// One permutation: the cpu row's `CLK` and the syscall's `PTR`, plus the 50 words read from
/// `[PTR, PTR+50)`. The output is not carried — this table recomputes it, and
/// `keccak_trace` `debug_assert`s the recomputation against `keccak::keccak_f`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeccakEvent {
    pub clk: u32,
    pub ptr: u32,
    pub input: [u32; WORDS],
}

impl<Fld: Field> BaseAir<Fld> for KeccakAir {
    fn width(&self) -> usize {
        col::WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        pre::WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        unreachable!("call KeccakAir::preprocessed_trace_at(height) instead")
    }
}

impl KeccakAir {
    /// Height is a property of the tier, not of this AIR — same split as
    /// `poseidon2::Poseidon2Air::preprocessed_trace_at`.
    pub fn preprocessed_trace_at<Fld: Field>(height: usize) -> RowMajorMatrix<Fld> {
        assert_eq!(height % BLOCK, 0, "keccak height must be a multiple of {BLOCK}");
        let mut v = Fld::zero_vec(height * pre::WIDTH);
        for block in 0..height / BLOCK {
            for r in 0..BLOCK {
                let base = (block * BLOCK + r) * pre::WIDTH;
                let row = &mut v[base..base + pre::WIDTH];
                if r < ROUNDS {
                    row[pre::IS_ROUND0 + r] = Fld::ONE;
                    for z in 0..BITS {
                        if (RC[r] >> z) & 1 == 1 {
                            row[pre::RC0 + z] = Fld::ONE;
                        }
                    }
                } else {
                    row[pre::IS_IDLE] = Fld::ONE;
                    row[pre::IS_IDLE0 + (r - ROUNDS)] = Fld::ONE;
                }
                if r == 0 {
                    row[pre::IS_FIRST] = Fld::ONE;
                }
                if r == ROUNDS - 1 {
                    row[pre::IS_LAST_ROUND] = Fld::ONE;
                }
            }
        }
        RowMajorMatrix::new(v, pre::WIDTH)
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for KeccakAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let pcur = |i: usize| -> AB::Expr { p.current(i).unwrap().into() };
        let pnext = |i: usize| -> AB::Expr { p.next(i).unwrap().into() };
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;

        let is_first = pcur(pre::IS_FIRST);
        let is_idle = pcur(pre::IS_IDLE);
        let is_round = one.clone() - is_idle.clone();
        let is_real = v(col::IS_REAL);

        // --- 1. IS_REAL boolean; IS_REAL/CLK/PTR/IN are block-constant. --------------------
        // No cross-block coupling: a real block may follow a padding block and vice versa,
        // exactly as in `poseidon2` (there padding is a suffix only because the cpu emits its
        // events in order; here, as there, nothing depends on where the padding sits).
        b.assert_bool(is_real.clone());
        {
            let same_block = one.clone() - pnext(pre::IS_FIRST);
            let mut t = b.when_transition();
            for i in [col::IS_REAL, col::CLK, col::PTR] {
                t.assert_zero(same_block.clone() * (n(i) - v(i)));
            }
            for i in 0..N_LIMBS {
                t.assert_zero(same_block.clone() * (n(col::IN0 + i) - v(col::IN0 + i)));
            }
        }

        // --- 2. Row 0 of a block: the state entering round 0 is the block's input. ---------
        for i in 0..N_LIMBS {
            b.assert_zero(is_first.clone() * (v(col::A0 + i) - v(col::IN0 + i)));
        }

        // --- 3. Every bit column is boolean. -----------------------------------------------
        // Unconditional: on an idle row these are all zero in the trace, and zero is boolean.
        for x in 0..5 {
            for z in 0..BITS {
                b.assert_bool(v(c_col(x, z)));
                b.assert_bool(v(cp_col(x, z)));
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..BITS {
                    b.assert_bool(v(ap_col(x, y, z)));
                }
            }
        }
        for z in 0..BITS {
            b.assert_bool(v(col::APP00B0 + z));
        }

        // --- 4. C' = C ⊕ D, with D[x] = C[x−1] ⊕ rotl(C[x+1], 1). -------------------------
        // Ungated (see the module doc): on an idle row every term is zero and this reads 0 = 0.
        for x in 0..5 {
            for z in 0..BITS {
                let d_lo = v(c_col((x + 4) % 5, z));
                let d_hi = v(c_col((x + 1) % 5, (z + BITS - 1) % BITS));
                b.assert_eq(v(cp_col(x, z)), xor3(v(c_col(x, z)), d_lo, d_hi));
            }
        }

        // --- 5. A = A' ⊕ C ⊕ C' (A' = A ⊕ D, C' = C ⊕ D), limb by limb. -------------------
        // This is also the 16-bit range check on every `A` limb — a sum of 16 booleans times
        // powers of two cannot wrap in Goldilocks. Written `is_round · A = Σ …` rather than
        // `is_round · (A − Σ …)` to stay at degree 3; identical on round rows.
        for x in 0..5 {
            for y in 0..5 {
                for l in 0..LIMBS {
                    let bits = |i: usize| {
                        let z = 16 * l + i;
                        xor3(v(ap_col(x, y, z)), v(c_col(x, z)), v(cp_col(x, z)))
                    };
                    b.assert_eq(is_round.clone() * v(a_col(x, y, l)), limb_from_bits(bits));
                }
            }
        }

        // --- 6. C is the true column parity of A. -----------------------------------------
        // `Σ_y A'[x,y][z] ≡ C'[x][z] (mod 2)`: A'[x,y] = A[x,y] ⊕ D[x], so the sum's parity is
        // `parity_y(A[x,y][z]) ⊕ D[x][z]` (5·D ≡ D mod 2), which is exactly C'[x][z] once C is
        // that parity — and the only way to satisfy it is for C to be it. The sum is in [0, 5]
        // and C' is boolean, so the honest difference is 0, 2 or 4. Ungated: zero on idle rows.
        for x in 0..5 {
            for z in 0..BITS {
                let sum: AB::Expr = (0..5).map(|y| v(ap_col(x, y, z))).sum();
                let diff = sum - v(cp_col(x, z));
                b.assert_zero(
                    diff.clone() * (diff.clone() - AB::Expr::TWO) * (diff - AB::Expr::from_u8(4)),
                );
            }
        }

        // --- 7. χ over the ρπ-permuted A'. -------------------------------------------------
        // Ungated: every `b(...)` is zero on an idle row, so both sides read zero.
        for x in 0..5 {
            for y in 0..5 {
                for l in 0..LIMBS {
                    let bits = |i: usize| {
                        let z = 16 * l + i;
                        andn_xor(
                            v(rho_pi_src(x, y, z)),
                            v(rho_pi_src((x + 1) % 5, y, z)),
                            v(rho_pi_src((x + 2) % 5, y, z)),
                        )
                    };
                    b.assert_eq(v(app_col(x, y, l)), limb_from_bits(bits));
                }
            }
        }

        // --- 8. ι on lane (0,0): bind A''[0,0]'s bits to its limbs, then XOR the constant. --
        for l in 0..LIMBS {
            b.assert_eq(v(app_col(0, 0, l)), limb_from_bits(|i| v(col::APP00B0 + 16 * l + i)));
            let with_rc = |i: usize| {
                let z = 16 * l + i;
                let (a, rc) = (v(col::APP00B0 + z), pcur(pre::RC0 + z));
                a.clone() + rc.clone() - (a * rc).double()
            };
            b.assert_eq(v(col::APPP00L0 + l), limb_from_bits(with_rc));
        }

        // --- 9. Round transition: the next row's state is this round's output. -------------
        // On row 23 the "next row" is idle row 24, which is therefore where the permutation's
        // output lives (and what the write-back messages below read).
        {
            let mut t = b.when_transition();
            for x in 0..5 {
                for y in 0..5 {
                    for l in 0..LIMBS {
                        let out = if (x, y) == (0, 0) {
                            v(col::APPP00L0 + l)
                        } else {
                            v(app_col(x, y, l))
                        };
                        t.assert_zero(is_round.clone() * (n(a_col(x, y, l)) - out));
                    }
                }
            }
            // --- 10. The idle rows all hold that same output. -----------------------------
            let same_block = one.clone() - pnext(pre::IS_FIRST);
            for i in 0..N_LIMBS {
                t.assert_zero(
                    is_idle.clone() * same_block.clone() * (n(col::A0 + i) - v(col::A0 + i)),
                );
            }
        }

        // --- 11. KECCAK: exactly one entry per real block, on the last round row. ----------
        // `MULT` is zero off the last round row and zero on a padding block — and, on the last
        // round row, is *equal* to `IS_REAL`, not merely bounded by it.
        //
        // That last clause is not `poseidon2`'s rule, and it has to be here. A real-but-unpaid
        // `poseidon2` block is inert: it supplies a lookup entry nobody claims and touches
        // nothing else. A real-but-unpaid *keccak* block is not, because this chip owns its
        // memory traffic and sends it on `IS_REAL` alone. With `MULT` free to sit at zero on a
        // real block, a prover could flip any padding block to `IS_REAL = 1`, point `PTR` at
        // live guest memory and pick any `CLK`, and the block would honestly read 50 words and
        // honestly write their permutation back at `ts = 4·CLK + 1` — a genuine Keccak-f the
        // guest never asked for, landing in RAM for a later `lw` to pick up. The memory table
        // would happily record it: the reads are read-after-write consistent and the writes sit
        // at a timestamp no cpu access occupies. Forcing `MULT = IS_REAL` here makes the
        // `KECCAK` bus balance a one-to-one pairing of real blocks with cpu `SYS_KECCAK` rows
        // (the key `(CLK, PTR)` carries the cpu's own unique `clk`), so a block that no syscall
        // issued cannot exist. It also makes `MULT` boolean, bounding the provided count at 1.
        let mult = v(col::MULT);
        let is_last = pcur(pre::IS_LAST_ROUND);
        b.assert_zero(mult.clone() * (one.clone() - is_last.clone()));
        b.assert_zero(is_last * (is_real.clone() - mult.clone()));
        bus::KECCAK.table_entry(b, [v(col::CLK), v(col::PTR)], mult);

        // --- 12/13. The chip's own MEMORY traffic. -----------------------------------------
        // One interaction per slot, with selector-weighted message columns: on any row at most
        // one selector is 1 (they are preprocessed one-hots), so each message is a single
        // well-defined access, and on a row that carries no access for this slot the count is
        // zero. Every message column is pinned on every row that sends one: `PTR`/`CLK` by
        // rule 1 (and the `KECCAK` bus, which is what ties them to the cpu's own row), the read
        // values by rules 1/2/5 through `IN`, the write values by rules 9/10 through `A`.
        let space = AB::Expr::from_u32(SPACE_RAM);
        let ts_read = v(col::CLK) * AB::Expr::from_u8(4);
        let ts_write = v(col::CLK) * AB::Expr::from_u8(4) + one.clone();
        for j in 0..READS_PER_ROW {
            let mut sel_sum = AB::Expr::ZERO;
            let mut addr = v(col::PTR);
            let mut value = AB::Expr::ZERO;
            for r in 0..=ROUNDS {
                // Rows 0..=24; row 24 is the first idle row.
                let sel = if r < ROUNDS { pcur(pre::IS_ROUND0 + r) } else { pcur(pre::IS_IDLE0) };
                let w = READS_PER_ROW * r + j;
                let (lo, hi) = word_cols(col::IN0, w);
                sel_sum += sel.clone();
                addr += sel.clone() * AB::Expr::from_u32(w as u32);
                value += sel * (v(lo) + v(hi) * AB::Expr::from_u32(1 << 16));
            }
            bus::MEMORY.send(
                b,
                [space.clone(), addr, ts_read.clone(), value, AB::Expr::ZERO],
                Count::bounded(is_real.clone() * sel_sum, 1),
            );
        }
        for j in 0..WRITES_PER_ROW {
            let mut sel_sum = AB::Expr::ZERO;
            let mut addr = v(col::PTR);
            let mut value = AB::Expr::ZERO;
            for i in 0..IDLE_ROWS {
                let w = WRITES_PER_ROW * i + j;
                if w >= WORDS {
                    continue; // idle row 7 carries only word 49
                }
                let sel = pcur(pre::IS_IDLE0 + i);
                let (lo, hi) = word_cols(col::A0, w);
                sel_sum += sel.clone();
                addr += sel.clone() * AB::Expr::from_u32(w as u32);
                value += sel * (v(lo) + v(hi) * AB::Expr::from_u32(1 << 16));
            }
            bus::MEMORY.send(
                b,
                [space.clone(), addr, ts_write.clone(), value, one.clone()],
                Count::bounded(is_real.clone() * sel_sum, 1),
            );
        }
    }
}

/// Write a `[u64; 25]` state into 100 consecutive 16-bit limb cells.
fn write_limbs(dst: &mut [F], state: &[u64; LANES]) {
    for (i, &l) in state.iter().enumerate() {
        for k in 0..LIMBS {
            dst[LIMBS * i + k] = F::from_u32(((l >> (16 * k)) & 0xffff) as u32);
        }
    }
}

fn bit(x: u64, z: usize) -> F {
    F::from_bool((x >> z) & 1 == 1)
}

/// Fills one 32-row block (`v.len() == BLOCK * col::WIDTH`) with the honest round-by-round
/// computation of `keccak_f(input)`. Returns the permutation's output state, which also sits in
/// `A` on every idle row of the block.
fn fill_block(v: &mut [F], clk: u32, ptr: u32, input: &[u32; WORDS], is_real: bool) -> [u64; LANES] {
    let mut state = words_to_state(input);
    let (clk_f, ptr_f) = (F::from_u32(clk), F::from_u32(ptr));
    let mut in_limbs = [F::ZERO; N_LIMBS];
    write_limbs(&mut in_limbs, &state);

    for r in 0..BLOCK {
        let row = &mut v[r * col::WIDTH..(r + 1) * col::WIDTH];
        if is_real {
            row[col::IS_REAL] = F::ONE;
        }
        row[col::CLK] = clk_f;
        row[col::PTR] = ptr_f;
        row[col::IN0..col::IN0 + N_LIMBS].copy_from_slice(&in_limbs);
        // `A` is the state entering round `r`; on the idle rows it is the final output.
        write_limbs(&mut row[col::A0..col::A0 + N_LIMBS], &state);
        if r >= ROUNDS {
            continue; // idle rows: every other main column stays zero
        }

        // θ: column parities, D, C' = C ⊕ D and A' = A ⊕ D.
        let c: [u64; 5] = core::array::from_fn(|x| (0..5).fold(0u64, |a, y| a ^ state[lane(x, y)]));
        let d: [u64; 5] = core::array::from_fn(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1));
        let cp: [u64; 5] = core::array::from_fn(|x| c[x] ^ d[x]);
        for x in 0..5 {
            for z in 0..BITS {
                row[c_col(x, z)] = bit(c[x], z);
                row[cp_col(x, z)] = bit(cp[x], z);
            }
        }
        let mut ap = [0u64; LANES];
        for x in 0..5 {
            for y in 0..5 {
                ap[lane(x, y)] = state[lane(x, y)] ^ d[x];
                for z in 0..BITS {
                    row[ap_col(x, y, z)] = bit(ap[lane(x, y)], z);
                }
            }
        }

        // ρπ then χ. `bmat[x][y] = rotl(A'[(x+3y)%5][x], ROT[(x+3y)%5][x])` — see `rho_pi_src`.
        let bmat: [u64; LANES] = core::array::from_fn(|i| {
            let (x, y) = (i % 5, i / 5);
            let (xp, yp) = ((x + 3 * y) % 5, x);
            ap[lane(xp, yp)].rotate_left(ROT[xp][yp])
        });
        let mut app = [0u64; LANES];
        for x in 0..5 {
            for y in 0..5 {
                app[lane(x, y)] =
                    bmat[lane(x, y)] ^ (!bmat[lane((x + 1) % 5, y)] & bmat[lane((x + 2) % 5, y)]);
            }
        }
        write_limbs(&mut row[col::APP0..col::APP0 + N_LIMBS], &app);
        for z in 0..BITS {
            row[col::APP00B0 + z] = bit(app[0], z);
        }

        // ι on lane (0,0).
        let appp00 = app[0] ^ RC[r];
        for l in 0..LIMBS {
            row[col::APPP00L0 + l] = F::from_u32(((appp00 >> (16 * l)) & 0xffff) as u32);
        }

        state = app;
        state[0] = appp00;
    }

    debug_assert_eq!(
        state,
        {
            let mut s = words_to_state(input);
            crate::keccak::keccak_f(&mut s);
            s
        },
        "keccak fill_block: the round-by-round trace disagrees with keccak::keccak_f"
    );
    state
}

/// One 32-row block per `KeccakEvent`, in event order, followed by as many padding blocks
/// (honest all-zero permutation, `IS_REAL = MULT = 0`) as needed to reach `height`.
pub fn keccak_trace(events: &[KeccakEvent], height: usize) -> RowMajorMatrix<F> {
    assert_eq!(height % BLOCK, 0, "keccak table height must be a multiple of {BLOCK}");
    let n_blocks = height / BLOCK;
    assert!(
        events.len() <= n_blocks,
        "keccak table needs {} blocks for {} events, height {height}",
        events.len(),
        events.len()
    );
    let mut v = F::zero_vec(height * col::WIDTH);
    for blk in 0..n_blocks {
        let rows = &mut v[blk * BLOCK * col::WIDTH..(blk + 1) * BLOCK * col::WIDTH];
        match events.get(blk) {
            Some(ev) => {
                fill_block(rows, ev.clk, ev.ptr, &ev.input, true);
                rows[(ROUNDS - 1) * col::WIDTH + col::MULT] = F::ONE;
            }
            None => {
                fill_block(rows, 0, 0, &[0u32; WORDS], false);
            }
        }
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
