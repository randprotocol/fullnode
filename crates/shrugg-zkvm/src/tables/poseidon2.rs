//! Width-8 Goldilocks Poseidon2, one row per round, in fixed 32-row blocks (30 round rows,
//! 2 idle rows). Approach A from the M3 spec.
//!
//! Round structure (`HALF_FULL_ROUNDS = 4` initial full rounds, `PARTIAL_ROUNDS = 22`
//! partial rounds, 4 terminal full rounds — `p3_goldilocks`'s own
//! `GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS`/`GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8`) and the
//! exact round arithmetic (`mds_light`'s `mat4`-then-outer-sum operation order,
//! `internal_matmul`'s diagonal trick) mirror the proven-correct plain-u64 reference at
//! `rand-zkvm-cuda/src/device/poseidon2.rs::permute`, which is itself bit-identical to
//! `p3_poseidon2`/`p3_goldilocks`'s `Poseidon2Goldilocks<8>::permute` (that equivalence is
//! `rand-zkvm-cuda/tests/poseidon2.rs`, already in this checkout). The one difference from
//! the CUDA reference's control flow: the CUDA `permute` applies the initial `mds_light`
//! *before* its round-0 loop iteration; this table folds that initial linear layer into row
//! 0's own S-box computation (`pre_first = mds_light(S) + RC[0]`) so that every round —
//! including round 0 — costs exactly one row. That is Plonky3's own
//! `external_initial_permute_state` fusion, not a deviation from it.
//!
//! ## Column layout
//!
//! Preprocessed (period 32, `pre::WIDTH = 13`): `RC0..7` (the round's constants — only lane
//! 0 is nonzero on a partial round), `IS_FULL`, `IS_PARTIAL`, `IS_FIRST` (row 0 of the
//! block), `IS_LAST` (row 29, the last round row), `IS_IDLE` (rows 30/31).
//!
//! Main (`col::WIDTH = 34`): `IS_REAL`, `MULT`, `S0..7` (the state entering this row),
//! `X3_0..7`/`X7_0..7` (S-box intermediates — see the degree note below), `IN0..7` (this
//! block's absorbed input, copied down every row of the block).
//!
//! ## Degree
//!
//! The S-box is split `X3 = (S+RC)^3`, `X7 = X3·X3·(S+RC)` so every constraint stays degree
//! ≤ 3 in the *columns*; gated by a degree-1 preprocessed selector, the S-box constraints are
//! degree 4. The linear-layer output constraints (`S_next = mds_light(X7)` or
//! `internal_matmul(X7)`) are degree 1 in the columns, degree 2 gated. `tests/tables.rs`
//! pins the table's measured max degree (including the packed `POSEIDON2` lookup) against
//! `machine::max_constraint_degrees`.
//!
//! ## Padding
//!
//! `IS_FULL`/`IS_PARTIAL`/`IS_IDLE` are *preprocessed* selectors, periodic with period 32
//! regardless of which blocks correspond to real events — so the round-transition
//! constraints they gate run on literally every block in the trace, real or not. A block
//! that has no real event still has to carry a genuine, self-consistent permutation trace
//! (of a canonical all-zero input) for the prover to satisfy them; `poseidon2_trace` below
//! fills every block this way and only ever leaves `IS_REAL`/`MULT` at zero to mark it as
//! padding, never leaves the S-box columns at their `zero_vec` default.
use super::{bus, F};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::MATRIX_DIAG_8_GOLDILOCKS;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::ExternalLayerConstants;
use rand::distr::StandardUniform;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use std::sync::OnceLock;

pub const STATE_WIDTH: usize = 8;
pub const HALF_FULL_ROUNDS: usize = 4; // GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS
pub const PARTIAL_ROUNDS: usize = 22; // GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8
pub const ROUND_ROWS: usize = 2 * HALF_FULL_ROUNDS + PARTIAL_ROUNDS; // 30
pub const IDLE_ROWS: usize = 2;
pub const BLOCK: usize = ROUND_ROWS + IDLE_ROWS; // 32

pub mod pre {
    pub const RC0: usize = 0; // 8: this round's constants; lanes > 0 are 0 on a partial round
    pub const IS_FULL: usize = 8;
    pub const IS_PARTIAL: usize = 9;
    pub const IS_FIRST: usize = 10; // row 0 of the block
    pub const IS_LAST: usize = 11; // row 29 of the block (the last round row)
    pub const IS_IDLE: usize = 12;
    pub const WIDTH: usize = 13;
}
pub mod col {
    pub const IS_REAL: usize = 0;
    pub const MULT: usize = 1;
    pub const S0: usize = 2; // 8: state entering this row
    pub const X3_0: usize = 10; // 8
    pub const X7_0: usize = 18; // 8
    pub const IN0: usize = 26; // 8: this block's absorbed input, copied down every row
    pub const WIDTH: usize = 34;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Poseidon2Air;

/// One event per emulator-side permutation call, in the order the emulator produces them.
/// Field values, not raw words: a Poseidon2 lane is a whole Goldilocks element, not a 32-bit
/// word, so `input`/`output` are `[F; 8]` states — exactly what `poseidon2_trace` needs and
/// what M3.1's own tests build directly (the emulator doesn't call `POSEIDON2` until M3.2,
/// which will wire its own word-level `HashEvent` into this same builder).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poseidon2Event {
    pub input: [F; 8],
    pub output: [F; 8],
}

/// Multiply a 4-element vector by `[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]`. Same operation
/// order as `p3_poseidon2::external::apply_mat4` / the CUDA reference's `mat4`.
fn mat4<E: Clone + PrimeCharacteristicRing>(x: &mut [E]) {
    let t01 = x[0].clone() + x[1].clone();
    let t23 = x[2].clone() + x[3].clone();
    let t0123 = t01.clone() + t23.clone();
    let t01123 = t0123.clone() + x[1].clone();
    let t01233 = t0123 + x[3].clone();
    let (x0, x2) = (x[0].clone(), x[2].clone());
    x[3] = t01233.clone() + x0.double();
    x[1] = t01123.clone() + x2.double();
    x[0] = t01123 + t01;
    x[2] = t01233 + t23;
}

/// The width-8 external (MDS-light) linear layer: `mat4` on each half, then add the
/// cross-half column sums. Same operation order as `p3_poseidon2::external::
/// mds_light_permutation` for `WIDTH = 8` and the CUDA reference's `mds_light`.
///
/// `pub`: exercised directly, over both `AB::Expr` (via the AIR below) and plain `Goldilocks`
/// (via `permute_scalar` and `tests/tables.rs`'s cross-checks against `Poseidon2Goldilocks`).
pub fn mds_light<E: Clone + PrimeCharacteristicRing>(s: [E; 8]) -> [E; 8] {
    let mut s = s;
    {
        let mut lo = [s[0].clone(), s[1].clone(), s[2].clone(), s[3].clone()];
        mat4(&mut lo);
        s[0..4].clone_from_slice(&lo);
    }
    {
        let mut hi = [s[4].clone(), s[5].clone(), s[6].clone(), s[7].clone()];
        mat4(&mut hi);
        s[4..8].clone_from_slice(&hi);
    }
    let sums: [E; 4] = core::array::from_fn(|k| s[k].clone() + s[k + 4].clone());
    for i in 0..8 {
        s[i] = s[i].clone() + sums[i % 4].clone();
    }
    s
}

/// The internal (partial-round) linear layer: `state[i] = sum + diag[i]*state[i]` for
/// `diag = MATRIX_DIAG_8_GOLDILOCKS = [-2, 1, 2, 1/2, 3, -1/2, -3, -4]`. Mirrors
/// `p3_goldilocks::poseidon2::GenericPoseidon2LinearLayersGoldilocks::internal_linear_layer`
/// (`matmul_internal(state, MATRIX_DIAG_8_GOLDILOCKS)`) and the CUDA reference's
/// `internal_matmul` (whose `half()`-trick special-casing per lane is the same field
/// arithmetic as this generic diagonal multiply, just unrolled for Goldilocks specifically).
pub fn internal_matmul<E: Clone + PrimeCharacteristicRing>(s: [E; 8]) -> [E; 8] {
    let mut s = s;
    let sum = s.iter().cloned().fold(E::ZERO, |a, b| a + b);
    for i in 0..8 {
        let d = E::from_u64(MATRIX_DIAG_8_GOLDILOCKS[i].as_canonical_u64());
        s[i] = sum.clone() + s[i].clone() * d;
    }
    s
}

/// The Goldilocks Poseidon2 S-box, `x^7`, split so that every constraint that uses it stays
/// degree ≤ 3 in the columns: `x3 = x^3`; the caller separately builds `x3*x3*x = x^7`.
pub fn cube<E: Clone + core::ops::Mul<Output = E>>(x: E) -> E {
    x.clone() * x.clone() * x
}

/// A plain-`F` replay of the permutation, built only from the `pub` helpers above plus
/// [`round_constants`] — no trace columns, no AIR. This is the M3-correctness anchor: compared
/// against `Poseidon2Goldilocks::<8>::permute` (which derives its own round constants from the
/// same `machine::PERM_SEED`-seeded RNG) in `tests/tables.rs::
/// poseidon2_scalar_helpers_match_plonky3`, it proves both that `round_constants` reproduces
/// the exact same constants and that `mds_light`/`internal_matmul`/`cube` compute the exact
/// same permutation p3_poseidon2 does.
pub fn permute_scalar(state: [F; 8]) -> [F; 8] {
    let rc = round_constants();
    let sbox_all = |s: [F; 8], round: [F; 8]| -> [F; 8] {
        core::array::from_fn(|i| {
            let p = s[i] + round[i];
            let x3 = cube(p);
            x3 * x3 * p // == p^7
        })
    };
    let mut s = mds_light(state);
    for r in 0..HALF_FULL_ROUNDS {
        s = mds_light(sbox_all(s, rc.initial[r]));
    }
    for r in 0..PARTIAL_ROUNDS {
        let mut x = s;
        let p0 = s[0] + rc.internal[r];
        let x3_0 = cube(p0);
        x[0] = x3_0 * x3_0 * p0;
        s = internal_matmul(x);
    }
    for r in 0..HALF_FULL_ROUNDS {
        s = mds_light(sbox_all(s, rc.terminal[r]));
    }
    s
}

/// This table's round constants, split the same way the AIR's row kinds are: `initial` (the
/// 4 initial full rounds), `internal` (the 22 partial rounds — one scalar per round, applied
/// only to lane 0), `terminal` (the 4 terminal full rounds).
pub struct RoundConstants {
    pub initial: [[F; 8]; HALF_FULL_ROUNDS],
    pub internal: [F; PARTIAL_ROUNDS],
    pub terminal: [[F; 8]; HALF_FULL_ROUNDS],
}

/// Reproduces the exact RNG draw `Poseidon2Goldilocks::<8>::new_from_rng_128` makes from
/// `StdRng::seed_from_u64(machine::PERM_SEED)` — the same seed `machine::permutation()`
/// uses — so this table's round constants are byte-identical to the machine's own hashing
/// permutation, with "no new constants" (per the M3.1 design ruling).
///
/// `p3_poseidon2::Poseidon2::new_from_rng_128` computes `(rounds_f, rounds_p) = (8, 22)` for
/// Goldilocks width 8 (a pure function of the field/width, consumes no RNG output), then
/// calls `new_from_rng(8, 22, rng)`, which draws, *in this order*: `ExternalLayerConstants::
/// new_from_rng(8, rng)` (4 initial `[Goldilocks; 8]` rows, then 4 terminal `[Goldilocks; 8]`
/// rows — `ExternalLayerConstants::new_from_rng`'s own draw order), then
/// `rng.sample_iter(StandardUniform).take(22)` for the internal (partial-round) scalars.
/// `ExternalLayerConstants` is public API (`get_initial_constants`/`get_terminal_constants`),
/// so this reproduces the stream by calling exactly the same public constructors — not by
/// reaching into `Poseidon2`'s opaque `external_layer`/`internal_layer` fields, which have no
/// accessor once built.
fn compute_round_constants() -> RoundConstants {
    let mut rng = StdRng::seed_from_u64(crate::machine::PERM_SEED);
    let external = ExternalLayerConstants::<F, 8>::new_from_rng(2 * HALF_FULL_ROUNDS, &mut rng);
    let initial: [[F; 8]; HALF_FULL_ROUNDS] =
        external.get_initial_constants().try_into().expect("4 initial rounds");
    let terminal: [[F; 8]; HALF_FULL_ROUNDS] =
        external.get_terminal_constants().try_into().expect("4 terminal rounds");
    let internal: Vec<F> = rng.sample_iter(StandardUniform).take(PARTIAL_ROUNDS).collect();
    let internal: [F; PARTIAL_ROUNDS] = internal.try_into().expect("22 internal rounds");
    RoundConstants { initial, internal, terminal }
}

/// Cached: pure and deterministic, but redrawing an RNG stream on every call is needless
/// work when the preprocessed trace and the witness builder both call this per block.
pub fn round_constants() -> &'static RoundConstants {
    static RC: OnceLock<RoundConstants> = OnceLock::new();
    RC.get_or_init(compute_round_constants)
}

impl<Fld: Field> BaseAir<Fld> for Poseidon2Air {
    fn width(&self) -> usize {
        col::WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        pre::WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        unreachable!("call Poseidon2Air::preprocessed_trace_at(height) instead")
    }
}

impl Poseidon2Air {
    /// Height is a property of the tier (`Tier::poseidon2_height`), not of this AIR — mirrors
    /// how `range.rs`/`nibble.rs` fix their own height but `program.rs` takes the program's
    /// length; `poseidon2.rs` takes the tier's height explicitly from the caller.
    pub fn preprocessed_trace_at<Fld: Field>(height: usize) -> RowMajorMatrix<Fld> {
        assert_eq!(height % BLOCK, 0, "poseidon2 height must be a multiple of {BLOCK}");
        let rc = round_constants();
        let mut v = Fld::zero_vec(height * pre::WIDTH);
        for block in 0..height / BLOCK {
            for r in 0..BLOCK {
                let row = &mut v[(block * BLOCK + r) * pre::WIDTH..(block * BLOCK + r + 1) * pre::WIDTH];
                if r < HALF_FULL_ROUNDS {
                    row[pre::IS_FULL] = Fld::ONE;
                    for i in 0..8 {
                        row[pre::RC0 + i] = Fld::from_u64(rc.initial[r][i].as_canonical_u64());
                    }
                } else if r < HALF_FULL_ROUNDS + PARTIAL_ROUNDS {
                    row[pre::IS_PARTIAL] = Fld::ONE;
                    row[pre::RC0] = Fld::from_u64(rc.internal[r - HALF_FULL_ROUNDS].as_canonical_u64());
                } else if r < ROUND_ROWS {
                    row[pre::IS_FULL] = Fld::ONE;
                    let k = r - HALF_FULL_ROUNDS - PARTIAL_ROUNDS;
                    for i in 0..8 {
                        row[pre::RC0 + i] = Fld::from_u64(rc.terminal[k][i].as_canonical_u64());
                    }
                } else {
                    row[pre::IS_IDLE] = Fld::ONE;
                }
                if r == 0 {
                    row[pre::IS_FIRST] = Fld::ONE;
                }
                if r == ROUND_ROWS - 1 {
                    row[pre::IS_LAST] = Fld::ONE;
                }
            }
        }
        RowMajorMatrix::new(v, pre::WIDTH)
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Poseidon2Air
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

        let (is_full, is_partial, is_first, is_last, is_idle) = (
            pcur(pre::IS_FULL),
            pcur(pre::IS_PARTIAL),
            pcur(pre::IS_FIRST),
            pcur(pre::IS_LAST),
            pcur(pre::IS_IDLE),
        );
        // Every row is exactly one of full/partial/idle (row-kind one-hot).
        b.assert_eq(is_full.clone() + is_partial.clone() + is_idle.clone(), one.clone());

        let is_real = v(col::IS_REAL);
        b.assert_bool(is_real.clone());

        let s: [AB::Expr; 8] = core::array::from_fn(|i| v(col::S0 + i));
        let x3: [AB::Expr; 8] = core::array::from_fn(|i| v(col::X3_0 + i));
        let x7: [AB::Expr; 8] = core::array::from_fn(|i| v(col::X7_0 + i));
        let inp: [AB::Expr; 8] = core::array::from_fn(|i| v(col::IN0 + i));
        let rc: [AB::Expr; 8] = core::array::from_fn(|i| pcur(pre::RC0 + i));

        // Block invariants: IN and IS_REAL persist within a block (reset only when the next
        // row starts a new block, i.e. `pnext(IS_FIRST) == 1`), and once IS_REAL drops to 0
        // across a block boundary it must stay 0 (padding is a block-aligned suffix).
        {
            let is_first_n = pnext(pre::IS_FIRST);
            let same_block = one.clone() - is_first_n.clone();
            let mut t = b.when_transition();
            for i in 0..8 {
                t.assert_zero(same_block.clone() * (n(col::IN0 + i) - inp[i].clone()));
            }
            t.assert_zero(same_block * (n(col::IS_REAL) - is_real.clone()));
            t.assert_zero((one.clone() - is_real.clone()) * n(col::IS_REAL) * is_first_n);
        }
        // Row 0 of a block: IN is exactly the raw absorbed state.
        for i in 0..8 {
            b.assert_zero(is_first.clone() * (inp[i].clone() - s[i].clone()));
        }

        // Full rounds: the S-box input is S+RC everywhere except row 0, where the initial
        // MDS-light layer applies first (Plonky3's `external_initial_permute_state`).
        let is_full_not_first = is_full.clone() - is_first.clone();
        let ms = mds_light(s.clone());
        for i in 0..8 {
            let pre_first = ms[i].clone() + rc[i].clone();
            b.assert_zero(is_first.clone() * (x3[i].clone() - cube(pre_first.clone())));
            b.assert_zero(is_first.clone() * (x7[i].clone() - x3[i].clone() * x3[i].clone() * pre_first));
            let pre_rest = s[i].clone() + rc[i].clone();
            b.assert_zero(is_full_not_first.clone() * (x3[i].clone() - cube(pre_rest.clone())));
            b.assert_zero(is_full_not_first.clone() * (x7[i].clone() - x3[i].clone() * x3[i].clone() * pre_rest));
        }
        let full_out = mds_light(x7.clone());
        for i in 0..8 {
            b.assert_zero(is_full.clone() * (n(col::S0 + i) - full_out[i].clone()));
        }

        // Partial rounds: S-box only on lane 0 (`add_rc_and_sbox` in
        // `p3_poseidon2::internal_permute_state` touches only `state[0]`); other lanes pass
        // X7 = S through unchanged (RC is pinned to 0 on lanes > 0 in the preprocessed trace).
        let pre0 = s[0].clone() + rc[0].clone();
        b.assert_zero(is_partial.clone() * (x3[0].clone() - cube(pre0.clone())));
        b.assert_zero(is_partial.clone() * (x7[0].clone() - x3[0].clone() * x3[0].clone() * pre0));
        for i in 1..8 {
            b.assert_zero(is_partial.clone() * (x7[i].clone() - s[i].clone()));
        }
        let partial_out = internal_matmul(x7.clone());
        for i in 0..8 {
            b.assert_zero(is_partial.clone() * (n(col::S0 + i) - partial_out[i].clone()));
        }

        // Idle rows: nothing else is constrained; MULT is forced to zero below regardless.

        // Bus: on the last round row of a real block, provide [IN, next-S] with count MULT.
        let mult = v(col::MULT);
        b.assert_zero(mult.clone() * (one.clone() - is_last.clone()));
        b.assert_zero(mult.clone() * (one - is_real));
        let out: [AB::Expr; 8] = core::array::from_fn(|i| n(col::S0 + i));
        let msg: Vec<AB::Expr> = inp.into_iter().chain(out).collect();
        bus::POSEIDON2.table_entry(b, msg, mult);
    }
}

/// Fills one 32-row block starting at `v[0]` (`v.len() == BLOCK * col::WIDTH`) with the
/// honest round-by-round computation of `permute(input)`, setting `IS_REAL` on every row iff
/// `is_real`. Returns the permutation's output (the state after the terminal full round),
/// which the caller writes nowhere explicitly — it is exactly what ends up in the block's
/// idle rows' `S0..7`, satisfying the AIR's `n(S) = full_out` constraint on the last round
/// row and exposed to the `POSEIDON2` bus via that same next-row read.
///
/// Mirrors `rand-zkvm-cuda/src/device/poseidon2.rs::permute`'s round loop exactly (see the
/// module doc comment for the initial-linear-layer fusion into row 0).
fn fill_block(v: &mut [F], input: [F; 8], is_real: bool) -> [F; 8] {
    let rc = round_constants();
    let mut s = input;
    for r in 0..BLOCK {
        let row = &mut v[r * col::WIDTH..(r + 1) * col::WIDTH];
        if is_real {
            row[col::IS_REAL] = F::ONE;
        }
        for i in 0..8 {
            row[col::IN0 + i] = input[i];
        }
        for i in 0..8 {
            row[col::S0 + i] = s[i];
        }
        if r < HALF_FULL_ROUNDS {
            let pre_state: [F; 8] = if r == 0 { mds_light(s) } else { s };
            let rc_row = rc.initial[r];
            let mut x7 = [F::ZERO; 8];
            for i in 0..8 {
                let p = pre_state[i] + rc_row[i];
                let x3 = p * p * p;
                row[col::X3_0 + i] = x3;
                x7[i] = x3 * x3 * p;
                row[col::X7_0 + i] = x7[i];
            }
            s = mds_light(x7);
        } else if r < HALF_FULL_ROUNDS + PARTIAL_ROUNDS {
            let rc0 = rc.internal[r - HALF_FULL_ROUNDS];
            let p0 = s[0] + rc0;
            let x3_0 = p0 * p0 * p0;
            row[col::X3_0] = x3_0;
            let mut x7 = s;
            x7[0] = x3_0 * x3_0 * p0;
            for i in 0..8 {
                row[col::X7_0 + i] = x7[i];
            }
            s = internal_matmul(x7);
        } else if r < ROUND_ROWS {
            let k = r - HALF_FULL_ROUNDS - PARTIAL_ROUNDS;
            let rc_row = rc.terminal[k];
            let mut x7 = [F::ZERO; 8];
            for i in 0..8 {
                let p = s[i] + rc_row[i];
                let x3 = p * p * p;
                row[col::X3_0 + i] = x3;
                x7[i] = x3 * x3 * p;
                row[col::X7_0 + i] = x7[i];
            }
            s = mds_light(x7);
        }
        // r in ROUND_ROWS..BLOCK: idle rows. X3/X7 stay at their `zero_vec` default (nothing
        // constrains them); `S` was already written above from the still-final `s`.
    }
    s
}

/// One 32-row block per `Poseidon2Event`, in event order, followed by as many padding blocks
/// (canonical all-zero input, `IS_REAL = 0`) as needed to reach `height`. Every block —
/// padding included — gets a genuine, AIR-satisfying permutation trace: see the module doc
/// comment's "Padding" section for why a merely-zeroed padding block would not verify.
pub fn poseidon2_trace(events: &[Poseidon2Event], height: usize) -> RowMajorMatrix<F> {
    assert_eq!(height % BLOCK, 0, "poseidon2 table height must be a multiple of {BLOCK}");
    let n_blocks = height / BLOCK;
    assert!(
        events.len() <= n_blocks,
        "poseidon2 table needs {} blocks for {} events, height {height}",
        events.len(),
        events.len()
    );
    let mut v = F::zero_vec(height * col::WIDTH);
    for blk in 0..n_blocks {
        let block_rows = &mut v[blk * BLOCK * col::WIDTH..(blk + 1) * BLOCK * col::WIDTH];
        if let Some(ev) = events.get(blk) {
            let out = fill_block(block_rows, ev.input, true);
            debug_assert_eq!(out, ev.output, "poseidon2_trace: recomputed output disagrees with event {blk}");
            block_rows[(ROUND_ROWS - 1) * col::WIDTH + col::MULT] = F::ONE;
        } else {
            let _ = fill_block(block_rows, [F::ZERO; 8], false);
        }
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
