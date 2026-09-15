//! The rVM's Poseidon2 chip (spec §5's ruling): **one row per permutation**, where the RV32
//! machine's table is one row per round in 32-row blocks. At the measured 51 595 permutations
//! per inner proof that is 2^16 rows of ~341 columns — 3.6× fewer cells than the round-per-row
//! shape, and the only one that fits a laptop's prover (spec §5).
//!
//! The 30 rounds are unrolled inside `eval` with the round constants baked in as literals (plan
//! R9 — a permutation-per-row chip has no periodic column structure, and ~240 constant
//! preprocessed columns would be opened at every FRI query for nothing). The constants, the
//! `mds_light`/`internal_matmul`/`cube` helpers and the `permute_scalar` reference are
//! **shared** with `shrugg_zkvm::tables::poseidon2`, so the chip's permutation is the machine's
//! own permutation by construction; the equality contract (`tests/poseidon2.rs`) pins it.
//!
//! ## Row kinds
//!
//! `IS_PERM` (the cpu's `POSEIDON2` instruction): the eight cells at `PTR` are the input,
//! permuted in place — 8 reads + 8 writes on `RAM`. `IS_SPONGE` (Task 9's `SPONGE`
//! instruction): the input is `[src(4) ‖ state(4..8)]` — four cells at `SRC_PTR` in lanes 0–3,
//! the state's own lanes 4–7 at `PTR + 4` — and the output is written to all eight cells at
//! `PTR` (4 + 4 + 8 `RAM` messages). The round arithmetic is identical for both; the kinds
//! differ only in the input's provenance, which is what the two buses distinguish.
use super::{bus, F};
use crate::emulator::PermEvent;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub use shrugg_zkvm::tables::poseidon2::{cube, internal_matmul, mds_light, round_constants};

pub const ROUNDS_F: usize = 8; // GOLDILOCKS_POSEIDON2_HALF_FULL_ROUNDS × 2
pub const ROUNDS_P: usize = 22; // GOLDILOCKS_POSEIDON2_PARTIAL_ROUNDS_8
pub const ROUNDS: usize = ROUNDS_F + ROUNDS_P; // 30

pub mod col {
    pub const IS_REAL: usize = 0;
    pub const MULT: usize = 1;
    pub const CLK: usize = 2;
    pub const PTR: usize = 3;
    pub const SRC_PTR: usize = 4;
    pub const IS_PERM: usize = 5;
    pub const IS_SPONGE: usize = 6;
    /// 8: the permutation's input state.
    pub const IN0: usize = 7;
    /// 29 × 8: the states after rounds 1..=29 (`R0 + (k-1)·8 + i` is lane `i` of the state after
    /// round `k`); the state after round 30 is `OUT`.
    pub const R0: usize = 15;
    /// 8: the permutation's output state.
    pub const OUT0: usize = R0 + 29 * 8;
    /// 8 full rounds × 8 lanes + 22 partial rounds × 1 lane = 86 S-box intermediates
    /// (`x³ = (s + rc)³`; `x⁷` is `x3·x3·(s + rc)` in the output expression, degree 3).
    pub const X3_0: usize = OUT0 + 8;
    pub const WIDTH: usize = X3_0 + 86;
}
use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct Poseidon2Air;

impl<Fld: Field> BaseAir<Fld> for Poseidon2Air {
    fn width(&self) -> usize { col::WIDTH }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Poseidon2Air
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let rc = round_constants();
        let lit = |x: F| AB::Expr::from_u64(x.as_canonical_u64());

        let is_real = v(IS_REAL);
        b.assert_bool(is_real.clone());
        // The multiplicity is pinned outright (audit-ZL2's pattern): a real row's permutation is
        // claimed on exactly one bus, a padding row's nowhere.
        b.assert_zero(v(MULT) - is_real.clone());
        let (is_perm, is_sponge) = (v(IS_PERM), v(IS_SPONGE));
        b.assert_bool(is_perm.clone());
        b.assert_bool(is_sponge.clone());
        b.assert_eq(is_perm.clone() + is_sponge.clone(), is_real.clone());
        // AGENTS.md invariant 1: the SPONGE message's source pointer is constrained on every row
        // kind that does not send it — zero there.
        b.assert_zero((one.clone() - is_sponge.clone()) * v(SRC_PTR));

        // ── the permutation, 30 rounds, every row (padding included: the M3.1 discipline — a
        // row that is not a genuine chained permutation does not exist in this table) ──
        let input: [AB::Expr; 8] = core::array::from_fn(|i| v(IN0 + i));
        let state_after = |k: usize| -> [AB::Expr; 8] {
            // The state after round `k` (1-based): rounds 1..=29 are `R0` columns, 30 is `OUT`.
            core::array::from_fn(|i| if k == ROUNDS { v(OUT0 + i) } else { v(R0 + (k - 1) * 8 + i) })
        };
        let mut round_in = mds_light(input);
        for r in 0..ROUNDS {
            let round_out = state_after(r + 1);
            if r < ROUNDS_F / 2 || r >= ROUNDS_F / 2 + ROUNDS_P {
                // A full round: S-box on every lane. X3 slot: initial rounds take 0..4, terminal
                // rounds 4..8.
                let slot = if r < ROUNDS_F / 2 { r } else { r - ROUNDS_P };
                let rc_r = if r < ROUNDS_F / 2 { &rc.initial[r] } else { &rc.terminal[r - ROUNDS_F / 2 - ROUNDS_P] };
                let x3: [AB::Expr; 8] = core::array::from_fn(|i| v(X3_0 + slot * 8 + i));
                let pre: [AB::Expr; 8] = core::array::from_fn(|i| round_in[i].clone() + lit(rc_r[i]));
                for i in 0..8 {
                    b.assert_zero(x3[i].clone() - cube(pre[i].clone()));
                }
                let out = mds_light(core::array::from_fn(|i| x3[i].clone() * x3[i].clone() * pre[i].clone()));
                for i in 0..8 {
                    b.assert_zero(round_out[i].clone() - out[i].clone());
                }
                round_in = round_out;
            } else {
                // A partial round: S-box on lane 0 only, the diagonal internal layer.
                let rc0 = lit(rc.internal[r - ROUNDS_F / 2]);
                let x3_0 = v(X3_0 + ROUNDS_F * 8 + (r - ROUNDS_F / 2));
                let pre0 = round_in[0].clone() + rc0;
                b.assert_zero(x3_0.clone() - cube(pre0.clone()));
                let mut x7 = round_in.clone();
                x7[0] = x3_0.clone() * x3_0 * pre0;
                let out = internal_matmul(x7);
                for i in 0..8 {
                    b.assert_zero(round_out[i].clone() - out[i].clone());
                }
                round_in = round_out;
            }
        }

        // ── buses ──
        let clk = v(CLK);
        let ptr = v(PTR);
        let sixteen = AB::Expr::from_u32(16);
        // The dispatch handle: the permutation's input and output never travel on these buses —
        // they are the `RAM` messages below (the keccak/sha256 pattern).
        bus::POSEIDON2.table_entry(b, [clk.clone(), ptr.clone()], is_perm.clone());
        bus::SPONGE.table_entry(b, [clk.clone(), ptr.clone(), v(SRC_PTR)], is_sponge.clone());
        // `IS_PERM`: 8 reads of the cells at `ptr`, 8 writes back. `IS_SPONGE`: 4 reads of the
        // source, 4 reads of the state's upper half, 8 writes. Timestamps are the dispatch row's
        // own slots, matching the emulator's access log exactly.
        for k in 0..8 {
            let ts_r = sixteen.clone() * clk.clone() + AB::Expr::from_u32(k as u32);
            let ts_w = sixteen.clone() * clk.clone() + AB::Expr::from_u32(8 + k as u32);
            let addr = ptr.clone() + AB::Expr::from_u32(k as u32);
            bus::RAM.send(b, [addr.clone(), ts_r, v(IN0 + k), AB::Expr::ZERO], Count::bounded(is_perm.clone(), 1));
            bus::RAM.send(b, [addr, ts_w, v(OUT0 + k), one.clone()], Count::bounded(is_perm.clone(), 1));
        }
        for k in 0..4 {
            let ts_r = sixteen.clone() * clk.clone() + AB::Expr::from_u32(k as u32);
            let addr = v(SRC_PTR) + AB::Expr::from_u32(k as u32);
            bus::RAM.send(b, [addr, ts_r, v(IN0 + k), AB::Expr::ZERO], Count::bounded(is_sponge.clone(), 1));
            let ts_r4 = sixteen.clone() * clk.clone() + AB::Expr::from_u32((4 + k) as u32);
            let addr4 = ptr.clone() + AB::Expr::from_u32((4 + k) as u32);
            bus::RAM.send(b, [addr4, ts_r4, v(IN0 + 4 + k), AB::Expr::ZERO], Count::bounded(is_sponge.clone(), 1));
        }
        for k in 0..8 {
            let ts_w = sixteen.clone() * clk.clone() + AB::Expr::from_u32((8 + k) as u32);
            let addr = ptr.clone() + AB::Expr::from_u32(k as u32);
            bus::RAM.send(b, [addr, ts_w, v(OUT0 + k), one.clone()], Count::bounded(is_sponge.clone(), 1));
        }
    }
}

pub const MIN_LOG_HEIGHT: u8 = 4;

/// One row per permutation plus one padding row, floored — the declared-height rule the proof
/// carries (`Proof::poseidon2_log_height`), like the RV32 keccak table's own.
pub fn poseidon2_log_height(perms: usize) -> u8 {
    super::pad_height(perms + 1, 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8
}

/// One row per `(clk, event)`, in event order, then padding. Every row — padding included —
/// carries a genuine chained permutation trace (the M3.1 discipline: the round constraints run
/// on every row, so an all-zero row would not verify). The clk is the dispatching cpu row's,
/// which is also the timestamp base of the row's `RAM` messages.
pub fn poseidon2_trace(events: &[(u32, PermEvent)], height: usize) -> RowMajorMatrix<F> {
    assert!(
        events.len() < height,
        "poseidon2 table needs a padding row: {} permutations, height {height}",
        events.len()
    );
    let mut v = F::zero_vec(height * col::WIDTH);
    for row in 0..height {
        let r = &mut v[row * col::WIDTH..(row + 1) * col::WIDTH];
        let (clk, input, output) = match events.get(row) {
            Some(&(clk, ev)) => {
                r[IS_REAL] = F::ONE;
                r[MULT] = F::ONE;
                r[PTR] = F::from_u64(ev.ptr);
                match ev.src {
                    None => r[IS_PERM] = F::ONE,
                    Some(src) => {
                        r[IS_SPONGE] = F::ONE;
                        r[SRC_PTR] = F::from_u64(src);
                    }
                }
                debug_assert_eq!(
                    ev.output,
                    shrugg_zkvm::tables::poseidon2::permute_scalar(ev.input),
                    "the emulator's PermEvent disagrees with the reference permutation"
                );
                (clk, ev.input, Some(ev.output))
            }
            None => (0, [F::ZERO; 8], None),
        };
        r[CLK] = F::from_u64(clk as u64);
        for i in 0..8 {
            r[IN0 + i] = input[i];
        }
        let out = fill_rounds(r, input);
        if let Some(want) = output {
            debug_assert_eq!(out, want, "the chip's own trace disagrees with the event's output");
        }
    }
    RowMajorMatrix::new(v, col::WIDTH)
}

/// The honest round-by-round computation over one row's columns: fills `R0..`, `OUT0..` and the
/// `X3` intermediates from `IN`, mirroring `permute_scalar` exactly. Returns the output state.
fn fill_rounds(r: &mut [F], input: [F; 8]) -> [F; 8] {
    let rc = round_constants();
    let mut round_in = mds_light(input);
    for round in 0..ROUNDS {
        let out = if round < ROUNDS_F / 2 || round >= ROUNDS_F / 2 + ROUNDS_P {
            let slot = if round < ROUNDS_F / 2 { round } else { round - ROUNDS_P };
            let rc_r = if round < ROUNDS_F / 2 { &rc.initial[round] } else { &rc.terminal[round - ROUNDS_F / 2 - ROUNDS_P] };
            let mut x7 = [F::ZERO; 8];
            for i in 0..8 {
                let p = round_in[i] + rc_r[i];
                let x3 = cube(p);
                r[X3_0 + slot * 8 + i] = x3;
                x7[i] = x3 * x3 * p;
            }
            mds_light(x7)
        } else {
            let p0 = round_in[0] + rc.internal[round - ROUNDS_F / 2];
            let x3 = cube(p0);
            r[X3_0 + ROUNDS_F * 8 + (round - ROUNDS_F / 2)] = x3;
            let mut x7 = round_in;
            x7[0] = x3 * x3 * p0;
            internal_matmul(x7)
        };
        if round + 1 == ROUNDS {
            for i in 0..8 {
                r[OUT0 + i] = out[i];
            }
        } else {
            for i in 0..8 {
                r[R0 + round * 8 + i] = out[i];
            }
        }
        round_in = out;
    }
    round_in
}
