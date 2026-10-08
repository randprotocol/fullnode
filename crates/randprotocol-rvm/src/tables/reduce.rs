//! The reduction chip (Task 8; phase 3 Cut D, 2026-10-05): one chip row per reduction column.
//!
//! **The layout is preprocessed.** Every run's addresses — its opened values, its row, its
//! inverse key, the chain's alpha and result cells — are compile-time constants of the program,
//! listed in `Program::reduce_layout`. The chip's preprocessed region holds one row per entry,
//! with a witness `MULT` (the `ProgramAir` pattern), and is committed by the verifier key. Each
//! run looks up its entry on its first row (`REDUCE_LAYOUT`), so a descriptor is never a witness
//! value. The aggregate program runs every entry N times; `MULT` is N.
//!
//! **Chains carry in the chip.** A run's rows step `acc += apow·(pz − px)·inv`,
//! `apow ·= alpha`; a run whose entry carries hands both to the next row, the next entry's first
//! row, dispatched by the very next cpu row (`n(CLK) = CLK + 1`, `n(ENTRY) = ENTRY + 1`). A chain
//! starts at `acc = 0`, `apow = 1`, reads alpha once, and writes its result once.
//!
//! Every message is degree 1: its counts are columns (`WRITES`, `READ_ALPHA` are constrained
//! products) and its values are columns (`OUT` is constrained to the step's output).
//!
//! **The fold row kind (Cut E2).** A `FOLD` dispatch is a run of `2a` rows under its cpu clock,
//! after the reduce rows: phase 1 (rows `K = 0..a`) reads `y_K` and adds `C_j·y_K` into eight
//! extension accumulators, the coefficients `C_j` looked up on `FOLD_COEFF` from a 14-row
//! preprocessed table (`emulator::fold_coefficients`) — the inverse DFT, so accumulator `j` ends
//! at `B_{a−1−j}`; phase 2 (rows `K = a..2a`) is Horner at `u` over the accumulators, shifted down
//! one pair a row. The last row writes `Σ_m B_m·u^m` after the row's salts. Every constraint is
//! degree 2 before its gating; there is no extension inverse.
//!
//! **The pow row kind (Cut F).** A `POW` dispatch is a run of `L` rows under its cpu clock, after
//! the fold rows: row `K` reads the bit at `buf + off + L − 1 − K` (boolean, checked here), carries
//! `P_G = G^{2^K}` by squaring and steps `S ← S·(1 + bit·(P_G − 1))` from `S = base`; the last row
//! writes `S` to `buf + 64`. `(clk, buf, off + 256·L, G, base)` arrive on the run's first row from
//! the cpu's `POW` lookup, so neither `G` nor `base` is the witness's choice.
use super::{bus, range::RangeCounts, F};
use crate::emulator::{
    Event, TS_ALPHA0, TS_ALPHA1, TS_FOLD_RES0, TS_FOLD_RES1, TS_FOLD_Y0, TS_FOLD_Y1, TS_KEY0, TS_KEY1, TS_POW_BIT, TS_POW_OUT, TS_RES0,
    TS_RES1, TS_RUN_PX, TS_RUN_PZ0, TS_RUN_PZ1,
};
use crate::isa::ReduceEntry;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use std::sync::Arc;

pub mod col {
    pub const IS_REAL: usize = 0;
    pub const IS_FIRST: usize = 1;
    pub const IS_LAST: usize = 2;
    pub const CLK: usize = 3;
    pub const ENTRY: usize = 4;
    pub const ADDR_V: usize = 5;
    pub const ADDR_R: usize = 6;
    /// The entry's last row cell, from the layout: `IS_LAST ⟺ ADDR_R = ROW_END` (R5).
    pub const ROW_END: usize = 7;
    pub const END_INV: usize = 8;
    pub const KEY: usize = 9;
    pub const ALPHA_ADDR: usize = 10;
    pub const RES: usize = 11;
    pub const CHAIN_START: usize = 12;
    pub const CARRY: usize = 13;
    pub const ACC0: usize = 14;
    pub const ACC1: usize = 15;
    pub const APOW0: usize = 16;
    pub const APOW1: usize = 17;
    pub const INV0: usize = 18;
    pub const INV1: usize = 19;
    pub const ALPHA0: usize = 20;
    pub const ALPHA1: usize = 21;
    pub const PZ0: usize = 22;
    pub const PZ1: usize = 23;
    pub const PX: usize = 24;
    /// The step's output accumulator on a last row: the result written when the chain closes.
    pub const OUT0: usize = 25;
    pub const OUT1: usize = 26;
    /// `IS_LAST·(1 − CARRY)` and `IS_FIRST·CHAIN_START`, as columns so every count is degree 1.
    pub const WRITES: usize = 27;
    pub const READ_ALPHA: usize = 28;
    /// The provider region's multiplicity: how many runs of this row's layout entry executed.
    pub const MULT: usize = 29;
    // ── the fold row kind (Cut E2): a run of 2a rows under one clock ──
    pub const IS_FOLD: usize = 30;
    pub const F_FIRST: usize = 31;
    /// Phase 1 (rows 0..a): accumulate the inverse DFT; phase 2 (rows a..2a): Horner.
    pub const F_PH1: usize = 32;
    pub const F_LAST: usize = 33;
    /// The row's index in its run, 0..2a.
    pub const F_K: usize = 34;
    pub const F_A: usize = 35;
    pub const F_MSG: usize = 36;
    pub const U0: usize = 37;
    pub const U1: usize = 38;
    pub const Y0: usize = 39;
    pub const Y1: usize = 40;
    /// The phase-1 row's eight coefficients, looked up from the preprocessed table.
    pub const C0: usize = 41; // 8
    /// Eight extension accumulators; after phase 1, pair j holds B_{a−1−j}; phase 2 shifts them.
    pub const D0: usize = 49; // 16
    pub const FACC0: usize = 65;
    pub const FACC1: usize = 66;
    pub const FOUT0: usize = 67;
    pub const FOUT1: usize = 68;
    /// The coefficient table's multiplicity.
    pub const MULT_C: usize = 69;
    // ── the pow row kind (Cut F): one row per index bit, high bit first ──
    pub const IS_POW: usize = 70;
    pub const P_FIRST: usize = 71;
    pub const P_LAST: usize = 72;
    pub const P_K: usize = 73;
    pub const P_BASE: usize = 74;
    /// The immediate's two bytes: `imm = P_OFF + 256·P_L`, both range-checked on the first row.
    pub const P_OFF: usize = 75;
    pub const P_L: usize = 76;
    pub const P_BIT: usize = 77;
    /// `G^{2^K}` and the running product before this row's bit.
    pub const P_G: usize = 78;
    pub const P_S: usize = 79;
    pub const P_OUT: usize = 80;
    pub const WIDTH: usize = 81;
}
pub mod pre {
    pub const L_IS_ENTRY: usize = 0;
    pub const L_ENTRY: usize = 1;
    pub const L_ADDR_V: usize = 2;
    pub const L_ADDR_R: usize = 3;
    pub const L_ROW_END: usize = 4;
    pub const L_KEY: usize = 5;
    pub const L_ALPHA: usize = 6;
    pub const L_RES: usize = 7;
    /// `chain_start + 2·carry`.
    pub const L_FLAGS: usize = 8;
    /// Cut E2: the fold coefficient table (`emulator::fold_coefficients`), 14 rows — arity 2 at
    /// rows 0–1, 4 at 2–5, 8 at 6–13 (row `a − 2 + k`).
    pub const C_IS_ROW: usize = 9;
    pub const C_A: usize = 10;
    pub const C_K: usize = 11;
    pub const C_V0: usize = 12; // 8
    pub const WIDTH: usize = 20;
}
use col::*;

pub const MIN_LOG_HEIGHT: u8 = 4;

/// Cut E2: the fold coefficient table's rows (arity 2, 4 and 8: 2 + 4 + 8), part of the provider
/// region whatever the layout.
pub const FOLD_COEFF_ROWS: usize = 14;

/// The chip carries its program's layout (the preprocessed region is built from it) and the
/// declared height that region is committed at.
#[derive(Clone, Debug)]
pub struct ReduceAir {
    pub layout: Arc<Vec<ReduceEntry>>,
    pub height: usize,
}

impl ReduceAir {
    pub fn new(layout: Arc<Vec<ReduceEntry>>, height: usize) -> Self {
        assert!(height >= provider_rows(&layout), "the reduce table must hold its provider region");
        ReduceAir { layout, height }
    }
}

/// Rows the preprocessed provider region occupies: the layout, and (Cut E2) the fold coefficient
/// table beside it in its own columns.
pub fn provider_rows(layout: &[ReduceEntry]) -> usize {
    layout.len().max(FOLD_COEFF_ROWS)
}

impl<Fld: Field> BaseAir<Fld> for ReduceAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let mut v = Fld::zero_vec(self.height * pre::WIDTH);
        for (i, e) in self.layout.iter().enumerate() {
            let r = &mut v[i * pre::WIDTH..(i + 1) * pre::WIDTH];
            r[pre::L_IS_ENTRY] = Fld::ONE;
            r[pre::L_ENTRY] = Fld::from_u64(i as u64);
            r[pre::L_ADDR_V] = Fld::from_u64(e.vals);
            r[pre::L_ADDR_R] = Fld::from_u64(e.row);
            r[pre::L_ROW_END] = Fld::from_u64(e.row + e.len as u64 - 1);
            r[pre::L_KEY] = Fld::from_u64(e.key);
            r[pre::L_ALPHA] = Fld::from_u64(e.alpha);
            r[pre::L_RES] = Fld::from_u64(e.res);
            r[pre::L_FLAGS] = Fld::from_u64(e.chain_start as u64 + 2 * e.carry as u64);
        }
        for la in 1..=3usize {
            let a = 1usize << la;
            for (k, c) in crate::emulator::fold_coefficients(la).iter().enumerate() {
                let r = &mut v[(a - 2 + k) * pre::WIDTH..(a - 1 + k) * pre::WIDTH];
                r[pre::C_IS_ROW] = Fld::ONE;
                r[pre::C_A] = Fld::from_u64(a as u64);
                r[pre::C_K] = Fld::from_u64(k as u64);
                for j in 0..8 {
                    r[pre::C_V0 + j] = Fld::from_u64(p3_field::PrimeField64::as_canonical_u64(&c[j]));
                }
            }
        }
        Some(RowMajorMatrix::new(v, pre::WIDTH))
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ReduceAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let l = |i: usize| -> AB::Expr { p.current(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let seven = AB::Expr::from_u64(7);
        let sixteen = AB::Expr::from_u32(16);

        let (is_real, is_first, is_last) = (v(IS_REAL), v(IS_FIRST), v(IS_LAST));
        for c in [IS_REAL, IS_FIRST, IS_LAST, CHAIN_START, CARRY] {
            b.assert_bool(v(c));
        }
        // V-OPCODES-1: both run-boundary kinds exist only on real rows.
        b.assert_zero(is_first.clone() * (one.clone() - is_real.clone()));
        b.assert_zero(is_last.clone() * (one.clone() - is_real.clone()));
        // R5: IS_LAST ⟺ ADDR_R = ROW_END on a real row (a last row sits there; a real non-last
        // row does not, witnessed by the inverse).
        let d = v(ADDR_R) - v(ROW_END);
        b.assert_zero(is_last.clone() * d.clone());
        b.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * (one.clone() - d * v(END_INV)));
        // The two count columns.
        b.assert_zero(v(WRITES) - is_last.clone() * (one.clone() - v(CARRY)));
        b.assert_zero(v(READ_ALPHA) - is_first.clone() * v(CHAIN_START));
        // A chain starts at acc = 0, apow = 1.
        b.assert_zero(v(READ_ALPHA) * v(ACC0));
        b.assert_zero(v(READ_ALPHA) * v(ACC1));
        b.assert_zero(v(READ_ALPHA) * (v(APOW0) - one.clone()));
        b.assert_zero(v(READ_ALPHA) * v(APOW1));
        // AGENTS.md invariant 2 on the provider: a multiplicity only on a layout row.
        b.assert_zero(v(MULT) * (one.clone() - l(pre::L_IS_ENTRY)));

        // ── boundaries and the run structure (ZKR-4) ──
        b.when_first_row().assert_zero(is_real.clone() * (one.clone() - is_first.clone()));
        b.when_first_row().assert_zero(is_first.clone() * (one.clone() - v(CHAIN_START)));
        // (The last-row rule and the padding rule are the three-kind ordering below, Cut E2.)
        {
            let mut t = b.when_transition();
            t.assert_zero(is_last.clone() * n(IS_REAL) * (one.clone() - n(IS_FIRST)));
            t.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * (one.clone() - n(IS_REAL)));
            t.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * n(IS_FIRST));
        }

        // ── the column step: diff = pz − px; t = apow·diff; t2 = t·inv; acc += t2; apow ·= alpha ──
        let (diff0, diff1) = (v(PZ0) - v(PX), v(PZ1));
        let t0 = v(APOW0) * diff0.clone() + seven.clone() * v(APOW1) * diff1.clone();
        let t1 = v(APOW0) * diff1 + v(APOW1) * diff0;
        let t2_0 = t0.clone() * v(INV0) + seven.clone() * t1.clone() * v(INV1);
        let t2_1 = t0 * v(INV1) + t1 * v(INV0);
        let acc_next0 = v(ACC0) + t2_0;
        let acc_next1 = v(ACC1) + t2_1;
        let apow_next0 = v(APOW0) * v(ALPHA0) + seven.clone() * v(APOW1) * v(ALPHA1);
        let apow_next1 = v(APOW0) * v(ALPHA1) + v(APOW1) * v(ALPHA0);
        b.assert_zero(is_last.clone() * (v(OUT0) - acc_next0.clone()));
        b.assert_zero(is_last.clone() * (v(OUT1) - acc_next1.clone()));

        // ── within an entry: the step chains, every per-entry column is carried ──
        let in_run_next = n(IS_REAL) * (one.clone() - n(IS_FIRST));
        {
            let mut t = b.when_transition();
            t.assert_zero(in_run_next.clone() * (n(ACC0) - acc_next0.clone()));
            t.assert_zero(in_run_next.clone() * (n(ACC1) - acc_next1.clone()));
            t.assert_zero(in_run_next.clone() * (n(APOW0) - apow_next0.clone()));
            t.assert_zero(in_run_next.clone() * (n(APOW1) - apow_next1.clone()));
            // Pinned by an isolating forgery or the carry rule in `tests/tables.rs`: the
            // addresses, `CLK`, `RES`, `ROW_END` (R5's end marker — uncarried, a run ends early and
            // skips columns). Kept, but redundant for a program that dispatches each chain's
            // entries in order — every builder-emitted program; the emulator refuses any other
            // order (`ReduceChain`) — so no forgery isolates them (the final review, 2026-10-06):
            // `ENTRY` and `CARRY` matter only on a last row, and the next entry's first row is
            // fixed by the cpu's `REDUCE [clk + 1, entry + 1]` dispatch and its layout lookup,
            // whose flags `check_layout`'s chain rules tie to this entry's; `CHAIN_START` gates
            // nothing off a first row. (Over a program that skips an entry, `ENTRY`'s carry and
            // the entry step are what refuse the skip: `a_carry_followed_by_the_wrong_entry_…`.)
            for c in [INV0, INV1, ALPHA0, ALPHA1, CLK, ENTRY, ROW_END, KEY, ALPHA_ADDR, RES, CHAIN_START, CARRY] {
                t.assert_zero(in_run_next.clone() * (n(c) - v(c)));
            }
            t.assert_zero(in_run_next.clone() * (n(ADDR_V) - v(ADDR_V) - AB::Expr::from_u32(2)));
            t.assert_zero(in_run_next.clone() * (n(ADDR_R) - v(ADDR_R) - one.clone()));
        }
        // ── across entries (R4): a carrying last row hands acc, apow and alpha to the next row,
        // which is the next entry's first row at the next clock; a continuation entry is entered
        // only that way ──
        let carry = is_last.clone() * v(CARRY);
        {
            let mut t = b.when_transition();
            t.assert_zero(carry.clone() * (one.clone() - n(IS_FIRST)));
            t.assert_zero(carry.clone() * n(CHAIN_START));
            t.assert_zero(carry.clone() * (n(ENTRY) - v(ENTRY) - one.clone()));
            t.assert_zero(carry.clone() * (n(CLK) - v(CLK) - one.clone()));
            t.assert_zero(carry.clone() * (n(ACC0) - acc_next0));
            t.assert_zero(carry.clone() * (n(ACC1) - acc_next1));
            t.assert_zero(carry.clone() * (n(APOW0) - apow_next0));
            t.assert_zero(carry.clone() * (n(APOW1) - apow_next1));
            t.assert_zero(carry.clone() * (n(ALPHA0) - v(ALPHA0)));
            t.assert_zero(carry.clone() * (n(ALPHA1) - v(ALPHA1)));
            t.assert_zero(n(IS_FIRST) * (one.clone() - n(CHAIN_START)) * (one.clone() - carry));
        }

        // ── kinds: reduce rows, then fold rows, then pow rows (Cut F), then padding ──
        let (is_fold, f_first, f_ph1, f_last) = (v(IS_FOLD), v(F_FIRST), v(F_PH1), v(F_LAST));
        for c in [IS_FOLD, F_FIRST, F_PH1, F_LAST] {
            b.assert_bool(v(c));
        }
        b.assert_zero(is_real.clone() * is_fold.clone());
        b.assert_zero(v(IS_POW) * is_real.clone());
        b.assert_zero(v(IS_POW) * is_fold.clone());
        for f in [f_first.clone(), f_ph1.clone(), f_last.clone()] {
            b.assert_zero(f * (one.clone() - is_fold.clone()));
        }
        b.assert_zero(v(MULT_C) * (one.clone() - l(pre::C_IS_ROW)));
        b.when_last_row().assert_zero(is_real.clone() + is_fold.clone() + v(IS_POW));
        b.when_first_row().assert_zero(is_fold.clone() * (one.clone() - f_first.clone()));
        {
            let mut t = b.when_transition();
            t.assert_zero((one.clone() - is_real.clone() - is_fold.clone() - v(IS_POW)) * (n(IS_REAL) + n(IS_FOLD) + n(IS_POW)));
            t.assert_zero(is_fold.clone() * n(IS_REAL));
            t.assert_zero(v(IS_POW) * (n(IS_REAL) + n(IS_FOLD)));
            // A run starts at K = 0 in phase 1 with zero accumulators, ends on F_LAST, and only there.
            t.assert_zero(is_fold.clone() * (one.clone() - f_last.clone()) * (one.clone() - n(IS_FOLD)));
            t.assert_zero(is_fold.clone() * (one.clone() - f_last.clone()) * n(F_FIRST));
            t.assert_zero(f_last.clone() * n(IS_FOLD) * (one.clone() - n(F_FIRST)));
            // A fold row entered from the last reduce row is a run's first row too — without
            // this, a headless run (no F_FIRST, so no FOLD message) could still write a forged
            // result at a clock of the prover's choosing (controller review, 2026-10-05).
            t.assert_zero(is_last.clone() * n(IS_FOLD) * (one.clone() - n(F_FIRST)));
        }
        b.assert_zero(f_first.clone() * v(F_K));
        b.assert_zero(f_first.clone() * (one.clone() - f_ph1.clone()));
        for j in 0..16 {
            b.assert_zero(f_first.clone() * v(D0 + j));
        }
        b.assert_zero(f_last.clone() * (v(F_K) - AB::Expr::from_u32(2) * v(F_A) + one.clone()));
        b.assert_zero(f_last.clone() * f_ph1.clone());
        // Horner's step, ext × ext: (FACC·U + D_0), the value the last row writes.
        let horner0 = v(FACC0) * v(U0) + seven.clone() * v(FACC1) * v(U1) + v(D0);
        let horner1 = v(FACC0) * v(U1) + v(FACC1) * v(U0) + v(D0 + 1);
        b.assert_zero(f_last.clone() * (v(FOUT0) - horner0.clone()));
        b.assert_zero(f_last.clone() * (v(FOUT1) - horner1.clone()));
        {
            let fr = n(IS_FOLD) * (one.clone() - n(F_FIRST));
            let mut t = b.when_transition();
            for c in [CLK, F_MSG, F_A, U0, U1] {
                t.assert_zero(fr.clone() * (n(c) - v(c)));
            }
            t.assert_zero(fr.clone() * (n(F_K) - v(F_K) - one.clone()));
            // Phase 1 is a prefix of the run, and it ends exactly at K = a − 1. (The prefix rule is
            // defence in depth: a phase-1 row after a phase-2 row has K ≥ a, and the committed
            // coefficient table has no `(a, K ≥ a)` row for its `FOLD_COEFF` lookup — the final
            // review, 2026-10-06.)
            t.assert_zero(fr.clone() * (one.clone() - f_ph1.clone()) * n(F_PH1));
            let switch = fr.clone() * f_ph1.clone() * (one.clone() - n(F_PH1));
            t.assert_zero(switch.clone() * (n(F_K) - v(F_A)));
            t.assert_zero(switch.clone() * n(FACC0));
            t.assert_zero(switch * n(FACC1));
            // Phase 1: accumulator pair j += C_j·y (base × ext).
            for j in 0..8 {
                t.assert_zero(fr.clone() * f_ph1.clone() * (n(D0 + 2 * j) - v(D0 + 2 * j) - v(C0 + j) * v(Y0)));
                t.assert_zero(fr.clone() * f_ph1.clone() * (n(D0 + 2 * j + 1) - v(D0 + 2 * j + 1) - v(C0 + j) * v(Y1)));
            }
            // Phase 2: Horner on the top pair, the pairs shift down, zero enters at the top.
            let ph2 = fr * (one.clone() - f_ph1.clone());
            t.assert_zero(ph2.clone() * (n(FACC0) - horner0));
            t.assert_zero(ph2.clone() * (n(FACC1) - horner1));
            for j in 0..14 {
                t.assert_zero(ph2.clone() * (n(D0 + j) - v(D0 + j + 2)));
            }
            t.assert_zero(ph2.clone() * n(D0 + 14));
            t.assert_zero(ph2 * n(D0 + 15));
        }

        // ── the pow row kind (Cut F) ──
        let (is_pow, p_first, p_last) = (v(IS_POW), v(P_FIRST), v(P_LAST));
        for c in [IS_POW, P_FIRST, P_LAST, P_BIT] {
            b.assert_bool(v(c));
        }
        b.assert_zero(p_first.clone() * (one.clone() - is_pow.clone()));
        b.assert_zero(p_last.clone() * (one.clone() - is_pow.clone()));
        b.when_first_row().assert_zero(is_pow.clone() * (one.clone() - p_first.clone()));
        b.assert_zero(p_first.clone() * v(P_K));
        b.assert_zero(p_last.clone() * (v(P_K) - v(P_L) + one.clone()));
        let step = v(P_S) * (one.clone() + v(P_BIT) * (v(P_G) - one.clone()));
        b.assert_zero(p_last.clone() * (v(P_OUT) - step.clone()));
        {
            let mut t = b.when_transition();
            t.assert_zero(is_pow.clone() * (one.clone() - p_last.clone()) * (one.clone() - n(IS_POW)));
            t.assert_zero(is_pow.clone() * (one.clone() - p_last.clone()) * n(P_FIRST));
            t.assert_zero(p_last.clone() * n(IS_POW) * (one.clone() - n(P_FIRST)));
            // A pow row entered from any other kind (the last reduce row, the last fold row) is a
            // run's first row: a headless run sends no `POW` message, and would still write its
            // output at a clock and base of the prover's choosing.
            t.assert_zero((one.clone() - is_pow.clone()) * n(IS_POW) * (one.clone() - n(P_FIRST)));
            let pr = n(IS_POW) * (one.clone() - n(P_FIRST));
            for c in [CLK, P_BASE, P_OFF, P_L] {
                t.assert_zero(pr.clone() * (n(c) - v(c)));
            }
            t.assert_zero(pr.clone() * (n(P_K) - v(P_K) - one.clone()));
            t.assert_zero(pr.clone() * (n(P_G) - v(P_G) * v(P_G)));
            t.assert_zero(pr * (n(P_S) - step));
        }

        // ── buses ──
        bus::REDUCE.table_entry(b, [v(CLK), v(ENTRY)], is_first.clone());
        let flags = v(CHAIN_START) + AB::Expr::from_u32(2) * v(CARRY);
        bus::REDUCE_LAYOUT.lookup_key(
            b,
            [v(ENTRY), v(ADDR_V), v(ADDR_R), v(ROW_END), v(KEY), v(ALPHA_ADDR), v(RES), flags],
            Count::bounded(is_first.clone(), 1),
        );
        bus::REDUCE_LAYOUT.table_entry(
            b,
            [l(pre::L_ENTRY), l(pre::L_ADDR_V), l(pre::L_ADDR_R), l(pre::L_ROW_END), l(pre::L_KEY), l(pre::L_ALPHA), l(pre::L_RES), l(pre::L_FLAGS)],
            v(MULT),
        );
        let clk = v(CLK);
        let ts = |slot: u32| sixteen.clone() * clk.clone() + AB::Expr::from_u32(slot);
        let zero = AB::Expr::ZERO;
        bus::RAM.send(b, [v(KEY), ts(TS_KEY0), v(INV0), zero.clone()], Count::bounded(is_first.clone(), 1));
        bus::RAM.send(b, [v(KEY) + one.clone(), ts(TS_KEY1), v(INV1), zero.clone()], Count::bounded(is_first.clone(), 1));
        bus::RAM.send(b, [v(ALPHA_ADDR), ts(TS_ALPHA0), v(ALPHA0), zero.clone()], Count::bounded(v(READ_ALPHA), 1));
        bus::RAM.send(b, [v(ALPHA_ADDR) + one.clone(), ts(TS_ALPHA1), v(ALPHA1), zero.clone()], Count::bounded(v(READ_ALPHA), 1));
        bus::RAM.send(b, [v(ADDR_V), ts(TS_RUN_PZ0), v(PZ0), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::RAM.send(b, [v(ADDR_V) + one.clone(), ts(TS_RUN_PZ1), v(PZ1), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::RAM.send(b, [v(ADDR_R), ts(TS_RUN_PX), v(PX), zero], Count::bounded(is_real, 1));
        bus::RAM.send(b, [v(RES), ts(TS_RES0), v(OUT0), one.clone()], Count::bounded(v(WRITES), 1));
        bus::RAM.send(b, [v(RES) + one.clone(), ts(TS_RES1), v(OUT1), one.clone()], Count::bounded(v(WRITES), 1));

        // ── the fold kind's messages (Cut E2): the dispatch on the run's first row, a coefficient
        // lookup and the value's two reads on every phase-1 row, the result's two writes on the
        // last row — every count a flag column, every address and value a carried column ──
        bus::FOLD.table_entry(b, [v(CLK), v(F_MSG), v(U0), v(U1), v(F_A)], f_first.clone());
        let coeff_msg: Vec<AB::Expr> = [v(F_A), v(F_K)].into_iter().chain((0..8).map(|j| v(C0 + j))).collect();
        bus::FOLD_COEFF.lookup_key(b, coeff_msg, Count::bounded(f_ph1.clone(), 1));
        let table_msg: Vec<AB::Expr> = [l(pre::C_A), l(pre::C_K)].into_iter().chain((0..8).map(|j| l(pre::C_V0 + j))).collect();
        bus::FOLD_COEFF.table_entry(b, table_msg, v(MULT_C));
        let fts = |slot: u32| sixteen.clone() * v(CLK) + AB::Expr::from_u32(slot);
        let y_addr = v(F_MSG) + AB::Expr::from_u32(2) * v(F_K);
        bus::RAM.send(b, [y_addr.clone(), fts(TS_FOLD_Y0), v(Y0), AB::Expr::ZERO], Count::bounded(f_ph1.clone(), 1));
        bus::RAM.send(b, [y_addr + one.clone(), fts(TS_FOLD_Y1), v(Y1), AB::Expr::ZERO], Count::bounded(f_ph1, 1));
        let res = v(F_MSG) + AB::Expr::from_u32(2) * v(F_A) + AB::Expr::from_u32(crate::isa::FOLD_SALT_CELLS as u32);
        bus::RAM.send(b, [res.clone(), fts(TS_FOLD_RES0), v(FOUT0), one.clone()], Count::bounded(f_last.clone(), 1));
        bus::RAM.send(b, [res + one.clone(), fts(TS_FOLD_RES1), v(FOUT1), one.clone()], Count::bounded(f_last, 1));

        // ── the pow kind's messages (Cut F): the dispatch and the immediate's two bytes on the run's
        // first row, one bit read a row, the output write on the last row ──
        let imm = v(P_OFF) + AB::Expr::from_u32(256) * v(P_L);
        bus::POW.table_entry(b, [v(CLK), v(P_BASE), imm, v(P_G), v(P_S)], p_first.clone());
        for c in [P_OFF, P_L] {
            bus::RANGE8.lookup_key(b, [v(c)], Count::bounded(p_first.clone(), 1));
        }
        let pts = |slot: u32| sixteen.clone() * v(CLK) + AB::Expr::from_u32(slot);
        let bit_addr = v(P_BASE) + v(P_OFF) + v(P_L) - one.clone() - v(P_K);
        bus::RAM.send(b, [bit_addr, pts(TS_POW_BIT), v(P_BIT), AB::Expr::ZERO], Count::bounded(is_pow, 1));
        bus::RAM.send(b, [v(P_BASE) + AB::Expr::from_u32(64), pts(TS_POW_OUT), v(P_OUT), one], Count::bounded(p_last, 1));
    }
}

/// The declared log-height: the runs plus one padding row, and at least the provider region,
/// floored — with `0` the "no reduce table" value (the keccak pattern, `machine::chips`).
pub fn reduce_log_height(rows: usize, provider: usize) -> u8 {
    if rows == 0 {
        return 0;
    }
    super::pad_height((rows + 1).max(provider), 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8
}

/// The chip rows one pass over `program`'s instructions contributes — the static twin of
/// `reduce_rows + fold_rows + pow_rows` over a run's events (the final fix wave, the whole-branch
/// review's Important 2): a `REDUCE` its layout entry's length, a `FOLD` `2a`, a `POW` its `L`. All
/// three are compile-time constants of the program the verifier key commits, so a verifier can
/// recompute them from the program alone, with nothing the proof declares. An instruction no run
/// can execute (an entry past the layout, an arity outside {2, 4, 8}) contributes nothing.
///
/// It equals the run's rows for a program that executes each of these instructions exactly once
/// per inner proof: the straight-line single-proof program (`programs::verify_rv32`) and the
/// aggregate program (`programs::verify_rv32n`), all of whose `REDUCE`/`FOLD`/`POW`s sit in the
/// N-proof loop's body — so an N-proof run has `N ×` this many (`machine::canonical_reduce_log_height`;
/// `tests/aggregate.rs` checks the equality against emulated runs).
pub fn program_rows(program: &crate::isa::Program) -> u64 {
    use crate::isa::Op;
    use p3_field::PrimeField64;
    program
        .instrs
        .iter()
        .map(|x| {
            let imm = x.b.as_canonical_u64();
            match x.op {
                Op::Reduce => usize::try_from(imm).ok().and_then(|k| program.reduce_layout.get(k)).map_or(0, |e| e.len as u64),
                Op::Fold if matches!(imm, 2 | 4 | 8) => 2 * imm,
                Op::Pow => imm / 256,
                _ => 0,
            }
        })
        .fold(0u64, u64::saturating_add)
}

/// The `REDUCE` events, in execution order.
pub fn reduce_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.reduce.is_some()).collect()
}

/// One chip row per reduced column.
pub fn reduce_rows(events: &[&Event]) -> usize {
    events.iter().map(|e| e.reduce.unwrap().len as usize).sum()
}

/// The `FOLD` events, in execution order.
pub fn fold_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.fold.is_some()).collect()
}

/// Two chip rows per fold value.
pub fn fold_rows(events: &[&Event]) -> usize {
    events.iter().map(|e| 2 * e.fold.unwrap().arity as usize).sum()
}

/// The `POW` events, in execution order (Cut F).
pub fn pow_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.pow.is_some()).collect()
}

/// One chip row per index bit.
pub fn pow_rows(events: &[&Event]) -> usize {
    events.iter().map(|e| e.pow.unwrap().len as usize).sum()
}

/// The runs in execution order (a chain's entries are consecutive dispatches, so adjacent), then
/// (Cut E2) the fold runs, (Cut F) the pow runs, the provider regions' multiplicities, and
/// all-zero padding. `counts` takes the pow runs' immediate bytes (`RANGE8`).
pub fn reduce_trace(
    layout: &[ReduceEntry],
    events: &[&Event],
    folds: &[&Event],
    pows: &[&Event],
    height: usize,
    counts: &mut RangeCounts,
) -> RowMajorMatrix<F> {
    let n_rows = reduce_rows(events) + fold_rows(folds) + pow_rows(pows);
    assert!(
        n_rows < height && provider_rows(layout) <= height,
        "reduce table: {n_rows} rows plus one padding row, and a provider region of {} rows ({} layout entries, the \
         {FOLD_COEFF_ROWS}-row coefficient table), against height {height}",
        provider_rows(layout),
        layout.len()
    );
    let mut v = F::zero_vec(height * WIDTH);
    let mut row = 0usize;
    for e in events {
        let ev = e.reduce.unwrap();
        let le = layout[ev.entry as usize];
        let (mut acc, mut apow) = (ev.acc_in, ev.apow_in);
        // The event's log: the key's two reads, the alpha's two at a chain start, then three per column.
        let mut reads = e.mem.iter().skip(if le.chain_start { 4 } else { 2 });
        let row_end = le.row + le.len as u64 - 1;
        for k in 0..le.len as u64 {
            let r = &mut v[row * WIDTH..(row + 1) * WIDTH];
            let (first, last) = (k == 0, k == le.len as u64 - 1);
            r[IS_REAL] = F::ONE;
            r[IS_FIRST] = F::from_bool(first);
            r[IS_LAST] = F::from_bool(last);
            r[CLK] = F::from_u64(e.clk as u64);
            r[ENTRY] = F::from_u64(ev.entry as u64);
            r[ADDR_V] = F::from_u64(le.vals + 2 * k);
            r[ADDR_R] = F::from_u64(le.row + k);
            r[ROW_END] = F::from_u64(row_end);
            if !last {
                r[END_INV] = (F::from_u64(le.row + k) - F::from_u64(row_end)).inverse();
            }
            r[KEY] = F::from_u64(le.key);
            r[ALPHA_ADDR] = F::from_u64(le.alpha);
            r[RES] = F::from_u64(le.res);
            r[CHAIN_START] = F::from_bool(le.chain_start);
            r[CARRY] = F::from_bool(le.carry);
            r[ACC0] = acc[0];
            r[ACC1] = acc[1];
            r[APOW0] = apow[0];
            r[APOW1] = apow[1];
            r[INV0] = ev.inv[0];
            r[INV1] = ev.inv[1];
            r[ALPHA0] = ev.alpha[0];
            r[ALPHA1] = ev.alpha[1];
            let pz = [reads.next().expect("pz0").value, reads.next().expect("pz1").value];
            let px = reads.next().expect("px").value;
            r[PZ0] = pz[0];
            r[PZ1] = pz[1];
            r[PX] = px;
            let (t0, t1) = ext_mul(apow, [pz[0] - px, pz[1]]);
            let (t2_0, t2_1) = ext_mul([t0, t1], ev.inv);
            acc = [acc[0] + t2_0, acc[1] + t2_1];
            apow = ext_mul(apow, ev.alpha).into();
            if last {
                r[OUT0] = acc[0];
                r[OUT1] = acc[1];
                r[WRITES] = F::from_bool(!le.carry);
            }
            r[READ_ALPHA] = F::from_bool(first && le.chain_start);
            row += 1;
        }
        debug_assert_eq!((acc, apow), (ev.acc_out, ev.apow_out), "the trace recomputes the emulator's chain");
    }
    for e in events {
        v[e.reduce.unwrap().entry as usize * WIDTH + MULT] += F::ONE;
    }
    let row = fill_folds(&mut v, row, folds);
    fill_pows(&mut v, row, pows, counts);
    RowMajorMatrix::new(v, WIDTH)
}

/// The fold runs, after the reduce runs (`reduce_trace` calls this with its next free row);
/// returns the next free row.
fn fill_folds(v: &mut [F], mut row: usize, folds: &[&Event]) -> usize {
    for e in folds {
        let ev = e.fold.unwrap();
        let a = ev.arity as usize;
        let la = a.trailing_zeros() as usize;
        let coeffs = crate::emulator::fold_coefficients(la);
        let u = ev.u;
        let ext_mul_add = |x: [F; 2], y: [F; 2], z: [F; 2]| -> [F; 2] {
            let (p0, p1) = ext_mul(x, y);
            [p0 + z[0], p1 + z[1]]
        };
        let mut d = [[F::ZERO; 2]; 8];
        let mut facc = [F::ZERO; 2];
        for k in 0..2 * a {
            let r = &mut v[row * WIDTH..(row + 1) * WIDTH];
            r[IS_FOLD] = F::ONE;
            r[F_FIRST] = F::from_bool(k == 0);
            r[F_PH1] = F::from_bool(k < a);
            r[F_LAST] = F::from_bool(k == 2 * a - 1);
            r[F_K] = F::from_u64(k as u64);
            r[F_A] = F::from_u64(a as u64);
            r[F_MSG] = F::from_u64(ev.msg);
            r[CLK] = F::from_u64(e.clk as u64);
            r[U0] = u[0];
            r[U1] = u[1];
            for j in 0..8 {
                r[D0 + 2 * j] = d[j][0];
                r[D0 + 2 * j + 1] = d[j][1];
            }
            r[FACC0] = facc[0];
            r[FACC1] = facc[1];
            if k < a {
                let y = ev.ys[k];
                r[Y0] = y[0];
                r[Y1] = y[1];
                for j in 0..8 {
                    r[C0 + j] = coeffs[k][j];
                    d[j] = [d[j][0] + coeffs[k][j] * y[0], d[j][1] + coeffs[k][j] * y[1]];
                }
            } else {
                let next = ext_mul_add(facc, u, d[0]);
                if k == 2 * a - 1 {
                    r[FOUT0] = next[0];
                    r[FOUT1] = next[1];
                    debug_assert_eq!(next, ev.out, "the trace recomputes the emulator's fold");
                }
                facc = next;
                d.rotate_left(1);
                d[7] = [F::ZERO; 2];
            }
            row += 1;
            if k < a {
                // The coefficient table's row for (a, k): arity 2 at rows 0–1, 4 at 2–5, 8 at 6–13.
                v[(a - 2 + k) * WIDTH + MULT_C] += F::ONE;
            }
        }
    }
    row
}

/// The pow runs, after the fold runs (Cut F). The event's reads are the bits in run order.
fn fill_pows(v: &mut [F], mut row: usize, pows: &[&Event], counts: &mut RangeCounts) {
    for e in pows {
        let ev = e.pow.unwrap();
        let (mut g, mut s) = (ev.g, ev.s0);
        counts.range8(ev.off);
        counts.range8(ev.len);
        for t in 0..ev.len as usize {
            let bit = e.mem[t].value;
            let r = &mut v[row * WIDTH..(row + 1) * WIDTH];
            r[IS_POW] = F::ONE;
            r[P_FIRST] = F::from_bool(t == 0);
            r[P_LAST] = F::from_bool(t + 1 == ev.len as usize);
            r[P_K] = F::from_u64(t as u64);
            r[P_BASE] = F::from_u64(ev.base);
            r[P_OFF] = F::from_u32(ev.off);
            r[P_L] = F::from_u32(ev.len);
            r[CLK] = F::from_u64(e.clk as u64);
            r[P_BIT] = bit;
            r[P_G] = g;
            r[P_S] = s;
            s *= F::ONE + bit * (g - F::ONE);
            g = g.square();
            if t + 1 == ev.len as usize {
                r[P_OUT] = s;
                debug_assert_eq!(s, ev.out, "the trace recomputes the emulator's power");
            }
            row += 1;
        }
    }
}

/// `(a0 + a1·X)·(b0 + b1·X)`, `X² = 7` — the same extension multiplication the cpu uses.
fn ext_mul(a: [F; 2], b: [F; 2]) -> (F, F) {
    let seven = F::from_u64(7);
    (a[0] * b[0] + seven * a[1] * b[1], a[0] * b[1] + a[1] * b[0])
}
