//! The reduction chip (plan Task 8, the batch-opening-reduction precompile): one chip row per
//! reduction *column*, chained across a run of `REDUCE` rows by the descriptor the cpu
//! dispatched. A run of `len` columns is `len` chip rows: the first reads the 11-cell
//! descriptor, each row does `acc += apow·(pz − px)·inv` and `apow ·= alpha` over one column,
//! and the last writes the accumulator and running power back — so a height group's runs chain
//! exactly like the compiled loop they replace (the differential reference,
//! `programs::run_reduce_sequence`).
//!
//! The arithmetic is extension-field: `pz` is an extension element (two cells), `px` is a base
//! element (one cell), and `inv`/`acc`/`apow`/`alpha` are extension constants of the run. Every
//! constraint is degree ≤ 3 (two extension multiplications and an add).
use super::{bus, F};
use crate::emulator::{Event, TS_RUN_PX, TS_RUN_PZ0, TS_RUN_PZ1, TS_WB_ACC0, TS_WB_ACC1, TS_WB_APOW0, TS_WB_APOW1};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const IS_REAL: usize = 0;
    pub const IS_FIRST: usize = 1;
    pub const IS_LAST: usize = 2;
    pub const CLK: usize = 3;
    pub const DESCR_PTR: usize = 4;
    pub const ACC0: usize = 5;
    pub const ACC1: usize = 6;
    pub const APOW0: usize = 7;
    pub const APOW1: usize = 8;
    pub const INV0: usize = 9;
    pub const INV1: usize = 10;
    pub const ALPHA0: usize = 11;
    pub const ALPHA1: usize = 12;
    pub const PZ0: usize = 13;
    pub const PZ1: usize = 14;
    pub const PX: usize = 15;
    pub const ADDR_V: usize = 16;
    pub const ADDR_R: usize = 17;
    pub const LEN: usize = 18;
    /// The is-one gadget on `LEN == 1` (the `alu.rs` two-constraint pattern): `IS_LAST` is not a
    /// free witness but exactly this gadget's output, so `IS_LAST ⟺ LEN == 1` is forced, not
    /// merely checked forward.
    pub const LEN1: usize = 19;
    pub const LEN1_INV: usize = 20;
    pub const WIDTH: usize = 21;
}
use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct ReduceAir;

impl<Fld: Field> BaseAir<Fld> for ReduceAir {
    fn width(&self) -> usize { col::WIDTH }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ReduceAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let seven = AB::Expr::from_u64(7);
        let sixteen = AB::Expr::from_u32(16);

        let is_real = v(IS_REAL);
        b.assert_bool(is_real.clone());
        let (is_first, is_last) = (v(IS_FIRST), v(IS_LAST));
        b.assert_bool(is_first.clone());
        b.assert_bool(is_last.clone());
        // A run starts on its first row: the table's first row is a run start when real.
        b.when_first_row().assert_zero(is_real.clone() * (one.clone() - is_first.clone()));
        // Padding is a suffix.
        b.when_transition().assert_zero((one.clone() - is_real.clone()) * n(IS_REAL));
        // After a last row, the next real row is a first row (a new run) or padding.
        {
            let mut t = b.when_transition();
            t.assert_zero(is_last.clone() * n(IS_REAL) * (one.clone() - n(IS_FIRST)));
        }
        // And `IS_LAST` is the gadget's output, not a witness: pinned below.
        // The is-one gadget on `LEN == 1` (the `alu.rs` pattern), and `IS_LAST` pinned to its
        // output: `IS_LAST ⟺ LEN == 1`, so the write-back happens on the run's final column and
        // never before it, and the run-close transition above closes the run after it.
        b.assert_bool(v(LEN1));
        b.assert_zero((v(LEN) - one.clone()) * v(LEN1_INV) - (one.clone() - v(LEN1)));
        b.assert_zero(v(LEN1) * (v(LEN) - one.clone()));
        b.assert_zero(is_last.clone() - v(LEN1));

        // ── the column step: diff = pz − px; t = apow·diff; t2 = t·inv; acc += t2; apow ·= alpha ──
        let (diff0, diff1) = (v(PZ0) - v(PX), v(PZ1));
        let t0 = v(APOW0) * diff0.clone() + seven.clone() * v(APOW1) * diff1.clone();
        let t1 = v(APOW0) * diff1.clone() + v(APOW1) * diff0;
        let t2_0 = t0.clone() * v(INV0) + seven.clone() * t1.clone() * v(INV1);
        let t2_1 = t0 * v(INV1) + t1 * v(INV0);
        let acc_next0 = v(ACC0) + t2_0;
        let acc_next1 = v(ACC1) + t2_1;
        let apow_next0 = v(APOW0) * v(ALPHA0) + seven.clone() * v(APOW1) * v(ALPHA1);
        let apow_next1 = v(APOW0) * v(ALPHA1) + v(APOW1) * v(ALPHA0);

        // The chain, gated on the next row being in the same run.
        let in_run_next = n(IS_REAL) * (one.clone() - n(IS_FIRST));
        let mut t = b.when_transition();
        t.assert_zero(in_run_next.clone() * (n(ACC0) - acc_next0.clone()));
        t.assert_zero(in_run_next.clone() * (n(ACC1) - acc_next1.clone()));
        t.assert_zero(in_run_next.clone() * (n(APOW0) - apow_next0.clone()));
        t.assert_zero(in_run_next.clone() * (n(APOW1) - apow_next1.clone()));
        t.assert_zero(in_run_next.clone() * (n(INV0) - v(INV0)));
        t.assert_zero(in_run_next.clone() * (n(INV1) - v(INV1)));
        t.assert_zero(in_run_next.clone() * (n(ALPHA0) - v(ALPHA0)));
        t.assert_zero(in_run_next.clone() * (n(ALPHA1) - v(ALPHA1)));
        t.assert_zero(in_run_next.clone() * (n(DESCR_PTR) - v(DESCR_PTR)));
        t.assert_zero(in_run_next.clone() * (n(ADDR_V) - v(ADDR_V) - AB::Expr::from_u32(2)));
        t.assert_zero(in_run_next.clone() * (n(ADDR_R) - v(ADDR_R) - one.clone()));
        t.assert_zero(in_run_next.clone() * (n(LEN) - v(LEN) + one.clone()));
        drop(t);

        // ── buses ──
        // The dispatch handle: one entry per run, on its first row (the sha256 block pattern).
        bus::REDUCE.table_entry(b, [v(CLK), v(DESCR_PTR)], is_first.clone());
        let clk = v(CLK);
        let ts = |slot: u32| sixteen.clone() * clk.clone() + AB::Expr::from_u32(slot);
        // The descriptor, on the first row: eleven reads at slots 0..10, whose values are the
        // run's state (AGENTS.md invariant 1: the message values are exactly the state columns).
        let descr = v(DESCR_PTR);
        let descr_reads: [(usize, AB::Expr); 11] = [
            (0, v(ADDR_V)),
            (1, v(ADDR_R)),
            (2, v(LEN)),
            (3, v(INV0)),
            (4, v(INV1)),
            (5, v(ACC0)),
            (6, v(ACC1)),
            (7, v(APOW0)),
            (8, v(APOW1)),
            (9, v(ALPHA0)),
            (10, v(ALPHA1)),
        ];
        for (k, value) in descr_reads {
            bus::RAM.send(
                b,
                [descr.clone() + AB::Expr::from_u32(k as u32), ts(k as u32), value, AB::Expr::ZERO],
                Count::bounded(is_first.clone(), 1),
            );
        }
        // The column's three reads, at the run-read slots.
        bus::RAM.send(b, [v(ADDR_V), ts(TS_RUN_PZ0), v(PZ0), AB::Expr::ZERO], Count::bounded(is_real.clone(), 1));
        bus::RAM.send(b, [v(ADDR_V) + one.clone(), ts(TS_RUN_PZ1), v(PZ1), AB::Expr::ZERO], Count::bounded(is_real.clone(), 1));
        bus::RAM.send(b, [v(ADDR_R), ts(TS_RUN_PX), v(PX), AB::Expr::ZERO], Count::bounded(is_real.clone(), 1));
        // The write-back, on the last row: the post-step accumulator and power, slots 14–15.
        let writebacks: [(usize, AB::Expr, u32); 4] = [
            (5, acc_next0, TS_WB_ACC0),
            (6, acc_next1, TS_WB_ACC1),
            (7, apow_next0, TS_WB_APOW0),
            (8, apow_next1, TS_WB_APOW1),
        ];
        for (k, value, slot) in writebacks {
            bus::RAM.send(
                b,
                [descr.clone() + AB::Expr::from_u32(k as u32), ts(slot), value, one.clone()],
                Count::bounded(is_last.clone(), 1),
            );
        }
    }
}

pub const MIN_LOG_HEIGHT: u8 = 4;

/// One chip row per reduction column plus one padding row, floored — with `0` the distinguished
/// "no reduce table in this proof" value, the keccak pattern (`machine::chips`).
pub fn reduce_log_height(rows: usize) -> u8 {
    if rows == 0 {
        return 0;
    }
    super::pad_height(rows + 1, 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8
}

/// The events the chip's trace is built from: one per dispatched `REDUCE`, in execution order.
pub fn reduce_events(events: &[Event]) -> Vec<&Event> {
    events.iter().filter(|e| e.reduce.is_some()).collect()
}

/// `len` rows per event: the first carries the descriptor's state (and the `IS_FIRST` bus
/// entry), each row one column's step, the last the write-back. Padding rows are all zero (the
/// row-kind selectors are witness, so an all-zero row satisfies every gated constraint).
pub fn reduce_trace(events: &[&Event], height: usize) -> RowMajorMatrix<F> {
    let n_rows: usize = events.iter().map(|e| e.reduce.unwrap().len as usize).sum();
    assert!(n_rows < height, "reduce table needs a padding row: {n_rows} rows, height {height}");
    let mut v = F::zero_vec(height * col::WIDTH);
    let mut row = 0usize;
    for e in events {
        let ev = e.reduce.unwrap();
        let (mut acc, mut apow) = (ev.acc, ev.apow);
        let mut reads = e.mem.iter();
        // The eleven descriptor reads, in slot order.
        let descr_reads: Vec<_> = (0..11).map(|_| reads.next().expect("the descriptor's eleven reads").clone()).collect();
        for k in 0..ev.len {
            let r = &mut v[row * col::WIDTH..(row + 1) * col::WIDTH];
            let (first, last) = (k == 0, k == ev.len - 1);
            r[IS_REAL] = F::ONE;
            r[IS_FIRST] = F::from_bool(first);
            r[IS_LAST] = F::from_bool(last);
            r[CLK] = F::from_u64(e.clk as u64);
            r[DESCR_PTR] = F::from_u64(ev.descr_ptr);
            r[INV0] = ev.inv[0];
            r[INV1] = ev.inv[1];
            r[ALPHA0] = ev.alpha[0];
            r[ALPHA1] = ev.alpha[1];
            r[ACC0] = acc[0];
            r[ACC1] = acc[1];
            r[APOW0] = apow[0];
            r[APOW1] = apow[1];
            r[ADDR_V] = F::from_u64(ev.vals_base + 2 * k as u64);
            r[ADDR_R] = F::from_u64(ev.row_base + k as u64);
            r[LEN] = F::from_u64((ev.len - k) as u64);
            let remaining = ev.len - k;
            if remaining == 1 {
                r[LEN1] = F::ONE;
            } else {
                r[LEN1_INV] = F::from_u64((remaining - 1) as u64).inverse();
            }
            let pz = [reads.next().expect("pz0 read").value, reads.next().expect("pz1 read").value];
            let px = reads.next().expect("px read").value;
            r[PZ0] = pz[0];
            r[PZ1] = pz[1];
            r[PX] = px;
            let diff = [
                pz[0] - px,
                pz[1],
            ];
            let (t0, t1) = ext_mul(apow, diff);
            let (t2_0, t2_1) = ext_mul([t0, t1], ev.inv);
            acc = [acc[0] + t2_0, acc[1] + t2_1];
            apow = ext_mul(apow, ev.alpha).into();
            if first {
                for (j, rd) in descr_reads.iter().enumerate() {
                    let want = [
                        ev.vals_base, ev.row_base, ev.len as u64, ev.inv[0].as_canonical_u64(), ev.inv[1].as_canonical_u64(),
                        ev.acc[0].as_canonical_u64(), ev.acc[1].as_canonical_u64(), ev.apow[0].as_canonical_u64(), ev.apow[1].as_canonical_u64(),
                        ev.alpha[0].as_canonical_u64(), ev.alpha[1].as_canonical_u64(),
                    ][j];
                    debug_assert_eq!(rd.value.as_canonical_u64(), want, "descriptor read {j}");
                    debug_assert_eq!(rd.addr, ev.descr_ptr + j as u64);
                }
            }
            row += 1;
        }
        // The four write-backs follow the run's reads; the recomputed final state must match.
        let wb: Vec<_> = (0..4).map(|_| reads.next().expect("the four write-backs").clone()).collect();
        debug_assert_eq!(wb.len(), 4);
        debug_assert_eq!([wb[0].value, wb[1].value], acc, "the write-back's accumulator");
        debug_assert_eq!([wb[2].value, wb[3].value], apow, "the write-back's running power");
        debug_assert!(reads.next().is_none(), "every REDUCE event logs exactly its own accesses");
    }
    // Padding rows: the is-one gadget on `LEN = 0` needs `LEN1_INV = −1` (`(LEN−1)·INV = 1−LEN1`
    // with `LEN1 = 0`), the `program.rs` padding lesson's shape here.
    for row in row..height {
        v[row * col::WIDTH + LEN1_INV] = F::NEG_ONE;
    }
    RowMajorMatrix::new(v, col::WIDTH)
}

/// `(a0 + a1·X)·(b0 + b1·X)`, `X² = 7` — the same extension multiplication the cpu uses.
fn ext_mul(a: [F; 2], b: [F; 2]) -> (F, F) {
    let seven = F::from_u64(7);
    (a[0] * b[0] + seven * a[1] * b[1], a[0] * b[1] + a[1] * b[0])
}
