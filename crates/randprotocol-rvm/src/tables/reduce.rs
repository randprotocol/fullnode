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
use super::{bus, range::RangeCounts, F};
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
    /// ZKQ-3 (the 2026-09-27 zk scan): the run's address range checks, three byte limbs each, on
    /// its first row — the descriptor's first and last cells (`DESCR_PTR`, `DESCR_PTR + 10`), the
    /// vals array's (`ADDR_V`, `ADDR_V + 2·LEN − 1`) and the row array's (`ADDR_R`,
    /// `ADDR_R + LEN − 1`). The cpu's REDUCE row range-checks nothing (REDUCE is not among its
    /// subjects), so before these a descriptor or an array could sit anywhere in the field.
    pub const DESCR_LIMB0: usize = 21; // 3
    pub const DESCR_END_LIMB0: usize = 24; // 3
    pub const VALS_LIMB0: usize = 27; // 3
    pub const VALS_END_LIMB0: usize = 30; // 3
    pub const ROW_LIMB0: usize = 33; // 3
    pub const ROW_END_LIMB0: usize = 36; // 3
    pub const WIDTH: usize = 39;
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
            // ZKR-4 (the 2026-09-27 zk scan): and the converse — a real row that is not its
            // run's last is followed by the same run's next row: not by padding, not by a new
            // run's first row. Before this a run could simply stop: its first row followed by
            // padding was accepted, the write-back (sent only on `IS_LAST`) never happened, and
            // the cpu read the accumulator cell's pre-reduction value back as the result.
            t.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * (one.clone() - n(IS_REAL)));
            t.assert_zero(is_real.clone() * (one.clone() - is_last.clone()) * n(IS_FIRST));
        }
        // The transition rules above never see the table's final row, so no run may be open
        // there: the final row is padding (`reduce_trace` always leaves at least one).
        b.when_last_row().assert_zero(is_real.clone());
        // And `IS_LAST` is the gadget's output, not a witness: pinned below.
        // The is-one gadget on `LEN == 1` (the `alu.rs` pattern), and `IS_LAST` pinned to its
        // output: `IS_LAST ⟺ LEN == 1`, so the write-back happens on the run's final column and
        // never before it, and the run-close transition above closes the run after it.
        b.assert_bool(v(LEN1));
        b.assert_zero((v(LEN) - one.clone()) * v(LEN1_INV) - (one.clone() - v(LEN1)));
        b.assert_zero(v(LEN1) * (v(LEN) - one.clone()));
        // V-OPCODES-1 (the 2026-09-27 zk scan): both row kinds exist only on real rows. `IS_LAST`
        // was `LEN1` on *every* row, and `LEN = LEN1 = 1` satisfies the gadget on a padding row as
        // well as on a real one — so a padding row could send the four write-backs, with values of
        // its choosing, at `16·CLK + 14/15` for a CLK that is only a field element (`clk + 1/16`
        // lands between any two real timestamps). `IS_FIRST` was a free boolean on padding. Now a
        // padding row is neither, and every message the chip sends is gated on a real row.
        b.assert_zero(is_last.clone() - is_real.clone() * v(LEN1));
        b.assert_zero(is_first.clone() * (one.clone() - is_real.clone()));

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
        // OPCODES-1 / TABLES-1 (the 2026-09-27 zk scan): the run's clock is carried like its
        // descriptor pointer. Every row's column reads — and the last row's write-back — sit at
        // `16·CLK + slot`, and only the first row's CLK is bound, by the `REDUCE` dispatch entry
        // the cpu row consumes. Without this line a later row's CLK was free: its reads could land
        // at any earlier clock (stale cells, whatever they held then) or a later one, and the
        // write-back at any time at all — the memory table only asks that each cell's history be
        // consistent in timestamp order, not that the chip's timestamps be the dispatch's.
        t.assert_zero(in_run_next.clone() * (n(CLK) - v(CLK)));
        t.assert_zero(in_run_next.clone() * (n(ADDR_V) - v(ADDR_V) - AB::Expr::from_u32(2)));
        t.assert_zero(in_run_next.clone() * (n(ADDR_R) - v(ADDR_R) - one.clone()));
        t.assert_zero(in_run_next.clone() * (n(LEN) - v(LEN) + one.clone()));
        drop(t);

        // ── ZKQ-3: the run's addresses, range-checked on its first row ──
        // Six subjects, both ends of each of the three runs of cells the chip touches. With both
        // ends below `2^24` and the run short — `LEN` on the first row is the run's row count,
        // which the chain and ZKR-4's end rule tie to the table's own height — every cell between
        // them is in range too; the rows after the first reach only `ADDR_V + 2k`, `ADDR_R + k`
        // and the descriptor cells, all inside the checked ranges.
        {
            let limbs = |c: usize| v(c) + v(c + 1) * AB::Expr::from_u32(1 << 8) + v(c + 2) * AB::Expr::from_u32(1 << 16);
            let subjects: [(AB::Expr, usize); 6] = [
                (v(DESCR_PTR), DESCR_LIMB0),
                (v(DESCR_PTR) + AB::Expr::from_u32(10), DESCR_END_LIMB0),
                (v(ADDR_V), VALS_LIMB0),
                (v(ADDR_V) + AB::Expr::from_u32(2) * v(LEN) - one.clone(), VALS_END_LIMB0),
                (v(ADDR_R), ROW_LIMB0),
                (v(ADDR_R) + v(LEN) - one.clone(), ROW_END_LIMB0),
            ];
            for (subject, c) in subjects {
                b.assert_zero(is_first.clone() * (subject - limbs(c)));
                for l in c..c + 3 {
                    bus::RANGE8.lookup_key(b, [v(l)], Count::bounded(is_first.clone(), 1));
                }
            }
        }

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
pub fn reduce_trace(events: &[&Event], height: usize, counts: &mut RangeCounts) -> RowMajorMatrix<F> {
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
                // ZKQ-3's six range checks, computed as the AIR recomputes them.
                let len = ev.len as u64;
                let subjects = [
                    (ev.descr_ptr, DESCR_LIMB0),
                    (ev.descr_ptr + 10, DESCR_END_LIMB0),
                    (ev.vals_base, VALS_LIMB0),
                    (ev.vals_base + 2 * len - 1, VALS_END_LIMB0),
                    (ev.row_base, ROW_LIMB0),
                    (ev.row_base + len - 1, ROW_END_LIMB0),
                ];
                for (s, c) in subjects {
                    assert!(s < 1 << 24, "the emulator bounds every REDUCE address below 2^24");
                    for k in 0..3 {
                        let limb = (s >> (8 * k)) as u32 & 0xff;
                        r[c + k] = F::from_u32(limb);
                        counts.range8(limb);
                    }
                }
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
