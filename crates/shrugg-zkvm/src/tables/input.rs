//! M4.1: the `input` witness table — one row per committed private-input word, providing
//! `(IDX, WORD)` on **two separate** buses, `INPUT_DIGEST` and `INPUT_READ`.
//!
//! Review round 1 (C1, critical): an earlier design put both consumers on one bus
//! (`INPUT_WORD`) with count `IS_REAL * (1 + MULT_READ)` — the mandatory "+1" the digest
//! always claims, plus however many times `SYS_READ` reads that index. That is unsound:
//! LogUp balances per `(idx, word)` key only, not per *consumer class*, so a prover can shift
//! budget between the digest's mandatory copy and a `SYS_READ`'s copy — e.g. stop the digest
//! from absorbing index `k` (dropping its demand by one) while a genuine `READ_INPUT(k)`
//! still succeeds (using up the row's now-sole remaining unit of supply), so `H_IN` ends up
//! committing to *fewer* words than the guest actually read, with every constraint still
//! satisfied. A range check on `MULT_READ` alone cannot close this: the row's *total* provided
//! count is still whatever the demand happens to be.
//!
//! The fix is to split the bus so the two consumer classes cannot trade with each other:
//! - `INPUT_DIGEST`, count `IS_REAL` — the digest's *only* source of (idx, word), one unit per
//!   real row, completely independent of how many times (if any) that index is read.
//! - `INPUT_READ`, count `IS_REAL * MULT_READ` — `SYS_READ`'s only source, `MULT_READ` a free
//!   but LogUp-balance-checked witness value, unrelated to `INPUT_DIGEST`'s count.
//!
//! With the two separated, `INPUT_DIGEST` alone is exactly `program`'s `MULT_WORD = VALID`
//! argument (`docs/02-tables-and-buses.md`'s "`hc` binds the whole executable program"
//! section): the cpu table's real (non-salt) `IS_INDIGEST` rows demand exactly the drained
//! absorption chain's index set — `{0, .., n_in-1}` with the words they actually absorbed,
//! fixed independently of this table (the drain/`ACT`/`HASH_IDX` chain, unaffected by this
//! change) — so for `INPUT_DIGEST` to balance, this table's real rows must supply *exactly*
//! that set: an index the digest doesn't demand (real row at `idx >= n_in`) is an unclaimed
//! supply, and an index the digest does demand but this table doesn't supply as real (a "hole"
//! below `n_in`) is an unclaimed demand — either way, `real_count == n_in` is forced, and the
//! absorbed words must equal this table's `WORD` values exactly. `INPUT_READ` then separately,
//! and independently, ties `MULT_READ` to the true `SYS_READ` count per index, with no way for
//! either bus to borrow slack from the other.
use super::{bus, F};
use crate::emulator::{CycleEvent, Syscall};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const IDX: usize = 0;
    pub const WORD: usize = 1;
    pub const IS_REAL: usize = 2;
    /// How many times `SYS_READ` actually consumes this row's `(IDX, WORD)` on `INPUT_READ` —
    /// a free witness value, but pinned to reality by that bus's own balance (independent of
    /// `INPUT_DIGEST`, split precisely so `MULT_READ` cannot affect the digest's own count —
    /// review round 1, C1). Needs no range check of its own: `IDX` is already pinned to the
    /// row's own index (one row per committed index, never revisited), so a too-large
    /// `MULT_READ` only ever inflates *this one row's* `INPUT_READ` supply — it can't be
    /// spread across multiple rows to hide an over-count, and an honest excess is caught by
    /// `INPUT_READ`'s own balance against the true `SYS_READ` demand regardless of how big the
    /// claimed value is.
    pub const MULT_READ: usize = 3;
    pub const WIDTH: usize = 4;
}
use col::*;

pub const MIN_HEIGHT: usize = 4;
pub const MIN_LOG_HEIGHT: u8 = 2; // 1 << 2 == MIN_HEIGHT
/// Ceiling on the declared (proof-carried) input-table log-height — 2^20 rows is a million
/// private-input words, comfortably past any guest this crate runs; mirrors
/// `tables::program::MAX_LOG_HEIGHT`'s role exactly, one size smaller since private inputs
/// are typically far shorter than programs. This is only the table-shape ceiling, not the
/// effective cap on `n_in`: `cpu`'s shared absorb machinery range-checks `HASH_LEFT` (the
/// words-not-yet-absorbed counter) via two `RANGE8` limbs on every indigest row, bounding it
/// to 16 bits — so `n_in` is effectively capped at 65535 well before `MAX_LOG_HEIGHT` bites.
pub const MAX_LOG_HEIGHT: u8 = 20;

/// Same "+1 padding row, floor at MIN_HEIGHT" rule as `tables::program::program_log_height`.
pub fn input_log_height(n: usize) -> u8 {
    super::pad_height(n + 1, MIN_HEIGHT).trailing_zeros() as u8
}

#[derive(Clone, Copy, Debug, Default)]
pub struct InputAir;

impl<Fld> BaseAir<Fld> for InputAir {
    fn width(&self) -> usize { WIDTH }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for InputAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;

        b.assert_bool(v(IS_REAL));
        // Real rows form a prefix — once IS_REAL drops to 0 it never returns, so the real-row
        // set is always exactly {0, .., realCount-1} for some realCount, never a scattered set.
        b.when_transition().assert_zero((one.clone() - v(IS_REAL)) * n(IS_REAL));
        // IDX = row index: 0 at row 0, +1 every row (including through padding — harmless,
        // nothing reads a padding row's IDX since its count is forced to 0 below). Unlike
        // `program`'s PC (which needs an external `base_pc` anchor), input indices always
        // start at 0 by definition, so no separate "no aliasing without a trusted base" check
        // is needed beyond this.
        b.when_first_row().assert_zero(v(IDX));
        b.when_transition().assert_zero(n(IDX) - v(IDX) - one.clone());
        // AGENTS.md invariant 1: pin the message columns on padding rows too.
        b.assert_zero((one.clone() - v(IS_REAL)) * v(WORD));
        // AGENTS.md invariant 2: MULT_READ forced to 0 on padding rows explicitly — the total
        // provided count below already zeroes out via the IS_REAL factor regardless of
        // MULT_READ's value, but a stray MULT_READ on a padding row is exactly the kind of
        // "unconstrained column nothing currently reads" AGENTS.md's ALU lesson warns about;
        // this local pin is also what makes cheating test (e) (below) a real rejection rather
        // than a no-op tamper.
        b.assert_zero((one.clone() - v(IS_REAL)) * v(MULT_READ));

        // Split per review round 1 (C1): the digest's mandatory copy and a SYS_READ's copy
        // are now on separate buses, so neither can borrow the other's budget.
        bus::INPUT_DIGEST.table_entry(b, [v(IDX), v(WORD)], v(IS_REAL));
        bus::INPUT_READ.table_entry(b, [v(IDX), v(WORD)], v(IS_REAL) * v(MULT_READ));
    }
}

/// How many times each committed index is actually consumed by a `READ_INPUT` — the honest
/// `MULT_READ` values `input_trace` needs. `idx` is always `< n` for an honest execution
/// (`emulator::execute` already errors `ExecError::InputIndex` otherwise), so this never
/// indexes out of bounds on a witness that got this far.
pub fn read_counts(n: usize, events: &[CycleEvent]) -> Vec<u32> {
    let mut counts = vec![0u32; n];
    for e in events {
        if let Some(Syscall::ReadInput { idx, .. }) = e.sys {
            counts[idx as usize] += 1;
        }
    }
    counts
}

pub fn input_trace(inputs: &[u32], read_counts: &[u32], height: usize) -> RowMajorMatrix<F> {
    assert!(inputs.len() <= height, "input table needs {} rows, height {height}", inputs.len());
    assert_eq!(inputs.len(), read_counts.len());
    let mut v = F::zero_vec(height * WIDTH);
    for (i, (&w, &rc)) in inputs.iter().zip(read_counts).enumerate() {
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        r[IDX] = F::from_u32(i as u32);
        r[WORD] = F::from_u32(w);
        r[IS_REAL] = F::ONE;
        r[MULT_READ] = F::from_u32(rc);
    }
    for i in inputs.len()..height {
        v[i * WIDTH + IDX] = F::from_u32(i as u32);
    }
    RowMajorMatrix::new(v, WIDTH)
}
