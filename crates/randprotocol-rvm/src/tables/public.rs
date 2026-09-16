//! The public table (plan R5): one row per published word, owning the batch's four public
//! values. The rVM's public interface is always exactly the 4-element interface digest
//! (`public_values::public_digest`), so `num_public_values` is a program-independent constant
//! and the table is four real rows plus padding.
//!
//! The tie between the trace and the public values is the RV32 cpu's `OUT_SEL` pattern at four
//! slots (`research/src/tables/cpu.rs:1383-1391`): on each real row exactly one `SEL_i` is set,
//! naming the slot `IDX == i` and pinning `VALUE = pv[i]`. The RV32 pattern's never-written arm
//! cannot arise — the digest is always four words, so all four slots are always selected — and
//! no `WRITTEN` accumulator is needed. The cpu's `PUBLIC` rows consume the table's entries on
//! the `PUBLIC` bus with a running `PUB_IDX` counter, so set equality forces: the values the
//! program published, in order, are exactly the proof's four public values.
use super::{bus, F};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

/// The rVM's public interface is always the 4-element interface digest (R5).
pub const NUM_PUBLIC_VALUES: usize = 4;

pub mod col {
    pub const IDX: usize = 0;
    pub const VALUE: usize = 1;
    pub const IS_REAL: usize = 2;
    pub const SEL0: usize = 3; // SEL1..3 = 4..6
    pub const WIDTH: usize = 7;
}
use col::*;

/// `pad_height(NUM_PUBLIC_VALUES + 1, 4)` — four real rows plus the padding rule.
pub const HEIGHT: usize = 8;

#[derive(Clone, Copy, Debug, Default)]
pub struct PublicAir;

impl<Fld: Field> BaseAir<Fld> for PublicAir {
    fn width(&self) -> usize { col::WIDTH }
    fn num_public_values(&self) -> usize { NUM_PUBLIC_VALUES }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for PublicAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let pvs: Vec<AB::Expr> = b.public_values().iter().map(|p| (*p).into()).collect();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;

        b.assert_bool(v(IS_REAL));
        // Real rows form a prefix.
        b.when_transition().assert_zero((one.clone() - v(IS_REAL)) * n(IS_REAL));
        // IDX is the row index.
        b.when_first_row().assert_zero(v(IDX));
        b.when_transition().assert_zero(n(IDX) - v(IDX) - one.clone());

        // The selector tie: on a real row exactly one SEL_i, naming slot i and pinning
        // VALUE = pv[i]; on padding rows none (AGENTS.md invariant 2 — no stray provides).
        let mut sel_sum = AB::Expr::ZERO;
        for i in 0..NUM_PUBLIC_VALUES {
            let s = v(SEL0 + i);
            b.assert_bool(s.clone());
            b.assert_zero(s.clone() * (v(IDX) - AB::Expr::from_u32(i as u32)));
            b.assert_zero(s.clone() * (v(VALUE) - pvs[i].clone()));
            sel_sum += s;
        }
        b.assert_eq(sel_sum, v(IS_REAL));

        bus::PUBLIC.table_entry(b, [v(IDX), v(VALUE)], v(IS_REAL));
    }
}

/// The witness trace: one real row per published word, `SEL_i` on row `i`, all-zero padding.
pub fn public_trace(published: &[F], height: usize) -> RowMajorMatrix<F> {
    assert_eq!(
        published.len(),
        NUM_PUBLIC_VALUES,
        "the interface digest is always four words (R5), got {}",
        published.len()
    );
    assert!(published.len() < height, "the public table needs a padding row");
    let mut v = F::zero_vec(height * col::WIDTH);
    for i in 0..height {
        let r = &mut v[i * col::WIDTH..(i + 1) * col::WIDTH];
        r[IDX] = F::from_u32(i as u32);
        if i < published.len() {
            r[VALUE] = published[i];
            r[IS_REAL] = F::ONE;
            r[SEL0 + i] = F::ONE;
        }
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
