//! 256-row range table, the `RANGE8` provider — the only range check in the machine (spec §3).
//! `research/src/tables/range.rs` minus the `POW2` half, which the rVM has no bus for (pinned
//! width: one preprocessed value column + one multiplicity column, where the plan's "~2 + 1"
//! was the estimate that included it).
use super::{bus, F};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

pub const HEIGHT: usize = 256;

pub mod pre {
    pub const A: usize = 0;
    pub const WIDTH: usize = 1;
}
pub mod col {
    pub const M_RANGE: usize = 0;
    pub const WIDTH: usize = 1;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RangeAir;

impl<Fld: Field> BaseAir<Fld> for RangeAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let mut v = Fld::zero_vec(HEIGHT * pre::WIDTH);
        for a in 0..HEIGHT {
            v[a * pre::WIDTH + pre::A] = Fld::from_u32(a as u32);
        }
        Some(RowMajorMatrix::new(v, pre::WIDTH))
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for RangeAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let a = p.current(pre::A).unwrap();
        let mr = m.current(col::M_RANGE).unwrap();
        bus::RANGE8.table_entry(b, [a.into()], mr.into());
    }
}

/// Counts every lookup the other tables perform against the range table, in lock-step with
/// the interactions their AIRs declare (`research`'s `RangeCounts`, one bus only).
#[derive(Clone, Debug, Default)]
pub struct RangeCounts { pub range: Vec<u64> }
impl RangeCounts {
    fn ensure(&mut self) {
        if self.range.is_empty() { self.range = vec![0; HEIGHT]; }
    }
    pub fn range8(&mut self, x: u32) { self.ensure(); assert!(x < 256); self.range[x as usize] += 1; }
}

pub fn range_trace(c: &RangeCounts) -> RowMajorMatrix<F> {
    let mut c = c.clone();
    c.ensure();
    let mut v = F::zero_vec(HEIGHT * col::WIDTH);
    for r in 0..HEIGHT {
        v[r * col::WIDTH + col::M_RANGE] = F::from_u64(c.range[r]);
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
