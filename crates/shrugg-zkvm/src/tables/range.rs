//! 256-row preprocessed range/pow2 table, replacing the range half of the old byte table.
use super::{bus, F};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

pub const HEIGHT: usize = 256;

pub mod pre {
    pub const A: usize = 0;
    pub const POW2: usize = 1;    // 2^A for A < 32, else 0
    pub const IS_POW2: usize = 2; // [A < 32]
    pub const WIDTH: usize = 3;
}
pub mod col {
    pub const M_RANGE: usize = 0;
    pub const M_POW2: usize = 1;
    pub const WIDTH: usize = 2;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RangeAir;

impl<Fld: Field> BaseAir<Fld> for RangeAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let mut v = Fld::zero_vec(HEIGHT * pre::WIDTH);
        for a in 0..256u32 {
            let r = a as usize * pre::WIDTH;
            v[r + pre::A] = Fld::from_u32(a);
            if a < 32 {
                v[r + pre::POW2] = Fld::from_u32(1 << a);
                v[r + pre::IS_POW2] = Fld::ONE;
            }
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
        let (a, pow2, is_pow2) = (p.current(pre::A).unwrap(), p.current(pre::POW2).unwrap(), p.current(pre::IS_POW2).unwrap());
        let (mr, mp) = (m.current(col::M_RANGE).unwrap(), m.current(col::M_POW2).unwrap());
        b.assert_zero(mp.into() * (AB::Expr::ONE - is_pow2.into()));
        bus::RANGE8.table_entry(b, [a.into()], mr.into());
        bus::POW2.table_entry(b, [a.into(), pow2.into()], mp.into());
    }
}

/// Counts every lookup the other tables perform against the range table, in lock-step with
/// the interactions their AIRs declare.
#[derive(Clone, Debug, Default)]
pub struct RangeCounts { pub range: Vec<u64>, pub pow2: Vec<u64> }
impl RangeCounts {
    fn ensure(&mut self) {
        if self.range.is_empty() { self.range = vec![0; HEIGHT]; self.pow2 = vec![0; HEIGHT]; }
    }
    pub fn range8(&mut self, x: u32) { self.ensure(); assert!(x < 256); self.range[x as usize] += 1; }
    pub fn pow2(&mut self, s: u32) { self.ensure(); assert!(s < 32); self.pow2[s as usize] += 1; }
}

pub fn range_trace(c: &RangeCounts) -> RowMajorMatrix<F> {
    let mut c = c.clone();
    c.ensure();
    let mut v = F::zero_vec(HEIGHT * col::WIDTH);
    for r in 0..HEIGHT {
        v[r * col::WIDTH + col::M_RANGE] = F::from_u64(c.range[r]);
        v[r * col::WIDTH + col::M_POW2] = F::from_u64(c.pow2[r]);
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
