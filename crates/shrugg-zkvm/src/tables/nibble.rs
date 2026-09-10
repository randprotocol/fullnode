//! 256-row preprocessed 4-bit bitwise table (16×16 nibble pairs), replacing the
//! bitwise half of the old byte table. A successful lookup proves both operands
//! are nibbles, so nibble-keyed lookups double as range checks.
use super::{bus, F};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

pub const HEIGHT: usize = 256;

pub mod pre {
    pub const A: usize = 0;
    pub const B: usize = 1;
    pub const AND: usize = 2;
    pub const OR: usize = 3;
    pub const XOR: usize = 4;
    pub const WIDTH: usize = 5;
}
pub mod col {
    pub const M_AND: usize = 0;
    pub const M_OR: usize = 1;
    pub const M_XOR: usize = 2;
    pub const WIDTH: usize = 3;
}

#[inline]
pub fn row_of(a: u32, b: u32) -> usize { (a as usize) * 16 + b as usize }

#[derive(Clone, Copy, Debug, Default)]
pub struct NibbleAir;

impl<Fld: Field> BaseAir<Fld> for NibbleAir {
    fn width(&self) -> usize { col::WIDTH }
    fn preprocessed_width(&self) -> usize { pre::WIDTH }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let mut v = Fld::zero_vec(HEIGHT * pre::WIDTH);
        for a in 0..16u32 {
            for b in 0..16u32 {
                let r = row_of(a, b) * pre::WIDTH;
                v[r + pre::A] = Fld::from_u32(a);
                v[r + pre::B] = Fld::from_u32(b);
                v[r + pre::AND] = Fld::from_u32(a & b);
                v[r + pre::OR] = Fld::from_u32(a | b);
                v[r + pre::XOR] = Fld::from_u32(a ^ b);
            }
        }
        Some(RowMajorMatrix::new(v, pre::WIDTH))
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for NibbleAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let (a, bb, and, or, xor) = (
            p.current(pre::A).unwrap(), p.current(pre::B).unwrap(),
            p.current(pre::AND).unwrap(), p.current(pre::OR).unwrap(), p.current(pre::XOR).unwrap(),
        );
        let (ma, mo, mx) = (m.current(col::M_AND).unwrap(), m.current(col::M_OR).unwrap(), m.current(col::M_XOR).unwrap());
        bus::AND4.table_entry(b, [a.into(), bb.into(), and.into()], ma.into());
        bus::OR4.table_entry(b, [a.into(), bb.into(), or.into()], mo.into());
        bus::XOR4.table_entry(b, [a.into(), bb.into(), xor.into()], mx.into());
    }
}

/// Counts every lookup the other tables perform against the nibble table, in lock-step
/// with the interactions their AIRs declare.
#[derive(Clone, Debug, Default)]
pub struct NibbleCounts { pub and: Vec<u64>, pub or: Vec<u64>, pub xor: Vec<u64> }
impl NibbleCounts {
    fn ensure(&mut self) {
        if self.and.is_empty() { self.and = vec![0; HEIGHT]; self.or = vec![0; HEIGHT]; self.xor = vec![0; HEIGHT]; }
    }
    pub fn and4(&mut self, a: u32, b: u32) { self.ensure(); assert!(a < 16 && b < 16); self.and[row_of(a, b)] += 1; }
    pub fn or4(&mut self, a: u32, b: u32) { self.ensure(); assert!(a < 16 && b < 16); self.or[row_of(a, b)] += 1; }
    pub fn xor4(&mut self, a: u32, b: u32) { self.ensure(); assert!(a < 16 && b < 16); self.xor[row_of(a, b)] += 1; }
}

pub fn nibble_trace(c: &NibbleCounts) -> RowMajorMatrix<F> {
    let mut c = c.clone();
    c.ensure();
    let mut v = F::zero_vec(HEIGHT * col::WIDTH);
    for r in 0..HEIGHT {
        v[r * col::WIDTH + col::M_AND] = F::from_u64(c.and[r]);
        v[r * col::WIDTH + col::M_OR] = F::from_u64(c.or[r]);
        v[r * col::WIDTH + col::M_XOR] = F::from_u64(c.xor[r]);
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
