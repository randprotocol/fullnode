//! 2^16-row preprocessed table of every byte pair, serving five buses.
use super::{bus, F};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;

pub const HEIGHT: usize = 1 << 16;

/// Preprocessed columns.
pub mod pre {
    pub const A: usize = 0;
    pub const B: usize = 1;
    pub const AND: usize = 2;
    pub const OR: usize = 3;
    pub const XOR: usize = 4;
    pub const POW2: usize = 5; // 2^A on rows with B == 0 and A < 32, else 0
    pub const IS_POW2: usize = 6; // 1 on those rows
    pub const WIDTH: usize = 7;
}
/// Main columns: one multiplicity per bus.
pub mod col {
    pub const M_RANGE: usize = 0;
    pub const M_AND: usize = 1;
    pub const M_OR: usize = 2;
    pub const M_XOR: usize = 3;
    pub const M_POW2: usize = 4;
    pub const WIDTH: usize = 5;
}

#[inline]
pub fn row_of(a: u32, b: u32) -> usize {
    (a as usize) * 256 + b as usize
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ByteAir;

impl<Fld: Field> BaseAir<Fld> for ByteAir {
    fn width(&self) -> usize {
        col::WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        pre::WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        let mut v = Fld::zero_vec(HEIGHT * pre::WIDTH);
        for a in 0..256u32 {
            for b in 0..256u32 {
                let r = row_of(a, b) * pre::WIDTH;
                v[r + pre::A] = Fld::from_u32(a);
                v[r + pre::B] = Fld::from_u32(b);
                v[r + pre::AND] = Fld::from_u32(a & b);
                v[r + pre::OR] = Fld::from_u32(a | b);
                v[r + pre::XOR] = Fld::from_u32(a ^ b);
                if b == 0 && a < 32 {
                    v[r + pre::POW2] = Fld::from_u32(1 << a);
                    v[r + pre::IS_POW2] = Fld::ONE;
                }
            }
        }
        Some(RowMajorMatrix::new(v, pre::WIDTH))
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ByteAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let p = b.preprocessed().clone();
        let m = b.main();
        let (a, bb, and, or, xor, pow2, is_pow2) = (
            p.current(pre::A).unwrap(),
            p.current(pre::B).unwrap(),
            p.current(pre::AND).unwrap(),
            p.current(pre::OR).unwrap(),
            p.current(pre::XOR).unwrap(),
            p.current(pre::POW2).unwrap(),
            p.current(pre::IS_POW2).unwrap(),
        );
        let (mr, ma, mo, mx, mp) = (
            m.current(col::M_RANGE).unwrap(),
            m.current(col::M_AND).unwrap(),
            m.current(col::M_OR).unwrap(),
            m.current(col::M_XOR).unwrap(),
            m.current(col::M_POW2).unwrap(),
        );
        // POW2 entries may only be consumed on pow2 rows.
        b.assert_zero(mp.into() * (AB::Expr::ONE - is_pow2.into()));
        bus::RANGE8.table_entry(b, [a.into()], mr.into());
        bus::AND8.table_entry(b, [a.into(), bb.into(), and.into()], ma.into());
        bus::OR8.table_entry(b, [a.into(), bb.into(), or.into()], mo.into());
        bus::XOR8.table_entry(b, [a.into(), bb.into(), xor.into()], mx.into());
        bus::POW2.table_entry(b, [a.into(), pow2.into()], mp.into());
    }
}

/// Counts every lookup the other tables perform. Trace builders call these in
/// lock-step with the interactions their AIRs declare.
#[derive(Clone, Debug, Default)]
pub struct ByteCounts {
    pub range: Vec<u64>,
    pub and: Vec<u64>,
    pub or: Vec<u64>,
    pub xor: Vec<u64>,
    pub pow2: Vec<u64>,
}
impl ByteCounts {
    fn ensure(&mut self) {
        if self.range.is_empty() {
            for v in [
                &mut self.range,
                &mut self.and,
                &mut self.or,
                &mut self.xor,
                &mut self.pow2,
            ] {
                *v = vec![0; HEIGHT];
            }
        }
    }
    pub fn range8(&mut self, x: u32) {
        self.ensure();
        assert!(x < 256);
        self.range[row_of(x, 0)] += 1;
    }
    pub fn and8(&mut self, a: u32, b: u32) {
        self.ensure();
        self.and[row_of(a, b)] += 1;
    }
    pub fn or8(&mut self, a: u32, b: u32) {
        self.ensure();
        self.or[row_of(a, b)] += 1;
    }
    pub fn xor8(&mut self, a: u32, b: u32) {
        self.ensure();
        self.xor[row_of(a, b)] += 1;
    }
    pub fn pow2(&mut self, s: u32) {
        self.ensure();
        assert!(s < 32);
        self.pow2[row_of(s, 0)] += 1;
    }
}

pub fn byte_trace(c: &ByteCounts) -> RowMajorMatrix<F> {
    let mut c = c.clone();
    c.ensure();
    let mut v = F::zero_vec(HEIGHT * col::WIDTH);
    for r in 0..HEIGHT {
        v[r * col::WIDTH + col::M_RANGE] = F::from_u64(c.range[r]);
        v[r * col::WIDTH + col::M_AND] = F::from_u64(c.and[r]);
        v[r * col::WIDTH + col::M_OR] = F::from_u64(c.or[r]);
        v[r * col::WIDTH + col::M_XOR] = F::from_u64(c.xor[r]);
        v[r * col::WIDTH + col::M_POW2] = F::from_u64(c.pow2[r]);
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
