//! 32-bit ALU as four byte limbs. Add/sub/compare share one adder; bitwise ops
//! and shifts go through the byte table; shifts are proved as exact integer
//! identities that cannot wrap in Goldilocks.
use super::{bus, byte::ByteCounts, limbs, F};
use crate::emulator::{AluEvent, CycleEvent};
use crate::isa::AluOp;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const FLAG0: usize = 0;   // 11 flags, AluOp code order
    pub const A: usize = 11; pub const B: usize = 12; pub const C: usize = 13;
    pub const A0: usize = 14; pub const B0: usize = 18; pub const C0: usize = 22;
    pub const Q0: usize = 26;     // shift quotient / sll high word limbs
    pub const S0: usize = 30;     // compare difference / right-shift remainder limbs
    pub const T0: usize = 34;     // pw - 1 - r limbs
    pub const SA: usize = 38; pub const SB: usize = 39; pub const SH: usize = 40; pub const PW: usize = 41;
    pub const CARRY0: usize = 42; pub const INV: usize = 46; pub const IS_REAL: usize = 47; pub const MULT: usize = 48;
    pub const WIDTH: usize = 49;
}
use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct AluAir;

impl<Fld> BaseAir<Fld> for AluAir { fn width(&self) -> usize { WIDTH } }

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for AluAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let c8 = |k: u32| AB::Expr::from_u32(1u32 << (8 * k));
        let f = |op: AluOp| v(FLAG0 + op.code() as usize);
        let (add, sub, and, or, xor, sll, srl, sra, slt, sltu, eq) = (
            f(AluOp::Add), f(AluOp::Sub), f(AluOp::And), f(AluOp::Or), f(AluOp::Xor), f(AluOp::Sll),
            f(AluOp::Srl), f(AluOp::Sra), f(AluOp::Slt), f(AluOp::Sltu), f(AluOp::Eq),
        );
        let is_real = v(IS_REAL);
        b.assert_bool(is_real.clone());
        let mut sum = AB::Expr::ZERO;
        for i in 0..AluOp::COUNT { b.assert_bool(v(FLAG0 + i)); sum += v(FLAG0 + i); }
        b.assert_eq(sum, is_real.clone());

        // limb recomposition and range checks
        let word = |base: usize| v(base) + v(base + 1) * c8(1) + v(base + 2) * c8(2) + v(base + 3) * c8(3);
        b.assert_eq(word(A0), v(A));
        b.assert_eq(word(B0), v(B));
        b.assert_eq(word(C0), v(C));
        for i in 0..4 {
            for base in [A0, B0, C0] { bus::RANGE8.lookup_key(b, [v(base + i)], Count::bounded(is_real.clone(), 1)); }
        }
        let cmp = slt.clone() + sltu.clone();
        let rshift = srl.clone() + sra.clone();
        let shift = sll.clone() + rshift.clone();
        for i in 0..4 {
            bus::RANGE8.lookup_key(b, [v(S0 + i)], Count::bounded(cmp.clone() + rshift.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(T0 + i)], Count::bounded(rshift.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(Q0 + i)], Count::bounded(shift.clone(), 1));
        }

        // shared adder: x + y = z (mod 2^32) with limb carries
        let adder = add.clone() + sub.clone() + cmp.clone();
        for i in 0..4 {
            let x = add.clone() * v(A0 + i) + sub.clone() * v(B0 + i) + cmp.clone() * v(B0 + i);
            let y = add.clone() * v(B0 + i) + sub.clone() * v(C0 + i) + cmp.clone() * v(S0 + i);
            let z = add.clone() * v(C0 + i) + (sub.clone() + cmp.clone()) * v(A0 + i);
            let cin = if i == 0 { AB::Expr::ZERO } else { v(CARRY0 + i - 1) };
            b.assert_bool(v(CARRY0 + i));
            b.assert_zero((one.clone() - adder.clone()) * v(CARRY0 + i));
            b.assert_zero(x + y + cin - z - v(CARRY0 + i) * AB::Expr::from_u32(256));
        }
        let borrow = v(CARRY0 + 3);
        // sign bits
        b.assert_bool(v(SA));
        b.assert_bool(v(SB));
        let c128 = AB::Expr::from_u32(128);
        bus::AND8.lookup_key(b, [v(A0 + 3), c128.clone(), v(SA) * c128.clone()], Count::bounded(slt.clone() + sra.clone(), 1));
        bus::AND8.lookup_key(b, [v(B0 + 3), c128.clone(), v(SB) * c128.clone()], Count::bounded(slt.clone(), 1));
        b.assert_zero(srl.clone() * v(SA));
        // compares
        b.assert_zero((cmp.clone() + eq.clone()) * v(C) * (v(C) - one.clone()));
        b.assert_zero(sltu.clone() * (v(C) - borrow.clone()));
        let sx = v(SA) + v(SB) - v(SA) * v(SB) * AB::Expr::TWO;
        b.assert_zero(slt.clone() * (v(C) - (one.clone() - sx.clone()) * borrow.clone() - sx * v(SA)));
        let diff = v(A) - v(B);
        b.assert_zero(eq.clone() * (diff.clone() * v(INV) + v(C) - one.clone()));
        b.assert_zero(eq.clone() * v(C) * diff);
        // bitwise
        for i in 0..4 {
            bus::AND8.lookup_key(b, [v(A0 + i), v(B0 + i), v(C0 + i)], Count::bounded(and.clone(), 1));
            bus::OR8.lookup_key(b, [v(A0 + i), v(B0 + i), v(C0 + i)], Count::bounded(or.clone(), 1));
            bus::XOR8.lookup_key(b, [v(A0 + i), v(B0 + i), v(C0 + i)], Count::bounded(xor.clone(), 1));
        }
        // shifts
        bus::AND8.lookup_key(b, [v(B0), AB::Expr::from_u32(31), v(SH)], Count::bounded(shift.clone(), 1));
        bus::POW2.lookup_key(b, [v(SH), v(PW)], Count::bounded(shift.clone(), 1));
        let q = word(Q0);
        let r = word(S0);
        let t = word(T0);
        let two32 = AB::Expr::from_u64(1 << 32);
        b.assert_zero(sll.clone() * (v(A) * v(PW) - q.clone() * two32 - v(C)));
        bus::AND8.lookup_key(b, [v(Q0 + 3), c128, AB::Expr::ZERO], Count::bounded(sll.clone(), 1));
        // right shifts: complement when negative (sra), shift, complement back
        let flip = |x: AB::Expr| x.clone() + v(SA) * (AB::Expr::from_u32(255) - x * AB::Expr::TWO);
        let a_prime = flip(v(A0)) + flip(v(A0 + 1)) * c8(1) + flip(v(A0 + 2)) * c8(2) + flip(v(A0 + 3)) * c8(3);
        b.assert_zero(rshift.clone() * (a_prime - q * v(PW) - r.clone()));
        b.assert_zero(rshift.clone() * (v(PW) - one.clone() - r - t));
        for i in 0..4 { b.assert_zero(rshift.clone() * (v(C0 + i) - flip(v(Q0 + i)))); }

        // provide (op, a, b, c)
        let mut op = AB::Expr::ZERO;
        for i in 0..AluOp::COUNT { op += v(FLAG0 + i) * AB::Expr::from_u32(i as u32); }
        bus::ALU.table_entry(b, [op, v(A), v(B), v(C)], v(MULT));
    }
}

fn set_limbs(row: &mut [F], base: usize, x: u32, counts: &mut ByteCounts, count: bool) {
    let l = limbs(x);
    for i in 0..4 { row[base + i] = l[i]; if count { counts.range8((x >> (8 * i)) & 0xff); } }
}

/// Fill one ALU row from an event and count its byte-table lookups.
pub fn fill_row(row: &mut [F], ev: &AluEvent, counts: &mut ByteCounts) {
    let AluEvent { op, a, b, c } = *ev;
    assert_eq!(c, op.eval(a, b), "ALU event {op:?}({a:#x}, {b:#x}) = {c:#x} does not match reference semantics");
    row[FLAG0 + op.code() as usize] = F::ONE;
    row[A] = F::from_u32(a); row[B] = F::from_u32(b); row[C] = F::from_u32(c);
    row[IS_REAL] = F::ONE; row[MULT] = F::ONE;
    set_limbs(row, A0, a, counts, true); set_limbs(row, B0, b, counts, true); set_limbs(row, C0, c, counts, true);
    let (a3, b3, b0) = ((a >> 24) & 0xff, (b >> 24) & 0xff, b & 0xff);
    let adder = |row: &mut [F], x: u32, y: u32| {
        // carries of x + y limb-wise
        let mut carry = 0u32;
        for i in 0..4 {
            let s = ((x >> (8 * i)) & 0xff) + ((y >> (8 * i)) & 0xff) + carry;
            carry = s >> 8;
            row[CARRY0 + i] = F::from_u32(carry);
        }
    };
    match op {
        AluOp::Add => adder(row, a, b),
        AluOp::Sub => adder(row, b, c),
        AluOp::Slt | AluOp::Sltu => {
            let d = a.wrapping_sub(b);
            set_limbs(row, S0, d, counts, true);
            adder(row, b, d);
            if op == AluOp::Slt {
                row[SA] = F::from_u32(a3 >> 7); row[SB] = F::from_u32(b3 >> 7);
                counts.and8(a3, 128); counts.and8(b3, 128);
            }
        }
        AluOp::Eq => { if a != b { row[INV] = (F::from_u32(a) - F::from_u32(b)).inverse(); } }
        AluOp::And => for i in 0..4 { counts.and8((a >> (8 * i)) & 0xff, (b >> (8 * i)) & 0xff) },
        AluOp::Or => for i in 0..4 { counts.or8((a >> (8 * i)) & 0xff, (b >> (8 * i)) & 0xff) },
        AluOp::Xor => for i in 0..4 { counts.xor8((a >> (8 * i)) & 0xff, (b >> (8 * i)) & 0xff) },
        AluOp::Sll | AluOp::Srl | AluOp::Sra => {
            let sh = b & 31; let pw = 1u32 << sh;
            row[SH] = F::from_u32(sh); row[PW] = F::from_u32(pw);
            counts.and8(b0, 31); counts.pow2(sh);
            if op == AluOp::Sll {
                let hi = ((a as u64 * pw as u64) >> 32) as u32;
                set_limbs(row, Q0, hi, counts, true);
                counts.and8((hi >> 24) & 0xff, 128);
            } else {
                let sa = if op == AluOp::Sra { a >> 31 } else { 0 };
                if op == AluOp::Sra { row[SA] = F::from_u32(sa); counts.and8(a3, 128); }
                let ap = if sa == 1 { !a } else { a };
                let q = ap >> sh; let r = ap - q * pw; let t = pw - 1 - r;
                set_limbs(row, Q0, q, counts, true); set_limbs(row, S0, r, counts, true); set_limbs(row, T0, t, counts, true);
            }
        }
    }
}

pub fn alu_trace(events: &[CycleEvent], height: usize, counts: &mut ByteCounts) -> RowMajorMatrix<F> {
    let evs: Vec<&AluEvent> = events.iter().flat_map(|e| e.alu.iter()).collect();
    assert!(evs.len() < height, "alu table needs a padding row: {} ops, height {height}", evs.len());
    let mut v = F::zero_vec(height * WIDTH);
    for (i, ev) in evs.iter().enumerate() { fill_row(&mut v[i * WIDTH..(i + 1) * WIDTH], ev, counts); }
    RowMajorMatrix::new(v, WIDTH)
}
