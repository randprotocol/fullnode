//! A 256-bit modular multiply-add chip — **prototype** (monorepo issue 68, ZKVM-115).
//!
//! One row proves `r = (a·b + c) mod p` for 256-bit `a`, `b`, `c` and a 256-bit modulus `p`
//! supplied by the caller: the one general operation secp256k1, ed25519's field, bn254 and
//! 256-bit `modexp` are built from. The quotient is a witness.
//!
//! **What this is and is not.** It is an AIR with a trace builder, proved standalone with the
//! range table (`tests/mulmod256.rs`) and attacked there by a forgery suite. It is *not* a
//! coprocessor of the machine: there is no syscall, no cpu handshake, no memory traffic, no gas
//! weight, and `machine::chips` does not know it — so nothing in the constraint set, the keys
//! or the proof format changes, and no guest can call it. Compiled only under the `next-set`
//! feature. `docs/05-roadmap.md`, "ZKVM-115", has what the MODQ chip's pattern carries over,
//! what it does not, the price, and what is left.
//!
//! ## Why not the MODQ chip's arithmetic
//!
//! `tables::modq` proves `O + q·K = α·U + β·V` as a single field identity: `q < 2^23`, so every
//! term fits Goldilocks (`p ≈ 2^64`) without wrapping. A 256-bit product does not fit any
//! field element, so the identity here is proved limb by limb with explicit carries.
//!
//! ## The row
//!
//! All values are little-endian **byte limbs**, each `RANGE8`-checked on a real row:
//! `A`, `B`, `C`, `P`, `R`, `D` (32 limbs each), `Q` (33), and 63 carries of two limbs each.
//!
//! 1. **The product.** For `k = 0..64`, with `S_k = Σ_{i+j=k} A_i·B_j + C_k − Σ_{i+j=k} Q_i·P_j
//!    − R_k` and `carry_k = CL_k + 256·CH_k − 2^14` (`carry_{−1} = carry_63 = 0`):
//!    `S_k + carry_{k−1} = 256·carry_k`. Every limb is a byte, so `|S_k| < 2^23` and
//!    `|256·carry_k| < 2^24`: no equation can wrap mod Goldilocks, each is an integer equation,
//!    and their `256^k`-weighted sum telescopes to `A·B + C = Q·P + R`.
//! 2. **Canonical result.** `R + D + 1 = P` by a byte-wise carry chain with boolean carries
//!    (`DC`): `R_i + D_i + in_i = P_i + 256·DC_i`, `in_0 = 1`, `in_i = DC_{i−1}`, `DC_31 = 0`.
//!    `D ≥ 0`, so `R ≤ P − 1`: with (1), `R` is the canonical residue and `Q` the quotient.
//!    A zero modulus has no satisfying row.
//!
//! `Q` has 33 limbs: `a·b + c < 2^512`, so the quotient fits whenever `p ≥ 2^248`. All four
//! target moduli are above `2^253`. For a smaller modulus an honest prover has no row unless
//! the operands are small enough; the chip refuses rather than mis-proves.
//!
//! Degree: every rule is `IS_REAL ×` a degree-2 form, so 3. Bus counts are degree 1.
//!
//! ## Padding
//!
//! A padding row has `IS_REAL = 0`: no rule is enforced and no lookup is made. Nothing reads a
//! padding row in the prototype; an integrated chip sends on its buses with count `IS_REAL`.
use super::range::RangeCounts;
use super::{bus, F};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

/// Limbs of a 256-bit value.
pub const N: usize = 32;
/// Limbs of the quotient.
pub const NQ: usize = 33;
/// Limb equations of the product identity: positions `0..64`.
pub const NK: usize = N + NQ - 1;
/// Carries between them: `carry_0..carry_62` (`carry_63` is zero).
pub const NCARRY: usize = NK - 1;
/// The offset that makes a signed carry two non-negative byte limbs.
pub const CARRY_OFFSET: u32 = 1 << 14;

pub mod col {
    use super::{N, NCARRY, NQ};
    pub const IS_REAL: usize = 0;
    pub const A: usize = 1;
    pub const B: usize = A + N;
    pub const C: usize = B + N;
    pub const P: usize = C + N;
    pub const Q: usize = P + N;
    pub const R: usize = Q + NQ;
    /// `P − 1 − R`.
    pub const D: usize = R + N;
    /// The boolean carries of `R + D + 1 = P`.
    pub const DC: usize = D + N;
    /// Low and high byte of each offset carry.
    pub const CL: usize = DC + N;
    pub const CH: usize = CL + NCARRY;
    pub const WIDTH: usize = CH + NCARRY; // 384
}

/// `RANGE8` lookups one real row makes: every limb except the boolean `DC`.
pub const LOOKUPS_PER_ROW: usize = 6 * N + NQ + 2 * NCARRY; // A B C P R D + Q + carries = 351

#[derive(Clone, Copy, Debug, Default)]
pub struct Mulmod256Air;

impl<Fld> BaseAir<Fld> for Mulmod256Air {
    fn width(&self) -> usize {
        col::WIDTH
    }
}

/// The columns a real row range-checks, in the order the trace builder counts them.
fn checked_columns() -> impl Iterator<Item = usize> {
    (col::A..col::DC).chain(col::CL..col::WIDTH)
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for Mulmod256Air
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let real = v(col::IS_REAL);
        b.assert_bool(real.clone());

        // (1) The product identity, limb by limb.
        let carry = |k: usize| -> AB::Expr { v(col::CL + k) + v(col::CH + k) * AB::Expr::from_u32(256) - AB::Expr::from_u32(CARRY_OFFSET) };
        for k in 0..NK {
            let mut s = AB::Expr::ZERO;
            for i in 0..N.min(k + 1) {
                let j = k - i;
                if j < N {
                    s += v(col::A + i) * v(col::B + j);
                }
            }
            for i in 0..NQ.min(k + 1) {
                let j = k - i;
                if j < N {
                    s -= v(col::Q + i) * v(col::P + j);
                }
            }
            if k < N {
                s += v(col::C + k) - v(col::R + k);
            }
            if k > 0 {
                s += carry(k - 1);
            }
            if k < NCARRY {
                s -= carry(k) * AB::Expr::from_u32(256);
            }
            b.assert_zero(real.clone() * s);
        }

        // (2) R + D + 1 = P, so R <= P - 1.
        for i in 0..N {
            b.assert_bool(v(col::DC + i));
            let carry_in = if i == 0 { AB::Expr::ONE } else { v(col::DC + i - 1) };
            b.assert_zero(real.clone() * (v(col::R + i) + v(col::D + i) + carry_in - v(col::P + i) - v(col::DC + i) * AB::Expr::from_u32(256)));
        }
        b.assert_zero(real.clone() * v(col::DC + N - 1));

        // Every limb is a byte.
        for c in checked_columns() {
            bus::RANGE8.lookup_key(b, [v(c)], Count::bounded(real.clone(), 1));
        }
    }
}

/// One operation: `(a·b + c) mod p`, little-endian bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MulmodEvent {
    pub a: [u8; N],
    pub b: [u8; N],
    pub c: [u8; N],
    pub p: [u8; N],
}

/// `a·b + c` as 65 little-endian bytes.
fn mul_add(a: &[u8; N], b: &[u8; N], c: &[u8; N]) -> [u8; 2 * N + 1] {
    let mut acc = [0u32; 2 * N + 1];
    for i in 0..N {
        for j in 0..N {
            acc[i + j] += a[i] as u32 * b[j] as u32;
        }
    }
    for i in 0..N {
        acc[i] += c[i] as u32;
    }
    let mut out = [0u8; 2 * N + 1];
    let mut carry = 0u32;
    for i in 0..2 * N + 1 {
        let x = acc[i] + carry;
        out[i] = x as u8;
        carry = x >> 8;
    }
    debug_assert_eq!(carry, 0);
    out
}

/// The quotient and remainder of `(a·b + c) / p`: `None` when `p` is zero or the quotient
/// needs more than 33 bytes (only possible for `p < 2^248`). Bitwise long division: slow and
/// obviously right, which is what a trace builder's reference wants.
pub fn mulmod(a: &[u8; N], b: &[u8; N], c: &[u8; N], p: &[u8; N]) -> Option<([u8; NQ], [u8; N])> {
    if p.iter().all(|x| *x == 0) {
        return None;
    }
    let n = mul_add(a, b, c);
    // rem holds up to 257 bits.
    let mut rem = [0u8; N + 1];
    let mut q = [0u8; 2 * N + 1];
    let ge = |rem: &[u8; N + 1]| -> bool {
        if rem[N] != 0 {
            return true;
        }
        for i in (0..N).rev() {
            if rem[i] != p[i] {
                return rem[i] > p[i];
            }
        }
        true
    };
    for bit in (0..8 * (2 * N + 1)).rev() {
        // rem = rem << 1 | bit
        let mut carry = (n[bit / 8] >> (bit % 8)) & 1;
        for x in rem.iter_mut() {
            let next = *x >> 7;
            *x = (*x << 1) | carry;
            carry = next;
        }
        if ge(&rem) {
            let mut borrow = 0i16;
            for i in 0..N + 1 {
                let d = rem[i] as i16 - if i < N { p[i] as i16 } else { 0 } - borrow;
                borrow = (d < 0) as i16;
                rem[i] = (d + 256 * borrow) as u8;
            }
            q[bit / 8] |= 1 << (bit % 8);
        }
    }
    if q[NQ..].iter().any(|x| *x != 0) {
        return None;
    }
    let mut qq = [0u8; NQ];
    qq.copy_from_slice(&q[..NQ]);
    let mut r = [0u8; N];
    r.copy_from_slice(&rem[..N]);
    Some((qq, r))
}

/// The witness limbs of one row, as integers: what the honest builder writes, and what a
/// forgery edits before [`fill_row`] turns them into field elements. Limbs are `i64` so a
/// forgery can hold a value no byte holds.
#[derive(Clone, Debug)]
pub struct Witness {
    pub a: [i64; N],
    pub b: [i64; N],
    pub c: [i64; N],
    pub p: [i64; N],
    pub q: [i64; NQ],
    pub r: [i64; N],
    pub d: [i64; N],
    pub dc: [i64; N],
}

impl Witness {
    /// The honest witness of an event; `None` when [`mulmod`] has none.
    pub fn honest(e: &MulmodEvent) -> Option<Self> {
        let (q, r) = mulmod(&e.a, &e.b, &e.c, &e.p)?;
        let w = |x: &[u8; N]| -> [i64; N] { core::array::from_fn(|i| x[i] as i64) };
        let mut me = Self { a: w(&e.a), b: w(&e.b), c: w(&e.c), p: w(&e.p), q: core::array::from_fn(|i| q[i] as i64), r: w(&r), d: [0; N], dc: [0; N] };
        me.solve_d();
        Some(me)
    }

    /// `D` and `DC` from `P` and `R`: `D = P − 1 − R`, byte-wise, with the carries of
    /// `R + D + 1`. When `R ≥ P` the subtraction wraps and the last carry is 1 — a row the AIR
    /// refuses, which is the point.
    pub fn solve_d(&mut self) {
        let mut borrow = 1i64; // the "− 1"
        for i in 0..N {
            let x = self.p[i] - self.r[i] - borrow;
            borrow = (x < 0) as i64;
            self.d[i] = x + 256 * borrow;
        }
        let mut carry = 1i64;
        for i in 0..N {
            let x = self.r[i] + self.d[i] + carry;
            carry = (x - self.p[i]) / 256;
            self.dc[i] = carry;
        }
    }

    /// The carries the product identity needs for these limbs, or `None` where a limb equation
    /// is not divisible by 256 (the limbs do not satisfy `A·B + C ≡ Q·P + R` at that position).
    pub fn carries(&self) -> Option<[i64; NCARRY]> {
        let mut out = [0i64; NCARRY];
        let mut carry = 0i64;
        for k in 0..NK {
            let mut s = carry;
            for i in 0..N.min(k + 1) {
                if k - i < N {
                    s += self.a[i] * self.b[k - i];
                }
            }
            for i in 0..NQ.min(k + 1) {
                if k - i < N {
                    s -= self.q[i] * self.p[k - i];
                }
            }
            if k < N {
                s += self.c[k] - self.r[k];
            }
            if s % 256 != 0 {
                return None;
            }
            carry = s / 256;
            if k < NCARRY {
                out[k] = carry;
            } else if carry != 0 {
                return None;
            }
        }
        Some(out)
    }
}

fn felt(x: i64) -> F {
    if x >= 0 {
        F::from_u64(x as u64)
    } else {
        -F::from_u64((-x) as u64)
    }
}

/// Write one real row from a witness and its carries, counting the `RANGE8` lookups of every
/// limb that is a byte (a forged limb outside `0..256` is written and not counted — the range
/// table cannot provide it, which is what refuses it).
pub fn fill_row(row: &mut [F], w: &Witness, carries: &[i64; NCARRY], range: &mut RangeCounts) {
    row[col::IS_REAL] = F::ONE;
    let mut put = |at: usize, xs: &[i64]| {
        for (i, x) in xs.iter().enumerate() {
            row[at + i] = felt(*x);
        }
    };
    put(col::A, &w.a);
    put(col::B, &w.b);
    put(col::C, &w.c);
    put(col::P, &w.p);
    put(col::Q, &w.q);
    put(col::R, &w.r);
    put(col::D, &w.d);
    put(col::DC, &w.dc);
    for k in 0..NCARRY {
        let off = carries[k] + CARRY_OFFSET as i64;
        // Low byte and the rest: the rest is a byte for every honest carry.
        let (lo, hi) = (off.rem_euclid(256), off.div_euclid(256));
        row[col::CL + k] = felt(lo);
        row[col::CH + k] = felt(hi);
    }
    for c in checked_columns() {
        let x = p3_field::PrimeField64::as_canonical_u64(&row[c]);
        if x < 256 {
            range.range8(x as u32);
        }
    }
}

/// One real row per event, then padding. Panics on an event with no honest row (a zero
/// modulus, or a quotient past 33 bytes): the caller's, as `poseidon2_trace`'s capacity is.
pub fn mulmod256_trace(events: &[MulmodEvent], height: usize, range: &mut RangeCounts) -> RowMajorMatrix<F> {
    assert!(events.len() <= height && height.is_power_of_two());
    let mut v = F::zero_vec(height * col::WIDTH);
    for (i, e) in events.iter().enumerate() {
        let w = Witness::honest(e).expect("an event with no honest row: zero modulus, or a quotient past 33 bytes");
        let carries = w.carries().expect("an honest witness satisfies the product identity");
        fill_row(&mut v[i * col::WIDTH..(i + 1) * col::WIDTH], &w, &carries, range);
    }
    RowMajorMatrix::new(v, col::WIDTH)
}
