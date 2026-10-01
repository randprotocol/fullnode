//! The EVM's 256-bit word as eight little-endian 32-bit limbs, with the arithmetic the
//! interpreter's opcodes need: wrapping add/sub/mul, unsigned and two's-complement division,
//! `ADDMOD`/`MULMOD` over a 512-bit intermediate, `EXP`, the shifts, `BYTE` and `SIGNEXTEND`.
//!
//! Everything here is `no_std` and allocation-free, and every routine is written for RV32IM: the
//! 32×32→64 products lower to `mul`/`mulhu`, the quotient estimates to `divu`/`remu`. The one
//! routine worth care is [`knuth_divrem`], Knuth's algorithm D over 32-bit limbs, shared by
//! `div`/`rem` (an 8-limb numerator) and `addmod`/`mulmod` (a 16-limb one). `num-bigint` is the
//! oracle for all of it in `research/tests/evm_u256.rs`; none of the carry paths are checked by
//! hand-derived values.

/// A 256-bit EVM word: limb 0 is the least significant 32 bits.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct U256(pub [u32; 8]);

impl U256 {
    pub const ZERO: U256 = U256([0; 8]);
    pub const ONE: U256 = U256([1, 0, 0, 0, 0, 0, 0, 0]);
    pub const MAX: U256 = U256([u32::MAX; 8]);

    pub fn from_u32(v: u32) -> U256 {
        U256([v, 0, 0, 0, 0, 0, 0, 0])
    }

    pub fn from_u64(v: u64) -> U256 {
        U256([v as u32, (v >> 32) as u32, 0, 0, 0, 0, 0, 0])
    }

    /// Limb 0 is the *last* four bytes: big-endian in, little-endian limbs out.
    pub fn from_be_bytes(b: &[u8; 32]) -> U256 {
        let mut l = [0u32; 8];
        for i in 0..8 {
            let o = 28 - 4 * i;
            l[i] = u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        }
        U256(l)
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for i in 0..8 {
            b[28 - 4 * i..32 - 4 * i].copy_from_slice(&self.0[i].to_be_bytes());
        }
        b
    }

    /// At most 32 bytes, right-aligned in the word — `PUSHn`'s immediate and `CALLDATALOAD`'s
    /// zero-padded tail. A longer slice is a caller bug; the low 32 bytes are taken.
    pub fn from_be_slice(b: &[u8]) -> U256 {
        debug_assert!(b.len() <= 32);
        let take = if b.len() > 32 { 32 } else { b.len() };
        let mut full = [0u8; 32];
        full[32 - take..].copy_from_slice(&b[b.len() - take..]);
        U256::from_be_bytes(&full)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u32; 8]
    }

    pub fn low_u32(&self) -> u32 {
        self.0[0]
    }

    pub fn low_u64(&self) -> u64 {
        self.0[0] as u64 | ((self.0[1] as u64) << 32)
    }

    /// Limbs 1..8 all zero, so `low_u32` loses nothing — what every offset/length check wants.
    pub fn fits_u32(&self) -> bool {
        self.0[1..] == [0u32; 7]
    }

    /// Position of the highest set bit plus one; zero for zero.
    pub fn bit_len(&self) -> u32 {
        for i in (0..8).rev() {
            if self.0[i] != 0 {
                return 32 * i as u32 + 32 - self.0[i].leading_zeros();
            }
        }
        0
    }

    /// Number of significant bytes; zero for zero (`EXP`'s gas and `RETURN`'s sizes want this).
    pub fn byte_len(&self) -> u32 {
        (self.bit_len() + 7) / 8
    }

    pub fn add(&self, o: &U256) -> U256 {
        let (r, _) = self.add_carry(o);
        r
    }

    /// The sum with its carry out of bit 255 — the 257th bit `addmod` needs.
    fn add_carry(&self, o: &U256) -> (U256, u32) {
        let mut r = [0u32; 8];
        let mut c = 0u64;
        for i in 0..8 {
            let s = self.0[i] as u64 + o.0[i] as u64 + c;
            r[i] = s as u32;
            c = s >> 32;
        }
        (U256(r), c as u32)
    }

    pub fn sub(&self, o: &U256) -> U256 {
        let mut r = [0u32; 8];
        let mut b = 0i64;
        for i in 0..8 {
            let d = self.0[i] as i64 - o.0[i] as i64 - b;
            r[i] = d as u32;
            b = (d < 0) as i64;
        }
        U256(r)
    }

    /// Schoolbook 8×8 limbs, keeping only the low 8 (mod 2^256). RV32M's `mul`/`mulhu` do the
    /// 32×32→64.
    pub fn mul(&self, o: &U256) -> U256 {
        let w = mul_wide(&self.0, &o.0);
        let mut l = [0u32; 8];
        l.copy_from_slice(&w[..8]);
        U256(l)
    }

    /// `x / 0 = 0` (the EVM's rule, not a trap).
    pub fn div(&self, o: &U256) -> U256 {
        if o.is_zero() {
            U256::ZERO
        } else {
            divrem(&self.0, &o.0).0
        }
    }

    /// `x % 0 = 0`.
    pub fn rem(&self, o: &U256) -> U256 {
        if o.is_zero() {
            U256::ZERO
        } else {
            divrem(&self.0, &o.0).1
        }
    }

    pub fn is_neg(&self) -> bool {
        self.0[7] >> 31 == 1
    }

    fn neg(&self) -> U256 {
        U256::ZERO.sub(self)
    }

    /// The magnitude, except for `MIN`, whose negation wraps back to `MIN` — which is exactly
    /// what makes the EVM's `MIN / -1 = MIN` fall out of `sdiv` below.
    fn abs(&self) -> U256 {
        if self.is_neg() {
            self.neg()
        } else {
            *self
        }
    }

    /// Truncating toward zero, as the EVM's `SDIV` does; `x / 0 = 0`.
    pub fn sdiv(&self, o: &U256) -> U256 {
        if o.is_zero() {
            return U256::ZERO;
        }
        let q = self.abs().div(&o.abs());
        if self.is_neg() != o.is_neg() {
            q.neg()
        } else {
            q
        }
    }

    /// The remainder takes the *dividend's* sign, as the EVM's `SMOD` does; `x % 0 = 0`.
    pub fn smod(&self, o: &U256) -> U256 {
        if o.is_zero() {
            return U256::ZERO;
        }
        let r = self.abs().rem(&o.abs());
        if self.is_neg() {
            r.neg()
        } else {
            r
        }
    }

    /// `(a + b) mod m` over the true 257-bit sum, never the wrapped one; `m = 0 → 0`.
    pub fn addmod(&self, o: &U256, m: &U256) -> U256 {
        if m.is_zero() {
            return U256::ZERO;
        }
        let (s, c) = self.add_carry(o);
        let mut wide = [0u32; 16];
        wide[..8].copy_from_slice(&s.0);
        wide[8] = c;
        U256(rem_wide(&wide, &m.0))
    }

    /// `(a · b) mod m` over the full 512-bit product; `m = 0 → 0`.
    pub fn mulmod(&self, o: &U256, m: &U256) -> U256 {
        if m.is_zero() {
            return U256::ZERO;
        }
        U256(rem_wide(&mul_wide(&self.0, &o.0), &m.0))
    }

    /// Square-and-multiply over the exponent's bits; `x^0 = 1`, `0^0 = 1`.
    pub fn exp(&self, e: &U256) -> U256 {
        let mut acc = U256::ONE;
        let mut base = *self;
        let bits = e.bit_len();
        for i in 0..bits {
            if (e.0[(i / 32) as usize] >> (i % 32)) & 1 == 1 {
                acc = acc.mul(&base);
            }
            base = base.mul(&base);
        }
        acc
    }

    /// Sign-extend from byte `b`, counting byte 0 as the least significant; `b >= 31` is the
    /// identity (and so is a `b` too wide for a `u32`).
    pub fn signextend(&self, b: &U256) -> U256 {
        if !b.fits_u32() || b.low_u32() >= 31 {
            return *self;
        }
        let bit = b.low_u32() * 8 + 7; // the sign bit of byte b
        let mask = U256::ONE.shl(&U256::from_u32(bit + 1)).sub(&U256::ONE); // bits 0..=bit
        let set = (self.0[(bit / 32) as usize] >> (bit % 32)) & 1 == 1;
        if set {
            self.or(&mask.not())
        } else {
            self.and(&mask)
        }
    }

    pub fn lt(&self, o: &U256) -> bool {
        for i in (0..8).rev() {
            if self.0[i] != o.0[i] {
                return self.0[i] < o.0[i];
            }
        }
        false
    }

    /// Two's-complement `<`: a negative value is below every non-negative one.
    pub fn slt(&self, o: &U256) -> bool {
        if self.is_neg() != o.is_neg() {
            self.is_neg()
        } else {
            self.lt(o)
        }
    }

    pub fn and(&self, o: &U256) -> U256 {
        U256(core::array::from_fn(|i| self.0[i] & o.0[i]))
    }

    pub fn or(&self, o: &U256) -> U256 {
        U256(core::array::from_fn(|i| self.0[i] | o.0[i]))
    }

    pub fn xor(&self, o: &U256) -> U256 {
        U256(core::array::from_fn(|i| self.0[i] ^ o.0[i]))
    }

    pub fn not(&self) -> U256 {
        U256(core::array::from_fn(|i| !self.0[i]))
    }

    /// Shift left by `n` bits; `n >= 256 → 0`.
    pub fn shl(&self, n: &U256) -> U256 {
        if !n.fits_u32() || n.low_u32() >= 256 {
            return U256::ZERO;
        }
        let (words, bits) = ((n.low_u32() / 32) as usize, n.low_u32() % 32);
        let mut r = [0u32; 8];
        for i in (words..8).rev() {
            let lo = self.0[i - words] << bits;
            let hi = if bits > 0 && i - words > 0 {
                self.0[i - words - 1] >> (32 - bits)
            } else {
                0
            };
            r[i] = lo | hi;
        }
        U256(r)
    }

    /// Logical shift right by `n` bits; `n >= 256 → 0`.
    pub fn shr(&self, n: &U256) -> U256 {
        if !n.fits_u32() || n.low_u32() >= 256 {
            return U256::ZERO;
        }
        let (words, bits) = ((n.low_u32() / 32) as usize, n.low_u32() % 32);
        let mut r = [0u32; 8];
        for i in 0..8 - words {
            let lo = self.0[i + words] >> bits;
            let hi = if bits > 0 && i + words + 1 < 8 {
                self.0[i + words + 1] << (32 - bits)
            } else {
                0
            };
            r[i] = lo | hi;
        }
        U256(r)
    }

    /// Arithmetic shift right by `n` bits; `n >= 256` fills with the sign (0 or `MAX`).
    pub fn sar(&self, n: &U256) -> U256 {
        let neg = self.is_neg();
        if !n.fits_u32() || n.low_u32() >= 256 {
            return if neg { U256::MAX } else { U256::ZERO };
        }
        let r = self.shr(n);
        if !neg {
            return r;
        }
        let fill = U256::MAX.shl(&U256::from_u32(256 - n.low_u32())); // the top n bits
        r.or(&fill)
    }

    /// Byte `i` counting from the *most* significant; `i >= 32 → 0`.
    pub fn byte(&self, i: &U256) -> U256 {
        if !i.fits_u32() || i.low_u32() >= 32 {
            return U256::ZERO;
        }
        U256::from_u32(self.to_be_bytes()[i.low_u32() as usize] as u32)
    }
}

/// 8×8 → 16 limbs, the full 512-bit product.
fn mul_wide(a: &[u32; 8], b: &[u32; 8]) -> [u32; 16] {
    let mut r = [0u32; 16];
    for i in 0..8 {
        let mut c = 0u64;
        for j in 0..8 {
            let t = a[i] as u64 * b[j] as u64 + r[i + j] as u64 + c;
            r[i + j] = t as u32;
            c = t >> 32;
        }
        // Never written by an earlier `i`: that pass stopped at `i - 1 + 8`.
        r[i + 8] = c as u32;
    }
    r
}

/// The remainder of a 16-limb numerator by a non-zero 8-limb divisor; the quotient (up to 16
/// limbs, so not a `U256`) is discarded.
fn rem_wide(n: &[u32; 16], d: &[u32; 8]) -> [u32; 8] {
    knuth_divrem(n, d).1
}

/// Quotient and remainder of an 8-limb numerator by a non-zero 8-limb divisor.
fn divrem(n: &[u32; 8], d: &[u32; 8]) -> (U256, U256) {
    let (q, r) = knuth_divrem(n, d);
    (U256(q), U256(r))
}

/// Knuth's algorithm D over 32-bit limbs: long division of `n` (up to 16 limbs, little-endian) by
/// the non-zero `d`, returning the quotient's low 8 limbs and the remainder. The divisor is
/// normalised so its top limb has bit 31 set, each quotient digit is estimated from the top two
/// numerator limbs over the top divisor limb (one `u64 / u32`), corrected at most twice, and the
/// multiply-subtract adds the divisor back on the rare negative result.
///
/// A quotient limb above index 7 can only be non-zero when the numerator exceeds `d · 2^256`,
/// which happens only for the wide `addmod`/`mulmod` callers — and they want the remainder alone,
/// so the high digits are computed (the remainder depends on them) and dropped.
fn knuth_divrem(n: &[u32], d: &[u32; 8]) -> ([u32; 8], [u32; 8]) {
    debug_assert!(n.len() <= 16);
    let mut q = [0u32; 8];
    let dn = significant_limbs(d);
    debug_assert!(dn > 0, "division by zero is the caller's to rule out");
    let m = significant_limbs(n);
    if m < dn {
        // The quotient is zero and the numerator is its own remainder (it fits in 8 limbs,
        // since `dn <= 8`).
        let mut r = [0u32; 8];
        r[..m].copy_from_slice(&n[..m]);
        return (q, r);
    }
    if dn == 1 {
        // Short division: one 64-by-32 step per limb.
        let d0 = d[0] as u64;
        let mut rem = 0u64;
        for i in (0..m).rev() {
            let cur = (rem << 32) | n[i] as u64;
            if i < 8 {
                q[i] = (cur / d0) as u32;
            }
            rem = cur % d0;
        }
        let mut r = [0u32; 8];
        r[0] = rem as u32;
        return (q, r);
    }

    // Normalise: shift both operands left so `dv[dn - 1]` has its high bit set, which is what
    // bounds the quotient-digit estimate's error at 2.
    let s = d[dn - 1].leading_zeros();
    let mut dv = [0u32; 8];
    for i in (0..dn).rev() {
        let hi = d[i] << s;
        let lo = if s > 0 && i > 0 { d[i - 1] >> (32 - s) } else { 0 };
        dv[i] = hi | lo;
    }
    let mut un = [0u32; 17]; // the numerator, normalised, with one extra high limb
    for i in (0..m).rev() {
        let hi = n[i] << s;
        let lo = if s > 0 && i > 0 { n[i - 1] >> (32 - s) } else { 0 };
        un[i] = hi | lo;
    }
    un[m] = if s > 0 { n[m - 1] >> (32 - s) } else { 0 };

    for j in (0..=m - dn).rev() {
        let num = ((un[j + dn] as u64) << 32) | un[j + dn - 1] as u64;
        let mut qhat = num / dv[dn - 1] as u64;
        let mut rhat = num % dv[dn - 1] as u64;
        // Correct the estimate down (at most twice) against the next divisor limb.
        while qhat >> 32 != 0
            || qhat * dv[dn - 2] as u64 > ((rhat << 32) | un[j + dn - 2] as u64)
        {
            qhat -= 1;
            rhat += dv[dn - 1] as u64;
            if rhat >> 32 != 0 {
                break;
            }
        }
        // Multiply and subtract `qhat · dv` from the numerator window.
        let mut carry = 0u64;
        let mut borrow = 0i64;
        for i in 0..dn {
            let p = qhat * dv[i] as u64 + carry;
            carry = p >> 32;
            let t = un[i + j] as i64 - borrow - (p as u32) as i64;
            un[i + j] = t as u32;
            borrow = (t < 0) as i64;
        }
        let t = un[j + dn] as i64 - carry as i64 - borrow;
        un[j + dn] = t as u32;
        if t < 0 {
            // The estimate was one too large (probability ~2^-32): add the divisor back.
            qhat -= 1;
            let mut c = 0u64;
            for i in 0..dn {
                let sum = un[i + j] as u64 + dv[i] as u64 + c;
                un[i + j] = sum as u32;
                c = sum >> 32;
            }
            un[j + dn] = (un[j + dn] as u64 + c) as u32;
        }
        if j < 8 {
            q[j] = qhat as u32;
        }
    }

    // Denormalise the remainder: its `dn` low limbs shifted back right by `s`.
    let mut r = [0u32; 8];
    for i in 0..dn {
        let lo = un[i] >> s;
        let hi = if s > 0 { un[i + 1] << (32 - s) } else { 0 };
        r[i] = lo | hi;
    }
    (q, r)
}

/// The number of limbs up to and including the highest non-zero one.
fn significant_limbs(v: &[u32]) -> usize {
    let mut n = v.len();
    while n > 0 && v[n - 1] == 0 {
        n -= 1;
    }
    n
}
