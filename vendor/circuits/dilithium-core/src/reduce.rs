//! Port of `crystals-dilithium` 2.0.0 `reduce.rs`. The `i64` products lower to `MUL`/`MULH` on
//! RV32IM.
use crate::params;

pub const Q_INV: i32 = 58728449; // q^(-1) mod 2^32

/// For integer a with -2^{31} * Q <= a <= 2^31 * Q,
/// compute r \equiv 2^{-32} * a (mod Q) such that -Q < r < Q.
pub fn montgomery_reduce(a: i64) -> i32 {
    let mut t = (a as i32).wrapping_mul(Q_INV) as i64;
    t = (a - t.wrapping_mul(params::Q as i64)) >> 32;
    t as i32
}

/// For finite field element a with a <= 2^{31} - 2^{22} - 1,
/// compute r \equiv a (mod Q) such that -6283009 <= r <= 6283007.
pub fn reduce32(a: i32) -> i32 {
    let mut t = (a + (1 << 22)) >> 23;
    t = a - t.wrapping_mul(params::Q);
    t
}

/// Add Q if input coefficient is negative.
pub fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & params::Q)
}
