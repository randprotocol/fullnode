//! The ring arithmetic of Dilithium2 verification behind a trait, over a fixed arena of 256-word
//! polynomials (spec §3.4 of the MODQ chip design). Three backends agree on every input:
//! [`SoftRing`] (canonical `u64` arithmetic, this file), the host's `HostModq` (the emulator's
//! exact semantics, `rand_zkvm::modq`) and the guest's `SyscallRing` (the `MODQ` syscall).
//!
//! Every backend computes the canonical residues `< q` of the exact mathematical NTT / INTT /
//! pointwise products, not the reference's Montgomery representatives. Inputs are read mod q
//! (any word below `2^24`). `intt` includes the `n^-1` factor, so `intt(ntt(a)) = a mod q`.
use crate::params::{N as N32, Q};

const N: usize = N32 as usize;
const QU: u64 = Q as u64;
/// `256^-1 mod q`.
const N_INV: u64 = 8_347_681;

/// Polynomials in the arena: z (4), one row of A (4), t1 (4), w (4), c, spare for h.
pub const ARENA_POLYS: usize = 21;

/// Poly indices of the verifier's working set.
pub mod slot {
    pub const Z: usize = 0;
    pub const ROW: usize = 4;
    pub const T1: usize = 8;
    pub const W: usize = 12;
    pub const C: usize = 16;
    pub const H: usize = 17;
}

/// `ARENA_POLYS` polynomials, `256` words each, 4-aligned (the syscall takes a word address).
#[repr(C, align(4))]
pub struct Arena {
    pub p: [[u32; N]; ARENA_POLYS],
}

impl Arena {
    pub const fn new() -> Self {
        Arena { p: [[0; N]; ARENA_POLYS] }
    }
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

/// The four ring operations of the `MODQ` chip. `p`, `out`, `a`, `b`, `c`, `t` are poly indices
/// into the arena. `dot4` writes `out = sum_{k<4} ar[a+k] * ar[b+k]`; `msub4` sets
/// `ar[out+k] -= ar[c] * ar[t+k]` for `k < 4`. Aliasing rules are the chip's (`DOT4`: the two
/// read spans disjoint; `MSUB4`: `[out,out+4)`, `[t,t+4)` and `{c}` pairwise disjoint).
pub trait Ring {
    fn ntt(&mut self, ar: &mut Arena, p: usize);
    fn intt(&mut self, ar: &mut Arena, p: usize);
    fn dot4(&mut self, ar: &mut Arena, out: usize, a: usize, b: usize);
    fn msub4(&mut self, ar: &mut Arena, out: usize, c: usize, t: usize);
}

impl<R: Ring + ?Sized> Ring for &mut R {
    fn ntt(&mut self, ar: &mut Arena, p: usize) {
        (**self).ntt(ar, p)
    }
    fn intt(&mut self, ar: &mut Arena, p: usize) {
        (**self).intt(ar, p)
    }
    fn dot4(&mut self, ar: &mut Arena, out: usize, a: usize, b: usize) {
        (**self).dot4(ar, out, a, b)
    }
    fn msub4(&mut self, ar: &mut Arena, out: usize, c: usize, t: usize) {
        (**self).msub4(ar, out, c, t)
    }
}

/// The syscall's `a1`: `op | out << 8 | a << 16 | b << 24` (ops: 0 NTT, 1 INTT, 2 DOT4, 3 MSUB4).
pub const fn modq_a1(op: u32, out: usize, a: usize, b: usize) -> u32 {
    op | (out as u32) << 8 | (a as u32) << 16 | (b as u32) << 24
}

const fn pow_mod(b: u64, mut e: u64) -> u64 {
    let (mut r, mut b) = (1u64, b % QU);
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % QU;
        }
        b = b * b % QU;
        e >>= 1;
    }
    r
}

/// `ZETA[k] = 1753^{brv8(k)} mod q`.
const ZETA: [u32; N] = {
    let mut t = [0u32; N];
    let mut k = 0;
    while k < N {
        t[k] = pow_mod(1753, (k as u8).reverse_bits() as u64) as u32;
        k += 1;
    }
    t
};

fn ntt_poly(a: &mut [u32; N]) {
    let mut len = 128;
    let mut k = 0;
    while len > 0 {
        let mut start = 0;
        while start < N {
            k += 1;
            let z = ZETA[k] as u64;
            let mut j = start;
            while j < start + len {
                let u = a[j] as u64 % QU;
                let t = z * (a[j + len] as u64 % QU) % QU;
                a[j] = ((u + t) % QU) as u32;
                a[j + len] = ((u + QU - t) % QU) as u32;
                j += 1;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

fn intt_poly(a: &mut [u32; N]) {
    let mut len = 1;
    let mut k = N;
    while len < N {
        let last = len == N / 2;
        let f = if last { N_INV } else { 1 };
        let mut start = 0;
        while start < N {
            k -= 1;
            let zp = (QU - ZETA[k] as u64) % QU;
            let mut j = start;
            while j < start + len {
                let u = a[j] as u64 % QU;
                let v = a[j + len] as u64 % QU;
                a[j] = (f * ((u + v) % QU) % QU) as u32;
                a[j + len] = (f * (zp * ((u + QU - v) % QU) % QU) % QU) as u32;
                j += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }
}

/// Software arithmetic: the same canonical algorithms as the chip, in `u64`. No heap.
pub struct SoftRing;

impl Ring for SoftRing {
    fn ntt(&mut self, ar: &mut Arena, p: usize) {
        ntt_poly(&mut ar.p[p]);
    }
    fn intt(&mut self, ar: &mut Arena, p: usize) {
        intt_poly(&mut ar.p[p]);
    }
    fn dot4(&mut self, ar: &mut Arena, out: usize, a: usize, b: usize) {
        for c in 0..N {
            let mut acc = 0u64;
            for k in 0..4 {
                acc = (acc + (ar.p[a + k][c] as u64 % QU) * (ar.p[b + k][c] as u64 % QU)) % QU;
            }
            ar.p[out][c] = acc as u32;
        }
    }
    fn msub4(&mut self, ar: &mut Arena, out: usize, c: usize, t: usize) {
        for k in 0..4 {
            for i in 0..N {
                let sub = (ar.p[c][i] as u64 % QU) * (ar.p[t + k][i] as u64 % QU) % QU;
                ar.p[out + k][i] = ((ar.p[out + k][i] as u64 % QU + QU - sub) % QU) as u32;
            }
        }
    }
}
