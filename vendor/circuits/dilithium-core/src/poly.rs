//! Port of the verify half of `crystals-dilithium` 2.0.0 `poly.rs`, `poly/lvl2.rs` and
//! `polyvec/lvl2.rs`. Fixed-size arrays only; every SHAKE goes through [`Shake`] over the
//! caller's [`Keccak`].
//!
//! Two deliberate shape changes, neither changing any output:
//! - `matrix_expand` + `matrix_pointwise_montgomery` become [`matrix_expand_row`], called from
//!   verify's row loop, so only one row of A (4 KiB) is live instead of all of A (16 KiB).
//! - [`k_pointwise_poly_montgomery`] works in place (the reference copies `t1` to `t1_2` first);
//!   the product is coefficient-wise, so in place is identical.
use crate::params::{self, SEEDBYTES, SHAKE128_RATE, SHAKE256_RATE};
use crate::{ntt, reduce, rounding, Keccak, Shake};

const N: usize = params::N as usize;
const K: usize = params::K;
const L: usize = params::L;
const UNIFORM_NBLOCKS: usize = (767 + SHAKE128_RATE) / SHAKE128_RATE;

/// Represents a polynomial
#[derive(Clone, Copy)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Poly { coeffs: [0i32; N] }
    }
}

// ---------------------------------------------------------------------------------- poly.rs

/// Inplace reduction of all coefficients of polynomial to representative in [-6283009,6283007].
pub fn reduce(a: &mut Poly) {
    for coeff in a.coeffs.iter_mut() {
        *coeff = reduce::reduce32(*coeff);
    }
}

/// For all coefficients of in/out polynomial add Q if coefficient is negative.
pub fn caddq(a: &mut Poly) {
    for coeff in a.coeffs.iter_mut() {
        *coeff = reduce::caddq(*coeff);
    }
}

/// Add polynomials in place. No modular reduction is performed.
pub fn add_ip(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a.coeffs[i] += b.coeffs[i];
    }
}

/// Subtract polynomials in place. No modular reduction is performed.
pub fn sub_ip(a: &mut Poly, b: &Poly) {
    for i in 0..N {
        a.coeffs[i] -= b.coeffs[i];
    }
}

/// Multiply polynomial by 2^D without modular reduction.
/// Assumes input coefficients to be less than 2^{31-D} in absolute value.
pub fn shiftl(a: &mut Poly) {
    for coeff in a.coeffs.iter_mut() {
        *coeff <<= params::D;
    }
}

/// Inplace forward NTT. Coefficients can grow by 8*Q in absolute value.
pub fn ntt(a: &mut Poly) {
    ntt::ntt(&mut a.coeffs);
}

/// Inplace inverse NTT and multiplication by 2^{32}.
pub fn invntt_tomont(a: &mut Poly) {
    ntt::invntt_tomont(&mut a.coeffs);
}

/// Pointwise multiplication of polynomials in NTT domain representation and multiplication of
/// resulting polynomial by 2^{-32}.
pub fn pointwise_montgomery(c: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        c.coeffs[i] = reduce::montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
    }
}

/// Check infinity norm of polynomial against given bound.
/// Assumes input coefficients were reduced by reduce32().
///
/// Returns 0 if norm is strictly smaller than B and B <= (Q-1)/8, 1 otherwise.
pub fn chknorm(a: &Poly, b: i32) -> i32 {
    if b > (params::Q - 1) / 8 {
        return 1;
    }
    for i in 0..N {
        let mut t = a.coeffs[i] >> 31;
        t = a.coeffs[i] - (t & (2 * a.coeffs[i]));
        if t >= b {
            return 1;
        }
    }
    0
}

/// Sample uniformly random coefficients in [0, Q-1] by performing rejection sampling on array of
/// random bytes.
///
/// Returns number of sampled coefficients. Can be smaller than a.len() if not enough random bytes
/// were given.
pub fn rej_uniform(a: &mut [i32], alen: usize, buf: &[u8], buflen: usize) -> usize {
    // Clamp to the real lengths: every caller passes alen <= a.len() and buflen <= buf.len(), so
    // this changes nothing, but it makes the indexing below provably in bounds.
    let alen = if alen < a.len() { alen } else { a.len() };
    let buflen = if buflen < buf.len() {
        buflen
    } else {
        buf.len()
    };
    let mut ctr: usize = 0;
    let mut pos: usize = 0;
    while ctr < alen && pos + 3 <= buflen {
        let mut t = buf[pos] as u32;
        t |= (buf[pos + 1] as u32) << 8;
        t |= (buf[pos + 2] as u32) << 16;
        t &= 0x7FFFFF;
        pos += 3;
        let t = t as i32;
        if t < params::Q {
            a[ctr] = t;
            ctr += 1;
        }
    }
    ctr
}

/// Sample polynomial with uniformly random coefficients in [0, Q-1] by performing rejection
/// sampling using the output stream of SHAKE128(seed|nonce).
pub fn uniform<H: Keccak>(k: &mut H, a: &mut Poly, seed: &[u8; SEEDBYTES], nonce: u16) {
    // fips202::shake128_stream_init
    let mut state = Shake::new128(&mut *k);
    let t = [nonce as u8, (nonce >> 8) as u8];
    state.absorb(seed);
    state.absorb(&t);
    state.finalize();

    let mut buf = [0u8; UNIFORM_NBLOCKS * SHAKE128_RATE + 2];
    state.squeeze(&mut buf[..UNIFORM_NBLOCKS * SHAKE128_RATE]);

    let mut buflen: usize = UNIFORM_NBLOCKS * SHAKE128_RATE;
    let mut ctr = rej_uniform(&mut a.coeffs, N, &buf, buflen);

    while ctr < N {
        let off = buflen % 3;
        for i in 0..off {
            buf[i] = buf[buflen - off + i];
        }
        buflen = SHAKE128_RATE + off;
        state.squeeze(&mut buf[off..off + SHAKE128_RATE]);
        ctr += rej_uniform(&mut a.coeffs[ctr..], N - ctr, &buf, buflen);
    }
}

/// Unpack polynomial t1 with 10-bit coefficients.
/// Output coefficients are standard representatives.
#[allow(clippy::identity_op)]
pub fn t1_unpack(r: &mut Poly, a: &[u8; params::POLYT1_PACKEDBYTES]) {
    for i in 0..N / 4 {
        r.coeffs[4 * i + 0] =
            (((a[5 * i + 0] >> 0) as u32 | (a[5 * i + 1] as u32) << 8) & 0x3FF) as i32;
        r.coeffs[4 * i + 1] =
            (((a[5 * i + 1] >> 2) as u32 | (a[5 * i + 2] as u32) << 6) & 0x3FF) as i32;
        r.coeffs[4 * i + 2] =
            (((a[5 * i + 2] >> 4) as u32 | (a[5 * i + 3] as u32) << 4) & 0x3FF) as i32;
        r.coeffs[4 * i + 3] =
            (((a[5 * i + 3] >> 6) as u32 | (a[5 * i + 4] as u32) << 2) & 0x3FF) as i32;
    }
}

// ---------------------------------------------------------------------------------- poly/lvl2.rs

/// Use hint polynomial to correct the high bits of a polynomial.
pub fn use_hint(a: &mut Poly, hint: &Poly) {
    for i in 0..N {
        a.coeffs[i] = rounding::use_hint(a.coeffs[i], hint.coeffs[i]);
    }
}

/// Implementation of H. Samples polynomial with TAU nonzero coefficients in {-1,1} using the
/// output stream of SHAKE256(seed).
#[allow(clippy::needless_range_loop)]
pub fn challenge<H: Keccak>(k: &mut H, c: &mut Poly, seed: &[u8; SEEDBYTES]) {
    let mut state = Shake::new256(&mut *k);
    state.absorb(seed);
    state.finalize();

    let mut buf = [0u8; SHAKE256_RATE];
    state.squeeze(&mut buf);

    let mut signs: u64 = 0;
    for i in 0..8 {
        signs |= (buf[i] as u64) << (8 * i);
    }

    let mut pos: usize = 8;
    c.coeffs.fill(0);
    for i in (N - params::TAU)..N {
        let mut b: usize;
        loop {
            if pos >= SHAKE256_RATE {
                state.squeeze(&mut buf);
                pos = 0;
            }
            b = buf[pos] as usize;
            pos += 1;
            if b <= i {
                break;
            }
        }
        c.coeffs[i] = c.coeffs[b];
        c.coeffs[b] = 1 - 2 * ((signs & 1) as i32);
        signs >>= 1;
    }
}

/// Unpack polynomial z with coefficients in [-(GAMMA1 - 1), GAMMA1 - 1].
#[allow(clippy::identity_op)]
pub fn z_unpack(r: &mut Poly, a: &[u8; params::POLYZ_PACKEDBYTES]) {
    for i in 0..N / 4 {
        r.coeffs[4 * i + 0] = a[9 * i + 0] as i32;
        r.coeffs[4 * i + 0] |= (a[9 * i + 1] as i32) << 8;
        r.coeffs[4 * i + 0] |= (a[9 * i + 2] as i32) << 16;
        r.coeffs[4 * i + 0] &= 0x3FFFF;

        r.coeffs[4 * i + 1] = (a[9 * i + 2] as i32) >> 2;
        r.coeffs[4 * i + 1] |= (a[9 * i + 3] as i32) << 6;
        r.coeffs[4 * i + 1] |= (a[9 * i + 4] as i32) << 14;
        r.coeffs[4 * i + 1] &= 0x3FFFF;

        r.coeffs[4 * i + 2] = (a[9 * i + 4] as i32) >> 4;
        r.coeffs[4 * i + 2] |= (a[9 * i + 5] as i32) << 4;
        r.coeffs[4 * i + 2] |= (a[9 * i + 6] as i32) << 12;
        r.coeffs[4 * i + 2] &= 0x3FFFF;

        r.coeffs[4 * i + 3] = (a[9 * i + 6] as i32) >> 6;
        r.coeffs[4 * i + 3] |= (a[9 * i + 7] as i32) << 2;
        r.coeffs[4 * i + 3] |= (a[9 * i + 8] as i32) << 10;
        r.coeffs[4 * i + 3] &= 0x3FFFF;

        r.coeffs[4 * i + 0] = params::GAMMA1 as i32 - r.coeffs[4 * i + 0];
        r.coeffs[4 * i + 1] = params::GAMMA1 as i32 - r.coeffs[4 * i + 1];
        r.coeffs[4 * i + 2] = params::GAMMA1 as i32 - r.coeffs[4 * i + 2];
        r.coeffs[4 * i + 3] = params::GAMMA1 as i32 - r.coeffs[4 * i + 3];
    }
}

/// Bit-pack polynomial w1 with coefficients in [0, 43].
/// Input coefficients are assumed to be standard representatives.
#[allow(clippy::identity_op)]
pub fn w1_pack(r: &mut [u8; params::POLYW1_PACKEDBYTES], a: &Poly) {
    for i in 0..N / 4 {
        r[3 * i + 0] = a.coeffs[4 * i + 0] as u8;
        r[3 * i + 0] |= (a.coeffs[4 * i + 1] << 6) as u8;
        r[3 * i + 1] = (a.coeffs[4 * i + 1] >> 2) as u8;
        r[3 * i + 1] |= (a.coeffs[4 * i + 2] << 4) as u8;
        r[3 * i + 2] = (a.coeffs[4 * i + 2] >> 4) as u8;
        r[3 * i + 2] |= (a.coeffs[4 * i + 3] << 2) as u8;
    }
}

// ---------------------------------------------------------------------------------- polyvec/lvl2.rs

#[derive(Clone, Copy)]
pub struct Polyveck {
    pub vec: [Poly; K],
}

impl Default for Polyveck {
    fn default() -> Self {
        Polyveck {
            vec: [Poly::default(); K],
        }
    }
}

#[derive(Clone, Copy)]
pub struct Polyvecl {
    pub vec: [Poly; L],
}

impl Default for Polyvecl {
    fn default() -> Self {
        Polyvecl {
            vec: [Poly::default(); L],
        }
    }
}

/// Row `i` of ExpandA (the reference's `matrix_expand` loop body for one `i`): a_{i,j} by
/// rejection sampling on the output stream of SHAKE128(rho|j|i).
pub fn matrix_expand_row<H: Keccak>(
    k: &mut H,
    row: &mut Polyvecl,
    rho: &[u8; SEEDBYTES],
    i: usize,
) {
    for j in 0..L {
        uniform(k, &mut row.vec[j], rho, ((i << 8) + j) as u16);
    }
}

/// Pointwise multiply vectors of polynomials of length L, multiply resulting vector by 2^{-32}
/// and add (accumulate) polynomials in it.
pub fn l_pointwise_acc_montgomery(w: &mut Poly, u: &Polyvecl, v: &Polyvecl) {
    pointwise_montgomery(w, &u.vec[0], &v.vec[0]);
    let mut t = Poly::default();
    for i in 1..L {
        pointwise_montgomery(&mut t, &u.vec[i], &v.vec[i]);
        add_ip(w, &t);
    }
}

/// Forward NTT of all polynomials in vector of length L.
pub fn l_ntt(v: &mut Polyvecl) {
    for i in 0..L {
        ntt(&mut v.vec[i]);
    }
}

pub fn l_chknorm(v: &Polyvecl, bound: i32) -> u8 {
    for i in 0..L {
        if chknorm(&v.vec[i], bound) > 0 {
            return 1;
        }
    }
    0
}

/// Reduce coefficients of polynomials in vector of length K.
pub fn k_reduce(v: &mut Polyveck) {
    for i in 0..K {
        reduce(&mut v.vec[i]);
    }
}

/// For all coefficients of polynomials in vector of length K add Q if coefficient is negative.
pub fn k_caddq(v: &mut Polyveck) {
    for i in 0..K {
        caddq(&mut v.vec[i]);
    }
}

/// Subtract vectors of polynomials of length K. No modular reduction is performed.
pub fn k_sub(w: &mut Polyveck, v: &Polyveck) {
    for i in 0..K {
        sub_ip(&mut w.vec[i], &v.vec[i]);
    }
}

/// Multiply vector of polynomials of Length K by 2^D without modular reduction.
pub fn k_shiftl(v: &mut Polyveck) {
    for i in 0..K {
        shiftl(&mut v.vec[i]);
    }
}

/// Forward NTT of all polynomials in vector of length K.
pub fn k_ntt(v: &mut Polyveck) {
    for i in 0..K {
        ntt(&mut v.vec[i]);
    }
}

/// Inverse NTT and multiplication by 2^{32} of polynomials in vector of length K.
pub fn k_invntt_tomont(v: &mut Polyveck) {
    for i in 0..K {
        invntt_tomont(&mut v.vec[i]);
    }
}

/// `r[i] = a * r[i]` (pointwise, Montgomery), in place. The reference's
/// `k_pointwise_poly_montgomery(r, a, v)` is always called with `v` a copy of `r`.
pub fn k_pointwise_poly_montgomery(r: &mut Polyveck, a: &Poly) {
    for i in 0..K {
        for j in 0..N {
            r.vec[i].coeffs[j] =
                reduce::montgomery_reduce(a.coeffs[j] as i64 * r.vec[i].coeffs[j] as i64);
        }
    }
}

pub fn k_use_hint(a: &mut Polyveck, hint: &Polyveck) {
    for i in 0..K {
        use_hint(&mut a.vec[i], &hint.vec[i]);
    }
}

pub fn k_pack_w1(r: &mut [u8; K * params::POLYW1_PACKEDBYTES], a: &Polyveck) {
    let (chunks, _) = r.as_chunks_mut::<{ params::POLYW1_PACKEDBYTES }>();
    for (chunk, p) in chunks.iter_mut().zip(a.vec.iter()) {
        w1_pack(chunk, p);
    }
}

// ---------------------------------------------------------------------------------- word paths

/// [`uniform`] from the `rho` words, straight into `out` (no `Poly`, no byte buffer): the
/// SHAKE128(rho ‖ nonce) rate is read as 42 words per block, four 23-bit candidates per three
/// words, accepted in stream order while `< q` until 256 are in. `rho` is the LE view of the
/// reference's 32 seed bytes.
///
/// The reference squeezes five blocks and then one at a time; the candidates are one stream, and
/// 256 candidates never fit four blocks (224), so the permutation count is the reference's too.
/// (Corner, harmless: the reference squeezes its first five blocks eagerly, this permutes a block
/// only when it needs it. They coincide because 224 < 256, but were that ever to change, or on a
/// stream that rejects so often that a sixth block is needed, only the permutation / cycle count
/// could differ from the reference, never a sample.)
pub fn uniform_words_w<H: Keccak>(k: &mut H, out: &mut [u32; N], rho: &[u32; 8], nonce: u16) {
    const M: u32 = 0x7f_ffff;
    const Q: u32 = params::Q as u32;
    // SHAKE128 absorb + finalize, in place: rho, the two nonce bytes, the 0x1f pad byte (byte 34)
    // and the final bit of the 168-byte rate (byte 167).
    // (Written out as a literal: `[0; 50]` plus stores is a `memset` call, about twice the cost.)
    let mut st: [u32; 50] = [
        rho[0], rho[1], rho[2], rho[3], rho[4], rho[5], rho[6], rho[7], nonce as u32 | 0x1f << 16,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // words 9..41
        1 << 31, // word 41, the last rate word
        0, 0, 0, 0, 0, 0, 0, 0, // the capacity
    ];
    // Store through a running pointer. The common group (all four candidates accepted, four slots
    // left) is four `sw` and one `addi`; anything else takes the checked per-candidate path.
    let base = out.as_mut_ptr();
    let end = base.wrapping_add(N);
    let limit = end.addr() - 4 * 4;
    let mut p = base;
    loop {
        k.permute_words(&mut st);
        let mut i = 0;
        while i < 42 {
            let (w0, w1, w2) = (st[i], st[i + 1], st[i + 2]);
            i += 3;
            let c0 = w0 & M;
            let c1 = (w0 >> 24 | w1 << 8) & M;
            let c2 = (w1 >> 16 | w2 << 16) & M;
            let c3 = (w2 >> 8) & M;
            if p.addr() <= limit && ((c0 < Q) as u32 & (c1 < Q) as u32 & (c2 < Q) as u32 & (c3 < Q) as u32) != 0 {
                // SAFETY: `p.addr() <= end.addr() - 16` leaves four u32 slots before `end`, which
                // is one past the end of `out`; `p` only ever advances from `base` by stores.
                unsafe {
                    *p = c0;
                    *p.add(1) = c1;
                    *p.add(2) = c2;
                    *p.add(3) = c3;
                    p = p.add(4);
                }
            } else {
                for c in [c0, c1, c2, c3] {
                    if p != end && c < Q {
                        // SAFETY: `p != end` and `p` only advances by one past each store, so
                        // `p` is in `out`.
                        unsafe {
                            *p = c;
                            p = p.add(1);
                        }
                    }
                }
                if p == end {
                    return;
                }
            }
        }
    }
}

/// [`uniform_words_w`] over seed bytes: equals [`uniform`] coefficient for coefficient.
pub fn uniform_words<H: Keccak>(k: &mut H, out: &mut [u32; N], seed: &[u8; SEEDBYTES], nonce: u16) {
    let rho: [u32; 8] = core::array::from_fn(|i| {
        u32::from_le_bytes([seed[4 * i], seed[4 * i + 1], seed[4 * i + 2], seed[4 * i + 3]])
    });
    uniform_words_w(k, out, &rho, nonce)
}

/// [`challenge`] from the seed words, into `out` as canonical residues (`-1` as `q - 1`).
pub fn challenge_words<H: Keccak>(k: &mut H, out: &mut [u32; N], seed: &[u32; 8]) {
    let mut state = Shake::new256(&mut *k);
    state.absorb_words(seed);
    state.finalize();

    let mut buf = [0u32; SHAKE256_RATE / 4];
    state.squeeze_words(&mut buf);

    let mut signs: u64 = buf[0] as u64 | (buf[1] as u64) << 32;
    let mut pos: usize = 8;
    // `out.fill(0)` is a `memset` call here (about 3 cycles a word); stores with a barrier
    // between passes stay stores (about 1.3).
    for ch in out.as_chunks_mut::<8>().0 {
        *ch = [0; 8];
        crate::packing::barrier();
    }
    for i in (N - params::TAU)..N {
        let mut b: usize;
        loop {
            if pos >= SHAKE256_RATE {
                state.squeeze_words(&mut buf);
                pos = 0;
            }
            b = (buf[pos >> 2] >> (8 * (pos & 3))) as u8 as usize;
            pos += 1;
            if b <= i {
                break;
            }
        }
        out[i] = out[b];
        out[b] = if signs & 1 == 0 { 1 } else { params::Q as u32 - 1 };
        signs >>= 1;
    }
}
