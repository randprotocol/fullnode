//! Port of `crystals-dilithium` 2.0.0 `rounding/lvl2.rs` (the verify half: `decompose`,
//! `use_hint`).
use crate::params::{self, Q};
const GAMMA2: i32 = params::GAMMA2 as i32;

/// For finite field element a, compute high and low bits a0, a1 such that
/// a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2, except if a1 = (Q-1)/ALPHA where we
/// set a1 = 0 and -ALPHA/2 <= a0 = a mod^+ Q - Q < 0. Assumes a to be standard representative.
///
/// Returns a tuple (a0, a1).
pub fn decompose(a: i32) -> (i32, i32) {
    let mut a1: i32 = (a + 127) >> 7;
    a1 = (a1 * 11275 + (1 << 23)) >> 24;
    a1 ^= ((43 - a1) >> 31) & a1;
    let mut a0: i32 = a - a1 * 2 * GAMMA2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a0, a1)
}

/// Correct high bits according to hint.
///
/// Returns corrected high bits.
pub fn use_hint(a: i32, hint: i32) -> i32 {
    let (a0, a1) = decompose(a);
    if hint == 0 {
        return a1;
    }
    if a0 > 0 {
        if a1 == 43 {
            0
        } else {
            a1 + 1
        }
    } else if a1 == 0 {
        43
    } else {
        a1 - 1
    }
}

// ---------------------------------------------------------------------------------- word path

/// `decompose`'s high part `a1` for a canonical `a < q`: the reference's formula with the fold of
/// `a1 = 44` to `0` as a multiply by a compare.
#[inline(always)]
fn high_bits(a: u32) -> u32 {
    let a1 = (((a + 127) >> 7) * 11275 + (1 << 23)) >> 24;
    a1 * (a1 < 44) as u32
}

/// Pack the high parts of one canonical polynomial `w`, 6 bits each, 16 coefficients to 3 words.
/// This is `use_hint` with `hint = 0` (which returns `a1`) followed by `w1_pack`; the bit stream
/// is the reference's byte layout read as little-endian words.
pub fn w1_pack_words(out: &mut [u32; 48], w: &[u32; 256]) {
    for (o, c) in out.as_chunks_mut::<3>().0.iter_mut().zip(w.as_chunks::<16>().0) {
        let h = |i: usize| high_bits(c[i]);
        let (h5, h10) = (h(5), h(10));
        o[0] = h(0) | h(1) << 6 | h(2) << 12 | h(3) << 18 | h(4) << 24 | h5 << 30;
        crate::packing::barrier(); // keep the scheduler from spilling a whole group (see there)
        o[1] = h5 >> 2 | h(6) << 4 | h(7) << 10 | h(8) << 16 | h(9) << 22 | h10 << 28;
        crate::packing::barrier();
        o[2] = h10 >> 4 | h(11) << 2 | h(12) << 8 | h(13) << 14 | h(14) << 20 | h(15) << 26;
    }
}

/// Replace coefficient `j`'s field in a packed polynomial by `use_hint(w[j], 1)`.
pub fn w1_apply_hint(out: &mut [u32; 48], w: &[u32; 256], j: usize) {
    let v = use_hint(w[j] as i32, 1) as u32;
    let b = 6 * j;
    let (wi, sh) = (b >> 5, (b & 31) as u32);
    out[wi] = out[wi] & !(63 << sh) | v << sh;
    if sh > 26 {
        // The field straddles into the next word.
        out[wi + 1] = out[wi + 1] & !(63 >> (32 - sh)) | v >> (32 - sh);
    }
}

/// `use_hint` then `w1_pack` over the four canonical polynomials `w` and 0/1 hints `h`, in one
/// pass over `w` (the hints are applied as patches to the `hint = 0` packing).
pub fn use_hint_pack_w1(out: &mut [u8; 768], w: &[[u32; 256]; 4], h: &[[u32; 256]; 4]) {
    for k in 0..4 {
        let mut p = [0u32; 48];
        w1_pack_words(&mut p, &w[k]);
        for j in 0..256 {
            if h[k][j] != 0 {
                w1_apply_hint(&mut p, &w[k], j);
            }
        }
        for (i, x) in p.iter().enumerate() {
            out[192 * k + 4 * i..192 * k + 4 * i + 4].copy_from_slice(&x.to_le_bytes());
        }
    }
}
