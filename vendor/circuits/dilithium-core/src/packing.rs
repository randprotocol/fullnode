//! Port of the verify half of `crystals-dilithium` 2.0.0 `packing/lvl2.rs`: `unpack_pk` and
//! `unpack_sig`, with every hint check. Inputs are fixed-size arrays; sub-arrays are taken with
//! `first_chunk`, whose `None` arm is unreachable at these constant offsets (it rejects rather
//! than panics).
use crate::params::{self, OMEGA, POLYT1_PACKEDBYTES, POLYZ_PACKEDBYTES, SEEDBYTES};
use crate::poly::{self, Polyveck, Polyvecl};

const K: usize = params::K;
const L: usize = params::L;

/// Unpack public key pk = (rho, t1).
pub fn unpack_pk(rho: &mut [u8; SEEDBYTES], t1: &mut Polyveck, pk: &[u8; params::PUBLICKEYBYTES]) {
    if let Some(r) = pk.first_chunk::<SEEDBYTES>() {
        *rho = *r;
    }
    for i in 0..K {
        if let Some(a) =
            pk[SEEDBYTES + i * POLYT1_PACKEDBYTES..].first_chunk::<POLYT1_PACKEDBYTES>()
        {
            poly::t1_unpack(&mut t1.vec[i], a);
        }
    }
}

/// Unpack signature sig = (c, z, h). Returns `false` on a malformed hint section, exactly where
/// the reference does. `h` must arrive zeroed (the reference's `Polyveck::default()`).
#[allow(clippy::needless_range_loop)]
pub fn unpack_sig(
    c: &mut [u8; SEEDBYTES],
    z: &mut Polyvecl,
    h: &mut Polyveck,
    sig: &[u8; params::SIGNBYTES],
) -> bool {
    match sig.first_chunk::<SEEDBYTES>() {
        Some(cc) => *c = *cc,
        None => return false,
    }

    let mut idx = SEEDBYTES;
    for i in 0..L {
        match sig[idx + i * POLYZ_PACKEDBYTES..].first_chunk::<POLYZ_PACKEDBYTES>() {
            Some(a) => poly::z_unpack(&mut z.vec[i], a),
            None => return false,
        }
    }
    idx += L * POLYZ_PACKEDBYTES;

    // The hint section: OMEGA index bytes, then K cumulative counts.
    let hint = match sig[idx..].first_chunk::<{ params::POLYVECH_PACKEDBYTES }>() {
        Some(hint) => hint,
        None => return false,
    };

    let mut k: usize = 0;
    for i in 0..K {
        if hint[OMEGA + i] < k as u8 || hint[OMEGA + i] > OMEGA as u8 {
            return false;
        }
        for j in k..hint[OMEGA + i] as usize {
            if j > k && hint[j] <= hint[j - 1] {
                return false;
            }
            h.vec[i].coeffs[hint[j] as usize] = 1;
        }
        k = hint[OMEGA + i] as usize;
    }

    for j in k..OMEGA {
        if hint[j] > 0 {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------------- word paths

/// Words in a public key / signature (`PUBLICKEYBYTES / 4`, `SIGNBYTES / 4`).
pub const PK_WORDS: usize = params::PUBLICKEYBYTES / 4;
pub const SIG_WORDS: usize = params::SIGNBYTES / 4;
/// First word of `z` (after `c`) and of the hint section, in a signature's words.
const Z_WORD: usize = SEEDBYTES / 4;
const HINT_WORD: usize = (SEEDBYTES + L * POLYZ_PACKEDBYTES) / 4;
const _: () = assert!(
    params::PUBLICKEYBYTES % 4 == 0 && params::SIGNBYTES % 4 == 0 && SEEDBYTES % 4 == 0 && POLYZ_PACKEDBYTES % 4 == 0
);
const _: () = assert!(K == 4 && L == 4);

/// The little-endian words of `b`.
fn words_of<const W: usize>(b: &[u8]) -> [u32; W] {
    core::array::from_fn(|i| u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]))
}

/// `$m!(n)` for `n` in `0..16`: the 16-coefficient groups are unrolled by hand because the
/// compiler leaves them as a loop of variable shifts (about twice the instructions).
macro_rules! unroll16 {
    ($m:ident) => {
        $m!(0); $m!(1); $m!(2); $m!(3);
        barrier();
        $m!(4); $m!(5); $m!(6); $m!(7);
        barrier();
        $m!(8); $m!(9); $m!(10); $m!(11);
        barrier();
        $m!(12); $m!(13); $m!(14); $m!(15);
    };
}

/// Compiler barrier (an empty `asm!`, which may touch memory as far as the optimiser knows).
/// Between four-coefficient groups it stops the scheduler from hoisting all of a group's loads
/// and shifts above the stores, which spilled most of them to the stack (about 4 cycles of the 14
/// each coefficient cost).
#[inline(always)]
pub(crate) fn barrier() {
    // SAFETY: an empty assembly template changes no state.
    unsafe { core::arch::asm!("", options(nostack, preserves_flags)) }
}

/// Field `N` (of `BITS` bits) of the little-endian bit stream `w`, shifted left by `UP`. All of
/// `BITS`, `UP`, `n` are constants at the call sites, so this is a handful of ALU instructions.
#[inline(always)]
fn field<const BITS: usize, const UP: usize, const W: usize, const N: usize>(w: &[u32; W]) -> u32 {
    let (wi, sh) = ((BITS * N) / 32, (BITS * N) % 32);
    let mask = ((1u32 << BITS) - 1) << UP;
    // Bring bit `sh` of `w[wi]` to bit `UP`, and (if the field straddles) the next word's bits
    // above it.
    let lo = if sh <= UP { w[wi] << (UP - sh) } else { w[wi] >> (sh - UP) };
    if sh + BITS > 32 {
        (lo | w[wi + 1] << (32 + UP - sh)) & mask
    } else {
        lo & mask
    }
}

/// `t1 << D` (< q, canonical) for the four polynomials of the public key's words `pk`.
pub fn unpack_t1_shifted_words(out: &mut [[u32; 256]; K], pk: &[u32; PK_WORDS]) {
    const _: () = assert!(params::D == 13 && POLYT1_PACKEDBYTES == 320);
    for (k, poly) in out.iter_mut().enumerate() {
        let src = &pk[SEEDBYTES / 4 + 80 * k..SEEDBYTES / 4 + 80 * (k + 1)];
        // 16 coefficients are 5 words.
        for (o, w) in poly.as_chunks_mut::<16>().0.iter_mut().zip(src.as_chunks::<5>().0) {
            macro_rules! one {
                ($n:literal) => {
                    o[$n] = field::<10, 13, 5, $n>(w);
                };
            }
            unroll16!(one);
        }
    }
}

/// [`unpack_t1_shifted_words`] over the public key's bytes.
pub fn unpack_t1_shifted(out: &mut [[u32; 256]; K], pk: &[u8; params::PUBLICKEYBYTES]) {
    unpack_t1_shifted_words(out, &words_of::<PK_WORDS>(pk))
}

/// Unpack `z` as canonical residues (`gamma1 - t`, plus `q` if negative) and check
/// `||z||_inf < gamma1 - beta` on the centred values in the same pass. Returns `false` iff the
/// norm check fails (the reference's `chknorm > 0`); the hint section is not looked at.
pub fn unpack_z_checked_words(out: &mut [[u32; 256]; L], sig: &[u32; SIG_WORDS]) -> bool {
    const G1: u32 = params::GAMMA1 as u32;
    const B: u32 = (params::GAMMA1 - params::BETA) as u32;
    // |gamma1 - t| < B  <=>  t - (gamma1 - B + 1) < 2B - 1 as an unsigned compare.
    const LO: u32 = G1 - B + 1;
    const SPAN: u32 = 2 * B - 1;
    const _: () = assert!(params::POLYZ_PACKEDBYTES == 576 && params::GAMMA1 == 1 << 17);
    let mut bad = 0u32;
    for (l, poly) in out.iter_mut().enumerate() {
        let src = &sig[Z_WORD + 144 * l..Z_WORD + 144 * (l + 1)];
        // 16 coefficients are 9 words.
        for (o, w) in poly.as_chunks_mut::<16>().0.iter_mut().zip(src.as_chunks::<9>().0) {
            macro_rules! one {
                ($n:literal) => {
                    let t = field::<18, 0, 9, $n>(w);
                    bad |= (t.wrapping_sub(LO) >= SPAN) as u32;
                    let u = G1 as i32 - t as i32;
                    o[$n] = (u + ((u >> 31) & params::Q)) as u32;
                };
            }
            unroll16!(one);
        }
    }
    bad == 0
}

/// [`unpack_z_checked_words`] over the signature's bytes.
pub fn unpack_z_checked(out: &mut [[u32; 256]; L], sig: &[u8; params::SIGNBYTES]) -> bool {
    unpack_z_checked_words(out, &words_of::<SIG_WORDS>(sig))
}

/// Walk the hint section of `sig` exactly as `unpack_sig` does, calling `f(poly, index)` for each
/// set hint, and return `false` on a malformed section: the same checks, in the same order among
/// themselves, as `unpack_sig`'s hint half. The caller runs it after the ring arithmetic (the
/// reference runs it before), which cannot change the answer. (`f` may have run for earlier hints
/// when the answer is `false`.)
pub fn for_each_hint(sig: &[u32; SIG_WORDS], mut f: impl FnMut(usize, usize)) -> bool {
    let hb = |j: usize| (sig[HINT_WORD + (j >> 2)] >> (8 * (j & 3))) as u8;
    let mut k: usize = 0;
    for i in 0..K {
        let cnt = hb(OMEGA + i);
        if cnt < k as u8 || cnt > OMEGA as u8 {
            return false;
        }
        for j in k..cnt as usize {
            if j > k && hb(j) <= hb(j - 1) {
                return false;
            }
            f(i, hb(j) as usize);
        }
        k = cnt as usize;
    }
    for j in k..OMEGA {
        if hb(j) > 0 {
            return false;
        }
    }
    true
}
