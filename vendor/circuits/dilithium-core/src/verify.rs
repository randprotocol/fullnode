//! Port of `crystals-dilithium` 2.0.0 `sign/lvl2.rs` `verify` (reached from `dilithium2.rs:245`,
//! `PublicKey::verify`). Each `fips202` call goes through [`Shake`] / [`shake256`] over the
//! caller's [`Keccak`].
//!
//! Shape change, same output: the reference expands all of A (`matrix_expand`) and then multiplies
//! (`matrix_pointwise_montgomery`); here one row of A is expanded and consumed at a time, and the
//! `t1_2` copy is gone (`k_pointwise_poly_montgomery` is in place). The order of the independent
//! steps (challenge, A, NTT of z) is the reference's.
use crate::params::{self as p, CRHBYTES, SEEDBYTES};
use crate::poly::{self, Poly, Polyveck, Polyvecl};
use crate::{packing, shake256, Keccak, Shake};

/// The phase-1 Montgomery-domain verifier, kept verbatim as the in-tree reference for the
/// [`Ring`](crate::ring::Ring) backends. Verify a round-3 Dilithium2 signature `sig` on `m` under `pk`. Agrees with
/// `crystals_dilithium::dilithium2::PublicKey::verify` on every input; never panics; no heap.
pub fn verify_reference<K: Keccak>(
    k: &mut K,
    pk: &[u8; p::PUBLICKEYBYTES],
    m: &[u8],
    sig: &[u8; p::SIGNBYTES],
) -> bool {
    let mut buf = [0u8; p::K * p::POLYW1_PACKEDBYTES];
    let mut rho = [0u8; SEEDBYTES];
    let mut mu = [0u8; CRHBYTES];
    let mut c = [0u8; SEEDBYTES];
    let mut c2 = [0u8; SEEDBYTES];
    let mut cp = Poly::default();
    let (mut row, mut z) = (Polyvecl::default(), Polyvecl::default());
    let (mut t1, mut w1, mut h) = (
        Polyveck::default(),
        Polyveck::default(),
        Polyveck::default(),
    );

    // (sig.len() != SIGNBYTES is unrepresentable: `sig` is a fixed-size array.)

    packing::unpack_pk(&mut rho, &mut t1, pk);
    if !packing::unpack_sig(&mut c, &mut z, &mut h, sig) {
        return false;
    }
    if poly::l_chknorm(&z, (p::GAMMA1 - p::BETA) as i32) > 0 {
        return false;
    }

    // Compute CRH(CRH(rho, t1), msg)
    shake256(k, &[pk], &mut mu[..SEEDBYTES]);
    let mut state = Shake::new256(&mut *k); // shake256_init()
    state.absorb(&mu[..SEEDBYTES]);
    state.absorb(m);
    state.finalize();
    state.squeeze(&mut mu);

    // Matrix-vector multiplication; compute Az - c2^dt1
    poly::challenge(k, &mut cp, &c);

    poly::l_ntt(&mut z);
    for i in 0..p::K {
        // matrix_expand row i, then matrix_pointwise_montgomery row i
        poly::matrix_expand_row(k, &mut row, &rho, i);
        poly::l_pointwise_acc_montgomery(&mut w1.vec[i], &row, &z);
    }

    poly::ntt(&mut cp);
    poly::k_shiftl(&mut t1);
    poly::k_ntt(&mut t1);
    poly::k_pointwise_poly_montgomery(&mut t1, &cp);

    poly::k_sub(&mut w1, &t1);
    poly::k_reduce(&mut w1);
    poly::k_invntt_tomont(&mut w1);

    // Reconstruct w1
    poly::k_caddq(&mut w1);
    poly::k_use_hint(&mut w1, &h);
    poly::k_pack_w1(&mut buf, &w1);

    // Call random oracle and verify challenge
    let mut state = Shake::new256(&mut *k);
    state.absorb(&mu);
    state.absorb(&buf);
    state.finalize();
    state.squeeze(&mut c2);
    // Doesn't require constant time equality check
    if c != c2 {
        return false;
    }
    true
}

// The z loops below index the K-long `z` rows by `p::K`; that is `p::L` only because they are
// equal.
const _: () = assert!(p::K == p::L && p::L == 4);

use crate::ring::{slot, Arena, Ring, SoftRing};
use crate::{poly::Poly as P, rounding};

/// The verifier over a [`Ring`]: the ring arithmetic runs in the arena, canonical residues
/// throughout. Same accept/reject as [`verify_reference`] on every input (spec §3.6): `chknorm`
/// runs on the centred `z` before it is made canonical, and the `w` entering `use_hint` is the
/// canonical value, which equals the reference's `caddq(w1)` word for word.
pub fn verify_with<K: Keccak, R: Ring>(
    k: &mut K,
    r: &mut R,
    ar: &mut Arena,
    pk: &[u8; p::PUBLICKEYBYTES],
    m: &[u8],
    sig: &[u8; p::SIGNBYTES],
) -> bool {
    let mut buf = [0u8; p::K * p::POLYW1_PACKEDBYTES];
    let mut rho = [0u8; SEEDBYTES];
    let mut mu = [0u8; CRHBYTES];
    let mut c = [0u8; SEEDBYTES];
    let mut c2 = [0u8; SEEDBYTES];
    let mut tmp = P::default();
    let mut z = Polyvecl::default();
    let (mut t1, mut h) = (Polyveck::default(), Polyveck::default());

    packing::unpack_pk(&mut rho, &mut t1, pk);
    if !packing::unpack_sig(&mut c, &mut z, &mut h, sig) {
        return false;
    }
    // On the centred z, before canonicalisation.
    if poly::l_chknorm(&z, (p::GAMMA1 - p::BETA) as i32) > 0 {
        return false;
    }
    for i in 0..p::K {
        for j in 0..256 {
            // t1 << 13 < q (t1 < 1024), canonical.
            ar.p[slot::T1 + i][j] = (t1.vec[i].coeffs[j] << p::D) as u32;
            let zc = z.vec[i].coeffs[j];
            ar.p[slot::Z + i][j] = (zc + ((zc >> 31) & p::Q)) as u32;
        }
    }

    shake256(k, &[pk], &mut mu[..SEEDBYTES]);
    let mut state = Shake::new256(&mut *k);
    state.absorb(&mu[..SEEDBYTES]);
    state.absorb(m);
    state.finalize();
    state.squeeze(&mut mu);

    poly::challenge(k, &mut tmp, &c);
    for j in 0..256 {
        // -1 -> q - 1
        ar.p[slot::C][j] = (tmp.coeffs[j] + ((tmp.coeffs[j] >> 31) & p::Q)) as u32;
    }

    for i in 0..p::K {
        r.ntt(ar, slot::Z + i);
    }
    for i in 0..p::K {
        for j in 0..p::L {
            poly::uniform(k, &mut tmp, &rho, ((i << 8) + j) as u16);
            for x in 0..256 {
                ar.p[slot::ROW + j][x] = tmp.coeffs[x] as u32;
            }
        }
        r.dot4(ar, slot::W + i, slot::ROW, slot::Z);
    }
    r.ntt(ar, slot::C);
    for i in 0..p::K {
        r.ntt(ar, slot::T1 + i);
    }
    r.msub4(ar, slot::W, slot::C, slot::T1);
    for i in 0..p::K {
        r.intt(ar, slot::W + i);
    }

    // use_hint on the canonical w, then pack w1.
    for i in 0..p::K {
        for j in 0..256 {
            tmp.coeffs[j] = rounding::use_hint(ar.p[slot::W + i][j] as i32, h.vec[i].coeffs[j]);
        }
        let (chunks, _) = buf.as_chunks_mut::<{ p::POLYW1_PACKEDBYTES }>();
        poly::w1_pack(&mut chunks[i], &tmp);
    }

    let mut state = Shake::new256(&mut *k);
    state.absorb(&mu);
    state.absorb(&buf);
    state.finalize();
    state.squeeze(&mut c2);
    c == c2
}

/// [`verify_with`] over [`SoftRing`] and a stack arena (21 KiB): the host / no-syscall verifier.
pub fn verify<K: Keccak>(
    k: &mut K,
    pk: &[u8; p::PUBLICKEYBYTES],
    m: &[u8],
    sig: &[u8; p::SIGNBYTES],
) -> bool {
    verify_with(k, &mut SoftRing, &mut Arena::new(), pk, m, sig)
}

/// [`verify_with`] on the wire format as little-endian words (`pk` 328, `sig` 605): the guest's
/// verifier, with no byte buffers on the hot path. Same accept/reject as [`verify_reference`] on
/// every input (spec §3.6), by construction of each step:
///
/// - `t1 << 13` and `z` (as `gamma1 - t`, then canonical) are unpacked straight into the arena;
///   the `chknorm` test is made on the centred `z` in the same pass, before canonicalisation
///   matters, and a failure returns before anything else runs;
/// - ExpandA samples straight from the SHAKE128 state words into the arena's A row;
/// - `use_hint` and `w1_pack` are one pass over the canonical `w` (the `caddq(w1)` of the
///   reference), the hints applied as patches while the hint section is walked with
///   `unpack_sig`'s own checks (a malformed section returns `false`, whenever it is reached).
pub fn verify_words_with<K: Keccak, R: Ring>(
    k: &mut K,
    r: &mut R,
    ar: &mut Arena,
    pk: &[u32; packing::PK_WORDS],
    m: &[u8],
    sig: &[u32; packing::SIG_WORDS],
) -> bool {
    let (Some(rho), Some(c)) = (pk.first_chunk::<8>(), sig.first_chunk::<8>()) else {
        return false;
    };
    {
        let Some(zs) = ar.p[slot::Z..].first_chunk_mut::<4>() else { return false };
        if !packing::unpack_z_checked_words(zs, sig) {
            return false;
        }
        let Some(ts) = ar.p[slot::T1..].first_chunk_mut::<4>() else { return false };
        packing::unpack_t1_shifted_words(ts, pk);
    }

    // mu = CRH(CRH(pk), m)
    let mut mu = [0u32; 16];
    {
        let mut state = Shake::new256(&mut *k);
        state.absorb_words(pk);
        state.finalize();
        state.squeeze_words(&mut mu[..8]);
        let mut state = Shake::new256(&mut *k);
        state.absorb_words(&mu[..8]);
        state.absorb(m);
        state.finalize();
        state.squeeze_words(&mut mu);
    }

    poly::challenge_words(k, &mut ar.p[slot::C], c);

    for i in 0..p::K {
        r.ntt(ar, slot::Z + i);
    }
    for i in 0..p::K {
        for j in 0..p::L {
            poly::uniform_words_w(k, &mut ar.p[slot::ROW + j], rho, ((i << 8) + j) as u16);
        }
        r.dot4(ar, slot::W + i, slot::ROW, slot::Z);
    }
    r.ntt(ar, slot::C);
    for i in 0..p::K {
        r.ntt(ar, slot::T1 + i);
    }
    r.msub4(ar, slot::W, slot::C, slot::T1);
    for i in 0..p::K {
        r.intt(ar, slot::W + i);
    }

    // use_hint + w1_pack: the hint = 0 packing, then the hints as patches.
    let mut buf = [0u32; p::K * p::POLYW1_PACKEDBYTES / 4];
    let (polys, _) = buf.as_chunks_mut::<48>();
    for (i, o) in polys.iter_mut().enumerate() {
        rounding::w1_pack_words(o, &ar.p[slot::W + i]);
    }
    let ok = packing::for_each_hint(sig, |i, j| {
        rounding::w1_apply_hint(&mut polys[i], &ar.p[slot::W + i], j)
    });
    if !ok {
        return false;
    }

    let mut state = Shake::new256(&mut *k);
    state.absorb_words(&mu);
    state.absorb_words(&buf);
    state.finalize();
    let mut c2 = [0u32; 8];
    state.squeeze_words(&mut c2);
    c2 == *c
}
