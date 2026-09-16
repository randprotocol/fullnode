//! The rVM's public interface (plan R5): every rVM proof's batch public values are exactly four
//! field elements — the digest of the program's public interface, computed in-circuit — and the
//! fullnode recomputes the §4.4 list from the covered bundles' public fields and compares the
//! digest. The cs6 `H_PUB` pattern (`Machine::verify_public`): the words travel with the
//! transaction, the proof carries only their commitment.
//!
//! The list itself, its layout, and the recompute-and-compare flow are spec §4.4 unchanged; only
//! what travels in the proof's public values changed (a variable-length list cannot be a batch
//! public-value vector at all, and tying a raw 39-word list to the trace costs ~78 columns).
use crate::isa::F;
use crate::shape::{inner_vk_digest, VerifierShape};
use p3_field::PrimeCharacteristicRing;

/// The hash-domain tag of [`public_digest`]. `randprotocol_zkvm::notes::domain` is occupied through 14,
/// `RVM_PROGRAM_DOMAIN` is 15 and `RVM_VK_DOMAIN` is 16; all four share one permutation, so a
/// collision would let one construction's digest stand in for another's.
pub const RVM_PUB_DOMAIN: u64 = 17;

/// The 4-element commitment of a public interface word list: the header — the domain tag and the
/// word count — seeded into the *capacity* lanes of the first permutation's input, then each
/// block of four overwrites rate lanes `0..4` and the state is permuted once; a trailing partial
/// block overwrites only its own lanes (the padding-free rule, `dsl::hash`'s doc). The
/// `Program::digest` construction generalized to a word slice, and exactly what the verifier
/// program's phase 8 computes in-circuit — the two are pinned to each other by
/// `tests/verifier.rs`'s differential.
pub fn public_digest(words: &[F]) -> [F; 4] {
    assert!(!words.is_empty(), "a padding-free sponge over an empty message is not a hash");
    let mut state = [F::ZERO; 8];
    state[4] = F::from_u64(RVM_PUB_DOMAIN);
    state[5] = F::from_u64(words.len() as u64);
    let mut done = 0;
    while done < words.len() {
        let k = (words.len() - done).min(4);
        state[..k].copy_from_slice(&words[done..done + k]);
        state = randprotocol_zkvm::hash::permute_state(state);
        done += k;
    }
    [state[0], state[1], state[2], state[3]]
}

/// The §4.4 list for one verified inner-proof set, in order: the inner verifier key digest
/// (4 elements), `N`, then `N ×` the shape's public-value count inner public values (constraint
/// set 6's `pv::NUM = 34` on the RV32 machine, `machine::NUM_PUBLIC_VALUES = 4` on the rVM —
/// `PUB0..7` included on both, since dropping `HC0..7` would let an aggregate accept a proof of
/// a different guest). The fullnode recomputes this list from the covered bundles' public fields
/// and its registered `hc`, hashes it with [`public_digest`], and compares.
///
/// Generic over [`VerifierShape`] (M5.4, T5): the RV32 machine's shape and the rVM's own
/// build the same list through the same call.
pub fn interface_words<S: VerifierShape>(shape: &S, key: &S::Key, pvs: &[Vec<u64>]) -> Vec<F> {
    let mut w = inner_vk_digest(shape, key).to_vec();
    w.push(F::from_u64(pvs.len() as u64));
    for pv in pvs {
        assert_eq!(
            pv.len(),
            shape.num_public_values()[shape.pv_instance()],
            "every inner proof carries exactly the shape's public-value count"
        );
        w.extend(pv.iter().map(|x| F::from_u64(*x)));
    }
    w
}
