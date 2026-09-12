//! The call-input envelope (spec §6.1): a confidential call's private inputs, sealed on chain
//! so that the caller's viewing key, a per-call key, or a designated auditor — and nobody else —
//! can read what the program was fed.
//!
//! The chain checks none of this (`shrugg_core::ledger::call_envelope` caps the size and stops);
//! what makes an envelope trustworthy is the AEAD binding to the proof's public `H_IN` plus the
//! holder's own `input_digest` recomputation, and those are what this file pins.

use shrugg_core::notes::{ShieldedAddress, Word8};
use shrugg_zkvm::address::address_of;
use shrugg_zkvm::call_envelope::{
    call_envelope_is_faithful, open_call_as_auditor, open_call_as_sender, open_call_with_key, seal_call_envelope,
    CallKey, MAX_CALL_INPUT_WORDS,
};
use shrugg_zkvm::executor::prove_call;
use shrugg_zkvm::hash::input_digest;
use shrugg_zkvm::machine::{Backend, FriProfile, Proof};
use shrugg_zkvm::notes::{SpendKey, ViewingKey};
use shrugg_zkvm::tables::cpu::pv;

const SALT: [u32; 4] = [0xdead_beef, 2, 3, 0xffff_ffff];

fn vk(seed: u32) -> ViewingKey {
    SpendKey([seed; 8]).viewing_key()
}

fn inputs() -> Vec<u32> {
    vec![7, 0, u32::MAX, 42, 1_000_000]
}

/// The digest an honest caller's envelope is bound to.
fn h_in(salt: [u32; 4], inputs: &[u32]) -> Word8 {
    input_digest(salt, inputs)
}

/// The three scopes of disclosure, on one envelope: the caller's own viewing key, the per-call
/// key it yields, and the auditor the caller named when sealing.
#[test]
fn a_sealed_call_opens_for_the_caller_the_per_call_key_and_the_auditor() {
    let caller = vk(11);
    let auditor = vk(12);
    let auditor_addr = address_of(&auditor);
    let inputs = inputs();
    let h = h_in(SALT, &inputs);

    let (env, key) = seal_call_envelope(&caller, Some(&auditor_addr), &h, SALT, &inputs).unwrap();
    assert!(!env.kem_ct.is_empty() && !env.to_auditor.is_empty(), "an auditor was named");
    assert!(env.len() <= shrugg_core::types::MAX_CALL_ENVELOPE_BYTES);

    let (sender_key, salt, opened) = open_call_as_sender(&env, &h, &caller).expect("the caller opens its own call");
    assert_eq!((sender_key, salt, &opened), (key, SALT, &inputs));

    assert_eq!(open_call_with_key(&env, &h, &key), Some((SALT, inputs.clone())));

    let (audit_key, salt, opened) = open_call_as_auditor(&env, &h, &auditor).expect("the named auditor opens it");
    assert_eq!((audit_key, salt, opened), (key, SALT, inputs.clone()));

    // Nobody else: not a stranger's viewing key, not a stranger as auditor, not a wrong key.
    let stranger = vk(13);
    assert_eq!(open_call_as_sender(&env, &h, &stranger), None);
    assert_eq!(open_call_as_auditor(&env, &h, &stranger), None);
    assert_eq!(open_call_with_key(&env, &h, &CallKey([9; 32])), None);
}

/// Without an auditor the two auditor parts are absent, and the caller's two openings still work.
#[test]
fn an_envelope_without_an_auditor_carries_no_kem_parts() {
    let caller = vk(21);
    let inputs = inputs();
    let h = h_in(SALT, &inputs);
    let (env, key) = seal_call_envelope(&caller, None, &h, SALT, &inputs).unwrap();
    assert!(env.kem_ct.is_empty() && env.to_auditor.is_empty());
    assert_eq!(open_call_as_sender(&env, &h, &caller).map(|(k, s, i)| (k, s, i)), Some((key, SALT, inputs.clone())));
    assert_eq!(open_call_with_key(&env, &h, &key), Some((SALT, inputs)));
    // There is nothing for an auditor to decapsulate.
    assert_eq!(open_call_as_auditor(&env, &h, &caller), None);
}

/// `H_IN` is the body's associated data, so an envelope lifted onto another call — or one whose
/// receipt digest was tampered with — authenticates for no one.
#[test]
fn a_tampered_h_in_opens_for_nobody() {
    let caller = vk(31);
    let auditor = vk(32);
    let inputs = inputs();
    let h = h_in(SALT, &inputs);
    let (env, key) = seal_call_envelope(&caller, Some(&address_of(&auditor)), &h, SALT, &inputs).unwrap();

    let mut wrong = h;
    wrong[3] ^= 1;
    assert_eq!(open_call_as_sender(&env, &wrong, &caller), None);
    assert_eq!(open_call_with_key(&env, &wrong, &key), None);
    assert_eq!(open_call_as_auditor(&env, &wrong, &auditor), None);
    // The real digest still opens it: the envelope itself was not damaged.
    assert!(open_call_with_key(&env, &h, &key).is_some());

    // A damaged body does not open either — the tag covers it.
    let mut torn = env.clone();
    let last = torn.body.len() - 1;
    torn.body[last] ^= 1;
    assert_eq!(open_call_with_key(&torn, &h, &key), None);
}

/// What a holder checks before believing a transcript: the opened `(salt, inputs)` must be the
/// preimage of the receipt's `H_IN`. A caller who published a false envelope is caught here.
#[test]
fn faithfulness_is_the_digest_recomputation() {
    let inputs = inputs();
    let h = h_in(SALT, &inputs);
    assert!(call_envelope_is_faithful(&h, SALT, &inputs));
    assert!(!call_envelope_is_faithful(&h, [0; 4], &inputs), "a wrong salt is not faithful");
    assert!(!call_envelope_is_faithful(&h, SALT, &inputs[..inputs.len() - 1]), "a truncated input vector is not");
    let mut lied = inputs.clone();
    lied[0] ^= 1;
    assert!(!call_envelope_is_faithful(&h, SALT, &lied), "a single flipped word is not");
}

/// Both caps the wallet must respect are enforced where the envelope is built, so a caller
/// never pays for a proof and then finds the transaction rejected: the spec's 4096-word input
/// vector, and the ledger's byte cap on the four parts together.
#[test]
fn sealing_refuses_an_input_vector_past_the_spec_cap_or_the_byte_cap() {
    let caller = vk(41);
    let too_many = vec![0u32; MAX_CALL_INPUT_WORDS + 1];
    let err = seal_call_envelope(&caller, None, &[0; 8], SALT, &too_many).unwrap_err();
    assert!(err.contains("4096"), "{err}");

    // The largest permitted vector fits the byte cap on its own …
    let full = vec![0u32; MAX_CALL_INPUT_WORDS];
    let (env, _) = seal_call_envelope(&caller, None, &[0; 8], SALT, &full).unwrap();
    assert!(env.len() <= shrugg_core::types::MAX_CALL_ENVELOPE_BYTES, "{} bytes", env.len());

    // … but not once an ML-KEM-768 ciphertext for an auditor is added, so that combination is
    // refused here rather than by a block (see the module doc comment).
    let auditor = address_of(&vk(42));
    let err = seal_call_envelope(&caller, Some(&auditor), &[0; 8], SALT, &full).unwrap_err();
    assert!(err.contains("17000") || err.contains("17_000"), "{err}");

    // The largest vector an audited call can carry does fit.
    let audited = vec![0u32; 3937];
    let (env, _) = seal_call_envelope(&caller, Some(&auditor), &[0; 8], SALT, &audited).unwrap();
    assert!(env.len() <= shrugg_core::types::MAX_CALL_ENVELOPE_BYTES, "{} bytes", env.len());
}

/// A malformed auditor address is an error, not a panic inside ML-KEM.
#[test]
fn a_wrong_length_auditor_key_is_reported() {
    let caller = vk(51);
    let bad = ShieldedAddress { pk: [1; 8], kem_ek: vec![0; 7] };
    let err = seal_call_envelope(&caller, Some(&bad), &[0; 8], SALT, &[1, 2]).unwrap_err();
    assert!(err.contains("7 bytes"), "{err}");
}

/// The seam between the prover and the envelope: `prove_call` hands back the very salt that
/// produced the proof's public `H_IN`, so the envelope it seals is bound to that proof. A
/// small guest at the smallest tier — seconds, not minutes.
#[test]
fn prove_call_returns_the_salt_behind_the_proofs_h_in() {
    let program = shrugg_zkvm::guests::fib(10);
    let inputs = inputs();
    let (bytes, outputs, tier, salt) =
        prove_call(FriProfile::Test, &program, &inputs, Some(10), Backend::Cpu).expect("fib proves at tier 10");
    assert_eq!(tier, 10);
    assert_eq!(outputs[0], 55, "fib(10)");

    let proof: Proof = postcard::from_bytes(&bytes).expect("a proof this crate just produced");
    let published: Word8 = std::array::from_fn(|i| proof.public_values[pv::IN0 + i] as u32);
    assert_eq!(input_digest(salt, &inputs), published, "the returned salt is the proof's H_IN preimage");

    // Which is exactly what makes the sealed transcript checkable by whoever opens it.
    let caller = vk(61);
    let (env, key) = seal_call_envelope(&caller, None, &published, salt, &inputs).unwrap();
    let (opened_salt, opened_inputs) = open_call_with_key(&env, &published, &key).expect("opens under the call's H_IN");
    assert!(call_envelope_is_faithful(&published, opened_salt, &opened_inputs));

    // Two calls never share a salt: the freshness `H_IN`'s hiding rests on.
    let (_, _, _, salt2) = prove_call(FriProfile::Test, &program, &inputs, Some(10), Backend::Cpu).unwrap();
    assert_ne!(salt, salt2);
}
