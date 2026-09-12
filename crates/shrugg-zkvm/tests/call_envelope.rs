//! The call-input envelope (spec §6.1): a confidential call's private inputs, sealed on chain
//! so that the caller's viewing key, a per-call key, or a designated auditor — and nobody else —
//! can read what the program was fed.
//!
//! The chain checks none of this (`shrugg_core::ledger::call_envelope` caps the size and stops);
//! what makes an envelope trustworthy is the AEAD binding to the proof's public `H_IN` plus the
//! holder's own `input_digest` recomputation, and those are what this file pins.

use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::notes::{ShieldedAddress, Word8};
use shrugg_core::program::ProgramRecord;
use shrugg_core::types::MAX_CALL_ENVELOPE_BYTES;
use shrugg_zkvm::address::address_of;
use shrugg_zkvm::call_envelope::{
    call_envelope_is_faithful, open_call_as_auditor, open_call_as_sender, open_call_with_key, seal_call_envelope,
    CallKey, MAX_CALL_INPUT_WORDS,
};
use shrugg_zkvm::executor::{prove_call, ZkExecutor};
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

/// The spec's 4096-word input cap is enforced where the envelope is built, so a caller never
/// pays for a proof and then finds the transaction rejected — and the largest envelope that cap
/// admits, auditor included, is inside the ledger's byte cap with room to spare.
#[test]
fn sealing_refuses_an_input_vector_past_the_spec_cap_and_the_largest_one_still_fits() {
    let caller = vk(41);
    let auditor = address_of(&vk(42));
    let too_many = vec![0u32; MAX_CALL_INPUT_WORDS + 1];
    let err = seal_call_envelope(&caller, None, &[0; 8], SALT, &too_many).unwrap_err();
    assert!(err.contains(&MAX_CALL_INPUT_WORDS.to_string()), "{err}");

    let full = vec![0u32; MAX_CALL_INPUT_WORDS];
    let (env, _) = seal_call_envelope(&caller, Some(&auditor), &h_in(SALT, &full), SALT, &full).unwrap();
    // nonce + salt + inputs + tag, an ML-KEM-768 ciphertext, and two nonce + key + tag wraps.
    let expected = (12 + 16 + 4 * MAX_CALL_INPUT_WORDS + 16) + 1088 + 2 * (12 + 32 + 16);
    assert_eq!(env.len(), expected, "the worst case the format can produce");
    assert!(
        expected <= MAX_CALL_ENVELOPE_BYTES,
        "the ledger's {MAX_CALL_ENVELOPE_BYTES}-byte cap must admit {expected}"
    );
    // Unaudited, the same vector is two wraps and a KEM ciphertext smaller.
    let (bare, _) = seal_call_envelope(&caller, None, &h_in(SALT, &full), SALT, &full).unwrap();
    assert_eq!(bare.len(), expected - 1088 - 60);
}

/// A malformed auditor address is an error, not a panic inside ML-KEM.
#[test]
fn a_wrong_length_auditor_key_is_reported() {
    let caller = vk(51);
    let bad = ShieldedAddress { pk: [1; 8], kem_ek: vec![0; 7] };
    let err = seal_call_envelope(&caller, Some(&bad), &h_in(SALT, &[1, 2]), SALT, &[1, 2]).unwrap_err();
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

    // And the chain-side verifier publishes that same `H_IN` on the call's outcome, which is
    // what puts it on the receipt and makes the envelope openable at all (spec §6.1).
    let executor = ZkExecutor::new(FriProfile::Test);
    let code_hash = executor.check_program(program.base_pc, &program.words).unwrap();
    let record = ProgramRecord {
        id: shrugg_core::program::program_id(program.base_pc, &program.words),
        base_pc: program.base_pc,
        words: program.words.clone(),
        code_hash,
        deployed_at: 0,
    };
    let outcome = executor.verify_call(&record, &bytes).expect("the proof this test just produced");
    assert_eq!(outcome.h_in, input_digest(salt, &inputs), "the receipt's H_IN is the transcript's digest");
    assert_eq!(outcome.outputs, outputs);
    assert_eq!(outcome.tier, 10);
}

/// An input vector no call may prove is refused before the prover is started, not after minutes
/// of proving produce an envelope that cannot be published.
#[test]
fn prove_call_refuses_an_input_vector_past_the_cap_before_proving() {
    let err = prove_call(
        FriProfile::Test,
        &shrugg_zkvm::guests::fib(10),
        &vec![0; MAX_CALL_INPUT_WORDS + 1],
        Some(10),
        Backend::Cpu,
    )
    .unwrap_err();
    assert!(err.contains(&MAX_CALL_INPUT_WORDS.to_string()), "{err}");
}
