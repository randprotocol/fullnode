use shrugg_zkvm::guests;
use shrugg_zkvm::machine::{FriProfile, Machine};

/// H_IN (`pv::IN0..IN0+8`) is salted (M4.1, controller ruling) precisely so it varies between
/// two proofs of the *same* run: public values are equal everywhere else (hiding of the
/// witness/cycle-count/tier padding this test always checked), but must now *differ* inside
/// the salted commitment window, since each `prove` call draws a fresh salt from OS entropy.
#[test]
fn two_proofs_of_the_same_run_differ_and_both_verify() {
    use shrugg_zkvm::tables::cpu::pv;
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let inputs = [400, 250, 300, 75];
    let (a, _) = m.prove(&p, &inputs, None).unwrap();
    let (b, _) = m.prove(&p, &inputs, None).unwrap();
    assert_eq!(&a.public_values[..pv::IN0], &b.public_values[..pv::IN0], "public values outside H_IN must still agree");
    assert_eq!(&a.public_values[pv::IN0 + 8..], &b.public_values[pv::IN0 + 8..], "public values after H_IN must still agree");
    assert_ne!(&a.public_values[pv::IN0..pv::IN0 + 8], &b.public_values[pv::IN0..pv::IN0 + 8], "H_IN must be salted (hiding)");
    assert_ne!(a.to_bytes(), b.to_bytes(), "hiding commitments must randomise the proof");
    m.verify(&p.digest(), &a).unwrap();
    m.verify(&p.digest(), &b).unwrap();
}

#[test]
fn different_private_inputs_same_output_are_indistinguishable_in_public_values() {
    use shrugg_zkvm::tables::cpu::pv;
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let (a, _) = m.prove(&p, &[400, 250, 300, 75], None).unwrap();
    let (b, _) = m.prove(&p, &[1000, 0, 0, 0], None).unwrap();
    assert_eq!(&a.public_values[..pv::IN0], &b.public_values[..pv::IN0], "public values outside H_IN must agree");
    assert_eq!(&a.public_values[pv::IN0 + 8..], &b.public_values[pv::IN0 + 8..], "public values after H_IN must agree");
    assert_eq!(a.batch.degree_bits, b.batch.degree_bits);
}

/// H_IN is a genuine commitment to *both* the salt and the input words — review round 1 (M5):
/// renamed and strengthened from a determinism-only check (comparing two calls into the host
/// reference function, never varying the inputs at all) into an actual binding check: real
/// proofs, with either the inputs or the salt held fixed and the other varied, must produce a
/// different `H_IN`. `pv::IN0..7` matching `hash::input_digest(salt, inputs)` exactly is the
/// determinism/correctness half; the two `assert_ne!`s below are the binding half.
#[test]
fn input_commitment_matches_the_reference_and_is_bound_to_salt_and_inputs() {
    use shrugg_zkvm::tables::cpu::pv;
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let salt_a = [1u32, 2, 3, 4];
    let salt_b = [5u32, 6, 7, 8];
    let inputs_a = [400u32, 250, 300, 75];
    let inputs_b = [1000u32, 0, 0, 0]; // same guest output, different private inputs

    let (proof, _) = m.prove_salted(&p, &inputs_a, salt_a, None).unwrap();
    let expected = shrugg_zkvm::hash::input_digest(salt_a, &inputs_a);
    for k in 0..8 {
        assert_eq!(proof.public_values[pv::IN0 + k], expected[k] as u64, "H_IN word {k}");
    }

    // Bound to the inputs: same salt, different inputs, via an actual second proof — not just
    // a second call into the host reference function.
    let (proof_diff_inputs, _) = m.prove_salted(&p, &inputs_b, salt_a, None).unwrap();
    assert_ne!(
        &proof.public_values[pv::IN0..pv::IN0 + 8],
        &proof_diff_inputs.public_values[pv::IN0..pv::IN0 + 8],
        "H_IN must be bound to the inputs"
    );

    // Bound to the salt: same inputs, different salt.
    let (proof_diff_salt, _) = m.prove_salted(&p, &inputs_a, salt_b, None).unwrap();
    assert_ne!(
        &proof.public_values[pv::IN0..pv::IN0 + 8],
        &proof_diff_salt.public_values[pv::IN0..pv::IN0 + 8],
        "H_IN must be bound to the salt"
    );
}
