use shrugg_zkvm::guests;
use shrugg_zkvm::machine::{FriProfile, Machine};

#[test]
fn two_proofs_of_the_same_run_differ_and_both_verify() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let inputs = [400, 250, 300, 75];
    let (a, _) = m.prove(&p, &inputs, None).unwrap();
    let (b, _) = m.prove(&p, &inputs, None).unwrap();
    assert_eq!(a.public_values, b.public_values);
    assert_ne!(a.to_bytes(), b.to_bytes(), "hiding commitments must randomise the proof");
    m.verify(&p, &a).unwrap();
    m.verify(&p, &b).unwrap();
}

#[test]
fn different_private_inputs_same_output_are_indistinguishable_in_public_values() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000);
    let (a, _) = m.prove(&p, &[400, 250, 300, 75], None).unwrap();
    let (b, _) = m.prove(&p, &[1000, 0, 0, 0], None).unwrap();
    assert_eq!(a.public_values, b.public_values);
    assert_eq!(a.batch.degree_bits, b.batch.degree_bits);
}
