//! Constraint set 9: a modq-bearing proof's preprocessed round includes the modq table's 16
//! preprocessed columns. Before the fix, `non_canonical` counted `chips(t, k, s)` and named every
//! honest msauth proof non-canonical: refused by the mempool, and by consensus under hardening_v6.
//! Node-local (the sync's `'auth*.rs'` exclude keeps it). The tier-10 one-NTT guest is
//! `executor::fixtures::one_modq_ntt_program`, shared with the node's aggregate-path tests.
use randprotocol_zkvm::executor::fixtures::one_modq_ntt_program;
use randprotocol_zkvm::executor::{decode_canonical, honest_fri_arities, non_canonical};
use randprotocol_zkvm::machine::{FriProfile, Machine, ProveOptions, Tier};

#[test]
fn an_honest_modq_bearing_proof_is_canonical() {
    let program = one_modq_ntt_program();
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove_with_options(&program, &[], &[], Some(Tier(10)), ProveOptions::default()).unwrap();
    assert_eq!(proof.modq_log_height, 10, "one 1 024-row modq block");
    m.verify(&program.digest(), &proof).expect("the fixture is an honest proof");
    let proof = decode_canonical(&proof.to_bytes()).unwrap(); // what the chain sees: the encoded proof
    assert_eq!(non_canonical(&proof), None);
    assert!(honest_fri_arities(&proof).is_some(), "a schedule is derived, so the arity rule runs");
    // And the arity rule bites on it: a finer fold where the honest prover folds coarser is a
    // second encoding (VERIFIER-2).
    let mut forged = decode_canonical(&proof.to_bytes()).unwrap();
    let step = forged.batch.opening_proof.1.commit_phase_openings.iter_mut().find(|s| s.log_arity > 1).expect("a fold coarser than 1");
    step.log_arity = 1;
    assert!(non_canonical(&forged).is_some(), "a finer FRI schedule on a modq-bearing proof is non-canonical");
}
