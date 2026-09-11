use shrugg_core::confidential::{ConfidentialError, ConfidentialExecutor};
use shrugg_core::program::{program_id, ProgramRecord};
use shrugg_core::Keypair;
use shrugg_zkvm::executor::{prove, ZkExecutor};
use shrugg_zkvm::guests;
use shrugg_zkvm::machine::{Backend, FriProfile};
use std::sync::OnceLock;

fn record(p: &shrugg_zkvm::isa::Program) -> ProgramRecord {
    let ex = ZkExecutor::new(FriProfile::Test);
    let code_hash = ex.check_program(p.base_pc, &p.words).unwrap();
    ProgramRecord {
        id: program_id(p.base_pc, &p.words),
        base_pc: p.base_pc,
        words: p.words.clone(),
        code_hash,
        deployer: Keypair::from_seed([1; 32]).unwrap().address(),
        deployed_at: 0,
    }
}

/// One proof shared by every test (proving takes ~20 s).
fn shared() -> &'static (Vec<u8>, [u32; 8], u8) {
    static P: OnceLock<(Vec<u8>, [u32; 8], u8)> = OnceLock::new();
    P.get_or_init(|| prove(FriProfile::Test, &guests::private_payment(1000), &[400, 250, 300, 75], None, Backend::Cpu).unwrap())
}

#[test]
fn verifies_a_real_proof_and_reports_outputs() {
    let p = guests::private_payment(1000);
    let (proof, outputs, tier) = shared();
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = record(&p);
    let out = ex.verify_call(&rec, proof).unwrap();
    assert_eq!(out.tier, *tier);
    assert_eq!(out.outputs, *outputs);
    assert_eq!(out.outputs[0], 1, "sum 1025 >= 1000 -> transfer");
    assert_eq!(out.outputs[1], 0);
    assert_eq!(out.outputs[2], 1025 - 1000, "pays the surplus");
    assert_eq!(ex.cached_keys(), 1);
    ex.warm(&rec);
    assert_eq!(
        ex.cached_keys(),
        shrugg_zkvm::machine::TIERS.len(),
        "warm precomputes every tier's key, reusing the cached one"
    );
    let t = std::time::Instant::now();
    ex.verify_call(&rec, proof).unwrap();
    assert!(t.elapsed().as_millis() < 500, "cached verify took {:?}", t.elapsed());
}

#[test]
fn rejects_wrong_program_tampered_bytes_and_wrong_profile() {
    let p = guests::private_payment(1000);
    let (proof, _, _) = shared();
    let ex = ZkExecutor::new(FriProfile::Test);
    let other = guests::private_payment(1001);
    assert!(matches!(ex.verify_call(&record(&other), proof), Err(ConfidentialError::InvalidProof(_))));
    let mut bad = proof.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 1;
    assert!(ex.verify_call(&record(&p), &bad).is_err());
    assert_eq!(ex.verify_call(&record(&p), b"nope"), Err(ConfidentialError::MalformedProof));
    let prod = ZkExecutor::new(FriProfile::Production);
    assert!(prod.verify_call(&record(&p), proof).is_err(), "a test-profile proof must not pass a production verifier");
}

#[test]
fn check_program_rejects_bad_words() {
    let ex = ZkExecutor::new(FriProfile::Test);
    assert!(matches!(ex.check_program(0, &[0xffff_ffff]), Err(ConfidentialError::BadInstruction { index: 0, .. })));
    assert!(ex.check_program(0, &[0x13]).is_ok());
    assert!(ex.check_program(2, &[0x13]).is_err(), "base_pc must be word aligned");
    assert!(ex.check_program(0, &[]).is_err());
}

#[test]
fn private_payment_emits_no_transfer_below_threshold() {
    let (_, outputs, _) = prove(FriProfile::Test, &guests::private_payment(2000), &[400, 250, 300, 75], None, Backend::Cpu).unwrap();
    assert_eq!(outputs, [0; 8]);
}

/// `prove` names the backend it runs on; `Backend::Cpu` is the same proof the other tests verify.
#[test]
fn prove_takes_a_backend_and_cpu_is_unchanged() {
    let p = guests::private_payment(1000);
    let (proof, outputs, tier) =
        prove(FriProfile::Test, &p, &[400, 250, 300, 75], None, shrugg_zkvm::machine::Backend::Cpu).unwrap();
    let ex = ZkExecutor::new(FriProfile::Test);
    let out = ex.verify_call(&record(&p), &proof).unwrap();
    assert_eq!((out.outputs, out.tier), (outputs, tier));
}
