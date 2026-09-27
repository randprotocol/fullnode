//! ZKA-1: a public output slot holds a 32-bit word, and `Machine::verify` says so.
//!
//! `pv::OUT0..7` are field elements, and until this check `verify` held them only to the
//! canonical-encoding rule (`< p`, Goldilocks' `2^64 − 2^32 + 1`). The circuit does not close the
//! gap on its own: `SYS_READ` hands a guest the input table's `WORD`, which no lookup
//! range-checks, so the AIR alone does not guarantee an output slot is below `2^32` (audit
//! ZKA-1) — a cheating prover could publish an output in `[2^32, p)` that no RV32 execution
//! writes. Every consumer reads the slots as `u32` (a chain's executor refuses such an output itself — fullnode's `verify_call` —
//! and the ledger's call-output checks do too), so nothing on a chain changes; this makes the
//! verifier's own answer match what its callers already assume.
//!
//! The red is on the public-value check itself (`machine::check_public_values`, the first thing
//! `verify` runs): forging a whole trace whose input word is `≥ 2^32` and still balances the
//! input-digest bus is a much larger construction than the check it would test, so the second
//! test takes an honest proof, sets `OUT0` to a canonical `2^32 + 55`, and asserts `verify` refuses
//! it with the named error *before* the batch verifier runs — before the check, the only refusal
//! was the batch's own public-values mismatch, which a forged trace would satisfy.
use randprotocol_zkvm::guests;
use randprotocol_zkvm::machine::{check_public_values, FriProfile, Machine, VerifyError};
use randprotocol_zkvm::tables::cpu::pv;

#[test]
fn an_output_slot_above_u32_is_refused_by_the_public_value_check() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], &[], None).unwrap();
    check_public_values(&p.digest(), &proof).expect("an honest proof's outputs are words");
    for slot in 0..8 {
        let honest = proof.public_values[pv::OUT0 + slot];
        // Canonical (far below p), so the encoding rule alone lets it through.
        proof.public_values[pv::OUT0 + slot] = u32::MAX as u64 + 1;
        assert!(
            matches!(check_public_values(&p.digest(), &proof), Err(VerifyError::OutputNotU32 { slot: s }) if s == slot),
            "slot {slot}: {:?}",
            check_public_values(&p.digest(), &proof)
        );
        proof.public_values[pv::OUT0 + slot] = honest;
    }
    // `u32::MAX` itself is a word.
    proof.public_values[pv::OUT0] = u32::MAX as u64;
    assert!(check_public_values(&p.digest(), &proof).is_ok());
}

#[test]
fn verify_names_an_oversized_output_before_the_batch_verifier_runs() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], &[], None).unwrap();
    m.verify(&p.digest(), &proof).unwrap();
    proof.public_values[pv::OUT0] = (1u64 << 32) + 55;
    let got = m.verify(&p.digest(), &proof);
    assert!(matches!(got, Err(VerifyError::OutputNotU32 { slot: 0 })), "{got:?}");
}
