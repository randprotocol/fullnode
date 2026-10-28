//! Fullnode #152 (v0.8.3): one admission decodes each proof once. The ledger's checks — the
//! canonical-proof rule, `check_auth_fields`' header, the digest and gas reads, the verify — each
//! hand the executor the same bytes; `executor::decode_canonical_shared` decodes the first time and
//! answers the rest from a memo keyed by the exact bytes.
//!
//! Its own test binary: the decode counter is process-wide.

use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_zkvm::executor::{clear_decode_memo, decode_canonical, decode_canonical_shared, prove_auth, shared_decodes, ZkExecutor};
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::notes::SpendKey;

const BINDING: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_ffff];

#[test]
fn one_admission_decodes_each_proof_once_with_the_same_verdicts() {
    let (proof, c, _) = prove_auth(FriProfile::Test, &SpendKey([7; 8]), &[9; 8], &BINDING, Backend::Cpu).unwrap();
    let ex = ZkExecutor::new(FriProfile::Test);
    clear_decode_memo();
    let before = shared_decodes();

    // The admission sequence `Ledger::validate` runs on an auth proof.
    assert_eq!(ex.non_canonical_proof(&proof), None);
    let (_shape, published, gas) = ex.auth_header(&proof).unwrap();
    assert_eq!(published, c);
    assert_eq!(ex.auth_proof_digest(&proof), Ok(c));
    assert_eq!(ex.auth_gas_limit(&proof), Ok(gas));
    assert_eq!(ex.verify_auth(&ZkExecutor::hc_auth(), &proof, &BINDING), Ok(c));
    assert_eq!(shared_decodes(), before + 1, "five reads of one proof, one decode");

    // The memoised decode is the decode.
    assert_eq!(decode_canonical_shared(&proof).unwrap().to_bytes(), decode_canonical(&proof).unwrap().to_bytes());

    // Other bytes are other entries — never a hit on a prefix or a near miss — and a refusal is
    // the refusal it always was (and is not memoised).
    let mut padded = proof.clone();
    padded.push(0);
    assert!(decode_canonical_shared(&padded).is_err());
    assert!(decode_canonical_shared(&padded).is_err());
    assert_eq!(ex.non_canonical_proof(&padded), None, "undecodable: the ledger's MalformedProof, not a canonical-rule name");
    assert!(ex.verify_auth(&ZkExecutor::hc_auth(), &padded, &BINDING).is_err());
    let mut flipped = proof.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    assert!(ex.verify_auth(&ZkExecutor::hc_auth(), &flipped, &BINDING).is_err(), "a one-byte change is not a hit");
    // And the honest proof is still answered from the memo after all that.
    let n = shared_decodes();
    assert_eq!(ex.verify_auth(&ZkExecutor::hc_auth(), &proof, &BINDING), Ok(c));
    assert_eq!(shared_decodes(), n);
}
