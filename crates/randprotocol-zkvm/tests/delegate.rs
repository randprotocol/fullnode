//! The sealed job and result a wallet and a `rand-prover` exchange
//! (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md` §3–§4).

use randprotocol_zkvm::address::address_of;
use randprotocol_zkvm::delegate::*;
use randprotocol_zkvm::notes::SpendKey;

fn a_job(reply_ek: Vec<u8>) -> JobRequest {
    JobRequest {
        version: VERSION,
        profile: "test".into(),
        kind: JobKind::Program { base_pc: 0, words: vec![0x13, 0x73], inputs: vec![1, 2, 3], tier: None, want_salt: true },
        deadline_secs: 120,
        reply_ek,
    }
}

#[test]
fn a_job_seals_to_the_prover_and_opens_there_only() {
    let prover_vk = SpendKey::random().viewing_key();
    let prover = ProverKey::from_viewing_key(&prover_vk);
    let other = ProverKey::from_viewing_key(&SpendKey::random().viewing_key());
    let reply = ReplyKey::generate();
    let job = a_job(reply.ek.clone());
    let sealed = seal_job(&address_of(&prover_vk), &job).unwrap();
    assert_eq!(open_job(&prover, &sealed).unwrap(), job);
    assert!(open_job(&other, &sealed).is_err(), "a different prover key must not open it");
    let mut tampered = sealed.clone();
    let last = tampered.body.len() - 1;
    tampered.body[last] ^= 1;
    assert!(open_job(&prover, &tampered).is_err(), "a flipped byte must fail authentication");
}

#[test]
fn a_result_seals_to_the_job_reply_key_and_opens_once_there() {
    let reply = ReplyKey::generate();
    let stranger = ReplyKey::generate();
    let result = JobResult::Bundle { proof: vec![9; 40], digest: [1; 8], tier: 14 };
    let sealed = seal_result(&reply.ek, &result).unwrap();
    assert_eq!(open_result(&reply, &sealed).unwrap(), result);
    assert!(open_result(&stranger, &sealed).is_err());
    // A result under a job's key is ciphertext to the prover's own key: the two AADs differ.
    let prover = ProverKey::from_viewing_key(&SpendKey::random().viewing_key());
    assert!(open_job(&prover, &sealed).is_err());
}

#[test]
fn the_wire_form_round_trips_and_rejects_garbage() {
    let sealed = Sealed { kem_ct: vec![1, 2, 3], body: vec![4, 5] };
    assert_eq!(decode(&encode(&sealed)).unwrap(), sealed);
    assert!(decode(&[0xff; 3]).is_err());
}

#[test]
fn the_job_encoding_is_pinned() {
    // A wallet and a prover built from different commits must agree on these bytes; this
    // vector is the postcard form of `a_job(vec![7; 4])`. Regenerate deliberately, never
    // silently, when `JobRequest` changes — and bump `VERSION` when you do.
    let job = a_job(vec![7; 4]);
    let bytes = postcard::to_allocvec(&job).unwrap();
    assert_eq!(hex::encode(&bytes), "0104746573740100021373030102030001780407070707");
}

#[test]
fn a_bad_encapsulation_key_is_an_error_not_a_panic() {
    let job = a_job(vec![7; 4]);
    let short = randprotocol_core::notes::ShieldedAddress { pk: [0; 8], kem_ek: vec![0; 10] };
    assert!(seal_job(&short, &job).unwrap_err().contains("10 bytes"));
    assert!(seal_result(&[0; 10], &JobResult::Failed { error: "x".into() }).unwrap_err().contains("10 bytes"));
}

#[test]
fn a_wrong_version_job_is_rejected_with_a_named_error() {
    let prover_vk = SpendKey::random().viewing_key();
    let prover = ProverKey::from_viewing_key(&prover_vk);
    let reply = ReplyKey::generate();
    let mut job = a_job(reply.ek.clone());
    job.version = VERSION + 1;
    let sealed = seal_job(&address_of(&prover_vk), &job).unwrap();
    let err = open_job(&prover, &sealed).unwrap_err();
    assert!(err.contains("version"), "error should mention version: {err}");
}

#[test]
fn a_body_shorter_than_the_nonce_is_an_error_not_a_panic() {
    let prover_vk = SpendKey::random().viewing_key();
    let prover = ProverKey::from_viewing_key(&prover_vk);
    let reply = ReplyKey::generate();
    let job = a_job(reply.ek.clone());
    let job_sealed = seal_job(&address_of(&prover_vk), &job).unwrap();
    let short_job = Sealed { kem_ct: job_sealed.kem_ct, body: vec![0; 5] };
    assert!(open_job(&prover, &short_job).is_err());

    let result = JobResult::Bundle { proof: vec![1; 8], digest: [0; 8], tier: 1 };
    let result_sealed = seal_result(&reply.ek, &result).unwrap();
    let short_result = Sealed { kem_ct: result_sealed.kem_ct, body: vec![0; 5] };
    assert!(open_result(&reply, &short_result).is_err());
}

#[test]
fn a_garbage_kem_ciphertext_is_an_error_not_a_panic() {
    let prover_vk = SpendKey::random().viewing_key();
    let prover = ProverKey::from_viewing_key(&prover_vk);
    let reply = ReplyKey::generate();
    let job = a_job(reply.ek.clone());
    let job_sealed = seal_job(&address_of(&prover_vk), &job).unwrap();
    let bad_ct_job = Sealed { kem_ct: vec![1, 2, 3], body: job_sealed.body };
    assert!(open_job(&prover, &bad_ct_job).is_err());

    let result = JobResult::Bundle { proof: vec![1; 8], digest: [0; 8], tier: 1 };
    let result_sealed = seal_result(&reply.ek, &result).unwrap();
    let bad_ct_result = Sealed { kem_ct: vec![1, 2, 3], body: result_sealed.body };
    assert!(open_result(&reply, &bad_ct_result).is_err());
}
