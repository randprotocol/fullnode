use randprotocol_prover::wire::*;
use ml_kem::kem::FromSeed;
use ml_kem::{KeyExport, MlKem768};

fn keypair(seed_byte: u8) -> (Dk, Vec<u8>) {
    let (dk, ek) = MlKem768::from_seed(&ml_kem::Seed::from([seed_byte; 64]));
    (dk, ek.to_bytes().to_vec())
}

fn job() -> ProveJob {
    ProveJob {
        version: WIRE_VERSION,
        token: [7; 32],
        witness_kind: WitnessKind::SpendKey,
        hc_bundle: [1, 2, 3, 4, 5, 6, 7, 8],
        profile: "test".into(),
        binding: [9; 8],
        inputs: (0..1204u32).map(|i| i.wrapping_mul(2654435761)).collect(),
        reply_key: [3; 32],
    }
}

#[test]
fn a_job_round_trips_through_the_sealed_wire() {
    let (dk, ek) = keypair(1);
    let sealed = seal_job(&ek, &job()).unwrap();
    assert!(sealed.len() > KEM_CT_BYTES + NONCE_BYTES + 16);
    assert!(sealed.len() <= MAX_SEALED_JOB_BYTES);
    let opened = open_job(&dk, &sealed).unwrap();
    let want = job();
    assert_eq!(opened.token, want.token);
    assert_eq!(opened.witness_kind, want.witness_kind);
    assert_eq!(opened.hc_bundle, want.hc_bundle);
    assert_eq!(opened.profile, want.profile);
    assert_eq!(opened.binding, want.binding);
    assert_eq!(opened.inputs, want.inputs);
    assert_eq!(opened.reply_key, want.reply_key);
}

#[test]
fn two_seals_of_one_job_differ() {
    let (_, ek) = keypair(1);
    assert_ne!(seal_job(&ek, &job()).unwrap(), seal_job(&ek, &job()).unwrap(), "fresh KEM randomness and nonce every time");
}

#[test]
fn a_job_sealed_to_another_key_does_not_open() {
    let (_, ek1) = keypair(1);
    let (dk2, _) = keypair(2);
    let sealed = seal_job(&ek1, &job()).unwrap();
    assert!(matches!(open_job(&dk2, &sealed), Err(WireError::NotForThisProver)));
}

#[test]
fn a_flipped_byte_anywhere_is_refused() {
    let (dk, ek) = keypair(1);
    let sealed = seal_job(&ek, &job()).unwrap();
    for at in [0, KEM_CT_BYTES - 1, KEM_CT_BYTES + 3, sealed.len() - 1] {
        let mut t = sealed.clone();
        t[at] ^= 0x40;
        assert!(open_job(&dk, &t).is_err(), "byte {at}");
    }
}

#[test]
fn a_short_or_oversized_body_is_malformed_before_any_crypto() {
    let (dk, _) = keypair(1);
    assert!(matches!(open_job(&dk, &[0u8; 100]), Err(WireError::Malformed(_))));
    assert!(matches!(open_job(&dk, &vec![0u8; MAX_SEALED_JOB_BYTES + 1]), Err(WireError::TooLong(_))));
}

#[test]
fn a_bad_encapsulation_key_is_refused_at_seal_time() {
    assert!(matches!(seal_job(&[0u8; 10], &job()), Err(WireError::BadKey(_))));
}

#[test]
fn a_foreign_wire_version_is_refused() {
    let (dk, ek) = keypair(1);
    let mut j = job();
    j.version = 2;
    let sealed = seal_job(&ek, &j).unwrap();
    assert!(matches!(open_job(&dk, &sealed), Err(WireError::Version(2))));
}

#[test]
fn a_reply_round_trips_and_a_wrong_key_fails() {
    let key = fresh_reply_key();
    let reply = ProveReply { proof: vec![1, 2, 3], digest: [4; 8], tier: 14 };
    let sealed = seal_reply(&key, &reply);
    assert_eq!(open_reply(&key, &sealed).unwrap(), reply);
    let other = fresh_reply_key();
    assert!(open_reply(&other, &sealed).is_err());
    assert_ne!(seal_reply(&key, &reply), sealed, "fresh nonce per seal");
}

#[test]
fn a_job_is_zeroize_on_drop() {
    fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
    assert_zod::<ProveJob>();
}

#[test]
fn zeroizing_a_job_clears_its_secrets() {
    let mut j = job();
    assert_ne!(j.inputs[5], 0);
    zeroize::Zeroize::zeroize(&mut j);
    assert!(j.inputs.is_empty(), "the witness was not zeroized");
    assert_eq!(j.token, [0; 32]);
    assert_eq!(j.reply_key, [0; 32]);
    assert_eq!(j.binding, [0; 8]);
}

#[test]
fn a_jobs_debug_does_not_print_the_witness() {
    let s = format!("{:?}", job());
    assert!(s.contains("inputs_len: 1204"), "{s}");
    assert!(!s.contains("token") && !s.contains("reply_key") && !s.contains("binding"), "{s}");
}

/// VK-4 (audit v6): the spend-key kind is retired, but its variant keeps its place on the wire —
/// postcard writes the variant's index — so a job from a wallet older than the retirement still
/// opens (and is then refused as a witness kind, which that wallet can print) and a viewing-key
/// job means the same thing to both.
#[test]
fn the_retired_spend_key_kind_still_decodes_at_its_index() {
    assert_eq!(postcard::to_allocvec(&WitnessKind::SpendKey).unwrap(), [0]);
    assert_eq!(postcard::to_allocvec(&WitnessKind::ViewingKey).unwrap(), [1]);
    assert_eq!(postcard::from_bytes::<WitnessKind>(&[0]).unwrap(), WitnessKind::SpendKey);
    let (dk, ek) = keypair(5);
    let opened = open_job(&dk, &seal_job(&ek, &job()).unwrap()).expect("a spend-key job is still a well-formed job");
    assert_eq!(opened.witness_kind, WitnessKind::SpendKey);
    assert_eq!((WitnessKind::parse("spend_key"), WitnessKind::parse("viewing_key")), (Some(WitnessKind::SpendKey), Some(WitnessKind::ViewingKey)));
}
