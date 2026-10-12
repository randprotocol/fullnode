//! The signer checks against the committed vectors (`tests/fixtures/*.json`, written by
//! `fixtures_gen.rs`'s seeded generator and vendored by the clients' core). Loads the files;
//! nothing inline.
use randprotocol_msig::{check_proposal, sign, verify_share, ProposalSummary};

fn fixture(name: &str) -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/").to_owned() + name).unwrap()
}
fn seeds() -> (Vec<[u8; 32]>, [u8; 32]) {
    let v: serde_json::Value = serde_json::from_str(&fixture("signer-seeds.json")).unwrap();
    let h = |s: &serde_json::Value| -> [u8; 32] { hex::decode(s.as_str().unwrap()).unwrap().try_into().unwrap() };
    (v["members"].as_array().unwrap().iter().map(h).collect(), h(&v["non_member"]))
}
fn expected() -> serde_json::Value {
    serde_json::from_str(&fixture("expected.json")).unwrap()
}

#[test]
fn the_valid_proposal_checks_to_the_expected_summary() {
    let s: ProposalSummary = check_proposal(&fixture("proposal-valid.json"), &fixture("policy.json")).unwrap();
    assert_eq!(serde_json::to_value(&s).unwrap(), expected()["summary"]);
    assert_eq!(hex::encode(s.signing_message), expected()["signing_message"].as_str().unwrap());
}

#[test]
fn a_tampered_output_is_refused() {
    let e = check_proposal(&fixture("proposal-tampered-output.json"), &fixture("policy.json")).unwrap_err();
    assert!(e.to_string().contains("does not open"), "{e}");
}

#[test]
fn a_value_mismatch_is_refused() {
    let e = check_proposal(&fixture("proposal-value-mismatch.json"), &fixture("policy.json")).unwrap_err();
    assert!(e.to_string().contains("value"), "{e}");
}

#[test]
fn an_expired_proposal_is_refused() {
    let e = check_proposal(&fixture("proposal-expired.json"), &fixture("policy.json")).unwrap_err();
    assert!(e.to_string().contains("expires"), "{e}");
}

#[test]
fn members_0_and_2_sign_the_expected_shares_and_a_non_member_is_refused() {
    let (members, outsider) = seeds();
    let (prop, pol) = (fixture("proposal-valid.json"), fixture("policy.json"));
    for (i, want) in [(0usize, "share_0"), (2, "share_2")] {
        let (idx, sig) = sign(&prop, &pol, &members[i]).unwrap();
        assert_eq!((idx as usize, sig.len()), (i, 2420));
        let share = format!("{idx}:{}", hex::encode(&sig));
        assert_eq!(share, expected()[want].as_str().unwrap(), "deterministic signing reproduces the vector");
        verify_share(&prop, &pol, &share).unwrap();
    }
    assert!(sign(&prop, &pol, &outsider).unwrap_err().to_string().contains("not one of the policy's signers"));
}

#[test]
fn verify_share_refuses_a_wrong_index_or_signature() {
    let (prop, pol) = (fixture("proposal-valid.json"), fixture("policy.json"));
    let share2 = expected()["share_2"].as_str().unwrap().to_string();
    let sig = share2.split_once(':').unwrap().1;
    assert!(verify_share(&prop, &pol, &format!("1:{sig}")).is_err(), "signer 2's signature under index 1");
    assert!(verify_share(&prop, &pol, &format!("7:{sig}")).is_err(), "an index outside the policy");
    let mut bad = hex::decode(sig).unwrap();
    bad[0] ^= 1;
    assert!(verify_share(&prop, &pol, &format!("2:{}", hex::encode(bad))).is_err());
    assert!(verify_share(&prop, &pol, "2:zz").is_err());
}
