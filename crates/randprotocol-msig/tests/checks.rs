//! The signer checks against the committed vectors (`tests/fixtures/*.json`, written by
//! `fixtures_gen.rs`'s seeded generator and vendored by the clients' core). Loads the files;
//! nothing inline.
use randprotocol_msig::{
    check_proposal, check_proposal_expecting, owner_fingerprint_of_text, sign, sign_expecting, verify_share, ProposalSummary, NO_EXPECTATION,
};

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

#[test]
fn a_wrong_expected_digest_is_refused() {
    let e = check_proposal(&fixture("proposal-wrong-expected.json"), &fixture("policy.json")).unwrap_err();
    assert!(e.to_string().contains("expected digest is not its bundle's"), "{e}");
}

/// The fee raised in the bundle and the witness, digest and binding re-made: only the per-asset
/// balance can refuse it (the nullifiers still re-derive).
#[test]
fn a_raised_fee_is_refused_by_the_balance() {
    let e = check_proposal(&fixture("proposal-fee-raised.json"), &fixture("policy.json")).unwrap_err();
    assert!(e.to_string().contains("the witness's value does not match the outputs: asset 0"), "{e}");
}

/// An envelope edited without re-making the binding.
#[test]
fn an_unbound_edit_is_refused_at_the_binding() {
    let e = check_proposal(&fixture("proposal-unbound.json"), &fixture("policy.json")).unwrap_err();
    assert!(e.to_string().contains("does not hash to the proposal's binding"), "{e}");
}

/// The informational summary is untrusted and shown nowhere: naming another address there
/// changes nothing a signer sees, and every output line claims only the owner key.
#[test]
fn the_summary_names_nothing_a_signer_is_shown() {
    let (prop, pol) = (fixture("proposal-valid.json"), fixture("policy.json"));
    let want = check_proposal(&prop, &pol).unwrap().lines();
    let other = randprotocol_core::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] };
    let mut v: serde_json::Value = serde_json::from_str(&prop).unwrap();
    v["summary"] = serde_json::json!([format!("pay 10 RAND to {}", other.to_string()), "fee 0.001 RAND"]);
    let lines = check_proposal(&v.to_string(), &pol).unwrap().lines();
    assert_eq!(lines, want);
    assert!(lines[2..6].iter().all(|l| l.contains("(owner key verified; delivery key NOT verifiable from this proposal)")), "{lines:?}");
    assert!(lines.iter().all(|l| !l.contains("rand1")), "no address is shown: {lines:?}");
}

/// The chain and genesis head the lines, then the loud payee warning (no expectation given).
#[test]
fn the_lines_name_the_chain_and_warn_when_no_payee_is_named() {
    let s = check_proposal(&fixture("proposal-valid.json"), &fixture("policy.json")).unwrap();
    assert!(!s.recipients_checked);
    let lines = s.lines();
    assert_eq!(serde_json::to_value(&lines).unwrap(), expected()["lines"]);
    assert_eq!(lines[0], format!("chain 7 · genesis {}", "0".repeat(64)));
    assert_eq!(lines[1], NO_EXPECTATION);
    assert!(lines[1].contains("no expected recipient given: the payee was NOT checked"));
    assert_eq!(lines.iter().filter(|l| l.contains("NOT checked")).count(), 1, "said once");
}

/// Naming the real recipient: the payment line says which address it matches, the warning goes,
/// the dummies and the change are not held to it.
#[test]
fn naming_the_recipient_marks_the_payment_and_drops_the_warning() {
    let e = expected();
    let to = e["recipient"].as_str().unwrap();
    let s = check_proposal_expecting(&fixture("proposal-valid.json"), &fixture("policy.json"), &[to]).unwrap();
    assert_eq!(serde_json::to_value(&s).unwrap(), e["summary_expecting_recipient"]);
    assert!(s.recipients_checked);
    let fp = randprotocol_core::notes::ShieldedAddress::parse(to).unwrap().fingerprint().to_string();
    assert_eq!(s.outputs.iter().map(|o| o.matches.clone()).collect::<Vec<_>>(), vec![None, None, Some(format!("{fp} ({} RAND)", randprotocol_core::format_amount(s.outputs[2].amount))), None]);
    let lines = s.lines();
    assert_eq!(serde_json::to_value(&lines).unwrap(), e["lines_expecting_recipient"]);
    assert!(lines[3].contains(&format!("matches {fp}")) && lines[3].contains("delivery key NOT verifiable"), "{lines:?}");
    assert!(lines.iter().all(|l| !l.contains("NOT checked")), "{lines:?}");
    assert_eq!(owner_fingerprint_of_text(to).unwrap(), e["recipient_owner_fingerprint"].as_str().unwrap());
    assert!(lines[3].contains(e["recipient_owner_fingerprint"].as_str().unwrap()));
}

/// The coordinator's theft: the payment re-made to its own key, every §6.5 check passes — and
/// naming the recipient the signer meant refuses it, naming the output and the key it pays.
#[test]
fn a_substituted_recipient_passes_the_checks_and_is_refused_only_under_an_expectation() {
    let (prop, pol) = (fixture("proposal-substituted-recipient.json"), fixture("policy.json"));
    let plain = check_proposal(&prop, &pol).unwrap();
    assert!(!plain.recipients_checked && plain.lines()[1] == NO_EXPECTATION);
    let to = expected()["recipient"].as_str().unwrap().to_string();
    let e = check_proposal_expecting(&prop, &pol, &[&to]).unwrap_err().to_string();
    let want = format!("output 2 pays {}, not an expected recipient", plain.outputs[2].owner_fingerprint);
    assert_eq!(e, want);
    assert_eq!(e, expected()["substituted_refusal"].as_str().unwrap());
    let (members, _) = seeds();
    assert_eq!(sign_expecting(&prop, &pol, &members[0], &[&to]).unwrap_err().to_string(), want, "no share for it");
    assert!(sign(&prop, &pol, &members[0]).is_ok(), "the coordinator-trusting mode still signs");
}

/// A pasted address that does not parse is refused naming its index; an empty list is no
/// expectation.
#[test]
fn a_malformed_expected_recipient_is_refused_by_index() {
    let (prop, pol) = (fixture("proposal-valid.json"), fixture("policy.json"));
    let to = expected()["recipient"].as_str().unwrap().to_string();
    let e = check_proposal_expecting(&prop, &pol, &[to.as_str(), "rand1nope"]).unwrap_err().to_string();
    assert!(e.starts_with("expected recipient 1 is not a shielded address"), "{e}");
    assert!(!check_proposal_expecting::<&str>(&prop, &pol, &[]).unwrap().recipients_checked);
    assert!(owner_fingerprint_of_text("rand1nope").is_err());
}

/// The unpaid second address: the valid proposal pays only the first; naming a second payee that
/// no output pays is refused (the coordinator could have dropped a payment), in `sign` too.
#[test]
fn an_expected_recipient_nobody_pays_is_refused() {
    let (prop, pol) = (fixture("proposal-valid.json"), fixture("policy.json"));
    let to = expected()["recipient"].as_str().unwrap().to_string();
    // The same address with one owner-key word changed: well-formed, paid by no output.
    let mut other = randprotocol_core::notes::ShieldedAddress::parse(&to).unwrap();
    other.pk[0] ^= 1;
    let other_text = other.to_string();
    let e = check_proposal_expecting(&prop, &pol, &[to.as_str(), other_text.as_str()]).unwrap_err().to_string();
    assert_eq!(e, format!("expected recipient {} is not paid", other.fingerprint()));
    let (members, _) = seeds();
    assert_eq!(sign_expecting(&prop, &pol, &members[0], &[to.as_str(), other_text.as_str()]).unwrap_err().to_string(), e);
}

/// `rand1…:AMOUNT`: the right amount is accepted and the paying line carries it; a wrong one,
/// and a malformed one, are refused.
#[test]
fn an_amount_pin_is_met_exactly_or_refused() {
    let (prop, pol) = (fixture("proposal-valid.json"), fixture("policy.json"));
    let to = expected()["recipient"].as_str().unwrap().to_string();
    let plain = check_proposal(&prop, &pol).unwrap();
    let paid = plain.outputs[2].amount;
    let rand = randprotocol_core::format_amount(paid);
    let fp = randprotocol_core::notes::ShieldedAddress::parse(&to).unwrap().fingerprint().to_string();
    let s = check_proposal_expecting(&prop, &pol, &[format!("{to}:{rand}")]).unwrap();
    assert_eq!(s.outputs[2].matches.as_deref(), Some(format!("{fp} ({rand} RAND)").as_str()));
    assert!(s.recipients_checked);
    assert!(s.lines()[3].contains(&format!("matches {fp} ({rand} RAND)")), "{:?}", s.lines());
    let wrong = format!("{to}:{}", randprotocol_core::format_amount(paid + 1));
    let e = check_proposal_expecting(&prop, &pol, &[wrong]).unwrap_err().to_string();
    assert_eq!(e, format!("expected recipient {fp} is paid {rand} RAND, not {} RAND", randprotocol_core::format_amount(paid + 1)));
    let e = check_proposal_expecting(&prop, &pol, &[to.clone(), format!("{to}:1.x")]).unwrap_err().to_string();
    assert!(e.starts_with("expected recipient 1 has a malformed amount"), "{e}");
}
