//! The validator operator's commands as the built `rand-node` binary runs them against a
//! loopback RPC fake: `status`, `register`, `unbond`, `withdraw`, `admit sign|submit` and
//! `price status|sign|submit`. The signatures are checked against the messages the ledger
//! verifies; the refusals are the ones decided before anything is sent. Chain 14, no proofs.

mod fakerpc;

use fakerpc::*;
use randprotocol_core::Action;
use serde_json::{json, Value};

fn genesis() -> String {
    "cd".repeat(32)
}

fn validators_node(who: &Signer, nonce: u64) -> (String, Calls) {
    let (address, payout) = (who.address.clone(), recipient());
    chain14(move |m, _| (m == "rand_getValidators").then(|| json!([{ "address": address, "nonce": nonce, "payout": payout }])))
}

#[test]
fn status_prints_the_node_status() {
    let (url, _) = chain14(|m, _| (m == "rand_status").then(|| json!({ "fri_profile": "test", "height": 9 })));
    let r = node(&["status", "--rpc", &url]);
    assert!(r.ok, "{}", r.err);
    assert_eq!(serde_json::from_str::<Value>(&r.out).unwrap()["height"], 9);
    let dead = node(&["status", "--rpc", "http://127.0.0.1:9"]);
    assert!(!dead.ok);
}

#[test]
fn register_prints_a_registration_that_decodes_and_verifies_for_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let me = signer(dir.path(), "validator");
    let (url, _) = chain14(|_, _| None);
    let payout = recipient();
    let r = node(&["register", "--key", me.key.to_str().unwrap(), "--payout", &payout, "--rpc", &url]);
    assert!(r.ok, "{}", r.err);
    let mut lines = r.out.lines();
    assert_eq!(lines.next().unwrap(), format!("validator {} on chain 14", me.address));
    let blob = lines.next().unwrap().strip_prefix("registration: ").unwrap();
    let reg = randprotocol_core::Registration::decode(&hex::decode(blob).unwrap()).unwrap();
    assert_eq!(reg.public_key.to_hex(), me.public);
    assert_eq!(reg.payout.to_string(), payout);
    // The v1 message is the chain-id one on chain 14; the v2 message binds the genesis hash too.
    let v1 = randprotocol_core::BindingDomain::ChainId.registration_message(14, &reg.public_key.address(), &reg.payout);
    assert!(reg.public_key.verify(v1.as_bytes(), &reg.signature));
    let r2 = node(&["register", "--key", me.key.to_str().unwrap(), "--payout", &payout, "--rpc", &url, "--v2"]);
    assert!(r2.ok, "{}", r2.err);
    let blob2 = r2.out.lines().nth(1).unwrap().strip_prefix("registration: ").unwrap();
    let reg2 = randprotocol_core::Registration::decode(&hex::decode(blob2).unwrap()).unwrap();
    assert_ne!(blob, blob2, "a v2 registration is a different signature");
    let g = randprotocol_core::Hash::from_hex(&genesis()).unwrap();
    let v2 = randprotocol_core::registration_message_v2(&g, 14, &reg2.public_key.address(), &reg2.payout);
    assert!(reg2.public_key.verify(v2.as_bytes(), &reg2.signature));
    assert!(!reg2.public_key.verify(v1.as_bytes(), &reg2.signature));

    let bad = node(&["register", "--key", me.key.to_str().unwrap(), "--payout", "rand1nope", "--rpc", &url]);
    assert!(!bad.ok && bad.err.contains("rand1nope is not a shielded address"), "{}", bad.err);
    let nokey = node(&["register", "--key", dir.path().join("none").to_str().unwrap(), "--payout", &payout, "--rpc", &url]);
    assert!(!nokey.ok);
}

#[test]
fn unbond_signs_the_register_nonce_and_submits_bundle_less() {
    let dir = tempfile::tempdir().unwrap();
    let me = signer(dir.path(), "validator");
    let (url, calls) = validators_node(&me, 6);
    let r = node(&["unbond", "2.5", "--key", me.key.to_str().unwrap(), "--rpc", &url]);
    assert!(r.ok, "{}", r.err);
    assert!(r.out.contains(&format!("submitted unbond of 2.5 RAND {}", "ef".repeat(32))), "{}", r.out);
    assert!(r.out.contains("committed in block 41"), "{}", r.out);
    let tx = &sent(&calls)[0];
    assert!(tx.bundle.is_none() && tx.chain_id == 14);
    let Action::Unbond { validator, amount, nonce, signature } = &tx.action else { panic!("{:?}", tx.action) };
    assert_eq!((validator.to_base58(), *amount, *nonce), (me.address.clone(), 2_500_000_000, 6));
    let pk = randprotocol_core::PublicKey::from_hex(&me.public).unwrap();
    let msg = randprotocol_core::BindingDomain::ChainId.unbond_message(14, validator, *amount, *nonce);
    assert!(pk.verify(msg.as_bytes(), signature), "the unbond is signed over the chain's message at the register's nonce");

    let nw = node(&["unbond", "1", "--key", me.key.to_str().unwrap(), "--rpc", &url, "--no-wait"]);
    assert!(nw.ok && !nw.out.contains("committed"), "{}", nw.out);

    // A key the register does not know is named, and nothing is sent.
    let stranger = signer(dir.path(), "stranger");
    let before = sent(&calls).len();
    let r = node(&["unbond", "1", "--key", stranger.key.to_str().unwrap(), "--rpc", &url]);
    assert!(!r.ok && r.err.contains(&format!("{} is not in the validator register", stranger.address)), "{}", r.err);
    assert_eq!(sent(&calls).len(), before);
    assert!(!node(&["unbond", "lots", "--key", me.key.to_str().unwrap(), "--rpc", &url]).ok);
}

#[test]
fn withdraw_seals_a_note_to_the_register_payout_and_refuses_an_amount_under_the_base() {
    let dir = tempfile::tempdir().unwrap();
    let me = signer(dir.path(), "validator");
    let (url, calls) = validators_node(&me, 2);
    let r = node(&["withdraw", "5", "--key", me.key.to_str().unwrap(), "--rpc", &url, "--no-wait"]);
    assert!(r.ok, "{}", r.err);
    assert!(r.out.contains("withdrawing 5 RAND: a note worth 4.999 RAND to rand1"), "{}", r.out);
    assert!(r.out.contains("the 0.001 RAND base to the block's proposer") && r.out.contains("at time 40"), "{}", r.out);
    let tx = &sent(&calls)[0];
    let Action::Withdraw { validator, amount, nonce, time, .. } = &tx.action else { panic!("{:?}", tx.action) };
    assert_eq!((validator.to_base58(), *amount, *nonce, *time), (me.address.clone(), 5_000_000_000, 2, 40));

    let small = node(&["withdraw", "0.001", "--key", me.key.to_str().unwrap(), "--rpc", &url]);
    assert!(!small.ok && small.err.contains("buys no note"), "{}", small.err);
    assert_eq!(sent(&calls).len(), 1);
}

#[test]
fn admit_votes_are_signed_checked_ordered_and_submitted() {
    let dir = tempfile::tempdir().unwrap();
    let (v1, v2, cand) = (signer(dir.path(), "v1"), signer(dir.path(), "v2"), signer(dir.path(), "cand"));
    let sign = |s: &Signer, candidate: &str, genesis: &str| node(&["admit", "sign", "--candidate", candidate, "--key", s.key.to_str().unwrap(), "--genesis-hash", genesis]);
    let (a, b) = (sign(&v1, &cand.public, &genesis()), sign(&v2, &cand.public, &genesis()));
    assert!(a.ok && b.ok, "{}{}", a.err, b.err);
    assert!(a.err.contains(&format!("validator {} votes to admit", v1.address)), "{}", a.err);
    let (la, lb) = (a.out.trim().to_string(), b.out.trim().to_string());
    assert!(la.starts_with(&format!("{}:", v1.public)));

    // The candidate may be a file holding the key, or a registration blob.
    let file = dir.path().join("cand.txt");
    std::fs::write(&file, format!("some words\n{}\n", cand.public)).unwrap();
    assert_eq!(sign(&v1, file.to_str().unwrap(), &genesis()).out.trim(), la, "the last word of the file is the key");
    let reg = node(&["register", "--key", cand.key.to_str().unwrap(), "--payout", &recipient(), "--rpc", &chain14(|_, _| None).0]);
    let blob = reg.out.lines().nth(1).unwrap().strip_prefix("registration: ").unwrap().to_string();
    assert_eq!(sign(&v1, &blob, &genesis()).out.trim(), la, "a registration blob names its key");
    let junk = sign(&v1, "zz", &genesis());
    assert!(!junk.ok && junk.err.contains("neither a validator public key in hex"), "{}", junk.err);
    let short = sign(&v1, "abcd", &genesis());
    assert!(!short.ok && short.err.contains("neither a"), "{}", short.err);
    let badg = sign(&v1, &cand.public, "nothex");
    assert!(!badg.ok && badg.err.contains("--genesis-hash"), "{}", badg.err);

    let (url, calls) = chain14(|_, _| None);
    let submit = |sigs: &[&str], extra: &[&str]| {
        let mut args = vec!["admit", "submit", "--candidate", cand.public.as_str(), "--rpc", url.as_str()];
        for s in sigs {
            args.push("--signature");
            args.push(s);
        }
        args.extend(extra);
        node(&args)
    };
    let ok = submit(&[&lb, &la], &["--no-wait"]);
    assert!(ok.ok, "{}", ok.err);
    assert!(ok.out.contains(&format!("submitted admission of {} by 2 vote(s)", cand.address)), "{}", ok.out);
    let Action::AdmitValidator { signatures, .. } = &sent(&calls)[0].action else { panic!("{:?}", sent(&calls)[0].action) };
    let voters: Vec<_> = signatures.iter().map(|(k, _)| k.address()).collect();
    let mut sorted = voters.clone();
    sorted.sort();
    assert_eq!(voters, sorted, "votes are sent in ascending voter order whatever order they were given");

    let twice = submit(&[&la, &la], &[]);
    assert!(!twice.ok && twice.err.contains("votes twice"), "{}", twice.err);
    let other_chain = sign(&v1, &cand.public, &"ab".repeat(32));
    let wrong = submit(&[other_chain.out.trim()], &[]);
    assert!(!wrong.ok && wrong.err.contains("not a signature over this chain's admission"), "{}", wrong.err);
    let fmt = submit(&["nocolon"], &[]);
    assert!(!fmt.ok && fmt.err.contains("<voter public key hex>:<signature hex>"), "{}", fmt.err);
    let nothex = submit(&[&format!("{}:zz", v1.public)], &[]);
    assert!(!nothex.ok && nothex.err.contains("signature is not hex"), "{}", nothex.err);
    let badkey = submit(&["zz:00"], &[]);
    assert!(!badkey.ok && badkey.err.contains("voter key"), "{}", badkey.err);
    let shortsig = submit(&[&format!("{}:00", v1.public)], &[]);
    assert!(!shortsig.ok, "{}", shortsig.err);
    assert_eq!(sent(&calls).len(), 1, "only the good submission was sent");
    let waited = submit(&[&la], &[]);
    assert!(waited.ok && waited.out.contains("committed in block 41"), "{}{}", waited.out, waited.err);
}

#[test]
fn price_status_reads_the_voted_price_or_says_there_is_none() {
    let (none, _) = chain14(|m, _| (m == "rand_getRandPrice").then_some(Value::Null));
    let r = node(&["price", "status", "--rpc", &none]);
    assert!(r.ok && r.out.contains("no voted price"), "{}{}", r.out, r.err);
    let (some, _) = chain14(|m, _| (m == "rand_getRandPrice").then(|| json!({ "price_micros_per_rand": "150000", "nonce": 4, "set_at_height": 33, "fresh": true, "max_age_blocks": 600 })));
    let r = node(&["price", "status", "--rpc", &some]);
    assert!(r.ok, "{}", r.err);
    assert_eq!(r.out.trim(), "price $0.15 per RAND (150000 µ$), set at height 33, nonce 4; fresh for the next block (max age 600 blocks); next update's nonce 5");
    let (stale, _) = chain14(|m, _| (m == "rand_getRandPrice").then(|| json!({ "price_micros_per_rand": 2_000_000u64, "nonce": 1, "set_at_height": 3, "fresh": false, "max_age_blocks": 10 })));
    assert!(node(&["price", "status", "--rpc", &stale]).out.contains("price $2 per RAND (2000000 µ$)") );
    let (bad, _) = chain14(|m, _| (m == "rand_getRandPrice").then(|| json!({ "nonce": 1 })));
    assert!(!node(&["price", "status", "--rpc", &bad]).ok);
}

#[test]
fn price_votes_are_signed_bound_to_price_and_nonce_and_submitted_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let (v1, v2) = (signer(dir.path(), "v1"), signer(dir.path(), "v2"));
    let sign = |s: &Signer, price: &str, nonce: &str| node(&["price", "sign", "--price", price, "--nonce", nonce, "--key", s.key.to_str().unwrap(), "--genesis-hash", &genesis()]);
    let (a, b) = (sign(&v1, "0.15", "5"), sign(&v2, "$0.15", "5"));
    assert!(a.ok && b.ok, "{}{}", a.err, b.err);
    assert!(a.err.contains("votes the RAND price to $0.15 at nonce 5"), "{}", a.err);
    let (la, lb) = (a.out.trim().to_string(), b.out.trim().to_string());
    for bad in ["0", "abc", "1.0000001", "", "."] {
        let r = sign(&v1, bad, "5");
        assert!(!r.ok, "{bad:?} must be refused");
    }
    assert!(sign(&v1, "0", "5").err.contains("must be greater than 0"));
    assert!(sign(&v1, "1.0000001", "5").err.contains("more than six decimals"));
    assert!(sign(&v1, "x", "5").err.contains("is not a dollar amount like 0.15"));

    // The node's last nonce is 4, so the next is 5.
    let (url, calls) = chain14(|m, _| (m == "rand_getRandPrice").then(|| json!({ "nonce": 4 })));
    let file = dir.path().join("votes.txt");
    std::fs::write(&file, format!("{lb}\n\n"))
        .unwrap();
    let r = node(&["price", "submit", "--price", "0.15", "--nonce", "5", "--signature", &la, "--signature", file.to_str().unwrap(), "--rpc", &url, "--no-wait"]);
    assert!(r.ok, "{}", r.err);
    assert!(r.out.contains("submitted RAND price $0.15 at nonce 5 by 2 vote(s)"), "{}", r.out);
    let Action::SetRandPrice { .. } = &sent(&calls)[0].action else { panic!("{:?}", sent(&calls)[0].action) };

    let wrong_nonce = node(&["price", "submit", "--price", "0.15", "--nonce", "9", "--signature", &la, "--rpc", &url]);
    assert!(!wrong_nonce.ok && wrong_nonce.err.contains("--nonce 9: the node's next price update is nonce 5"), "{}", wrong_nonce.err);
    let wrong_price = node(&["price", "submit", "--price", "0.16", "--nonce", "5", "--signature", &la, "--rpc", &url]);
    assert!(!wrong_price.ok && wrong_price.err.contains("not a signature over this chain's price update to $0.16 at nonce 5"), "{}", wrong_price.err);
    let twice = node(&["price", "submit", "--price", "0.15", "--nonce", "5", "--signature", &la, "--signature", &la, "--rpc", &url]);
    assert!(!twice.ok && twice.err.contains("votes twice"), "{}", twice.err);
    assert_eq!(sent(&calls).len(), 1);
    let waited = node(&["price", "submit", "--price", "0.15", "--nonce", "5", "--signature", &la, "--rpc", &url]);
    assert!(waited.ok && waited.out.contains("committed in block 41"), "{}", waited.out);

    // A node with no price yet expects nonce 1.
    let (fresh, _) = chain14(|m, _| (m == "rand_getRandPrice").then_some(Value::Null));
    let one = sign(&v1, "0.15", "1");
    let r = node(&["price", "submit", "--price", "0.15", "--nonce", "1", "--signature", one.out.trim(), "--rpc", &fresh, "--no-wait"]);
    assert!(r.ok, "{}", r.err);
}
