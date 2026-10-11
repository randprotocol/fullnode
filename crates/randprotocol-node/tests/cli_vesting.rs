//! `rand-node vesting …` and `rand-node aggregator …` as the built binary runs them against a
//! loopback RPC fake: reading an entry, claiming, bonding and unbonding locked RAND, the
//! three-step revoke, and the aggregator's register / unbond / withdraw. Every signature is
//! checked against the message the ledger verifies. Chain 14, nothing proved.

mod fakerpc;

use fakerpc::*;
use randprotocol_core::Action;
use serde_json::{json, Value};

fn entry_id() -> String {
    "ab".repeat(32)
}

fn vesting_reply(beneficiary_free: bool, revocable: bool, revoked: bool, claimable: u64, revokers: &[&Signer]) -> Value {
    json!({
        "entry": entry_id(), "nonce": 3, "claimable_now": claimable.to_string(), "unvested_now": "4000000000",
        "revocable": revocable, "revoke_nonce": 5, "treasury": recipient(), "as_of_ms": 1_000_000u64,
        "revoked_at": if revoked { json!(7) } else { Value::Null },
        "revokers": revokers.iter().map(|s| s.address.clone()).collect::<Vec<_>>(),
        "threshold": 2, "beneficiary_free": beneficiary_free,
    })
}

fn vesting_node(reply: Value) -> (String, Calls) {
    chain14(move |m, _| (m == "rand_getVesting").then(|| reply.clone()))
}

#[test]
fn vesting_status_prints_the_entry_and_refuses_bad_ids_and_sectionless_chains() {
    let (url, calls) = vesting_node(vesting_reply(true, false, false, 9, &[]));
    let r = node(&["vesting", "status", &entry_id(), "--rpc", &url]);
    assert!(r.ok, "{}", r.err);
    assert_eq!(serde_json::from_str::<Value>(&r.out).unwrap()["nonce"], 3);
    assert_eq!(calls.lock().unwrap()[0].1, json!([entry_id(), Value::Null]));
    let bad = node(&["vesting", "status", "xyz", "--rpc", &url]);
    assert!(!bad.ok && bad.err.contains("is not a vesting entry id (64 hex characters)"), "{}", bad.err);
    let (none, _) = chain14(|m, _| (m == "rand_getVesting").then_some(json!({ "enabled": false })));
    let r = node(&["vesting", "status", &entry_id(), "--rpc", &none]);
    assert!(!r.ok && r.err.contains("this chain has no vesting section"), "{}", r.err);
    let (missing, _) = chain14(|m, _| (m == "rand_getVesting").then_some(Value::Null));
    let r = node(&["vesting", "status", &entry_id(), "--rpc", &missing]);
    assert!(!r.ok && r.err.contains(&format!("no vesting entry {} on this chain", entry_id())), "{}", r.err);
}

#[test]
fn vesting_claim_signs_the_amount_and_refuses_what_the_chain_would() {
    let dir = tempfile::tempdir().unwrap();
    let me = signer(dir.path(), "beneficiary");
    let (url, calls) = vesting_node(vesting_reply(true, false, false, 3_000_000_000, &[]));
    let to = recipient();
    let key = me.key.to_str().unwrap();
    let all = node(&["vesting", "claim", "--entry", &entry_id(), "--to", &to, "--all", "--key", key, "--rpc", &url, "--no-wait"]);
    assert!(all.ok, "{}", all.err);
    assert!(all.out.contains("claiming 3 RAND from entry") && all.out.contains("a note worth 2.999 RAND"), "{}", all.out);
    let Action::ClaimVested { entry, amount, nonce, time, .. } = &sent(&calls)[0].action else { panic!() };
    assert_eq!((hex::encode(entry), *amount, *nonce, *time), (entry_id(), 3_000_000_000, 3, 40));

    let part = node(&["vesting", "claim", "--entry", &entry_id(), "--to", &to, "--amount", "1.5", "--key", key, "--rpc", &url, "--no-wait"]);
    assert!(part.ok, "{}", part.err);
    let Action::ClaimVested { amount, .. } = &sent(&calls)[1].action else { panic!() };
    assert_eq!(*amount, 1_500_000_000);

    let over = node(&["vesting", "claim", "--entry", &entry_id(), "--to", &to, "--amount", "4", "--key", key, "--rpc", &url]);
    assert!(!over.ok && over.err.contains("only 3 RAND is claimable now, not 4 RAND"), "{}", over.err);
    let dust = node(&["vesting", "claim", "--entry", &entry_id(), "--to", &to, "--amount", "0.001", "--key", key, "--rpc", &url]);
    assert!(!dust.ok && dust.err.contains("buys no note"), "{}", dust.err);
    let badto = node(&["vesting", "claim", "--entry", &entry_id(), "--to", "rand1x", "--all", "--key", key, "--rpc", &url]);
    assert!(!badto.ok && badto.err.contains("rand1x is not a shielded address"), "{}", badto.err);
    let neither = node(&["vesting", "claim", "--entry", &entry_id(), "--to", &to, "--key", key, "--rpc", &url]);
    assert!(!neither.ok, "--amount or --all is required");
    let both = node(&["vesting", "claim", "--entry", &entry_id(), "--to", &to, "--amount", "1", "--all", "--key", key, "--rpc", &url]);
    assert!(!both.ok, "--amount conflicts with --all");
    assert_eq!(sent(&calls).len(), 2);
}

#[test]
fn vesting_bond_and_unbond_sign_the_entry_nonce_and_a_revocable_entry_cannot_bond() {
    let dir = tempfile::tempdir().unwrap();
    let me = signer(dir.path(), "beneficiary");
    let validator = signer(dir.path(), "validator");
    let key = me.key.to_str().unwrap();
    let (url, calls) = vesting_node(vesting_reply(true, false, false, 0, &[]));
    let bond = node(&["vesting", "bond", "--entry", &entry_id(), "--validator", &validator.address, "10", "--key", key, "--rpc", &url, "--no-wait"]);
    assert!(bond.ok, "{}", bond.err);
    assert!(bond.out.contains(&format!("submitted bond of 10 locked RAND to {}", validator.address)), "{}", bond.out);
    let Action::BondVested { amount, nonce, registration, .. } = &sent(&calls)[0].action else { panic!() };
    assert_eq!((*amount, *nonce, registration.is_none()), (10_000_000_000, 3, true));

    // With a registration blob for a new validator riding along.
    let reg = node(&["register", "--key", validator.key.to_str().unwrap(), "--payout", &recipient(), "--rpc", &url]);
    let blob = reg.out.lines().nth(1).unwrap().strip_prefix("registration: ").unwrap().to_string();
    let with = node(&["vesting", "bond", "--entry", &entry_id(), "--validator", &validator.address, "10", "--registration", &blob, "--key", key, "--rpc", &url, "--no-wait"]);
    assert!(with.ok, "{}", with.err);
    let Action::BondVested { registration, .. } = &sent(&calls)[1].action else { panic!() };
    assert!(registration.is_some());
    let badreg = node(&["vesting", "bond", "--entry", &entry_id(), "--validator", &validator.address, "10", "--registration", "zz", "--key", key, "--rpc", &url]);
    assert!(!badreg.ok && badreg.err.contains("--registration is hex"), "{}", badreg.err);
    let badval = node(&["vesting", "bond", "--entry", &entry_id(), "--validator", "nope", "10", "--key", key, "--rpc", &url]);
    assert!(!badval.ok && badval.err.contains("nope is not a validator address"), "{}", badval.err);

    let un = node(&["vesting", "unbond", "--entry", &entry_id(), "4", "--key", key, "--rpc", &url]);
    assert!(un.ok && un.out.contains("submitted unbond of 4 locked RAND") && un.out.contains("committed in block 41"), "{}{}", un.out, un.err);

    let (revocable, calls2) = vesting_node(vesting_reply(false, true, false, 0, &[]));
    let r = node(&["vesting", "bond", "--entry", &entry_id(), "--validator", &validator.address, "1", "--key", key, "--rpc", &revocable]);
    assert!(!r.ok && r.err.contains("a revocable entry cannot bond"), "{}", r.err);
    assert!(sent(&calls2).is_empty());
}

#[test]
fn a_revoke_is_prepared_signed_by_the_revokers_and_submitted() {
    let dir = tempfile::tempdir().unwrap();
    let (r0, r1) = (signer(dir.path(), "r0"), signer(dir.path(), "r1"));
    let (url, calls) = vesting_node(vesting_reply(false, true, false, 0, &[&r0, &r1]));
    let file = dir.path().join("revoke.json");
    let f = file.to_str().unwrap();
    let prep = node(&["vesting", "revoke", "prepare", "--entry", &entry_id(), "--out", f, "--rpc", &url]);
    assert!(prep.ok, "{}", prep.err);
    assert!(prep.out.contains("prepared the revoke of entry") && prep.out.contains("4 RAND to the treasury") && prep.out.contains("2 of 2 revokers sign it"), "{}", prep.out);
    assert!(calls.lock().unwrap().iter().any(|(m, p)| m == "rand_getVesting" && p[1] == json!(1_600_000u64)), "the schedule is asked at head + the 600 s margin");
    let again = node(&["vesting", "revoke", "prepare", "--entry", &entry_id(), "--out", f, "--rpc", &url]);
    assert!(!again.ok && again.err.contains("a prepared revoke is never overwritten"), "{}", again.err);

    let s0 = node(&["vesting", "revoke", "sign", "--proposal", f, "--key", r0.key.to_str().unwrap()]);
    let s1 = node(&["vesting", "revoke", "sign", "--proposal", f, "--key", r1.key.to_str().unwrap()]);
    assert!(s0.ok && s1.ok, "{}{}", s0.err, s1.err);
    assert!(s0.out.starts_with("0:") && s1.out.starts_with("1:"));
    assert!(s0.err.contains("check that address against the entry's `treasury` in the genesis file"), "{}", s0.err);

    let sub = node(&["vesting", "revoke", "submit", "--proposal", f, "--signature", s1.out.trim(), "--signature", s0.out.trim(), "--rpc", &url]);
    assert!(sub.ok, "{}", sub.err);
    assert!(sub.out.contains("submitted revoke of 4 RAND") && sub.out.contains("committed in block 41"), "{}", sub.out);
    let Action::RevokeVesting { signatures, nonce, .. } = &sent(&calls)[0].action else { panic!() };
    assert_eq!((signatures.iter().map(|s| s.index).collect::<Vec<_>>(), *nonce), (vec![0, 1], 5));

    let dup = node(&["vesting", "revoke", "submit", "--proposal", f, "--signature", s0.out.trim(), "--signature", s0.out.trim(), "--rpc", &url]);
    assert!(!dup.ok && dup.err.contains("revoker 0 is given twice"), "{}", dup.err);
    let malformed = node(&["vesting", "revoke", "submit", "--proposal", f, "--signature", "nocolon", "--rpc", &url]);
    assert!(!malformed.ok && malformed.err.contains("--signature takes <index>:<hex>"), "{}", malformed.err);
    assert_eq!(sent(&calls).len(), 1);
}

#[test]
fn a_revoke_is_refused_for_an_irrevocable_entry_and_swept_exactly_once_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let r0 = signer(dir.path(), "r0");
    let (irrev, _) = vesting_node(vesting_reply(true, false, false, 0, &[]));
    let f = dir.path().join("r.json");
    let r = node(&["vesting", "revoke", "prepare", "--entry", &entry_id(), "--out", f.to_str().unwrap(), "--rpc", &irrev]);
    assert!(!r.ok && r.err.contains("has no revoker: it is irrevocable"), "{}", r.err);
    assert!(!f.exists());

    let (revoked, calls) = vesting_node(vesting_reply(false, true, true, 0, &[&r0]));
    let r = node(&["vesting", "revoke", "prepare", "--entry", &entry_id(), "--out", f.to_str().unwrap(), "--rpc", &revoked]);
    assert!(r.ok, "{}", r.err);
    assert!(r.out.contains("prepared the sweep of entry") && !r.out.contains("unvested 600 s from now"), "{}", r.out);
    assert_eq!(calls.lock().unwrap().iter().filter(|(m, _)| m == "rand_getVesting").count(), 1, "no second read at a later time");

    let (spent, _) = vesting_node({
        let mut v = vesting_reply(false, true, true, 0, &[&r0]);
        v["unvested_now"] = json!("1000000");
        v
    });
    let f2 = dir.path().join("r2.json");
    let r = node(&["vesting", "revoke", "prepare", "--entry", &entry_id(), "--out", f2.to_str().unwrap(), "--rpc", &spent]);
    assert!(!r.ok && r.err.contains("nothing above the 0.001 RAND base is left to sweep"), "{}", r.err);
    let (none_left, _) = vesting_node({
        let mut v = vesting_reply(false, true, false, 0, &[&r0]);
        v["unvested_now"] = json!("0");
        v
    });
    let r = node(&["vesting", "revoke", "prepare", "--entry", &entry_id(), "--out", f2.to_str().unwrap(), "--rpc", &none_left]);
    assert!(!r.ok && r.err.contains("nothing left to revoke"), "{}", r.err);
}

#[test]
fn an_aggregator_registers_unbonds_and_withdraws_its_bond() {
    let dir = tempfile::tempdir().unwrap();
    let me = signer(dir.path(), "agg");
    let payout = recipient();
    let (p2, key) = (payout.clone(), me.address.clone());
    let (url, calls) = chain14(move |m, _| {
        (m == "rand_getAggregators").then(|| json!([{ "address": key, "nonce": 4, "payout": p2, "bond": "250000000000" }]))
    });
    let k = me.key.to_str().unwrap();
    let reg = node(&["aggregator", "register", "--key", k, "--bond", "250", "--payout", &payout, "--rpc", &url]);
    assert!(reg.ok, "{}", reg.err);
    assert!(reg.out.starts_with(&format!("aggregator {} on chain 14\nregistration: ", me.address)), "{}", reg.out);
    assert!(reg.out.contains("bond 250 RAND rides through the wallet's `submit`"), "{}", reg.out);
    let blob = reg.out.lines().nth(1).unwrap().strip_prefix("registration: ").unwrap();
    let decoded: randprotocol_core::types::actions::AggregatorRegistration = bincode::deserialize(&hex::decode(blob).unwrap()).unwrap();
    assert_eq!(decoded.public_key.to_hex(), me.public);
    let msg = randprotocol_core::BindingDomain::ChainId.aggregator_register_message(14, &decoded.public_key.address(), &decoded.payout);
    assert!(decoded.public_key.verify(msg.as_bytes(), &decoded.signature));
    assert!(!node(&["aggregator", "register", "--key", k, "--bond", "250", "--payout", "bad", "--rpc", &url]).ok);

    let un = node(&["aggregator", "unbond", "--key", k, "--rpc", &url, "--no-wait"]);
    assert!(un.ok && un.out.contains("submitted aggregator unbond"), "{}{}", un.out, un.err);
    let Action::UnbondAggregator { nonce, signature, aggregator } = &sent(&calls)[0].action else { panic!() };
    assert_eq!(*nonce, 4);
    let umsg = randprotocol_core::BindingDomain::ChainId.aggregator_unbond_message(14, aggregator, 4);
    assert!(decoded.public_key.verify(umsg.as_bytes(), signature));

    let wd = node(&["aggregator", "withdraw", "--key", k, "--rpc", &url]);
    assert!(wd.ok && wd.out.contains("submitted aggregator withdraw") && wd.out.contains("committed in block 41"), "{}{}", wd.out, wd.err);
    let Action::WithdrawAggregator { nonce, time, .. } = &sent(&calls)[1].action else { panic!() };
    assert_eq!((*nonce, *time), (4, 40));

    // An unregistered key is named; a bond that cannot cover the base is refused.
    let stranger = signer(dir.path(), "stranger");
    let r = node(&["aggregator", "unbond", "--key", stranger.key.to_str().unwrap(), "--rpc", &url]);
    assert!(!r.ok && r.err.contains(&stranger.address), "{}", r.err);
    let (a2, p3) = (me.address.clone(), payout.clone());
    let (thin, calls2) = chain14(move |m, _| (m == "rand_getAggregators").then(|| json!([{ "address": a2, "nonce": 1, "payout": p3, "bond": "1000" }])));
    let r = node(&["aggregator", "withdraw", "--key", k, "--rpc", &thin]);
    assert!(!r.ok && r.err.contains("the bond does not cover the bundle base"), "{}", r.err);
    assert!(sent(&calls2).is_empty());
}
