//! `rand-node multisig …` as an operator runs it: the built binary against a loopback RPC fake.
//! The three-step flows (`prepare` → `sign` per signer → `submit`) for a payment and a rotation,
//! the id derivation, and the refusals decided before anything is sent. Nothing proves; chain 14
//! is a chain cut before `binding_domain`, so no genesis binding is needed.

mod fakerpc;

use fakerpc::*;
use serde_json::{json, Value};

/// A chain-14 node whose `rand_getMultisig` answers `account`.
fn fake(account: Value) -> (String, Calls) {
    chain14(move |m, _| (m == "rand_getMultisig").then(|| account.clone()))
}

const SALT: &str = "0707070707070707070707070707070707070707070707070707070707070707";

fn account_reply(
    id: &str,
    signers: &[&Signer],
    threshold: u8,
    nonce: u64,
    rand_in_vault: u64,
) -> Value {
    json!({
        "id": id, "signers": signers.iter().map(|s| s.public.clone()).collect::<Vec<_>>(),
        "threshold": threshold, "nonce": nonce,
        "vault": [{ "asset": 0, "amount": rand_in_vault.to_string() }],
    })
}

fn id_of(signers: &[&Signer], threshold: u8) -> String {
    let mut args = vec![
        "multisig".to_string(),
        "id".into(),
        "--salt".into(),
        SALT.into(),
        "--threshold".into(),
        threshold.to_string(),
        "--chain-id".into(),
        "14".into(),
    ];
    for s in signers {
        args.push("--signer".into());
        args.push(s.public.clone());
    }
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = node(&a);
    assert!(r.ok, "{}", r.err);
    r.out.trim().to_string()
}

#[test]
fn multisig_id_is_the_ledgers_and_depends_on_order_threshold_and_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b, c) = (
        signer(dir.path(), "a"),
        signer(dir.path(), "b"),
        signer(dir.path(), "c"),
    );
    let id = id_of(&[&a, &b, &c], 2);
    assert_eq!(id.len(), 64);
    let keys: Vec<_> = [&a, &b, &c]
        .iter()
        .map(|s| randprotocol_core::PublicKey::from_hex(&s.public).unwrap())
        .collect();
    assert_eq!(
        id,
        hex::encode(randprotocol_core::ledger::multisig::account_id(
            14, &[7; 32], 2, &keys
        ))
    );
    assert_eq!(id, id_of(&[&a, &b, &c], 2), "deterministic");
    assert_ne!(id, id_of(&[&b, &a, &c], 2), "the order is part of the id");
    assert_ne!(id, id_of(&[&a, &b, &c], 3), "the threshold is");
    let r = node(&[
        "multisig",
        "id",
        "--salt",
        SALT,
        "--threshold",
        "4",
        "--chain-id",
        "14",
        "--signer",
        &a.public,
        "--signer",
        &b.public,
    ]);
    assert!(!r.ok && r.err.contains("threshold"), "{}", r.err);
    let r = node(&[
        "multisig",
        "id",
        "--salt",
        "abcd",
        "--threshold",
        "1",
        "--chain-id",
        "14",
        "--signer",
        &a.public,
    ]);
    assert!(
        !r.ok && r.err.contains("is not a salt (64 hex characters)"),
        "{}",
        r.err
    );
    let r = node(&[
        "multisig",
        "id",
        "--salt",
        SALT,
        "--threshold",
        "1",
        "--chain-id",
        "14",
        "--signer",
        "zz",
    ]);
    assert!(
        !r.ok && r.err.contains("signer 0: not a Dilithium2 public key"),
        "{}",
        r.err
    );
}

#[test]
fn multisig_status_prints_the_account_and_refuses_unknown_and_sectionless_chains() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (signer(dir.path(), "a"), signer(dir.path(), "b"));
    let id = id_of(&[&a, &b], 2);
    let (url, _) = fake(account_reply(&id, &[&a, &b], 2, 3, 5_000_000_000));
    let r = node(&["multisig", "status", &id, "--rpc", &url]);
    assert!(r.ok, "{}", r.err);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert_eq!(
        (v["threshold"].clone(), v["nonce"].clone()),
        (json!(2), json!(3))
    );
    assert!(r.out.contains("\n  \"id\""), "pretty-printed: {}", r.out);

    let (url, _) = fake(Value::Null);
    let r = node(&["multisig", "status", &id, "--rpc", &url]);
    assert!(
        !r.ok
            && r.err
                .contains(&format!("no multisig account {id} on this chain")),
        "{}",
        r.err
    );
    let (url, _) = fake(json!({ "enabled": false }));
    let r = node(&["multisig", "status", &id, "--rpc", &url]);
    assert!(
        !r.ok && r.err.contains("this chain has no multisig section"),
        "{}",
        r.err
    );
    let r = node(&["multisig", "status", "abcd", "--rpc", &url]);
    assert!(
        !r.ok && r.err.contains("multisig account id (64 hex characters)"),
        "{}",
        r.err
    );
}

#[test]
fn a_payment_is_prepared_signed_by_two_signers_and_submitted_bundle_less() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b, c) = (
        signer(dir.path(), "a"),
        signer(dir.path(), "b"),
        signer(dir.path(), "c"),
    );
    let id = id_of(&[&a, &b, &c], 2);
    let (url, calls) = fake(account_reply(&id, &[&a, &b, &c], 2, 4, 50_000_000_000));
    let pay = dir.path().join("pay.json");
    let to = recipient();
    let prep = node(&[
        "multisig",
        "pay",
        "prepare",
        "--account",
        &id,
        "--to",
        &to,
        "--amount",
        "1.5",
        "--out",
        pay.to_str().unwrap(),
        "--rpc",
        &url,
    ]);
    assert!(prep.ok, "{}", prep.err);
    assert!(
        prep.out.contains("prepared a payment from account") && prep.out.contains("1 payout(s)"),
        "{}",
        prep.out
    );
    assert!(prep.out.contains("2 of 3 signers sign it"), "{}", prep.out);
    assert!(
        prep.out.contains("of asset 0 to") && prep.out.contains("within 256 blocks of height 40"),
        "{}",
        prep.out
    );
    let file: Value = serde_json::from_str(&std::fs::read_to_string(&pay).unwrap()).unwrap();
    assert_eq!(
        (file["nonce"].clone(), file["account"].clone()),
        (json!(4), json!(id))
    );

    // A prepared file is never overwritten.
    let again = node(&[
        "multisig",
        "pay",
        "prepare",
        "--account",
        &id,
        "--to",
        &to,
        "--amount",
        "1",
        "--out",
        pay.to_str().unwrap(),
        "--rpc",
        &url,
    ]);
    assert!(
        !again.ok
            && again
                .err
                .contains("a prepared payment is never overwritten"),
        "{}",
        again.err
    );

    // Each signer signs the same file: stdout is exactly `<index>:<hex>`, the review is on stderr.
    let sig_a = node(&[
        "multisig",
        "pay",
        "sign",
        "--proposal",
        pay.to_str().unwrap(),
        "--key",
        a.key.to_str().unwrap(),
    ]);
    let sig_c = node(&[
        "multisig",
        "pay",
        "sign",
        "--proposal",
        pay.to_str().unwrap(),
        "--key",
        c.key.to_str().unwrap(),
    ]);
    assert!(sig_a.ok && sig_c.ok, "{}{}", sig_a.err, sig_c.err);
    assert!(
        sig_a.out.starts_with("0:") && sig_c.out.starts_with("2:"),
        "{} / {}",
        &sig_a.out[..4],
        &sig_c.out[..4]
    );
    assert_eq!(sig_a.out.trim().lines().count(), 1);
    assert!(
        sig_a.err.contains("check every recipient before signing")
            && sig_a.err.contains("nonce 4, note time 40"),
        "{}",
        sig_a.err
    );

    // A key outside the account cannot sign it.
    let outsider = signer(dir.path(), "outsider");
    let bad = node(&[
        "multisig",
        "pay",
        "sign",
        "--proposal",
        pay.to_str().unwrap(),
        "--key",
        outsider.key.to_str().unwrap(),
    ]);
    assert!(!bad.ok, "{}", bad.out);

    let sub = node(&[
        "multisig",
        "pay",
        "submit",
        "--proposal",
        pay.to_str().unwrap(),
        "--signature",
        sig_a.out.trim(),
        "--signature",
        sig_c.out.trim(),
        "--rpc",
        &url,
    ]);
    assert!(sub.ok, "{}", sub.err);
    assert!(
        sub.out.contains(&format!(
            "submitted payment of 1 payout(s) from account {id} {}",
            "ef".repeat(32)
        )),
        "{}",
        sub.out
    );
    assert!(sub.out.contains("committed in block 41"), "{}", sub.out);
    let txs = sent(&calls);
    assert_eq!(txs.len(), 1);
    assert!(txs[0].bundle.is_none() && txs[0].chain_id == 14);
    assert!(
        matches!(txs[0].action, randprotocol_core::Action::MultisigPay { .. }),
        "{:?}",
        txs[0].action
    );

    let nowait = node(&[
        "multisig",
        "pay",
        "submit",
        "--proposal",
        pay.to_str().unwrap(),
        "--signature",
        sig_a.out.trim(),
        "--signature",
        sig_c.out.trim(),
        "--rpc",
        &url,
        "--no-wait",
    ]);
    assert!(
        nowait.ok && !nowait.out.contains("committed in block"),
        "{}",
        nowait.out
    );
}

#[test]
fn a_payment_is_refused_at_prepare_when_the_vault_cannot_cover_it_or_the_flags_disagree() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (signer(dir.path(), "a"), signer(dir.path(), "b"));
    let id = id_of(&[&a, &b], 2);
    let (url, calls) = fake(account_reply(&id, &[&a, &b], 2, 0, 1_000));
    let out = dir.path().join("p.json");
    let o = out.to_str().unwrap();
    let to = recipient();
    let r = node(&[
        "multisig",
        "pay",
        "prepare",
        "--account",
        &id,
        "--to",
        &to,
        "--amount",
        "1",
        "--out",
        o,
        "--rpc",
        &url,
    ]);
    assert!(!r.ok && r.err.contains("holds 0.000001000 RAND (1000 units) of asset 0, the payment needs 1.001000000 RAND (1001000000 units)"), "{}", r.err);
    assert!(
        !out.exists(),
        "nothing is written for a payment the vault cannot cover"
    );
    let r = node(&[
        "multisig",
        "pay",
        "prepare",
        "--account",
        &id,
        "--to",
        &to,
        "--to",
        &to,
        "--amount",
        "1",
        "--out",
        o,
        "--rpc",
        &url,
    ]);
    assert!(
        !r.ok
            && r.err
                .contains("2 --to and 1 --amount: one amount per recipient"),
        "{}",
        r.err
    );
    let r = node(&[
        "multisig",
        "pay",
        "prepare",
        "--account",
        &id,
        "--to",
        &to,
        "--amount",
        "1",
        "--asset",
        "1",
        "--asset",
        "2",
        "--out",
        o,
        "--rpc",
        &url,
    ]);
    assert!(!r.ok && r.err.contains("2 --asset for 1 --to"), "{}", r.err);
    let r = node(&[
        "multisig",
        "pay",
        "prepare",
        "--account",
        &id,
        "--to",
        "rand1nope",
        "--amount",
        "1",
        "--out",
        o,
        "--rpc",
        &url,
    ]);
    assert!(
        !r.ok && r.err.contains("rand1nope is not a shielded address"),
        "{}",
        r.err
    );
    assert!(sent(&calls).is_empty());
}

#[test]
fn a_rotation_is_prepared_signed_and_submitted_and_a_wrong_chain_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b, c) = (
        signer(dir.path(), "a"),
        signer(dir.path(), "b"),
        signer(dir.path(), "c"),
    );
    let fresh = signer(dir.path(), "fresh");
    let id = id_of(&[&a, &b, &c], 2);
    let (url, calls) = fake(account_reply(&id, &[&a, &b, &c], 2, 9, 0));
    let rot = dir.path().join("rotate.json");
    let r = rot.to_str().unwrap();

    let bad = node(&[
        "multisig",
        "rotate",
        "prepare",
        "--account",
        &id,
        "--signer",
        &fresh.public,
        "--threshold",
        "3",
        "--out",
        r,
        "--rpc",
        &url,
    ]);
    assert!(
        !bad.ok,
        "a 3-of-1 set is refused when prepared: {}",
        bad.out
    );
    assert!(!rot.exists());
    let prep = node(&[
        "multisig",
        "rotate",
        "prepare",
        "--account",
        &id,
        "--signer",
        &fresh.public,
        "--signer",
        &a.public,
        "--threshold",
        "2",
        "--out",
        r,
        "--rpc",
        &url,
    ]);
    assert!(prep.ok, "{}", prep.err);
    assert!(
        prep.out.contains("to 2 of 2 new signers")
            && prep.out.contains("2 of 3 current signers sign it"),
        "{}",
        prep.out
    );
    let again = node(&[
        "multisig",
        "rotate",
        "prepare",
        "--account",
        &id,
        "--signer",
        &fresh.public,
        "--threshold",
        "1",
        "--out",
        r,
        "--rpc",
        &url,
    ]);
    assert!(
        !again.ok
            && again
                .err
                .contains("a prepared rotation is never overwritten"),
        "{}",
        again.err
    );

    let s0 = node(&[
        "multisig",
        "rotate",
        "sign",
        "--proposal",
        r,
        "--key",
        a.key.to_str().unwrap(),
    ]);
    let s1 = node(&[
        "multisig",
        "rotate",
        "sign",
        "--proposal",
        r,
        "--key",
        b.key.to_str().unwrap(),
        "--index",
        "1",
    ]);
    assert!(s0.ok && s1.ok, "{}{}", s0.err, s1.err);
    assert!(s0.out.starts_with("0:") && s1.out.starts_with("1:"));
    assert!(
        s0.err
            .contains("check every new key with its holder before signing")
            && s0.err.contains("nonce 9"),
        "{}",
        s0.err
    );

    let sub = node(&[
        "multisig",
        "rotate",
        "submit",
        "--proposal",
        r,
        "--signature",
        s0.out.trim(),
        "--signature",
        s1.out.trim(),
        "--rpc",
        &url,
        "--no-wait",
    ]);
    assert!(sub.ok, "{}", sub.err);
    assert!(
        sub.out.contains(&format!(
            "submitted rotation of account {id} to 2 of 2 {}",
            "ef".repeat(32)
        )),
        "{}",
        sub.out
    );
    assert!(matches!(
        sent(&calls)[0].action,
        randprotocol_core::Action::MultisigRotate { .. }
    ));

    // The same file against a node on another chain is refused before anything is sent. The fake
    // serves chain 14; editing the prepared file's chain id makes it a chain-99 rotation.
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&rot).unwrap()).unwrap();
    doc["chain_id"] = json!(99);
    let other = dir.path().join("other.json");
    std::fs::write(&other, doc.to_string()).unwrap();
    let before = sent(&calls).len();
    let wrong = node(&[
        "multisig",
        "rotate",
        "submit",
        "--proposal",
        other.to_str().unwrap(),
        "--signature",
        s0.out.trim(),
        "--signature",
        s1.out.trim(),
        "--rpc",
        &url,
        "--no-wait",
    ]);
    assert!(!wrong.ok);
    assert!(
        wrong
            .err
            .contains("was prepared for chain 99, this node serves chain 14"),
        "{}",
        wrong.err
    );
    assert_eq!(sent(&calls).len(), before);
}
