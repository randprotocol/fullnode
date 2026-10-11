//! The `rand` binary against a loopback JSON-RPC fake: the read-only subcommands, the offline
//! ones (contacts, program build, viewing key, QR output) and the argument refusals that are
//! decided before the first call. Everything here runs on a hosted CI runner: no proving, no
//! real node, no network beyond 127.0.0.1.

mod common;

use common::*;
use serde_json::{json, Value};

#[test]
fn keygen_refuses_to_overwrite_and_names_the_file_and_address() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("w.key.json");
    let first = rand(DEAD, &key, &["keygen"]);
    assert!(first.ok);
    assert!(
        first
            .out
            .starts_with(&format!("wrote {}\naddress: rand1", key.display())),
        "{}",
        first.out
    );
    let again = rand(DEAD, &key, &["keygen"]);
    assert!(!again.ok, "a second keygen must not overwrite the key");
    assert!(std::fs::read_to_string(&key).unwrap().len() > 10);
}

#[test]
fn a_missing_key_file_is_an_error_not_a_default_wallet() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("absent.json");
    for args in [&["address"][..], &["viewing-key"], &["notes"], &["history"]] {
        let r = rand(DEAD, &key, args);
        assert!(!r.ok, "{args:?} without a key file must fail");
    }
}

#[test]
fn address_uri_carries_amount_asset_and_memo_and_a_bad_amount_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let addr = address_of(&key);
    let r = rand(
        DEAD,
        &key,
        &["address", "--uri", "--amount", "1.5", "--memo", "rent"],
    );
    assert!(r.ok, "{}", r.err);
    let lines: Vec<&str> = r.out.lines().collect();
    assert_eq!(lines[0], addr);
    assert!(
        lines[1].starts_with("randpay:") && lines[1].contains(&addr),
        "{}",
        lines[1]
    );
    let parsed = randprotocol_core::payment_uri::PaymentUri::parse(lines[1]).unwrap();
    assert_eq!(parsed.amount.as_deref(), Some("1.5"));
    assert_eq!(parsed.memo.as_deref(), Some("rent"));
    assert_eq!(parsed.asset, None);

    let bad = rand(
        DEAD,
        &key,
        &["address", "--uri", "--amount", "not-a-number"],
    );
    assert!(!bad.ok, "a link nobody can pay is refused, not printed");
}

#[test]
fn address_qr_prints_a_terminal_code_and_the_png_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let png = dir.path().join("pay.png");
    let r = rand(
        DEAD,
        &key,
        &["address", "--qr", "--qr-png", png.to_str().unwrap()],
    );
    assert!(r.ok, "{}", r.err);
    assert!(
        r.out.lines().count() > 10,
        "a QR spans many terminal rows: {}",
        r.out
    );
    assert!(r.err.contains("wrote"), "{}", r.err);
    let bytes = std::fs::read(&png).unwrap();
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
}

#[test]
fn viewing_key_is_64_hex_on_stdout_and_stable_across_runs() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let a = rand(DEAD, &key, &["viewing-key"]);
    let b = rand(DEAD, &key, &["viewing-key"]);
    assert!(a.ok);
    let hex = a.out.trim();
    assert_eq!(hex.len(), 64, "{hex}");
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(a.out, b.out);
    assert!(a.err.contains("rand_importViewingKey"), "{}", a.err);
    // A different wallet has a different viewing key.
    let other = tempfile::tempdir().unwrap();
    let key2 = keygen(&other);
    assert_ne!(rand(DEAD, &key2, &["viewing-key"]).out, a.out);
}

#[test]
fn contacts_add_list_show_remove_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let other = tempfile::tempdir().unwrap();
    let addr = address_of(&keygen(&other));

    assert_eq!(
        rand(DEAD, &key, &["contacts", "list"]).out.trim(),
        "no contacts"
    );
    assert!(!rand(DEAD, &key, &["contacts", "show", "alice"]).ok);

    let add = rand(DEAD, &key, &["contacts", "add", "alice", &addr, "--yes"]);
    assert!(add.ok, "{}", add.err);
    assert!(
        add.out.contains("fingerprint ") && add.out.contains("saved alice"),
        "{}",
        add.out
    );

    let list = rand(DEAD, &key, &["contacts", "list"]);
    assert_eq!(list.out.trim(), format!("alice  {addr}"));

    let show = rand(DEAD, &key, &["contacts", "show", "alice"]);
    assert!(
        show.out.starts_with(&addr) && show.out.contains("fingerprint "),
        "{}",
        show.out
    );
    let qr = rand(DEAD, &key, &["contacts", "show", "alice", "--qr"]);
    assert!(qr.ok && qr.out.lines().count() > 10);

    // Adding by a randpay: link takes its address.
    let third = tempfile::tempdir().unwrap();
    let link = format!("randpay:{}", address_of(&keygen(&third)));
    let add2 = rand(DEAD, &key, &["contacts", "add", "bob", &link, "--yes"]);
    assert!(add2.ok, "{}{}", add2.out, add2.err);

    let rm = rand(DEAD, &key, &["contacts", "remove", "alice"]);
    assert!(rm.ok && rm.out.contains("removed alice"), "{}", rm.out);
    assert!(
        !rand(DEAD, &key, &["contacts", "remove", "alice"]).ok,
        "removing twice fails"
    );
    assert!(!rand(DEAD, &key, &["contacts", "show", "alice"]).ok);
}

#[test]
fn contacts_add_refuses_junk_and_asks_before_saving_on_a_non_tty() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let junk = rand(DEAD, &key, &["contacts", "add", "x", "garbage", "--yes"]);
    assert!(!junk.ok);
    assert!(
        junk.err
            .contains("neither a shielded address nor a randpay: link"),
        "{}",
        junk.err
    );
    let other = tempfile::tempdir().unwrap();
    let addr = address_of(&keygen(&other));
    let ask = rand(DEAD, &key, &["contacts", "add", "alice", &addr]);
    assert!(!ask.ok);
    assert!(
        ask.err.contains("pass --yes to add without confirmation"),
        "{}",
        ask.err
    );
    assert_eq!(
        rand(DEAD, &key, &["contacts", "list"]).out.trim(),
        "no contacts",
        "nothing saved without the answer"
    );
}

#[test]
fn prover_show_and_forget_with_nothing_paired() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    assert_eq!(
        rand(DEAD, &key, &["prover", "show"]).out.trim(),
        "no prover paired for this wallet"
    );
    assert_eq!(
        rand(DEAD, &key, &["prover", "forget"]).out.trim(),
        "no prover was paired for this wallet"
    );
    // --prover with nothing paired is refused before any RPC.
    let r = rand(
        DEAD,
        &key,
        &["--prover", "send", &address_of(&key), "1", "--yes"],
    );
    assert!(!r.ok);
    assert!(
        r.err.contains("no prover paired for this wallet"),
        "{}",
        r.err
    );
}

#[test]
fn prover_and_cuda_together_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let to = address_of(&key);
    let r = rand(
        DEAD,
        &key,
        &["--prover", "send", &to, "1", "--yes", "--cuda"],
    );
    assert!(!r.ok);
    assert!(r.err.contains("--prover and --cuda: the bundle is proved on the paired prover or on this machine's GPU, not both"), "{}", r.err);
}

#[test]
fn a_bad_max_prover_fee_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let to = address_of(&key);
    let r = rand(
        DEAD,
        &key,
        &["--max-prover-fee", "lots", "send", &to, "1", "--yes"],
    );
    assert!(!r.ok);
    assert!(r.err.contains("--max-prover-fee lots"), "{}", r.err);
}

#[test]
fn notes_history_and_asset_balance_on_an_empty_store_say_so_offline() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    assert_eq!(
        rand(DEAD, &key, &["notes"]).out.trim(),
        "no notes (run `rand sync`)"
    );
    assert_eq!(
        rand(DEAD, &key, &["history"]).out.trim(),
        "no notes sent from this wallet"
    );
}

#[test]
fn program_build_writes_a_json_program_and_prints_its_id_for_each_guest() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let mut ids = std::collections::BTreeSet::new();
    for (guest, args) in [
        ("fib", vec!["--arg", "10"]),
        ("memcpy", vec!["--arg", "4"]),
        (
            "bubble_sort",
            vec!["--arg", "3", "--arg", "1", "--arg", "2"],
        ),
        ("balance_check", vec!["--arg", "5"]),
        ("private_payment", vec!["--arg", "5"]),
        ("public_echo", vec![]),
        ("rpl2_counter", vec![]),
    ] {
        let out = dir.path().join(format!("{guest}.json"));
        let mut a = vec![
            "program",
            "build",
            "--guest",
            guest,
            "--out",
            out.to_str().unwrap(),
        ];
        a.extend(args);
        let r = rand(DEAD, &key, &a);
        assert!(r.ok, "{guest}: {}", r.err);
        assert!(
            r.out.starts_with(&format!("wrote {} (", out.display())),
            "{}",
            r.out
        );
        let id = r
            .out
            .rsplit("program id ")
            .next()
            .unwrap()
            .trim()
            .trim_end_matches(')')
            .to_string();
        assert_eq!(id.len(), 64, "{guest}: {id}");
        assert!(ids.insert(id), "{guest}: every guest has its own id");
        let p =
            randprotocol_zkvm::codec::program_from_json(&std::fs::read_to_string(&out).unwrap())
                .unwrap();
        assert!(!p.words.is_empty());
        assert!(
            r.out.contains(&format!("({} words", p.words.len())),
            "{}",
            r.out
        );
    }
    // Fewer arguments than the guest needs, and an unknown guest, are refused by name.
    let out = dir.path().join("x.json");
    let few = rand(
        DEAD,
        &key,
        &[
            "program",
            "build",
            "--guest",
            "fib",
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert!(
        !few.ok && few.err.contains("fib needs 1 --arg value(s)"),
        "{}",
        few.err
    );
    let unk = rand(
        DEAD,
        &key,
        &[
            "program",
            "build",
            "--guest",
            "nope",
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert!(
        !unk.ok && unk.err.contains("unknown guest nope"),
        "{}",
        unk.err
    );
    assert!(!out.exists());
}

#[test]
fn fee_refuses_flags_that_belong_to_another_kind_before_any_call() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    for (args, want) in [
        (
            vec!["fee", "bundle", "--gas", "1"],
            "--gas is for `fee call`",
        ),
        (
            vec!["fee", "call", "18", "--public-words", "2"],
            "--public-words is for `fee deploy`",
        ),
        (
            vec!["fee", "deploy", "10", "--bytes", "2"],
            "--bytes is for `fee call`",
        ),
        (
            vec!["fee", "bundle", "--keccak-log-height", "3"],
            "--keccak-log-height is for `fee call`",
        ),
        (
            vec!["fee", "bundle", "--sha256-log-height", "3"],
            "--sha256-log-height is for `fee call`",
        ),
        (vec!["fee", "deploy"], "`fee deploy` needs a word count"),
        (vec!["fee", "call"], "`fee call` needs a tier"),
        (vec!["fee", "stake"], "unknown fee kind stake"),
    ] {
        let r = rand(DEAD, &key, &args);
        assert!(!r.ok, "{args:?}");
        assert!(r.err.contains(want), "{args:?}: {}", r.err);
    }
}

fn node_reading() -> Fake {
    fake(Box::new(move |m, _| match m {
        "rand_getHead" => Ok(json!({ "height": 7, "hash": "ab" })),
        "rand_status" => Ok(json!({ "fri_profile": "test", "peers": 2 })),
        "rand_getPeers" => Ok(json!(["peer-a", "peer-b"])),
        "rand_getValidators" => Ok(json!([{ "stake": "100" }])),
        _ => Err((-32601, "method not found".into())),
    }))
}

#[test]
fn head_status_peers_validators_print_the_reply_as_pretty_json() {
    let node = node_reading();
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("none.json");
    let head = rand(&node.url, &key, &["head"]);
    assert!(head.ok, "{}", head.err);
    assert_eq!(
        serde_json::from_str::<Value>(&head.out).unwrap(),
        json!({ "height": 7, "hash": "ab" })
    );
    assert!(
        head.out.contains("\n  \"height\": 7"),
        "pretty-printed: {}",
        head.out
    );
    assert_eq!(
        serde_json::from_str::<Value>(&rand(&node.url, &key, &["status"]).out).unwrap()["peers"],
        2
    );
    assert_eq!(
        serde_json::from_str::<Value>(&rand(&node.url, &key, &["peers"]).out).unwrap(),
        json!(["peer-a", "peer-b"])
    );
    assert_eq!(
        serde_json::from_str::<Value>(&rand(&node.url, &key, &["validators"]).out).unwrap()[0]
            ["stake"],
        "100"
    );
}

#[test]
fn an_rpc_error_exits_nonzero_and_says_what_the_node_said() {
    let node = fake(Box::new(|_, _| Err((-32000, "node is on fire".into()))));
    let dir = tempfile::tempdir().unwrap();
    let r = rand(&node.url, &dir.path().join("k.json"), &["head"]);
    assert!(!r.ok);
    assert!(r.err.contains("node is on fire"), "{}", r.err);
    let down = rand(DEAD, &dir.path().join("k.json"), &["head"]);
    assert!(
        !down.ok && down.err.contains("connecting to http://127.0.0.1:9"),
        "{}",
        down.err
    );
}

#[test]
fn tx_block_and_receipt_look_up_by_hash_and_say_when_unknown() {
    let h = "11".repeat(32);
    let node = fake(Box::new(|m, p| match m {
        "rand_getTransaction" if p[0] == json!("11".repeat(32)) => {
            Ok(json!({ "height": 3, "index": 0 }))
        }
        "rand_getTransaction" => Ok(Value::Null),
        "rand_getBlockByHeight" => Ok(json!({ "height": p[0] })),
        "rand_getBlockByHash" => Ok(json!({ "hash": p[0] })),
        "rand_getReceipt" if p[0] == json!("11".repeat(32)) => Ok(json!({ "ok": true })),
        "rand_getReceipt" => Ok(Value::Null),
        _ => Err((-32601, "method not found".into())),
    }));
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.json");
    let tx = rand(&node.url, &key, &["tx", &h]);
    assert_eq!(
        serde_json::from_str::<Value>(&tx.out).unwrap()["height"],
        3,
        "{}{}",
        tx.out,
        tx.err
    );
    assert!(rand(&node.url, &key, &["tx", &"22".repeat(32)])
        .out
        .contains("not found"));
    assert!(!rand(&node.url, &key, &["tx", "zz"]).ok);

    let by_height = rand(&node.url, &key, &["block", "5"]);
    assert_eq!(
        serde_json::from_str::<Value>(&by_height.out).unwrap()["height"],
        5
    );
    let by_hash = rand(&node.url, &key, &["block", &h]);
    assert_eq!(
        serde_json::from_str::<Value>(&by_hash.out).unwrap()["hash"],
        json!(h)
    );
    let bad = rand(&node.url, &key, &["block", "not-a-hash"]);
    assert!(
        !bad.ok && bad.err.contains("block id must be a height or a hash"),
        "{}",
        bad.err
    );

    assert!(rand(&node.url, &key, &["receipt", &h])
        .out
        .contains("\"ok\": true"));
    assert!(rand(&node.url, &key, &["receipt", &"33".repeat(32)])
        .out
        .contains("no receipt"));
    assert!(!rand(&node.url, &key, &["receipt", "xyz"]).ok);
}

#[test]
fn bridge_state_and_message_by_sequence() {
    let node = fake(Box::new(|m, p| match m {
        "rand_getBridgeState" => Ok(json!({ "mint_paused": false, "pause_nonce": 0 })),
        "rand_getBridgeBurn" if p[0] == json!(4) => Ok(json!({ "sequence": 4, "payload": "00" })),
        "rand_getBridgeBurn" => Ok(Value::Null),
        _ => Err((-32601, "method not found".into())),
    }));
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.json");
    assert_eq!(
        serde_json::from_str::<Value>(&rand(&node.url, &key, &["bridge"]).out).unwrap()
            ["pause_nonce"],
        0
    );
    assert_eq!(
        serde_json::from_str::<Value>(&rand(&node.url, &key, &["bridge-message", "4"]).out)
            .unwrap()["sequence"],
        4
    );
    assert_eq!(
        rand(&node.url, &key, &["bridge-message", "9"]).out.trim(),
        "no burn with sequence 9"
    );
}

#[test]
fn fee_sends_only_the_fields_given_and_prints_the_amount_in_rand() {
    let node = fake(Box::new(|m, _| match m {
        "rand_estimateFee" => Ok(json!("1500000000")),
        "rand_getLimits" => Err((-32601, "method not found".into())),
        _ => Err((-32601, "method not found".into())),
    }));
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.json");
    let r = rand(&node.url, &key, &["fee", "bundle"]);
    assert_eq!(r.out.trim(), "1.5 RAND", "{}", r.err);
    assert_eq!(
        node.params_of("rand_estimateFee").unwrap(),
        json!([{ "kind": "bundle" }])
    );

    let node = fake(Box::new(|m, _| match m {
        "rand_estimateFee" => Ok(json!("2000000000")),
        _ => Err((-32601, "method not found".into())),
    }));
    let r = rand(
        &node.url,
        &key,
        &["fee", "deploy", "40", "--public-words", "3"],
    );
    assert_eq!(r.out.trim(), "2 RAND", "{}", r.err);
    assert_eq!(
        node.params_of("rand_estimateFee").unwrap(),
        json!([{ "kind": "deploy", "words": 40, "public_words": 3 }])
    );
    let r = rand(&node.url, &key, &["fee", "deploy", "40"]);
    assert!(r.ok);
    let r = rand(
        &node.url,
        &key,
        &[
            "fee",
            "call",
            "18",
            "--bytes",
            "99",
            "--keccak-log-height",
            "4",
            "--sha256-log-height",
            "5",
            "--gas",
            "777",
        ],
    );
    assert!(r.ok, "{}", r.err);
    let sent = node
        .calls
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(m, _)| m == "rand_estimateFee")
        .unwrap()
        .1
        .clone();
    assert_eq!(
        sent,
        json!([{ "kind": "call", "tier": 18, "bytes": 99, "keccak_log_height": 4, "sha256_log_height": 5, "gas": 777 }])
    );
}

#[test]
fn faucet_mints_to_the_wallet_address_and_waits_for_the_commit() {
    let node = fake(Box::new(|m, _| match m {
        "rand_mint" => Ok(json!("aa".repeat(32))),
        "rand_getTransactionStatus" => Ok(json!([{ "status": "committed" }])),
        "rand_getTransaction" => {
            Ok(json!({ "height": 12, "index": 1, "block_hash": "bb".repeat(32) }))
        }
        _ => Err((-32601, "method not found".into())),
    }));
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let addr = address_of(&key);
    let r = rand(&node.url, &key, &["faucet", "--amount", "2.5"]);
    assert!(r.ok, "{}", r.err);
    assert!(
        r.out.contains(&format!(
            "submitted mint {} (2.5 RAND to {addr})",
            "aa".repeat(32)
        )),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("committed in block 12 (index 1)"),
        "{}",
        r.out
    );
    assert_eq!(
        node.params_of("rand_mint").unwrap(),
        json!([addr, "2500000000"])
    );

    // An explicit address wins over the wallet's.
    let other = tempfile::tempdir().unwrap();
    let to = address_of(&keygen(&other));
    let r = rand(&node.url, &key, &["faucet", &to, "--amount", "1"]);
    assert!(r.ok, "{}", r.err);
    assert!(r.out.contains(&format!("to {to})")), "{}", r.out);
    let bad = rand(
        &node.url,
        &key,
        &["faucet", "not-an-address", "--amount", "1"],
    );
    assert!(
        !bad.ok && bad.err.contains("invalid shielded address"),
        "{}",
        bad.err
    );
}

#[test]
fn a_rejected_faucet_mint_reports_the_admission_reason() {
    let node = fake(Box::new(|m, _| match m {
        "rand_mint" => Ok(json!("aa".repeat(32))),
        "rand_getTransactionStatus" => {
            Ok(json!([{ "status": "rejected", "reason": "recipient not on allow-list" }]))
        }
        _ => Err((-32601, "method not found".into())),
    }));
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let r = rand(&node.url, &key, &["faucet", "--amount", "1"]);
    assert!(!r.ok);
    assert!(
        r.err.contains("rejected: recipient not on allow-list"),
        "{}",
        r.err
    );
}

#[test]
fn program_show_state_and_vault_read_the_chain() {
    let id = "5a".repeat(32);
    let (k1, v1, k2, v2) = (
        "01".repeat(32),
        "02".repeat(32),
        "03".repeat(32),
        "04".repeat(32),
    );
    let (k1c, v1c, k2c, v2c) = (k1.clone(), v1.clone(), k2.clone(), v2.clone());
    let node = fake(Box::new(move |m, p| match m {
        "rand_getProgram" if p[0] == json!("5a".repeat(32)) => Ok(json!({ "words": 4 })),
        "rand_getProgram" => Ok(Value::Null),
        "rand_getProgramCell" => Ok(json!({ "enabled": true, "value": v1c })),
        "rand_getProgramCells" => {
            if p[1]["after"].is_null() {
                Ok(json!({ "cells": [{ "key": k1c, "value": v1c }], "next": k1c }))
            } else {
                Ok(json!({ "cells": [{ "key": k2c, "value": v2c }], "next": Value::Null }))
            }
        }
        "rand_getProgramVault" => {
            Ok(json!([{ "asset": 0, "amount": "5" }, { "asset": 3, "amount": 9 }]))
        }
        _ => Err((-32601, "method not found".into())),
    }));
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.json");
    assert_eq!(
        serde_json::from_str::<Value>(&rand(&node.url, &key, &["program", "show", &id]).out)
            .unwrap()["words"],
        4
    );
    assert!(
        rand(&node.url, &key, &["program", "show", &"00".repeat(32)])
            .out
            .contains("unknown program")
    );

    let cell = rand(&node.url, &key, &["program", "state", &id, "--cell", &k1]);
    let cell: Value = serde_json::from_str(&cell.out).unwrap();
    assert_eq!(
        (
            cell["key"].as_str().unwrap(),
            cell["value"].as_str().unwrap()
        ),
        (k1.as_str(), v1.as_str())
    );
    let bad = rand(&node.url, &key, &["program", "state", &id, "--cell", "12"]);
    assert!(
        !bad.ok && bad.err.contains("is not 64 hex characters"),
        "{}",
        bad.err
    );

    let all: Value =
        serde_json::from_str(&rand(&node.url, &key, &["program", "state", &id]).out).unwrap();
    assert_eq!(all["program"], json!(id));
    let cells = all["cells"].as_array().unwrap();
    assert_eq!(cells.len(), 2, "both pages are followed");
    assert_eq!(cells[1]["key"], json!(k2));
    assert_eq!(cells[1]["value"], json!(v2));

    let vault: Value =
        serde_json::from_str(&rand(&node.url, &key, &["program", "vault", &id]).out).unwrap();
    assert_eq!(
        vault["vault"],
        json!([{ "asset": 0, "amount": "5" }, { "asset": 3, "amount": "9" }])
    );
}

#[test]
fn program_state_on_a_chain_without_the_section_says_so() {
    let node = fake(Box::new(|_, _| Ok(json!({ "enabled": false }))));
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.json");
    let id = "5a".repeat(32);
    for args in [vec!["program", "state", &id], vec!["program", "vault", &id]] {
        let r = rand(&node.url, &key, &args);
        assert!(
            !r.ok && r.err.contains("this chain has no program_state section"),
            "{args:?}: {}",
            r.err
        );
    }
}

#[test]
fn token_list_forwards_its_paging_arguments() {
    let node = fake(Box::new(|m, _| match m {
        "rand_getTokens" => Ok(json!({ "tokens": [] })),
        _ => Err((-32601, "method not found".into())),
    }));
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.json");
    let r = rand(
        &node.url,
        &key,
        &["token", "list", "--from", "3", "--limit", "10"],
    );
    assert!(r.ok, "{}", r.err);
    assert_eq!(node.params_of("rand_getTokens").unwrap(), json!([3, 10]));
    assert_eq!(
        serde_json::from_str::<Value>(&r.out).unwrap(),
        json!({ "tokens": [] })
    );
}

#[test]
fn tx_key_for_an_uncommitted_transaction_names_it() {
    let node = fake(Box::new(|_, _| Ok(Value::Null)));
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let h = "ab".repeat(32);
    let r = rand(&node.url, &key, &["tx-key", &h]);
    assert!(!r.ok);
    assert!(
        r.err
            .contains(&format!("{h} is not a committed transaction on this node")),
        "{}",
        r.err
    );
    assert!(!rand(&node.url, &key, &["tx-key", "nothex"]).ok);
}

/// A node with an empty chain: what a first `rand sync` of a new wallet sees.
fn empty_chain() -> Fake {
    fake(Box::new(|m, p| match m {
        "rand_getGenesisHash" => Ok(json!("cd".repeat(32))),
        "rand_getHead" => Ok(json!({ "height": 0 })),
        "rand_getBridgeState" => Ok(json!({})),
        "rand_getBlocks" => Ok(json!((p[0].as_u64().unwrap()..=p[1].as_u64().unwrap())
            .map(|h| json!({ "height": h, "tx_count": 0 }))
            .collect::<Vec<_>>())),
        "rand_getCommitments" | "rand_getNullifiers" => Ok(json!([])),
        "rand_getAssets" => Ok(json!([])),
        _ => Err((-32601, "method not found".into())),
    }))
}

#[test]
fn balance_sync_and_asset_balance_on_an_empty_chain() {
    let node = empty_chain();
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let bal = rand(&node.url, &key, &["balance"]);
    assert!(bal.ok, "{}", bal.err);
    assert_eq!(bal.out, "balance: 0 RAND\nnotes: 0 unspent\n");
    assert!(node.methods().contains(&"rand_getGenesisHash".to_string()));
    assert!(
        dir.path().join("w.key.json.notes.json").exists(),
        "the store is saved after a scan"
    );

    let sync = rand(&node.url, &key, &["sync"]);
    assert!(sync.ok, "{}", sync.err);
    assert!(
        sync.out.starts_with("scanned 0 leaves and "),
        "{}",
        sync.out
    );
    assert!(
        sync.out.trim_end().ends_with("0 notes, 0 unspent"),
        "{}",
        sync.out
    );

    let rescan = rand(&node.url, &key, &["sync", "--rescan"]);
    assert!(
        rescan.ok && rescan.err.contains("rescanning from leaf 0"),
        "{}",
        rescan.err
    );

    let all = rand(&node.url, &key, &["asset-balance"]);
    assert_eq!(all.out.trim(), "no notes (run `rand sync`)", "{}", all.err);
    let one = rand(&node.url, &key, &["asset-balance", "0"]);
    assert_eq!(
        one.out.trim(),
        "asset 0: 0 units (RAND), 0 notes unspent",
        "{}",
        one.err
    );
    let missing = rand(&node.url, &key, &["asset-balance", "7"]);
    assert!(
        missing
            .out
            .contains("asset 7: 0 units (not in this chain's registry)"),
        "{}",
        missing.out
    );
}

#[test]
fn a_store_scanned_against_another_chain_is_rescanned_with_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let a = empty_chain();
    assert!(rand(&a.url, &key, &["sync"]).ok);
    let b = fake(Box::new(|m, p| match m {
        "rand_getGenesisHash" => Ok(json!("ee".repeat(32))),
        "rand_getHead" => Ok(json!({ "height": 0 })),
        "rand_getBridgeState" => Ok(json!({})),
        "rand_getBlocks" => Ok(json!((p[0].as_u64().unwrap()..=p[1].as_u64().unwrap())
            .map(|h| json!({ "height": h, "tx_count": 0 }))
            .collect::<Vec<_>>())),
        _ => Ok(json!([])),
    }));
    let r = rand(&b.url, &key, &["sync"]);
    assert!(r.ok, "{}", r.err);
    assert!(
        r.err.contains("the note store was scanned against chain"),
        "{}",
        r.err
    );
}

#[test]
fn send_refuses_an_unknown_recipient_and_a_missing_amount_before_proving() {
    let node = empty_chain();
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let r = rand(&node.url, &key, &["send", "nobody", "1", "--yes"]);
    assert!(!r.ok);
    assert!(
        r.err
            .contains("nobody is not a shielded address, a randpay: link, or a saved contact"),
        "{}",
        r.err
    );
    let to = address_of(&key);
    let r = rand(&node.url, &key, &["send", &to, "--yes"]);
    assert!(
        !r.ok
            && r.err
                .contains("no amount: give one or use a link that carries it"),
        "{}",
        r.err
    );
    // A link's amount and a conflicting flag disagree loudly.
    let link = format!("randpay:{to}?amount=2");
    let r = rand(&node.url, &key, &["send", &link, "3", "--yes"]);
    assert!(!r.ok, "{}", r.err);
    assert!(
        r.err.contains("does not match the link's amount"),
        "{}",
        r.err
    );
}
