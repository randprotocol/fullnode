//! `rand perp …` against a loopback node: the offline helpers (keygen, genesis-root, image-hc),
//! the reads, and the signed submissions (order, cancel, withdraw, oracle), whose transactions
//! are captured off the wire and decoded. None of these proves anything. Chain 14 is one of the
//! chains cut before `binding_domain`, so no genesis hash is needed to sign.

mod common;

use common::*;
use randprotocol_core::ledger::perps::account_id;
use randprotocol_core::notes::word8_to_hex;
use randprotocol_core::{Action, Transaction};
use serde_json::{json, Value};

fn sent(node: &Fake) -> Vec<Transaction> {
    node.calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(m, _)| m == "rand_sendTransaction")
        .map(|(_, p)| Transaction::decode(&hex::decode(p[0].as_str().unwrap()).unwrap()).unwrap())
        .collect()
}

fn perps_state() -> Value {
    json!({
        "enabled": true, "collateral_asset": 0, "max_tier": 18, "max_window_blocks": 8,
        "engine_hc": "00".repeat(32), "proved_root": "11".repeat(32), "proved_height": 5,
    })
}

fn trading_node(account_nonce: Option<u64>) -> Fake {
    fake(Box::new(move |m, _| match m {
        "rand_chainId" => Ok(json!(14)),
        "rand_getPerps" => Ok(perps_state()),
        "rand_getHead" => Ok(json!({ "height": 40 })),
        "rand_getPerpAccount" => Ok(match account_nonce {
            Some(n) => json!({ "account": "00", "trading_key": "00", "nonce_high": n.to_string() }),
            None => Value::Null,
        }),
        "rand_sendTransaction" => Ok(json!("ab".repeat(32))),
        _ => Err((-32601, "method not found".into())),
    }))
}

#[test]
fn perp_keygen_writes_a_trading_key_once_and_prints_its_account() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let out = dir.path().join("trade.json");
    let r = rand(
        DEAD,
        &key,
        &["perp", "keygen", "--out", out.to_str().unwrap()],
    );
    assert!(r.ok, "{}", r.err);
    let kp = randprotocol_client::perps::load_dilithium_key(&out).unwrap();
    assert_eq!(
        r.out,
        format!(
            "wrote {}\naccount: {}\n",
            out.display(),
            word8_to_hex(&account_id(kp.public_key()))
        )
    );
    let again = rand(
        DEAD,
        &key,
        &["perp", "keygen", "--out", out.to_str().unwrap()],
    );
    assert!(!again.ok, "an existing trading key is never overwritten");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn perp_genesis_root_and_image_hc_agree_with_the_library() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.json");
    let words = dir.path().join("state.json");
    std::fs::write(&words, "[1,2,3,4]").unwrap();
    let r = rand(
        DEAD,
        &key,
        &["perp", "genesis-root", "--state", words.to_str().unwrap()],
    );
    assert!(r.ok, "{}", r.err);
    assert_eq!(
        r.out.trim(),
        word8_to_hex(&randprotocol_client::perps::genesis_root(&[1, 2, 3, 4]))
    );
    std::fs::write(&words, "[1,2,3,5]").unwrap();
    let r2 = rand(
        DEAD,
        &key,
        &["perp", "genesis-root", "--state", words.to_str().unwrap()],
    );
    assert_ne!(r.out, r2.out, "the root binds the words");
    std::fs::write(&words, "{\"not\":\"an array\"}").unwrap();
    let bad = rand(
        DEAD,
        &key,
        &["perp", "genesis-root", "--state", words.to_str().unwrap()],
    );
    assert!(
        !bad.ok && bad.err.contains("is not a JSON array of u32 words"),
        "{}",
        bad.err
    );

    let program = randprotocol_zkvm::guests::fib(5);
    let image = dir.path().join("engine.bin");
    std::fs::write(&image, randprotocol_zkvm::codec::program_to_bytes(&program)).unwrap();
    let hc = rand(
        DEAD,
        &key,
        &["perp", "image-hc", "--image", image.to_str().unwrap()],
    );
    assert!(hc.ok, "{}", hc.err);
    assert_eq!(
        hc.out.trim(),
        word8_to_hex(&randprotocol_client::perps::image_hc(&program))
    );
    std::fs::write(&image, b"xx").unwrap();
    let junk = rand(
        DEAD,
        &key,
        &["perp", "image-hc", "--image", image.to_str().unwrap()],
    );
    assert!(
        !junk.ok && junk.err.contains("is not a program image"),
        "{}",
        junk.err
    );
    let absent = rand(
        DEAD,
        &key,
        &[
            "perp",
            "image-hc",
            "--image",
            dir.path().join("nope").to_str().unwrap(),
        ],
    );
    assert!(
        !absent.ok && absent.err.contains("reading the engine image"),
        "{}",
        absent.err
    );
}

#[test]
fn perp_state_account_and_inputs_read_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.json");
    let trade = dir.path().join("t.json");
    assert!(
        rand(
            DEAD,
            &key,
            &["perp", "keygen", "--out", trade.to_str().unwrap()]
        )
        .ok
    );
    let id = word8_to_hex(&account_id(
        randprotocol_client::perps::load_dilithium_key(&trade)
            .unwrap()
            .public_key(),
    ));
    let known = id.clone();
    let node = fake(Box::new(move |m, p| match m {
        "rand_getPerps" => Ok(perps_state()),
        "rand_getPerpAccount" if p[0] == json!(known) => {
            Ok(json!({ "account": known, "nonce_high": 3 }))
        }
        "rand_getPerpAccount" => Ok(Value::Null),
        "rand_getPerpInputs" if p[0] == json!(9) => Ok(json!({ "words": [1, 2] })),
        "rand_getPerpInputs" => Ok(Value::Null),
        _ => Err((-32601, "method not found".into())),
    }));
    let state: Value =
        serde_json::from_str(&rand(&node.url, &key, &["perp", "state"]).out).unwrap();
    assert_eq!(state["max_tier"], 18);
    let by_id = rand(&node.url, &key, &["perp", "account", &id]);
    assert_eq!(
        serde_json::from_str::<Value>(&by_id.out).unwrap()["nonce_high"],
        3,
        "{}",
        by_id.err
    );
    let by_key = rand(
        &node.url,
        &key,
        &["perp", "account", "--trading-key", trade.to_str().unwrap()],
    );
    assert_eq!(by_key.out, by_id.out);
    let none = "07".repeat(32);
    assert_eq!(
        rand(&node.url, &key, &["perp", "account", &none])
            .out
            .trim(),
        format!("no account {none}")
    );
    let neither = rand(&node.url, &key, &["perp", "account"]);
    assert!(
        !neither.ok && neither.err.contains("name the account"),
        "{}",
        neither.err
    );
    assert_eq!(
        serde_json::from_str::<Value>(&rand(&node.url, &key, &["perp", "inputs", "9"]).out)
            .unwrap()["words"],
        json!([1, 2])
    );
    assert_eq!(
        rand(&node.url, &key, &["perp", "inputs", "10"]).out.trim(),
        "no perp inputs at height 10"
    );
}

#[test]
fn perp_state_on_a_chain_without_perps_is_named_by_the_actions() {
    let node = fake(Box::new(|m, _| match m {
        "rand_getPerps" => Ok(json!({ "enabled": false })),
        "rand_chainId" => Ok(json!(14)),
        "rand_getHead" => Ok(json!({ "height": 1 })),
        _ => Err((-32601, "method not found".into())),
    }));
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let trade = dir.path().join("t.json");
    assert!(
        rand(
            DEAD,
            &key,
            &["perp", "keygen", "--out", trade.to_str().unwrap()]
        )
        .ok
    );
    let r = rand(
        &node.url,
        &key,
        &[
            "perp",
            "withdraw",
            "--trading-key",
            trade.to_str().unwrap(),
            "--amount",
            "5",
        ],
    );
    assert!(
        !r.ok && r.err.contains("this chain has no perps section"),
        "{}",
        r.err
    );
}

#[test]
fn perp_order_signs_and_submits_with_the_next_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let trade = dir.path().join("t.json");
    assert!(
        rand(
            DEAD,
            &key,
            &["perp", "keygen", "--out", trade.to_str().unwrap()]
        )
        .ok
    );
    let kp = randprotocol_client::perps::load_dilithium_key(&trade).unwrap();
    let account = account_id(kp.public_key());

    let node = trading_node(Some(6));
    let t = trade.to_str().unwrap();
    let r = rand(
        &node.url,
        &key,
        &[
            "perp",
            "order",
            "--trading-key",
            t,
            "--market",
            "2",
            "--side",
            "sell",
            "--size",
            "10",
            "--price",
            "500",
            "--tif",
            "post",
            "--reduce-only",
            "--no-wait",
        ],
    );
    assert!(r.ok, "{}", r.err);
    assert_eq!(
        r.out,
        format!(
            "order {}\naccount {} nonce 7\n",
            "ab".repeat(32),
            word8_to_hex(&account)
        )
    );
    let txs = sent(&node);
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].chain_id, 14);
    assert!(txs[0].bundle.is_none(), "a perp order rides no bundle");
    match &txs[0].action {
        Action::PerpOrder {
            account: a,
            body,
            signature,
        } => {
            assert_eq!(*a, account);
            assert_eq!(
                (
                    body.nonce,
                    body.market,
                    body.side,
                    body.kind,
                    body.tif,
                    body.reduce_only,
                    body.price,
                    body.size
                ),
                (7, 2, 1, 0, 2, true, 500, 10)
            );
            assert!(
                *signature != randprotocol_core::Signature::empty(),
                "the order is signed"
            );
        }
        other => panic!("not an order: {other:?}"),
    }

    // A fresh account starts at nonce 1; an explicit --nonce is used as given and skips the lookup.
    let fresh = trading_node(None);
    let r = rand(
        &fresh.url,
        &key,
        &[
            "perp",
            "order",
            "--trading-key",
            t,
            "--market",
            "1",
            "--side",
            "buy",
            "--size",
            "1",
            "--kind",
            "market",
            "--no-wait",
        ],
    );
    assert!(r.ok && r.out.contains("nonce 1"), "{}{}", r.out, r.err);
    let r = rand(
        &fresh.url,
        &key,
        &[
            "perp",
            "order",
            "--trading-key",
            t,
            "--market",
            "1",
            "--side",
            "buy",
            "--size",
            "1",
            "--kind",
            "market",
            "--nonce",
            "99",
            "--no-wait",
        ],
    );
    assert!(r.ok && r.out.contains("nonce 99"), "{}", r.out);
    assert_eq!(
        fresh
            .methods()
            .iter()
            .filter(|m| *m == "rand_getPerpAccount")
            .count(),
        1,
        "--nonce skips the account lookup"
    );
}

#[test]
fn perp_order_refuses_malformed_arguments_before_any_submission() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let trade = dir.path().join("t.json");
    assert!(
        rand(
            DEAD,
            &key,
            &["perp", "keygen", "--out", trade.to_str().unwrap()]
        )
        .ok
    );
    let t = trade.to_str().unwrap();
    let node = trading_node(None);
    for (extra, want) in [
        (
            vec!["--side", "up", "--size", "1", "--price", "5"],
            "--side up: buy or sell",
        ),
        (
            vec![
                "--side", "buy", "--size", "1", "--price", "5", "--kind", "stop",
            ],
            "--kind stop: limit or market",
        ),
        (
            vec![
                "--side", "buy", "--size", "1", "--price", "5", "--tif", "fok",
            ],
            "--tif fok: gtc, ioc or post",
        ),
        (
            vec!["--side", "buy", "--size", "1"],
            "a limit order needs --price",
        ),
        (
            vec![
                "--side", "buy", "--size", "1", "--kind", "market", "--price", "5",
            ],
            "a market order takes no --price",
        ),
        (
            vec!["--side", "buy", "--size", "0", "--price", "5"],
            "--size 0 orders nothing",
        ),
    ] {
        let mut args = vec![
            "perp",
            "order",
            "--trading-key",
            t,
            "--market",
            "1",
            "--no-wait",
        ];
        args.extend(extra.iter());
        let r = rand(&node.url, &key, &args);
        assert!(!r.ok, "{extra:?}");
        assert!(r.err.contains(want), "{extra:?}: {}", r.err);
    }
    assert!(sent(&node).is_empty(), "nothing was submitted");
}

#[test]
fn perp_cancel_submits_a_cancel_of_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let trade = dir.path().join("t.json");
    assert!(
        rand(
            DEAD,
            &key,
            &["perp", "keygen", "--out", trade.to_str().unwrap()]
        )
        .ok
    );
    let node = trading_node(Some(2));
    let r = rand(
        &node.url,
        &key,
        &[
            "perp",
            "cancel",
            "--trading-key",
            trade.to_str().unwrap(),
            "--target",
            "2",
            "--no-wait",
        ],
    );
    assert!(r.ok, "{}", r.err);
    assert!(
        r.out.contains("cancel ") && r.out.trim_end().ends_with("nonce 3 target 2"),
        "{}",
        r.out
    );
    assert!(matches!(sent(&node)[0].action, Action::PerpCancel { .. }));
}

#[test]
fn perp_withdraw_prints_the_note_the_payout_will_be() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let addr = address_of(&key);
    let trade = dir.path().join("t.json");
    assert!(
        rand(
            DEAD,
            &key,
            &["perp", "keygen", "--out", trade.to_str().unwrap()]
        )
        .ok
    );
    let node = trading_node(Some(0));
    let r = rand(
        &node.url,
        &key,
        &[
            "perp",
            "withdraw",
            "--trading-key",
            trade.to_str().unwrap(),
            "--amount",
            "123",
            "--no-wait",
        ],
    );
    assert!(r.ok, "{}", r.err);
    assert!(
        r.out.contains(&format!("request {}", "ab".repeat(32))),
        "{}",
        r.out
    );
    assert!(
        r.out
            .contains(&format!("amount 123 units of asset 0 to {addr}")),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("time 40\nr "),
        "the note's time is the head height: {}",
        r.out
    );
    assert!(
        r.out
            .contains("paid as that note when a state proof covers the request"),
        "{}",
        r.out
    );
    match &sent(&node)[0].action {
        Action::PerpWithdraw { .. } => {}
        other => panic!("not a withdrawal: {other:?}"),
    }
}

#[test]
fn perp_oracle_signs_sorted_prices_and_refuses_bad_lists() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let node_key = dir.path().join("node.json");
    assert!(
        rand(
            DEAD,
            &key,
            &["perp", "keygen", "--out", node_key.to_str().unwrap()]
        )
        .ok
    );
    let nk = node_key.to_str().unwrap();
    let node = trading_node(None);
    let r = rand(
        &node.url,
        &key,
        &[
            "perp",
            "oracle",
            "--node-key",
            nk,
            "--price",
            "3=300, 1=100",
            "--no-wait",
        ],
    );
    assert!(r.ok, "{}", r.err);
    assert!(
        r.out
            .starts_with(&format!("oracle {} nonce ", "ab".repeat(32))),
        "{}",
        r.out
    );
    match &sent(&node)[0].action {
        Action::PerpOracle { prices, .. } => {
            assert_eq!(
                prices
                    .iter()
                    .map(|p| (p.market, p.price))
                    .collect::<Vec<_>>(),
                vec![(1, 100), (3, 300)]
            );
        }
        other => panic!("not an oracle submission: {other:?}"),
    }
    for (price, want) in [
        ("1", "expected <market>=<units>"),
        ("x=5", "market is not a number"),
        ("1=y", "price is not a number of units"),
        ("1=0", "a price of 0 reads as no price"),
        ("1=5,1=6", "a market is priced twice"),
        (",", "at least one <market>=<units>"),
    ] {
        let r = rand(
            &node.url,
            &key,
            &[
                "perp",
                "oracle",
                "--node-key",
                nk,
                "--price",
                price,
                "--no-wait",
            ],
        );
        assert!(!r.ok && r.err.contains(want), "{price}: {}", r.err);
    }
    assert_eq!(sent(&node).len(), 1, "only the good list was sent");
}

#[test]
fn a_refused_oracle_submission_is_an_error_without_every_and_logged_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let node_key = dir.path().join("node.json");
    assert!(
        rand(
            DEAD,
            &key,
            &["perp", "keygen", "--out", node_key.to_str().unwrap()]
        )
        .ok
    );
    let node = fake(Box::new(|m, _| match m {
        "rand_chainId" => Ok(json!(14)),
        "rand_sendTransaction" => Err((-32000, "oracle window closed".into())),
        _ => Err((-32601, "method not found".into())),
    }));
    let r = rand(
        &node.url,
        &key,
        &[
            "perp",
            "oracle",
            "--node-key",
            node_key.to_str().unwrap(),
            "--price",
            "1=5",
            "--no-wait",
        ],
    );
    assert!(!r.ok && r.err.contains("oracle window closed"), "{}", r.err);
}

#[test]
fn perp_prove_refuses_a_bad_fri_name_and_a_missing_job() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k.json");
    let job = dir.path().join("job.json");
    let image = dir.path().join("engine.bin");
    let r = rand(
        DEAD,
        &key,
        &[
            "perp",
            "prove",
            "--image",
            image.to_str().unwrap(),
            "--job",
            job.to_str().unwrap(),
        ],
    );
    assert!(!r.ok && r.err.contains("reading"), "{}", r.err);
    std::fs::write(&job, "{}").unwrap();
    let r = rand(
        DEAD,
        &key,
        &[
            "perp",
            "prove",
            "--image",
            image.to_str().unwrap(),
            "--job",
            job.to_str().unwrap(),
        ],
    );
    assert!(
        !r.ok && r.err.contains("is not a perp prove job"),
        "{}",
        r.err
    );
}
