//! `rand token …`, `rand bridge-pause` / `bridge-unpause`: the refusals that are decided before a
//! key is opened or a bundle proved — flag combinations, malformed hex, a governance file that
//! does not verify on this chain. Chain 14 is one of the chains cut before `binding_domain`, and
//! the guardian vectors are chain 99's, so a vector file here is a well-formed file for the wrong
//! chain: the CLI must say so rather than send it.

mod common;

use common::*;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../../randprotocol-core/tests/fixtures/pq-cosignatures.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn bridge_state(paused: bool, pause_nonce: u64, list_nonce: u64) -> Value {
    let file = vectors();
    let keys: Vec<Value> = file["pq_guardians"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["public_key"].clone())
        .collect();
    json!({
        "enabled": true,
        "emitters": { "2": "02", "3": "03", "4": "04", "5": "05" },
        "registration_fee": 1_000_000_000u64,
        "pq_guardians": keys,
        "pause_key": file["governance"]["pause"]["pause_key"],
        "mint_paused": paused,
        "pause_nonce": pause_nonce,
        "list_nonce": list_nonce,
    })
}

fn gov_node(paused: bool, pause_nonce: u64, list_nonce: u64) -> Fake {
    fake(Box::new(move |m, _| match m {
        "rand_chainId" => Ok(json!(14)),
        "rand_getBridgeState" => Ok(bridge_state(paused, pause_nonce, list_nonce)),
        _ => Err((-32601, "method not found".into())),
    }))
}

fn no_key() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("absent.key.json");
    (dir, key)
}

#[test]
fn bridge_pause_refuses_a_signature_that_is_not_hex_or_not_a_signature_without_a_key_file() {
    let (_d, key) = no_key();
    let node = gov_node(false, 0, 0);
    let r = rand(
        &node.url,
        &key,
        &["bridge-pause", "--sig", "zz", "--no-wait"],
    );
    assert!(
        !r.ok && r.err.contains("the pause signature is not hex"),
        "{}",
        r.err
    );
    let r = rand(
        &node.url,
        &key,
        &["bridge-pause", "--sig", "abcd", "--no-wait"],
    );
    assert!(!r.ok && r.err.contains("2 bytes"), "{}", r.err);
    assert!(!node.methods().contains(&"rand_sendTransaction".to_string()));
}

#[test]
fn bridge_pause_with_another_chains_signature_does_not_verify_and_is_not_sent() {
    let (dir, key) = no_key();
    let sig = vectors()["governance"]["pause"]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let node = gov_node(false, 0, 0);
    let r = rand(
        &node.url,
        &key,
        &["bridge-pause", "--sig", &sig, "--no-wait"],
    );
    assert!(!r.ok);
    assert!(
        r.err
            .contains("does not verify for chain 14 at pause_nonce 0"),
        "{}",
        r.err
    );
    // The same signature from a file, with trailing newline, reaches the same verdict.
    let file = dir.path().join("pause.sig");
    std::fs::write(&file, format!("{sig}\n")).unwrap();
    let r = rand(
        &node.url,
        &key,
        &[
            "bridge-pause",
            "--sig",
            &format!("@{}", file.display()),
            "--no-wait",
        ],
    );
    assert!(!r.ok && r.err.contains("does not verify"), "{}", r.err);
    let r = rand(
        &node.url,
        &key,
        &[
            "bridge-pause",
            "--sig",
            "@/definitely/not/here",
            "--no-wait",
        ],
    );
    assert!(
        !r.ok && r.err.contains("reading /definitely/not/here"),
        "{}",
        r.err
    );
    assert!(
        !node.methods().contains(&"rand_sendTransaction".to_string()),
        "nothing reached the wire"
    );
}

#[test]
fn bridge_pause_on_an_already_paused_bridge_says_so() {
    let (_d, key) = no_key();
    let sig = vectors()["governance"]["pause"]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let node = gov_node(true, 3, 0);
    let r = rand(
        &node.url,
        &key,
        &["bridge-pause", "--sig", &sig, "--no-wait"],
    );
    assert!(
        !r.ok && r.err.contains("already paused (pause_nonce 3)"),
        "{}",
        r.err
    );
}

#[test]
fn bridge_unpause_refuses_an_unpaused_bridge_and_a_short_or_malformed_quorum() {
    let (_d, key) = no_key();
    let pq = vectors()["governance"]["unpause"]["pq_signatures"].to_string();
    let unpaused = gov_node(false, 1, 0);
    let r = rand(
        &unpaused.url,
        &key,
        &["bridge-unpause", "--pq", &pq, "--no-wait"],
    );
    assert!(
        !r.ok && r.err.contains("not paused (pause_nonce 1)"),
        "{}",
        r.err
    );

    let paused = gov_node(true, 1, 0);
    let short: Vec<Value> = vectors()["governance"]["unpause"]["pq_signatures"]
        .as_array()
        .unwrap()[..4]
        .to_vec();
    let r = rand(
        &paused.url,
        &key,
        &[
            "bridge-unpause",
            "--pq",
            &json!(short).to_string(),
            "--no-wait",
        ],
    );
    assert!(
        !r.ok && r.err.contains("4 PQ co-signatures, need 5 of 6"),
        "{}",
        r.err
    );
    let r = rand(
        &paused.url,
        &key,
        &["bridge-unpause", "--pq", "not json", "--no-wait"],
    );
    assert!(!r.ok, "{}", r.err);
    // The full quorum is chain 99's: it names itself as not verifying on 14.
    let r = rand(
        &paused.url,
        &key,
        &["bridge-unpause", "--pq", &pq, "--no-wait"],
    );
    assert!(!r.ok, "{}", r.err);
    assert!(!paused
        .methods()
        .contains(&"rand_sendTransaction".to_string()));
}

#[test]
fn token_register_bridged_and_list_backing_refuse_before_any_proof() {
    let (_d, key) = no_key();
    let node = gov_node(false, 0, 0);
    let pq = vectors()["governance"]["register"]["pq_signatures"].to_string();
    let salt = "07".repeat(32);
    let tok = "09".repeat(32);
    let base = |chain: &'static str,
                decimals: &'static str,
                salt: String,
                tok: String,
                pq: String|
     -> Vec<String> {
        [
            "token",
            "register-bridged",
            "--name",
            "Tether",
            "--symbol",
            "zUSDT",
            "--salt",
            &salt,
            "--chain",
            chain,
            "--token",
            &tok,
            "--decimals",
            decimals,
            "--pq",
            &pq,
            "--no-wait",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    };
    let run = |args: Vec<String>| {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        rand(&node.url, &key, &a)
    };
    let r = run(base("2", "6", "short".into(), tok.clone(), pq.clone()));
    assert!(
        !r.ok && r.err.contains("--salt must be 32 bytes of hex"),
        "{}",
        r.err
    );
    let r = run(base("2", "6", salt.clone(), "zz".into(), pq.clone()));
    assert!(
        !r.ok && r.err.contains("--token must be 32 bytes of hex"),
        "{}",
        r.err
    );
    let r = run(base("7", "6", salt.clone(), tok.clone(), pq.clone()));
    assert!(
        !r.ok && r.err.contains("chain 7 has no registered emitter"),
        "{}",
        r.err
    );
    let r = run(base("2", "19", salt.clone(), tok.clone(), pq.clone()));
    assert!(!r.ok && r.err.contains("over 18"), "{}", r.err);
    let r = run(base("2", "6", salt.clone(), tok.clone(), pq.clone()));
    assert!(
        !r.ok,
        "a quorum for chain 99 is no quorum on chain 14: {}",
        r.err
    );

    let r = rand(
        &node.url,
        &key,
        &[
            "token",
            "list-backing",
            "--asset",
            "1",
            "--chain",
            "5",
            "--token",
            "xx",
            "--decimals",
            "6",
            "--pq",
            &pq,
            "--no-wait",
        ],
    );
    assert!(
        !r.ok && r.err.contains("--token must be 32 bytes of hex"),
        "{}",
        r.err
    );
    let r = rand(
        &node.url,
        &key,
        &[
            "token",
            "list-backing",
            "--asset",
            "1",
            "--chain",
            "5",
            "--token",
            &tok,
            "--decimals",
            "6",
            "--pq",
            &pq,
            "--no-wait",
        ],
    );
    assert!(!r.ok, "{}", r.err);
    assert!(!node.methods().contains(&"rand_sendTransaction".to_string()));
}

#[test]
fn token_create_refuses_every_bad_flag_combination_before_the_network() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let to = address_of(&key);
    let out = dir.path().join("auth.json");
    let out_s = out.to_str().unwrap();
    let pid = "ab".repeat(32);
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (
            vec![],
            "pass exactly one of --fixed-supply, --authority-key-out or --program",
        ),
        (
            vec!["--fixed-supply", "5", "--authority-key-out", out_s],
            "pass exactly one of --fixed-supply, --authority-key-out or --program",
        ),
        (
            vec!["--fixed-supply", "5", "--initial", "1", "--to", &to],
            "do not also pass --initial",
        ),
        (
            vec!["--fixed-supply", "0", "--to", &to],
            "a fixed supply of zero mints nothing",
        ),
        (vec!["--fixed-supply", "5"], "--fixed-supply needs --to"),
        (
            vec!["--authority-key-out", out_s, "--initial", "5"],
            "--initial and --to must be given together",
        ),
        (
            vec!["--authority-key-out", out_s, "--to", &to],
            "--initial and --to must be given together",
        ),
        (
            vec!["--authority-key-out", out_s, "--initial", "0", "--to", &to],
            "an initial mint of zero mints nothing",
        ),
        (
            vec!["--program", &pid, "--fixed-supply", "5", "--to", &to],
            "--program is the token's whole authority",
        ),
        (vec!["--program", "nothex"], "--program: invalid program id"),
        // Issue #142: display units at `--decimals` (2 here), like `token mint --amount`.
        (
            vec!["--authority-key-out", out_s, "--initial", "1.234", "--to", &to],
            "at most 2 decimals",
        ),
        (
            vec!["--fixed-supply", "1", "--fixed-supply-units", "100", "--to", &to],
            "cannot be used with",
        ),
    ];
    for (extra, want) in cases {
        let mut args = vec![
            "token",
            "create",
            "--name",
            "Coin",
            "--symbol",
            "COIN",
            "--decimals",
            "2",
            "--no-wait",
        ];
        args.extend(extra.iter());
        let r = rand(DEAD, &key, &args);
        assert!(!r.ok, "{extra:?}");
        assert!(r.err.contains(want), "{extra:?}: {}", r.err);
        assert!(
            !r.err.contains("connecting to"),
            "{extra:?} must be refused before any call: {}",
            r.err
        );
    }
    // An existing authority file, or a stale `.pending` beside it, is never overwritten.
    std::fs::write(&out, "x").unwrap();
    let r = rand(
        DEAD,
        &key,
        &[
            "token",
            "create",
            "--name",
            "Coin",
            "--symbol",
            "COIN",
            "--decimals",
            "2",
            "--authority-key-out",
            out_s,
        ],
    );
    assert!(
        !r.ok && r.err.contains("already exists; refusing to overwrite"),
        "{}",
        r.err
    );
    std::fs::remove_file(&out).unwrap();
    let pending = randprotocol_client::wallet::pending_authority_key_path(&out);
    std::fs::write(&pending, "x").unwrap();
    let r = rand(
        DEAD,
        &key,
        &[
            "token",
            "create",
            "--name",
            "Coin",
            "--symbol",
            "COIN",
            "--decimals",
            "2",
            "--authority-key-out",
            out_s,
        ],
    );
    assert!(
        !r.ok && r.err.contains("an earlier `token create` may have crashed"),
        "{}",
        r.err
    );
}

#[test]
fn token_set_authority_needs_exactly_one_of_new_key_and_renounce() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let auth = dir.path().join("a.json");
    let r = rand(
        DEAD,
        &key,
        &["perp", "keygen", "--out", auth.to_str().unwrap()],
    );
    assert!(r.ok);
    let a = auth.to_str().unwrap();
    let neither = rand(
        DEAD,
        &key,
        &[
            "token",
            "set-authority",
            "--asset",
            "1",
            "--authority-key",
            a,
        ],
    );
    assert!(
        !neither.ok
            && neither
                .err
                .contains("pass exactly one of --new-key or --renounce"),
        "{}",
        neither.err
    );
    let both = rand(
        DEAD,
        &key,
        &[
            "token",
            "set-authority",
            "--asset",
            "1",
            "--authority-key",
            a,
            "--new-key",
            a,
            "--renounce",
        ],
    );
    assert!(
        !both.ok
            && both
                .err
                .contains("pass exactly one of --new-key or --renounce"),
        "{}",
        both.err
    );
}

#[test]
fn token_info_and_mint_name_an_unknown_token() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let node = fake(Box::new(|m, _| match m {
        "rand_getTokens" => Ok(
            json!({ "tokens": [{ "index": 1, "id": "aa".repeat(32), "symbol": "COIN", "decimals": 2 }], "total": 1 }),
        ),
        _ => Err((-32601, "method not found".into())),
    }));
    let r = rand(&node.url, &key, &["token", "info", "9"]);
    assert!(
        !r.ok,
        "an unknown token index is an error: {}{}",
        r.out, r.err
    );
    let to = address_of(&key);
    let r = rand(
        &node.url,
        &key,
        &[
            "token",
            "mint",
            "--asset",
            "9",
            "--to",
            &to,
            "--amount",
            "1",
            "--authority-key",
            "/nonexistent",
        ],
    );
    assert!(!r.ok, "{}", r.err);
}

#[test]
fn bridge_burn_refuses_malformed_addresses_before_reading_the_bridge() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let good = "0a".repeat(32);
    let r = rand(
        DEAD,
        &key,
        &["bridge-burn", "1", "5", "2", &good, "zz", "--yes"],
    );
    assert!(
        !r.ok
            && r.err
                .contains("the destination address must be 32 bytes of hex"),
        "{}",
        r.err
    );
    let r = rand(
        DEAD,
        &key,
        &["bridge-burn", "1", "5", "2", "zz", &good, "--yes"],
    );
    assert!(
        !r.ok
            && r.err
                .contains("the source-chain token address must be 32 bytes of hex"),
        "{}",
        r.err
    );
}
