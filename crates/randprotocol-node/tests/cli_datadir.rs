//! The offline operator commands on a data directory, as the built `rand-node` binary runs them:
//! `genesis` → `init` → `verify` → `safety status|clear-halt|release-lock` → `db drop-*`, plus
//! `alloc-note` and the test-profile refusal. A chain that has produced no block (initialised
//! only), so nothing proves. Needs the test FRI profile, allowed by the harness variable.

use serde_json::Value;
use std::path::Path;
use std::process::Command;

struct Out {
    ok: bool,
    out: String,
    err: String,
}

fn node_env(args: &[&str], allow_test: bool) -> Out {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rand-node"));
    c.args(args);
    if allow_test {
        c.env("RAND_ALLOW_TEST_FRI_PROFILE", "1");
    } else {
        c.env_remove("RAND_ALLOW_TEST_FRI_PROFILE");
    }
    let o = c.output().expect("rand-node runs");
    Out {
        ok: o.status.success(),
        out: String::from_utf8_lossy(&o.stdout).into(),
        err: String::from_utf8_lossy(&o.stderr).into(),
    }
}

fn node(args: &[&str]) -> Out {
    node_env(args, true)
}

fn validator_arg() -> String {
    let pk = randprotocol_core::Keypair::from_seed([1; 32])
        .unwrap()
        .public_key()
        .to_hex();
    let payout = randprotocol_zkvm::address::address_of(
        &randprotocol_zkvm::notes::SpendKey([7; 8]).viewing_key(),
    )
    .to_string();
    let stake = randprotocol_core::ledger::staking::MIN_STAKE / randprotocol_core::UNITS_PER_RAND;
    format!("{pk},{stake},{payout}")
}

fn make_genesis(dir: &Path) -> std::path::PathBuf {
    let out = dir.join("genesis.json");
    let r = node(&[
        "genesis",
        "--chain-id",
        "14",
        "--fri-profile",
        "test",
        "--validator",
        &validator_arg(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(r.ok, "{}", r.err);
    out
}

fn init(dir: &Path) -> std::path::PathBuf {
    let genesis = make_genesis(dir);
    let data = dir.join("data");
    let r = node(&[
        "init",
        "--datadir",
        data.to_str().unwrap(),
        "--genesis",
        genesis.to_str().unwrap(),
    ]);
    assert!(r.ok, "{}", r.err);
    data
}

#[test]
fn init_writes_the_genesis_beside_the_database_and_names_the_chain() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = make_genesis(dir.path());
    let data = dir.path().join("fresh").join("data");
    let r = node(&[
        "init",
        "--datadir",
        data.to_str().unwrap(),
        "--genesis",
        genesis.to_str().unwrap(),
    ]);
    assert!(r.ok, "{}", r.err);
    assert!(
        r.out
            .starts_with(&format!("initialised {} at genesis ", data.display()))
            && r.out.contains("(chain id 14)"),
        "{}",
        r.out
    );
    assert!(r.out.contains("gas: none"), "{}", r.out);
    assert_eq!(
        std::fs::read(data.join("genesis.json")).unwrap(),
        std::fs::read(&genesis).unwrap(),
        "the genesis is kept verbatim"
    );
    assert!(data.join("db").exists());
}

#[test]
fn a_test_profile_genesis_is_refused_by_init_and_verify_without_the_allowance() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = make_genesis(dir.path());
    let data = dir.path().join("data");
    let r = node_env(
        &[
            "init",
            "--datadir",
            data.to_str().unwrap(),
            "--genesis",
            genesis.to_str().unwrap(),
        ],
        false,
    );
    assert!(
        !r.ok
            && r.err.contains("fri_profile \"test\"")
            && r.err.contains("--allow-test-fri-profile"),
        "{}",
        r.err
    );
    // The flag is the same allowance as the variable.
    let flagged = node_env(
        &[
            "--allow-test-fri-profile",
            "init",
            "--datadir",
            data.to_str().unwrap(),
            "--genesis",
            genesis.to_str().unwrap(),
        ],
        false,
    );
    assert!(flagged.ok, "{}", flagged.err);
    let v = node_env(&["verify", "--datadir", data.to_str().unwrap()], false);
    assert!(!v.ok && v.err.contains("fri_profile \"test\""), "{}", v.err);
}

#[test]
fn init_refuses_a_missing_or_malformed_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let missing = node(&[
        "init",
        "--datadir",
        data.to_str().unwrap(),
        "--genesis",
        dir.path().join("nope.json").to_str().unwrap(),
    ]);
    assert!(!missing.ok);
    let junk = dir.path().join("junk.json");
    std::fs::write(&junk, "{ not json").unwrap();
    let r = node(&[
        "init",
        "--datadir",
        data.to_str().unwrap(),
        "--genesis",
        junk.to_str().unwrap(),
    ]);
    assert!(!r.ok);
}

#[test]
fn verify_an_initialised_directory_in_every_mode() {
    let dir = tempfile::tempdir().unwrap();
    let data = init(dir.path());
    let d = data.to_str().unwrap();
    for mode in ["off", "quick", "full"] {
        let r = node(&["verify", "--datadir", d, "--mode", mode]);
        assert!(r.ok, "{mode}: {}{}", r.out, r.err);
        assert!(
            r.out.starts_with("ok: 1 blocks verified"),
            "{mode}: {}",
            r.out
        );
        assert!(r.out.to_lowercase().contains(mode), "{mode}: {}", r.out);
    }
    let bad = node(&["verify", "--datadir", d, "--mode", "paranoid"]);
    assert!(
        !bad.ok
            && bad
                .err
                .contains("unknown verify mode paranoid (off|quick|replay|full)"),
        "{}",
        bad.err
    );
    let empty = tempfile::tempdir().unwrap();
    assert!(
        !node(&["verify", "--datadir", empty.path().to_str().unwrap()]).ok,
        "a directory with no genesis is not a node"
    );
}

#[test]
fn safety_commands_on_a_node_that_has_never_voted() {
    let dir = tempfile::tempdir().unwrap();
    let data = init(dir.path());
    let d = data.to_str().unwrap();
    let st = node(&["safety", "status", "--datadir", d]);
    assert!(st.ok, "{}", st.err);
    assert!(st.out.contains("committed head: height 0"), "{}", st.out);
    assert!(
        st.out
            .contains("safety state: none recorded (this node has not voted)"),
        "{}",
        st.out
    );
    assert!(
        st.out
            .contains("certified blocks persisted above the head: 0")
            && st.out.contains("safety halt: none"),
        "{}",
        st.out
    );

    let clear = node(&["safety", "clear-halt", "--datadir", d]);
    assert!(
        clear.ok
            && clear
                .out
                .contains(&format!("no safety halt is recorded in {d}")),
        "{}",
        clear.out
    );
    let clear = node(&[
        "safety",
        "clear-halt",
        "--datadir",
        d,
        "--i-have-compared-this-node-with-the-fleet",
    ]);
    assert!(
        clear.ok && clear.out.contains("no safety halt is recorded"),
        "{}",
        clear.out
    );
    let release = node(&["safety", "release-lock", "--datadir", d]);
    assert!(
        release.ok && release.out.contains("nothing to release"),
        "{}",
        release.out
    );
}

#[test]
fn db_drop_commands_report_what_was_and_was_not_there() {
    let dir = tempfile::tempdir().unwrap();
    let data = init(dir.path());
    let d = data.to_str().unwrap();
    let r = node(&["db", "drop-receipts-index", "--datadir", d]);
    assert!(r.ok, "{}", r.err);
    assert!(r.out.contains("receipts_by_program"), "{}", r.out);
    assert!(
        r.out.contains("a pre-v0.3 build can open this database"),
        "{}",
        r.out
    );
    let again = node(&["db", "drop-receipts-index", "--datadir", d]);
    assert!(
        again.ok
            && again
                .out
                .contains("no receipts_by_program column family in"),
        "dropping twice reports the family gone: {}",
        again.out
    );
    assert!(
        again.out.contains("no meta key receipts_by_program_built"),
        "{}",
        again.out
    );

    let p = node(&["db", "drop-perp-inputs", "--datadir", d]);
    assert!(p.ok, "{}", p.err);
    assert!(p.out.contains("perp_inputs"), "{}", p.out);
    assert!(
        p.out
            .contains("a build from before RPL-3 can open this database"),
        "{}",
        p.out
    );
    // The directory still verifies after the drops.
    assert!(node(&["verify", "--datadir", d]).ok);
}

#[test]
fn alloc_note_prints_a_genesis_note_for_an_address_and_refuses_bad_amounts() {
    let to = randprotocol_zkvm::address::address_of(
        &randprotocol_zkvm::notes::SpendKey([9; 8]).viewing_key(),
    )
    .to_string();
    let r = node(&["alloc-note", "--to", &to, "--amount", "10"]);
    assert!(r.ok, "{}", r.err);
    let v: Value = serde_json::from_str(&r.out).unwrap();
    assert!(v.is_object(), "{}", r.out);
    let same = node(&["alloc-note", "--to", &to, "--amount", "10"]);
    assert_ne!(same.out, r.out, "each note is sealed with fresh randomness");
    let other = node(&[
        "alloc-note",
        "--to",
        &to,
        "--amount",
        "10",
        "--envelope-bytes",
        "1860",
    ]);
    assert!(other.ok, "{}{}", other.out, other.err);
    assert!(!node(&["alloc-note", "--to", "rand1nope", "--amount", "10"]).ok);
    assert!(!node(&["alloc-note", "--to", &to, "--amount", "ten"]).ok);
}

#[test]
fn bench_apply_reports_a_verdict_and_exits_nonzero_when_over_budget() {
    let ok = node(&[
        "bench",
        "apply",
        "--bundles",
        "20",
        "--blocks",
        "4",
        "--report-every",
        "2",
        "--fail-over-ms",
        "60000",
    ]);
    assert!(ok.ok, "{}", ok.err);
    assert!(
        ok.out.contains("propose_ms") && ok.out.contains("apply_ms"),
        "{}",
        ok.out
    );
    assert!(
        ok.out.contains("verdict: apply ")
            && ok
                .out
                .contains("at block 4 (320 nullifiers) — within the 60000 ms budget"),
        "{}",
        ok.out
    );
    let rows = ok
        .out
        .lines()
        .filter(|l| l.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .count();
    assert_eq!(rows, 2, "a row every 2 blocks over 4: {}", ok.out);

    let incremental = node(&[
        "bench",
        "apply",
        "--bundles",
        "20",
        "--blocks",
        "4",
        "--report-every",
        "2",
        "--incremental-nullifier-root",
        "--fail-over-ms",
        "60000",
    ]);
    assert!(
        incremental.ok && incremental.out.contains("within the 60000 ms budget"),
        "{}",
        incremental.out
    );

    let over = node(&[
        "bench",
        "apply",
        "--bundles",
        "20",
        "--blocks",
        "4",
        "--report-every",
        "2",
        "--fail-over-ms",
        "0",
    ]);
    assert!(!over.ok, "over the budget is a failure for a script");
    assert!(over.out.contains("OVER the 0 ms budget"), "{}", over.out);
}
