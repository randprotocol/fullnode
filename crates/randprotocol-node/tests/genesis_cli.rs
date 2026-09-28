//! `rand-node genesis` as an operator runs it — the built binary, a real output file — for the two
//! things the hidden-asset bundle (chain 14) needs of it: the file pins **this build's** bundle
//! guest, which is now the hidden-asset guest and not the retired 2-in-2-out one, and the RPL
//! `tokens` section given by `--tokens` round-trips into the file and into the chain it builds.

use randprotocol_core::genesis::{Genesis, TokensConfig};
use randprotocol_core::notes::word8_to_hex;
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::notes::SpendKey;
use std::path::Path;
use std::process::{Command, Output};

/// `--validator` for one fixed key at the staking minimum, paying out to a real shielded address.
fn validator_arg() -> String {
    let pk = randprotocol_core::Keypair::from_seed([1; 32]).unwrap().public_key().to_hex();
    let payout = randprotocol_zkvm::address::address_of(&SpendKey([7; 8]).viewing_key()).to_string();
    let stake = randprotocol_core::ledger::staking::MIN_STAKE / randprotocol_core::UNITS_PER_RAND;
    format!("{pk},{stake},{payout}")
}

/// Run `rand-node genesis --fri-profile test --chain-id 14 … --out <out>` plus `extra`.
fn genesis(out: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rand-node"))
        .args(["genesis", "--chain-id", "14", "--fri-profile", "test", "--validator", &validator_arg(), "--out"])
        .arg(out)
        .args(extra)
        .output()
        .expect("rand-node runs")
}

fn read(out: &Path) -> Genesis {
    Genesis::from_json(&std::fs::read_to_string(out).unwrap()).unwrap()
}

/// The written `hc_bundle` is the hidden-asset guest's digest — the chain-14 hard fork is in the
/// file, not only in the binary — and never the retired guest's that chain 13 pins. A node built
/// from this tree runs the file it wrote (`check_build_runs_genesis` compares exactly this field).
#[test]
fn the_genesis_command_pins_the_hidden_asset_guest() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("genesis.json");
    let run = genesis(&out, &[]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let gen = read(&out);
    assert_eq!(gen.hc_bundle, word8_to_hex(&ZkExecutor::hc_hidden_bundle()));
    assert_eq!(gen.hc_bundle, word8_to_hex(&ZkExecutor::hc_bundle()), "the build's chain guest is the hidden one");
    assert_ne!(gen.hc_bundle, word8_to_hex(&ZkExecutor::hc_legacy_bundle()));
    assert!(gen.tokens.is_none(), "no --tokens, no section");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains(&format!("hc_bundle {}", gen.hc_bundle)), "the operator is told which guest: {stdout}");
}

/// `--tokens` writes the `TokensConfig` file into the genesis unchanged, the chain it builds
/// carries the registry at that fee with no token listed (native tokens arrive by
/// `RegisterToken`), and the section is part of the genesis hash. A config the build refuses — a
/// listed token on a chain with no `bridge` section — fails the command and writes nothing.
#[test]
fn the_genesis_command_round_trips_a_tokens_section() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = TokensConfig { registration_fee: 1_000_000_000, tokens: Vec::new(), mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None };
    let cfg_path = dir.path().join("tokens.json");
    std::fs::write(&cfg_path, serde_json::to_string(&cfg).unwrap()).unwrap();

    let out = dir.path().join("genesis.json");
    let run = genesis(&out, &["--tokens", cfg_path.to_str().unwrap()]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let gen = read(&out);
    assert_eq!(gen.tokens, Some(cfg.clone()), "the section round-trips through the file");
    let state = gen.build(&ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test)).unwrap();
    let registry = state.ledger.tokens().expect("the gate is on");
    assert_eq!(registry.registration_fee, cfg.registration_fee);
    assert_eq!(registry.next_index(), 1, "no token listed; index 0 is RAND's");
    let mut without = gen.clone();
    without.tokens = None;
    let bare = without.build(&ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test)).unwrap();
    assert_ne!(bare.hash(), state.hash(), "the tokens section is bound by the genesis hash");

    // A listed token needs a bridge section, which this command never writes.
    let listed = serde_json::json!({
        "registration_fee": 1, "tokens": [{ "name": "Tether USD", "symbol": "zUSDT", "salt": "5a".repeat(32),
            "backings": [{ "chain": 2, "token": "aa".repeat(32), "decimals": 8 }] }]
    });
    let bad_cfg = dir.path().join("listed.json");
    std::fs::write(&bad_cfg, listed.to_string()).unwrap();
    let bad_out = dir.path().join("refused.json");
    let run = genesis(&bad_out, &["--tokens", bad_cfg.to_str().unwrap()]);
    assert!(!run.status.success(), "a listed token without a bridge must be refused");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!stderr.contains("is not a valid tokens config"), "refused by the build, not the parse: {stderr}");
    assert!(!bad_out.exists(), "and nothing is written");
}

/// v0.6's next-cut switches from the command line: `--bundle-guest v2` pins the branch-free guest
/// (INT-2 / GV-1) and `--hardening-v6` turns the v0.6 rules on as validity rules. The file carries
/// both, it builds, a node built from this tree accepts it, and it is a different chain from the
/// default (v1, no switch) — while the default still writes exactly what it always did.
#[test]
fn the_genesis_command_pins_guest_v2_and_the_v06_switch_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("plain.json");
    let next = dir.path().join("next.json");
    assert!(genesis(&plain, &[]).status.success());
    let run = genesis(&next, &["--bundle-guest", "v2", "--hardening-v6"]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let (p, n) = (read(&plain), read(&next));
    assert_eq!(p.hc_bundle, word8_to_hex(&ZkExecutor::hc_hidden_bundle()), "the default stays v1");
    assert_eq!(p.hardening_v6, None, "and writes no switch");
    assert_eq!(n.hc_bundle, word8_to_hex(&ZkExecutor::hc_hidden_bundle_v2()));
    assert_eq!(n.hardening_v6, Some(true));
    let executor = randprotocol_node::node::executor_for_profile(&n.fri_profile).unwrap();
    let state = n.build(executor.as_ref()).unwrap();
    assert!(state.ledger.hardening_v6());
    randprotocol_node::node::check_build_runs_genesis(&state, &ZkExecutor::known_hc_bundles()).unwrap();
    let plain_state = p.build(executor.as_ref()).unwrap();
    assert_ne!(state.hash(), plain_state.hash(), "a different chain");
    assert!(genesis(&dir.path().join("bad.json"), &["--bundle-guest", "v4"]).status.code() != Some(0), "an unknown guest is refused");
}

/// The genesis hash a `rand-node` run printed (`genesis hash <hex>` or `at genesis <hex>`).
fn printed_hash(out: &Output, after: &str) -> String {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let at = stdout.find(after).unwrap_or_else(|| panic!("no {after:?} in {stdout}")) + after.len();
    stdout[at..at + 64].to_string()
}

/// Split authorisation from the command line: `--bundle-guest v3 --auth-guest` pins bundle guest
/// v3 and this build's auth guest as `hc_auth`; the two are a pair both ways — v3 alone and
/// `--auth-guest` with v1/v2 are refused, writing nothing. The file it writes is one `rand-node
/// init` accepts, re-deriving the hash the genesis command printed, and a node built from this
/// tree runs it.
#[test]
fn the_genesis_command_pins_guest_v3_with_the_auth_guest() {
    let dir = tempfile::tempdir().unwrap();

    let bare = dir.path().join("bare.json");
    let run = genesis(&bare, &["--bundle-guest", "v3"]);
    assert!(!run.status.success(), "v3 without --auth-guest must be refused");
    assert!(String::from_utf8_lossy(&run.stderr).contains("--bundle-guest v3 needs --auth-guest"), "{}", String::from_utf8_lossy(&run.stderr));
    assert!(!bare.exists(), "and nothing is written");
    for guest in ["v1", "v2"] {
        let wrong = dir.path().join(format!("{guest}.json"));
        let run = genesis(&wrong, &["--bundle-guest", guest, "--auth-guest"]);
        assert!(!run.status.success(), "{guest} --auth-guest must be refused");
        assert!(String::from_utf8_lossy(&run.stderr).contains("--auth-guest needs --bundle-guest v3"), "{}", String::from_utf8_lossy(&run.stderr));
        assert!(!wrong.exists());
    }
    let default_json = dir.path().join("default.json");
    let run = genesis(&default_json, &["--auth-guest"]);
    assert!(!run.status.success(), "--auth-guest with the default guest (v1) is refused too");
    assert!(!default_json.exists(), "and nothing is written");

    let out = dir.path().join("split.json");
    let run = genesis(&out, &["--bundle-guest", "v3", "--auth-guest", "--hardening-v6"]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let gen = read(&out);
    assert_eq!(gen.hc_bundle, word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()));
    assert_eq!(gen.hc_auth, Some(word8_to_hex(&ZkExecutor::hc_auth())));
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains(&format!("hc_auth {}", word8_to_hex(&ZkExecutor::hc_auth()))), "the operator is told: {stdout}");
    let executor = randprotocol_node::node::executor_for_profile(&gen.fri_profile).unwrap();
    let state = gen.build(executor.as_ref()).unwrap();
    assert_eq!(state.ledger.hc_auth(), Some(ZkExecutor::hc_auth()));
    randprotocol_node::node::check_build_runs_genesis(&state, &ZkExecutor::known_hc_bundles()).unwrap();
    let printed = printed_hash(&run, "genesis hash ");
    assert_eq!(printed, state.hash().to_hex());

    let datadir = dir.path().join("data");
    let init = Command::new(env!("CARGO_BIN_EXE_rand-node"))
        .args(["init", "--datadir"])
        .arg(&datadir)
        .arg("--genesis")
        .arg(&out)
        .output()
        .expect("rand-node runs");
    assert!(init.status.success(), "{}", String::from_utf8_lossy(&init.stderr));
    assert_eq!(printed_hash(&init, "at genesis "), printed, "init re-derives the hash the genesis command printed");

    let help = Command::new(env!("CARGO_BIN_EXE_rand-node")).args(["genesis", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("--auth-guest") && help.contains("v1|v2|v3"), "{help}");
}
