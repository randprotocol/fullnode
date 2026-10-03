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
    let cfg = TokensConfig { registration_fee: 1_000_000_000, tokens: Vec::new(), mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None };
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

/// RPL-2 from the command line: `--program-state-cell-fee` writes the `program_state` section
/// with that fee, the chain it builds has program state, and the section is part of the genesis
/// hash — while the default writes no section at all. It stands on four other flags, each
/// refused by name before any file is written; the section's own bound is the build's to refuse.
#[test]
fn the_genesis_command_writes_the_program_state_section_when_asked() {
    use randprotocol_core::ledger::program_state::ProgramStateConfig;
    let dir = tempfile::tempdir().unwrap();
    let cfg = TokensConfig { registration_fee: 1_000_000_000, tokens: Vec::new(), mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None };
    let cfg_path = dir.path().join("tokens.json");
    std::fs::write(&cfg_path, serde_json::to_string(&cfg).unwrap()).unwrap();
    let tokens = cfg_path.to_str().unwrap();
    // A v3 chain's block holds three proofs (`gas::min_block_bytes`), hence the block cap.
    let all = ["--tokens", tokens, "--gas-price", "100", "--bundle-guest", "v3", "--auth-guest", "--hardening-v6", "--max-block-bytes", "8388608"];

    let plain = dir.path().join("plain.json");
    let run = genesis(&plain, &all);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let p = read(&plain);
    assert_eq!(p.program_state, None, "no flag, no section");
    assert!(!std::fs::read_to_string(&plain).unwrap().contains("program_state"));

    let with = dir.path().join("with.json");
    let run = genesis(&with, &[all.as_slice(), &["--program-state-cell-fee", "10000000"]].concat());
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let w = read(&with);
    assert_eq!(w.program_state, Some(ProgramStateConfig { cell_fee: 10_000_000 }));
    let executor = randprotocol_node::node::executor_for_profile(&w.fri_profile).unwrap();
    let state = w.build(executor.as_ref()).unwrap();
    assert_eq!(state.ledger.program_state().map(|s| s.cell_fee), Some(10_000_000));
    randprotocol_node::node::check_build_runs_genesis(&state, &ZkExecutor::known_hc_bundles()).unwrap();
    assert_ne!(state.hash(), p.build(executor.as_ref()).unwrap().hash(), "the section is bound by the genesis hash");
    assert_eq!(printed_hash(&run, "genesis hash "), state.hash().to_hex());
    assert!(String::from_utf8_lossy(&run.stdout).contains("program_state: cell fee 0.01 RAND"));

    // Each flag it stands on, missing one at a time, refused by name; and a fee past the bound.
    let without = |skip: &str| -> Vec<&str> {
        let mut args = Vec::new();
        let mut i = 0;
        while i < all.len() {
            if all[i] == skip {
                i += if all[i].starts_with("--") && i + 1 < all.len() && !all[i + 1].starts_with("--") { 2 } else { 1 };
                continue;
            }
            args.push(all[i]);
            i += 1;
        }
        args
    };
    for flag in ["--tokens", "--gas-price", "--hardening-v6", "--auth-guest"] {
        let mut args = without(flag);
        if flag == "--auth-guest" {
            // v3 without the auth guest is refused for its own reason first; drop the guest too.
            args = without("--auth-guest").into_iter().filter(|a| *a != "--bundle-guest" && *a != "v3").collect();
        }
        args.extend(["--program-state-cell-fee", "1"]);
        let bad = dir.path().join(format!("bad{}.json", flag.trim_start_matches('-')));
        let run = genesis(&bad, &args);
        assert!(!run.status.success(), "{flag}");
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(stderr.contains(&format!("--program-state-cell-fee needs {flag}")), "{flag}: {stderr}");
        assert!(!bad.exists(), "{flag}: nothing is written");
    }
    let over = dir.path().join("over.json");
    let run = genesis(&over, &[all.as_slice(), &["--program-state-cell-fee", "1000000000001"]].concat());
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("program_state"), "{}", String::from_utf8_lossy(&run.stderr));
    assert!(!over.exists());
}

/// RPL-3 from the command line: `--perps <PATH>` reads a `PerpsConfig` JSON file into the
/// genesis `perps` section, the chain it builds has the perps state at the section's root, and
/// the section is part of the genesis hash — the default writes none. It stands on the same four
/// flags RPL-2's does, each refused by name before any file is written; an unreadable or
/// out-of-bounds config is refused too.
#[test]
fn the_genesis_command_writes_the_perps_section_when_asked() {
    use randprotocol_core::ledger::perps::{MarketSpec, PerpsConfig};
    let dir = tempfile::tempdir().unwrap();
    let cfg = TokensConfig {
        registration_fee: 1_000_000_000,
        tokens: Vec::new(),
        mint_cap_per_day: 100_000 * 100_000_000,
        max_tokens: None,
        burn_registration_fee: None,
        bound_note_value: None,
        incremental_root: None,
    };
    let cfg_path = dir.path().join("tokens.json");
    std::fs::write(&cfg_path, serde_json::to_string(&cfg).unwrap()).unwrap();
    let tokens = cfg_path.to_str().unwrap();
    let section = PerpsConfig {
        collateral_asset: 0,
        max_tier: 16,
        max_window_blocks: 8,
        engine_hc: [9; 8],
        genesis_root: [8; 8],
        markets: vec![MarketSpec {
            id: 0,
            symbol: "BTC-PERP".into(),
            lot: 1_000_000,
            tick: 1_000,
            max_leverage: 10,
            maintenance_bps: 500,
            taker_fee_bps: 5,
            maker_fee_bps: 2,
        }],
    };
    let perps_path = dir.path().join("perps.json");
    std::fs::write(&perps_path, serde_json::to_string_pretty(&section).unwrap()).unwrap();
    let perps = perps_path.to_str().unwrap();
    let all = [
        "--tokens",
        tokens,
        "--gas-price",
        "100",
        "--bundle-guest",
        "v3",
        "--auth-guest",
        "--hardening-v6",
        "--max-block-bytes",
        "8388608",
    ];

    let plain = dir.path().join("plain.json");
    let run = genesis(&plain, &all);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let p = read(&plain);
    assert_eq!(p.perps, None, "no flag, no section");
    assert!(!std::fs::read_to_string(&plain).unwrap().contains("perps"));

    let with = dir.path().join("with.json");
    let run = genesis(&with, &[all.as_slice(), &["--perps", perps]].concat());
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let w = read(&with);
    assert_eq!(w.perps.as_ref(), Some(&section));
    let executor = randprotocol_node::node::executor_for_profile(&w.fri_profile).unwrap();
    let state = w.build(executor.as_ref()).unwrap();
    let p_state = state.ledger.perps().expect("the chain has the perps state");
    assert_eq!((p_state.proved_root, p_state.proved_height), ([8; 8], 0));
    randprotocol_node::node::check_build_runs_genesis(&state, &ZkExecutor::known_hc_bundles()).unwrap();
    assert_ne!(state.hash(), p.build(executor.as_ref()).unwrap().hash(), "the section is bound by the genesis hash");
    assert_eq!(printed_hash(&run, "genesis hash "), state.hash().to_hex());
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(stdout.contains("perps: 1 market"), "{stdout}");

    // Each flag it stands on, missing one at a time, refused by name; nothing is written.
    let without = |skip: &str| -> Vec<&str> {
        let mut args = Vec::new();
        let mut i = 0;
        while i < all.len() {
            if all[i] == skip {
                i += if all[i].starts_with("--") && i + 1 < all.len() && !all[i + 1].starts_with("--") { 2 } else { 1 };
                continue;
            }
            args.push(all[i]);
            i += 1;
        }
        args
    };
    for flag in ["--tokens", "--gas-price", "--hardening-v6", "--auth-guest"] {
        let mut args = without(flag);
        if flag == "--auth-guest" {
            // v3 without the auth guest is refused for its own reason first; drop the guest too.
            args = without("--auth-guest").into_iter().filter(|a| *a != "--bundle-guest" && *a != "v3").collect();
        }
        args.extend(["--perps", perps]);
        let bad = dir.path().join(format!("bad{}.json", flag.trim_start_matches('-')));
        let run = genesis(&bad, &args);
        assert!(!run.status.success(), "{flag}");
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(stderr.contains(&format!("--perps needs {flag}")), "{flag}: {stderr}");
        assert!(!bad.exists(), "{flag}: nothing is written");
    }
    // A config the section's own bounds refuse, and one that is not a config at all.
    let mut over = section.clone();
    over.max_tier = 11;
    let over_path = dir.path().join("over-perps.json");
    std::fs::write(&over_path, serde_json::to_string(&over).unwrap()).unwrap();
    let out = dir.path().join("over.json");
    let run = genesis(&out, &[all.as_slice(), &["--perps", over_path.to_str().unwrap()]].concat());
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("max_tier"), "{}", String::from_utf8_lossy(&run.stderr));
    assert!(!out.exists());
    let junk_path = dir.path().join("junk.json");
    std::fs::write(&junk_path, "{\"markets\": 3}").unwrap();
    let run = genesis(&out, &[all.as_slice(), &["--perps", junk_path.to_str().unwrap()]].concat());
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("--perps"), "{}", String::from_utf8_lossy(&run.stderr));
    assert!(!out.exists());
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

    // At the default caps (2 MiB proofs, 4 MiB blocks) the pair is refused: a v3 `Call` carries
    // three proofs and the block must hold 3 * 2 MiB + 1 MiB (review I-1). Nothing is written.
    let small = dir.path().join("small.json");
    let run = genesis(&small, &["--bundle-guest", "v3", "--auth-guest"]);
    assert!(!run.status.success(), "v3 at the 4 MiB default block cap must be refused");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("three proofs (bundle, auth, call)") && stderr.contains("7340032"), "{stderr}");
    assert!(!small.exists(), "and nothing is written");

    // With chain 17's caps (4 MiB proofs, 20 MiB blocks) it is written.
    let out = dir.path().join("split.json");
    let run = genesis(
        &out,
        &["--bundle-guest", "v3", "--auth-guest", "--hardening-v6", "--max-proof-bytes", "4194304", "--max-block-bytes", "20971520"],
    );
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
    // The genesis this harness writes names the `test` profile, which the binary refuses at
    // `init` without being told this is a test (ZK-5a): the harness's environment variable.
    let init = Command::new(env!("CARGO_BIN_EXE_rand-node"))
        .env("RAND_ALLOW_TEST_FRI_PROFILE", "1")
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

/// Audit v6, ZK-5a: a genesis naming `fri_profile: "test"` proves about 17 bits, and whoever
/// writes a genesis file can select it. The binary refuses it at `init` and `run` unless told
/// this is a test — `--allow-test-fri-profile` or `RAND_ALLOW_TEST_FRI_PROFILE=1` — and says
/// what the profile is worth; `genesis --fri-profile test` warns on stderr; a production-profile
/// genesis needs nothing. (`verify` reads the same genesis through the same check as `run`.)
#[test]
fn the_binary_refuses_a_test_profile_genesis_unless_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("genesis.json");
    let written = genesis(&out, &[]);
    assert!(written.status.success(), "{}", String::from_utf8_lossy(&written.stderr));
    let warned = String::from_utf8_lossy(&written.stderr);
    assert!(warned.contains("fri_profile \"test\"") && warned.contains("17 bits"), "genesis warns: {warned}");

    let node = || Command::new(env!("CARGO_BIN_EXE_rand-node"));
    let datadir = dir.path().join("data");
    // `init` without the flag: refused, naming the profile's worth; nothing initialised.
    let refused = node().env_remove("RAND_ALLOW_TEST_FRI_PROFILE").args(["init", "--datadir"]).arg(&datadir).arg("--genesis").arg(&out).output().unwrap();
    assert!(!refused.status.success());
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(err.contains("fri_profile \"test\"") && err.contains("17 bits") && err.contains("--allow-test-fri-profile"), "{err}");
    assert!(!datadir.join("db").exists(), "the refusal opened no database");
    // With the flag: accepted.
    let allowed = node().env_remove("RAND_ALLOW_TEST_FRI_PROFILE").args(["init", "--allow-test-fri-profile", "--datadir"]).arg(&datadir).arg("--genesis").arg(&out).output().unwrap();
    assert!(allowed.status.success(), "{}", String::from_utf8_lossy(&allowed.stderr));
    // `run` on that datadir without the flag: refused before the key is read (no key exists).
    let key = dir.path().join("node.key.json");
    let refused = node().env_remove("RAND_ALLOW_TEST_FRI_PROFILE").args(["run", "--datadir"]).arg(&datadir).arg("--key").arg(&key).output().unwrap();
    assert!(!refused.status.success());
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(err.contains("fri_profile \"test\""), "{err}");
    assert!(!err.contains("node.key.json"), "refused before the key was read: {err}");
    // With the environment variable it gets past the profile, to the missing key.
    let past = node().env("RAND_ALLOW_TEST_FRI_PROFILE", "1").args(["run", "--datadir"]).arg(&datadir).arg("--key").arg(&key).output().unwrap();
    let err = String::from_utf8_lossy(&past.stderr);
    assert!(!err.contains("fri_profile"), "{err}");

    // A production-profile genesis: no warning, and `init` needs nothing.
    let prod = dir.path().join("production.json");
    let written = node()
        .args(["genesis", "--chain-id", "14", "--fri-profile", "production", "--validator", &validator_arg(), "--out"])
        .arg(&prod)
        .output()
        .unwrap();
    assert!(written.status.success(), "{}", String::from_utf8_lossy(&written.stderr));
    assert!(!String::from_utf8_lossy(&written.stderr).contains("17 bits"));
    let init = node().env_remove("RAND_ALLOW_TEST_FRI_PROFILE").args(["init", "--datadir"]).arg(dir.path().join("prod-data")).arg("--genesis").arg(&prod).output().unwrap();
    assert!(init.status.success(), "{}", String::from_utf8_lossy(&init.stderr));
}

/// Audit v6, STAKE-2: `--staking` writes a `StakingConfig` file into the genesis unchanged —
/// `admission_by_vote` with it — and `--consensus-domain` the signing domain; the chain the file
/// builds runs with both, and the flag is part of the genesis hash. Without `--staking` the file
/// has no section, as before. A section the build refuses fails the command.
#[test]
fn the_genesis_command_round_trips_a_staking_section_with_admission_by_vote() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = serde_json::json!({
        "faucet_budget_per_epoch": "0", "bond_activation_epochs": 2, "max_weight_bps": 3333,
        "registration_v2": true, "admission_by_vote": true,
    });
    let cfg_path = dir.path().join("staking.json");
    std::fs::write(&cfg_path, cfg.to_string()).unwrap();

    let out = dir.path().join("genesis.json");
    let run = genesis(&out, &["--staking", cfg_path.to_str().unwrap(), "--consensus-domain", "1"]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let gen = read(&out);
    let section = gen.staking.clone().expect("the section is in the file");
    assert_eq!(section.admission_by_vote, Some(true));
    assert_eq!((section.bond_activation_epochs, section.max_weight_bps, section.registration_v2), (2, Some(3333), Some(true)));
    assert_eq!(gen.consensus_domain, Some(1));
    let executor = ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
    let state = gen.build(&executor).unwrap();
    assert!(state.ledger.staking().unwrap().admission_by_vote());
    let mut without = gen.clone();
    without.staking.as_mut().unwrap().admission_by_vote = None;
    assert_ne!(without.build(&executor).unwrap().hash(), state.hash(), "the flag is bound by the genesis hash");

    // No flag, no section, no domain: the shape this command always wrote.
    let plain = dir.path().join("plain.json");
    assert!(genesis(&plain, &[]).status.success());
    assert!(read(&plain).staking.is_none() && read(&plain).consensus_domain.is_none());

    // A misspelled key is refused by the section's own `deny_unknown_fields`, and nothing is written.
    let bad_path = dir.path().join("bad.json");
    std::fs::write(&bad_path, r#"{"faucet_budget_per_epoch":"0","bond_activation_epochs":2,"admission_by_votes":true}"#).unwrap();
    let refused = dir.path().join("refused.json");
    let run = genesis(&refused, &["--staking", bad_path.to_str().unwrap()]);
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("not a valid staking config"), "{}", String::from_utf8_lossy(&run.stderr));
    assert!(!refused.exists());
}

/// Audit v6, STAKE-2: `--testnet` writes the marker that lets a faucet sit beside a bridge
/// section spliced in later; without it the file has no such field.
#[test]
fn the_genesis_command_writes_the_testnet_marker_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("genesis.json");
    let run = genesis(&out, &["--faucet", "--testnet"]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let gen = read(&out);
    assert_eq!((gen.faucet, gen.testnet), (true, Some(true)));
    assert!(std::fs::read_to_string(&out).unwrap().contains("\"testnet\": true"));
    let executor = ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
    assert!(gen.build(&executor).unwrap().ledger.testnet());
    let plain = dir.path().join("plain.json");
    assert!(genesis(&plain, &["--faucet"]).status.success());
    assert_eq!(read(&plain).testnet, None);
    assert!(!std::fs::read_to_string(&plain).unwrap().contains("testnet"));
}

/// Audit v6 (TOK-1, issue #86): `--tokens-incremental-root` sets `"incremental_root": true` on the
/// tokens section the file carries, and the chain it builds commits its registry incrementally;
/// without `--tokens` it is refused by name and nothing is written; without the flag the section
/// is what the config file says — no field, chain 20's shape.
#[test]
fn the_genesis_command_writes_the_incremental_token_root_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = TokensConfig { registration_fee: 1_000_000_000, tokens: Vec::new(), mint_cap_per_day: 100_000 * 100_000_000, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None };
    let cfg_path = dir.path().join("tokens.json");
    std::fs::write(&cfg_path, serde_json::to_string(&cfg).unwrap()).unwrap();
    let out = dir.path().join("genesis.json");
    let run = genesis(&out, &["--tokens", cfg_path.to_str().unwrap(), "--tokens-incremental-root"]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let gen = read(&out);
    assert_eq!(gen.tokens.as_ref().unwrap().incremental_root, Some(true));
    assert!(std::fs::read_to_string(&out).unwrap().contains("\"incremental_root\": true"));
    let executor = ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
    let state = gen.build(&executor).unwrap();
    assert!(state.ledger.tokens().unwrap().incremental_root(), "the chain's registry commits incrementally");
    let mut without = gen.clone();
    without.tokens.as_mut().unwrap().incremental_root = None;
    assert_ne!(without.build(&executor).unwrap().hash(), state.hash(), "the field is bound by the genesis hash");

    let refused = dir.path().join("refused.json");
    let run = genesis(&refused, &["--tokens-incremental-root"]);
    assert!(!run.status.success());
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(stderr.contains("--tokens-incremental-root needs --tokens"), "{stderr}");
    assert!(!refused.exists(), "and nothing is written");

    let plain = dir.path().join("plain.json");
    assert!(genesis(&plain, &["--tokens", cfg_path.to_str().unwrap()]).status.success());
    assert_eq!(read(&plain).tokens.unwrap().incremental_root, None);
    assert!(!std::fs::read_to_string(&plain).unwrap().contains("incremental_root"));
}

/// Issue #118: `--proof-window-blocks N` writes the window; out of [256, 4096] it is refused and
/// nothing is written; without it the file has no such field (256/256, chain 18's rules).
#[test]
fn the_genesis_command_writes_the_proof_window_when_asked() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("genesis.json");
    let run = genesis(&out, &["--proof-window-blocks", "1024"]);
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let gen = read(&out);
    assert_eq!(gen.proof_window_blocks, Some(1024));
    assert!(std::fs::read_to_string(&out).unwrap().contains("\"proof_window_blocks\": 1024"));
    let executor = ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
    assert_eq!(gen.build(&executor).unwrap().ledger.proof_window(), 1024);
    let refused = dir.path().join("refused.json");
    let run = genesis(&refused, &["--proof-window-blocks", "255"]);
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("bad proof_window_blocks 255"), "{}", String::from_utf8_lossy(&run.stderr));
    assert!(!refused.exists());
    let plain = dir.path().join("plain.json");
    assert!(genesis(&plain, &[]).status.success());
    assert_eq!(read(&plain).proof_window_blocks, None);
    assert!(!std::fs::read_to_string(&plain).unwrap().contains("proof_window_blocks"));
}

/// Fee feedback (`docs/fees.md` §1.3): `--fees` writes a `FeesConfig` file into the genesis
/// unchanged — all three flags, `subsidy_net_of_fees` on an aggregating chain, which it needs —
/// and the chain it builds runs every rule; the section is part of the genesis hash. Without the
/// flag the file has no section, as before. A misspelled key is refused by the section's own
/// `deny_unknown_fields`, and nothing is written.
#[test]
fn the_genesis_command_round_trips_a_fees_section_with_all_three_flags() {
    let dir = tempfile::tempdir().unwrap();
    let cfg_path = dir.path().join("fees.json");
    std::fs::write(&cfg_path, r#"{"burn_base":true,"subsidy_net_of_fees":true,"burn_floor":true}"#).unwrap();
    // The smallest aggregation section the command accepts: one admitted shape, the bundle
    // guest's own test-profile shape, under a placeholder (non-zero) program digest.
    let shape = format!(
        "test,{},12,10,0,0,{},16,hc_bundle,{}",
        randprotocol_core::types::BUNDLE_PROOF_TIER,
        randprotocol_core::types::BUNDLE_PUBLIC_LOG_HEIGHT,
        "0000000000000001".repeat(4)
    );
    let aggregation = ["--aggregation", "100,3,100,210000,256", "--admitted-shape", shape.as_str()];

    let out = dir.path().join("genesis.json");
    let run = genesis(&out, &[&aggregation[..], &["--fees", cfg_path.to_str().unwrap()]].concat());
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let gen = read(&out);
    let section = gen.fees.clone().expect("the section is in the file");
    assert_eq!((section.burn_base, section.subsidy_net_of_fees, section.burn_floor), (Some(true), Some(true), Some(true)));
    let executor = ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
    let state = gen.build(&executor).unwrap();
    let fees = state.ledger.fees();
    assert!(fees.burn_base() && fees.subsidy_net_of_fees() && fees.burn_floor(), "the chain runs every rule");
    let mut without = gen.clone();
    without.fees = None;
    assert_ne!(without.build(&executor).unwrap().hash(), state.hash(), "the section is bound by the genesis hash");

    // No flag, no section: the shape this command always wrote.
    let plain = dir.path().join("plain.json");
    assert!(genesis(&plain, &[]).status.success());
    assert!(read(&plain).fees.is_none());
    assert!(!std::fs::read_to_string(&plain).unwrap().contains("\"fees\""));

    let bad_path = dir.path().join("bad.json");
    std::fs::write(&bad_path, r#"{"burn_bases":true}"#).unwrap();
    let refused = dir.path().join("refused.json");
    let run = genesis(&refused, &["--fees", bad_path.to_str().unwrap()]);
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("not a valid fees config"), "{}", String::from_utf8_lossy(&run.stderr));
    assert!(!refused.exists());
}

/// `--fees` is validated by the genesis checks, not only parsed: `burn_floor` widens the burned
/// base, so without `burn_base` it is refused (issue #135), and `subsidy_net_of_fees` without an
/// aggregation section has no subsidy to net. Either way nothing is written.
#[test]
fn the_genesis_command_refuses_a_fees_section_the_genesis_checks_refuse() {
    let dir = tempfile::tempdir().unwrap();
    for (cfg, words) in [
        (r#"{"burn_floor":true}"#, "fees.burn_floor needs fees.burn_base"),
        (r#"{"burn_base":true,"subsidy_net_of_fees":true}"#, "fees.subsidy_net_of_fees needs an aggregation section"),
    ] {
        let cfg_path = dir.path().join("fees.json");
        std::fs::write(&cfg_path, cfg).unwrap();
        let refused = dir.path().join("refused.json");
        let run = genesis(&refused, &["--fees", cfg_path.to_str().unwrap()]);
        assert!(!run.status.success(), "{cfg} was accepted");
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(stderr.contains(words), "{cfg}: {stderr}");
        assert!(!refused.exists(), "{cfg}: and nothing is written");
    }
}
