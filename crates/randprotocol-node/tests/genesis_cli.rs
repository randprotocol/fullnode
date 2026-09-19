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
    let cfg = TokensConfig { registration_fee: 1_000_000_000, tokens: Vec::new(), mint_cap_per_day: 100_000 * 100_000_000 };
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
