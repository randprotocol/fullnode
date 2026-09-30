//! The `rand` binary as a script sees it (final review B1): `$(rand address)` is exactly the
//! address, and a `rand send` that would have prompted refuses clearly when nobody can answer.
//! Neither needs a node: both are decided before the first RPC call.

use std::process::{Command, Stdio};

fn rand(key: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rand"))
        .arg("--key")
        .arg(key)
        // Nothing listens here: a test that reached the network would fail loudly, not hang.
        .args(["--rpc", "http://127.0.0.1:9"])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run rand")
}

fn keygen(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let key = dir.path().join("w.key.json");
    let out = rand(&key, &["keygen"]);
    assert!(out.status.success(), "keygen: {}", String::from_utf8_lossy(&out.stderr));
    key
}

#[test]
fn rand_address_prints_exactly_the_address_on_a_piped_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let out = rand(&key, &["address"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    let address = stdout.trim_end_matches('\n');
    assert!(address.starts_with("rand1") && !address.contains(char::is_whitespace), "stdout is not one address: {stdout:?}");
    assert_eq!(stdout, format!("{address}\n"), "exactly the address and a newline");
    randprotocol_core::notes::ShieldedAddress::parse(address).expect("stdout parses as an address");
    assert!(String::from_utf8_lossy(&out.stderr).contains("fingerprint"), "the fingerprint still shows, on stderr");
}

#[test]
fn rand_send_without_yes_on_a_non_tty_stdin_refuses_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let to = String::from_utf8(rand(&key, &["address"]).stdout).unwrap().lines().next().unwrap().to_string();
    let out = rand(&key, &["send", &to, "1"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("stdin is not a terminal: pass --yes to send without confirmation"),
        "{stderr}"
    );
}

/// VK-4 (audit v6): `rand prover pair` says what the paired prover will receive and asks before
/// anything is saved or the prover is contacted. With nobody to answer (a script, a pipe) and no
/// `--yes` it refuses — the convention `rand send` follows — and writes no pairing. The link here
/// says `own=1`, which no longer decides anything: the disclosure is the same for every pairing.
#[test]
fn rand_prover_pair_says_what_the_prover_receives_and_asks_first() {
    let dir = tempfile::tempdir().unwrap();
    let key = keygen(&dir);
    let prover = randprotocol_prover::key::ProverKey::generate();
    for own in [true, false] {
        // Nothing listens at the link's URL either: a pair that reached it would fail differently.
        let link = randprotocol_prover::pairing::PairingLink { kem_ek: prover.kem_ek().to_vec(), url: "http://127.0.0.1:9".into(), token: [7; 32], own }.format();
        let out = rand(&key, &["prover", "pair", &link]);
        assert!(!out.status.success());
        let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        assert!(stderr.contains("stdin is not a terminal: pass --yes to pair without confirmation"), "own={own}: {stderr}");
        assert!(
            stdout.contains("this prover will receive this wallet's viewing key: it can read the wallet's whole history; it cannot spend"),
            "own={own}: what the prover receives is shown before the question: {stdout}"
        );
        assert!(stdout.contains(&prover.fingerprint().to_string()) && stdout.contains("http://127.0.0.1:9"), "own={own}: {stdout}");
        assert!(!dir.path().join("w.key.json.prover.json").exists(), "own={own}: nothing is saved without the answer");
    }
    // `--yes` skips the question (and then fails to reach the prover nobody runs): still nothing saved.
    let link = randprotocol_prover::pairing::PairingLink { kem_ek: prover.kem_ek().to_vec(), url: "http://127.0.0.1:9".into(), token: [7; 32], own: true }.format();
    let out = rand(&key, &["prover", "pair", &link, "--yes"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("reaching the prover") && !stderr.contains("not a terminal"), "{stderr}");
    assert!(!dir.path().join("w.key.json.prover.json").exists());
}
