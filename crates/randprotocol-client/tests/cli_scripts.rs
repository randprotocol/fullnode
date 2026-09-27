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
