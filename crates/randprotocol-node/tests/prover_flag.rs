//! `rand-node run --prover`: the flag checks that run before the node opens its database.

use std::process::Command;

#[test]
fn run_with_prover_refuses_without_a_key_and_refuses_the_rpc_address() {
    let dir = tempfile::tempdir().unwrap();
    // `--key` is required by `run`; the prover checks come before the node key is read, so a
    // missing node key file never masks them.
    let node_key = dir.path().join("node.key.json");
    let out = Command::new(env!("CARGO_BIN_EXE_rand-node"))
        .args(["run", "--datadir"])
        .arg(dir.path())
        .arg("--key")
        .arg(&node_key)
        .args(["--prover", "127.0.0.1:0"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("no prover key"), "{err}");
    assert!(err.contains("rand-prover"), "{err}");
    let out = Command::new(env!("CARGO_BIN_EXE_rand-node"))
        .args(["run", "--datadir"])
        .arg(dir.path())
        .arg("--key")
        .arg(&node_key)
        .args(["--rpc", "127.0.0.1:8599", "--prover", "127.0.0.1:8599"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("never a method of the public RPC"), "{err}");
    // A wildcard RPC bind overlaps a specific prover bind on the same port.
    let out = Command::new(env!("CARGO_BIN_EXE_rand-node"))
        .args(["run", "--datadir"])
        .arg(dir.path())
        .arg("--key")
        .arg(&node_key)
        .args(["--rpc", "0.0.0.0:8599", "--prover", "127.0.0.1:8599"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("never a method of the public RPC"), "{err}");
    // No refusal opened the database.
    assert!(!dir.path().join("db").exists());
}

#[test]
fn run_help_lists_the_prover_flags() {
    let out = Command::new(env!("CARGO_BIN_EXE_rand-node")).args(["run", "--help"]).output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    for f in ["--prover ", "--prover-home", "--prover-accept-spend-key", "--prover-max-parallel", "--prover-max-queue", "--prover-skip-memory-check", "--prover-cuda", "--prover-allow-origin"] {
        assert!(s.contains(f), "{f} missing:\n{s}");
    }
}

#[test]
fn run_refuses_a_malformed_prover_origin_before_anything_else() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rand-node"))
        .args(["run", "--datadir"])
        .arg(dir.path())
        .arg("--key")
        .arg(dir.path().join("node.key.json"))
        .args(["--prover", "127.0.0.1:0", "--prover-allow-origin", "https://wallet.example/"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("--prover-allow-origin \"https://wallet.example/\""), "{err}");
    assert!(!dir.path().join("db").exists());
}
