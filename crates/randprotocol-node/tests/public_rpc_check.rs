//! VK-2 (monorepo#17): `deploy/check-public-rpc.sh` against a real node's two listeners.
//!
//! The script is what an operator runs to show that a public RPC hop ends at the node's public
//! listener, and its output is the deploy record's evidence, so it is tested against the real
//! thing: one node with `--public-rpc` on. Pointed at the public listener it passes, naming the
//! node as the gate for every viewing-key method, `rand_mint` and `rand_getPeers`. Pointed at the
//! operator listener — a hop that ends at `--rpc`, which is the state VK-2 describes — it fails
//! and says which methods answered.

mod common;

use randprotocol_core::Keypair;
use randprotocol_node::node::{self, NetOptions, NodeConfig, RpcOptions};
use std::process::Command;
use std::time::Duration;

fn check(args: &[&str]) -> (bool, String) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/check-public-rpc.sh");
    let out = Command::new("bash").arg(script).args(args).output().expect("bash runs");
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_check_passes_on_the_public_listener_and_fails_on_the_operator_one() {
    let key = Keypair::from_seed([101; 32]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("genesis.json"), common::genesis(&key).to_json()).unwrap();
    // The public listener needs a port of its own, named up front: one the OS just handed out.
    let public_addr = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let handle = node::start_with(
        NodeConfig {
            viewing_open: false,
            datadir: dir.path().to_path_buf(),
            seed: *key.seed(),
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![],
            rpc_addr: "127.0.0.1:0".parse().unwrap(),
            enable_mdns: false,
            validator: true,
            block_interval: Duration::from_millis(150),
            base_timeout: Duration::from_millis(1500),
            max_timeout: Duration::from_secs(6),
            verify: randprotocol_node::storage::VerifyMode::Full,
            keep_raw_proofs: false,
            min_free_disk_bytes: 0,
            verify_workers: None,
            apply_inline: false,
            state_proof_tier_cap: None,
            multisig_account_cap: None,
            prune_history: None,
            gas_policy: None,
            msauth: Default::default(),
            perps_keys: Default::default(),
        },
        RpcOptions { public_addr: Some(public_addr), ..RpcOptions::default() },
        NetOptions::default(),
    )
    .await
    .expect("node starts");
    let public = format!("http://{}", handle.public_rpc_addr.expect("the public listener is up"));
    let operator = format!("http://{}", handle.rpc_addr);

    let (on_public, on_operator, through_proxy_flag) = tokio::task::spawn_blocking(move || {
        (check(&["--url", &public]), check(&["--url", &operator]), check(&["--behind-proxy", "--url", &operator]))
    })
    .await
    .unwrap();

    let (ok, out) = on_public;
    assert!(ok, "the public listener should pass:\n{out}");
    assert!(out.contains("rand_chainId: 7"), "{out}");
    for m in ["rand_getPeers", "rand_mint", "rand_importViewingKey", "rand_getViewingNotes", "rand_removeViewingKey"] {
        assert!(out.contains(&format!("{m}: refused, gate: node")), "{m} on the public listener:\n{out}");
    }
    assert!(out.contains("batch: refused"), "{out}");
    assert!(out.trim_end().ends_with("public-rpc: ok"), "{out}");

    // A hop that ends at the operator listener: loopback is the operator there.
    let (ok, out) = on_operator;
    assert!(!ok, "the operator listener must fail the check:\n{out}");
    assert!(out.contains("rand_getPeers: SERVED OR NOT GATED"), "{out}");
    assert!(out.contains("batch: SERVED"), "{out}");
    assert!(out.contains("fail: rand_getPeers is not refused: the hop ends at the operator listener"), "{out}");
    assert!(out.trim_end().ends_with("public-rpc: FAIL"), "{out}");
    // --behind-proxy forgives a proxy's own refusal, never a method that answers.
    let (ok, out) = through_proxy_flag;
    assert!(!ok && out.contains("rand_getPeers: SERVED OR NOT GATED"), "--behind-proxy must not pass the operator listener:\n{out}");

    // Nothing listening: it fails rather than passing on silence.
    let (ok, out) = tokio::task::spawn_blocking(|| check(&["--url", "http://127.0.0.1:9"])).await.unwrap();
    assert!(!ok && out.contains("rand_chainId: no answer"), "{out}");

    handle.shutdown().await;
}
