//! `rand-node run --prover`'s lifecycle, through the same `hosted_prover` calls `main.rs` makes:
//! the prover's address is bound before the node opens its database (a port in use fails at
//! once), the prover answers beside a running node, and a prover task that ends stops the node.
//! No proof is made here, so no test takes the proving slot.

use randprotocol_core::genesis::{Genesis, GenesisValidator};
use randprotocol_core::notes::word8_to_hex;
use randprotocol_core::Keypair;
use randprotocol_node::hosted_prover::{self, Options};
use randprotocol_node::node::{self, NodeConfig};
use randprotocol_prover::key::ProverKey;
use randprotocol_prover::pairing::Pairings;
use randprotocol_zkvm::executor::ZkExecutor;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// `wallet_flow.rs`'s one-validator test chain.
fn genesis(validator: &Keypair) -> Genesis {
    Genesis {
        chain_id: 7,
        timestamp_ms: 0,
        validators: vec![GenesisValidator {
            public_key: validator.public_key().clone(),
            stake: randprotocol_core::ledger::staking::MIN_STAKE as u128,
            payout: randprotocol_core::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] }
                .to_string(),
        }],
        alloc: vec![],
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
        bridge: None,
        tokens: None,
        aggregation: None,
        consensus_domain: None,
        staking: None,
        epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
        max_program_words: None,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words: None,
        envelope_bytes: None,
        vesting: None,
        hardening_v6: None,
        hc_auth: None,
        gas: None,
        testnet: None,
        binding_domain: None,
        proof_window_blocks: None,
        program_state: None,
    }
}

/// A prover home as `rand-prover keygen` + `pair` leave it: a key and one pairing.
fn prover_home(home: &Path) -> ProverKey {
    std::fs::create_dir_all(home).unwrap();
    let key = ProverKey::generate();
    key.save_new(&home.join("prover.key.json")).unwrap();
    let mut pairings = Pairings::load(&home.join("pairings.json")).unwrap();
    pairings.pair("laptop", true).unwrap();
    pairings.save(&home.join("pairings.json")).unwrap();
    key
}

fn options(addr: &str, home: &Path) -> Options {
    Options {
        addr: addr.parse().unwrap(),
        rpc: "127.0.0.1:0".parse().unwrap(),
        home: home.to_path_buf(),
        max_parallel: 1,
        max_queue: 4,
        cuda: false,
        // The gate is `rand-prover`'s own, tested there; a test machine need not hold a prover.
        skip_memory_check: true,
        allow_origins: vec![],
        fee: None,
        fee_address: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_hosted_prover_answers_beside_the_node_and_its_exit_stops_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([101; 32]).unwrap();
    let home = dir.path().join("prover");
    let prover_key = prover_home(&home);

    // As `main.rs`: prepare (and bind) first, then the node, then serve.
    let hosted = hosted_prover::prepare(&options("127.0.0.1:0", &home)).expect("prepare");
    let bound = hosted.local_addr().unwrap();
    assert!(!dir.path().join("db").exists(), "prepare opens no database");
    std::fs::write(dir.path().join("genesis.json"), genesis(&key).to_json()).unwrap();
    let handle = node::start(NodeConfig {
        viewing_open: false,
        datadir: dir.path().to_path_buf(),
        seed: *key.seed(),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        enable_mdns: false,
        validator: true,
        block_interval: Duration::from_secs(3),
        base_timeout: Duration::from_secs(6),
        max_timeout: Duration::from_secs(30),
        verify: randprotocol_node::storage::VerifyMode::Full,
        keep_raw_proofs: false,
        min_free_disk_bytes: 0,
        prune_history: None,
        gas_policy: None,
    })
    .await
    .expect("node starts");
    let node_rpc = handle.rpc_addr;
    let (served, prover) = hosted_prover::start(hosted).await.expect("serve");
    assert_eq!(served, bound, "served on the listener prepare bound");
    let abort = prover.task.abort_handle();
    let run = tokio::spawn(hosted_prover::run(handle, Some(prover), std::future::pending::<()>()));

    let http = reqwest::Client::new();
    let info: Value = http
        .post(format!("http://{bound}"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "prover_info", "params": [] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let info = &info["result"];
    assert_eq!(info["kem_fingerprint"], json!(prover_key.fingerprint().to_string()), "{info}");
    assert_eq!(info["witness_kinds"], json!(["viewing_key"]), "viewing-key (v3) jobs only — the spend-key kind is retired (VK-4): {info}");
    assert_eq!(info["allowed_origins"][0], json!("chrome-extension://*"), "no --prover-allow-origin: the default list: {info}");
    // The node's own RPC is up beside it, and knows nothing of `prover_*`.
    let on_node: Value = http
        .post(format!("http://{node_rpc}"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "prover_info", "params": [] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(on_node.get("error").is_some(), "the prover is never a method of the node's RPC: {on_node}");
    assert!(!run.is_finished());

    // The prover's task ends: the node stops, and says why.
    abort.abort();
    let out = tokio::time::timeout(Duration::from_secs(60), run).await.expect("the node stops with its prover").unwrap();
    let e = out.expect_err("a prover that exits is an error").to_string();
    assert!(e.contains("prover listener exited"), "{e}");
    // A fresh client: the pooled keep-alive connection above is its own task and may outlive the listener.
    let fresh = reqwest::Client::new();
    assert!(fresh.post(format!("http://{node_rpc}")).json(&json!({})).send().await.is_err(), "the node's RPC listener is closed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_node_stops_cleanly_on_shutdown_with_its_prover() {
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([102; 32]).unwrap();
    let home = dir.path().join("prover");
    prover_home(&home);
    let hosted = hosted_prover::prepare(&options("127.0.0.1:0", &home)).unwrap();
    let bound = hosted.local_addr().unwrap();
    std::fs::write(dir.path().join("genesis.json"), genesis(&key).to_json()).unwrap();
    let handle = node::start(NodeConfig {
        viewing_open: false,
        datadir: dir.path().to_path_buf(),
        seed: *key.seed(),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        enable_mdns: false,
        validator: true,
        block_interval: Duration::from_secs(3),
        base_timeout: Duration::from_secs(6),
        max_timeout: Duration::from_secs(30),
        verify: randprotocol_node::storage::VerifyMode::Full,
        keep_raw_proofs: false,
        min_free_disk_bytes: 0,
        prune_history: None,
        gas_policy: None,
    })
    .await
    .unwrap();
    let (_, prover) = hosted_prover::start(hosted).await.unwrap();
    let svc = prover.svc.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(hosted_prover::run(handle, Some(prover), async move {
        let _ = stopped.await;
    }));
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(60), run).await.unwrap().unwrap().expect("a requested stop is not an error");
    // The prover's task was aborted on the way out: its port is free again.
    tokio::time::sleep(Duration::from_millis(200)).await;
    std::net::TcpListener::bind(bound).expect("the prover's listener is closed");
    // ... and its queue is shut: a submit is refused before the job is even opened.
    assert!(matches!(svc.submit(&[0u8; 8]), Err(randprotocol_prover::service::Refusal::Bad(why)) if why == "shutting down"));
}

#[test]
fn a_prover_address_in_use_fails_before_the_database_opens() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("prover");
    prover_home(&home);
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap().to_string();

    // The library call...
    let e = hosted_prover::prepare(&options(&addr, &home)).err().expect("a bound port is refused").to_string();
    assert!(e.contains("binding the prover on"), "{e}");

    // ...and the binary, whose prover checks (the bind among them) come before the node key is
    // read and the database opened.
    let out = Command::new(env!("CARGO_BIN_EXE_rand-node"))
        .args(["run", "--datadir"])
        .arg(dir.path())
        .arg("--key")
        .arg(dir.path().join("node.key.json"))
        .args(["--prover", &addr, "--prover-skip-memory-check"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(err.contains("binding the prover on"), "{err}");
    assert!(!dir.path().join("db").exists(), "no database was opened");
    drop(taken);
}

/// `--prover-allow-origin` reaches the listener: the given list is the whole list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hosted_prover_serves_its_origin_list() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("prover");
    prover_home(&home);
    let mut o = options("127.0.0.1:0", &home);
    o.allow_origins = vec!["https://wallet.example".into()];
    let hosted = hosted_prover::prepare(&o).expect("prepare");
    let (bound, served) = hosted_prover::start(hosted).await.expect("serve");
    let http = reqwest::Client::new();
    let post = |origin: &'static str| {
        http.post(format!("http://{bound}"))
            .header("origin", origin)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "prover_info", "params": [] }))
            .send()
    };
    let ok = post("https://wallet.example").await.unwrap();
    assert_eq!(ok.headers()["access-control-allow-origin"], "https://wallet.example");
    let v: Value = ok.json().await.unwrap();
    assert_eq!(v["result"]["allowed_origins"], json!(["https://wallet.example"]), "{v}");
    let refused = post("chrome-extension://abcdefghijklmnopabcdefghijklmnop").await.unwrap();
    assert!(refused.headers().get("access-control-allow-origin").is_none());
    let v: Value = refused.json().await.unwrap();
    assert_eq!(v["error"]["code"], -32007, "{v}");
    served.svc.shutdown();
    served.task.abort();
}

/// `--prover-fee`/`--prover-fee-address` reach the listener: `prover_info` quotes the fee in base
/// units; one flag without the other, or a malformed one, fails at `prepare`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hosted_prover_quotes_its_fee() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("prover");
    prover_home(&home);
    let to = randprotocol_core::notes::ShieldedAddress { pk: [3; 8], kem_ek: vec![7; randprotocol_core::notes::KEM_EK_BYTES] }.to_string();
    let mut o = options("127.0.0.1:0", &home);
    o.fee = Some("0.25".into());
    let e = hosted_prover::prepare(&o).err().expect("a fee without an address").to_string();
    assert!(e.contains("give both or neither"), "{e}");
    o.fee_address = Some("rand1nope".into());
    let e = hosted_prover::prepare(&o).err().expect("a bad address").to_string();
    assert!(e.contains("--prover-fee-address"), "{e}");
    o.fee_address = Some(to.clone());
    let hosted = hosted_prover::prepare(&o).expect("prepare");
    let (bound, served) = hosted_prover::start(hosted).await.expect("serve");
    let v: Value = reqwest::Client::new()
        .post(format!("http://{bound}"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "prover_info", "params": [] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["result"]["fee"], json!({ "amount": "250000000", "address": to }), "{v}");
    served.svc.shutdown();
    served.task.abort();
}
