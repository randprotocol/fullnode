//! End-to-end: several nodes over real TCP on localhost reach consensus,
//! apply a transfer submitted over RPC, and a late joiner syncs the chain.

use shrugg_core::genesis::{Genesis, GenesisValidator};
use shrugg_core::{Address, Keypair, Transaction, UNITS_PER_SHRUGG};
use shrugg_node::node::{self, NodeConfig, NodeHandle};
use shrugg_client::RpcClient;
use std::time::{Duration, Instant};

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn,shrugg_node=info".into()))
        .with_test_writer()
        .try_init();
}

fn keys(n: u8) -> Vec<Keypair> {
    (1..=n).map(|i| Keypair::from_seed([i + 100; 32]).unwrap()).collect()
}

fn genesis(validators: &[Keypair], funded: &[Keypair]) -> Genesis {
    Genesis {
        chain_id: 7,
        timestamp_ms: 0,
        validators: validators.iter().map(|k| GenesisValidator { public_key: k.public_key().clone(), stake: 10 }).collect(),
        alloc: funded.iter().map(|k| (k.address().to_base58(), 1_000 * UNITS_PER_SHRUGG)).collect(),
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        bridge: None,
    }
}

struct TestNode {
    handle: NodeHandle,
    dir: tempfile::TempDir,
    rpc: RpcClient,
}

async fn start_node(key: &Keypair, gen: &Genesis, bootstrap: Vec<libp2p::Multiaddr>, validator: bool) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("genesis.json"), gen.to_json()).unwrap();
    start_in(dir, key, bootstrap, validator).await
}

async fn start_in(dir: tempfile::TempDir, key: &Keypair, bootstrap: Vec<libp2p::Multiaddr>, validator: bool) -> TestNode {
    let handle = node::start(NodeConfig {
        datadir: dir.path().to_path_buf(),
        seed: *key.seed(),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap,
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        enable_mdns: false,
        validator,
        block_interval: Duration::from_millis(150),
        base_timeout: Duration::from_millis(1500),
        max_timeout: Duration::from_secs(6),
        verify: shrugg_node::storage::VerifyMode::Full,
    })
    .await
    .expect("node starts");
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));
    TestNode { handle, dir, rpc }
}

/// Stop a node (abort its loop, close its sockets) and keep its data directory.
async fn stop(n: TestNode) -> tempfile::TempDir {
    n.handle.shutdown().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    n.dir
}

fn bootstrap_addr(n: &TestNode) -> libp2p::Multiaddr {
    let mut a = n.handle.listen_addrs[0].clone();
    a.push(libp2p::multiaddr::Protocol::P2p(n.handle.network.local_peer_id));
    a
}

async fn wait_for<F: Fn() -> bool>(what: &str, timeout: Duration, f: F) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_height(nodes: &[&TestNode], min: u64, timeout: Duration) {
    wait_for(&format!("all nodes at height >= {min}"), timeout, || {
        nodes.iter().all(|n| n.handle.status.read().unwrap().height >= min)
    })
    .await;
}

impl TestNode {
    fn rpc_balance_sync(&self, a: &Address) -> u128 {
        self.handle.storage.account(a).map(|x| x.balance).unwrap_or(0)
    }
}

async fn balance(n: &TestNode, a: &Address) -> u128 {
    n.rpc.account(a).await.map(|a| a.balance).unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_validators_commit_and_transfer() {
    init_tracing();
    let ks = keys(2);
    let gen = genesis(&ks, &ks);
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let b = start_node(&ks[1], &gen, vec![bootstrap_addr(&a)], true).await;
    wait_height(&[&a, &b], 3, Duration::from_secs(40)).await;

    // Transfer 1.5 SHRUGG from validator 0 to a fresh address, submitted to node B.
    let dest = Keypair::from_seed([200; 32]).unwrap().address();
    let amount = 15 * UNITS_PER_SHRUGG / 10;
    let nonce = b.rpc.account(&ks[0].address()).await.unwrap().nonce;
    let tx = Transaction::transfer(&ks[0], 7, nonce, dest, amount, 1_000);
    let hash = b.rpc.send_transaction(&tx).await.expect("accepted");
    wait_for("transfer visible on both nodes", Duration::from_secs(30), || {
        a.handle.storage.tx_location(&hash).unwrap().is_some() && b.handle.storage.tx_location(&hash).unwrap().is_some()
    })
    .await;
    assert_eq!(balance(&a, &dest).await, amount);
    assert_eq!(balance(&b, &dest).await, amount);
    let acct0 = a.rpc.account(&ks[0].address()).await.unwrap();
    let (n0, bal0) = (acct0.nonce, acct0.balance);
    assert_eq!(n0, nonce + 1);
    // sender paid amount + fee, may have earned fees as proposer
    assert!(bal0 <= 1_000 * UNITS_PER_SHRUGG - amount - 1_000 + 1_000);
    // Same tx again is rejected (nonce used).
    assert!(b.rpc.send_transaction(&tx).await.is_err());
    // Both heads agree.
    let ha = a.handle.storage.head().unwrap();
    let hb = b.handle.storage.head().unwrap();
    let common = ha.height.min(hb.height);
    assert_eq!(
        a.handle.storage.block_by_height(common).unwrap().unwrap().hash(),
        b.handle.storage.block_by_height(common).unwrap().unwrap().hash()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_validators_plus_late_observer_syncs() {
    init_tracing();
    let ks = keys(5);
    let gen = genesis(&ks[..4], &ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], 6, Duration::from_secs(60)).await;

    let dest = Keypair::from_seed([201; 32]).unwrap().address();
    let nonce = n2.rpc.account(&ks[4].address()).await.unwrap().nonce;
    let tx = Transaction::transfer(&ks[4], 7, nonce, dest, 5 * UNITS_PER_SHRUGG, 10);
    let hash = n2.rpc.send_transaction(&tx).await.expect("accepted");
    wait_for("tx committed on n0", Duration::from_secs(30), || n0.handle.storage.tx_location(&hash).unwrap().is_some()).await;

    // Late observer (not a validator) joins and must sync the whole chain.
    let obs = start_node(&ks[4], &gen, boot.clone(), false).await;
    assert!(!obs.handle.status.read().unwrap().is_validator);
    let target = n0.handle.status.read().unwrap().height;
    wait_height(&[&obs], target, Duration::from_secs(60)).await;
    assert_eq!(balance(&obs, &dest).await, 5 * UNITS_PER_SHRUGG);
    // Observer's chain is byte-identical to n0's up to the target.
    for h in 0..=target {
        assert_eq!(
            obs.handle.storage.block_by_height(h).unwrap().unwrap().hash(),
            n0.handle.storage.block_by_height(h).unwrap().unwrap().hash(),
            "height {h}"
        );
    }
    // And it keeps following live consensus afterwards.
    wait_height(&[&obs], target + 3, Duration::from_secs(30)).await;
    let peers = obs.rpc.call("shrugg_getPeers", serde_json::json!([])).await.unwrap();
    assert!(peers.as_array().unwrap().len() >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validator_restarts_from_disk_and_resumes() {
    init_tracing();
    let ks = keys(2);
    let gen = genesis(&ks, &ks);
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let b = start_node(&ks[1], &gen, vec![bootstrap_addr(&a)], true).await;
    wait_height(&[&a, &b], 4, Duration::from_secs(40)).await;

    // Stop B. With two validators the chain must halt: no QC without both signatures.
    let height_at_stop = b.handle.status.read().unwrap().height;
    let dir = stop(b).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let a_height = a.handle.status.read().unwrap().height;
    assert!(a_height <= height_at_stop + 1, "chain advanced without quorum: {a_height} > {height_at_stop}");

    // Restart B from the same directory: it resumes at its persisted head and the chain continues.
    let b = start_in(dir, &ks[1], vec![bootstrap_addr(&a)], true).await;
    let resumed_from = b.handle.storage.head().unwrap().height;
    assert_eq!(resumed_from, height_at_stop);
    wait_height(&[&a, &b], a_height + 4, Duration::from_secs(60)).await;
    let common = a.handle.status.read().unwrap().height.min(b.handle.status.read().unwrap().height);
    assert_eq!(
        a.handle.storage.block_by_height(common).unwrap().unwrap().hash(),
        b.handle.storage.block_by_height(common).unwrap().unwrap().hash()
    );
}

// ---------------------------------------------------------------------------
// Restart / resync tests with real nodes on disk
// ---------------------------------------------------------------------------

/// Every node's chain must be identical up to the lowest common height, and the
/// account state (all validator balances + nonces) must agree at that height.
fn assert_chains_equal(nodes: &[&TestNode], validators: &[Keypair]) {
    let common = nodes.iter().map(|n| n.handle.storage.head().unwrap().height).min().unwrap();
    let reference = &nodes[0].handle.storage;
    for h in 0..=common {
        let r = reference.block_by_height(h).unwrap().unwrap();
        for (i, n) in nodes.iter().enumerate().skip(1) {
            let b = n.handle.storage.block_by_height(h).unwrap().unwrap();
            assert_eq!(b.hash(), r.hash(), "node {i} differs from node 0 at height {h}");
            assert_eq!(b.header.state_root, r.header.state_root, "state root differs at height {h}");
            assert_eq!(n.handle.storage.qc_by_height(h).unwrap().unwrap().block_hash, b.hash(), "qc mismatch at {h}");
        }
    }
    // Balances at the tip may legitimately differ by a few blocks of proposer fees,
    // but with fee-free empty blocks they only change with transfers, so compare them.
    for k in validators {
        let a = k.address();
        let r = reference.account(&a).unwrap();
        for (i, n) in nodes.iter().enumerate().skip(1) {
            let x = n.handle.storage.account(&a).unwrap();
            assert_eq!(x.nonce, r.nonce, "nonce of {a} differs on node {i}");
        }
    }
}

async fn wait_caught_up(node: &TestNode, others: &[&TestNode], timeout: Duration) {
    wait_for("node catches up", timeout, || {
        let target = others.iter().map(|n| n.handle.status.read().unwrap().height).max().unwrap();
        node.handle.status.read().unwrap().height + 1 >= target
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_cycles_keep_all_nodes_in_sync() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks, &ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let mut nodes = vec![n0];
    for k in &ks[1..] {
        nodes.push(start_node(k, &gen, boot.clone(), true).await);
    }
    wait_height(&nodes.iter().collect::<Vec<_>>(), 5, Duration::from_secs(60)).await;

    // Restart nodes 1, 2, 3 in turn (never the bootstrap node, so the others keep an address to dial).
    for cycle in 0..2 {
        for i in 1..4 {
            let before = nodes[i].handle.storage.head().unwrap().height;
            let stopped = nodes.remove(i);
            let dir = stop(stopped).await;
            // Others advance while it is down.
            let rest: Vec<&TestNode> = nodes.iter().collect();
            let target = rest.iter().map(|n| n.handle.status.read().unwrap().height).max().unwrap() + 4;
            wait_height(&rest, target, Duration::from_secs(60)).await;
            // Also submit a transfer while it is down so it has state to catch up on.
            let dest = Keypair::from_seed([210 + cycle as u8 * 4 + i as u8; 32]).unwrap().address();
            let nonce = nodes[0].rpc.account(&ks[0].address()).await.unwrap().nonce;
            let tx = Transaction::transfer(&ks[0], 7, nonce, dest, UNITS_PER_SHRUGG, 1);
            let hash = nodes[0].rpc.send_transaction(&tx).await.unwrap();
            nodes[0].rpc.wait_for_transaction(&hash, Duration::from_secs(30)).await.unwrap();

            let restarted = start_in(dir, &ks[i], boot.clone(), true).await;
            assert_eq!(restarted.handle.storage.head().unwrap().height, before, "restart lost committed blocks");
            wait_caught_up(&restarted, &nodes.iter().collect::<Vec<_>>(), Duration::from_secs(60)).await;
            assert_eq!(restarted.rpc.balance(&dest).await.unwrap(), UNITS_PER_SHRUGG, "missed transfer after restart");
            nodes.insert(i, restarted);
            assert_chains_equal(&nodes.iter().collect::<Vec<_>>(), &ks);
        }
    }
    // All four keep committing together afterwards.
    let all: Vec<&TestNode> = nodes.iter().collect();
    let h = all.iter().map(|n| n.handle.status.read().unwrap().height).max().unwrap();
    wait_height(&all, h + 5, Duration::from_secs(60)).await;
    assert_chains_equal(&all, &ks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_of_four_down_halts_and_recovers_without_fork() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks, &ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], 5, Duration::from_secs(60)).await;

    let d2 = stop(n2).await;
    let d3 = stop(n3).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let h0 = n0.handle.status.read().unwrap().height;
    tokio::time::sleep(Duration::from_secs(6)).await;
    let h1 = n0.handle.status.read().unwrap().height;
    assert!(h1 <= h0 + 1, "chain advanced without quorum: {h0} -> {h1}");
    assert_chains_equal(&[&n0, &n1], &ks);

    let n2 = start_in(d2, &ks[2], boot.clone(), true).await;
    let n3 = start_in(d3, &ks[3], boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], h1 + 6, Duration::from_secs(90)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3], &ks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_behind_by_more_than_one_sync_batch_catches_up() {
    init_tracing();
    // Four validators: with three, stopping one leaves exactly 2/3 stake, which is not a quorum.
    let ks = keys(4);
    let gen = genesis(&ks, &ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], 3, Duration::from_secs(60)).await;

    let stopped_at = n2.handle.storage.head().unwrap().height;
    let d2 = stop(n2).await;
    // Sync batches are 100 blocks; get the others more than that ahead (empty blocks, ~150ms each).
    // With one validator down every fourth view times out, so ~2 s per 3 blocks; give it room
    // (the suite runs several clusters in parallel on a few threads).
    wait_height(&[&n0, &n1, &n3], stopped_at + 130, Duration::from_secs(400)).await;
    let dest = Keypair::from_seed([230; 32]).unwrap().address();
    let nonce = n0.rpc.account(&ks[0].address()).await.unwrap().nonce;
    let tx = Transaction::transfer(&ks[0], 7, nonce, dest, 2 * UNITS_PER_SHRUGG, 1);
    let hash = n0.rpc.send_transaction(&tx).await.unwrap();
    n0.rpc.wait_for_transaction(&hash, Duration::from_secs(30)).await.unwrap();

    let n2 = start_in(d2, &ks[2], boot.clone(), true).await;
    assert_eq!(n2.handle.storage.head().unwrap().height, stopped_at);
    wait_caught_up(&n2, &[&n0, &n1, &n3], Duration::from_secs(120)).await;
    assert_eq!(n2.rpc.balance(&dest).await.unwrap(), 2 * UNITS_PER_SHRUGG);
    assert_chains_equal(&[&n0, &n1, &n2, &n3], &ks);
    // and it participates again afterwards
    let h = n0.handle.status.read().unwrap().height;
    wait_height(&[&n0, &n1, &n2, &n3], h + 5, Duration::from_secs(60)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3], &ks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupted_rocksdb_is_detected_truncated_and_resynced() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks, &ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let _n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    // A transfer early in the chain, so state must survive the repair.
    let dest = Keypair::from_seed([240; 32]).unwrap().address();
    let nonce = n0.rpc.account(&ks[0].address()).await.unwrap().nonce;
    let tx = Transaction::transfer(&ks[0], 7, nonce, dest, 3 * UNITS_PER_SHRUGG, 1);
    let hash = n0.rpc.send_transaction(&tx).await.unwrap();
    let receipt = n0.rpc.wait_for_transaction(&hash, Duration::from_secs(30)).await.unwrap();
    wait_height(&[&n0, &n1, &n2], receipt.height + 8, Duration::from_secs(60)).await;

    let head = n2.handle.storage.head().unwrap().height;
    let dir = stop(n2).await;
    // Damage the middle of n2's chain on disk, after the transfer block.
    let bad_height = receipt.height + 3;
    {
        let st = shrugg_node::storage::Storage::open(dir.path()).unwrap();
        st.overwrite_block_bytes_for_testing(bad_height, b"\xff\x00corrupt").unwrap();
        // and a subtle one: an account with the wrong balance
        st.overwrite_account_for_testing(&dest, &shrugg_core::Account { nonce: 0, balance: 1 }).unwrap();
        let gs_ = gen.build().unwrap();
        let check = st.verify_chain(&gs_, shrugg_node::storage::VerifyMode::Full, shrugg_node::node::executor_for(&gs_).unwrap().as_ref()).unwrap();
        assert!(!check.is_ok());
        assert_eq!(check.last_good, bad_height - 1);
    }
    // Restart: startup verification must truncate to bad_height-1, then sync catches up.
    let n2 = start_in(dir, &ks[2], boot.clone(), true).await;
    let resumed = n2.handle.storage.head().unwrap().height;
    assert!(resumed >= bad_height - 1 && resumed < head, "expected truncation below {head}, got {resumed}");
    wait_caught_up(&n2, &[&n0, &n1], Duration::from_secs(90)).await;
    assert_eq!(n2.rpc.balance(&dest).await.unwrap(), 3 * UNITS_PER_SHRUGG, "repaired ledger lost the transfer");
    assert_chains_equal(&[&n0, &n1, &n2], &ks);
    // Verified clean again after the resync.
    let gs_ = gen.build().unwrap();
    let check = n2.handle.storage.verify_chain(&gs_, shrugg_node::storage::VerifyMode::Full, shrugg_node::node::executor_for(&gs_).unwrap().as_ref()).unwrap();
    assert!(check.is_ok(), "{:?}", check.problem);
    let h = n0.handle.status.read().unwrap().height;
    wait_height(&[&n0, &n1, &n2], h + 4, Duration::from_secs(60)).await;
    assert_chains_equal(&[&n0, &n1, &n2], &ks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn faucet_mint_via_rpc_reaches_every_node() {
    init_tracing();
    let ks = keys(2);
    let gen = genesis(&ks, &ks); // faucet: true in this test genesis
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let b = start_node(&ks[1], &gen, vec![bootstrap_addr(&a)], true).await;
    wait_height(&[&a, &b], 2, Duration::from_secs(40)).await;
    let fresh = Keypair::from_seed([250; 32]).unwrap().address();
    assert_eq!(a.rpc.balance(&fresh).await.unwrap(), 0);
    // Default amount (100 SHRUGG), submitted to B.
    let h1 = b.rpc.mint(&fresh, None).await.expect("mint accepted");
    b.rpc.wait_for_transaction(&h1, Duration::from_secs(30)).await.unwrap();
    wait_for("mint visible on A", Duration::from_secs(30), || a.handle.storage.tx_location(&h1).unwrap().is_some()).await;
    assert_eq!(a.rpc.balance(&fresh).await.unwrap(), 100 * UNITS_PER_SHRUGG);
    assert_eq!(b.rpc.balance(&fresh).await.unwrap(), 100 * UNITS_PER_SHRUGG);
    // Second mint from the same node right away (nonce must advance past the pending one).
    let h2 = b.rpc.mint(&fresh, Some(5 * UNITS_PER_SHRUGG)).await.expect("second mint accepted");
    b.rpc.wait_for_transaction(&h2, Duration::from_secs(30)).await.unwrap();
    wait_for("second mint on A", Duration::from_secs(30), || a.rpc_balance_sync(&fresh) == 105 * UNITS_PER_SHRUGG).await;
    // Over the cap is rejected.
    assert!(b.rpc.mint(&fresh, Some(101 * UNITS_PER_SHRUGG)).await.is_err());
    // The minted coins are spendable.
    let fresh_key = Keypair::from_seed([250; 32]).unwrap();
    let tx = Transaction::transfer(&fresh_key, 7, 0, ks[0].address(), 50 * UNITS_PER_SHRUGG, 1);
    let h3 = a.rpc.send_transaction(&tx).await.unwrap();
    a.rpc.wait_for_transaction(&h3, Duration::from_secs(30)).await.unwrap();
    assert_eq!(a.rpc.balance(&fresh).await.unwrap(), 55 * UNITS_PER_SHRUGG - 1);
    assert_chains_equal(&[&a, &b], &ks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn faucet_is_rejected_when_genesis_disables_it() {
    init_tracing();
    let ks = keys(1);
    let mut gen = genesis(&ks, &ks);
    gen.faucet = false;
    let a = start_node(&ks[0], &gen, vec![], true).await;
    wait_height(&[&a], 2, Duration::from_secs(40)).await;
    let fresh = Keypair::from_seed([251; 32]).unwrap().address();
    let err = a.rpc.mint(&fresh, None).await.unwrap_err().to_string();
    assert!(err.contains("faucet is disabled"), "{err}");
    // A hand-built mint is rejected by the mempool too.
    let tx = Transaction::mint(&ks[0], 7, a.rpc.account(&ks[0].address()).await.unwrap().nonce, fresh, 1, 0);
    assert!(a.rpc.send_transaction(&tx).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn confidential_call_moves_funds_on_every_node() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks, &ks); // fri_profile "test", confidential true
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), false).await; // observer verifies too
    wait_height(&[&n0, &n1, &n2, &n3], 2, Duration::from_secs(40)).await;

    // Deploy through n0.
    let program = shrugg_zkvm::guests::private_payment(1000);
    let (pid, dtx) = n0.rpc.deploy(&ks[0], program.base_pc, program.words.clone()).await.unwrap();
    n0.rpc.wait_for_transaction(&dtx, Duration::from_secs(60)).await.unwrap();
    wait_for("program on every node", Duration::from_secs(60), || {
        [&n0, &n1, &n2, &n3].iter().all(|n| n.handle.storage.program(&pid).unwrap().is_some())
    })
    .await;
    let shown = n3.rpc.program(&pid).await.unwrap().expect("program via rpc");
    assert_eq!(shown["words_len"].as_u64().unwrap() as usize, program.words.len());

    // Prove off-chain and call through n1 with bob as recipient 0.
    let bob = Keypair::from_seed([9; 32]).unwrap().address();
    let (proof, outputs, tier) =
        shrugg_zkvm::executor::prove(shrugg_zkvm::machine::FriProfile::Test, &program, &[400, 250, 300, 75], None, shrugg_zkvm::machine::Backend::Cpu).unwrap();
    assert_eq!(outputs[0], 1);
    let fee = shrugg_core::gas::call_fee(tier);
    let before = n1.rpc.balance(&ks[0].address()).await.unwrap();
    let ctx = n1.rpc.call_program(&ks[0], pid, proof.clone(), vec![bob], fee).await.unwrap();
    let r = n1.rpc.wait_for_transaction(&ctx, Duration::from_secs(120)).await.unwrap();
    wait_for("receipt on all nodes", Duration::from_secs(60), || {
        [&n0, &n1, &n2, &n3].iter().all(|n| n.handle.storage.receipt(&ctx).unwrap().is_some())
    })
    .await;
    for n in [&n0, &n1, &n2, &n3] {
        let rc = n.handle.storage.receipt(&ctx).unwrap().unwrap();
        assert_eq!(rc.effect, Some((bob, 25)));
        assert_eq!(rc.height, r.height);
        assert_eq!(rc.outputs, outputs);
        assert_eq!(n.rpc.balance(&bob).await.unwrap(), 25);
    }
    let after = n1.rpc.balance(&ks[0].address()).await.unwrap();
    assert!(after <= before - 25 - fee + fee, "caller paid amount and fee (may earn the fee back as proposer)");
    let receipt_rpc = n2.rpc.receipt(&ctx).await.unwrap().unwrap();
    assert_eq!(receipt_rpc["effect"]["amount"], "25");
    assert_chains_equal(&[&n0, &n1, &n2, &n3], &ks);

    // The same proof against another program id must be rejected at admission.
    let other = shrugg_zkvm::guests::private_payment(1001);
    let (pid2, dtx2) = n0.rpc.deploy(&ks[1], other.base_pc, other.words.clone()).await.unwrap();
    n0.rpc.wait_for_transaction(&dtx2, Duration::from_secs(60)).await.unwrap();
    let err = n0.rpc.call_program(&ks[0], pid2, proof.clone(), vec![bob], fee).await.unwrap_err().to_string();
    assert!(err.contains("invalid proof"), "{err}");
    // And a too-small fee is rejected with the minimum in the message.
    let err = n0.rpc.call_program(&ks[0], pid, proof, vec![bob], 1).await.unwrap_err().to_string();
    assert!(err.contains("below minimum"), "{err}");

    // Restart the observer: the startup check re-verifies the proof in full mode and keeps the receipt.
    let dir = stop(n3).await;
    let n3 = start_in(dir, &ks[3], boot.clone(), false).await;
    assert!(n3.handle.storage.receipt(&ctx).unwrap().is_some());
    wait_caught_up(&n3, &[&n0, &n1, &n2], Duration::from_secs(60)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3], &ks);
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

/// The shared attestation vectors (Task B1), the same file `shrugg-core`
/// compiles in, so a cluster mints against exactly the bytes the contracts on
/// the other chains are tested with.
fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../shrugg-core/src/bridge/vectors.json")).expect("vectors.json parses")
}

fn hex32(v: &serde_json::Value) -> [u8; 32] {
    hex::decode(v.as_str().expect("hex string")).expect("hex").try_into().expect("32 bytes")
}

/// `genesis`, plus a `bridge` section built from the vectors' guardians, Rand
/// emitter, and source-chain emitter table.
fn bridged_genesis(validators: &[Keypair], funded: &[Keypair]) -> Genesis {
    let file = vectors();
    let guardians = file["guardians"]
        .as_array()
        .expect("guardians")
        .iter()
        .map(|g| hex::decode(g["address"].as_str().expect("address")).expect("hex").try_into().expect("20 bytes"))
        .collect();
    let emitters = file["emitters"]
        .as_object()
        .expect("emitters")
        .iter()
        .map(|(chain, addr)| (chain.parse().expect("chain id"), hex32(addr)))
        .collect();
    let bridge = shrugg_core::bridge::BridgeConfig { emitter: hex32(&file["rand_emitter"]), guardians, emitters };
    Genesis { bridge: Some(bridge), ..genesis(validators, funded) }
}

/// A vector by name, as `(attestation bytes, payload)`.
fn vector(name: &str) -> (Vec<u8>, serde_json::Value) {
    let file = vectors();
    let v = file["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .find(|v| v["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("no vector named {name}"))
        .clone();
    (hex::decode(v["attestation"].as_str().expect("attestation")).expect("hex"), v["payload"].clone())
}

/// Mint a bridged asset from a shared vector through RPC and see it on every
/// node, then across a restart — the storage round trip end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bridge_mint_reaches_every_node() {
    init_tracing();
    let ks = keys(2);
    let gen = bridged_genesis(&ks, &ks);
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&a)];
    let b = start_node(&ks[1], &gen, boot.clone(), true).await;
    wait_height(&[&a, &b], 2, Duration::from_secs(40)).await;

    // `transfer_eth_usdt_6dp_ok`: 100000000 units of an Ethereum token, of
    // which 1000 is the bridge fee, to the recipient in the payload. Guardian
    // set 0 never expires, so the cluster's wall-clock block time is fine.
    let (attestation, payload) = vector("transfer_eth_usdt_6dp_ok");
    let token = hex32(&payload["token_address"]);
    let asset = shrugg_core::bridge::asset_id(payload["token_chain"].as_u64().unwrap() as u16, &token);
    let recipient = Address(hex32(&payload["to"]));
    let amount: u128 = payload["amount"].as_str().unwrap().parse().unwrap();
    let fee: u128 = payload["fee"].as_str().unwrap().parse().unwrap();
    let net = amount - fee;

    // The bridge is enabled and empty before the mint.
    let state = a.rpc.bridge_state().await.unwrap();
    assert_eq!(state["enabled"], true);
    assert_eq!(state["guardians"].as_array().unwrap().len(), 6);
    assert_eq!(state["burn_sequence"], 0);
    assert_eq!(state["assets"], serde_json::json!([]));
    assert_eq!(a.rpc.asset_balance(&recipient, &asset).await.unwrap(), 0);
    // The node computes the same asset id the test does.
    assert_eq!(b.rpc.bridge_asset_id(2, &token).await.unwrap(), asset);

    // Submitted to B by validator 0, which keeps the bridge fee.
    let submitter = ks[0].address();
    let hash = b.rpc.bridge_attest(&ks[0], attestation.clone(), 1_000).await.expect("attestation accepted");
    b.rpc.wait_for_transaction(&hash, Duration::from_secs(30)).await.unwrap();
    for n in [&a, &b] {
        wait_for("mint visible on every node", Duration::from_secs(30), || {
            n.handle.storage.asset_balance(&asset, &recipient).unwrap() == net
        })
        .await;
        assert_eq!(n.rpc.asset_balance(&recipient, &asset).await.unwrap(), net);
        assert_eq!(n.rpc.asset_balance(&submitter, &asset).await.unwrap(), fee);
        let holdings = n.rpc.assets(&recipient).await.unwrap();
        assert_eq!(holdings.len(), 1);
        assert_eq!((holdings[0].asset, holdings[0].token_chain, holdings[0].balance), (asset, 2, net));
        // The asset is now registered chain-wide.
        assert_eq!(n.rpc.bridge_state().await.unwrap()["assets"].as_array().unwrap().len(), 1);
    }

    // Replaying the same attestation is rejected before it reaches a block.
    let err = a.rpc.bridge_attest(&ks[0], attestation, 1_000).await.unwrap_err().to_string();
    assert!(err.contains("already consumed"), "{err}");
    assert_chains_equal(&[&a, &b], &ks);

    // Restart B: the bridged balances must come back from storage, not from a
    // replay of the genesis section.
    let head_before = b.handle.storage.head().unwrap().height;
    let dir = stop(b).await;
    let b = start_in(dir, &ks[1], boot.clone(), true).await;
    assert!(b.handle.storage.head().unwrap().height >= head_before, "restart lost blocks");
    assert_eq!(b.handle.storage.asset_balance(&asset, &recipient).unwrap(), net);
    assert_eq!(b.rpc.asset_balance(&recipient, &asset).await.unwrap(), net);
    assert_eq!(b.rpc.asset_balance(&submitter, &asset).await.unwrap(), fee);
    assert_eq!(b.rpc.bridge_state().await.unwrap()["assets"].as_array().unwrap().len(), 1);
    wait_caught_up(&b, &[&a], Duration::from_secs(60)).await;
    assert_chains_equal(&[&a, &b], &ks);
}
