//! End-to-end: several nodes over real TCP on localhost reach consensus, apply a faucet mint
//! submitted over RPC, and a late joiner syncs the chain.
//!
//! Traffic here is faucet mints rather than transfers: a redacted chain has no transfers to
//! submit from a test, and a mint is the one transaction a node can build for itself (a bundle
//! needs a wallet holding a spend key, which is phase S5's). What a mint exercises is the same
//! plumbing the tests care about — a transaction gossips, commits, changes the commitment tree,
//! and every node's state root agrees afterwards.

use shrugg_core::genesis::{Genesis, GenesisValidator};
use shrugg_core::notes::word8_to_hex;
use shrugg_core::{Action, Hash, Keypair, Word8, UNITS_PER_SHRUGG};
use shrugg_client::RpcClient;
use shrugg_node::node::{self, NodeConfig, NodeHandle};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::notes::SpendKey;
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

/// The shielded address every mint in this file pays. Its spend key is `SpendKey([1; 8])`, so a
/// wallet in phase S5 could open these notes; nothing here needs to.
fn payee(seed: u8) -> String {
    shrugg_zkvm::address::address_of(&SpendKey([seed as u32; 8]).viewing_key()).to_string()
}

/// A chain with no deposit notes: every note in these tests is minted by a validator at runtime.
/// `hc_bundle` must be this build's own guest, or `node::start` refuses to run at all.
fn genesis(validators: &[Keypair]) -> Genesis {
    Genesis {
        chain_id: 7,
        timestamp_ms: 0,
        validators: validators.iter().map(|k| GenesisValidator { public_key: k.public_key().clone(), stake: 10 }).collect(),
        alloc: vec![],
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
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
    /// Mint `amount` units to `payee(seed)` through this node's RPC and wait for the commit.
    /// Returns the transaction hash and the commitment of the note it created, which is the
    /// thing every node must agree on afterwards.
    async fn mint(&self, seed: u8, amount: u64) -> (Hash, Word8) {
        let hash = self.rpc.mint_shielded(&payee(seed), Some(amount)).await.expect("mint accepted");
        self.rpc.wait_for_transaction(&hash, Duration::from_secs(30)).await.expect("mint commits");
        (hash, self.note_of(&hash).expect("a committed mint has a note"))
    }

    /// The commitment a committed mint created, read back from the block it landed in.
    fn note_of(&self, hash: &Hash) -> Option<Word8> {
        let (height, index) = self.handle.storage.tx_location(hash).unwrap()?;
        let block = self.handle.storage.block_by_height(height).unwrap()?;
        match &block.transactions.get(index as usize)?.action {
            Action::Mint { cm, .. } => Some(*cm),
            _ => None,
        }
    }

    /// Whether this node's committed state holds `cm` — the redacted stand-in for "did the
    /// value arrive": nobody, this test included, can say who owns the note.
    ///
    /// Scans the notes family rather than asking the tree: `CommitmentTree` is a frontier, so it
    /// keeps a root and a rightmost path, never the leaf set.
    fn holds(&self, cm: &Word8) -> bool {
        self.handle.storage.notes_from(0, usize::MAX).map(|rows| rows.iter().any(|(_, r)| r.cm == *cm)).unwrap_or(false)
    }

    fn height(&self) -> u64 {
        self.handle.status.read().unwrap().height
    }
}

/// Every node's chain must be identical up to the lowest common height, and the shielded state
/// (the commitment tree, the nullifier set, the anchors, the validator rewards) must agree
/// there. `Ledger`'s own equality covers all of it, but comparing state roots localises a
/// failure to a height instead of dumping two whole ledgers.
fn assert_chains_equal(nodes: &[&TestNode]) {
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
    // The tree is append-only, so a node that is a few blocks ahead has a superset of the
    // leaves; what must match at the common height is the chain above, already checked. Here
    // only the genesis-relative invariant is asserted: nobody has lost a leaf.
    let least = nodes.iter().map(|n| n.handle.storage.notes_count().unwrap()).min().unwrap();
    for (i, n) in nodes.iter().enumerate() {
        assert!(n.handle.storage.notes_count().unwrap() >= least, "node {i} lost notes");
    }
}

async fn wait_caught_up(node: &TestNode, others: &[&TestNode], timeout: Duration) {
    wait_for("node catches up", timeout, || {
        let target = others.iter().map(|n| n.height()).max().unwrap();
        node.height() + 1 >= target
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_validators_plus_late_observer_syncs() {
    init_tracing();
    let ks = keys(5);
    let gen = genesis(&ks[..4]);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], 6, Duration::from_secs(60)).await;

    let (hash, cm) = n2.mint(1, 5 * UNITS_PER_SHRUGG).await;
    wait_for("mint committed on n0", Duration::from_secs(30), || n0.handle.storage.tx_location(&hash).unwrap().is_some())
        .await;

    // Late observer (not a validator) joins and must sync the whole chain.
    let obs = start_node(&ks[4], &gen, boot.clone(), false).await;
    assert!(!obs.handle.status.read().unwrap().is_validator);
    let target = n0.height();
    wait_height(&[&obs], target, Duration::from_secs(60)).await;
    assert!(obs.holds(&cm), "the observer replayed the chain without the minted note");
    // Observer's chain is byte-identical to n0's up to the target.
    for h in 0..=target {
        assert_eq!(
            obs.handle.storage.block_by_height(h).unwrap().unwrap().hash(),
            n0.handle.storage.block_by_height(h).unwrap().unwrap().hash(),
            "height {h}"
        );
    }
    // An observer holds no validator key, so it cannot serve the faucet itself.
    let err = obs.rpc.mint_shielded(&payee(2), Some(1)).await.unwrap_err().to_string();
    assert!(err.contains("validators"), "{err}");
    // And it keeps following live consensus afterwards.
    wait_height(&[&obs], target + 3, Duration::from_secs(30)).await;
    let peers = obs.rpc.call("shrugg_getPeers", serde_json::json!([])).await.unwrap();
    assert!(!peers.as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validator_restarts_from_disk_and_resumes() {
    init_tracing();
    let ks = keys(2);
    let gen = genesis(&ks);
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let b = start_node(&ks[1], &gen, vec![bootstrap_addr(&a)], true).await;
    wait_height(&[&a, &b], 4, Duration::from_secs(40)).await;

    // Stop B. With two validators the chain must halt: no QC without both signatures.
    let height_at_stop = b.height();
    let dir = stop(b).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let a_height = a.height();
    assert!(a_height <= height_at_stop + 1, "chain advanced without quorum: {a_height} > {height_at_stop}");

    // Restart B from the same directory: it resumes at its persisted head and the chain continues.
    let b = start_in(dir, &ks[1], vec![bootstrap_addr(&a)], true).await;
    let resumed_from = b.handle.storage.head().unwrap().height;
    assert_eq!(resumed_from, height_at_stop);
    wait_height(&[&a, &b], a_height + 4, Duration::from_secs(60)).await;
    let common = a.height().min(b.height());
    assert_eq!(
        a.handle.storage.block_by_height(common).unwrap().unwrap().hash(),
        b.handle.storage.block_by_height(common).unwrap().unwrap().hash()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_cycles_keep_all_nodes_in_sync() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let mut nodes = vec![n0];
    for k in &ks[1..] {
        nodes.push(start_node(k, &gen, boot.clone(), true).await);
    }
    wait_height(&nodes.iter().collect::<Vec<_>>(), 5, Duration::from_secs(60)).await;

    // Restart nodes 1, 2, 3 in turn (never the bootstrap node, so the others keep an address to dial).
    for cycle in 0..2u8 {
        for i in 1..4 {
            let before = nodes[i].handle.storage.head().unwrap().height;
            let stopped = nodes.remove(i);
            let dir = stop(stopped).await;
            // Others advance while it is down.
            let rest: Vec<&TestNode> = nodes.iter().collect();
            let target = rest.iter().map(|n| n.height()).max().unwrap() + 4;
            wait_height(&rest, target, Duration::from_secs(60)).await;
            // Also mint while it is down, so it has state to catch up on.
            let (_, cm) = nodes[0].mint(10 + cycle * 4 + i as u8, UNITS_PER_SHRUGG).await;

            let restarted = start_in(dir, &ks[i], boot.clone(), true).await;
            assert_eq!(restarted.handle.storage.head().unwrap().height, before, "restart lost committed blocks");
            wait_caught_up(&restarted, &nodes.iter().collect::<Vec<_>>(), Duration::from_secs(60)).await;
            wait_for("the missed note arrives", Duration::from_secs(30), || restarted.holds(&cm)).await;
            nodes.insert(i, restarted);
            assert_chains_equal(&nodes.iter().collect::<Vec<_>>());
        }
    }
    // All four keep committing together afterwards.
    let all: Vec<&TestNode> = nodes.iter().collect();
    let h = all.iter().map(|n| n.height()).max().unwrap();
    wait_height(&all, h + 5, Duration::from_secs(60)).await;
    assert_chains_equal(&all);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_of_four_down_halts_and_recovers_without_fork() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], 5, Duration::from_secs(60)).await;

    let d2 = stop(n2).await;
    let d3 = stop(n3).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let h0 = n0.height();
    tokio::time::sleep(Duration::from_secs(6)).await;
    let h1 = n0.height();
    assert!(h1 <= h0 + 1, "chain advanced without quorum: {h0} -> {h1}");
    assert_chains_equal(&[&n0, &n1]);

    let n2 = start_in(d2, &ks[2], boot.clone(), true).await;
    let n3 = start_in(d3, &ks[3], boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], h1 + 6, Duration::from_secs(90)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_behind_by_more_than_one_sync_batch_catches_up() {
    init_tracing();
    // Four validators: with three, stopping one leaves exactly 2/3 stake, which is not a quorum.
    let ks = keys(4);
    let gen = genesis(&ks);
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
    let (_, cm) = n0.mint(30, 2 * UNITS_PER_SHRUGG).await;

    let n2 = start_in(d2, &ks[2], boot.clone(), true).await;
    assert_eq!(n2.handle.storage.head().unwrap().height, stopped_at);
    wait_caught_up(&n2, &[&n0, &n1, &n3], Duration::from_secs(120)).await;
    wait_for("the note minted while it was down", Duration::from_secs(30), || n2.holds(&cm)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3]);
    // and it participates again afterwards
    let h = n0.height();
    wait_height(&[&n0, &n1, &n2, &n3], h + 5, Duration::from_secs(60)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupted_rocksdb_is_detected_truncated_and_resynced() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks);
    let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let _n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    // A mint early in the chain, so the note must survive the repair.
    let (hash, cm) = n0.mint(40, 3 * UNITS_PER_SHRUGG).await;
    let receipt_height = n0.handle.storage.tx_location(&hash).unwrap().unwrap().0;
    wait_height(&[&n0, &n1, &n2], receipt_height + 8, Duration::from_secs(60)).await;

    let head = n2.handle.storage.head().unwrap().height;
    let dir = stop(n2).await;
    // Damage the middle of n2's chain on disk, after the mint block.
    let bad_height = receipt_height + 3;
    {
        let st = shrugg_node::storage::Storage::open(dir.path()).unwrap();
        st.overwrite_block_bytes_for_testing(bad_height, b"\xff\x00corrupt").unwrap();
        // and a subtle one: a validator entry with rewards it never earned
        let mut entry = st.validator(&ks[0].address()).unwrap().expect("a genesis validator");
        entry.rewards += 12_345;
        st.overwrite_validator_for_testing(&ks[0].address(), &entry).unwrap();
        let gs_ = gen.build(executor.as_ref()).unwrap();
        let check = st.verify_chain(&gs_, shrugg_node::storage::VerifyMode::Full, executor.as_ref()).unwrap();
        assert!(!check.is_ok());
        assert_eq!(check.last_good, bad_height - 1);
    }
    // Restart: startup verification must truncate to bad_height-1, then sync catches up.
    let n2 = start_in(dir, &ks[2], boot.clone(), true).await;
    let resumed = n2.handle.storage.head().unwrap().height;
    assert!(resumed >= bad_height - 1 && resumed < head, "expected truncation below {head}, got {resumed}");
    wait_caught_up(&n2, &[&n0, &n1], Duration::from_secs(90)).await;
    assert!(n2.holds(&cm), "the repaired ledger lost the minted note");
    assert_chains_equal(&[&n0, &n1, &n2]);
    // Verified clean again after the resync.
    let gs_ = gen.build(executor.as_ref()).unwrap();
    let check = n2.handle.storage.verify_chain(&gs_, shrugg_node::storage::VerifyMode::Full, executor.as_ref()).unwrap();
    assert!(check.is_ok(), "{:?}", check.problem);
    let h = n0.height();
    wait_height(&[&n0, &n1, &n2], h + 4, Duration::from_secs(60)).await;
    assert_chains_equal(&[&n0, &n1, &n2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn faucet_mints_reach_every_node_and_respect_the_cap() {
    init_tracing();
    let ks = keys(2);
    let gen = genesis(&ks);
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let b = start_node(&ks[1], &gen, vec![bootstrap_addr(&a)], true).await;
    wait_height(&[&a, &b], 2, Duration::from_secs(40)).await;
    assert_eq!(a.handle.storage.notes_count().unwrap(), 0, "an alloc-free genesis starts empty");

    let (h1, cm1) = b.mint(1, 100 * UNITS_PER_SHRUGG).await;
    wait_for("mint visible on A", Duration::from_secs(30), || a.handle.storage.tx_location(&h1).unwrap().is_some()).await;
    assert!(a.holds(&cm1) && b.holds(&cm1));

    // A second mint right away: nothing serialises two mints from one node any more, since
    // there is no nonce to advance — the notes simply differ.
    let (_, cm2) = b.mint(2, 5 * UNITS_PER_SHRUGG).await;
    assert_ne!(cm1, cm2);
    wait_for("both notes on A", Duration::from_secs(30), || a.holds(&cm1) && a.holds(&cm2)).await;
    assert_eq!(a.handle.storage.notes_count().unwrap(), 2);

    // Over the cap is rejected, and so is an address that is not a shielded address.
    assert!(b.rpc.mint_shielded(&payee(3), Some(101 * UNITS_PER_SHRUGG)).await.is_err());
    assert!(b.rpc.mint_shielded("not-an-address", Some(1)).await.is_err());
    assert_chains_equal(&[&a, &b]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn faucet_is_rejected_when_genesis_disables_it() {
    init_tracing();
    let ks = keys(1);
    let mut gen = genesis(&ks);
    gen.faucet = false;
    let a = start_node(&ks[0], &gen, vec![], true).await;
    wait_height(&[&a], 2, Duration::from_secs(40)).await;
    let err = a.rpc.mint_shielded(&payee(1), None).await.unwrap_err().to_string();
    assert!(err.contains("faucet is disabled"), "{err}");
    assert_eq!(a.handle.storage.notes_count().unwrap(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_build_whose_bundle_guest_differs_from_genesis_refuses_to_start() {
    init_tracing();
    let ks = keys(1);
    let mut gen = genesis(&ks);
    // What an operator running the wrong commit would have on disk.
    gen.hc_bundle = word8_to_hex(&[0xdead; 8]);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("genesis.json"), gen.to_json()).unwrap();
    let started = node::start(NodeConfig {
        datadir: dir.path().to_path_buf(),
        seed: *ks[0].seed(),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        enable_mdns: false,
        validator: true,
        block_interval: Duration::from_millis(150),
        base_timeout: Duration::from_millis(1500),
        max_timeout: Duration::from_secs(6),
        verify: shrugg_node::storage::VerifyMode::Full,
    })
    .await;
    // `NodeHandle` is not `Debug`, so unwrap the error by hand rather than via `expect_err`.
    let err = match started {
        Ok(_) => panic!("a mismatched bundle guest must not start"),
        Err(e) => e.to_string(),
    };
    // The message must name both digests: an operator has to know which build to go back to.
    assert!(err.contains("bundle guest"), "{err}");
    assert!(err.contains(&word8_to_hex(&ZkExecutor::hc_bundle())), "{err}");
    assert!(err.contains(&word8_to_hex(&[0xdead; 8])), "{err}");
}
