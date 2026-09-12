//! End-to-end: several nodes over real TCP on localhost reach consensus, apply shielded bundles
//! and faucet mints submitted over RPC, and a late joiner syncs the chain.
//!
//! Two kinds of traffic run here, and the split is deliberate. A *faucet mint* is the one
//! transaction a node can build for itself, costs nothing to make, and still exercises the whole
//! plumbing the structural tests care about — a transaction gossips, commits, changes the
//! commitment tree, and every node's state root agrees afterwards. Those tests run on a fast
//! chain (150 ms blocks) because no proof is involved. A *bundle* costs about a minute and a half
//! of proving in the `test` FRI profile, so the tests that need one (a real transfer, a
//! double-spend race, a deploy and a call) run on a chain whose blocks are slow enough that the
//! 256-block anchor and time windows outlive the proof: at [`PROVING`] that is over four minutes
//! against a proof of about one and a half, margin enough for several such tests proving at once.
//!
//! What the bundle tests assert is always a *wallet's* view, never a node's: the chain has no
//! balances, so `balance(node, wallet)` scans a fresh note store against that node's RPC and
//! trial-decrypts, exactly as `shrugg balance` does. A node that served the scan cannot answer
//! the same question itself.

use shrugg_client::wallet::{self, NoteStore, Wallet};
use shrugg_client::RpcClient;
use shrugg_core::genesis::{EnvelopeHex, Genesis, GenesisNote, GenesisValidator};
use shrugg_core::notes::{word8_to_hex, ShieldedAddress};
use shrugg_core::{gas, Action, Hash, Keypair, Word8, UNITS_PER_SHRUGG};
use shrugg_node::node::{self, NodeConfig, NodeHandle};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::machine::{Backend, FriProfile};
use shrugg_zkvm::notes::{Note, SpendKey};
use shrugg_zkvm::viewing::TxKey;
use std::time::{Duration, Instant};

const CHAIN_ID: u64 = 7;

/// What one funded wallet holds at genesis.
const ALLOC: u64 = 1_000 * UNITS_PER_SHRUGG;

/// Block spacing for the structural tests: nothing in them proves anything, so the chain runs as
/// fast as consensus will go.
const FAST: Duration = Duration::from_millis(150);

/// Block spacing for the tests that prove a bundle. `ANCHOR_WINDOW` and `TIME_WINDOW` are 256
/// *blocks*, so a bundle has 256 blocks between reading its anchor and being committed under it;
/// at 1 s that is a little over four minutes, against a tier-14 proof measured at about 98 s in
/// the `test` profile. The margin is deliberately more than 2×: `cargo test --workspace`
/// schedules the proving tests concurrently (one of them proves twice), so three or four proofs
/// compete for the same cores and the wall-clock cost of each one grows. A faster chain would
/// expire the anchor mid-proof and the test would fail on the clock rather than on the property
/// it is about. The view timeouts scale with the interval, and every `wait_*` bound in these
/// tests still holds at 1 s blocks (`wallet::COMMIT_TIMEOUT` is 180 s).
const PROVING: Duration = Duration::from_millis(1000);

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn,shrugg_node=info".into()))
        .with_test_writer()
        .try_init();
}

fn keys(n: u8) -> Vec<Keypair> {
    (1..=n).map(|i| Keypair::from_seed([i + 100; 32]).unwrap()).collect()
}

/// Test wallet `i`, from the spend key `SpendKey([i; 8])`. Deterministic so a note minted or
/// allocated to `wallet(i)` in one part of a test can be opened by `wallet(i)` in another.
fn wallet(i: u32) -> Wallet {
    Wallet::from_spend_key(SpendKey([i; 8]))
}

/// The shielded address a mint pays, as its `shrugg1…` text.
fn payee(seed: u8) -> String {
    wallet(seed as u32).address.to_string()
}

/// What `wallet` can spend according to `node` — a fresh note store scanned against that node's
/// RPC, which is the only way a balance exists at all on this chain.
async fn balance(node: &TestNode, w: &Wallet) -> u64 {
    let mut store = NoteStore::default();
    wallet::scan(&node.rpc, w, &mut store).await.expect("scanning the tree");
    store.balance()
}

/// One genesis deposit note, built exactly as `shrugg-node genesis` builds it (`main.rs`'s
/// `deposit_note`/`seal_deposit`): a note owned by `to` with fresh commitment randomness, sealed
/// to `to` under a throwaway sender key that is dropped here — a genesis has no identity to keep
/// an outgoing-viewing record for.
fn alloc_note(to: &ShieldedAddress, amount: u64) -> GenesisNote {
    let note = Note::new(to.pk, [0; 8], amount, 0, 0);
    let throwaway = SpendKey::random().viewing_key();
    let envelope =
        shrugg_zkvm::address::seal_note(&throwaway, to, &note, &TxKey::random()).expect("sealing a deposit note");
    GenesisNote { cm: word8_to_hex(&note.commitment()), envelope: EnvelopeHex::from_envelope(&envelope), amount }
}

/// A chain with no deposit notes: every note in these tests is minted by a validator at runtime.
/// `hc_bundle` must be this build's own guest, or `node::start` refuses to run at all.
fn genesis(validators: &[Keypair]) -> Genesis {
    genesis_funding(validators, &[])
}

/// The same chain with one [`ALLOC`] deposit note per wallet in `funded`.
fn genesis_funding(validators: &[Keypair], funded: &[&Wallet]) -> Genesis {
    Genesis {
        chain_id: CHAIN_ID,
        timestamp_ms: 0,
        validators: validators.iter().map(|k| GenesisValidator { public_key: k.public_key().clone(), stake: 10 }).collect(),
        alloc: funded.iter().map(|w| alloc_note(&w.address, ALLOC)).collect(),
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
    start_node_at(key, gen, bootstrap, validator, FAST).await
}

async fn start_node_at(
    key: &Keypair,
    gen: &Genesis,
    bootstrap: Vec<libp2p::Multiaddr>,
    validator: bool,
    block_interval: Duration,
) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("genesis.json"), gen.to_json()).unwrap();
    start_in_at(dir, key, bootstrap, validator, block_interval).await
}

async fn start_in(dir: tempfile::TempDir, key: &Keypair, bootstrap: Vec<libp2p::Multiaddr>, validator: bool) -> TestNode {
    start_in_at(dir, key, bootstrap, validator, FAST).await
}

async fn start_in_at(
    dir: tempfile::TempDir,
    key: &Keypair,
    bootstrap: Vec<libp2p::Multiaddr>,
    validator: bool,
    block_interval: Duration,
) -> TestNode {
    let handle = node::start(NodeConfig {
        datadir: dir.path().to_path_buf(),
        seed: *key.seed(),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap,
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        enable_mdns: false,
        validator,
        block_interval,
        base_timeout: Duration::from_millis(1500).max(block_interval * 10),
        max_timeout: Duration::from_secs(6).max(block_interval * 40),
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
async fn faucet_mint_via_rpc_reaches_every_node() {
    init_tracing();
    let ks = keys(3);
    let gen = genesis(&ks[..2]);
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&a)];
    let b = start_node(&ks[1], &gen, boot.clone(), true).await;
    let obs = start_node(&ks[2], &gen, boot, false).await;
    wait_height(&[&a, &b, &obs], 2, Duration::from_secs(40)).await;
    assert_eq!(a.handle.storage.notes_count().unwrap(), 0, "an alloc-free genesis starts empty");

    // A validator mints the faucet's full 100 SHRUGG to C.
    let c = wallet(3);
    let (h1, cm1) = b.mint(3, 100 * UNITS_PER_SHRUGG).await;
    wait_for("mint visible on A", Duration::from_secs(30), || a.handle.storage.tx_location(&h1).unwrap().is_some()).await;
    assert!(a.holds(&cm1) && b.holds(&cm1));
    // Every node — the observer included — serves the leaf C's viewing key opens, and none of
    // them can say whose it is.
    wait_for("the observer has the note", Duration::from_secs(30), || obs.holds(&cm1)).await;
    for n in [&a, &b, &obs] {
        assert_eq!(balance(n, &c).await, 100 * UNITS_PER_SHRUGG, "C's balance");
        assert_eq!(balance(n, &wallet(4)).await, 0, "a wallet that was never paid sees nothing");
    }

    // A second mint right away: nothing serialises two mints from one node any more, since
    // there is no nonce to advance — the notes simply differ.
    let (_, cm2) = b.mint(2, 5 * UNITS_PER_SHRUGG).await;
    assert_ne!(cm1, cm2);
    wait_for("both notes on A", Duration::from_secs(30), || a.holds(&cm1) && a.holds(&cm2)).await;
    assert_eq!(a.handle.storage.notes_count().unwrap(), 2);

    // An observer holds no validator key, so it cannot serve the faucet itself.
    let err = obs.rpc.mint_shielded(&payee(3), Some(1)).await.unwrap_err().to_string();
    assert!(err.contains("validators"), "{err}");
    // Over the cap is rejected, and so is an address that is not a shielded address.
    assert!(b.rpc.mint_shielded(&payee(3), Some(101 * UNITS_PER_SHRUGG)).await.is_err());
    assert!(b.rpc.mint_shielded("not-an-address", Some(1)).await.is_err());
    assert_chains_equal(&[&a, &b, &obs]);
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

// ---------------------------------------------------------------- shielded bundles
//
// Everything below proves a real 2-in-2-out bundle, so these tests are minutes rather than
// seconds and run on a `PROVING`-paced chain (see the constant). They are also the only tests
// here that look at value at all: a mint proves that a note arrived, a bundle proves that value
// moved from one wallet to another without the chain ever learning either.

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_validators_commit_and_shielded_transfer() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    let (a, b) = (wallet(1), wallet(2));
    let gen = genesis_funding(&ks, &[&a]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(60)).await;

    // The genesis deposit note is on both nodes, and only A's viewing key opens it.
    for n in [&n0, &n1] {
        assert_eq!(balance(n, &a).await, ALLOC, "A's genesis note");
        assert_eq!(balance(n, &b).await, 0, "B has nothing yet");
    }

    let fee = gas::BUNDLE_BASE;
    let pay = UNITS_PER_SHRUGG;
    let mut store = NoteStore::default();
    let sent = wallet::send(&n0.rpc, &a, &mut store, &b.address, pay, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the bundle is accepted and commits");
    eprintln!("transfer: tier {}, proved in {:.1?}, {} proof bytes", sent.tier, sent.proving, sent.proof_bytes);

    // Both validators carry the same transaction, and both answer the same two balances.
    wait_for("the transfer reaches n1", Duration::from_secs(60), || {
        n1.handle.storage.tx_location(&sent.hash).unwrap().is_some()
    })
    .await;
    for n in [&n0, &n1] {
        assert_eq!(balance(n, &b).await, pay, "B was paid 1 SHRUGG");
        assert_eq!(balance(n, &a).await, ALLOC - pay - fee, "A keeps 999 SHRUGG less the fee");
    }
    // The fee left the pool and landed in the proposer's public register entry.
    let rewards: u64 = gen
        .validators
        .iter()
        .map(|v| n0.handle.storage.validator(&v.public_key.address()).unwrap().map(|e| e.rewards).unwrap_or(0))
        .sum();
    assert_eq!(rewards, fee, "the bundle fee is the only reward paid so far");

    // A replay of the very bytes that committed: the nullifiers are in the set now, so the
    // node refuses it before any proof is re-verified.
    let (height, index) = n0.handle.storage.tx_location(&sent.hash).unwrap().unwrap();
    let tx = n0.handle.storage.block_by_height(height).unwrap().unwrap().transactions[index as usize].clone();
    let err = n0.rpc.send_transaction(&tx).await.unwrap_err().to_string();
    assert!(err.contains("spent"), "a replayed bundle must be refused as spent: {err}");

    assert_chains_equal(&[&n0, &n1]);
    eprintln!("two_validators_commit_and_shielded_transfer in {:.1?}", started.elapsed());
}

/// Two bundles spending the same note, proved in parallel and submitted to two different
/// validators. Whichever reaches a block first spends the note; the other can never be admitted
/// again — it is refused at the RPC if the nullifier is already committed, or dropped from the
/// mempool by `prune` if it was accepted before the race resolved. Either way the chain must end
/// with exactly one of them and every node must agree on the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_bundles_spending_one_note_only_one_commits() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    let (a, b) = (wallet(5), wallet(6));
    let gen = genesis_funding(&ks, &[&a]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(60)).await;
    assert_eq!(balance(&n0, &a).await, ALLOC);

    let fee = gas::BUNDLE_BASE;
    // Different amounts, so the two bundles differ in every public field except the nullifier
    // they collide on — and `--no-wait`, so each returns as soon as its node has answered.
    let race = |rpc: RpcClient, pay: u64| {
        tokio::spawn(async move {
            let (a, b) = (wallet(5), wallet(6));
            let mut store = NoteStore::default();
            let out =
                wallet::send(&rpc, &a, &mut store, &b.address, pay, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, false)
                    .await;
            out.map(|s| (s.hash, s.amount))
        })
    };
    let one = race(n0.rpc.clone(), UNITS_PER_SHRUGG);
    let two = race(n1.rpc.clone(), 2 * UNITS_PER_SHRUGG);
    let (one, two) = tokio::join!(one, two);

    let mut accepted: Vec<(Hash, u64)> = Vec::new();
    let mut refused: Vec<String> = Vec::new();
    for r in [one.expect("the prover task did not panic"), two.expect("the prover task did not panic")] {
        match r {
            Ok(pair) => accepted.push(pair),
            Err(e) => refused.push(e.to_string()),
        }
    }
    assert!(!accepted.is_empty(), "both bundles were refused outright: {refused:?}");
    eprintln!("accepted {} bundle(s), refused {refused:?}", accepted.len());

    // One of the accepted hashes commits; give the chain a few blocks past it so a loser that was
    // admitted has been pruned rather than merely not-yet-proposed.
    let hashes: Vec<Hash> = accepted.iter().map(|(h, _)| *h).collect();
    let committed_on = |n: &TestNode| -> Vec<Hash> {
        hashes.iter().copied().filter(|h| n.handle.storage.tx_location(h).unwrap().is_some()).collect()
    };
    wait_for("one of the two bundles commits", Duration::from_secs(90), || !committed_on(&n0).is_empty()).await;
    let h = n0.height();
    wait_height(&[&n0, &n1], h + 6, Duration::from_secs(90)).await;

    let winners = committed_on(&n0);
    assert_eq!(winners.len(), 1, "exactly one of two bundles spending the same note may commit");
    assert_eq!(committed_on(&n1), winners, "the two validators disagree about which one won");

    // The winner's amount is what B holds, and A's note paid for it exactly once.
    let paid = accepted.iter().find(|(h, _)| *h == winners[0]).map(|(_, amount)| *amount).unwrap();
    for n in [&n0, &n1] {
        assert_eq!(balance(n, &b).await, paid, "B holds the winning bundle's payment, and only that");
        assert_eq!(balance(n, &a).await, ALLOC - paid - fee);
    }
    assert_chains_equal(&[&n0, &n1]);
    eprintln!("two_bundles_spending_one_note_only_one_commits in {:.1?}", started.elapsed());
}

/// Deploy and call, both paid for by a bundle rather than by an account. The deploy and the call
/// are ordinary shielded transactions whose `Action` happens to carry a program: the wallet pays
/// each one's fee floor out of its notes, and the only thing the chain learns is that *some*
/// note paid.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn confidential_call_rides_on_a_bundle() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    let a = wallet(7);
    let gen = genesis_funding(&ks, &[&a]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(60)).await;

    let program = shrugg_zkvm::guests::private_payment(1_000);
    let id = shrugg_core::program::program_id(program.base_pc, &program.words);
    let mut store = NoteStore::default();

    // ---- deploy, paid by a bundle ----
    let action = Action::Deploy { base_pc: program.base_pc, words: program.words.clone() };
    let deploy_fee = wallet::deploy_fee_default(&action);
    assert_eq!(deploy_fee, gas::BUNDLE_BASE + gas::deploy_fee(program.words.len()));
    let deployed =
        wallet::submit(&n0.rpc, &a, &mut store, None, action, deploy_fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
            .await
            .expect("the deploy bundle commits");
    eprintln!("deploy: {} words, fee {deploy_fee}, proved in {:.1?}", program.words.len(), deployed.proving);
    assert_eq!(deployed.amount, 0, "a deploy pays nobody; it is a self-transfer of zero");
    for n in [&n0, &n1] {
        wait_for("the program reaches every node", Duration::from_secs(60), || {
            n.handle.storage.program(&id).unwrap().is_some()
        })
        .await;
    }

    // ---- call, proved locally, paid by a second bundle ----
    let (proof, outputs, tier) =
        shrugg_zkvm::executor::prove(FriProfile::Test, &program, &[400, 250, 300, 75], None, Backend::Cpu)
            .expect("the call proves");
    eprintln!("call: tier {tier}, {} proof bytes, outputs {outputs:?}", proof.len());
    let call_fee = wallet::call_fee_default(tier);
    let called = wallet::submit(
        &n0.rpc,
        &a,
        &mut store,
        None,
        Action::Call { program: id, proof },
        call_fee,
        FriProfile::Test,
        Backend::Cpu,
        CHAIN_ID,
        true,
    )
    .await
    .expect("the call bundle commits");
    eprintln!("call bundle: fee {call_fee}, proved in {:.1?}", called.proving);

    // The receipt is on every node, with the outputs the prover published.
    for n in [&n0, &n1] {
        wait_for("the receipt reaches every node", Duration::from_secs(60), || {
            n.handle.storage.receipt(&called.hash).unwrap().is_some()
        })
        .await;
        let r = n.handle.storage.receipt(&called.hash).unwrap().unwrap();
        assert_eq!(r.program, id);
        assert_eq!(r.tier, tier);
        assert_eq!(r.outputs, outputs);
    }

    // A paid the two fee floors and not one unit more: the deploy and the call moved no value.
    for n in [&n0, &n1] {
        assert_eq!(balance(n, &a).await, ALLOC - deploy_fee - call_fee, "A paid exactly the two floors");
    }
    assert_chains_equal(&[&n0, &n1]);
    eprintln!("confidential_call_rides_on_a_bundle in {:.1?}", started.elapsed());
}
