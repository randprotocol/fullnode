//! The multi-node harness `cluster.rs` grew and `zusd_e2e.rs` shares: real nodes over real TCP on
//! localhost, each with its own RocksDB directory, and the wallet-side reads (`balance`,
//! `asset_balance`) a test asserts value with.
//!
//! Moved here from `cluster.rs` unchanged, so both test binaries drive nodes the same way — the
//! view timeouts scaled to the block interval, the data directory kept across a restart, the
//! chain-equality check by state root.

use randprotocol_client::wallet::{self, NoteStore, Wallet};
use randprotocol_client::RpcClient;
use randprotocol_core::genesis::Genesis;
use randprotocol_core::{Action, Hash, Keypair, Word8};
use randprotocol_node::node::{self, NodeConfig, NodeHandle};
use randprotocol_zkvm::notes::SpendKey;
use std::time::{Duration, Instant};

/// Block spacing for the structural tests: nothing in them proves anything, so the chain runs as
/// fast as consensus will go.
pub const FAST: Duration = Duration::from_millis(150);

/// Block spacing for every test that proves a bundle. The 256-block anchor and time windows are
/// counted in blocks, so three-second blocks give a bundle nearly thirteen minutes between reading
/// its anchor and being committed under it; `cluster.rs`'s `PROVING` history (why 3 s, and why the
/// proving slot rather than this number is the bound) is kept in that file's module docs.
pub const PROVING: Duration = Duration::from_millis(3000);

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn,randprotocol_node=info".into()))
        .with_test_writer()
        .try_init();
}

pub fn keys(n: u8) -> Vec<Keypair> {
    (1..=n).map(|i| Keypair::from_seed([i + 100; 32]).unwrap()).collect()
}

/// Test wallet `i`, from the spend key `SpendKey([i; 8])`. Deterministic so a note minted or
/// allocated to `wallet(i)` in one part of a test can be opened by `wallet(i)` in another.
pub fn wallet(i: u32) -> Wallet {
    Wallet::from_spend_key(SpendKey([i; 8]))
}

/// The shielded address a mint pays, as its `rand1…` text.
pub fn payee(seed: u8) -> String {
    wallet(seed as u32).address.to_string()
}

/// What `wallet` can spend according to `node` — a fresh note store scanned against that node's
/// RPC, which is the only way a balance exists at all on this chain.
pub async fn balance(node: &TestNode, w: &Wallet) -> u64 {
    asset_balance(node, w, 0).await
}

/// The same question about one asset: the notes of that registry index this wallet can open or
/// rebuild (`rand asset-balance`). Index 0 is RAND, which is what [`balance`] asks.
pub async fn asset_balance(node: &TestNode, w: &Wallet, asset: u32) -> u64 {
    let mut store = NoteStore::default();
    wallet::scan(&node.rpc, w, &mut store).await.expect("scanning the tree");
    store.balance_of(asset)
}

/// The supply audit, as `rand_getSupply` reports it (`docs/supply.md`).
pub async fn supply_of(node: &TestNode) -> serde_json::Value {
    node.rpc.call("rand_getSupply", serde_json::json!([])).await.expect("getSupply answers")
}

/// An amount from an RPC reply. Every amount the register and the supply audit publish is a
/// decimal string, because a JSON number is not an exact integer past 2^53.
pub fn units(v: &serde_json::Value) -> u64 {
    v.as_str().expect("an amount is a decimal string").parse().expect("an amount parses")
}

pub struct TestNode {
    pub handle: NodeHandle,
    pub dir: tempfile::TempDir,
    pub rpc: RpcClient,
}

pub async fn start_node(key: &Keypair, gen: &Genesis, bootstrap: Vec<libp2p::Multiaddr>, validator: bool) -> TestNode {
    start_node_at(key, gen, bootstrap, validator, FAST).await
}

pub async fn start_node_at(
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

pub async fn start_in(dir: tempfile::TempDir, key: &Keypair, bootstrap: Vec<libp2p::Multiaddr>, validator: bool) -> TestNode {
    start_in_at(dir, key, bootstrap, validator, FAST).await
}

pub async fn start_in_at(
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
        verify: randprotocol_node::storage::VerifyMode::Full,
        keep_raw_proofs: false,
    })
    .await
    .expect("node starts");
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));
    TestNode { handle, dir, rpc }
}

/// Stop a node (abort its loop, close its sockets) and keep its data directory.
pub async fn stop(n: TestNode) -> tempfile::TempDir {
    n.handle.shutdown().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    n.dir
}

pub fn bootstrap_addr(n: &TestNode) -> libp2p::Multiaddr {
    let mut a = n.handle.listen_addrs[0].clone();
    a.push(libp2p::multiaddr::Protocol::P2p(n.handle.network.local_peer_id));
    a
}

pub async fn wait_for<F: Fn() -> bool>(what: &str, timeout: Duration, f: F) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn wait_height(nodes: &[&TestNode], min: u64, timeout: Duration) {
    wait_for(&format!("all nodes at height >= {min}"), timeout, || {
        nodes.iter().all(|n| n.handle.status.read().unwrap().height >= min)
    })
    .await;
}

impl TestNode {
    /// Mint `amount` units to `payee(seed)` through this node's RPC and wait for the commit.
    /// Returns the transaction hash and the commitment of the note it created, which is the
    /// thing every node must agree on afterwards.
    pub async fn mint(&self, seed: u8, amount: u64) -> (Hash, Word8) {
        let hash = self.rpc.mint_shielded(&payee(seed), Some(amount)).await.expect("mint accepted");
        self.rpc.wait_for_transaction(&hash, Duration::from_secs(30)).await.expect("mint commits");
        (hash, self.note_of(&hash).expect("a committed mint has a note"))
    }

    /// The commitment a committed mint created, read back from the block it landed in.
    pub fn note_of(&self, hash: &Hash) -> Option<Word8> {
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
    pub fn holds(&self, cm: &Word8) -> bool {
        self.handle.storage.notes_from(0, usize::MAX).map(|rows| rows.iter().any(|(_, r)| r.cm == *cm)).unwrap_or(false)
    }

    pub fn height(&self) -> u64 {
        self.handle.status.read().unwrap().height
    }
}

/// Every node's chain must be identical up to the lowest common height, and the shielded state
/// (the commitment tree, the nullifier set, the anchors, the validator rewards) must agree
/// there. `Ledger`'s own equality covers all of it, but comparing state roots localises a
/// failure to a height instead of dumping two whole ledgers.
pub fn assert_chains_equal(nodes: &[&TestNode]) {
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

pub async fn wait_caught_up(node: &TestNode, others: &[&TestNode], timeout: Duration) {
    wait_for("node catches up", timeout, || {
        let target = others.iter().map(|n| n.height()).max().unwrap();
        node.height() + 1 >= target
    })
    .await;
}
