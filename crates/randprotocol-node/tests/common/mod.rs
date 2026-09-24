//! The smallest chain an RPC test can run against: one validator, 150 ms blocks, nothing proved.
//!
//! `cluster.rs` has the same shapes, but integration test binaries do not share modules — each
//! `tests/*.rs` is its own crate — so this is a deliberate small copy rather than an import, and
//! it stays small for that reason: a genesis, a start, and a handle that keeps its data directory
//! alive.

#![allow(dead_code)]

/// The multi-node harness (`cluster.rs`, `zusd_e2e.rs`).
pub mod cluster;
/// Test bridge guardians and what they sign (`cluster.rs`, `zusd_e2e.rs`).
pub mod bridge;

use randprotocol_core::confidential::StubExecutor;
use randprotocol_core::genesis::{Genesis, GenesisValidator};
use randprotocol_core::ledger::staking::MIN_STAKE;
use randprotocol_core::notes::word8_to_hex;
use randprotocol_core::Keypair;
use randprotocol_node::node::{self, NodeConfig, NodeHandle};
use randprotocol_node::rpc::{HeadSummary, NodeStatus, RpcState};
use randprotocol_zkvm::executor::ZkExecutor;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;

/// Block spacing: nothing here proves anything, so the chain runs as fast as consensus will go.
/// The same constant, for the same reason, as `cluster.rs`'s `FAST`.
const FAST: Duration = Duration::from_millis(150);

/// A running node plus the temporary directory its database lives in.
///
/// [`NodeHandle`] does not own the directory, and a `TempDir` deletes its tree when it drops — so
/// returning the handle alone would pull the database out from under a running RocksDB. Every
/// field of the handle (`rpc_addr`, `status`, …) reaches through the `Deref`.
pub struct TestNode {
    handle: NodeHandle,
    _dir: tempfile::TempDir,
}

impl std::ops::Deref for TestNode {
    type Target = NodeHandle;
    fn deref(&self) -> &NodeHandle {
        &self.handle
    }
}

impl TestNode {
    /// Stop the node loop and the RPC server, then release the directory.
    pub async fn shutdown(self) {
        self.handle.shutdown().await;
    }
}

/// A one-validator chain. `hc_bundle` must be this build's own guest, or `node::start` refuses to
/// run at all.
fn genesis(key: &Keypair) -> Genesis {
    genesis_with_aggregation(key, None)
}

/// `genesis`, with an `aggregation` section when the test is about one.
fn genesis_with_aggregation(key: &Keypair, aggregation: Option<randprotocol_core::ledger::aggregation::AggregationConfig>) -> Genesis {
    Genesis {
        chain_id: 7,
        timestamp_ms: 0,
        validators: vec![GenesisValidator {
            public_key: key.public_key().clone(),
            stake: MIN_STAKE as u128,
            // Nothing here withdraws; this only has to parse.
            payout: randprotocol_core::notes::ShieldedAddress {
                pk: [1; 8],
                kem_ek: vec![1; randprotocol_core::notes::KEM_EK_BYTES],
            }
            .to_string(),
        }],
        alloc: vec![],
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
        bridge: None,
        tokens: None,
        aggregation,
        consensus_domain: None,
        epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
        max_program_words: None,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words: None,
        staking: None,
    }
}

/// Start that chain's single validator on an ephemeral RPC port. It commits an empty block every
/// [`FAST`], which is all a head subscription needs.
pub async fn start_one_validator() -> TestNode {
    start_one_validator_with(None).await
}

/// `start_one_validator`, on a chain whose genesis carries an `aggregation` section.
pub async fn start_one_validator_aggregating(
    aggregation: randprotocol_core::ledger::aggregation::AggregationConfig,
) -> TestNode {
    start_one_validator_with(Some(aggregation)).await
}

async fn start_one_validator_with(
    aggregation: Option<randprotocol_core::ledger::aggregation::AggregationConfig>,
) -> TestNode {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn,randprotocol_node=info".into()),
        )
        .with_test_writer()
        .try_init();
    let key = Keypair::from_seed([101; 32]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("genesis.json"), genesis_with_aggregation(&key, aggregation).to_json()).unwrap();
    let handle = node::start(NodeConfig {
        viewing_open: false,
        datadir: dir.path().to_path_buf(),
        seed: *key.seed(),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        enable_mdns: false,
        validator: true,
        block_interval: FAST,
        base_timeout: Duration::from_millis(1500),
        max_timeout: Duration::from_secs(6),
        verify: randprotocol_node::storage::VerifyMode::Full,
        keep_raw_proofs: false,
        min_free_disk_bytes: 0,
    })
    .await
    .expect("node starts");
    TestNode { handle, _dir: dir }
}

/// An RPC server with no node behind it and a head channel of `capacity` slots, so a test can
/// decide exactly what a subscriber sees.
///
/// The backpressure rule is about the *channel*, not about the chain: proving it against a real
/// node would mean outrunning a 256-slot channel one 150 ms block at a time, which is half a
/// minute of waiting to observe a property the channel decides on its own. `RpcState`'s fields are
/// public, so the test builds one over an empty database and drives the sender itself.
pub async fn serve_heads(capacity: usize) -> (SocketAddr, broadcast::Sender<HeadSummary>, ServedRpc) {
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([102; 32]).unwrap();
    let gs = genesis(&key).build(&StubExecutor).expect("genesis builds");
    let storage = Arc::new(randprotocol_node::storage::Storage::open(dir.path()).unwrap());
    storage.init_genesis(&gs).unwrap();
    let (heads, _) = broadcast::channel(capacity);
    // Nothing here sends a `NodeCommand`; the receiver is kept only so the sender stays open.
    let (node_tx, node_rx) = tokio::sync::mpsc::channel(1);
    let state = RpcState {
            limiter: std::sync::Arc::new(randprotocol_node::rpc::RpcLimiter::default()),
        viewing_open: false,
        storage,
        status: Arc::new(RwLock::new(NodeStatus::default())),
        node: node_tx,
        chain_id: gs.chain_id,
        limits: randprotocol_node::rpc::ChainLimits::of(&gs.ledger),
        max_body_bytes: randprotocol_node::rpc::ChainLimits::of(&gs.ledger).rpc_max_body_bytes(),
        executor: Arc::new(StubExecutor),
        heads: heads.clone(),
        commits: broadcast::channel(capacity).0,
        refusals: broadcast::channel(capacity).0,
        ws_conns: Arc::new(AtomicUsize::new(0)),
        viewing: Arc::new(RwLock::new(randprotocol_node::viewing::Registry::default())),
    };
    let ws_conns = state.ws_conns.clone();
    let (addr, task) = randprotocol_node::rpc::serve("127.0.0.1:0".parse().unwrap(), state).await.expect("rpc binds");
    (addr, heads, ServedRpc { task, ws_conns, _dir: dir, _node_rx: node_rx })
}

/// Keeps a [`serve_heads`] server's task, database directory and command receiver alive for the
/// length of a test.
pub struct ServedRpc {
    task: tokio::task::JoinHandle<()>,
    ws_conns: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
    _node_rx: tokio::sync::mpsc::Receiver<randprotocol_node::rpc::NodeCommand>,
}

impl ServedRpc {
    /// Live WebSocket connections, the number `NodeStatus::ws_clients` reports on a real node.
    /// Read straight off the counter here, because there is no node loop to publish it.
    pub fn ws_conns(&self) -> usize {
        self.ws_conns.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait, bounded, for the live count to reach `want`. Returns what it actually was, so the
    /// caller asserts on a value rather than on a timeout.
    pub async fn wait_ws_conns(&self, want: usize, timeout: Duration) -> usize {
        let deadline = tokio::time::Instant::now() + timeout;
        while self.ws_conns() != want && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.ws_conns()
    }
}

impl Drop for ServedRpc {
    fn drop(&mut self) {
        self.task.abort();
    }
}
