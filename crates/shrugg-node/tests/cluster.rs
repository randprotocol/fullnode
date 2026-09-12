//! End-to-end: several nodes over real TCP on localhost reach consensus, apply shielded bundles
//! and faucet mints submitted over RPC, and a late joiner syncs the chain.
//!
//! Two kinds of traffic run here, and the split is deliberate. A *faucet mint* is the one
//! transaction a node can build for itself, costs nothing to make, and still exercises the whole
//! plumbing the structural tests care about — a transaction gossips, commits, changes the
//! commitment tree, and every node's state root agrees afterwards. Those tests run on a fast
//! chain (150 ms blocks) because no proof is involved. A *bundle* costs about a minute and a half
//! of proving in the `test` FRI profile, so the tests that need one (a real transfer, a
//! double-spend race, a deploy and a call, a call's input envelope, a bridge deposit and burn) run
//! on a chain whose blocks are slow enough that the 256-block anchor and time windows outlive the
//! proof — see [`PROVING`].
//!
//! What the bundle tests assert is always a *wallet's* view, never a node's: the chain has no
//! balances, so `balance(node, wallet)` scans a fresh note store against that node's RPC and
//! trial-decrypts, exactly as `shrugg balance` does. A node that served the scan cannot answer
//! the same question itself.

use shrugg_client::wallet::{self, NoteStore, Wallet};
use shrugg_client::RpcClient;
use shrugg_core::bridge::{
    digest, guardian_address, sign_digest, Attestation, Body, BridgeConfig, Payload, Transfer, CHAIN_RAND,
};
use shrugg_core::genesis::{EnvelopeHex, Genesis, GenesisNote, GenesisValidator};
use shrugg_core::notes::{word8_to_hex, Bundle, Envelope, ShieldedAddress};
use shrugg_core::{gas, Action, Hash, Keypair, Transaction, Word8, UNITS_PER_SHRUGG};
use shrugg_node::node::{self, NodeConfig, NodeHandle};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::machine::{Backend, FriProfile};
use shrugg_zkvm::notes::{Note, SpendKey};
use shrugg_zkvm::viewing::TxKey;
use shrugg_zkvm::{call_envelope, hash};
use std::time::{Duration, Instant};

const CHAIN_ID: u64 = 7;

/// What one funded wallet holds at genesis.
const ALLOC: u64 = 1_000 * UNITS_PER_SHRUGG;

/// Block spacing for the structural tests: nothing in them proves anything, so the chain runs as
/// fast as consensus will go.
const FAST: Duration = Duration::from_millis(150);

/// Block spacing for every test here that proves a bundle. `ANCHOR_WINDOW` and `TIME_WINDOW` are
/// 256 *blocks*, so a bundle gets 256 blocks between reading its anchor and being committed under
/// it — and its own `time` word gets the same window. Three-second blocks make that nearly thirteen
/// minutes, which is the number `wallet_flow.rs` uses for the same reason.
///
/// The margin has to be far more than one proof's worth, because `cargo test --workspace` schedules
/// every proving test in this file concurrently and they compete for the same cores: a tier-14
/// bundle measures about 98 s alone and 255 s with six other proofs running, and `submit_burn`
/// proves *twice* under one anchor (189 s for the pair, alone). At 1 s blocks — where this constant
/// started — a 255 s proof put the committed bundle's own `time` outside the window by the time the
/// test replayed it, and `two_validators_commit_and_shielded_transfer` failed on
/// `bundle time 2 is outside [3, 259]` instead of on the double-spend it is about. A test must fail
/// on its property, not on the clock.
///
/// The view timeouts scale with the interval (`start_node_at`), and every `wait_*` bound in these
/// tests is a wall-clock timeout with room to spare at 3 s blocks (`wallet::COMMIT_TIMEOUT` is
/// 180 s, which is 60 blocks).
const PROVING: Duration = Duration::from_millis(3000);

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
    asset_balance(node, w, 0).await
}

/// The same question about one bridged asset: the notes of that registry index this wallet's
/// viewing key opens (`shrugg asset-balance`). Index 0 is SHRUGG, which is what [`balance`] asks.
async fn asset_balance(node: &TestNode, w: &Wallet, asset: u32) -> u64 {
    let mut store = NoteStore::default();
    wallet::scan(&node.rpc, w, &mut store).await.expect("scanning the tree");
    store.balance_of(asset)
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
    genesis_bridge(validators, funded, None)
}

/// [`genesis_funding`] with an optional `bridge` section. A chain built with `None` has no bridge
/// at all — no registry, no bridge root, and both bridge actions inadmissible.
fn genesis_bridge(validators: &[Keypair], funded: &[&Wallet], bridge: Option<BridgeConfig>) -> Genesis {
    Genesis {
        chain_id: CHAIN_ID,
        timestamp_ms: 0,
        validators: validators
            .iter()
            .map(|k| GenesisValidator { public_key: k.public_key().clone(), stake: 10, payout: None })
            .collect(),
        alloc: funded.iter().map(|w| alloc_note(&w.address, ALLOC)).collect(),
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
        bridge,
        epoch_blocks: shrugg_core::genesis::EPOCH_BLOCKS_DEFAULT,
    }
}

// ---------------------------------------------------------------- the bridge
//
// A bridged test chain, built the way `docs/bridge.md` describes one: six guardian secrets whose
// addresses are the genesis guardian set, and chain 2 registered as a source emitter. These are
// the same fixed secrets the core bridge tests sign with; they are built here out of the public
// API (`guardian_address`, `sign_digest`, `Attestation`) rather than borrowed from those tests,
// which are `#[cfg(test)]` inside `shrugg-core` and unreachable from an integration test.

/// The six guardian secrets of a bridged test chain. Five signatures is a quorum for six keys.
fn guardian_secrets() -> Vec<[u8; 32]> {
    (1u8..=6).map(|i| [i; 32]).collect()
}

/// The `bridge` section those guardians name, with chain 2 as the one registered source emitter.
/// No asset is registered: a registry starts empty and the first attestation to name a token is
/// what puts it in, under index 1.
fn bridge_config() -> BridgeConfig {
    BridgeConfig {
        emitter: [1; 32],
        guardians: guardian_secrets().iter().map(guardian_address).collect(),
        emitters: std::collections::BTreeMap::from([(TOKEN_CHAIN, [TOKEN_CHAIN as u8; 32])]),
    }
}

/// The bridged token these tests move: chain 2's `0xaa…`, which the first attestation registers as
/// asset index 1.
const TOKEN: [u8; 32] = [0xaa; 32];
const TOKEN_CHAIN: u16 = 2;

/// A well-formed EVM burn destination: twelve zero bytes then twenty address bytes (spec 3.5),
/// which is the shape `BridgeState::check_burn` requires for chains 2, 3 and 4.
const EVM_TO: [u8; 32] = {
    let mut t = [0u8; 32];
    let mut i = 12;
    while i < 32 {
        t[i] = 0x22;
        i += 1;
    }
    t
};

/// One inbound transfer attestation: `amount` units of [`TOKEN`] addressed to `to`, emitted by
/// chain 2's registered emitter and signed by five of the six guardians.
///
/// The 32-byte recipient slot carries `to.recipient_hash()`, not an address: a shielded address is
/// 1.2 KB and the wire format has room for a hash, so the source-chain depositor names the hash and
/// the transaction carries the address for the ledger to check against it.
fn attestation(to: &ShieldedAddress, amount: u128) -> Vec<u8> {
    let secrets = guardian_secrets();
    let body = Body {
        timestamp: 1,
        nonce: 0,
        emitter_chain: TOKEN_CHAIN,
        emitter_address: [TOKEN_CHAIN as u8; 32],
        sequence: 0,
        consistency_level: 0,
        payload: Payload::Transfer(Transfer {
            amount: Transfer::u256_from_u128(amount),
            token_address: TOKEN,
            token_chain: TOKEN_CHAIN,
            to: to.recipient_hash(),
            to_chain: CHAIN_RAND,
            fee: Transfer::u256_from_u128(0),
        })
        .encode(),
    };
    let d = digest(&body.encode());
    let signatures = (0..5).map(|i| sign_digest(&secrets[i], i as u8, &d)).collect();
    Attestation { guardian_set_index: 0, signatures, body }.encode()
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
        Action::Call { program: id, proof, input_envelope: None },
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

// ---------------------------------------------------------------- the bridge, end to end
//
// One inbound deposit and one outbound burn across two validators. This is the only place the two
// bridge actions meet a real chain: a guardian-signed attestation turns into a note the chain
// computes itself, and a burn spends that note through two bundles in one transaction.

/// The relayer's half of `shrugg bridge-mint`, in the wallet helpers the command itself uses: read
/// the deposit out of the attestation bytes, resolve the index the note will carry against the
/// node's registry, stamp the note with a `time` inside the admission window, seal the recipient's
/// envelope against the commitment the *chain* will compute, and pay for all of it with a bundle of
/// the relayer's own SHRUGG.
///
/// Returns the submission, the asset index and the deposit note's commitment — the last of which is
/// on no wire anywhere: the chain derives it from the amount the guardians signed, which is what
/// stops a relayer minting a note of its own choosing.
async fn bridge_mint(
    node: &TestNode,
    relayer: &Wallet,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    attestation: Vec<u8>,
) -> (wallet::Submission, u32, Word8) {
    let d = wallet::attested_deposit(&attestation).expect("the attestation decodes to a transfer");
    assert_eq!(d.to_hash, to.recipient_hash(), "the guardians signed this recipient's hash");
    // The asset id from the node, over the two wire fields the guardians signed; a disagreement
    // would mean the two are not talking about the same chain.
    let asset_id = node.rpc.bridge_asset_id(d.token_chain, &d.token).await.expect("the node computes an asset id");
    assert_eq!(asset_id, d.asset.to_hex(), "and computes the same one this wallet did");
    let state = node.rpc.bridge_state().await.expect("bridge state");
    let assets = node.rpc.assets().await.expect("the registry");
    let index = wallet::deposit_index(&state, &assets, &asset_id).expect("an index for this asset").index();
    let time = u32::try_from(node.rpc.head().await.expect("head")["height"].as_u64().expect("height")).unwrap();
    let (note, envelope) = wallet::deposit_note_for(relayer, to, d.amount, index, time).expect("sealing the deposit");
    let action =
        Action::BridgeAttest { attestation, recipient: to.clone(), r: note.r, time, asset: index, envelope };
    let fee = gas::fee_floor(&action);
    let s = wallet::submit(&node.rpc, relayer, store, None, action, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the attestation's fee bundle commits");
    (s, index, note.commitment())
}

/// A second transaction for the same attestation, as a relayer who has not noticed it was already
/// consumed would build it — except that its bundle carries junk where a proof goes.
///
/// Admission checks the action at step 7 and a bundle proof only at step 9 (spec §7,
/// `docs/shielded.md` §5), so everything before the action passes and the refusal that comes back
/// is the *attestation's*. That is what makes this a probe worth a second of test time rather than
/// a second bundle proof.
async fn replayed_attest(node: &TestNode, to: &ShieldedAddress, attestation: Vec<u8>, asset: u32) -> Transaction {
    let (height, anchor) = node.rpc.anchor(None).await.expect("the head anchor");
    let time = u32::try_from(height).unwrap();
    let empty = Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] };
    let bundle = Bundle {
        anchor,
        nullifiers: [[0x51; 8], [0x52; 8]],
        commitments: [[0x53; 8], [0x54; 8]],
        fee: gas::BUNDLE_BASE,
        burn: 0,
        asset: 0,
        time,
        envelopes: [empty.clone(), empty.clone()],
        proof: vec![0xff; 32],
    };
    let action =
        Action::BridgeAttest { attestation, recipient: to.clone(), r: [7; 8], time, asset, envelope: empty };
    Transaction::shielded(CHAIN_ID, bundle, action)
}

/// Inbound and outbound across a two-validator bridged chain: an attestation deposits a note only
/// its recipient can open, the registry names the token on both nodes, the same attestation
/// resubmitted is refused, and a two-bundle burn spends the note and leaves an outbound message
/// every guardian reads identically.
///
/// Three bundle proofs (one for the attestation's fee bundle, two for the burn), so this is the
/// slowest test in this file; the burn's pair is also what sets [`PROVING`]'s lower bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn bridge_mint_deposits_a_note_and_a_burn_spends_it() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    // The relayer pays the fees and the recipient receives the deposit: two wallets, because a
    // relayer having no claim on what it relays is the property worth showing.
    let (relayer, recipient) = (wallet(60), wallet(61));
    let gen = genesis_bridge(&ks, &[&relayer, &recipient], Some(bridge_config()));
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(90)).await;

    // A bridged genesis names guardians and emitters, and nothing else: the registry is empty, so
    // the attestation below is a first sighting and its deposit takes the first index.
    let state = n0.rpc.bridge_state().await.unwrap();
    assert_eq!(state["enabled"], true);
    assert_eq!(state["guardians"].as_array().unwrap().len(), 6);
    assert_eq!(state["next_index"], 1, "nothing registered yet");
    assert!(n0.rpc.assets().await.unwrap().is_empty());

    // ---- inbound: one attestation, one deposit note ----
    let deposit = 5_000u64;
    let attested = attestation(&recipient.address, deposit as u128);
    let mut relayer_store = NoteStore::default();
    let (minted, index, cm) =
        bridge_mint(&n0, &relayer, &mut relayer_store, &recipient.address, attested.clone()).await;
    assert_eq!(index, 1, "a first sighting takes FIRST_ASSET_INDEX");
    eprintln!("bridge-mint: tier {}, proved in {:.1?}, {} proof bytes", minted.tier, minted.proving, minted.proof_bytes);

    wait_for("the attestation reaches n1", Duration::from_secs(120), || {
        n1.handle.storage.tx_location(&minted.hash).unwrap().is_some()
    })
    .await;
    for n in [&n0, &n1] {
        assert!(n.holds(&cm), "the deposit note the chain computed is a leaf");
        assert_eq!(asset_balance(n, &recipient, index).await, deposit, "the recipient holds the deposit");
        assert_eq!(asset_balance(n, &relayer, index).await, 0, "and the relayer, who paid for it, holds none");
        assert_eq!(balance(n, &relayer).await, ALLOC - gas::BUNDLE_BASE, "the relayer paid one bundle base");
        assert_eq!(balance(n, &recipient).await, ALLOC, "the recipient paid nothing");
        // Both nodes registered the same token under the same index.
        let rows = n.rpc.assets().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].index, rows[0].chain, rows[0].token.as_slice()), (index, TOKEN_CHAIN, &TOKEN[..]));
        assert_eq!(n.rpc.bridge_state().await.unwrap()["next_index"], index + 1);
    }
    // The explorer's view of it: the amount and the asset decoded out of the attestation, and the
    // index the action named, which admission held to the registry's answer.
    let rendered = n0.rpc.call("shrugg_getTransaction", serde_json::json!([minted.hash.to_hex()])).await.unwrap();
    let action = &rendered["tx"]["action"];
    assert_eq!(action["kind"], "bridge_attest");
    assert_eq!(action["amount"], deposit);
    assert_eq!(action["asset"], index, "the index the action named");
    assert_eq!(action["asset_index"], index, "and the one the registry resolves, which admission held it to");

    // ---- the same attestation again: one digest, one deposit ----
    let replay = replayed_attest(&n0, &recipient.address, attested, index).await;
    let err = n0.rpc.send_transaction(&replay).await.unwrap_err().to_string();
    assert!(err.contains("already consumed"), "a replayed attestation must be refused as consumed: {err}");

    // ---- outbound: the recipient burns part of it, through two bundles in one transaction ----
    let (burn, relayer_fee) = (2_000u64, 100u64);
    let burn_fee = wallet::burn_fee_default();
    // Pinned here rather than taken on trust from the wallet: the floor this transaction has to
    // clear is the bundle base once per bundle a node verifies, and a burn is the one transaction
    // with two (spec §7 item 3). The balance assertion below would hold against a wrong default.
    assert_eq!(burn_fee, 2 * gas::BUNDLE_BASE);
    let mut recipient_store = NoteStore::default();
    let burned = wallet::submit_burn(
        &n0.rpc,
        &recipient,
        &mut recipient_store,
        index,
        burn,
        relayer_fee,
        TOKEN_CHAIN,
        EVM_TO,
        burn_fee,
        FriProfile::Test,
        Backend::Cpu,
        CHAIN_ID,
        true,
    )
    .await
    .expect("both of the burn's bundles commit");
    eprintln!("bridge-burn: tier {}, proved in {:.1?}, {} proof bytes", burned.tier, burned.proving, burned.proof_bytes);
    assert_eq!(burned.amount, burn + relayer_fee, "what left the pool is the burn plus the relayer fee");
    assert_eq!(burned.change, deposit - burn - relayer_fee);
    assert_eq!(burned.asset, index);

    wait_for("the burn reaches n1", Duration::from_secs(120), || {
        n1.handle.storage.tx_location(&burned.hash).unwrap().is_some()
    })
    .await;
    for n in [&n0, &n1] {
        assert_eq!(
            asset_balance(n, &recipient, index).await,
            deposit - burn - relayer_fee,
            "the change note is what is left of the deposit"
        );
        assert_eq!(balance(n, &recipient).await, ALLOC - burn_fee, "the fee bundle paid two bundle bases in SHRUGG");
        // The outbound message, which is the whole point of a burn: guardians sign this digest.
        let msg = n.rpc.bridge_burn(0).await.unwrap().expect("the burn emitted a message");
        assert_eq!(msg["sequence"], 0);
        assert_eq!(msg["tx"], burned.hash.to_hex(), "the transaction hash stands in for the absent sender");
        assert_eq!(msg["digest"].as_str().unwrap().len(), 64);
        assert!(!msg["body_hex"].as_str().unwrap().is_empty());
        assert_eq!(n.rpc.bridge_burn(1).await.unwrap(), None, "and only the one");
    }
    assert_chains_equal(&[&n0, &n1]);
    eprintln!("bridge_mint_deposits_a_note_and_a_burn_spends_it in {:.1?}", started.elapsed());
}

/// The call-input envelope end to end (spec §6.1). A call's private inputs are published as one
/// sealed transcript, and exactly three keys open it: the caller's outgoing viewing key, the
/// per-call key, and the viewing key of the auditor named when it was sealed. Every node serves the
/// ciphertext to anyone who asks and none of them holds a key to it.
///
/// What the chain guarantees is only the binding: the transcript's AEAD is bound to the `H_IN` the
/// proof published, and a holder who decrypts checks that it hashes back to that `H_IN`. Both
/// halves are asserted here, against the bytes a *node* served rather than the ones sealed locally.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_call_envelope_is_opened_by_the_caller_and_the_auditor_only() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    let (caller, auditor, stranger) = (wallet(70), wallet(71), wallet(72));
    let gen = genesis_funding(&ks, &[&caller]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(60)).await;

    let program = shrugg_zkvm::guests::private_payment(1_000);
    let id = shrugg_core::program::program_id(program.base_pc, &program.words);
    let mut store = NoteStore::default();
    let deploy = Action::Deploy { base_pc: program.base_pc, words: program.words.clone() };
    let deploy_fee = wallet::deploy_fee_default(&deploy);
    wallet::submit(&n0.rpc, &caller, &mut store, None, deploy, deploy_fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the deploy bundle commits");

    // `prove_call` is `prove` plus the salt the input commitment was drawn with — the one value
    // that never leaves the prover on its own, and the thing the transcript is sealed around.
    let inputs = [400u32, 250, 300, 75];
    let (proof, outputs, tier, salt) =
        shrugg_zkvm::executor::prove_call(FriProfile::Test, &program, &inputs, None, Backend::Cpu)
            .expect("the call proves");
    let h_in = hash::input_digest(salt, &inputs);
    let (sealed, key) = call_envelope::seal_call_envelope(&caller.vk, Some(&auditor.address), &h_in, salt, &inputs)
        .expect("sealing the transcript");
    let called = wallet::submit(
        &n0.rpc,
        &caller,
        &mut store,
        None,
        Action::Call { program: id, proof, input_envelope: Some(sealed.clone()) },
        wallet::call_fee_default(tier),
        FriProfile::Test,
        Backend::Cpu,
        CHAIN_ID,
        true,
    )
    .await
    .expect("the call bundle commits");
    eprintln!("call: tier {tier}, envelope {} bytes, outputs {outputs:?}", sealed.len());

    for n in [&n0, &n1] {
        wait_for("the receipt reaches every node", Duration::from_secs(90), || {
            n.handle.storage.receipt(&called.hash).unwrap().is_some()
        })
        .await;
        let (served_h_in, served) =
            n.rpc.call_envelope(&called.hash).await.unwrap().expect("the node serves the transcript");
        assert_eq!(served_h_in, h_in, "served against the H_IN the proof published");
        assert_eq!(served, sealed, "and verbatim: a node holds no key to any part of it");
        let receipt = n.rpc.receipt(&called.hash).await.unwrap().expect("a receipt");
        assert_eq!(receipt["h_in"].as_str().unwrap(), word8_to_hex(&h_in));
        assert_eq!(receipt["tier"], tier);

        // The caller, through the outgoing viewing key that opens every call this wallet made.
        let (as_caller, salt_back, inputs_back) =
            call_envelope::open_call_as_sender(&served, &served_h_in, &caller.vk).expect("the caller opens it");
        assert_eq!(salt_back, salt);
        assert_eq!(inputs_back, inputs.to_vec(), "the words the guest was fed, off the chain");
        assert_eq!(as_caller, key, "and the very per-call key it was sealed under");
        // The auditor it was addressed to, through a different path entirely: ML-KEM against that
        // address's encapsulation key, not the caller's `ovk`.
        let (as_auditor, _, audited) =
            call_envelope::open_call_as_auditor(&served, &served_h_in, &auditor.vk).expect("the auditor opens it");
        assert_eq!((as_auditor, audited), (key, inputs_back.clone()));
        // A third wallet — neither the caller nor the auditor — is served the same bytes and gets
        // nothing out of either path.
        assert!(call_envelope::open_call_as_sender(&served, &served_h_in, &stranger.vk).is_none());
        assert!(call_envelope::open_call_as_auditor(&served, &served_h_in, &stranger.vk).is_none());
        // Nor do the two named parties open each other's part: the wrapped key is a different
        // ciphertext under different associated data in each.
        assert!(call_envelope::open_call_as_sender(&served, &served_h_in, &auditor.vk).is_none());
        assert!(call_envelope::open_call_as_auditor(&served, &served_h_in, &caller.vk).is_none());
        // The per-call key alone opens this one call — the grain of disclosure that hands over no
        // history.
        assert_eq!(call_envelope::open_call_with_key(&served, &served_h_in, &key), Some((salt, inputs.to_vec())));

        // Faithfulness is the holder's own recomputation, not something the chain checked: the
        // transcript hashes back to the receipt's H_IN, and a transcript with one word changed
        // does not — which is how a caller who published a lie is caught, by whoever decrypts.
        assert!(call_envelope::call_envelope_is_faithful(&served_h_in, salt_back, &inputs_back));
        let mut tampered = inputs_back.clone();
        tampered[0] += 1;
        assert!(!call_envelope::call_envelope_is_faithful(&served_h_in, salt_back, &tampered));
        // And the ciphertext is bound to that H_IN by the AEAD: a flipped byte opens for nobody,
        // and neither does the real envelope read against another call's H_IN.
        let mut bent = served.clone();
        *bent.body.last_mut().unwrap() ^= 1;
        assert!(call_envelope::open_call_as_sender(&bent, &served_h_in, &caller.vk).is_none());
        let other_h_in = hash::input_digest(salt, &tampered);
        assert!(call_envelope::open_call_with_key(&served, &other_h_in, &key).is_none());
    }

    // The transcript is voluntary — a call built with `--no-envelope` publishes none and the node
    // serves `null` for it — which costs a proof to show here and is already pinned against a
    // committed block in `rpc.rs`'s `get_call_envelope_serves_the_sealed_transcript_of_a_call`.
    assert_chains_equal(&[&n0, &n1]);
    eprintln!("a_call_envelope_is_opened_by_the_caller_and_the_auditor_only in {:.1?}", started.elapsed());
}
