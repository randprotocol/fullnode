//! Audit v12, OPS-602 (monorepo#26): the 27 Oct burst against a real node, with the memory it
//! costs *measured*, not counted.
//!
//! On 2026-10-27 bursts of eight ~2.9 MB shielded transfers, arriving at once at a node's RPC or
//! at its peers over gossip, OOM-killed 2 GB validators. v0.8.3 put one byte budget over what
//! admission holds (`admission::AdmissionBudget`), and the unit tests show the budget's own
//! counter never passes its limit (`rpc::tests::the_27_oct_burst_shape_...`,
//! `node::tests::a_submission_burst_is_...`). A counter is not memory: each counted byte is held
//! in more than one form on the way in (the hex body, the JSON string, the decoded bytes, the
//! transaction), and none of that was measured.
//!
//! This test measures it. The whole test binary runs on a counting allocator, so the figure is
//! every live Rust heap byte in the process — the node, its RPC server, its network task and its
//! verify workers — above the idle baseline, sampled at every allocation. One real node (its own
//! RocksDB, RPC listener and libp2p swarm) runs with the admission budget a 1 967 MB validator
//! gets by default on chain 21, on a genesis with chain 21's size limits.
//!
//! What it found, on the build before this test (bodies charged their length once, the 2 GB
//! default then 117 MiB): eight at once held 140 MiB, sixteen 276 MiB, twenty-four 344 MiB —
//! up to 2.9 times the budget, about 18 MB of heap per 5.8 MB body — and the 27 Oct eight were
//! all admitted. A body is now charged three times its length (`admission::body_charge`), and
//! the figures this test prints and bounds are the ones after that.
//!
//! What it does not measure, said plainly: the transactions carry a proof of the right *size*
//! that does not verify — making eight valid 2.9 MB proofs means proving, which CI does not do —
//! so the verifier's scratch for a proof that goes all the way through is outside this figure,
//! as is RocksDB's own (C++) memory. It bounds what a burst of large submissions makes the node
//! hold before it can judge them, which is the part the 27 Oct kills were traced to.

mod common;

use randprotocol_core::genesis::Genesis;
use randprotocol_core::notes::{Bundle, Envelope};
use randprotocol_core::{Action, Keypair, Transaction};
use randprotocol_node::admission::AdmissionBudget;
use randprotocol_node::network::{self, EdgeConfig, GossipMessage, NetworkConfig, WireLimits};
use randprotocol_node::node::{self, NetOptions, NodeConfig, NodeHandle, RpcOptions};
use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// Live and peak heap bytes of this process's Rust allocations.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

// SAFETY: every call is forwarded to `System` unchanged; the counters are only arithmetic.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Start measuring from what is live now; returns that baseline.
fn mark() -> usize {
    let base = LIVE.load(Ordering::Relaxed);
    PEAK.store(base, Ordering::Relaxed);
    base
}

/// The most that was live above `base` since [`mark`].
fn peak_above(base: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(base)
}

const MIB: usize = 1 << 20;
/// The fleet's 2 GB droplet, as the kernel reports it.
const HOST_RAM: u64 = 1_967 * 1_000_000;
/// Chain 21's size limits (`deploy/genesis-chain21.json`).
const MAX_PROOF_BYTES: u32 = 6_291_456;
const MAX_BLOCK_BYTES: u32 = 19_922_944;
/// A 27 Oct transfer's proof: with the bundle's other fields the transaction encodes to ~2.9 MB.
const PROOF_BYTES: usize = 2_900_000;

fn env(tag: u8) -> Envelope {
    Envelope { kem_ct: vec![tag; 8], to_receiver: vec![tag; 4], to_sender: vec![], body: vec![tag; 16] }
}

/// A shielded transfer of the 27 Oct size, distinct per `i`, anchored at the chain's current
/// root with unspent nullifiers and a fee far over the minimum — everything admission checks
/// before the proof is right. The proof is `PROOF_BYTES` of filler: it does not verify.
fn big_transfer(chain_id: u64, anchor: [u32; 8], i: u32) -> Transaction {
    let w = |k: u32| [1_000 + 16 * i + k; 8];
    let proof: Vec<u8> = (0..PROOF_BYTES).map(|n| (n as u32).wrapping_mul(2_654_435_761).wrapping_add(i) as u8).collect();
    Transaction {
        chain_id,
        bundle: Some(Bundle {
            anchor,
            nullifiers: [w(0), w(1), w(2), w(3)],
            commitments: [w(4), w(5), w(6), w(7)],
            fee: 1_000_000_000_000,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 0,
            envelopes: [env(1), env(2), env(3), env(4)],
            proof,
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        }),
        action: Action::None,
    }
}

fn chain21_sized(key: &Keypair) -> Genesis {
    let mut g = common::genesis(key);
    g.max_proof_bytes = Some(MAX_PROOF_BYTES);
    g.max_block_bytes = Some(MAX_BLOCK_BYTES);
    g
}

async fn start_node(gen: &Genesis, key: &Keypair, budget: usize) -> (NodeHandle, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("genesis.json"), gen.to_json()).unwrap();
    let handle = node::start_with(
        NodeConfig {
            viewing_open: false,
            datadir: dir.path().to_path_buf(),
            seed: *key.seed(),
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![],
            rpc_addr: "127.0.0.1:0".parse().unwrap(),
            enable_mdns: false,
            validator: false,
            block_interval: Duration::from_millis(150),
            base_timeout: Duration::from_millis(1500),
            max_timeout: Duration::from_secs(6),
            verify: randprotocol_node::storage::VerifyMode::Full,
            keep_raw_proofs: false,
            min_free_disk_bytes: 0,
            verify_workers: None,
            apply_inline: false,
            state_proof_tier_cap: None,
            prune_history: None,
            gas_policy: None,
            msauth: Default::default(),
        },
        RpcOptions { admission_budget: Some(budget), ..RpcOptions::default() },
        NetOptions::default(),
    )
    .await
    .expect("node starts");
    (handle, dir)
}

async fn call(addr: std::net::SocketAddr, method: &str) -> Value {
    let v: Value = reqwest::Client::new()
        .post(format!("http://{addr}/"))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["result"].clone()
}

/// How one `rand_sendTransaction` was answered.
#[derive(Debug, PartialEq)]
enum Answer {
    /// Its hash: held by the node.
    Hash,
    /// `-32005`: busy, retry.
    Busy,
    /// Refused for what it is, with this message.
    Refused(String),
}

/// POST each prepared body at once; every one must be answered with JSON, never reset.
async fn burst(addr: std::net::SocketAddr, bodies: &[&'static [u8]]) -> Vec<Answer> {
    let client = reqwest::Client::new();
    let sends = bodies.iter().map(|b| {
        let (client, b) = (client.clone(), *b);
        tokio::spawn(async move {
            let resp = client.post(format!("http://{addr}/")).header("content-type", "application/json").body(b).send().await.expect("answered, not reset");
            let v: Value = resp.json().await.expect("a JSON answer");
            if v.get("result").is_some_and(Value::is_string) {
                Answer::Hash
            } else if v["error"]["code"] == json!(-32005) {
                Answer::Busy
            } else {
                Answer::Refused(v["error"]["message"].as_str().unwrap_or_default().to_string())
            }
        })
    });
    let mut out = Vec::new();
    for s in sends.collect::<Vec<_>>() {
        out.push(s.await.unwrap());
    }
    out
}

/// The 27 Oct burst, and bursts two and three times its size, at a real node's RPC on a 2 GB
/// host's default admission budget for chain 21, with the heap it costs measured.
///
/// Asserted, per burst:
/// * every submission is answered exactly once — a refusal naming the proof, or `-32005` — and
///   none is acknowledged (no proof here verifies), so nothing is acknowledged and dropped;
/// * the heap live above the idle baseline never passes `HEAP_PER_BUDGET_BYTE` times the
///   budget, however large the burst: past the budget, submissions are refused before they are
///   read, so 24 at once cost no more than 8;
/// * a burst that is over the budget has some submissions told busy, and some still judged;
/// * the node is back at its baseline (within 16 MiB) once the burst is answered: nothing is
///   left held;
/// * and it still answers.
///
/// Then eight arrive over gossip from a peer, and the same bound holds; that figure includes the
/// publishing peer's own copies (it runs in this process), so it is an upper bound on the node's.
/// Afterwards the node holds one copy of each and no more — its recent-transaction cache, which
/// has its own cap and is not the admission budget's.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_27_oct_burst_costs_a_real_node_a_bounded_heap() {
    /// Heap held per byte of budget, at most. With a body charged three times its length the
    /// burst is measured at about 0.9 of the budget (the printed lines); before, at up to 2.9.
    const HEAP_PER_BUDGET_BYTE: f64 = 1.25;
    let key = Keypair::from_seed([101; 32]).unwrap();
    let gen = chain21_sized(&key);
    let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
    let gs = gen.build(executor.as_ref()).unwrap();
    let anchor = gs.ledger.anchors().back().expect("a ledger always has an anchor").1;
    // Chain 21's floor — one largest submission: its 38 322 176-byte body cap at what a body is
    // charged, plus the 19 922 944-byte block cap — is past RAM/16 on this host, so the floor is
    // the default: 134 889 472 bytes, ~129 MiB.
    let budget = AdmissionBudget::default_for(HOST_RAM, AdmissionBudget::floor_for(38_322_176, 19_922_944));
    assert_eq!(budget, 134_889_472);
    let bound = (budget as f64 * HEAP_PER_BUDGET_BYTE) as usize;

    // Every body is built before anything is measured, so the test's own copies are in the
    // baseline, not in the burst's figure. 48 over RPC, 8 more over gossip.
    let txs: Vec<Transaction> = (0..56).map(|i| big_transfer(gen.chain_id, anchor, i)).collect();
    let tx_len = txs[0].encoded_len();
    assert!((2_850_000..2_950_000).contains(&tx_len), "a 27 Oct-sized transaction: {tx_len} B");
    // Leaked, so each request body is sent from the one copy made here.
    let bodies: Vec<&'static [u8]> = txs[..48]
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            let body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":i,"method":"rand_sendTransaction","params":[hex::encode(tx.encode())]})).unwrap();
            &*Box::leak(body.into_boxed_slice())
        })
        .collect();
    let per_submission = randprotocol_node::admission::body_charge(bodies[0].len()) + randprotocol_node::admission::charge_of(&txs[0]);

    let (node, _dir) = start_node(&gen, &key, budget).await;
    let addr = node.rpc_addr;
    // A gossip peer, connected before the baseline so its connection is in it.
    let target = node.listen_addrs[0].clone().with(libp2p::multiaddr::Protocol::P2p(node.network.local_peer_id));
    let (peer, _peer_rx) = network::start_with(
        NetworkConfig { chain_id: gen.chain_id, listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()], bootstrap: vec![target], enable_mdns: false, limits: WireLimits::default() },
        [77; 32],
        EdgeConfig::default(),
    )
    .await
    .unwrap();
    common::cluster::wait_for("the gossip peer is connected", Duration::from_secs(30), || node.status.read().unwrap().connected_peers >= 1).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(call(addr, "rand_chainId").await, json!(gen.chain_id));

    eprintln!(
        "burst memory: budget {} MiB (a {} MB host's default on chain 21); one submission is a {:.1} MB body charged three times + {:.1} MB decoded = {:.1} MB counted; heap bound {} MiB",
        budget / MIB,
        HOST_RAM / 1_000_000,
        bodies[0].len() as f64 / 1e6,
        randprotocol_node::admission::charge_of(&txs[0]) as f64 / 1e6,
        per_submission as f64 / 1e6,
        bound / MIB
    );

    let mut from = 0;
    for size in [8usize, 16, 24] {
        let base = mark();
        let answers = burst(addr, &bodies[from..from + size]).await;
        from += size;
        let peak = peak_above(base);
        let busy = answers.iter().filter(|a| **a == Answer::Busy).count();
        let refused: Vec<&String> = answers.iter().filter_map(|a| if let Answer::Refused(m) = a { Some(m) } else { None }).collect();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let after = LIVE.load(Ordering::Relaxed).saturating_sub(base);
        eprintln!(
            "burst memory: {size} x {:.1} MB over RPC ({:.0} MB counted if all were admitted): peak heap +{:.1} MiB ({:.2} of the budget); refused on the proof {}, busy {}; +{:.1} MiB left after",
            tx_len as f64 / 1e6,
            (size * per_submission) as f64 / 1e6,
            peak as f64 / MIB as f64,
            peak as f64 / budget as f64,
            refused.len(),
            busy,
            after as f64 / MIB as f64
        );
        assert_eq!(answers.len(), size);
        assert!(!answers.contains(&Answer::Hash), "a transaction whose proof does not verify was acknowledged");
        assert_eq!(refused.len() + busy, size, "every submission is answered once, with a refusal or busy");
        for m in &refused {
            assert!(m.contains("proof"), "refused for something other than its proof, so it never reached the verifier: {m}");
        }
        assert!(!refused.is_empty(), "nothing reached the verifier");
        if size * per_submission <= budget {
            assert_eq!(busy, 0, "{size} fit the budget outright");
        } else {
            assert!(busy > 0, "{size} at once is over the budget and none was told busy");
        }
        assert!(peak <= bound, "{size} at once held {} MiB over the baseline; the bound is {} MiB", peak / MIB, bound / MIB);
        assert!(after <= 16 * MIB, "{} MiB still held after the burst was answered", after / MIB);
        assert_eq!(call(addr, "rand_chainId").await, json!(gen.chain_id), "the node still answers");
    }

    // The same eight over gossip, from a peer. Its copies are in the figure too.
    let refused_before = call(addr, "rand_status").await["refused_cache"].as_u64().unwrap();
    let base = mark();
    for tx in &txs[48..] {
        peer.broadcast(GossipMessage::Transaction(tx.clone())).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut judged = 0;
    while judged < 8 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        judged = call(addr, "rand_status").await["refused_cache"].as_u64().unwrap() - refused_before;
    }
    let peak = peak_above(base);
    // The publishing peer goes, and its copies with it; what is left is the node's.
    peer.shutdown().await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let after = LIVE.load(Ordering::Relaxed).saturating_sub(base);
    eprintln!(
        "burst memory: 8 x {:.1} MB over gossip: peak heap +{:.1} MiB ({:.2} of the budget), publisher's copies included; judged and refused {judged}; +{:.1} MiB left after, the node's recent-transaction cache",
        tx_len as f64 / 1e6,
        peak as f64 / MIB as f64,
        peak as f64 / budget as f64,
        after as f64 / MIB as f64
    );
    assert_eq!(judged, 8, "every gossiped transaction was verified and its refusal cached");
    assert!(peak <= bound, "eight over gossip held {} MiB over the baseline; the bound is {} MiB", peak / MIB, bound / MIB);
    // A gossiped body stays in the node's recent-transaction cache (`compact::RecentTxs`, capped
    // at four blocks' worth of bytes) for a compact proposal to be rebuilt from: one copy each,
    // and nothing beyond that.
    assert!(after <= 8 * tx_len + 8 * MIB, "{} MiB still held after the gossip burst, more than one copy of each", after / MIB);

    node.shutdown().await;
}
