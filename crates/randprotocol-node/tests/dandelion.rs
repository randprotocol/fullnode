//! Dandelion++ stem relay for transactions (issue #145), end to end: five real nodes on loopback,
//! each with its own RocksDB, connected to one another, and transactions submitted over one node's
//! JSON-RPC. What is watched is every node's mempool, sampled every millisecond — exactly what the
//! chain-21 experiment watched (over `rand_getMempoolInfo` at 20 Hz) to find that the first node
//! holding a transaction was the one it was submitted to, 27 times in 27.
//!
//! The chain does not commit: the genesis validator is not among the nodes (all run without
//! `--validator`), so a pooled transaction stays pooled and "node i holds transaction k" is "node
//! i's mempool counts k". The transactions are faucet mints signed by the genesis validator's
//! key — valid, and verified on every hop without a proof.

use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::genesis::Genesis;
use randprotocol_core::{Hash, Keypair, Transaction};
use randprotocol_node::dandelion::DandelionConfig;
use randprotocol_node::network::{self, EdgeConfig, NetworkConfig, NetworkEvent, WireLimits};
use randprotocol_node::node::{self, NetOptions, NodeConfig, RpcOptions};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod common;
use common::cluster::{wallet, TestNode};

/// The genesis validator's key: it signs the mints, and runs nowhere.
fn minter() -> Keypair {
    Keypair::from_seed([101; 32]).unwrap()
}

struct Net {
    nodes: Vec<TestNode>,
    gen: Genesis,
    executor: Arc<dyn ConfidentialExecutor>,
    next: u64,
}

async fn start(gen: &Genesis, seed: u8, bootstrap: Vec<libp2p::Multiaddr>, dandelion: DandelionConfig) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("genesis.json"), gen.to_json()).unwrap();
    let key = Keypair::from_seed([seed; 32]).unwrap();
    let handle = node::start_with(
        NodeConfig {
            viewing_open: false,
            datadir: dir.path().to_path_buf(),
            seed: *key.seed(),
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap,
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
            prune_history: None,
            gas_policy: None,
            msauth: Default::default(),
        },
        RpcOptions::default(),
        NetOptions { dandelion, ..NetOptions::default() },
    )
    .await
    .expect("node starts");
    let rpc = randprotocol_client::RpcClient::new(format!("http://{}", handle.rpc_addr));
    TestNode { handle, dir, rpc }
}

impl Net {
    /// `configs.len()` nodes, each bootstrapped to every node before it, waited on until each one
    /// is connected to all the others — and, where its config speaks the stem, until it knows
    /// every other stem-capable node as a stem peer — plus two gossip heartbeats for the mesh.
    async fn start(configs: Vec<DandelionConfig>) -> Net {
        common::cluster::init_tracing();
        let gen = common::genesis(&minter());
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let mut nodes: Vec<TestNode> = Vec::new();
        for (i, cfg) in configs.iter().enumerate() {
            let boot = nodes.iter().map(common::cluster::bootstrap_addr).collect();
            nodes.push(start(&gen, 1 + i as u8, boot, cfg.clone()).await);
        }
        let n = nodes.len();
        let capable = configs.iter().filter(|c| c.enabled).count();
        common::cluster::wait_for("a fully connected network", Duration::from_secs(30), || {
            nodes.iter().zip(&configs).all(|(node, cfg)| {
                node.handle.status.read().unwrap().connected_peers >= n - 1
                    && (!cfg.enabled || node.handle.dandelion.stem_peers.load(Ordering::Relaxed) >= capable - 1)
            })
        })
        .await;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        Net { nodes, gen, executor, next: 0 }
    }

    /// A fresh valid transaction: a faucet mint the genesis validator signed.
    fn mint(&mut self) -> Transaction {
        self.next += 1;
        let gs = self.gen.build(self.executor.as_ref()).unwrap();
        node::faucet_mint_tx(
            gs.ledger.binding_domain(),
            self.gen.chain_id,
            gs.ledger.envelope_bytes(),
            &wallet(self.next as u32).address,
            1_000 + self.next,
            0,
            &minter(),
            self.executor.as_ref(),
        )
        .unwrap()
    }

    /// Start sampling every node's mempool size on a thread of its own, spinning rather than
    /// sleeping: when each node first counted `count` transactions, measured from `start`. On
    /// loopback a stem hop and a gossip hop each take well under a millisecond, so a sampler that
    /// slept between reads would see the submitter and its successor in one sample.
    fn watch(&self, count: usize, start: Instant, within: Duration) -> std::thread::JoinHandle<Vec<Duration>> {
        let statuses: Vec<_> = self.nodes.iter().map(|n| n.handle.status.clone()).collect();
        std::thread::spawn(move || {
            let mut first: Vec<Option<Duration>> = vec![None; statuses.len()];
            while first.iter().any(Option::is_none) {
                for (f, st) in first.iter_mut().zip(&statuses) {
                    if f.is_none() && st.read().unwrap().mempool_size >= count {
                        *f = Some(start.elapsed());
                    }
                }
                assert!(start.elapsed() < within, "not every mempool holds transaction {count} after {within:?}: {first:?}");
                std::hint::spin_loop();
            }
            first.into_iter().map(Option::unwrap).collect()
        })
    }

    /// Submit `tx` over node `at`'s RPC and watch every mempool until all hold `count`
    /// transactions ([`Net::watch`]).
    async fn submit_and_watch(&self, at: usize, tx: &Transaction, count: usize, within: Duration) -> Vec<Duration> {
        let start = Instant::now();
        let watching = self.watch(count, start, within);
        let h = self.nodes[at].rpc.send_transaction(tx).await.expect("accepted");
        assert_eq!(h, tx.hash());
        tokio::task::spawn_blocking(move || watching.join().expect("every mempool got it")).await.unwrap()
    }

    fn stat(&self, i: usize, f: impl Fn(&randprotocol_node::dandelion::DandelionStats) -> &std::sync::atomic::AtomicU64) -> u64 {
        f(&self.nodes[i].handle.dandelion).load(Ordering::Relaxed)
    }

    fn total(&self, f: impl Fn(&randprotocol_node::dandelion::DandelionStats) -> &std::sync::atomic::AtomicU64 + Copy) -> u64 {
        (0..self.nodes.len()).map(|i| self.stat(i, f)).sum()
    }

    async fn stop(self) {
        for n in self.nodes {
            common::cluster::stop(n).await;
        }
    }
}

/// The node that held the transaction first. Samples are a millisecond apart, so two nodes can
/// tie; a tie goes to `submitter`, which makes "the submitter was not first" the stricter claim.
fn first_holder(at: &[Duration], submitter: usize) -> usize {
    let t = *at.iter().min().unwrap();
    if at[submitter] == t {
        submitter
    } else {
        (0..at.len()).find(|&i| at[i] == t).unwrap()
    }
}

fn cfg(q: f64, embargo_ms: u64, seed: u64) -> DandelionConfig {
    DandelionConfig { fluff_prob: q, embargo: Duration::from_millis(embargo_ms), seed: Some(seed), ..DandelionConfig::default() }
}

/// q = 1: the submitter stems its transaction to one successor, which fluffs it. Every mempool
/// gets it, and the first to hold it is not the submitter but that successor — the only node
/// that was stemmed anything. The submitter's route is fixed for the epoch, so three transactions
/// take the same successor.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn at_q_one_the_submitters_stem_successor_holds_it_first_and_every_mempool_gets_it() {
    let mut net = Net::start((0..5).map(|i| cfg(1.0, 30_000, 10 + i)).collect()).await;
    let a = 0;
    let mut fluffers = Vec::new();
    for k in 1..=3 {
        let tx = net.mint();
        let at = net.submit_and_watch(a, &tx, k, Duration::from_secs(20)).await;
        let first = first_holder(&at, a);
        eprintln!("q = 1, tx {k}: first holder node {first} at {:?}; submitter at {:?}; all by {:?}", at[first], at[a], at.iter().max().unwrap());
        assert_ne!(first, a, "the submitter held its own transaction first");
        assert!(at[a] > at[first]);
        fluffers.push(first);
    }
    assert!(fluffers.windows(2).all(|w| w[0] == w[1]), "one successor for the epoch: {fluffers:?}");
    let s = fluffers[0];
    assert_eq!(net.stat(a, |d| &d.stem_sent), 3, "the submitter stemmed each one");
    assert_eq!(net.stat(s, |d| &d.stem_received), 3, "the first holder is the submitter's stem successor");
    assert_eq!(net.stat(s, |d| &d.fluff_coin), 3);
    for i in (0..5).filter(|&i| i != s) {
        assert_eq!(net.stat(i, |d| &d.stem_received), 0, "node {i} was stemmed something");
    }
    assert_eq!(net.total(|d| &d.fluff_embargo), 0);
    net.stop().await;
}

/// q = 0: no relay ever fluffs on the coin, so the stem walks the network (going on past every
/// loop) until a node has forwarded it `MAX_STEM_FORWARDS` times, and only an embargo releases
/// it. While it is on the stem no node shows it to anyone over RPC — not the submitter either:
/// `rand_getTransactionStatus` says unknown and `rand_getMempoolInfo` counts nothing, on every
/// node. Then the first embargo fires — a relay's (in `[b, 2b]`), never the submitter's
/// (`2b + …`) — and every mempool gets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn at_q_zero_the_stem_is_invisible_until_an_embargo_fluffs_it_into_every_mempool() {
    let b = 3000;
    let mut net = Net::start((0..5).map(|i| cfg(0.0, b, 20 + i)).collect()).await;
    let a = 0;
    let tx = net.mint();
    let h: Hash = tx.hash();
    let start = Instant::now();
    let watching = net.watch(1, start, Duration::from_secs(30));
    net.nodes[a].rpc.send_transaction(&tx).await.expect("accepted");
    tokio::time::sleep(Duration::from_millis(800)).await;
    for (i, n) in net.nodes.iter().enumerate() {
        let st = n.rpc.call("rand_getTransactionStatus", serde_json::json!([[h.to_hex()]])).await.unwrap();
        assert_eq!(st[0]["status"], "unknown", "node {i} answered {st}");
        let info = n.rpc.call("rand_getMempoolInfo", serde_json::json!([])).await.unwrap();
        assert_eq!(info["count"], 0, "node {i}'s mempool shows it: {info}");
    }
    assert!(start.elapsed() < Duration::from_millis(b), "the probe ran inside the embargo");
    assert!(net.total(|d| &d.stem_received) >= 4, "the stem reached the network");
    let at = tokio::task::spawn_blocking(move || watching.join().expect("every mempool got it")).await.unwrap();
    let f = first_holder(&at, a);
    eprintln!("q = 0, embargo {b} ms: first holder node {f} at {:?}, all by {:?}; stem sends {}", at[f], at.iter().max().unwrap(), net.total(|d| &d.stem_sent));
    assert!(at[f] >= Duration::from_millis(b), "fluffed before any embargo could fire: {:?}", at[f]);
    assert_ne!(f, a, "the submitter's longer embargo fired first");
    assert!(net.stat(f, |d| &d.stem_received) >= 1, "the first holder was on the stem");
    assert_eq!(net.total(|d| &d.fluff_coin), 0);
    assert!(net.total(|d| &d.fluff_embargo) >= 1);
    assert!(net.total(|d| &d.loop_absorbed) >= 1, "the walk ended at the forward cap");
    for (i, n) in net.nodes.iter().enumerate() {
        let st = n.rpc.call("rand_getTransactionStatus", serde_json::json!([[h.to_hex()]])).await.unwrap();
        assert_eq!(st[0]["status"], "pending", "node {i} after the fluff: {st}");
    }
    net.stop().await;
}

/// The fail-safe against a black hole: the submitter's only stem-capable peer takes the stem and
/// drops it (a bare network node that acknowledges and does nothing else). The other four nodes
/// run with Dandelion off, so they are never sent a stem. The submitter's own embargo (`2b +
/// Exp(b/4)`) fluffs it, and every mempool gets it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_stem_dropped_by_its_successor_is_fluffed_by_the_submitters_embargo() {
    let b = 1000;
    let mut configs = vec![cfg(0.0, b, 30)];
    configs.extend((0..4).map(|_| DandelionConfig::off()));
    let mut net = Net::start(configs).await;
    let a = 0;
    let (hole, mut hole_rx) = network::start_with(
        NetworkConfig {
            chain_id: net.gen.chain_id,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![common::cluster::bootstrap_addr(&net.nodes[a])],
            enable_mdns: false,
            limits: WireLimits::default(),
        },
        [99; 32],
        EdgeConfig { dandelion: true, ..EdgeConfig::default() },
    )
    .await
    .unwrap();
    let (dropped_tx, mut dropped) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(ev) = hole_rx.recv().await {
            if let NetworkEvent::StemTx { tx, .. } = ev {
                let _ = dropped_tx.send(tx.hash());
            }
        }
    });
    common::cluster::wait_for("the black hole is the submitter's stem peer", Duration::from_secs(20), || {
        net.nodes[a].handle.dandelion.stem_peers.load(Ordering::Relaxed) == 1
    })
    .await;
    let tx = net.mint();
    let at = net.submit_and_watch(a, &tx, 1, Duration::from_secs(30)).await;
    assert_eq!(dropped.recv().await, Some(tx.hash()), "the stem went to the black hole");
    let f = first_holder(&at, a);
    eprintln!("black hole, embargo {b} ms: first holder node {f} at {:?}, all by {:?}", at[f], at.iter().max().unwrap());
    assert_eq!(f, a, "the submitter fluffed it");
    assert!(at[a] >= Duration::from_millis(2 * b), "before the submitter's embargo: {:?}", at[a]);
    assert_eq!(net.stat(a, |d| &d.fluff_embargo), 1);
    for i in 1..5 {
        assert_eq!(net.stat(i, |d| &d.stem_received), 0, "node {i} has Dandelion off and was stemmed");
    }
    hole.shutdown().await;
    net.stop().await;
}

/// The added propagation latency, measured: the same five-node network with Dandelion off
/// (publish at once, as before v0.8.3) and on at the defaults (q = 0.1, 3 s embargo), ten
/// transactions each from rotating submitters. Prints time to the first holder and to every
/// mempool, and how the stems ended. On loopback a hop costs a mint's verification plus a local
/// round trip, so this is the floor; on the fleet each hop adds a one-way network delay.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn dandelion_latency_against_publishing_at_once() {
    const TXS: usize = 10;
    let mut report = Vec::new();
    for (label, make) in [
        ("off", Box::new(|_: u64| DandelionConfig::off()) as Box<dyn Fn(u64) -> DandelionConfig>),
        ("on (q = 0.1, b = 3 s)", Box::new(|i: u64| DandelionConfig { seed: Some(40 + i), ..DandelionConfig::default() })),
    ] {
        let mut net = Net::start((0..5).map(&make).collect()).await;
        let (mut to_first, mut to_all, mut submitter_first) = (Vec::new(), Vec::new(), 0);
        for k in 1..=TXS {
            let tx = net.mint();
            let at_node = (k - 1) % 5;
            let at = net.submit_and_watch(at_node, &tx, k, Duration::from_secs(30)).await;
            let f = first_holder(&at, at_node);
            submitter_first += usize::from(f == at_node);
            to_first.push(at[f]);
            to_all.push(*at.iter().max().unwrap());
            // About four transactions a second: the chain commits about one, and each peer's
            // allowances are sized to that (`admission::PEER_TX_PER_SEC`).
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let ms = |v: &[Duration]| {
            let mut s: Vec<f64> = v.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
            s.sort_by(f64::total_cmp);
            (s.iter().sum::<f64>() / s.len() as f64, s[s.len() / 2], s[s.len() - 1])
        };
        let (fm, fmed, fmax) = ms(&to_first);
        let (am, amed, amax) = ms(&to_all);
        let line = format!(
            "dandelion {label}: first holder mean {fm:.1} ms (median {fmed:.1}, max {fmax:.1}); every mempool mean {am:.1} ms (median {amed:.1}, max {amax:.1}); submitter first {submitter_first}/{TXS}; stem sends {} ({:.1}/tx); fluffs coin {} embargo {} no-route {}",
            net.total(|d| &d.stem_sent),
            net.total(|d| &d.stem_sent) as f64 / TXS as f64,
            net.total(|d| &d.fluff_coin),
            net.total(|d| &d.fluff_embargo),
            net.total(|d| &d.fluff_no_route),
        );
        eprintln!("{line}");
        report.push((label, am, submitter_first));
        if label == "off" {
            assert_eq!(submitter_first, TXS, "without Dandelion the submitter is always first (the #145 finding)");
        } else {
            assert!(submitter_first < TXS, "with Dandelion the submitter was first every time");
        }
        net.stop().await;
    }
    eprintln!("dandelion added {:.1} ms to the mean time to every mempool on loopback", report[1].1 - report[0].1);
}
