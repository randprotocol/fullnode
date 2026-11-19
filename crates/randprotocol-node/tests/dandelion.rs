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
    start_on_lanes(gen, seed, bootstrap, dandelion, false).await
}

/// [`start`], choosing the node's transaction lanes: `anonymous_tx_only` is what a node of v0.9.0
/// or later runs by default, off is a v0.8.x node's default (both lanes subscribed and relayed).
async fn start_on_lanes(gen: &Genesis, seed: u8, bootstrap: Vec<libp2p::Multiaddr>, dandelion: DandelionConfig, anonymous_tx_only: bool) -> TestNode {
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
            state_proof_tier_cap: None,
            multisig_account_cap: None,
            prune_history: None,
            gas_policy: None,
            msauth: Default::default(),
            perps_keys: Default::default(),
        },
        RpcOptions::default(),
        NetOptions { dandelion, anonymous_tx_only, ..NetOptions::default() },
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
        Net::start_on_lanes(configs, &[]).await
    }

    /// [`Net::start`] with the nodes whose index is in `anonymous_only` on the anonymous
    /// transaction lane only, the rest on both lanes.
    async fn start_on_lanes(configs: Vec<DandelionConfig>, anonymous_only: &[usize]) -> Net {
        common::cluster::init_tracing();
        let gen = common::genesis(&minter());
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let mut nodes: Vec<TestNode> = Vec::new();
        for (i, cfg) in configs.iter().enumerate() {
            let boot = nodes.iter().map(common::cluster::bootstrap_addr).collect();
            let node = if anonymous_only.contains(&i) {
                start_on_lanes(&gen, 1 + i as u8, boot, cfg.clone(), true).await
            } else {
                start(&gen, 1 + i as u8, boot, cfg.clone()).await
            };
            nodes.push(node);
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

    /// Start sampling every node's mempool size on a thread of its own: when each node first
    /// counted `count` transactions, measured from `start`. A measurement only — never evidence of
    /// order: a node publishes its status at the top of its loop, and on a loaded runner one node's
    /// loop can lag another's by more than a stem hop, so the tests assert on the Dandelion
    /// counters (who stemmed, who fluffed) instead.
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
                std::thread::yield_now();
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

    /// Every time node `i` published a transaction on gossip (a fluff, for whatever reason): the
    /// causal record of who put each transaction on gossip, which no clock can reorder.
    fn fluffs(&self, i: usize) -> u64 {
        self.stat(i, |d| &d.fluff_coin) + self.stat(i, |d| &d.fluff_no_route) + self.stat(i, |d| &d.fluff_full) + self.stat(i, |d| &d.fluff_embargo)
    }

    fn all_fluffs(&self) -> Vec<u64> {
        (0..self.nodes.len()).map(|i| self.fluffs(i)).collect()
    }

    async fn stop(self) {
        for n in self.nodes {
            common::cluster::stop(n).await;
        }
    }
}

/// The node whose mempool counter rose first, for the printed measurements only.
fn first_holder(at: &[Duration]) -> usize {
    (0..at.len()).min_by_key(|&i| at[i]).unwrap()
}

fn cfg(q: f64, embargo_ms: u64, seed: u64) -> DandelionConfig {
    DandelionConfig { fluff_prob: q, embargo: Duration::from_millis(embargo_ms), seed: Some(seed), ..DandelionConfig::default() }
}

/// What changed in each node's fluff counter between two snapshots: who published.
fn published_by(before: &[u64], after: &[u64]) -> Vec<usize> {
    (0..before.len()).filter(|&i| after[i] > before[i]).collect()
}

/// q = 1: the submitter stems its transaction to one successor, which fluffs it on the coin, and
/// every mempool gets it. Asserted on what each node did, not on when its mempool was sampled:
/// for each of three transactions exactly one node published it, and that node is the one the
/// submitter stemmed to — the only node stemmed anything. The submitter never published, and its
/// route is fixed for the epoch, so all three take the same successor.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn at_q_one_the_submitters_stem_successor_holds_it_first_and_every_mempool_gets_it() {
    let mut net = Net::start((0..5).map(|i| cfg(1.0, 30_000, 10 + i)).collect()).await;
    let a = 0;
    let mut fluffers = Vec::new();
    for k in 1..=3 {
        let tx = net.mint();
        let before = net.all_fluffs();
        let at = net.submit_and_watch(a, &tx, k, Duration::from_secs(30)).await;
        let by = published_by(&before, &net.all_fluffs());
        eprintln!("q = 1, tx {k}: published by {by:?}; sampled first holder node {} at {:?}, all by {:?}", first_holder(&at), at[first_holder(&at)], at.iter().max().unwrap());
        assert_eq!(by.len(), 1, "one node published transaction {k}: {by:?}");
        assert_ne!(by[0], a, "the submitter published its own transaction");
        fluffers.push(by[0]);
    }
    assert!(fluffers.windows(2).all(|w| w[0] == w[1]), "one successor for the epoch: {fluffers:?}");
    let s = fluffers[0];
    assert_eq!(net.stat(a, |d| &d.stem_sent), 3, "the submitter stemmed each one");
    assert_eq!(net.fluffs(a), 0, "and published none");
    assert_eq!(net.stat(s, |d| &d.stem_received), 3, "the publisher is the submitter's stem successor");
    assert_eq!(net.stat(s, |d| &d.fluff_coin), 3, "and published each on the coin");
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
/// node. Then a relay's embargo fluffs it and every mempool gets it; the submitter never publishes
/// it. The submitter runs a 60 s embargo here, so which timer fires first is not a race the test
/// depends on (the protocol's own margin is in the unit tests).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn at_q_zero_the_stem_is_invisible_until_an_embargo_fluffs_it_into_every_mempool() {
    let b = 5000;
    let mut configs: Vec<DandelionConfig> = (0..5).map(|i| cfg(0.0, b, 20 + i)).collect();
    configs[0].embargo = Duration::from_secs(30);
    let mut net = Net::start(configs).await;
    let a = 0;
    let tx = net.mint();
    let h: Hash = tx.hash();
    let start = Instant::now();
    let watching = net.watch(1, start, Duration::from_secs(40));
    net.nodes[a].rpc.send_transaction(&tx).await.expect("accepted");
    tokio::time::sleep(Duration::from_millis(800)).await;
    for (i, n) in net.nodes.iter().enumerate() {
        let st = n.rpc.call("rand_getTransactionStatus", serde_json::json!([[h.to_hex()]])).await.unwrap();
        assert_eq!(st[0]["status"], "unknown", "node {i} answered {st}");
        let info = n.rpc.call("rand_getMempoolInfo", serde_json::json!([])).await.unwrap();
        assert_eq!(info["count"], 0, "node {i}'s mempool shows it: {info}");
    }
    assert!(start.elapsed() < Duration::from_millis(b), "the probe ran inside every relay's embargo");
    assert!(net.total(|d| &d.stem_received) >= 4, "the stem reached the network");
    let at = tokio::task::spawn_blocking(move || watching.join().expect("every mempool got it")).await.unwrap();
    let by = published_by(&[0; 5], &net.all_fluffs());
    eprintln!(
        "q = 0, embargo {b} ms: published by {by:?}; first mempool at {:?}, all by {:?}; stem sends {}",
        at.iter().min().unwrap(),
        at.iter().max().unwrap(),
        net.total(|d| &d.stem_sent)
    );
    assert!(!by.is_empty() && !by.contains(&a), "published by {by:?}, never by the submitter");
    for &f in &by {
        assert!(net.stat(f, |d| &d.stem_received) >= 1, "node {f} published it without being on the stem");
        assert_eq!(net.stat(f, |d| &d.fluff_embargo), net.fluffs(f), "node {f} published it other than by its embargo");
    }
    // Causal, so safe to assert: nothing reaches gossip before the first embargo can fire.
    assert!(*at.iter().min().unwrap() >= Duration::from_millis(b), "a mempool held it before any embargo: {at:?}");
    assert_eq!(net.total(|d| &d.fluff_coin), 0);
    assert!(net.total(|d| &d.loop_absorbed) >= 1, "the walk ended at the forward cap");
    for (i, n) in net.nodes.iter().enumerate() {
        let st = n.rpc.call("rand_getTransactionStatus", serde_json::json!([[h.to_hex()]])).await.unwrap();
        assert_eq!(st[0]["status"], "pending", "node {i} after the fluff: {st}");
    }
    net.stop().await;
}

/// The fail-safe against a black hole: the submitter's only stem-capable peer takes the stem and
/// drops it (a bare network node that acknowledges and does nothing else). The other four nodes
/// run with Dandelion off, so they are never sent a stem. The submitter's own embargo fluffs it —
/// it is the only node that published it — and every mempool gets it, none before that embargo
/// could fire. Since audit v12 (PRIV-604) the submitter's embargo is a relay's, `b + min(Exp(b/4),
/// b)`, so the fluff lands in the window a relay's would.
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
    let by = published_by(&[0; 5], &net.all_fluffs());
    eprintln!("black hole, embargo {b} ms: published by {by:?}; first mempool at {:?}, all by {:?}", at.iter().min().unwrap(), at.iter().max().unwrap());
    assert_eq!(by, vec![a], "only the submitter published it");
    assert_eq!(net.stat(a, |d| &d.fluff_embargo), 1, "on its embargo");
    assert!(*at.iter().min().unwrap() >= Duration::from_millis(b), "a mempool held it before the submitter's embargo: {at:?}");
    for i in 1..5 {
        assert_eq!(net.stat(i, |d| &d.stem_received), 0, "node {i} has Dandelion off and was stemmed");
    }
    hole.shutdown().await;
    net.stop().await;
}

/// Audit v12, PRIV-604 (monorepo#30), end to end: a successor that acknowledges a stem and drops
/// it no longer makes the submitter publish, when the submitter has another successor.
///
/// The submitter A first has one stem-capable peer, a black hole (a bare network node that
/// acknowledges and does nothing else); three more nodes run with Dandelion off.
///
/// * Control, transaction 1: with nowhere else to stem, A's embargo fluffs it — A is the only
///   node that published it, as before.
/// * Then a fifth node B joins with Dandelion on at q = 1 and becomes A's second successor. A's
///   own edge stays mapped to the black hole for the epoch, so transaction 2 goes to the hole
///   again. This time A's first embargo stems it to B, B fluffs it, and every mempool gets it:
///   A published nothing, and no mempool held it before A's first embargo could run out.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_submitter_stems_around_a_black_hole_to_its_other_successor_and_never_publishes() {
    let b = 1000;
    let mut configs = vec![cfg(0.0, b, 30)];
    configs.extend((0..3).map(|_| DandelionConfig::off()));
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

    // The control: no other successor, so the submitter's embargo publishes it.
    let tx1 = net.mint();
    net.submit_and_watch(a, &tx1, 1, Duration::from_secs(30)).await;
    assert_eq!(dropped.recv().await, Some(tx1.hash()), "transaction 1 went to the black hole");
    assert_eq!(published_by(&[0; 4], &net.all_fluffs()), vec![a], "with no other successor only the submitter publishes it");
    assert_eq!(net.stat(a, |d| &d.embargo_restem), 0);

    // B joins: Dandelion on, and it fluffs whatever is stemmed to it.
    let boot = net.nodes.iter().map(common::cluster::bootstrap_addr).collect();
    let node_b = start(&net.gen, 6, boot, cfg(1.0, b, 31)).await;
    net.nodes.push(node_b);
    let bi = 4;
    common::cluster::wait_for("B is the submitter's second stem peer", Duration::from_secs(30), || {
        net.nodes[a].handle.dandelion.stem_peers.load(Ordering::Relaxed) == 2 && net.nodes[bi].handle.status.read().unwrap().connected_peers >= 4
    })
    .await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let before = net.all_fluffs();
    let tx2 = net.mint();
    let h2 = tx2.hash();
    let start_at = Instant::now();
    assert_eq!(net.nodes[a].rpc.send_transaction(&tx2).await.expect("accepted"), h2);
    assert_eq!(dropped.recv().await, Some(h2), "transaction 2 went to the black hole too: the edge keeps its successor");
    // When each node first shows it pooled.
    let mut pending_at: Vec<Option<Duration>> = vec![None; net.nodes.len()];
    while pending_at.iter().any(Option::is_none) {
        assert!(start_at.elapsed() < Duration::from_secs(30), "not every mempool holds transaction 2: {pending_at:?}");
        for (i, n) in net.nodes.iter().enumerate() {
            if pending_at[i].is_none() {
                let st = n.rpc.call("rand_getTransactionStatus", serde_json::json!([[h2.to_hex()]])).await.unwrap();
                if st[0]["status"] == "pending" {
                    pending_at[i] = Some(start_at.elapsed());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let by = published_by(&before, &net.all_fluffs());
    eprintln!(
        "black hole with another successor, embargo {b} ms: published by {by:?}; first mempool at {:?}, all by {:?}; submitter's embargo restems {}",
        pending_at.iter().flatten().min().unwrap(),
        pending_at.iter().flatten().max().unwrap(),
        net.stat(a, |d| &d.embargo_restem)
    );
    assert_eq!(by, vec![bi], "B published it; the submitter did not");
    assert_eq!(net.stat(a, |d| &d.embargo_restem), 1, "the submitter's first embargo stemmed it to B");
    assert_eq!(net.stat(bi, |d| &d.stem_received), 1);
    assert_eq!(net.stat(bi, |d| &d.fluff_coin), 1, "B fluffed it on the coin");
    assert_eq!(net.fluffs(a), before[a], "the submitter published nothing new");
    hole.shutdown().await;
    net.stop().await;
}

/// The added propagation latency, measured and printed, not asserted beyond every mempool
/// getting each transaction within 30 s: the same five-node network with Dandelion off (publish
/// at once, as before v0.8.3) and on at the defaults (q = 0.1, 3 s embargo), ten transactions
/// each from rotating submitters. Prints time to the first and to every mempool, how often the
/// submitter itself published (the causal form of the #145 finding: always, without Dandelion),
/// and how the stems ended. On loopback a hop costs a mint's verification plus a local round
/// trip, so this is the floor; on the fleet each hop adds a one-way network delay.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn dandelion_latency_against_publishing_at_once() {
    const TXS: usize = 10;
    let mut report = Vec::new();
    for (label, make) in [
        ("off", Box::new(|_: u64| DandelionConfig::off()) as Box<dyn Fn(u64) -> DandelionConfig>),
        ("on (q = 0.1, b = 3 s)", Box::new(|i: u64| DandelionConfig { seed: Some(40 + i), ..DandelionConfig::default() })),
    ] {
        let mut net = Net::start((0..5).map(&make).collect()).await;
        let (mut to_first, mut to_all, mut submitter_published) = (Vec::new(), Vec::new(), 0);
        for k in 1..=TXS {
            let tx = net.mint();
            let at_node = (k - 1) % 5;
            let before = net.all_fluffs();
            let at = net.submit_and_watch(at_node, &tx, k, Duration::from_secs(30)).await;
            submitter_published += usize::from(published_by(&before, &net.all_fluffs()).contains(&at_node));
            to_first.push(*at.iter().min().unwrap());
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
        eprintln!(
            "dandelion {label}: first mempool mean {fm:.1} ms (median {fmed:.1}, max {fmax:.1}); every mempool mean {am:.1} ms (median {amed:.1}, max {amax:.1}); submitter published {submitter_published}/{TXS}; stem sends {} ({:.1}/tx); fluffs coin {} embargo {} no-route {}",
            net.total(|d| &d.stem_sent),
            net.total(|d| &d.stem_sent) as f64 / TXS as f64,
            net.total(|d| &d.fluff_coin),
            net.total(|d| &d.fluff_embargo),
            net.total(|d| &d.fluff_no_route),
        );
        report.push(am);
        net.stop().await;
    }
    eprintln!("dandelion added {:.1} ms to the mean time to every mempool on loopback", report[1] - report[0]);
}

/// A first spy: a bare network node connected to every node of `net`, on both transaction lanes,
/// speaking no stem (so no node ever stems to it), that relays nothing and records, for each
/// transaction, the peer that first forwarded it — the first-spy estimator's guess at its origin —
/// and the lane each copy arrived on.
struct Spy {
    handle: network::NetworkHandle,
    seen: Arc<std::sync::Mutex<Vec<(Hash, libp2p::PeerId, network::GossipLane)>>>,
}

impl Spy {
    async fn join(net: &Net) -> Spy {
        let (handle, mut rx) = network::start_with(
            NetworkConfig {
                chain_id: net.gen.chain_id,
                listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                bootstrap: net.nodes.iter().map(common::cluster::bootstrap_addr).collect(),
                enable_mdns: false,
                limits: WireLimits::default(),
            },
            [98; 32],
            EdgeConfig::default(),
        )
        .await
        .unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let connected = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (record, count, reporter) = (seen.clone(), connected.clone(), handle.clone());
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                match ev {
                    NetworkEvent::PeerConnected(_) => {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                    NetworkEvent::Gossip { from, msg, id } => {
                        if let network::GossipMessage::Transaction(tx) = &msg {
                            record.lock().unwrap().push((tx.hash(), from, id.lane));
                        }
                        // Every delivery is answered; `Ignore`: the spy relays nothing.
                        reporter.report_validation(id, libp2p::gossipsub::MessageAcceptance::Ignore).await;
                    }
                    _ => {}
                }
            }
        });
        let n = net.nodes.len();
        common::cluster::wait_for("the spy is connected to every node", Duration::from_secs(30), || connected.load(Ordering::Relaxed) >= n).await;
        // Three gossip heartbeats, so every node has grafted the spy into its transaction mesh.
        tokio::time::sleep(Duration::from_millis(3000)).await;
        Spy { handle, seen }
    }

    /// The node (by index in `net`) that first forwarded `tx` to the spy.
    fn first_forwarder(&self, net: &Net, tx: &Hash) -> Option<usize> {
        let from = self.seen.lock().unwrap().iter().find(|(h, ..)| h == tx).map(|(_, from, _)| *from)?;
        net.nodes.iter().position(|n| n.handle.network.local_peer_id == from)
    }

    /// How many transaction copies reached the spy on the legacy signed topic.
    fn signed_copies(&self) -> usize {
        self.seen.lock().unwrap().iter().filter(|(.., lane)| *lane == network::GossipLane::Signed).count()
    }
}

/// The first-spy test (monorepo#27, PRIV-601), in process: the measurement that found the
/// submitter first in 27 of 27 traces on chain 21, re-run against this build's defaults with an
/// observer that is connected to every node and guesses each transaction's origin as the peer
/// that first forwarded it.
///
/// * Control, Dandelion off (how a node published before v0.8.3): the spy's guess is the
///   submitter for at least 8 of 10 transactions — the estimator works, so the next result means
///   something.
/// * Dandelion on at the defaults (q = 0.1, 3 s embargo), 20 transactions from rotating
///   submitters over a mixed fleet — two nodes on the anonymous lane only (a v0.9.0 node's
///   default), three on both lanes (a v0.8.x node's): the spy's guess is the submitter for at most
///   half of them, every mempool still gets every transaction, and both counts are printed.
/// * In both runs no copy reaches the spy on the legacy signed topic: nothing names a publisher.
///
/// Five nodes on loopback bound what this shows: with five nodes a stem ends back at the
/// submitter about one time in five. The fleet measurement is `docs/deploy.md`'s to record.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_first_spy_names_the_submitter_without_dandelion_and_rarely_with_it() {
    // (label, configs, nodes on the anonymous lane only, transactions)
    let runs: [(&str, Vec<DandelionConfig>, &[usize], usize); 2] = [
        ("off", (0..5).map(|_| DandelionConfig::off()).collect(), &[], 10),
        ("on (q = 0.1, b = 3 s)", (0..5).map(|i| DandelionConfig { seed: Some(60 + i), ..DandelionConfig::default() }).collect(), &[1, 3], 20),
    ];
    let mut named = Vec::new();
    for (label, configs, anonymous_only, txs) in runs {
        let mut net = Net::start_on_lanes(configs, anonymous_only).await;
        let spy = Spy::join(&net).await;
        let (mut spy_named_submitter, mut submitter_published, mut unheard) = (0, 0, 0);
        for k in 1..=txs {
            let tx = net.mint();
            let at_node = (k - 1) % 5;
            let before = net.all_fluffs();
            net.submit_and_watch(at_node, &tx, k, Duration::from_secs(30)).await;
            submitter_published += usize::from(published_by(&before, &net.all_fluffs()).contains(&at_node));
            let hash = tx.hash();
            let heard = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(first) = spy.first_forwarder(&net, &hash) {
                        return first;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;
            match heard {
                Ok(first) => spy_named_submitter += usize::from(first == at_node),
                Err(_) => unheard += 1,
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        eprintln!(
            "first spy, dandelion {label}: the spy named the submitter for {spy_named_submitter}/{txs}; the submitter itself published {submitter_published}/{txs}; unheard by the spy {unheard}; copies on the signed legacy topic {}",
            spy.signed_copies()
        );
        assert_eq!(unheard, 0, "dandelion {label}: the spy missed a transaction, so its count means nothing");
        assert_eq!(spy.signed_copies(), 0, "dandelion {label}: a transaction reached the spy on the signed legacy topic");
        named.push((spy_named_submitter, txs));
        spy.handle.shutdown().await;
        net.stop().await;
    }
    let ((off, off_txs), (on, on_txs)) = (named[0], named[1]);
    assert!(off * 10 >= off_txs * 8, "without Dandelion the first spy should name the submitter nearly always: {off}/{off_txs}");
    assert!(on * 2 <= on_txs, "with Dandelion the first spy named the submitter for more than half: {on}/{on_txs}");
}
