//! Transaction admission on a live node loop, over both doors a transaction comes in by.
//!
//! Everything here is about the path rather than about a proof, so it runs on mints: a mint is
//! validated by a signature instead of a STARK, which is the same journey through the queue at a
//! thousandth of the cost. The two tests are the two halves of the exactly-once reporting rule —
//! an RPC submission answers its caller after a worker verified it, and a gossiped transaction is
//! verified off the loop and its permanent refusal remembered — and both are invisible to the unit
//! tests, which decide the *policy* without a loop to run it on.

mod common;

use serde_json::{json, Value};
use randprotocol_core::notes::Envelope;
use randprotocol_core::{Action, Keypair, Transaction};
use std::time::Duration;

async fn rpc(addr: std::net::SocketAddr, method: &str, params: Value) -> Value {
    reqwest::Client::new()
        .post(format!("http://{addr}/"))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn env(tag: u8) -> Envelope {
    Envelope { kem_ct: vec![tag; 8], to_receiver: vec![tag; 4], to_sender: vec![], body: vec![tag; 16] }
}

/// The gossip half: a raw libp2p peer publishes a transaction on the tx topic, and the node
/// prechecks it, verifies it off the loop, and caches the permanent refusal — which is the whole
/// chain of `on_gossiped_tx` -> queue -> worker -> `on_verdict` -> report.
#[tokio::test]
async fn a_gossiped_transaction_is_verified_off_the_loop_and_its_refusal_cached() {
    let node = common::start_one_validator().await;
    let addr = node.rpc_addr;
    let validator = Keypair::from_seed([101; 32]).unwrap();
    let target = node.listen_addrs[0]
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(node.network.local_peer_id));

    let (peer, _rx) = randprotocol_node::network::start(
        randprotocol_node::network::NetworkConfig {
            chain_id: 7,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![target],
            enable_mdns: false,
            limits: Default::default(),
        },
        [77u8; 32],
    )
    .await
    .unwrap();

    let mut bad = Transaction::mint(7, [7; 8], 0, [7; 8], env(3), 1000, &validator, &real_executor());
    if let Action::Mint { amount, .. } = &mut bad.action {
        *amount = 998;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut cached = false;
    while !cached && tokio::time::Instant::now() < deadline {
        peer.broadcast(randprotocol_node::network::GossipMessage::Transaction(bad.clone())).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let st = rpc(addr, "rand_status", json!([])).await;
        cached = st["result"]["refused_cache"] == json!(1);
    }
    assert!(cached, "the node never verified and cached the gossiped transaction");

    peer.shutdown().await;
    node.shutdown().await;
}

/// The RPC half: the caller's answer now comes back from a worker's verdict rather than from a
/// verification on the consensus loop — the same answers, including the error messages
/// `docs/rpc.md` quotes, and a second submission of a permanently bad transaction served from the
/// refused cache without verifying anything.
#[tokio::test]
async fn the_rpc_submission_path_runs_through_the_verify_queue() {
    let node = common::start_one_validator().await;
    let addr = node.rpc_addr;
    let validator = Keypair::from_seed([101; 32]).unwrap();

    // 1. A valid mint, signed by the chain's one validator: precheck passes, the verdict comes back
    //    from a blocking worker, and the caller hears a hash.
    let good = Transaction::mint(7, [9; 8], 0, [9; 8], env(1), 1000, &validator, &real_executor());
    let r = rpc(addr, "rand_sendTransaction", json!([hex::encode(good.encode())])).await;
    assert!(r.get("result").is_some(), "valid mint refused: {r}");
    assert_eq!(r["result"].as_str().unwrap(), good.hash().to_hex());

    // 2. A mint whose signature covers a different amount: validate answers BadMintSignature, which
    //    is permanent, so it is rejected and cached.
    let mut bad = Transaction::mint(7, [8; 8], 0, [8; 8], env(2), 1000, &validator, &real_executor());
    if let Action::Mint { amount, .. } = &mut bad.action {
        *amount = 999;
    }
    let r = rpc(addr, "rand_sendTransaction", json!([hex::encode(bad.encode())])).await;
    let first = r["error"]["message"].as_str().expect("an error").to_string();
    assert!(first.contains("signature"), "unexpected error: {first}");

    // 3. And the second submission of the same bytes is answered from the refused cache, with the
    //    same message.
    let r = rpc(addr, "rand_sendTransaction", json!([hex::encode(bad.encode())])).await;
    assert_eq!(r["error"]["message"].as_str().unwrap(), first);

    // 4. The status fields say so.
    let st = rpc(addr, "rand_status", json!([])).await;
    assert_eq!(st["result"]["refused_cache"], json!(1), "{st}");
    assert_eq!(st["result"]["verify_queue"], json!(0), "{st}");

    // 5. The good mint reached the pool and commits, so the loop is still turning.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut committed = false;
    while !committed && tokio::time::Instant::now() < deadline {
        let got = rpc(addr, "rand_getTransaction", json!([good.hash().to_hex()])).await;
        committed = got.get("result").map(|v| !v.is_null()).unwrap_or(false);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(committed, "the mint never committed");

    node.shutdown().await;
}

/// The aggregate arm of the gossip path: a gossiped `Aggregate` goes through the same queue to
/// a worker, which runs the covered-carrying validation — and a verdict about its bytes is
/// cached, exactly like the mint's. The chain is aggregation-gated (the gate is the
/// preflight's first check) and the transaction's chain id is wrong: a permanent refusal,
/// reached before any state — no aggregator registered, no cover looked up — is consulted.
///
/// **Ignored since the hidden-asset bundle (node I2).** `node::check_build_runs_genesis` bails on
/// any genesis carrying an `aggregation` section until the admitted shapes and the recursion
/// fixtures are re-measured for the new bundle guest, and this is the only caller of
/// `start_one_validator_aggregating`. It cannot be moved to an ungated chain either: on one,
/// `preflight_aggregate` answers `UnsupportedAction` (deliberately not permanent) *before*
/// `WrongChain`, so nothing is cached and the assertion has nothing to observe — and the generic
/// gossip → queue → worker → refused-cache path is already pinned by
/// `a_gossiped_transaction_is_verified_off_the_loop_and_its_refusal_cached` in this file.
/// Un-ignore with the re-measurement work.
#[tokio::test]
#[ignore = "aggregation is refused at startup on the hidden-asset bundle until its admitted shape is re-measured (b053a76)"]
async fn a_gossiped_aggregate_is_verified_off_the_loop_and_its_refusal_cached() {
    let node = common::start_one_validator_aggregating(randprotocol_core::ledger::aggregation::AggregationConfig {
        bond: 100 * randprotocol_core::UNITS_PER_RAND,
        max_covers: 3,
        subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
        halving_blocks: 210_000,
        window: 256,
        // No shapes admitted: nothing warms at startup, and this test's refusal never reaches
        // the shape checks.
        admitted_shapes: vec![],
    })
    .await;
    let addr = node.rpc_addr;
    let target = node.listen_addrs[0]
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(node.network.local_peer_id));

    let (peer, _rx) = randprotocol_node::network::start(
        randprotocol_node::network::NetworkConfig {
            chain_id: 7,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![target],
            enable_mdns: false,
            limits: Default::default(),
        },
        [78u8; 32],
    )
    .await
    .unwrap();

    let kp = Keypair::from_seed([102; 32]).unwrap();
    let aggregator = kp.public_key().address();
    // A fresh copy per broadcast: gossipsub dedupes a byte-identical message after the first
    // publish, so re-gossiping the same bytes can race the mesh and never land — each attempt
    // gets its own proof bytes (and hash); the verdict is the same WrongChain for all of them.
    let attempt = |tag: u8| {
        let covers = vec![randprotocol_core::Hash::digest(&[tag])];
        let proof = vec![tag; 8];
        let r = [9u32; 8];
        Transaction {
            chain_id: 99,
            bundle: None,
            action: Action::Aggregate {
                covers: covers.clone(),
                proof: proof.clone(),
                aggregator,
                nonce: 0,
                time: 0,
                r,
                envelope: env(4),
                signature: kp.sign(
                    randprotocol_core::types::actions::aggregate_signing_hash(99, 0, 0, &r, &covers, &randprotocol_core::Hash::digest(&proof))
                        .as_bytes(),
                ),
            },
        }
    };

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut cached = 0;
    let mut tag = 1u8;
    while cached == 0 && tokio::time::Instant::now() < deadline {
        tag = tag.wrapping_add(1);
        peer.broadcast(randprotocol_node::network::GossipMessage::Transaction(attempt(tag))).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let st = rpc(addr, "rand_status", json!([])).await;
        cached = st["result"]["refused_cache"].as_u64().unwrap_or(0);
    }
    assert!(cached > 0, "the node never verified and cached a gossiped aggregate");

    // And the verdict behind the cache entry is the WrongChain the preflight answers: the RPC
    // door hears it too (served from the cache on this resubmission).
    let r = rpc(addr, "rand_sendTransaction", json!([hex::encode(attempt(tag).encode())])).await;
    let msg = r["error"]["message"].as_str().unwrap_or_default().to_string();
    assert!(msg.contains("wrong chain id"), "unexpected error: {msg} ({r})");

    peer.shutdown().await;
    node.shutdown().await;
}

/// The node's own commitment function (a mint's `cm` must be the one admission derives), without
/// the prover: `note_commitment` is a plain hash, the same under every FRI profile.
fn real_executor() -> randprotocol_zkvm::executor::ZkExecutor {
    randprotocol_zkvm::executor::ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test)
}
