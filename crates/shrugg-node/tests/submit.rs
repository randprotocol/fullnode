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
use shrugg_core::notes::Envelope;
use shrugg_core::{Action, Keypair, Transaction};
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

    let (peer, _rx) = shrugg_node::network::start(
        shrugg_node::network::NetworkConfig {
            chain_id: 7,
            listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap: vec![target],
            enable_mdns: false,
        },
        [77u8; 32],
    )
    .await
    .unwrap();

    let mut bad = Transaction::mint(7, [7; 8], env(3), 1000, &validator);
    if let Action::Mint { amount, .. } = &mut bad.action {
        *amount = 998;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut cached = false;
    while !cached && tokio::time::Instant::now() < deadline {
        peer.broadcast(shrugg_node::network::GossipMessage::Transaction(bad.clone())).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let st = rpc(addr, "shrugg_status", json!([])).await;
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
    let good = Transaction::mint(7, [9; 8], env(1), 1000, &validator);
    let r = rpc(addr, "shrugg_sendTransaction", json!([hex::encode(good.encode())])).await;
    assert!(r.get("result").is_some(), "valid mint refused: {r}");
    assert_eq!(r["result"].as_str().unwrap(), good.hash().to_hex());

    // 2. A mint whose signature covers a different amount: validate answers BadMintSignature, which
    //    is permanent, so it is rejected and cached.
    let mut bad = Transaction::mint(7, [8; 8], env(2), 1000, &validator);
    if let Action::Mint { amount, .. } = &mut bad.action {
        *amount = 999;
    }
    let r = rpc(addr, "shrugg_sendTransaction", json!([hex::encode(bad.encode())])).await;
    let first = r["error"]["message"].as_str().expect("an error").to_string();
    assert!(first.contains("signature"), "unexpected error: {first}");

    // 3. And the second submission of the same bytes is answered from the refused cache, with the
    //    same message.
    let r = rpc(addr, "shrugg_sendTransaction", json!([hex::encode(bad.encode())])).await;
    assert_eq!(r["error"]["message"].as_str().unwrap(), first);

    // 4. The status fields say so.
    let st = rpc(addr, "shrugg_status", json!([])).await;
    assert_eq!(st["result"]["refused_cache"], json!(1), "{st}");
    assert_eq!(st["result"]["verify_queue"], json!(0), "{st}");

    // 5. The good mint reached the pool and commits, so the loop is still turning.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut committed = false;
    while !committed && tokio::time::Instant::now() < deadline {
        let got = rpc(addr, "shrugg_getTransaction", json!([good.hash().to_hex()])).await;
        committed = got.get("result").map(|v| !v.is_null()).unwrap_or(false);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(committed, "the mint never committed");

    node.shutdown().await;
}
