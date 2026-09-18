//! The WebSocket half of the RPC: a real listener, a real client, and a head that arrives
//! without anyone polling for it.

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

mod common; // reuse the cluster harness's genesis/keys helpers via a small shared module

/// Read frames until one satisfies `f`, or time out.
async fn wait_frame<S, T>(sock: &mut S, timeout: Duration, mut f: impl FnMut(Value) -> Option<T>) -> Option<T>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return None;
        }
        match tokio::time::timeout(left, sock.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                if let Some(v) = serde_json::from_str::<Value>(&t).ok().and_then(&mut f) {
                    return Some(v);
                }
            }
            Ok(Some(Ok(_))) => {}
            _ => return None,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscriber_is_pushed_every_committed_head() {
    let node = common::start_one_validator().await; // FAST (150 ms) blocks, no proving
    let url = format!("ws://{}/ws", node.rpc_addr);
    let (mut sock, _) = tokio_tungstenite::connect_async(&url).await.expect("upgrade");

    sock.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_subscribe", "params": ["newHeads"] }).to_string(),
    ))
    .await
    .unwrap();
    let sub = wait_frame(&mut sock, Duration::from_secs(5), |v| {
        (v["id"] == json!(1)).then(|| v["result"].as_str().unwrap().to_string())
    })
    .await
    .expect("a subscription id");

    // Three heads arrive, strictly ascending, with the shape rand_getHead returns.
    let mut heights = Vec::new();
    while heights.len() < 3 {
        let h = wait_frame(&mut sock, Duration::from_secs(15), |v| {
            (v["method"] == json!("rand_subscription") && v["params"]["subscription"] == json!(sub.clone()))
                .then(|| v["params"]["result"].clone())
        })
        .await
        .expect("a head notification");
        assert!(h["hash"].as_str().unwrap().len() == 64);
        assert!(h["view"].is_u64());
        heights.push(h["height"].as_u64().unwrap());
    }
    assert!(heights.windows(2).all(|w| w[1] > w[0]), "heads ascend: {heights:?}");

    // Unsubscribing stops them: nothing more arrives in three block intervals.
    sock.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": 2, "method": "rand_unsubscribe", "params": [sub] }).to_string(),
    ))
    .await
    .unwrap();
    assert_eq!(
        wait_frame(&mut sock, Duration::from_secs(2), |v| (v["id"] == json!(2)).then(|| v["result"].clone())).await,
        Some(json!(true))
    );
    assert!(
        wait_frame(&mut sock, Duration::from_millis(600), |v| {
            (v["method"] == json!("rand_subscription")).then_some(())
        })
        .await
        .is_none(),
        "an unsubscribed socket is quiet"
    );
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_socket_serves_only_subscribe_and_unsubscribe() {
    let node = common::start_one_validator().await;
    let (mut sock, _) = tokio_tungstenite::connect_async(format!("ws://{}/", node.rpc_addr))
        .await
        .expect("the bare path upgrades too");
    for (id, method, params) in [
        (1, "rand_getHead", json!([])),         // a read: HTTP's job
        (2, "rand_subscribe", json!(["logs"])), // an unknown topic
        (3, "rand_unsubscribe", json!(["99"])), // an id this socket never held
    ] {
        sock.send(Message::Text(
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string(),
        ))
        .await
        .unwrap();
    }
    let first = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(1)).then(|| v.clone()))
        .await
        .expect("a reply");
    assert_eq!(first["error"]["code"], -32601, "reads stay on HTTP POST");
    let second = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(2)).then(|| v.clone()))
        .await
        .expect("a reply");
    assert_eq!(second["error"]["code"], -32602, "an unknown topic is refused");
    let third = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(3)).then(|| v.clone()))
        .await
        .expect("a reply");
    assert_eq!(third["result"], json!(false), "unsubscribing something you do not hold is false, not an error");
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_may_hold_at_most_eight_subscriptions() {
    let node = common::start_one_validator().await;
    let (mut sock, _) = tokio_tungstenite::connect_async(format!("ws://{}/ws", node.rpc_addr)).await.expect("upgrade");
    for i in 0..randprotocol_node::ws::MAX_WS_SUBSCRIPTIONS {
        sock.send(Message::Text(
            json!({ "jsonrpc": "2.0", "id": i, "method": "rand_subscribe", "params": ["newHeads"] }).to_string(),
        ))
        .await
        .unwrap();
        let got = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(i)).then(|| v.clone()))
            .await
            .expect("a reply");
        assert!(got["result"].is_string(), "subscription {i}: {got}");
    }
    let over = randprotocol_node::ws::MAX_WS_SUBSCRIPTIONS;
    sock.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": over, "method": "rand_subscribe", "params": ["newHeads"] }).to_string(),
    ))
    .await
    .unwrap();
    let got = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(over)).then(|| v.clone()))
        .await
        .expect("a reply");
    assert_eq!(got["error"]["code"], -32000, "the ninth subscription is refused, not served: {got}");
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_cap_refuses_the_sixty_fifth_socket() {
    let node = common::start_one_validator().await;
    let url = format!("ws://{}/ws", node.rpc_addr);
    let mut held = Vec::new();
    for i in 0..randprotocol_node::ws::MAX_WS_CONNECTIONS {
        held.push(tokio_tungstenite::connect_async(&url).await.unwrap_or_else(|e| panic!("socket {i}: {e}")).0);
    }
    assert!(tokio_tungstenite::connect_async(&url).await.is_err(), "the cap is a hard bound");
    // And the count is visible to an operator. `publish_status` runs a pass of the node loop, so
    // give it one: the assertion is on the value, the wait only on it having been written once.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while node.status.read().unwrap().ws_clients != randprotocol_node::ws::MAX_WS_CONNECTIONS
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(node.status.read().unwrap().ws_clients, randprotocol_node::ws::MAX_WS_CONNECTIONS);
    drop(held);
    node.shutdown().await;
}

/// A frame bigger than the cap is not answered and not buffered — the socket ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_over_the_limit_ends_the_socket() {
    let (addr, _heads, _served) = common::serve_heads(4).await;
    let (mut sock, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await.expect("upgrade");
    // A well-formed request, padded past the cap with a parameter nothing will ever read.
    let padding = "x".repeat(randprotocol_node::ws::WS_MAX_FRAME_BYTES);
    let _ = sock
        .send(Message::Text(
            json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_subscribe", "params": ["newHeads", padding] })
                .to_string(),
        ))
        .await;
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match sock.next().await {
                // Never a reply: the frame is refused before it is a request at all.
                Some(Ok(Message::Text(t))) => panic!("an oversized frame was answered: {t}"),
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "an oversized frame ends the socket");
}

/// The route merge put a `GET` on `/` beside the `POST`. The POST is the whole HTTP RPC, so this
/// is the check that mounting the upgrade next to it changed nothing about it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_still_answers_json_rpc_on_the_merged_router() {
    let (addr, _heads, _served) = common::serve_heads(4).await;
    let body: Value = reqwest::Client::new()
        .post(format!("http://{addr}/"))
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_getHead", "params": [] }))
        .send()
        .await
        .expect("the POST route is still mounted")
        .json()
        .await
        .expect("a JSON-RPC body");
    assert_eq!(body["id"], json!(1));
    assert_eq!(body["result"]["height"], json!(0), "the genesis head");
    assert!(body["result"]["hash"].as_str().unwrap().len() == 64);
    assert!(body["result"]["view"].is_u64());

    // `GET /` is the upgrade now, so a plain browser GET is a bad upgrade request (400) rather
    // than the 405 a POST-only route answered. Documented in docs/rpc.md; asserted here so the
    // documentation cannot quietly stop being true.
    let plain = reqwest::Client::new().get(format!("http://{addr}/")).send().await.expect("a response");
    assert_eq!(plain.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// A subscriber that stops reading altogether does not get to hold a connection slot. This is the
/// denial the write deadline exists for: without it the node's task parks in the kernel's send
/// buffer until the link is torn down, and 64 such sockets close the endpoint to everyone while
/// `ws_clients` reports 64 healthy clients.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscriber_that_never_reads_is_dropped_and_frees_its_slot() {
    // Room for every head this test will push, so the channel cannot overrun: the *only* way out
    // of this connection is the write deadline, which is the thing being proved. (The lag path has
    // its own test, and with a small channel it would fire first and prove nothing about writes.)
    const HEADS: usize = 50_000;
    let (addr, heads, served) = common::serve_heads(HEADS).await;
    let (mut sock, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await.expect("upgrade");
    sock.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_subscribe", "params": ["newHeads"] }).to_string(),
    ))
    .await
    .unwrap();
    // The one and only read: after this the client goes silent, which is what a wedged client
    // looks like from here.
    assert!(wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(1)).then_some(())).await.is_some());
    assert_eq!(served.ws_conns(), 1, "the slot is held while the client is connected");

    // ~10 MB of notifications at a socket nobody is draining: far more than any kernel buffer, so
    // the node's write blocks and stays blocked.
    for height in 1..=HEADS as u64 {
        heads.send(randprotocol_node::rpc::HeadSummary { height, hash: "cd".repeat(32), view: height }).expect("a receiver");
    }

    let started = tokio::time::Instant::now();
    let left = served.wait_ws_conns(0, randprotocol_node::ws::WS_SEND_TIMEOUT * 6).await;
    let took = started.elapsed();
    assert_eq!(left, 0, "a client that stopped reading does not keep its slot");
    assert!(
        took >= randprotocol_node::ws::WS_SEND_TIMEOUT,
        "the slot came back in {took:?}, before the write deadline — this test is no longer proving it"
    );
    drop(sock);
}

/// A subscriber that cannot keep up is closed, not buffered: this node's memory is not a client's
/// to consume. `1008` is the code, and the reason says what happened.
///
/// Driven over a bare `rpc::serve` with a two-slot head channel rather than over a node, because
/// the rule belongs to the channel: outrunning the real 256-slot one 150 ms block at a time would
/// take most of a minute to observe the same thing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscriber_that_falls_behind_is_closed_with_1008() {
    let (addr, heads, _served) = common::serve_heads(2).await;
    let (mut sock, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await.expect("upgrade");
    sock.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_subscribe", "params": ["newHeads"] }).to_string(),
    ))
    .await
    .unwrap();
    assert!(wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(1)).then_some(())).await.is_some());

    // Push heads far faster than a socket nobody is reading can take them. The client stops
    // reading here on purpose: that is what a slow subscriber is.
    let pump = tokio::spawn(async move {
        for height in 1u64..100_000 {
            if heads
                .send(randprotocol_node::rpc::HeadSummary { height, hash: "ab".repeat(32), view: height })
                .is_err()
            {
                break; // the only receiver is gone: the socket has been closed
            }
            if height % 1000 == 0 {
                tokio::task::yield_now().await;
            }
        }
    });

    let frame = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match sock.next().await {
                Some(Ok(Message::Close(frame))) => return frame,
                Some(Ok(_)) => {}
                other => panic!("the socket ended without a close frame: {other:?}"),
            }
        }
    })
    .await
    .expect("the node closes a subscriber that falls behind")
    .expect("with a close frame");
    pump.abort();
    assert_eq!(u16::from(frame.code), 1008, "policy violation, so the client knows it was dropped on purpose");
    assert!(frame.reason.contains("behind"), "the reason says what happened: {}", frame.reason);
}

/// The `transaction` topic over a live node loop. Subscribed before submitting, a good mint's
/// subscription hears its commit and a bad mint's hears its refusal — with the reason
/// `rand_getTransactionStatus` gives, because both read the same refused cache. Subscribed
/// *after*, the same two outcomes arrive on the next block (the node makes empty ones), so a
/// client that POSTs first has the same one code path. Mints, as in `tests/submit.rs`: the same
/// path through the verify queue as a proof, at a thousandth of the cost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transaction_subscription_hears_its_commit_or_its_refusal_once() {
    use randprotocol_core::notes::Envelope;
    use randprotocol_core::{Action, Keypair, Transaction};

    let node = common::start_one_validator().await;
    let validator = Keypair::from_seed([101; 32]).unwrap();
    let env = |tag: u8| Envelope { kem_ct: vec![tag; 8], to_receiver: vec![tag; 4], to_sender: vec![], body: vec![tag; 16] };
    let good = Transaction::mint(7, [9; 8], env(1), 1000, &validator);
    // A signature over a different amount: a permanent refusal, so it enters the refused cache.
    let mut bad = Transaction::mint(7, [8; 8], env(2), 1000, &validator);
    if let Action::Mint { amount, .. } = &mut bad.action {
        *amount = 999;
    }

    let (mut sock, _) = tokio_tungstenite::connect_async(format!("ws://{}/ws", node.rpc_addr)).await.expect("upgrade");
    // Subscribe to `transaction` for each hash; the ids, in order.
    async fn subscribe<S>(sock: &mut S, first_id: u64, hashes: [&str; 2]) -> Vec<String>
    where
        S: SinkExt<Message> + StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
        <S as futures::Sink<Message>>::Error: std::fmt::Debug,
    {
        let mut subs = Vec::new();
        for (id, h) in (first_id..).zip(hashes) {
            let req = json!({ "jsonrpc": "2.0", "id": id, "method": "rand_subscribe", "params": ["transaction", h] });
            sock.send(Message::Text(req.to_string())).await.unwrap();
            let sub = wait_frame(sock, Duration::from_secs(5), |v| {
                (v["id"] == json!(id)).then(|| v["result"].as_str().expect("a subscription id").to_string())
            })
            .await
            .expect("a reply");
            subs.push(sub);
        }
        subs
    }
    // Both notifications, in whichever order the node reaches them; every frame is kept, since
    // waiting for one would throw the other away.
    async fn two_notifications<S>(sock: &mut S) -> Vec<Value>
    where
        S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        let mut got = Vec::new();
        while got.len() < 2 {
            let n = wait_frame(sock, Duration::from_secs(20), |v| {
                (v["method"] == json!("rand_subscription")).then(|| v["params"].clone())
            })
            .await
            .expect("a transaction notification");
            got.push(n);
        }
        got
    }
    let (good_hex, bad_hex) = (good.hash().to_hex(), bad.hash().to_hex());
    let subs = subscribe(&mut sock, 1, [&good_hex, &bad_hex]).await;

    let client = reqwest::Client::new();
    let post = |method: &'static str, params: Value| {
        let req = client
            .post(format!("http://{}/", node.rpc_addr))
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }));
        async move { req.send().await.unwrap().json::<Value>().await.unwrap() }
    };
    for tx in [&good, &bad] {
        post("rand_sendTransaction", json!([hex::encode(tx.encode())])).await;
    }

    let got = two_notifications(&mut sock).await;
    let of = |got: &[Value], sub: &String| {
        got.iter().find(|n| n["subscription"] == json!(sub)).expect("one per subscription")["result"].clone()
    };
    let committed = of(&got, &subs[0]);
    assert_eq!(committed["status"], json!("committed"), "{committed}");
    assert!(committed["height"].as_u64().unwrap() > 0 && committed["index"].is_u64(), "{committed}");
    let rejected = of(&got, &subs[1]);
    assert_eq!(rejected["status"], json!("rejected"), "{rejected}");
    let status = post("rand_getTransactionStatus", json!([[bad.hash().to_hex()]])).await;
    assert_eq!(rejected["reason"], status["result"][0]["reason"], "the same reason: {status}");

    // Delivered once, then gone: unsubscribing either is `false`.
    for (id, sub) in [(3, &subs[0]), (4, &subs[1])] {
        sock.send(Message::Text(
            json!({ "jsonrpc": "2.0", "id": id, "method": "rand_unsubscribe", "params": [sub] }).to_string(),
        ))
        .await
        .unwrap();
        let r = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(id)).then(|| v["result"].clone())).await;
        assert_eq!(r, Some(json!(false)), "a delivered transaction subscription removes itself");
    }

    // Subscribed after the fact: the same outcomes, on the next block rather than synchronously.
    let late = subscribe(&mut sock, 5, [&good_hex, &bad_hex]).await;
    let got = two_notifications(&mut sock).await;
    assert_eq!(of(&got, &late[0]), committed, "the stored location, as it was announced live");
    assert_eq!(of(&got, &late[1]), rejected, "the cached refusal, as it was announced live");
    node.shutdown().await;
}
