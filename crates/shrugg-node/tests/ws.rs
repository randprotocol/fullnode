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
        json!({ "jsonrpc": "2.0", "id": 1, "method": "shrugg_subscribe", "params": ["newHeads"] }).to_string(),
    ))
    .await
    .unwrap();
    let sub = wait_frame(&mut sock, Duration::from_secs(5), |v| {
        (v["id"] == json!(1)).then(|| v["result"].as_str().unwrap().to_string())
    })
    .await
    .expect("a subscription id");

    // Three heads arrive, strictly ascending, with the shape shrugg_getHead returns.
    let mut heights = Vec::new();
    while heights.len() < 3 {
        let h = wait_frame(&mut sock, Duration::from_secs(15), |v| {
            (v["method"] == json!("shrugg_subscription") && v["params"]["subscription"] == json!(sub.clone()))
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
        json!({ "jsonrpc": "2.0", "id": 2, "method": "shrugg_unsubscribe", "params": [sub] }).to_string(),
    ))
    .await
    .unwrap();
    assert_eq!(
        wait_frame(&mut sock, Duration::from_secs(2), |v| (v["id"] == json!(2)).then(|| v["result"].clone())).await,
        Some(json!(true))
    );
    assert!(
        wait_frame(&mut sock, Duration::from_millis(600), |v| {
            (v["method"] == json!("shrugg_subscription")).then_some(())
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
        (1, "shrugg_getHead", json!([])),         // a read: HTTP's job
        (2, "shrugg_subscribe", json!(["logs"])), // an unknown topic
        (3, "shrugg_unsubscribe", json!(["99"])), // an id this socket never held
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
    assert_eq!(second["error"]["code"], -32602, "newHeads is the only topic");
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
    for i in 0..shrugg_node::ws::MAX_WS_SUBSCRIPTIONS {
        sock.send(Message::Text(
            json!({ "jsonrpc": "2.0", "id": i, "method": "shrugg_subscribe", "params": ["newHeads"] }).to_string(),
        ))
        .await
        .unwrap();
        let got = wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(i)).then(|| v.clone()))
            .await
            .expect("a reply");
        assert!(got["result"].is_string(), "subscription {i}: {got}");
    }
    let over = shrugg_node::ws::MAX_WS_SUBSCRIPTIONS;
    sock.send(Message::Text(
        json!({ "jsonrpc": "2.0", "id": over, "method": "shrugg_subscribe", "params": ["newHeads"] }).to_string(),
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
    for i in 0..shrugg_node::ws::MAX_WS_CONNECTIONS {
        held.push(tokio_tungstenite::connect_async(&url).await.unwrap_or_else(|e| panic!("socket {i}: {e}")).0);
    }
    assert!(tokio_tungstenite::connect_async(&url).await.is_err(), "the cap is a hard bound");
    // And the count is visible to an operator. `publish_status` runs a pass of the node loop, so
    // give it one: the assertion is on the value, the wait only on it having been written once.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while node.status.read().unwrap().ws_clients != shrugg_node::ws::MAX_WS_CONNECTIONS
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(node.status.read().unwrap().ws_clients, shrugg_node::ws::MAX_WS_CONNECTIONS);
    drop(held);
    node.shutdown().await;
}

/// A frame bigger than the cap is not answered and not buffered — the socket ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_over_the_limit_ends_the_socket() {
    let (addr, _heads, _served) = common::serve_heads(4).await;
    let (mut sock, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/ws")).await.expect("upgrade");
    // A well-formed request, padded past the cap with a parameter nothing will ever read.
    let padding = "x".repeat(shrugg_node::ws::WS_MAX_FRAME_BYTES);
    let _ = sock
        .send(Message::Text(
            json!({ "jsonrpc": "2.0", "id": 1, "method": "shrugg_subscribe", "params": ["newHeads", padding] })
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
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "shrugg_getHead", "params": [] }))
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
        json!({ "jsonrpc": "2.0", "id": 1, "method": "shrugg_subscribe", "params": ["newHeads"] }).to_string(),
    ))
    .await
    .unwrap();
    assert!(wait_frame(&mut sock, Duration::from_secs(5), |v| (v["id"] == json!(1)).then_some(())).await.is_some());

    // Push heads far faster than a socket nobody is reading can take them. The client stops
    // reading here on purpose: that is what a slow subscriber is.
    let pump = tokio::spawn(async move {
        for height in 1u64..100_000 {
            if heads
                .send(shrugg_node::rpc::HeadSummary { height, hash: "ab".repeat(32), view: height })
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
