//! The WebSocket half of the RPC: a `newHeads` subscription, so an explorer or a wallet stops
//! polling `shrugg_getHead`.
//!
//! Three bounds hold this endpoint, because it is unauthenticated: a per-node connection cap, a
//! per-connection subscription cap, and a bounded broadcast channel whose lagging receivers are
//! *closed* rather than buffered. Buffering a slow subscriber is how a node runs out of memory; a
//! dropped one reconnects and resyncs from `shrugg_getCompactBlocks`, which is the documented
//! recovery.
//!
//! Reads are not served here. A subscription is cheap — one channel receiver and a map — while a
//! read is `shrugg_getWitness` rebuilding the commitment tree, and serving those over a socket
//! would need its own blocking-pool and concurrency discipline to gain what `POST /` already does.

use crate::rpc::{HeadSummary, RpcState};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering::SeqCst;
use tokio::sync::broadcast::error::RecvError;

/// WebSocket clients one node will carry at once. The 65th is refused at the upgrade.
pub const MAX_WS_CONNECTIONS: usize = 64;

/// Subscriptions one connection may hold. One topic exists, so eight is already generous; the cap
/// is here because the map is the one thing a client can make grow without limit.
pub const MAX_WS_SUBSCRIPTIONS: usize = 8;

/// The largest frame either direction may carry. A request here is a hundred bytes and a head
/// notification about two hundred; 64 KiB is room for a client's own framing and nothing like
/// enough for the proof-carrying bodies `POST /` takes.
pub const WS_MAX_FRAME_BYTES: usize = 64 * 1024;

/// The one topic this node serves.
const NEW_HEADS: &str = "newHeads";

/// WebSocket close code 1008 "policy violation": what a subscriber that could not keep up is
/// closed with, so the reason reaches the client rather than looking like a dropped TCP link.
const CLOSE_POLICY: u16 = 1008;

/// The upgrade handler, mounted by [`crate::rpc::serve`] on `GET /` and `GET /ws`.
pub async fn upgrade(State(st): State<RpcState>, ws: WebSocketUpgrade) -> Response {
    // Claim a slot before upgrading: an upgrade the node then closes looks like a network fault to
    // the client, while a 503 says exactly what happened.
    if st.ws_conns.fetch_update(SeqCst, SeqCst, |n| (n < MAX_WS_CONNECTIONS).then_some(n + 1)).is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("this node serves at most {MAX_WS_CONNECTIONS} websocket clients"),
        )
            .into_response();
    }
    let failed = st.clone();
    ws.max_message_size(WS_MAX_FRAME_BYTES)
        .max_frame_size(WS_MAX_FRAME_BYTES)
        // The slot is claimed above, before the handshake can fail, so it has to be released on
        // both exits or a client that disappears mid-handshake leaks one until restart.
        .on_failed_upgrade(move |e| {
            tracing::debug!("websocket upgrade failed: {e}");
            release(&failed);
        })
        .on_upgrade(move |socket| run(socket, st))
}

/// One connection: its own receiver on the head channel, and its own subscription map.
async fn run(mut socket: WebSocket, st: RpcState) {
    let mut heads = st.heads.subscribe();
    // Subscription id -> topic. One topic today; the map is what makes unsubscribe a lookup rather
    // than a boolean, and what the per-connection cap counts.
    let mut subs: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut next_id = 1u64;
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                let Some(Ok(msg)) = incoming else { break };
                // Pings and pongs are answered by axum; a close is the `None`/`Err` above or a
                // `Message::Close`, and either way there is nothing to reply to.
                let Message::Text(text) = msg else { continue };
                let reply = on_request(&text, &mut subs, &mut next_id);
                if socket.send(Message::Text(reply)).await.is_err() { break }
            }
            head = heads.recv() => match head {
                Ok(h) => {
                    let Some(frames) = notifications(&subs, &h) else { continue };
                    let mut ok = true;
                    for frame in frames {
                        if socket.send(Message::Text(frame)).await.is_err() { ok = false; break }
                    }
                    if !ok { break }
                }
                // The subscriber missed `n` heads: it cannot be made whole from here, and
                // buffering it is what this cap exists to prevent.
                Err(RecvError::Lagged(n)) => {
                    tracing::debug!("closing a websocket subscriber that fell {n} heads behind");
                    let reason =
                        format!("subscriber fell {n} heads behind; reconnect and catch up with shrugg_getCompactBlocks");
                    let frame = CloseFrame { code: CLOSE_POLICY, reason: reason.into() };
                    let _ = socket.send(Message::Close(Some(frame))).await;
                    break;
                }
                // The node loop is gone: so is this node.
                Err(RecvError::Closed) => break,
            }
        }
    }
    release(&st);
}

/// One `shrugg_subscription` frame per subscription this connection holds, or `None` when it
/// holds none — the common case for a socket that has connected and not yet subscribed, and the
/// one that must not cost a serialization.
fn notifications(subs: &BTreeMap<String, &'static str>, head: &HeadSummary) -> Option<Vec<String>> {
    if subs.is_empty() {
        return None;
    }
    let result = serde_json::to_value(head).ok()?;
    Some(
        subs.keys()
            .map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "method": "shrugg_subscription",
                    "params": { "subscription": id, "result": result },
                })
                .to_string()
            })
            .collect(),
    )
}

/// One text frame in, one response object out — as a string, because every outcome here is a
/// reply and nothing on this socket is fire-and-forget.
fn on_request(text: &str, subs: &mut BTreeMap<String, &'static str>, next_id: &mut u64) -> String {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return err(Value::Null, -32600, "invalid request: not JSON".into());
    };
    // A frame with no `id` is a JSON-RPC notification, which this node refuses on the socket for
    // the same reason it refuses one over HTTP: a subscribe whose id never comes back is a
    // subscription the client cannot ever cancel.
    let Some(id) = v.get("id").cloned() else {
        let m = "this node does not accept notifications; every request must carry an id";
        return err(Value::Null, -32600, m.into());
    };
    let Some(method) = v.get("method").and_then(Value::as_str) else {
        return err(id, -32600, "invalid request: no method".into());
    };
    let params = v.get("params").cloned().unwrap_or(Value::Null);
    match method {
        "shrugg_subscribe" => match params.get(0).and_then(Value::as_str) {
            Some(NEW_HEADS) => {
                if subs.len() >= MAX_WS_SUBSCRIPTIONS {
                    return err(
                        id,
                        -32000,
                        format!("at most {MAX_WS_SUBSCRIPTIONS} subscriptions per connection"),
                    );
                }
                let sub = next_id.to_string();
                *next_id += 1;
                subs.insert(sub.clone(), NEW_HEADS);
                json!({ "jsonrpc": "2.0", "id": id, "result": sub }).to_string()
            }
            Some(other) => err(id, -32602, format!("unknown subscription topic {other}; this node serves {NEW_HEADS}")),
            None => err(id, -32602, format!("shrugg_subscribe takes one topic, which must be {NEW_HEADS}")),
        },
        "shrugg_unsubscribe" => match params.get(0).and_then(Value::as_str) {
            // A bool, `false` for an id this socket never held rather than an error: that is what
            // Ethereum clients answer, and a client tearing down after a reconnect has no way to
            // know which ids survived.
            Some(sub) => json!({ "jsonrpc": "2.0", "id": id, "result": subs.remove(sub).is_some() }).to_string(),
            None => err(id, -32602, "shrugg_unsubscribe takes one subscription id, as a string".into()),
        },
        other => err(
            id,
            -32601,
            format!("the websocket serves shrugg_subscribe and shrugg_unsubscribe; reads go to POST / (got {other})"),
        ),
    }
}

fn err(id: Value, code: i64, message: String) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

/// Give the connection slot back. Called exactly once per claimed slot, on either exit.
fn release(st: &RpcState) {
    st.ws_conns.fetch_sub(1, SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (BTreeMap<String, &'static str>, u64) {
        (BTreeMap::new(), 1)
    }

    fn call(subs: &mut BTreeMap<String, &'static str>, next: &mut u64, req: Value) -> Value {
        serde_json::from_str(&on_request(&req.to_string(), subs, next)).unwrap()
    }

    #[test]
    fn subscribing_hands_back_an_id_that_unsubscribe_takes() {
        let (mut subs, mut next) = fresh();
        let r = call(&mut subs, &mut next, json!({ "id": 1, "method": "shrugg_subscribe", "params": ["newHeads"] }));
        assert_eq!(r["result"], json!("1"));
        assert_eq!(subs.len(), 1);
        let r = call(&mut subs, &mut next, json!({ "id": 2, "method": "shrugg_unsubscribe", "params": ["1"] }));
        assert_eq!(r["result"], json!(true));
        assert!(subs.is_empty());
        // The same id a second time is `false`, not an error, and ids are never reused.
        let r = call(&mut subs, &mut next, json!({ "id": 3, "method": "shrugg_unsubscribe", "params": ["1"] }));
        assert_eq!(r["result"], json!(false));
        let r = call(&mut subs, &mut next, json!({ "id": 4, "method": "shrugg_subscribe", "params": ["newHeads"] }));
        assert_eq!(r["result"], json!("2"), "a released id is not handed out again");
    }

    #[test]
    fn the_ninth_subscription_is_refused() {
        let (mut subs, mut next) = fresh();
        for i in 0..MAX_WS_SUBSCRIPTIONS {
            let req = json!({ "id": i, "method": "shrugg_subscribe", "params": ["newHeads"] });
            let r = call(&mut subs, &mut next, req);
            assert!(r["result"].is_string(), "subscription {i}: {r}");
        }
        let r = call(&mut subs, &mut next, json!({ "id": 9, "method": "shrugg_subscribe", "params": ["newHeads"] }));
        assert_eq!(r["error"]["code"], -32000);
        assert_eq!(subs.len(), MAX_WS_SUBSCRIPTIONS, "a refused subscribe leaves the map alone");
    }

    #[test]
    fn everything_but_the_two_subscription_methods_is_refused() {
        let (mut subs, mut next) = fresh();
        let r = call(&mut subs, &mut next, json!({ "id": 1, "method": "shrugg_getHead", "params": [] }));
        assert_eq!(r["error"]["code"], -32601);
        let r = call(&mut subs, &mut next, json!({ "id": 2, "method": "shrugg_subscribe", "params": ["logs"] }));
        assert_eq!(r["error"]["code"], -32602);
        let r = call(&mut subs, &mut next, json!({ "id": 3, "method": "shrugg_subscribe", "params": [] }));
        assert_eq!(r["error"]["code"], -32602);
        let r = call(&mut subs, &mut next, json!({ "id": 4, "method": "shrugg_unsubscribe", "params": [7] }));
        assert_eq!(r["error"]["code"], -32602, "a subscription id is a string");
        assert!(subs.is_empty());
    }

    #[test]
    fn a_frame_that_is_not_a_request_answers_with_a_null_id() {
        let (mut subs, mut next) = fresh();
        let r: Value = serde_json::from_str(&on_request("not json", &mut subs, &mut next)).unwrap();
        assert_eq!(r["error"]["code"], -32600);
        assert_eq!(r["id"], Value::Null);
        let r = call(&mut subs, &mut next, json!({ "method": "shrugg_subscribe", "params": ["newHeads"] }));
        assert_eq!(r["error"]["code"], -32600, "a notification is refused, as it is over HTTP");
        assert!(subs.is_empty());
        let r = call(&mut subs, &mut next, json!({ "id": 1 }));
        assert_eq!(r["error"]["code"], -32600);
    }

    #[test]
    fn a_head_goes_to_every_subscription_the_connection_holds_and_to_no_others() {
        let (mut subs, mut next) = fresh();
        let head = HeadSummary { height: 7, hash: "ab".repeat(32), view: 9 };
        assert!(notifications(&subs, &head).is_none(), "a socket with no subscription is not written to");
        for i in 0..3 {
            call(&mut subs, &mut next, json!({ "id": i, "method": "shrugg_subscribe", "params": ["newHeads"] }));
        }
        let frames = notifications(&subs, &head).expect("three frames");
        assert_eq!(frames.len(), 3);
        for (frame, want) in frames.iter().zip(["1", "2", "3"]) {
            let v: Value = serde_json::from_str(frame).unwrap();
            assert_eq!(v["method"], json!("shrugg_subscription"));
            assert_eq!(v["params"]["subscription"], json!(want));
            // Exactly `shrugg_getHead`'s three fields, so a client can use one parser for both.
            assert_eq!(v["params"]["result"], json!({ "height": 7, "hash": "ab".repeat(32), "view": 9 }));
            assert!(v.get("id").is_none(), "a notification carries no id");
        }
    }
}
