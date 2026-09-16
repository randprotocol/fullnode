//! The WebSocket half of the RPC: a `newHeads` subscription, so an explorer or a wallet stops
//! polling `rand_getHead`.
//!
//! Four bounds hold this endpoint, because it is unauthenticated: a per-node connection cap, a
//! per-connection subscription cap, a bounded broadcast channel whose lagging receivers are
//! *closed* rather than buffered, and a deadline on every write. Buffering a slow subscriber is
//! how a node runs out of memory; a dropped one reconnects and resyncs from
//! `rand_getCompactBlocks`, which is the documented recovery.
//!
//! The write deadline is what makes "closed rather than buffered" true of the *socket* and not
//! only of the channel. A client that subscribes and then stops reading fills its TCP window, and
//! an unbounded `send().await` parks this task in the kernel's buffer instead: the connection slot
//! is held until the OS tears the link down, which is minutes, and 64 such sockets from one host
//! close the endpoint to everyone else while `ws_clients` reports 64 healthy clients. A write that
//! does not complete inside [`WS_SEND_TIMEOUT`] is a dead client, and the socket is dropped rather
//! than written to again. [`WS_PING_INTERVAL`] covers the other half of it: a connection that
//! never subscribes and never reads is never written to at all, so it is pinged, and a pong that
//! does not come back inside the same deadline ends it.
//!
//! Reads are not served here. A subscription is cheap — one channel receiver and a map — while a
//! read is `rand_getWitness` rebuilding the commitment tree, and serving those over a socket
//! would need its own blocking-pool and concurrency discipline to gain what `POST /` already does.

use crate::rpc::{HeadSummary, RpcState};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;
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

/// How long one outbound frame may take before the client is treated as dead.
///
/// This is a bound on a *write into a socket buffer*, not on a round trip: a client that is
/// reading at all takes a 200-byte notification in microseconds. Five seconds is therefore
/// generous even across a bad link, and what it refuses is the client that has stopped reading
/// entirely — which is precisely the one this node must not hold a slot for. The socket is
/// dropped on expiry rather than written to again; there is nothing useful to say to a peer that
/// is not reading.
pub const WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// How often a connection with nothing to say is pinged, and within [`WS_SEND_TIMEOUT`] of which
/// a pong must come back.
///
/// Without it a socket that never subscribes is never written to, so no write deadline ever
/// applies to it and it holds its slot until the peer or the OS gives up. Thirty seconds is well
/// inside the idle timeout of any proxy that would sit in front of this, and costs two frames a
/// minute per client.
pub const WS_PING_INTERVAL: Duration = Duration::from_secs(30);

/// WebSocket close code 1008 "policy violation": what a subscriber that could not keep up is
/// closed with, so the reason reaches the client rather than looking like a dropped TCP link.
const CLOSE_POLICY: u16 = 1008;

/// One of this node's [`MAX_WS_CONNECTIONS`] connection slots, held for as long as the connection
/// is.
///
/// A guard rather than a pair of counter statements: the slot is claimed before the handshake, so
/// releasing it by hand means getting every exit right — the handshake that fails, the loop that
/// breaks, and a panic anywhere inside a connection. A leaked slot is permanent until restart and
/// invisible except as an endpoint that slowly stops accepting clients.
struct ConnSlot(Arc<AtomicUsize>);

impl ConnSlot {
    /// Claim a slot, or `None` if the node is already at the cap.
    fn claim(conns: &Arc<AtomicUsize>) -> Option<ConnSlot> {
        conns.fetch_update(SeqCst, SeqCst, |n| (n < MAX_WS_CONNECTIONS).then_some(n + 1)).ok()?;
        Some(ConnSlot(conns.clone()))
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        // `checked_sub` rather than `fetch_sub`: one released slot too many would wrap the count to
        // `usize::MAX` and refuse every client from then on, which is a far worse failure than the
        // over-count it would be correcting.
        let _ = self.0.fetch_update(SeqCst, SeqCst, |n| n.checked_sub(1));
    }
}

/// The upgrade handler, mounted by [`crate::rpc::serve`] on `GET /` and `GET /ws`.
pub async fn upgrade(State(st): State<RpcState>, ws: WebSocketUpgrade) -> Response {
    // Claim a slot before upgrading: an upgrade the node then closes looks like a network fault to
    // the client, while a 503 says exactly what happened.
    let Some(slot) = ConnSlot::claim(&st.ws_conns) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("this node serves at most {MAX_WS_CONNECTIONS} websocket clients"),
        )
            .into_response();
    };
    ws.max_message_size(WS_MAX_FRAME_BYTES)
        .max_frame_size(WS_MAX_FRAME_BYTES)
        .on_failed_upgrade(|e| tracing::debug!("websocket upgrade failed: {e}"))
        // `slot` moves into the callback, which is the one place it can be. It is released when
        // the connection ends, and equally when the handshake fails and the callback is dropped
        // without ever being called.
        .on_upgrade(move |socket| run(socket, st, slot))
}

/// Write one frame, or give up on the client. `false` ends the connection, and the caller must not
/// write again: a socket that missed its deadline is not going to take a close frame either.
async fn send_or_give_up(socket: &mut WebSocket, msg: Message) -> bool {
    match tokio::time::timeout(WS_SEND_TIMEOUT, socket.send(msg)).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            tracing::debug!("websocket write failed: {e}");
            false
        }
        Err(_) => {
            tracing::debug!("closing a websocket client that did not take a frame in {WS_SEND_TIMEOUT:?}");
            false
        }
    }
}

/// Sleep until `at`, or forever when there is no deadline to wait for.
async fn deadline(at: Option<tokio::time::Instant>) {
    match at {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

/// One connection: its own receiver on the head channel, and its own subscription map.
///
/// `slot` is never read. It is this connection's claim on [`MAX_WS_CONNECTIONS`], and dropping it
/// — on any exit from this function, a panic included — is what gives the slot back.
async fn run(mut socket: WebSocket, st: RpcState, slot: ConnSlot) {
    let _slot = slot;
    let mut heads = st.heads.subscribe();
    // Subscription id -> topic. One topic today; the map is what makes unsubscribe a lookup rather
    // than a boolean, and what the per-connection cap counts.
    let mut subs: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut next_id = 1u64;
    // The first ping is one interval away, not immediate: a client that has just connected has
    // said everything it needs to.
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + WS_PING_INTERVAL, WS_PING_INTERVAL);
    // When the pong for an outstanding ping stops being worth waiting for. `None` while none is
    // outstanding.
    let mut pong_due: Option<tokio::time::Instant> = None;
    loop {
        tokio::select! {
            incoming = socket.recv() => {
                let Some(Ok(msg)) = incoming else { break };
                match msg {
                    Message::Text(text) => {
                        let reply = on_request(&text, &mut subs, &mut next_id);
                        if !send_or_give_up(&mut socket, Message::Text(reply)).await { break }
                    }
                    // The keepalive came back, so this client is alive whether or not it has
                    // anything subscribed.
                    Message::Pong(_) => pong_due = None,
                    // A client's ping is answered by axum; a close ends the stream on the next
                    // poll; binary is not a request here.
                    _ => {}
                }
            }
            head = heads.recv() => match head {
                Ok(h) => {
                    let Some(frames) = notifications(&subs, &h) else { continue };
                    let mut ok = true;
                    for frame in frames {
                        if !send_or_give_up(&mut socket, Message::Text(frame)).await { ok = false; break }
                    }
                    if !ok { break }
                }
                // The subscriber missed `n` heads: it cannot be made whole from here, and
                // buffering it is what this cap exists to prevent.
                Err(RecvError::Lagged(n)) => {
                    tracing::debug!("closing a websocket subscriber that fell {n} heads behind");
                    let reason =
                        format!("subscriber fell {n} heads behind; reconnect and catch up with rand_getCompactBlocks");
                    let frame = CloseFrame { code: CLOSE_POLICY, reason: reason.into() };
                    // On its own deadline like every other write: a subscriber that lagged because
                    // it stopped reading will not take this frame either, and waiting on it is the
                    // same parked task the deadline exists to prevent.
                    let _ = send_or_give_up(&mut socket, Message::Close(Some(frame))).await;
                    break;
                }
                // The node loop is gone: so is this node.
                Err(RecvError::Closed) => break,
            },
            _ = ping.tick() => {
                if !send_or_give_up(&mut socket, Message::Ping(Vec::new())).await { break }
                // Only the *first* unanswered ping sets the deadline, so a client that has gone
                // quiet is not given a fresh grace period every interval.
                pong_due.get_or_insert(tokio::time::Instant::now() + WS_SEND_TIMEOUT);
            }
            _ = deadline(pong_due) => {
                tracing::debug!("closing a websocket client that did not answer a ping in {WS_SEND_TIMEOUT:?}");
                break;
            }
        }
    }
}

/// One `rand_subscription` frame per subscription this connection holds, or `None` when it
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
                    "method": "rand_subscription",
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
        "rand_subscribe" => match params.get(0).and_then(Value::as_str) {
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
            None => err(id, -32602, format!("rand_subscribe takes one topic, which must be {NEW_HEADS}")),
        },
        "rand_unsubscribe" => match params.get(0).and_then(Value::as_str) {
            // A bool, `false` for an id this socket never held rather than an error: that is what
            // Ethereum clients answer, and a client tearing down after a reconnect has no way to
            // know which ids survived.
            Some(sub) => json!({ "jsonrpc": "2.0", "id": id, "result": subs.remove(sub).is_some() }).to_string(),
            None => err(id, -32602, "rand_unsubscribe takes one subscription id, as a string".into()),
        },
        other => err(
            id,
            -32601,
            format!("the websocket serves rand_subscribe and rand_unsubscribe; reads go to POST / (got {other})"),
        ),
    }
}

fn err(id: Value, code: i64, message: String) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
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
        let r = call(&mut subs, &mut next, json!({ "id": 1, "method": "rand_subscribe", "params": ["newHeads"] }));
        assert_eq!(r["result"], json!("1"));
        assert_eq!(subs.len(), 1);
        let r = call(&mut subs, &mut next, json!({ "id": 2, "method": "rand_unsubscribe", "params": ["1"] }));
        assert_eq!(r["result"], json!(true));
        assert!(subs.is_empty());
        // The same id a second time is `false`, not an error, and ids are never reused.
        let r = call(&mut subs, &mut next, json!({ "id": 3, "method": "rand_unsubscribe", "params": ["1"] }));
        assert_eq!(r["result"], json!(false));
        let r = call(&mut subs, &mut next, json!({ "id": 4, "method": "rand_subscribe", "params": ["newHeads"] }));
        assert_eq!(r["result"], json!("2"), "a released id is not handed out again");
    }

    #[test]
    fn the_ninth_subscription_is_refused() {
        let (mut subs, mut next) = fresh();
        for i in 0..MAX_WS_SUBSCRIPTIONS {
            let req = json!({ "id": i, "method": "rand_subscribe", "params": ["newHeads"] });
            let r = call(&mut subs, &mut next, req);
            assert!(r["result"].is_string(), "subscription {i}: {r}");
        }
        let r = call(&mut subs, &mut next, json!({ "id": 9, "method": "rand_subscribe", "params": ["newHeads"] }));
        assert_eq!(r["error"]["code"], -32000);
        assert_eq!(subs.len(), MAX_WS_SUBSCRIPTIONS, "a refused subscribe leaves the map alone");
    }

    #[test]
    fn everything_but_the_two_subscription_methods_is_refused() {
        let (mut subs, mut next) = fresh();
        let r = call(&mut subs, &mut next, json!({ "id": 1, "method": "rand_getHead", "params": [] }));
        assert_eq!(r["error"]["code"], -32601);
        let r = call(&mut subs, &mut next, json!({ "id": 2, "method": "rand_subscribe", "params": ["logs"] }));
        assert_eq!(r["error"]["code"], -32602);
        let r = call(&mut subs, &mut next, json!({ "id": 3, "method": "rand_subscribe", "params": [] }));
        assert_eq!(r["error"]["code"], -32602);
        let r = call(&mut subs, &mut next, json!({ "id": 4, "method": "rand_unsubscribe", "params": [7] }));
        assert_eq!(r["error"]["code"], -32602, "a subscription id is a string");
        assert!(subs.is_empty());
    }

    #[test]
    fn a_frame_that_is_not_a_request_answers_with_a_null_id() {
        let (mut subs, mut next) = fresh();
        let r: Value = serde_json::from_str(&on_request("not json", &mut subs, &mut next)).unwrap();
        assert_eq!(r["error"]["code"], -32600);
        assert_eq!(r["id"], Value::Null);
        let r = call(&mut subs, &mut next, json!({ "method": "rand_subscribe", "params": ["newHeads"] }));
        assert_eq!(r["error"]["code"], -32600, "a notification is refused, as it is over HTTP");
        assert!(subs.is_empty());
        let r = call(&mut subs, &mut next, json!({ "id": 1 }));
        assert_eq!(r["error"]["code"], -32600);
    }

    #[test]
    fn a_slot_is_claimed_up_to_the_cap_and_given_back_by_dropping_it() {
        let conns = Arc::new(AtomicUsize::new(0));
        let held: Vec<ConnSlot> = (0..MAX_WS_CONNECTIONS).map(|_| ConnSlot::claim(&conns).expect("a slot")).collect();
        assert_eq!(conns.load(SeqCst), MAX_WS_CONNECTIONS);
        assert!(ConnSlot::claim(&conns).is_none(), "the cap is a hard bound");
        drop(held);
        assert_eq!(conns.load(SeqCst), 0, "every slot comes back");
        // A connection that panics releases its slot the same way, because nothing else does.
        let conns2 = conns.clone();
        assert!(std::panic::catch_unwind(move || {
            let _slot = ConnSlot::claim(&conns2).expect("a slot");
            panic!("something inside the connection");
        })
        .is_err());
        assert_eq!(conns.load(SeqCst), 0, "a panicking connection does not leak its slot");
    }

    #[test]
    fn releasing_more_slots_than_were_claimed_cannot_wrap_the_count() {
        let conns = Arc::new(AtomicUsize::new(0));
        // The counter is shared, so the failure to rule out is an underflow to `usize::MAX`, which
        // would refuse every client from then on.
        drop(ConnSlot(conns.clone()));
        assert_eq!(conns.load(SeqCst), 0);
        assert!(ConnSlot::claim(&conns).is_some(), "and the endpoint still accepts");
    }

    #[test]
    fn a_head_goes_to_every_subscription_the_connection_holds_and_to_no_others() {
        let (mut subs, mut next) = fresh();
        let head = HeadSummary { height: 7, hash: "ab".repeat(32), view: 9 };
        assert!(notifications(&subs, &head).is_none(), "a socket with no subscription is not written to");
        for i in 0..3 {
            call(&mut subs, &mut next, json!({ "id": i, "method": "rand_subscribe", "params": ["newHeads"] }));
        }
        let frames = notifications(&subs, &head).expect("three frames");
        assert_eq!(frames.len(), 3);
        for (frame, want) in frames.iter().zip(["1", "2", "3"]) {
            let v: Value = serde_json::from_str(frame).unwrap();
            assert_eq!(v["method"], json!("rand_subscription"));
            assert_eq!(v["params"]["subscription"], json!(want));
            // Exactly `rand_getHead`'s three fields, so a client can use one parser for both.
            assert_eq!(v["params"]["result"], json!({ "height": 7, "hash": "ab".repeat(32), "view": 9 }));
            assert!(v.get("id").is_none(), "a notification carries no id");
        }
    }
}
