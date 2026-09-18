//! The WebSocket half of the RPC: three subscription topics, so an explorer or a wallet stops
//! polling. `newHeads` pushes every committed head, as `rand_getHead` reports it. `receipts`
//! pushes each block's call receipts, all of them or one program's, as `rand_getReceipt` reports
//! them, and says nothing about a block with none. `transaction <hash>` fires once — when that
//! transaction commits, or when this node refuses it for good — and then removes itself. A hash
//! that had already committed or been refused when the subscribe arrived is answered on the next
//! committed block, not synchronously, so subscribing before or after submitting is one code path
//! for the client.
//!
//! Four bounds hold this endpoint, because it is unauthenticated: a per-node connection cap, a
//! per-connection subscription cap, bounded broadcast channels whose lagging receivers are
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

use crate::rpc::{CommitSummary, HeadSummary, NodeCommand, PoolStatus, RpcState};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use randprotocol_core::{Hash, ProgramId};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

/// WebSocket clients one node will carry at once. The 65th is refused at the upgrade.
pub const MAX_WS_CONNECTIONS: usize = 64;

/// Subscriptions one connection may hold, across all three topics. A wallet watching its head,
/// its program and a pending transaction or two is well inside eight; the cap is here because the
/// map is the one thing a client can make grow without limit.
pub const MAX_WS_SUBSCRIPTIONS: usize = 8;

/// The largest frame either direction may carry. A request here is a hundred bytes and a head
/// notification about two hundred; 64 KiB is room for a client's own framing and nothing like
/// enough for the proof-carrying bodies `POST /` takes.
pub const WS_MAX_FRAME_BYTES: usize = 64 * 1024;

/// The topics this node serves, as `rand_subscribe`'s first parameter names them.
const NEW_HEADS: &str = "newHeads";
const RECEIPTS: &str = "receipts";
const TRANSACTION: &str = "transaction";

/// The topic list every refused subscribe quotes, so a client learns the vocabulary from its error.
const TOPICS: &str = "newHeads, receipts [program_id], transaction <hash>";

/// What one subscription listens for.
#[derive(Clone, Debug, PartialEq)]
enum Topic {
    NewHeads,
    /// Every call receipt, or only one program's.
    Receipts(Option<ProgramId>),
    /// One transaction's fate, delivered once. The outcome is filled in at subscribe time when
    /// the hash was already committed or refused, and delivered on the next committed block.
    Transaction(Hash, Option<Known>),
}

/// A `transaction` subscription's outcome, already settled when the subscribe arrived.
#[derive(Clone, Debug, PartialEq)]
enum Known {
    Committed { height: u64, index: u32 },
    Rejected(String),
}

/// The three broadcast channels a connection reads, for deciding whether a lag on one of them
/// cost this connection anything.
#[derive(Clone, Copy, Debug)]
enum Channel {
    Heads,
    Commits,
    Refusals,
}

/// Whether `topic` is fed by `channel`. `commits` feeds `transaction` as well as `receipts`,
/// because a commit is how a transaction subscription is answered, a settled one included.
fn serves(channel: Channel, topic: &Topic) -> bool {
    matches!(
        (channel, topic),
        (Channel::Heads, Topic::NewHeads)
            | (Channel::Commits, Topic::Receipts(_) | Topic::Transaction(..))
            | (Channel::Refusals, Topic::Transaction(..))
    )
}

/// Whether this connection holds any subscription `channel` feeds. A lag on a channel nobody here
/// listens to missed nothing, and must not close a socket whose own topic is keeping up: a gossip
/// flood of refusals is not a reason to drop a `newHeads` client.
fn listens(subs: &BTreeMap<String, Topic>, channel: Channel) -> bool {
    subs.values().any(|t| serves(channel, t))
}

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

/// One connection: its own receiver on each of the three channels, and its own subscription map.
///
/// `slot` is never read. It is this connection's claim on [`MAX_WS_CONNECTIONS`], and dropping it
/// — on any exit from this function, a panic included — is what gives the slot back.
async fn run(mut socket: WebSocket, st: RpcState, slot: ConnSlot) {
    let _slot = slot;
    let mut heads = st.heads.subscribe();
    let mut commits = st.commits.subscribe();
    let mut refusals = st.refusals.subscribe();
    // Subscription id -> topic. The map is what makes unsubscribe a lookup, what a delivered
    // `transaction` subscription removes itself from, and what the per-connection cap counts.
    let mut subs: BTreeMap<String, Topic> = BTreeMap::new();
    let mut next_id = 1u64;
    // The first ping is one interval away, not immediate: a client that has just connected has
    // said everything it needs to.
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + WS_PING_INTERVAL, WS_PING_INTERVAL);
    // When the pong for an outstanding ping stops being worth waiting for. `None` while none is
    // outstanding.
    let mut pong_due: Option<tokio::time::Instant> = None;
    loop {
        // Each channel arm yields the frames to write, or ends the connection. A socket with no
        // subscription skips the frame builders entirely: that is the common case for a client
        // that has connected and not yet subscribed, and it must not cost a serialization.
        let frames = tokio::select! {
            incoming = socket.recv() => {
                let Some(Ok(msg)) = incoming else { break };
                match msg {
                    Message::Text(text) => {
                        let (reply, made) = on_request(&text, &mut subs, &mut next_id);
                        // A transaction subscription learns here whether its question is already
                        // answered. Before the reply is written, and delivered only on a later
                        // block, so the id always reaches the client before a notification for it.
                        if let Some(Topic::Transaction(h, known)) = made.and_then(|id| subs.get_mut(&id)) {
                            *known = known_outcome(&st, h).await;
                        }
                        vec![reply]
                    }
                    // The keepalive came back, so this client is alive whether or not it has
                    // anything subscribed.
                    Message::Pong(_) => {
                        pong_due = None;
                        continue;
                    }
                    // A client's ping is answered by axum; a close ends the stream on the next
                    // poll; binary is not a request here.
                    _ => continue,
                }
            }
            head = heads.recv() => match head {
                Ok(_) if subs.is_empty() => continue,
                Ok(h) => head_frames(&subs, &h),
                Err(RecvError::Lagged(_)) if !listens(&subs, Channel::Heads) => continue,
                Err(RecvError::Lagged(n)) => {
                    close_lagged(&mut socket, format!("{n} heads"), "rand_getCompactBlocks").await;
                    break;
                }
                // The node loop is gone: so is this node.
                Err(RecvError::Closed) => break,
            },
            commit = commits.recv() => match commit {
                Ok(_) if subs.is_empty() => continue,
                Ok(c) => commit_frames(&mut subs, &c),
                Err(RecvError::Lagged(_)) if !listens(&subs, Channel::Commits) => continue,
                Err(RecvError::Lagged(n)) => {
                    close_lagged(&mut socket, format!("{n} committed blocks"), "rand_getReceipts").await;
                    break;
                }
                Err(RecvError::Closed) => break,
            },
            refusal = refusals.recv() => match refusal {
                Ok(_) if subs.is_empty() => continue,
                Ok((hash, reason)) => refusal_frames(&mut subs, &hash, &reason),
                Err(RecvError::Lagged(_)) if !listens(&subs, Channel::Refusals) => continue,
                Err(RecvError::Lagged(n)) => {
                    close_lagged(&mut socket, format!("{n} refusals"), "rand_getTransactionStatus").await;
                    break;
                }
                Err(RecvError::Closed) => break,
            },
            _ = ping.tick() => {
                if !send_or_give_up(&mut socket, Message::Ping(Vec::new())).await { break }
                // Only the *first* unanswered ping sets the deadline, so a client that has gone
                // quiet is not given a fresh grace period every interval.
                pong_due.get_or_insert(tokio::time::Instant::now() + WS_SEND_TIMEOUT);
                continue;
            }
            _ = deadline(pong_due) => {
                tracing::debug!("closing a websocket client that did not answer a ping in {WS_SEND_TIMEOUT:?}");
                break;
            }
        };
        let mut ok = true;
        for frame in frames {
            if !send_or_give_up(&mut socket, Message::Text(frame)).await { ok = false; break }
        }
        if !ok { break }
    }
}

/// What a new `transaction` subscription is already owed: committed, from storage, or refused,
/// from the node loop's refused cache (the same round trip `rand_getTransactionStatus` makes).
/// Storage first, so the node loop is asked only about a hash that has not committed.
///
/// `None` — wait for a block or a refusal — for a pending or unknown hash, and equally when the
/// lookup fails or the node loop does not answer within [`WS_SEND_TIMEOUT`]: a missed early answer
/// costs the client a wait, while an unbounded one here would stall this connection's reads.
async fn known_outcome(st: &RpcState, h: &Hash) -> Option<Known> {
    match st.storage.tx_location(h) {
        Ok(Some((height, index))) => return Some(Known::Committed { height, index }),
        Ok(None) => {}
        Err(e) => {
            tracing::debug!("websocket transaction lookup failed: {e}");
            return None;
        }
    }
    let ask = async {
        let (reply, rx) = tokio::sync::oneshot::channel();
        st.node.send(NodeCommand::TxStatus { hashes: vec![*h], reply }).await.ok()?;
        rx.await.ok()
    };
    match tokio::time::timeout(WS_SEND_TIMEOUT, ask).await {
        Ok(Some(status)) => match status.into_iter().next() {
            Some(PoolStatus::Rejected(reason)) => Some(Known::Rejected(reason)),
            _ => None,
        },
        _ => None,
    }
}

/// Close a subscriber that missed `what` on one of the broadcast channels: it cannot be made
/// whole from here, and buffering it is what the channel's bound exists to prevent. `recover` is
/// the read that catches it up after it reconnects.
async fn close_lagged(socket: &mut WebSocket, what: String, recover: &str) {
    tracing::debug!("closing a websocket subscriber that fell {what} behind");
    let reason = format!("subscriber fell {what} behind; reconnect and catch up with {recover}");
    let frame = CloseFrame { code: CLOSE_POLICY, reason: reason.into() };
    // On its own deadline like every other write: a subscriber that lagged because it stopped
    // reading will not take this frame either, and waiting on it is the same parked task the
    // deadline exists to prevent.
    let _ = send_or_give_up(socket, Message::Close(Some(frame))).await;
}

/// One `rand_subscription` frame.
fn frame(id: &str, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "method": "rand_subscription", "params": { "subscription": id, "result": result } })
        .to_string()
}

/// One frame per `newHeads` subscription this connection holds, carrying exactly the three fields
/// `rand_getHead` returns. Nothing is serialized when there is no such subscription.
fn head_frames(subs: &BTreeMap<String, Topic>, head: &HeadSummary) -> Vec<String> {
    let mut ids = subs.iter().filter(|(_, t)| **t == Topic::NewHeads).map(|(id, _)| id).peekable();
    if ids.peek().is_none() {
        return Vec::new();
    }
    let Ok(result) = serde_json::to_value(head) else { return Vec::new() };
    ids.map(|id| frame(id, result.clone())).collect()
}

/// The frames one committed block earns: for each `receipts` subscription, the block's receipts
/// that pass its program filter — no frame at all when none do, so a quiet chain is a quiet
/// socket — and for each `transaction` subscription whose hash is in the block, its height and
/// index; a `transaction` subscription settled at subscribe time is answered by any block. A
/// delivered `transaction` subscription is removed: its question has been answered.
fn commit_frames(subs: &mut BTreeMap<String, Topic>, c: &CommitSummary) -> Vec<String> {
    let mut out = Vec::new();
    let mut done = Vec::new();
    for (id, topic) in subs.iter() {
        match topic {
            Topic::Receipts(filter) => {
                let rows: Vec<Value> = c
                    .receipts
                    .iter()
                    .filter(|r| filter.is_none_or(|p| r.program == p))
                    .map(crate::rpc::receipt_json)
                    .collect();
                if !rows.is_empty() {
                    out.push(frame(id, json!({ "height": c.height, "hash": c.hash.to_hex(), "receipts": rows })));
                }
            }
            Topic::Transaction(h, known) => {
                let result = match known {
                    Some(Known::Committed { height, index }) => {
                        Some(json!({ "status": "committed", "height": height, "index": index }))
                    }
                    Some(Known::Rejected(reason)) => Some(json!({ "status": "rejected", "reason": reason })),
                    None => c
                        .tx_hashes
                        .iter()
                        .position(|t| t == h)
                        .map(|index| json!({ "status": "committed", "height": c.height, "index": index })),
                };
                if let Some(result) = result {
                    out.push(frame(id, result));
                    done.push(id.clone());
                }
            }
            Topic::NewHeads => {}
        }
    }
    for id in done {
        subs.remove(&id);
    }
    out
}

/// The frames one refusal earns: one per still-open `transaction` subscription to that hash, each
/// then removed. The reason is the one `rand_getTransactionStatus` reports for it. A subscription
/// settled at subscribe time is left to the next block, which answers it with what it already
/// holds — a committed transaction resubmitted and refused as spent stays committed.
fn refusal_frames(subs: &mut BTreeMap<String, Topic>, hash: &Hash, reason: &str) -> Vec<String> {
    let done: Vec<String> = subs
        .iter()
        .filter(|(_, t)| matches!(t, Topic::Transaction(h, None) if h == hash))
        .map(|(id, _)| id.clone())
        .collect();
    done.iter()
        .map(|id| {
            subs.remove(id);
            frame(id, json!({ "status": "rejected", "reason": reason }))
        })
        .collect()
}

/// `rand_subscribe`'s parameters, as a topic, or the message a `-32602` carries.
fn parse_topic(params: &Value) -> Result<Topic, String> {
    match params.get(0).and_then(Value::as_str) {
        Some(NEW_HEADS) => Ok(Topic::NewHeads),
        Some(RECEIPTS) => match params.get(1) {
            None | Some(Value::Null) => Ok(Topic::Receipts(None)),
            Some(v) => v
                .as_str()
                .and_then(|s| ProgramId::from_hex(s).ok())
                .map(|p| Topic::Receipts(Some(p)))
                .ok_or_else(|| "receipts takes an optional program id, as hex".to_string()),
        },
        Some(TRANSACTION) => params
            .get(1)
            .and_then(Value::as_str)
            .and_then(|s| Hash::from_hex(s).ok())
            .map(|h| Topic::Transaction(h, None))
            .ok_or_else(|| "transaction takes one transaction hash, as hex".to_string()),
        Some(other) => Err(format!("unknown subscription topic {other}; this node serves {TOPICS}")),
        None => Err(format!("rand_subscribe takes a topic: {TOPICS}")),
    }
}

/// One text frame in, one response object out, and the id of the subscription it made if it made
/// one, so the caller can settle a new `transaction` subscription's outcome. A subscribe is the
/// only thing that advances `next_id`, and the id it hands out is the value it advanced from.
fn on_request(text: &str, subs: &mut BTreeMap<String, Topic>, next_id: &mut u64) -> (String, Option<String>) {
    let before = *next_id;
    let reply = respond(text, subs, next_id);
    (reply, (*next_id != before).then(|| before.to_string()))
}

/// One text frame in, one response object out — as a string, because every outcome here is a
/// reply and nothing on this socket is fire-and-forget.
fn respond(text: &str, subs: &mut BTreeMap<String, Topic>, next_id: &mut u64) -> String {
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
        "rand_subscribe" => match parse_topic(&params) {
            Ok(topic) => {
                if subs.len() >= MAX_WS_SUBSCRIPTIONS {
                    return err(
                        id,
                        -32000,
                        format!("at most {MAX_WS_SUBSCRIPTIONS} subscriptions per connection"),
                    );
                }
                let sub = next_id.to_string();
                *next_id += 1;
                subs.insert(sub.clone(), topic);
                json!({ "jsonrpc": "2.0", "id": id, "result": sub }).to_string()
            }
            Err(m) => err(id, -32602, m),
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
    use randprotocol_core::CallReceipt;

    fn fresh() -> (BTreeMap<String, Topic>, u64) {
        (BTreeMap::new(), 1)
    }

    fn call(subs: &mut BTreeMap<String, Topic>, next: &mut u64, req: Value) -> Value {
        serde_json::from_str(&on_request(&req.to_string(), subs, next).0).unwrap()
    }

    fn sub(subs: &mut BTreeMap<String, Topic>, next: &mut u64, params: Value) -> String {
        let r = call(subs, next, json!({ "id": 1, "method": "rand_subscribe", "params": params }));
        r["result"].as_str().unwrap_or_else(|| panic!("{r}")).to_string()
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
        // The id a subscribe made comes back beside the reply, for `run` to settle; nothing else
        // makes one.
        let req = json!({ "id": 5, "method": "rand_subscribe", "params": ["newHeads"] }).to_string();
        assert_eq!(on_request(&req, &mut subs, &mut next).1, Some("3".to_string()));
        let req = json!({ "id": 6, "method": "rand_unsubscribe", "params": ["3"] }).to_string();
        assert_eq!(on_request(&req, &mut subs, &mut next).1, None);
        let req = json!({ "id": 7, "method": "rand_subscribe", "params": ["logs"] }).to_string();
        assert_eq!(on_request(&req, &mut subs, &mut next).1, None);
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
        let r: Value = serde_json::from_str(&on_request("not json", &mut subs, &mut next).0).unwrap();
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
        assert!(head_frames(&subs, &head).is_empty(), "a socket with no subscription is not written to");
        for i in 0..3 {
            call(&mut subs, &mut next, json!({ "id": i, "method": "rand_subscribe", "params": ["newHeads"] }));
        }
        // A subscription to another topic hears nothing about heads.
        sub(&mut subs, &mut next, json!(["receipts"]));
        let frames = head_frames(&subs, &head);
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

    #[test]
    fn receipts_topic_filters_by_program_and_skips_empty_blocks() {
        let (mut subs, mut next) = fresh();
        let pid_a = Hash([1; 32]);
        let pid_b = Hash([2; 32]);
        let all = sub(&mut subs, &mut next, json!(["receipts"]));
        let only_b = sub(&mut subs, &mut next, json!(["receipts", pid_b.to_hex()]));
        let rec = |pid| CallReceipt {
            tx: Hash([3; 32]),
            program: pid,
            tier: 1,
            outputs: [0; 8],
            height: 5,
            index: 0,
            h_in: [0; 8],
            input_envelope: None,
        };
        let c = CommitSummary { height: 5, hash: Hash([5; 32]), tx_hashes: vec![Hash([3; 32])], receipts: vec![rec(pid_a)] };
        let frames = commit_frames(&mut subs, &c);
        assert_eq!(frames.len(), 1, "only the unfiltered subscription hears a pid_a receipt");
        let f: Value = serde_json::from_str(&frames[0]).unwrap();
        assert_eq!(f["params"]["subscription"], all);
        assert_eq!(f["params"]["result"]["height"], 5);
        assert_eq!(f["params"]["result"]["receipts"][0]["program"], pid_a.to_hex());
        let empty = CommitSummary { height: 6, hash: Hash([6; 32]), tx_hashes: vec![], receipts: vec![] };
        assert!(commit_frames(&mut subs, &empty).is_empty());
        let _ = only_b;
    }

    #[test]
    fn transaction_topic_fires_once_on_commit_or_refusal_and_removes_itself() {
        let (mut subs, mut next) = fresh();
        let h = Hash([9; 32]);
        let id = sub(&mut subs, &mut next, json!(["transaction", h.to_hex()]));
        let c = CommitSummary { height: 5, hash: Hash([5; 32]), tx_hashes: vec![h], receipts: vec![] };
        let frames = commit_frames(&mut subs, &c);
        assert_eq!(frames.len(), 1);
        let f: Value = serde_json::from_str(&frames[0]).unwrap();
        assert_eq!(f["params"]["subscription"], id);
        assert_eq!(f["params"]["result"]["status"], "committed");
        assert_eq!(f["params"]["result"]["index"], 0);
        assert!(subs.is_empty(), "delivered once, then gone");

        let id = sub(&mut subs, &mut next, json!(["transaction", h.to_hex()]));
        let frames = refusal_frames(&mut subs, &h, "nullifier already spent");
        assert_eq!(frames.len(), 1);
        let f: Value = serde_json::from_str(&frames[0]).unwrap();
        assert_eq!(f["params"]["subscription"], id);
        assert_eq!(f["params"]["result"]["reason"], "nullifier already spent");
        assert!(subs.is_empty());
        assert!(refusal_frames(&mut subs, &Hash([1; 32]), "x").is_empty());
    }

    #[test]
    fn bad_topics_are_refused_with_the_topic_list() {
        let (mut subs, mut next) = fresh();
        let r = call(&mut subs, &mut next, json!({ "id": 1, "method": "rand_subscribe", "params": ["logs"] }));
        assert_eq!(r["error"]["code"], -32602);
        assert!(r["error"]["message"].as_str().unwrap().contains("receipts"));
        let r = call(&mut subs, &mut next, json!({ "id": 1, "method": "rand_subscribe", "params": ["transaction"] }));
        assert_eq!(r["error"]["code"], -32602, "a transaction subscription needs its hash");
        let r = call(&mut subs, &mut next, json!({ "id": 1, "method": "rand_subscribe", "params": ["receipts", "zz"] }));
        assert_eq!(r["error"]["code"], -32602);
    }

    #[test]
    fn a_transaction_already_answered_is_delivered_on_the_next_block_and_removed() {
        let (mut subs, mut next) = fresh();
        let (h, g) = (Hash([9; 32]), Hash([8; 32]));
        let done = sub(&mut subs, &mut next, json!(["transaction", h.to_hex()]));
        let refused = sub(&mut subs, &mut next, json!(["transaction", g.to_hex()]));
        let waiting = sub(&mut subs, &mut next, json!(["transaction", Hash([7; 32]).to_hex()]));
        // What `run` fills in at subscribe time, from storage and from the node loop.
        subs.insert(done.clone(), Topic::Transaction(h, Some(Known::Committed { height: 3, index: 2 })));
        subs.insert(refused.clone(), Topic::Transaction(g, Some(Known::Rejected("bad signature".into()))));
        // Not answered by a refusal event: a known outcome goes out on a block, one code path.
        assert!(refusal_frames(&mut subs, &g, "bad signature").is_empty());
        // An unrelated, empty block answers both, with the payloads a live outcome would carry.
        let c = CommitSummary { height: 9, hash: Hash([5; 32]), tx_hashes: vec![], receipts: vec![] };
        let frames: Vec<Value> = commit_frames(&mut subs, &c).iter().map(|f| serde_json::from_str(f).unwrap()).collect();
        assert_eq!(frames.len(), 2);
        let of = |id: &String| frames.iter().find(|f| f["params"]["subscription"] == json!(id)).unwrap()["params"]["result"].clone();
        assert_eq!(of(&done), json!({ "status": "committed", "height": 3, "index": 2 }));
        assert_eq!(of(&refused), json!({ "status": "rejected", "reason": "bad signature" }));
        assert_eq!(subs.keys().collect::<Vec<_>>(), vec![&waiting], "both removed; the unanswered one waits");
    }

    #[test]
    fn a_lag_closes_only_a_connection_listening_to_that_channel() {
        let (mut subs, mut next) = fresh();
        for ch in [Channel::Heads, Channel::Commits, Channel::Refusals] {
            assert!(!listens(&subs, ch), "no subscription: nothing missed");
        }
        sub(&mut subs, &mut next, json!(["newHeads"]));
        assert!(listens(&subs, Channel::Heads));
        assert!(!listens(&subs, Channel::Commits), "a heads-only client missed nothing on commits");
        assert!(!listens(&subs, Channel::Refusals), "nor on refusals");
        let r = sub(&mut subs, &mut next, json!(["receipts"]));
        assert!(listens(&subs, Channel::Commits));
        assert!(!listens(&subs, Channel::Refusals));
        subs.remove(&r);
        sub(&mut subs, &mut next, json!(["transaction", Hash([9; 32]).to_hex()]));
        assert!(listens(&subs, Channel::Commits) && listens(&subs, Channel::Refusals));
    }
}
