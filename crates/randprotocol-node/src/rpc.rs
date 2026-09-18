//! JSON-RPC 2.0 over HTTP. Reads come straight from storage and the shared
//! status snapshot; transaction submission goes to the node loop.
//!
//! The redacted chain has no balances to report, so the wallet's read surface is the pool's
//! own: a page of commitments (with their envelopes, which only their owner can open), the
//! nullifiers published so far, the anchors a prover may build against, and the Merkle witness
//! of one leaf. A node cannot tell which of those belong to whom, and neither can anyone
//! watching the RPC port.

use crate::mempool::MempoolError;
use crate::network::PeerInfo;
use crate::storage::Storage;
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use randprotocol_core::bridge::{asset_id, AssetInfo, BridgeMeta};
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::notes::{word8_to_hex, Envelope};
use randprotocol_core::{Action, CallReceipt, Hash, ProgramId, ShieldedAddress, Transaction, TOKEN_DECIMALS, TOKEN_SYMBOL};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot};

/// The most rows one paged read may return. A wallet scanning from zero pages through the tree;
/// an unbounded `limit` would let one request pull the whole pool into memory.
const MAX_PAGE: usize = 1000;

/// The most blocks one `rand_getCompactBlocks` call may cover. Half the 256-block anchor
/// window (`ledger::ANCHOR_WINDOW`), so a wallet syncing forward never crosses more than one
/// window per request.
const MAX_COMPACT_BLOCKS: u64 = 128;

/// The most request objects one batch may carry. A batch is a request amplifier and
/// `rand_getWitness` rebuilds the whole commitment tree per call, so this is deliberately
/// small: the realistic batch is a head, a tree info and two pages, which is four.
///
/// The *byte* bound is `RPC_MAX_BODY_BYTES`, which is sized for one proof-carrying transaction, so
/// a batch of submissions is refused on size at the extractor long before this count is consulted.
const MAX_BATCH: usize = 20;

/// The longest string any RPC parameter may offer as a shielded address (spec ruling 3). See
/// `parse_shielded` for why this is checked before the address is parsed rather than after.
const MAX_ADDRESS_CHARS: usize = 2000;

/// The most receipts one `rand_getReceipts` page may return; an out-of-range `limit` is clamped
/// to it rather than refused.
pub const MAX_RECEIPTS_PAGE: usize = 256;

/// The most leaf indices one `rand_getWitnesses` call may fold into a single tree build.
pub const MAX_WITNESSES: usize = 32;

/// Snapshot the node loop keeps up to date for RPC readers.
#[derive(Clone, Debug, Default, Serialize)]
pub struct NodeStatus {
    pub height: u64,
    pub head_hash: String,
    pub view: u64,
    pub high_qc_view: u64,
    pub syncing: bool,
    pub sync_target: u64,
    /// How long the outstanding sync request has been waiting, if one is outstanding.
    ///
    /// `syncing: true` with a rising `sync_target` says only that this node knows it is behind. An
    /// age that keeps climbing past a few seconds says the request it is waiting on is not coming
    /// back — the shape of the chain-8 catch-up stall, which showed nothing else at all.
    pub sync_inflight_age_ms: Option<u64>,
    /// Sync batch requests that failed since start: a wire or codec error, a give-up past the wire
    /// timeout, or a batch that could not be applied. Rising while `height` does not is the
    /// signature of a node that cannot catch up.
    pub sync_failures: u64,
    /// Batches applied after their request had been given up on. Progress rather than failure, but
    /// a rising count means the give-up is firing on requests that were still alive.
    pub sync_late_batches: u64,
    /// Every peer this node knows of, including those seen only as the author of relayed gossip.
    pub peer_count: usize,
    /// Peers this node holds an open connection to — the ones sync can actually ask for blocks. A
    /// `peer_count` far above this says most of what we know about the network is hearsay.
    pub connected_peers: usize,
    /// WebSocket clients currently connected, against `ws::MAX_WS_CONNECTIONS`. At the cap the
    /// next upgrade is refused with a 503, which an operator would otherwise only see as clients
    /// that cannot connect for no visible reason.
    pub ws_clients: usize,
    /// Transaction hashes this node refuses for free, because it has already verified them and the
    /// refusal was about their bytes (`admission::REFUSED_CACHE_ENTRIES` is the cap). Rising fast
    /// means someone is re-sending known-bad proofs — which now cost a hash lookup, not 20 ms.
    pub refused_cache: usize,
    /// Transactions waiting for a proof verification slot, against `admission::MAX_VERIFY_QUEUE`.
    /// Normally 0: a queue that sits near the cap means this node is shedding gossiped
    /// transactions, and it is unrelated to the sync counters above.
    pub verify_queue: usize,
    pub mempool_size: usize,
    /// Viewing keys this node holds for node-side scanning (`rand_importViewingKey`), against
    /// `viewing::MAX_VIEWING_KEYS`. In memory only, so it reads zero after every restart. Nonzero
    /// changes what compromising this process would disclose: the notes those keys open — which
    /// their holders can already see, and never spend authority.
    pub viewing_keys: usize,
    /// This node holds a validator key and is running as one (`--validator`).
    pub is_validator: bool,
    /// That key is in the validator set of the epoch the next block belongs to (spec §8). A
    /// validator that has bonded in but whose epoch has not arrived — or one that has unbonded
    /// below the minimum — is `is_validator` without being `active_validator`.
    pub active_validator: bool,
    pub faucet: bool,
    pub confidential: bool,
    pub fri_profile: String,
    pub programs: u64,
    /// Leaves in the commitment tree — every note the chain has ever created.
    pub notes: u64,
    /// Nullifiers published — every note the chain has ever spent.
    pub nullifiers: u64,
    /// The current tree root, as a wallet would anchor against.
    pub tree_root: String,
    /// The bundle guest this chain's proofs are against.
    pub hc_bundle: String,
    pub address: Option<String>,
    pub peer_id: String,
    /// The aggregation section (spec §8): the register's size, the coverable bundles the
    /// daemon's work list would return right now, and the verification queue's depth. Absent
    /// (zeroed) on a chain without the section.
    #[serde(default)]
    pub aggregation: AggregationStatus,
}

/// `rand_status`'s `aggregation` object (spec §8).
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct AggregationStatus {
    /// Aggregators in the register right now.
    pub registered: usize,
    /// Bundles an aggregator may still cover: committed, in-window, unsealed.
    pub unsealed: usize,
    /// Transactions waiting for a verification slot — the top-level `verify_queue`, repeated
    /// here because an aggregator watches it as its own backpressure signal.
    pub verify_queue: usize,
    // The chain parameters an aggregate daemon needs to compute the payment it seals (spec
    // §5.4) — zeroed on a chain without the section.
    /// The most bundles one aggregate may cover (genesis `max_covers`).
    pub max_covers: u32,
    /// The cover and pruning window, in blocks (genesis `window`).
    pub window: u64,
    /// `subsidy(0)` in units (genesis `subsidy_base`).
    pub subsidy_base: u64,
    /// The halving interval of the subsidy schedule, in sealed blocks.
    pub halving_blocks: u64,
    /// Sealed blocks so far — the schedule index `n` the next aggregate mints at.
    pub sealed_blocks: u64,
}

pub enum NodeCommand {
    SubmitTx { tx: Transaction, reply: oneshot::Sender<Result<Hash, MempoolError>> },
    Peers { reply: oneshot::Sender<Vec<PeerInfo>> },
    /// Testnet faucet: mint `amount` units into a note owned by `to`, signed by this node.
    /// Only a validator can serve it, so the reply carries a message rather than a
    /// `MempoolError` — "this node is an observer" is not a mempool outcome.
    Mint { to: ShieldedAddress, amount: u64, reply: oneshot::Sender<Result<Hash, String>> },
    /// Where the chain is in its epoch schedule, and which validators run this epoch and the
    /// next. It comes from the node loop rather than from storage because the *next* epoch's set
    /// is derived from the tip's register, which only the replica holds — and deriving it on
    /// every pass of the loop, to keep a snapshot fresh, would cost a set clone per message.
    Epoch { reply: oneshot::Sender<EpochInfo> },
    /// The pool's occupancy — count, combined encoded size, oldest entry's age — for
    /// `rand_getMempoolInfo`. Answered by the node loop rather than read from a shared snapshot
    /// because the pool itself lives there.
    MempoolInfo { reply: oneshot::Sender<crate::mempool::MempoolInfo> },
    /// What the mempool and the refusal cache know about each hash, for `rand_getTransactionStatus`
    /// — pooled, refused (with the admission reason), or neither. Storage's half of the answer
    /// (committed, at a height and index) is read by the dispatcher itself; this only covers what
    /// the node loop holds.
    TxStatus { hashes: Vec<Hash>, reply: oneshot::Sender<Vec<PoolStatus>> },
    /// Where `hash` sits in this replica's consensus state, for `rand_getFinality`. The
    /// dispatcher answers a committed block from storage itself; this covers the tree — certified
    /// (a QC names it) or merely proposed — and the "never heard of it" case.
    Finality { hash: Hash, reply: oneshot::Sender<Finality> },
    /// The leader of each view in `views`, under the current validator set, for
    /// `rand_getProposer`. `epoch` is the tip's epoch, the same for every view in the answer.
    Proposer { views: Vec<u64>, reply: oneshot::Sender<(u64, Vec<randprotocol_core::Address>)> },
}

/// The most hashes one `rand_getTransactionStatus` call may ask about.
pub const MAX_STATUS_HASHES: usize = 64;

/// The most views one `rand_getProposer` range may cover.
pub const MAX_PROPOSER_VIEWS: usize = 64;

/// The answer to [`NodeCommand::Finality`] and `rand_getFinality`'s hash-lookup branch: where a
/// block hash sits in this replica's consensus state.
#[derive(Clone, Debug, PartialEq)]
pub enum Finality {
    /// Part of the committed chain.
    Committed { height: u64, hash: Hash },
    /// In the tree, not yet committed, but a quorum certificate names it.
    Certified { height: u64, hash: Hash, qc_view: u64 },
    /// In the tree, proposed but not yet certified.
    Proposed { height: u64, hash: Hash },
    /// Not a block this replica has ever held.
    Unknown,
}

/// What the node loop knows about a hash that storage does not: pooled, refused, or neither.
#[derive(Clone, Debug, PartialEq)]
pub enum PoolStatus {
    Pending,
    Rejected(String),
    Unknown,
}

/// The answer to [`NodeCommand::Epoch`]: the current epoch, its length, and the sets of this
/// epoch and the next, as addresses.
#[derive(Clone, Debug, Default)]
pub struct EpochInfo {
    pub epoch: u64,
    pub epoch_blocks: u64,
    /// The set the next block is proposed and voted by.
    pub current: Vec<randprotocol_core::Address>,
    /// What the next epoch's set would be if this epoch ended now (spec §8). It is a projection,
    /// not a commitment: every bond and unbond before the boundary still moves it.
    pub next: Vec<randprotocol_core::Address>,
}

/// Slots in the head broadcast channel. A 100-block sync batch fits with slack, and at 3 s blocks
/// 256 heads is thirteen minutes: a subscriber that falls further behind than that is not going to
/// catch up, and is closed rather than buffered.
pub const HEAD_CHANNEL: usize = 256;

/// The commit this binary was built from (`build.rs`), for `rand_getVersion`.
pub const GIT_SHA: &str = env!("RAND_GIT_SHA");

/// `rand_getHealth`: one word a load balancer can read, and the lag an operator can.
pub fn health_json(s: &NodeStatus) -> Value {
    let behind = s.sync_target.saturating_sub(s.height);
    if s.sync_inflight_age_ms.is_some() {
        json!({ "status": "syncing", "behind": behind })
    } else if behind > 2 {
        json!({ "status": "behind", "behind": behind })
    } else {
        json!({ "status": "ok" })
    }
}

/// One committed head, as `rand_getHead` reports it. What a `newHeads` notification carries.
#[derive(Clone, Debug, Serialize)]
pub struct HeadSummary {
    pub height: u64,
    pub hash: String,
    pub view: u64,
}

/// One committed block, as the WebSocket's `receipts` and `transaction` topics read it: the
/// transaction hashes in block order, so a `transaction` subscriber hears its index, and the
/// block's call receipts, which a `receipts` subscriber is sent through [`receipt_json`] — the
/// same object `rand_getReceipt` answers with.
#[derive(Clone, Debug)]
pub struct CommitSummary {
    pub height: u64,
    pub hash: Hash,
    pub tx_hashes: Vec<Hash>,
    pub receipts: Vec<CallReceipt>,
}

/// The head as `rand_getHead` reports it — one function, so the RPC and the subscription can
/// never drift apart.
pub fn head_summary(storage: &Storage, status: &RwLock<NodeStatus>) -> crate::storage::Result<HeadSummary> {
    let head = storage.head()?;
    let view = status.read().unwrap_or_else(|e| e.into_inner()).view;
    Ok(HeadSummary { height: head.height, hash: head.hash.to_hex(), view })
}

#[derive(Clone)]
pub struct RpcState {
    pub storage: Arc<Storage>,
    pub status: Arc<RwLock<NodeStatus>>,
    pub node: mpsc::Sender<NodeCommand>,
    pub chain_id: u64,
    /// The chain's deploy cap in words, from its genesis ledger (`max_program_words`, default
    /// `gas::MAX_PROGRAM_WORDS`): what `rand_estimateFee` refuses a deploy estimate past, so it
    /// agrees with admission.
    pub max_program_words: usize,
    /// Needed by `rand_getWitness`, which rebuilds the tree to fold a path.
    pub executor: Arc<dyn ConfidentialExecutor>,
    /// Committed heads, one per block, fanned out to WebSocket subscribers. Bounded: a subscriber
    /// that falls more than [`HEAD_CHANNEL`] behind is closed, not buffered.
    pub heads: tokio::sync::broadcast::Sender<HeadSummary>,
    /// Committed blocks, one per head and sent right after it, for the `receipts` and
    /// `transaction` topics. [`HEAD_CHANNEL`] slots, closed-not-buffered like `heads`.
    pub commits: tokio::sync::broadcast::Sender<CommitSummary>,
    /// Transactions this node refused for a reason about their bytes — exactly the set
    /// `rand_getTransactionStatus` reports as `rejected` — with that reason, for the `transaction`
    /// topic. [`HEAD_CHANNEL`] slots.
    pub refusals: tokio::sync::broadcast::Sender<(Hash, String)>,
    /// Live WebSocket connections, against [`crate::ws::MAX_WS_CONNECTIONS`].
    pub ws_conns: Arc<std::sync::atomic::AtomicUsize>,
    /// Viewing keys imported for node-side scanning (`rand_importViewingKey`), in memory only:
    /// a restart clears them. Nothing else in the process reads it — the scan is lazy, driven by
    /// `rand_getViewingNotes` calls.
    pub viewing: Arc<RwLock<crate::viewing::Registry>>,
}

#[derive(Deserialize)]
struct Request {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    method: String,
    #[serde(default)]
    params: Value,
    /// A request object's `id`. `None` is a *missing* `id` member — a JSON-RPC notification, which
    /// this node refuses (see `docs/rpc.md`); `Some(Value::Null)` is an explicit null id and is a
    /// normal request, as it has always been here.
    ///
    /// `Option<Value>` alone cannot say that: serde reads an explicit `null` as `None`, collapsing
    /// the two. `id_member` is only ever called for a member that is *present*, so it is what keeps
    /// `"id": null` a request; `default` covers the missing one.
    #[serde(default, deserialize_with = "id_member")]
    id: Option<Value>,
}

/// A present `id` member, null included. See [`Request::id`].
fn id_member<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn invalid_params(m: impl Into<String>) -> RpcError {
        RpcError { code: -32602, message: m.into() }
    }
    /// A request we could not read as a request at all — an oversized or malformed body.
    fn invalid_request(m: impl Into<String>) -> RpcError {
        RpcError { code: -32600, message: m.into() }
    }
    fn not_found(m: impl Into<String>) -> RpcError {
        RpcError { code: -32001, message: m.into() }
    }
    fn rejected(m: impl Into<String>) -> RpcError {
        RpcError { code: -32000, message: m.into() }
    }
    fn internal(m: impl std::fmt::Display) -> RpcError {
        RpcError { code: -32603, message: m.to_string() }
    }
}

/// The largest request body the RPC accepts, derived from the largest transaction the chain can
/// admit rather than guessed.
///
/// `rand_sendTransaction` carries `hex(bincode(tx))` inside a JSON envelope, so every byte of the
/// transaction costs two here. The terms, all per single transaction:
///
/// - `2 * MAX_PROOF_BYTES` — a `Call` carries **two** proofs, the fee bundle's and the call's own,
///   and a `BridgeBurn` likewise carries two bundles. This is the term the retired limit missed: it
///   allowed `2 * MAX_PROOF_BYTES + 256 KiB` *in total*, which is one hex-encoded proof, so a
///   constraint-set-5 `Call` — measured at 1 321 773 bytes for the fee bundle's proof plus ~1.2 MB
///   for the call's — was refused after about a hundred seconds of proving.
/// - `2 * MAX_ENVELOPE_BYTES` — the bundle's two output envelopes.
/// - `MAX_CALL_ENVELOPE_BYTES` — the call's input envelope.
/// - `MAX_ATTESTATION_BYTES` — a `BridgeAttest`'s attestation.
/// - 64 KiB for the rest: public keys, signatures, hashes, nullifiers and bincode framing.
///
/// Then doubled for the hex encoding, plus 256 KiB for the JSON envelope and headers.
pub const RPC_MAX_BODY_BYTES: usize = 2
    * (2 * randprotocol_core::gas::MAX_PROOF_BYTES
        + 2 * randprotocol_core::notes::MAX_ENVELOPE_BYTES
        + randprotocol_core::types::actions::MAX_CALL_ENVELOPE_BYTES
        + randprotocol_core::gas::MAX_ATTESTATION_BYTES
        + 64 * 1024)
    + 256 * 1024;

pub async fn serve(addr: SocketAddr, state: RpcState) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let app = Router::new()
        // Same port, two protocols: `POST /` is the JSON-RPC this file serves, `GET /` and
        // `GET /ws` are the WebSocket upgrade. A client that knows only the POST sees no change.
        .route("/", post(handle).get(crate::ws::upgrade))
        .route("/ws", axum::routing::get(crate::ws::upgrade))
        // `RPC_MAX_BODY_BYTES`, unchanged — it bounds the POST. A WebSocket upgrade is a GET with
        // no body, so the layer costs it nothing; frames are bounded by `ws::WS_MAX_FRAME_BYTES`
        // instead.
        .layer(axum::extract::DefaultBodyLimit::max(RPC_MAX_BODY_BYTES))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("rpc server exited: {e}");
        }
    });
    Ok((bound, task))
}

/// One error response object. Built from an `RpcError` so every `-32600` in this file comes from
/// `RpcError::invalid_request` — including the oversized-body one `rejection_error` already makes.
fn error_value(id: Value, e: RpcError) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": e.code, "message": e.message } })
}

/// One request object in, one response object out. Every failure mode — an object that does not
/// deserialize, a notification, an unknown method — is a response, so a batch's replies always
/// line up one-for-one with its requests.
async fn dispatch_one(st: &RpcState, v: Value) -> Value {
    // Echo whatever id the object carried even if nothing else about it parses.
    let raw_id = v.get("id").cloned();
    let req: Request = match serde_json::from_value(v) {
        Ok(r) => r,
        Err(e) => {
            return error_value(
                raw_id.unwrap_or(Value::Null),
                RpcError::invalid_request(format!("invalid request: {e}")),
            )
        }
    };
    let Some(id) = req.id.clone() else {
        return error_value(
            Value::Null,
            RpcError::invalid_request("this node does not accept notifications; every request must carry an id"),
        );
    };
    match dispatch(st, &req).await {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(e) => error_value(id, e),
    }
}

async fn handle(
    State(st): State<RpcState>,
    // `Result<Json<_>, _>` rather than `Json<_>`: a body axum refuses — over the limit, or not
    // JSON at all — otherwise comes back as a *plain-text* 413 or 400, which no JSON-RPC client can
    // read. `rand send` reported a body over the limit as
    // "expected value at line 1 column 1" after a hundred seconds of proving, naming neither the
    // size nor the limit.
    //
    // `Value` rather than `Request` because the body may also be an *array* of request objects, and
    // because a single object that does not deserialize should answer with the id it carried rather
    // than with axum's rejection.
    req: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> (StatusCode, Json<Value>) {
    let body = match req {
        Ok(Json(body)) => body,
        Err(rejection) => {
            // The HTTP status stays what axum decided (413 for an oversized body); only the body
            // becomes something a client can parse. The id is `null`: we never saw the request.
            return (rejection.status(), Json(error_value(Value::Null, rejection_error(&rejection))));
        }
    };
    // Everything past here parsed, so the HTTP status is 200 and the errors are in the body.
    let out = match body {
        Value::Array(items) if items.is_empty() => {
            error_value(Value::Null, RpcError::invalid_request("invalid request: empty batch"))
        }
        Value::Array(items) if items.len() > MAX_BATCH => error_value(
            Value::Null,
            RpcError::invalid_request(format!("batch of {} requests exceeds the limit of {MAX_BATCH}", items.len())),
        ),
        // Sequential on purpose: a batch must not multiply this node's concurrency, and the
        // expensive reads inside already hand themselves to the blocking pool one at a time.
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(dispatch_one(&st, it).await);
            }
            Value::Array(out)
        }
        obj @ Value::Object(_) => dispatch_one(&st, obj).await,
        _ => error_value(Value::Null, RpcError::invalid_request("invalid request: expected an object or an array")),
    };
    (StatusCode::OK, Json(out))
}

/// Turn a body axum would not give us into a JSON-RPC error, naming the limit when that is why.
fn rejection_error(rejection: &axum::extract::rejection::JsonRejection) -> RpcError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return RpcError::invalid_request(format!(
            "request body is larger than the {RPC_MAX_BODY_BYTES}-byte limit; \
             a transaction is sent as hex, so it may be at most half of that"
        ));
    }
    RpcError::invalid_request(rejection.body_text())
}

/// Run a storage read that is not O(1) on the blocking pool, so it cannot stall the tokio
/// workers the node loop shares. The closure takes owned handles (`Arc` clones) because it
/// outlives this call's borrow of the state.
async fn blocking<T, F>(f: F) -> Result<T, RpcError>
where
    T: Send + 'static,
    F: FnOnce() -> crate::storage::Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r.map_err(RpcError::internal),
        Err(e) => Err(RpcError::internal(format!("storage task failed: {e}"))),
    }
}

/// The viewing-key surface's own failure set. Storage errors ride the same channel so the arms
/// can use `?` for both.
enum ViewingError {
    Full,
    NotImported,
    Storage(crate::storage::StorageError),
}

impl From<crate::storage::StorageError> for ViewingError {
    fn from(e: crate::storage::StorageError) -> ViewingError {
        ViewingError::Storage(e)
    }
}

impl From<crate::viewing::RegistryFull> for ViewingError {
    fn from(_: crate::viewing::RegistryFull) -> ViewingError {
        ViewingError::Full
    }
}

/// `blocking` for the viewing-key arms: same spawn-blocking discipline (a scan trial-decrypts up
/// to `viewing::MAX_SCAN_ROWS` envelopes per call), a different error channel — the import cap
/// is a refusal and an unimported key is not-found, and neither is an internal error.
async fn blocking_viewing<T, F>(f: F) -> Result<T, RpcError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ViewingError> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(ViewingError::Full)) => Err(RpcError::rejected(crate::viewing::RegistryFull.to_string())),
        Ok(Err(ViewingError::NotImported)) => {
            Err(RpcError::not_found("that viewing key is not imported on this node"))
        }
        Ok(Err(ViewingError::Storage(e))) => Err(RpcError::internal(e)),
        Err(e) => Err(RpcError::internal(format!("storage task failed: {e}"))),
    }
}

fn param<T: serde::de::DeserializeOwned>(params: &Value, idx: usize, name: &str) -> Result<T, RpcError> {
    let v = params.get(idx).ok_or_else(|| RpcError::invalid_params(format!("missing param {name}")))?;
    serde_json::from_value(v.clone()).map_err(|e| RpcError::invalid_params(format!("bad param {name}: {e}")))
}

fn parse_hash(params: &Value, idx: usize) -> Result<Hash, RpcError> {
    let s: String = param(params, idx, "hash")?;
    Hash::from_hex(&s).map_err(|e| RpcError::invalid_params(format!("hash: {e}")))
}

/// A `rand1…` shielded address.
///
/// The length is checked *before* parsing: `ShieldedAddress::parse` base58-decodes the whole
/// string before it ever looks at the decoded length, and base58 decoding is quadratic in the
/// input. This runs on a tokio worker shared with the node loop, so an unbounded parameter would
/// let one request stall consensus. A real address is `rand1` plus ~1663 base58 characters
/// (32-byte `pk` + a 1184-byte ML-KEM-768 encapsulation key), so 2000 is generous.
fn parse_shielded(params: &Value, idx: usize) -> Result<ShieldedAddress, RpcError> {
    let s: String = param(params, idx, "address")?;
    if s.len() > MAX_ADDRESS_CHARS {
        return Err(RpcError::invalid_params(format!(
            "address is {} characters, at most {MAX_ADDRESS_CHARS} allowed",
            s.len()
        )));
    }
    ShieldedAddress::parse(&s).map_err(|e| RpcError::invalid_params(format!("address: {e}")))
}

/// A 32-byte value as hex, with or without `0x`: a bridge token address or emitter.
fn parse_bytes32(params: &Value, idx: usize, name: &str) -> Result<[u8; 32], RpcError> {
    let s: String = param(params, idx, name)?;
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(&s))
        .map_err(|_| RpcError::invalid_params(format!("{name} must be hex")))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| RpcError::invalid_params(format!("{name} must be 32 bytes, got {}", v.len())))
}

/// A `Word8` parameter as 64 hex characters, with or without `0x` — a viewing key's `nk`.
fn parse_word8(params: &Value, idx: usize, name: &str) -> Result<randprotocol_core::Word8, RpcError> {
    let s: String = param(params, idx, name)?;
    randprotocol_core::notes::word8_from_hex(s.strip_prefix("0x").unwrap_or(&s))
        .ok_or_else(|| RpcError::invalid_params(format!("{name} must be 64 hex characters")))
}

/// A note as the viewing-key methods report it. The amount is a **string**, like every amount
/// this RPC serves as chain state (`getValidators`, `getSupply`): a note's amount is a u64 a
/// JSON number cannot hold past 2^53, and these rows exist to be summed.
fn note_json(n: &randprotocol_zkvm::notes::Note) -> Value {
    json!({
        "pk": word8_to_hex(&n.pk),
        "from": word8_to_hex(&n.from),
        "amount": n.amount.to_string(),
        "asset": n.asset,
        "time": n.time,
    })
}

/// A page size, clamped to `MAX_PAGE`. A missing or null `limit` asks for the maximum.
fn parse_limit(params: &Value, idx: usize) -> Result<usize, RpcError> {
    match params.get(idx) {
        None | Some(Value::Null) => Ok(MAX_PAGE),
        Some(_) => {
            let n: u64 = param(params, idx, "limit")?;
            Ok((n as usize).min(MAX_PAGE))
        }
    }
}

fn envelope_json(e: &Envelope) -> Value {
    json!({
        "kem_ct": hex::encode(&e.kem_ct),
        "to_receiver": hex::encode(&e.to_receiver),
        "to_sender": hex::encode(&e.to_sender),
        "body": hex::encode(&e.body),
    })
}

/// What a `BridgeAttest` deposits, as far as it is public: the note's asset index and the
/// amount. `None` for a rotation, for an attestation this node cannot decode, and for an asset
/// the registry does not hold — the last of which only a transaction that is not committed yet
/// can be.
fn attest_deposit(attestation: &[u8], bridge: Option<&BridgeMeta>) -> Option<(u32, u64)> {
    let (asset, amount) = randprotocol_core::ledger::bridge_notes::attested_transfer(attestation)?;
    Some((bridge?.assets.get(&asset)?.index, amount))
}

/// One row of the bridge's asset registry: the note's `asset` word and the wire identity
/// guardians sign about.
fn asset_json(asset: &randprotocol_core::bridge::AssetId, info: &AssetInfo) -> Value {
    json!({
        "index": info.index,
        "chain": info.chain,
        "token": hex::encode(info.token),
        "asset_id": asset.to_hex(),
    })
}

/// The registry as `rand_getAssets` serves it: one row per registered asset, ascending by
/// index, which is registration order.
fn assets_json(bridge: &BridgeMeta) -> Vec<Value> {
    let mut rows: Vec<(&randprotocol_core::bridge::AssetId, &AssetInfo)> = bridge.assets.iter().collect();
    rows.sort_by_key(|(_, info)| info.index);
    rows.into_iter().map(|(asset, info)| asset_json(asset, info)).collect()
}

/// One block as a light wallet reads it: the header fields it chains on, and per transaction
/// the notes it created (leaf index, commitment, envelope) and the nullifiers it spent. No
/// proof, no action, no receipt — those are `rand_getBlockByHeight`'s job.
///
/// `notes` is this block's slice of the tree in append order. Each transaction owns
/// `commitments().len() + derived_note_count()` of it, in the order `Storage::commit` appended
/// them; anything left over goes into the block-level `commitments`, which is where genesis
/// deposits live and where a future note the attribution does not know about would still surface
/// rather than disappear.
fn compact_block_json(b: &randprotocol_core::Block, notes: &[(u64, crate::storage::NoteRow)]) -> Value {
    let row = |(index, r): &(u64, crate::storage::NoteRow)| {
        json!({ "index": index, "cm": word8_to_hex(&r.cm), "envelope": envelope_json(&r.envelope) })
    };
    let mut at = 0usize;
    let mut txs = Vec::with_capacity(b.transactions.len());
    for tx in &b.transactions {
        let want = tx.commitments().len() + crate::storage::derived_note_count(tx);
        let end = (at + want).min(notes.len());
        txs.push(json!({
            "hash": tx.hash().to_hex(),
            "commitments": notes[at..end].iter().map(row).collect::<Vec<_>>(),
            "nullifiers": tx.nullifiers().iter().map(word8_to_hex).collect::<Vec<_>>(),
        }));
        at = end;
    }
    json!({
        "height": b.height(),
        "hash": b.hash().to_hex(),
        "timestamp_ms": b.header.timestamp_ms,
        "commitments": notes[at.min(notes.len())..].iter().map(row).collect::<Vec<_>>(),
        "transactions": txs,
    })
}

/// The object `rand_getReceipt` returns: a call's public outcome, without the sealed transcript
/// (`rand_getCallEnvelope`'s job). Shared with `rand_getReceipts`' rows and the WebSocket's
/// `receipts` topic, which pushes a program's receipts as they land.
pub(crate) fn receipt_json(r: &CallReceipt) -> Value {
    json!({
        "tx": r.tx.to_hex(), "program": r.program.to_hex(), "tier": r.tier, "outputs": r.outputs,
        "height": r.height, "index": r.index,
        // The proof's public commitment to the call's private inputs. Public like every other
        // receipt field, and the associated data a call-input envelope is sealed against:
        // without it `rand_getCallEnvelope`'s bytes could not be opened by anyone (spec §6.1).
        "h_in": word8_to_hex(&r.h_in),
    })
}

/// A block's header fields alone — everything `block_json` reports except `transactions`, and
/// what `rand_getBlocks` pages over instead of the full block.
fn header_json(b: &randprotocol_core::Block, sealed: bool) -> Value {
    json!({
        "hash": b.hash().to_hex(), "height": b.height(), "view": b.view(), "parent": b.parent().to_hex(),
        "proposer": b.proposer().to_base58(), "timestamp_ms": b.header.timestamp_ms,
        "tx_root": b.header.tx_root.to_hex(), "state_root": b.header.state_root.to_hex(),
        "justify_view": b.header.justify.view, "sealed": sealed, "tx_count": b.transactions.len(),
    })
}

/// `rand_getFinality`'s response body, from either the storage-side committed answer or a
/// [`Finality`] the node loop sent back.
fn finality_json(f: &Finality) -> Value {
    match f {
        Finality::Committed { height, hash } => json!({ "status": "committed", "height": height, "hash": hash.to_hex() }),
        Finality::Certified { height, hash, qc_view } => {
            json!({ "status": "certified", "height": height, "hash": hash.to_hex(), "qc_view": qc_view })
        }
        Finality::Proposed { height, hash } => json!({ "status": "proposed", "height": height, "hash": hash.to_hex() }),
        Finality::Unknown => json!({ "status": "unknown" }),
    }
}

fn block_json(b: &randprotocol_core::Block, bridge: Option<&BridgeMeta>, executor: &dyn ConfidentialExecutor, storage: &crate::storage::Storage) -> Value {
    let sealed = storage.block_sealed(&b.hash()).unwrap_or(false);
    let txs: Vec<Value> = b
        .transactions
        .iter()
        .map(|t| {
            let mut j = tx_json(t, bridge, executor);
            // Per-bundle `sealed_by` (spec §8): the aggregate that covered it, `null` while it
            // is coverable — and for a bundle-less transaction, `null` by construction.
            let sealed_by = match &t.bundle {
                Some(_) => match storage.sealed_by(&t.hash()) {
                    Ok(Some((agg, _))) => Value::String(agg.to_hex()),
                    _ => Value::Null,
                },
                None => Value::Null,
            };
            j["sealed_by"] = sealed_by;
            j
        })
        .collect();
    let mut j = header_json(b, sealed);
    j["transactions"] = Value::Array(txs);
    j
}

/// The bundles an aggregator may still cover (spec §3.2, R8's view): committed
/// bundle-carrying transactions inside the window with no seal, paginated by block height as
/// `(rows, next_from)` — each row the hash, its block height and its excess over the floor
/// (what an aggregate would earn for covering it).
pub(crate) fn unsealed_bundles(
    storage: &crate::storage::Storage,
    head: u64,
    window: u64,
    from: u64,
    limit: usize,
) -> (Vec<Value>, Option<u64>) {
    let mut out = Vec::new();
    let mut next_from = None;
    'blocks: for h in from..=head {
        // The window (spec §3.3): coverable means newer than `head - window`.
        if h + window <= head {
            continue;
        }
        let Ok(Some(block)) = storage.block_by_height(h) else { continue };
        for tx in &block.transactions {
            let Some(b) = &tx.bundle else { continue };
            // The bundle's identity is its *raw* hash — the hash marks and covers name; a
            // marker-form record (this node synced the block in sealed form) resolves through
            // the proof-hash index.
            let raw_hash = match randprotocol_core::notes::pruned_proof_hash(&b.proof) {
                Some(ph) => match storage.tx_hash_by_proof_hash(&ph) {
                    Ok(Some(raw)) => raw,
                    _ => continue,
                },
                None => tx.hash(),
            };
            if matches!(storage.sealed_by(&raw_hash), Ok(Some(_))) {
                continue;
            }
            out.push(json!({
                "hash": raw_hash.to_hex(),
                "height": h,
                "excess": b.fee.saturating_sub(randprotocol_core::gas::BUNDLE_BASE).to_string(),
            }));
            if out.len() >= limit {
                next_from = Some(h + 1);
                break 'blocks;
            }
        }
    }
    (out, next_from)
}

/// What a block explorer can say about a transaction — which is, deliberately, almost nothing:
/// the bundle's public fields (none of which name a party) and the shape of its action. Envelope
/// and proof are reported by length only; anyone who wants the bytes can fetch the block, and a
/// call's public input commitment `H_IN` — the one thing a holder needs to open its input
/// envelope — is served on the receipt (`rand_getReceipt`, `rand_getCallEnvelope`).
/// A bundle's public fields — none of which names a party. Used for the transaction's own
/// bundle and, since S3's `BridgeBurn`, for the asset bundle riding inside the action.
fn bundle_json(b: &randprotocol_core::Bundle) -> Value {
    json!({
        "anchor": word8_to_hex(&b.anchor),
        "nullifiers": [word8_to_hex(&b.nullifiers[0]), word8_to_hex(&b.nullifiers[1])],
        "commitments": [word8_to_hex(&b.commitments[0]), word8_to_hex(&b.commitments[1])],
        "fee": b.fee,
        "burn": b.burn,
        "asset": b.asset,
        "time": b.time,
        "proof_len": b.proof.len(),
        "envelope_len": [b.envelopes[0].len(), b.envelopes[1].len()],
    })
}

/// `bridge` is the asset registry, which a `BridgeAttest` needs and nothing else does: the
/// deposit's asset index is state, not a field of the transaction. `executor` is what computes
/// that deposit's commitment, the one note commitment the wire does not carry.
fn tx_json(t: &Transaction, bridge: Option<&BridgeMeta>, executor: &dyn ConfidentialExecutor) -> Value {
    let bundle = t.bundle.as_ref().map(bundle_json);
    let action = match &t.action {
        Action::None => json!({ "kind": "none" }),
        Action::Mint { cm, amount, minter, .. } => json!({
            "kind": "mint", "cm": word8_to_hex(cm), "amount": amount, "minter": minter.address().to_base58()
        }),
        Action::Deploy { base_pc, words, public } => json!({
            "kind": "deploy", "program": randprotocol_core::program::program_id_with_public(*base_pc, words, public).to_hex(), "words": words.len()
        }),
        Action::Call { program, proof, input_envelope } => json!({
            "kind": "call", "program": program.to_hex(), "proof_len": proof.len(),
            // Length only, like every other envelope: the transcript is for the caller's
            // viewing key and an auditor, not for whoever is reading the explorer.
            "input_envelope_len": input_envelope.as_ref().map(|e| e.len() as u64),
        }),
        // The staking actions are the one place this chain has public amounts by design
        // (spec §8): the register is public, so its inputs are too.
        Action::Bond { validator, amount, registration } => json!({
            "kind": "bond", "validator": validator.to_base58(), "amount": amount,
            "registered": registration.is_some(),
        }),
        Action::Unbond { validator, amount, nonce, .. } => json!({
            "kind": "unbond", "validator": validator.to_base58(), "amount": amount, "nonce": nonce
        }),
        // `time` is the note's time word, which the withdrawing node chose: public like the
        // amount, and the one field an explorer needs to say which note this paid.
        Action::Withdraw { validator, amount, nonce, time, .. } => json!({
            "kind": "withdraw", "validator": validator.to_base58(), "amount": amount, "nonce": nonce,
            "time": time
        }),
        // The amount and the asset are inside the attestation, so they are decoded out of it
        // rather than read off a field; the index is what the registry gave that asset. Both
        // are `null` for a guardian-set rotation, which deposits nothing, and on a chain whose
        // registry does not name the asset yet. The recipient is public in this transaction
        // only — the note's later spend is not.
        Action::BridgeAttest { attestation, recipient, r, time, asset, .. } => {
            let deposit = attest_deposit(attestation, bridge);
            json!({
                "kind": "bridge_attest",
                "attestation_len": attestation.len(),
                "recipient": recipient.to_string(),
                // The index the action itself names — what the recipient's envelope was sealed
                // for — beside the one the registry resolves. Admission refuses a transaction
                // where they differ, so on a committed attest they agree; `asset_index` is still
                // the one to read, because it is `null` exactly when there is no deposit.
                "asset": asset,
                "asset_index": deposit.map(|(index, _)| index),
                "amount": deposit.map(|(_, amount)| amount),
                // The deposit note's own `time` word, which is what a recipient rebuilding that
                // note needs and the window rule this action was admitted under.
                "time": time,
                // The note's blinding. Not a secret: it is a field of the action, signed over by
                // the transaction and in every replica's block store — and with it, the four
                // above and the recipient, *every* word of the deposit note is here. That is the
                // recipient's recovery path when a hostile submitter publishes a garbage envelope
                // (`docs/bridge.md` §8): the note is rebuilt from these fields and checked
                // against `commitment`, with nothing decrypted.
                "r": word8_to_hex(r),
                // The leaf the chain appended for this deposit — the one note commitment the wire
                // does not carry, since the chain computes it rather than the submitter. `null`
                // for a rotation, which deposits nothing.
                "commitment": deposit.map(|(index, amount)| {
                    let cm = randprotocol_core::ledger::bridge_notes::deposit_commitment(
                        recipient, amount, index, *time, r, executor,
                    );
                    word8_to_hex(&cm)
                }),
            })
        }
        Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain, to } => json!({
            "kind": "bridge_burn", "asset": asset, "amount": amount, "relayer_fee": relayer_fee,
            "to_chain": to_chain, "to": hex::encode(to),
            "asset_bundle": bundle_json(asset_bundle),
        }),
        // Block aggregation: the register is public by design (spec §2), so its inputs are too —
        // the staking actions' rule, one register over. The aggregate itself reports the cover
        // count and the proof size; the covered bundles are named by hash anyway.
        Action::RegisterAggregator { registration } => json!({
            "kind": "register_aggregator", "aggregator": registration.public_key.address().to_base58()
        }),
        Action::UnbondAggregator { aggregator, nonce, .. } => json!({
            "kind": "unbond_aggregator", "aggregator": aggregator.to_base58(), "nonce": nonce
        }),
        Action::WithdrawAggregator { aggregator, nonce, time, .. } => json!({
            "kind": "withdraw_aggregator", "aggregator": aggregator.to_base58(), "nonce": nonce,
            "time": time
        }),
        Action::SlashAggregator { a, b } => json!({
            "kind": "slash_aggregator", "aggregator": a.aggregator.to_base58(), "nonce": a.nonce,
            "headers": [a.proof_hash.to_hex(), b.proof_hash.to_hex()]
        }),
        Action::Aggregate { covers, proof, aggregator, nonce, time, .. } => json!({
            "kind": "aggregate", "covers": covers.len(), "proof_len": proof.len(),
            "aggregator": aggregator.to_base58(), "nonce": nonce, "time": time
        }),
    };
    json!({
        "hash": t.hash().to_hex(),
        "chain_id": t.chain_id,
        "bundle": bundle,
        "action": action,
    })
}

/// Ask the node loop where the chain is in its epoch schedule.
async fn epoch_info(st: &RpcState) -> Result<EpochInfo, RpcError> {
    let (reply, rx) = oneshot::channel();
    st.node.send(NodeCommand::Epoch { reply }).await.map_err(|_| RpcError::internal("node loop closed"))?;
    rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))
}

async fn dispatch(st: &RpcState, req: &Request) -> Result<Value, RpcError> {
    let p = &req.params;
    match req.method.as_str() {
        "rand_chainId" => Ok(json!(st.chain_id)),
        "rand_tokenInfo" => Ok(json!({ "symbol": TOKEN_SYMBOL, "decimals": TOKEN_DECIMALS })),
        "rand_getVersion" => {
            let s = st.status.read().unwrap_or_else(|e| e.into_inner());
            Ok(json!({
                "version": env!("CARGO_PKG_VERSION"), "git_sha": GIT_SHA, "chain_id": st.chain_id,
                "hc_bundle": s.hc_bundle, "fri_profile": s.fri_profile,
            }))
        }
        "rand_getGenesisHash" => Ok(json!(st.storage.genesis_hash().map_err(RpcError::internal)?.to_hex())),
        "rand_getHealth" => {
            let s = st.status.read().unwrap_or_else(|e| e.into_inner()).clone();
            Ok(health_json(&s))
        }
        "rand_sendTransaction" => {
            let raw: String = param(p, 0, "tx")?;
            let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(&raw))
                .map_err(|_| RpcError::invalid_params("tx must be hex"))?;
            let tx = Transaction::decode(&bytes).map_err(|e| RpcError::invalid_params(format!("tx decode: {e}")))?;
            // The body limit admits more than a block can carry — two `MAX_PROOF_BYTES` proofs are
            // a legal `Call` by the per-part caps and still over `MAX_BLOCK_BYTES` — so refuse one
            // here rather than handing the node loop a transaction no block could ever include.
            // Admission refuses it too (`TxError::TransactionTooLarge`); this keeps it off the loop.
            let encoded_len = tx.encoded_len();
            if encoded_len > randprotocol_core::gas::MAX_BLOCK_BYTES {
                return Err(RpcError::rejected(format!(
                    "transaction of {encoded_len} bytes exceeds the {} byte block limit",
                    randprotocol_core::gas::MAX_BLOCK_BYTES
                )));
            }
            let (reply, rx) = oneshot::channel();
            st.node
                .send(NodeCommand::SubmitTx { tx, reply })
                .await
                .map_err(|_| RpcError::internal("node loop closed"))?;
            match rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))? {
                Ok(h) => Ok(json!(h.to_hex())),
                Err(e) => Err(RpcError::rejected(e.to_string())),
            }
        }
        "rand_mint" => {
            let to = parse_shielded(p, 0)?;
            let amount: u64 = match p.get(1) {
                None | Some(Value::Null) => randprotocol_core::FAUCET_MAX_UNITS,
                Some(v) => {
                    let s: String = serde_json::from_value(v.clone())
                        .map_err(|_| RpcError::invalid_params("amount must be a string of units"))?;
                    s.parse().map_err(|_| RpcError::invalid_params("amount must be a string of units"))?
                }
            };
            let (reply, rx) = oneshot::channel();
            st.node
                .send(NodeCommand::Mint { to, amount, reply })
                .await
                .map_err(|_| RpcError::internal("node loop closed"))?;
            match rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))? {
                Ok(h) => Ok(json!(h.to_hex())),
                Err(e) => Err(RpcError::rejected(e)),
            }
        }
        // ---- the shielded pool ----
        "rand_getCommitments" => {
            let from: u64 = param(p, 0, "from_index")?;
            let limit = parse_limit(p, 1)?;
            let rows = st.storage.notes_from(from, limit).map_err(RpcError::internal)?;
            Ok(json!(rows
                .into_iter()
                .map(|(index, r)| json!({
                    "index": index,
                    "cm": word8_to_hex(&r.cm),
                    "envelope": envelope_json(&r.envelope),
                    "height": r.height,
                }))
                .collect::<Vec<_>>()))
        }
        "rand_getNullifiers" => {
            let from: u64 = param(p, 0, "from_height")?;
            let limit = parse_limit(p, 1)?;
            // Scans and sorts the whole family (the rows are keyed by nullifier, not height), so
            // it grows with the chain and does not belong on a runtime worker.
            let storage = st.storage.clone();
            let rows = blocking(move || storage.nullifiers_from(from, limit)).await?;
            Ok(json!(rows
                .into_iter()
                .map(|(height, nf)| json!({ "height": height, "nullifier": word8_to_hex(&nf) }))
                .collect::<Vec<_>>()))
        }
        // A range of blocks with everything a light wallet needs and nothing it does not: the
        // commitments each transaction created with their leaf indices and envelopes, and the
        // nullifiers it spent. Zcash's `CompactBlock` by another name (`docs/rpc-comparison.md` §4),
        // and the reason a sync is one round-trip per page instead of two per block.
        "rand_getCompactBlocks" => {
            let from: u64 = param(p, 0, "from_height")?;
            let to: u64 = param(p, 1, "to_height")?;
            if to < from {
                return Err(RpcError::invalid_params(format!("to_height {to} is below from_height {from}")));
            }
            let to = to.min(from.saturating_add(MAX_COMPACT_BLOCKS - 1));
            let storage = st.storage.clone();
            // Reads every block in the range and scans a slice of the notes family: linear in the
            // range, so it goes on the blocking pool like the other unbounded reads here.
            let out = blocking(move || {
                let head = storage.head()?.height;
                let to = to.min(head);
                let mut rows: Vec<Value> = Vec::new();
                let mut emitted = 0usize;
                for h in from..=to {
                    let Some(b) = storage.block_by_height(h)? else { break };
                    // Always emit the first block whole, however many notes it holds, so a client
                    // is never stuck behind one fat block; after that the page cap ends the reply.
                    if !rows.is_empty() && emitted >= MAX_PAGE {
                        break;
                    }
                    let notes = storage.notes_in_heights(h, h, usize::MAX)?;
                    emitted += notes.len();
                    rows.push(compact_block_json(&b, &notes));
                }
                Ok(rows)
            })
            .await?;
            Ok(json!(out))
        }
        // A node that caught up in one sync batch longer than the anchor window only stores
        // rows for the heights that batch covered, so `getAnchor` can answer "no anchor at
        // height h" for a height the chain really did pass through; ask for the head instead,
        // which is the only anchor a prover should build against anyway.
        "rand_getAnchor" => {
            let (height, root) = match p.get(0) {
                None | Some(Value::Null) => {
                    st.storage.latest_anchor().map_err(RpcError::internal)?.ok_or_else(|| RpcError::not_found("no anchor"))?
                }
                Some(_) => {
                    let h: u64 = param(p, 0, "height")?;
                    let root = st
                        .storage
                        .anchor(h)
                        .map_err(RpcError::internal)?
                        .ok_or_else(|| RpcError::not_found(format!("no anchor at height {h}")))?;
                    (h, root)
                }
            };
            Ok(json!({ "height": height, "root": word8_to_hex(&root) }))
        }
        "rand_getWitness" => {
            let index: u64 = param(p, 0, "index")?;
            // Reads every leaf and rebuilds a full depth-32 tree to fold one path: the most
            // expensive read this node serves, and unbounded in the chain's size.
            let (storage, executor) = (st.storage.clone(), st.executor.clone());
            match blocking(move || storage.witness(index, executor.as_ref())).await? {
                None => Ok(Value::Null),
                Some((root, path)) => Ok(json!({
                    "index": index,
                    "root": word8_to_hex(&root),
                    "path": path.iter().map(word8_to_hex).collect::<Vec<_>>(),
                })),
            }
        }
        // `rand_getWitness`, folded over many leaves in one tree build: a wallet proving several
        // notes at once pays for the rebuild once instead of once per note.
        "rand_getWitnesses" => {
            let indices: Vec<u64> = param(p, 0, "indices")?;
            if indices.is_empty() || indices.len() > MAX_WITNESSES {
                return Err(RpcError::invalid_params(format!("indices must hold 1 to {MAX_WITNESSES} leaf indices")));
            }
            let (storage, executor) = (st.storage.clone(), st.executor.clone());
            let idx = indices.clone();
            let (root, paths) = blocking(move || storage.witnesses(&idx, executor.as_ref())).await?;
            let witnesses: Vec<Value> = indices
                .iter()
                .zip(paths)
                .map(|(i, p)| json!({
                    "index": i,
                    "path": p.map(|p| p.iter().map(word8_to_hex).collect::<Vec<_>>()),
                }))
                .collect();
            Ok(json!({ "root": word8_to_hex(&root), "witnesses": witnesses }))
        }
        "rand_getTreeInfo" => {
            let next_index = st.storage.notes_count().map_err(RpcError::internal)?;
            let root = st.storage.tree().map_err(RpcError::internal)?.root();
            let nullifiers = st.storage.nullifiers_count().map_err(RpcError::internal)?;
            Ok(json!({ "next_index": next_index, "root": word8_to_hex(&root), "nullifiers": nullifiers }))
        }
        // ---- node-side viewing keys (`docs/rpc-comparison.md` §4) ----
        // The Zcash `z_importviewingkey` analogue, and the one deliberate exception to "the node
        // never holds a key": an operator hands this node a viewing key and the node scans for
        // that key's notes on the holder's behalf — what a block explorer runs a node *for*. The
        // RPC layer has no type for a *spend* key, so nothing here can move value. Imports are
        // in memory only; a restart clears them.
        "rand_importViewingKey" => {
            let nk = parse_word8(p, 0, "viewing_key")?;
            let rescan_from_height: u64 = match p.get(1) {
                None | Some(Value::Null) => 0,
                Some(_) => param(p, 1, "rescan_from_height")?,
            };
            let (viewing, storage) = (st.viewing.clone(), st.storage.clone());
            blocking_viewing(move || {
                // The cursor starts at the first leaf of that height (one binary search), so the
                // scan never reads — let alone trial-decrypts — anything earlier.
                let start = storage.first_note_at_or_after(rescan_from_height)?;
                let mut reg = viewing.write().unwrap_or_else(|e| e.into_inner());
                let imported = reg.import(nk, rescan_from_height, start)?;
                Ok(json!({ "imported": imported, "rescan_from_height": rescan_from_height, "viewing_keys": reg.len() }))
            })
            .await
        }
        // The scan is lazy and lives here: import only records the key, and each call advances
        // the cursor by at most `viewing::MAX_SCAN_ROWS` leaves (the rescan-range cap), so one
        // request can never make the node re-walk unbounded history.
        "rand_getViewingNotes" => {
            let nk = parse_word8(p, 0, "viewing_key")?;
            let from_index: u64 = match p.get(1) {
                None | Some(Value::Null) => 0,
                Some(_) => param(p, 1, "from_index")?,
            };
            let limit = parse_limit(p, 2)?;
            let (viewing, storage) = (st.viewing.clone(), st.storage.clone());
            blocking_viewing(move || {
                let mut reg = viewing.write().unwrap_or_else(|e| e.into_inner());
                let import = reg.get_mut(&nk).ok_or(ViewingError::NotImported)?;
                crate::viewing::advance(&storage, import, crate::viewing::MAX_SCAN_ROWS)?;
                let next_index = storage.notes_count()?;
                let mut notes = Vec::new();
                for n in import.notes.iter().filter(|n| n.index >= from_index).take(limit) {
                    // A received note's nullifier is a function of this key, so its spent state is
                    // a point lookup served fresh on every call; a sent note belongs to someone
                    // else and has neither.
                    let (nullifier, spent) = match n.role {
                        crate::viewing::Role::Received => {
                            let nf = import.vk.nullifier(&n.cm);
                            (Some(word8_to_hex(&nf)), Some(storage.nullifier_height(&nf)?.is_some()))
                        }
                        crate::viewing::Role::Sent => (None, None),
                    };
                    notes.push(json!({
                        "index": n.index, "cm": word8_to_hex(&n.cm), "height": n.height,
                        "role": n.role.as_str(), "note": note_json(&n.note),
                        "nullifier": nullifier, "spent": spent,
                    }));
                }
                Ok(json!({
                    "scanned_index": import.scanned_index,
                    "next_index": next_index,
                    "complete": import.scanned_index >= next_index,
                    "notes": notes,
                }))
            })
            .await
        }
        // ---- confidential computation ----
        "rand_getProgram" => {
            let id = parse_hash(p, 0)?;
            match st.storage.program(&id).map_err(RpcError::internal)? {
                None => Ok(Value::Null),
                Some(r) => Ok(json!({
                    "id": r.id.to_hex(), "base_pc": r.base_pc, "words_len": r.words.len(),
                    "code_hash": hex::encode(&r.code_hash), "deployed_at": r.deployed_at
                })),
            }
        }
        "rand_getProgramCode" => {
            let id = parse_hash(p, 0)?;
            Ok(st
                .storage
                .program(&id)
                .map_err(RpcError::internal)?
                .map(|r| json!({ "base_pc": r.base_pc, "words": r.words }))
                .unwrap_or(Value::Null))
        }
        "rand_getReceipt" => {
            let h = parse_hash(p, 0)?;
            Ok(st.storage.receipt(&h).map_err(RpcError::internal)?.map(|r| receipt_json(&r)).unwrap_or(Value::Null))
        }
        // A program's receipts, height then index, the index Task 2 built for it. `limit` is
        // clamped rather than refused, like `rand_getCompactBlocks`'s page, but it is a soft
        // floor: a page never splits a height, so it may exceed `limit` by the rest of its last
        // height's calls, bounded by however many calls one block can hold. `next_height` is the
        // first height this page did not serve, `null` once the range is exhausted.
        "rand_getReceipts" => {
            let program: ProgramId = parse_hash(p, 0)?;
            let from: u64 = param(p, 1, "from_height")?;
            let to: u64 = param(p, 2, "to_height")?;
            if to < from {
                return Err(RpcError::invalid_params(format!("to_height {to} is below from_height {from}")));
            }
            let limit = match p.get(3) {
                Some(Value::Null) | None => MAX_RECEIPTS_PAGE,
                Some(_) => param::<usize>(p, 3, "limit")?.clamp(1, MAX_RECEIPTS_PAGE),
            };
            let storage = st.storage.clone();
            let (rows, next) = blocking(move || storage.receipts_for_program(&program, from, to, limit)).await?;
            Ok(json!({ "receipts": rows.iter().map(receipt_json).collect::<Vec<_>>(), "next_height": next }))
        }
        // The sealed transcript of a call's private inputs (spec §6.1), verbatim, in hex. The
        // node holds no key that opens it and never looks inside: it is served so that the
        // caller's viewing key, a per-call key, or the auditor named when it was sealed can
        // (`randprotocol_zkvm::call_envelope`). `null` for a call that published none, for a
        // transaction that is not a call, and for a hash this node has no receipt for.
        "rand_getCallEnvelope" => {
            let h = parse_hash(p, 0)?;
            Ok(st
                .storage
                .receipt(&h)
                .map_err(RpcError::internal)?
                .and_then(|r| r.input_envelope.map(|e| (r.tx, r.h_in, e)))
                .map(|(tx, h_in, e)| {
                    json!({
                        "tx": tx.to_hex(),
                        // Repeated from the receipt so one request is enough to open the
                        // envelope: it is the AEAD associated data every part below is bound to.
                        "h_in": word8_to_hex(&h_in),
                        "kem_ct": hex::encode(&e.kem_ct),
                        "to_sender": hex::encode(&e.to_sender),
                        "to_auditor": hex::encode(&e.to_auditor),
                        "body": hex::encode(&e.body),
                    })
                })
                .unwrap_or(Value::Null))
        }
        "rand_estimateFee" => {
            let spec: Value = param(p, 0, "spec")?;
            let kind = spec.get("kind").and_then(|k| k.as_str()).unwrap_or_default();
            let fee = match kind {
                // Every transaction that carries a bundle pays the base; `Action::None` is the
                // plain shielded transfer, so its floor is the base alone.
                "bundle" => randprotocol_core::gas::BUNDLE_BASE,
                "deploy" => {
                    let words = spec.get("words").and_then(|w| w.as_u64()).unwrap_or(0) as usize;
                    if words > st.max_program_words {
                        return Err(RpcError::invalid_params(format!(
                            "words must be at most {} (this chain's program cap)",
                            st.max_program_words
                        )));
                    }
                    // `fee_floor(&Action::Deploy { words: vec![0; words], .. })` would compute the
                    // same number, but only after allocating a throwaway `words`-long `Vec<u32>`
                    // (up to `max_program_words`, i.e. up to 256 KiB) on every estimate call —
                    // `deploy_fee` is the pure per-word term `fee_floor` itself adds to
                    // `BUNDLE_BASE` for a deploy, so call it directly instead.
                    randprotocol_core::gas::BUNDLE_BASE + randprotocol_core::gas::deploy_fee(words)
                }
                "call" => {
                    let Some(n) = spec.get("tier").and_then(|t| t.as_u64()) else {
                        return Err(RpcError::invalid_params("call needs a tier"));
                    };
                    // Tiers are the even log2 heights 10..=20; `n as u8` alone would silently
                    // truncate (256 became tier 0).
                    let Ok(tier) = u8::try_from(n) else {
                        return Err(RpcError::invalid_params("tier must be one of 10, 12, 14, 16, 18, 20"));
                    };
                    if !(randprotocol_core::gas::MIN_TIER..=randprotocol_core::gas::MAX_TIER).contains(&tier) || tier % 2 != 0 {
                        return Err(RpcError::invalid_params("tier must be one of 10, 12, 14, 16, 18, 20"));
                    }
                    // The byte term is zero here: this is the fee of a call under the free
                    // allowance, which is every call a default chain admits (spec §7).
                    randprotocol_core::gas::BUNDLE_BASE + randprotocol_core::gas::call_fee(tier, 0)
                }
                _ => return Err(RpcError::invalid_params("kind must be bundle, deploy or call")),
            };
            Ok(json!(fee.to_string()))
        }
        "rand_getTransaction" => {
            let h = parse_hash(p, 0)?;
            let bridge = st.storage.bridge_meta().map_err(RpcError::internal)?;
            match st.storage.tx_location(&h).map_err(RpcError::internal)? {
                None => Ok(Value::Null),
                Some((height, index)) => {
                    let b = st
                        .storage
                        .block_by_height(height)
                        .map_err(RpcError::internal)?
                        .ok_or_else(|| RpcError::not_found("block missing"))?;
                    let tx = b.transactions.get(index as usize).ok_or_else(|| RpcError::not_found("tx index"))?;
                    Ok(json!({
                        "height": height,
                        "index": index,
                        "block_hash": b.hash().to_hex(),
                        "tx": tx_json(tx, bridge.as_ref(), st.executor.as_ref()),
                    }))
                }
            }
        }
        // Monero's `check_tx_proof` shape (`docs/rpc-comparison.md` §4): given a committed
        // transaction's hash and a per-transaction `TxKey`, report what that key discloses about
        // the transaction. Stateless — the key opens this one call's envelopes and is dropped;
        // nothing is registered, and a key that sealed nothing gets an empty list, not an error.
        "rand_checkTransaction" => {
            // Cheap before expensive: both byte parameters are parsed before any storage read.
            let h = parse_hash(p, 0)?;
            let key = parse_bytes32(p, 1, "key")?;
            let Some((height, index)) = st.storage.tx_location(&h).map_err(RpcError::internal)? else {
                return Ok(Value::Null);
            };
            let b = st
                .storage
                .block_by_height(height)
                .map_err(RpcError::internal)?
                .ok_or_else(|| RpcError::not_found("block missing"))?;
            let tx = b.transactions.get(index as usize).ok_or_else(|| RpcError::not_found("tx index"))?;
            // A `BridgeAttest`'s deposit commitment — the one commitment the wire does not carry
            // — computed from the registry exactly as `tx_json` renders it.
            let deposit_cm = match &tx.action {
                Action::BridgeAttest { attestation, recipient, r, time, .. } => {
                    let bridge = st.storage.bridge_meta().map_err(RpcError::internal)?;
                    attest_deposit(attestation, bridge.as_ref()).map(|(index, amount)| {
                        randprotocol_core::ledger::bridge_notes::deposit_commitment(
                            recipient,
                            amount,
                            index,
                            *time,
                            r,
                            st.executor.as_ref(),
                        )
                    })
                }
                _ => None,
            };
            let opened = crate::viewing::disclosed(tx, deposit_cm, &randprotocol_zkvm::viewing::TxKey(key));
            if opened.is_empty() {
                return Ok(json!({ "tx": h.to_hex(), "height": height, "disclosed": [] }));
            }
            // Each opened note's leaf index, by matching its commitment against the block's own
            // slice of the tree — unique, because the ledger refuses duplicate commitments.
            let rows = st.storage.notes_in_heights(height, height, usize::MAX).map_err(RpcError::internal)?;
            let mut out = Vec::with_capacity(opened.len());
            for o in opened {
                let leaf = rows
                    .iter()
                    .find(|(_, r)| r.cm == o.cm)
                    .map(|(i, _)| *i)
                    .ok_or_else(|| RpcError::internal("the disclosed note's commitment is not a leaf of its block"))?;
                out.push(json!({
                    "output": match o.output {
                        "deposit" => "deposit".to_string(),
                        other => format!("{other}:{}", o.slot),
                    },
                    "cm": word8_to_hex(&o.cm),
                    "index": leaf,
                    "note": note_json(&o.note),
                }));
            }
            Ok(json!({ "tx": h.to_hex(), "height": height, "disclosed": out }))
        }
        "rand_getBlockByHeight" => {
            let h: u64 = param(p, 0, "height")?;
            let bridge = st.storage.bridge_meta().map_err(RpcError::internal)?;
            let block = st.storage.block_by_height(h).map_err(RpcError::internal)?;
            Ok(block.map(|b| block_json(&b, bridge.as_ref(), st.executor.as_ref(), &st.storage)).unwrap_or(Value::Null))
        }
        "rand_getBlockByHash" => {
            let h = parse_hash(p, 0)?;
            let bridge = st.storage.bridge_meta().map_err(RpcError::internal)?;
            let block = st.storage.block_by_hash(&h).map_err(RpcError::internal)?;
            Ok(block.map(|b| block_json(&b, bridge.as_ref(), st.executor.as_ref(), &st.storage)).unwrap_or(Value::Null))
        }
        // Headers over a range, capped like `rand_getCompactBlocks`: the block list a client
        // pages through without paying for every transaction in it.
        "rand_getBlocks" => {
            let from: u64 = param(p, 0, "from_height")?;
            let to: u64 = param(p, 1, "to_height")?;
            if to < from {
                return Err(RpcError::invalid_params(format!("to_height {to} is below from_height {from}")));
            }
            let head = st.storage.head().map_err(RpcError::internal)?.height;
            let to = to.min(head).min(from.saturating_add(MAX_COMPACT_BLOCKS - 1));
            let storage = st.storage.clone();
            let headers = blocking(move || {
                let mut out = Vec::new();
                for h in from..=to {
                    if let Some(b) = storage.block_by_height(h)? {
                        let sealed = storage.block_sealed(&b.hash())?;
                        out.push(header_json(&b, sealed));
                    }
                }
                Ok(out)
            })
            .await?;
            Ok(Value::Array(headers))
        }
        // ---- block aggregation (spec §8) ----
        // The register is public by design (spec §2), so its rows and the sealing facts are too.
        "rand_getAggregate" => {
            let h = parse_hash(p, 0)?;
            let Some(tx) = st.storage.tx_by_hash(&h).map_err(RpcError::internal)? else {
                return Ok(Value::Null);
            };
            let randprotocol_core::types::Action::Aggregate { covers, aggregator, .. } = &tx.action else {
                return Ok(Value::Null);
            };
            let (height, _) = st.storage.tx_location(&h).map_err(RpcError::internal)?.unwrap_or((0, 0));
            let (subsidy, shares, n) = st.storage.aggregate_payment(&h).map_err(RpcError::internal)?.unwrap_or((0, 0, 0));
            Ok(json!({
                "hash": h.to_hex(),
                "height": height,
                "covers": covers.iter().map(|c| c.to_hex()).collect::<Vec<_>>(),
                "aggregator": aggregator.to_base58(),
                "subsidy": subsidy.to_string(),
                "proving_share": shares.to_string(),
                "n": n,
            }))
        }
        "rand_getAggregators" => {
            let rows = st.storage.aggregators().map_err(RpcError::internal)?;
            Ok(json!(rows
                .iter()
                .map(|(addr, e)| json!({
                    "address": addr.to_base58(),
                    "bond": e.bond.to_string(),
                    "payout": e.payout.to_string(),
                    "nonce": e.nonce,
                    "unbonding": e.unbonding,
                }))
                .collect::<Vec<_>>()))
        }
        "rand_getUnsealed" => {
            let from: u64 = param(p, 0, "from")?;
            let limit = parse_limit(p, 1)?;
            let head = st.storage.head().map_err(RpcError::internal)?.height;
            let ledger = st.storage.load_ledger(st.executor.as_ref()).map_err(RpcError::internal)?;
            let Some(cfg) = ledger.aggregation() else {
                return Ok(json!({ "bundles": [], "next_from": Value::Null }));
            };
            let (bundles, next_from) = unsealed_bundles(&st.storage, head, cfg.window, from, limit);
            Ok(json!({ "bundles": bundles, "next_from": next_from }))
        }
        // The raw bytes a prover needs (the aggregate daemon's fetch): the full transaction,
        // bincode then hex — what `tx_json` deliberately does not render.
        "rand_getRawTransaction" => {
            let h = parse_hash(p, 0)?;
            let Some(tx) = st.storage.tx_by_hash(&h).map_err(RpcError::internal)? else {
                return Ok(Value::Null);
            };
            Ok(json!(hex::encode(tx.encode())))
        }
        "rand_getHead" => {
            let head = head_summary(&st.storage, &st.status).map_err(RpcError::internal)?;
            Ok(serde_json::to_value(head).map_err(RpcError::internal)?)
        }
        "rand_syncStatus" | "rand_status" => {
            let s = st.status.read().unwrap_or_else(|e| e.into_inner()).clone();
            Ok(serde_json::to_value(s).map_err(RpcError::internal)?)
        }
        "rand_getPeers" => {
            let (reply, rx) = oneshot::channel();
            st.node.send(NodeCommand::Peers { reply }).await.map_err(|_| RpcError::internal("node loop closed"))?;
            let peers = rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))?;
            Ok(serde_json::to_value(peers).map_err(RpcError::internal)?)
        }
        // ---- the bridge ----
        // Public by design (spec §10): the bridge's own state names no pool participant. What
        // it does name — guardians, source emitters, the asset registry, how many messages have
        // gone out — is what a relayer and a guardian both have to read to work.
        "rand_getBridgeState" => {
            let Some(bridge) = st.storage.bridge_meta().map_err(RpcError::internal)? else {
                return Ok(json!({ "enabled": false }));
            };
            let guardians = bridge
                .guardian_sets
                .get(&bridge.current_set)
                .map(|s| s.keys.iter().map(hex::encode).collect::<Vec<_>>())
                .unwrap_or_default();
            Ok(json!({
                "enabled": true,
                "emitter": hex::encode(bridge.emitter),
                "emitters": bridge
                    .emitters
                    .iter()
                    .map(|(c, a)| (c.to_string(), json!(hex::encode(a))))
                    .collect::<serde_json::Map<String, Value>>(),
                "guardian_set_index": bridge.current_set,
                "guardians": guardians,
                "burn_sequence": bridge.burn_sequence,
                "next_index": bridge.next_index,
                "assets": assets_json(&bridge),
            }))
        }
        // The registry alone, which is what a wallet needs to read a note's `asset` word.
        // Empty on a chain without a bridge, like every other bridge read here.
        "rand_getAssets" => {
            let bridge = st.storage.bridge_meta().map_err(RpcError::internal)?;
            Ok(json!(bridge.as_ref().map(assets_json).unwrap_or_default()))
        }
        // The outbound message with this sequence, verbatim, for guardians to sign.
        "rand_getBridgeBurn" => {
            let sequence: u64 = param(p, 0, "sequence")?;
            Ok(st
                .storage
                .bridge_burn(sequence)
                .map_err(RpcError::internal)?
                .map(|r| {
                    json!({
                        "sequence": r.sequence, "body_hex": hex::encode(&r.body), "digest": hex::encode(r.digest),
                        "tx": r.tx.to_hex(), "height": r.height,
                    })
                })
                .unwrap_or(Value::Null))
        }
        // Pure arithmetic on the two wire fields, so it answers on any chain: the asset id is
        // what the registry is keyed by, and a caller that has a token address needs it to
        // find that token's note index.
        "rand_bridgeAssetId" => {
            let token_chain: u16 = param(p, 0, "token_chain")?;
            let token_address = parse_bytes32(p, 1, "token_address")?;
            Ok(json!(asset_id(token_chain, &token_address).to_hex()))
        }
        // Since phase S2 this is the *register* (spec §8), not the genesis set: every address
        // that has ever bonded, whether or not it is in an epoch's set today. `active` is what
        // says which of them are running the current epoch.
        "rand_getValidators" => {
            let register = st.storage.register().map_err(RpcError::internal)?;
            let active = epoch_info(st).await?.current;
            let out: Vec<Value> = register
                .iter()
                .map(|(addr, e)| {
                    json!({
                        "address": addr.to_base58(),
                        // Amounts go out as decimal strings: JSON numbers are not safe integers
                        // past 2^53, and a stake is 10^9 units per RAND.
                        "stake": e.stake.to_string(),
                        "pending": e.pending
                            .iter()
                            .map(|(release_epoch, amount)| json!({ "release_epoch": release_epoch, "amount": amount.to_string() }))
                            .collect::<Vec<_>>(),
                        "rewards": e.rewards.to_string(),
                        "payout": e.payout.to_string(),
                        "nonce": e.nonce,
                        "active": active.contains(addr),
                    })
                })
                .collect();
            Ok(json!(out))
        }
        "rand_getEpoch" => {
            let info = epoch_info(st).await?;
            Ok(json!({
                "epoch": info.epoch,
                "epoch_blocks": info.epoch_blocks,
                "next_set": info.next.iter().map(|a| a.to_base58()).collect::<Vec<_>>(),
            }))
        }
        "rand_getMempoolInfo" => {
            let (reply, rx) = oneshot::channel();
            st.node.send(NodeCommand::MempoolInfo { reply }).await.map_err(|_| RpcError::internal("node loop closed"))?;
            let info = rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))?;
            Ok(serde_json::to_value(info).map_err(RpcError::internal)?)
        }
        // Committed comes straight from storage; pending, rejected (with the admission reason)
        // and unknown come from the node loop, which alone holds the mempool and the refused
        // cache. That cache holds only refusals about the transaction's own bytes
        // (`admission::is_permanent`); a state-dependent one (a spent nullifier, an expired
        // anchor) is never remembered and reads `unknown` once the transaction is out of the pool.
        // Nor is a rejection kept forever — the cache can evict — but a client polling
        // `wait_for_transaction` sees it before that happens, which is the point.
        "rand_getTransactionStatus" => {
            let raw: Vec<String> = param(p, 0, "hashes")?;
            if raw.is_empty() || raw.len() > MAX_STATUS_HASHES {
                return Err(RpcError::invalid_params(format!(
                    "hashes must hold 1 to {MAX_STATUS_HASHES} entries"
                )));
            }
            let hashes = raw
                .iter()
                .map(|s| Hash::from_hex(s).map_err(|e| RpcError::invalid_params(format!("hash: {e}"))))
                .collect::<Result<Vec<_>, _>>()?;
            let (reply, rx) = oneshot::channel();
            st.node
                .send(NodeCommand::TxStatus { hashes: hashes.clone(), reply })
                .await
                .map_err(|_| RpcError::internal("node loop closed"))?;
            let pool = rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))?;
            // Up to 64 RocksDB reads: one blocking task for all of them, not one per hash.
            let storage = st.storage.clone();
            let located = blocking(move || {
                hashes.into_iter().map(|h| Ok((h, storage.tx_location(&h)?))).collect::<crate::storage::Result<Vec<_>>>()
            })
            .await?;
            let mut out = Vec::with_capacity(located.len());
            for ((h, loc), ps) in located.into_iter().zip(pool) {
                let h = h.to_hex();
                let entry = match loc {
                    Some((height, index)) => {
                        json!({ "hash": h, "status": "committed", "height": height, "index": index })
                    }
                    None => match ps {
                        PoolStatus::Pending => json!({ "hash": h, "status": "pending" }),
                        PoolStatus::Rejected(reason) => {
                            json!({ "hash": h, "status": "rejected", "reason": reason })
                        }
                        PoolStatus::Unknown => json!({ "hash": h, "status": "unknown" }),
                    },
                };
                out.push(entry);
            }
            Ok(Value::Array(out))
        }
        // `p[0]` is a height or a hash. A height only ever names a committed block (or none),
        // which storage answers alone; a hash might be committed (storage again), or it might be
        // a block only the replica's tree still holds — certified, merely proposed, or unknown to
        // it altogether — which only the node loop can say.
        "rand_getFinality" => {
            let v = p.get(0).ok_or_else(|| RpcError::invalid_params("missing param 0"))?;
            if let Some(h) = v.as_u64() {
                return Ok(match st.storage.block_by_height(h).map_err(RpcError::internal)? {
                    Some(b) => json!({ "status": "committed", "height": h, "hash": b.hash().to_hex() }),
                    None => json!({ "status": "unknown" }),
                });
            }
            let Some(s) = v.as_str() else {
                return Err(RpcError::invalid_params("param 0 must be a height or a block hash"));
            };
            let hash = Hash::from_hex(s).map_err(|e| RpcError::invalid_params(format!("hash: {e}")))?;
            if let Some(b) = st.storage.block_by_hash(&hash).map_err(RpcError::internal)? {
                return Ok(json!({ "status": "committed", "height": b.height(), "hash": hash.to_hex() }));
            }
            let (reply, rx) = oneshot::channel();
            st.node.send(NodeCommand::Finality { hash, reply }).await.map_err(|_| RpcError::internal("node loop closed"))?;
            let f = rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))?;
            // The block may have committed between the storage miss above and the node loop's
            // answer — and a committed block below the head is pruned from the tree, so the loop
            // no longer knows it. One more storage look turns that race's `unknown` into the
            // `committed` it really is; a hash neither side has is still `unknown`.
            if f == Finality::Unknown {
                if let Some(b) = st.storage.block_by_hash(&hash).map_err(RpcError::internal)? {
                    return Ok(json!({ "status": "committed", "height": b.height(), "hash": hash.to_hex() }));
                }
            }
            Ok(finality_json(&f))
        }
        // `[view]` or `[from, to]` (inclusive): the leader of each view under the current
        // validator set, which only the node loop's replica derives.
        "rand_getProposer" => {
            let from: u64 = param(p, 0, "view")?;
            let to: u64 = match p.get(1) {
                Some(v) if !v.is_null() => {
                    serde_json::from_value(v.clone()).map_err(|e| RpcError::invalid_params(format!("bad param to: {e}")))?
                }
                _ => from,
            };
            if to < from {
                return Err(RpcError::invalid_params("to must be >= from"));
            }
            // Overflow-safe count check, and checked *before* any allocation: `to - from + 1`
            // overflows at `[u64::MAX - 1, u64::MAX]`, and collecting `from..=to` first would let
            // `[0, u64::MAX]` try to allocate 2^64 entries before this ever ran.
            if to - from >= MAX_PROPOSER_VIEWS as u64 {
                return Err(RpcError::invalid_params(format!("views must hold at most {MAX_PROPOSER_VIEWS} entries")));
            }
            let views: Vec<u64> = (from..=to).collect();
            let (reply, rx) = oneshot::channel();
            st.node
                .send(NodeCommand::Proposer { views: views.clone(), reply })
                .await
                .map_err(|_| RpcError::internal("node loop closed"))?;
            let (epoch, proposers) = rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))?;
            if proposers.len() != views.len() {
                return Err(RpcError::internal("proposer reply length mismatch"));
            }
            Ok(json!({
                "epoch": epoch,
                "proposers": views.iter().zip(proposers.iter())
                    .map(|(v, a)| json!({ "view": v, "proposer": a.to_base58() }))
                    .collect::<Vec<_>>(),
            }))
        }
        // The supply audit (`ledger::supply`). Note values are hidden, but every crossing of the
        // pool's boundary is public, so this is exact rather than an estimate — and
        // `--verify-chain` recomputes every counter in it by replaying the chain.
        "rand_getSupply" => {
            let height = st.storage.head().map_err(RpcError::internal)?.height;
            let supply = st.storage.supply().map_err(RpcError::internal)?;
            let register = st.storage.register().map_err(RpcError::internal)?;
            let aggregators = st.storage.aggregators().map_err(RpcError::internal)?;
            // The register's two halves, exactly `Ledger::audit`'s: the aggregator register's
            // outstanding bonds are register-side value, and without them the invariant would
            // read false on any chain with a live registration.
            let register_total = randprotocol_core::ledger::register_total(&register)
                .saturating_add(randprotocol_core::ledger::supply::aggregators_total(&aggregators));
            let audit = randprotocol_core::ledger::Audit::new(supply, register_total);
            Ok(json!({
                "height": height,
                "genesis_deposited": supply.genesis_deposited.to_string(),
                "genesis_staked": supply.genesis_staked.to_string(),
                "faucet_minted": supply.faucet_minted.to_string(),
                "withdraw_deposited": supply.withdraw_deposited.to_string(),
                "fees_paid": supply.fees_paid.to_string(),
                "burned": supply.burned.to_string(),
                // Block aggregation (spec §5.3): the subsidy and its schedule index, and the
                // aggregator register's two bond counters — reported separately from
                // `faucet_minted`, so an auditor checks the schedule against `sealed_blocks`
                // directly.
                "subsidised": supply.subsidised.to_string(),
                "sealed_blocks": supply.sealed_blocks.to_string(),
                "aggregator_bonds": supply.aggregator_bonds.to_string(),
                "slashed": supply.slashed.to_string(),
                "pool_value": audit.pool_value.to_string(),
                "register_total": audit.register_total.to_string(),
                "total_supply": audit.total_supply().to_string(),
                "invariant_holds": audit.invariant_holds(),
            }))
        }
        // Emission (spec §5.1): inflation is a fixed zero — nothing here ever mints outside a
        // genesis allocation, the testnet faucet, or the bounded aggregation subsidy below — so
        // the field is constant rather than computed. `subsidy` is `null` without an aggregation
        // section (there is then no schedule to report), otherwise the current per-block amount
        // and the halving math `sealed_blocks` indexes into. Two meta reads, never a
        // `load_ledger` (spec §1: no second way to trigger a commitment-tree rebuild): the config
        // is genesis truth and never changes after `init_genesis`, so a commit landing between
        // the two reads can only move `sealed_blocks`, and the answer is then as of that commit.
        "rand_getEmission" => {
            let faucet = st.status.read().unwrap_or_else(|e| e.into_inner()).faucet;
            let storage = st.storage.clone();
            let (cfg, sealed) =
                blocking(move || Ok((storage.aggregation_config()?, storage.supply()?.sealed_blocks))).await?;
            let subsidy = cfg.map(|cfg| {
                let current = randprotocol_core::gas::subsidy(sealed, &cfg);
                // Saturating: past the last representable halving the multiply would overflow
                // (a debug-build panic on the RPC thread); `u64::MAX` reads as "never". Genesis
                // validation refuses a zero `halving_blocks`, which `subsidy` divides by too.
                let next_halving_at =
                    (sealed / cfg.halving_blocks).saturating_add(1).saturating_mul(cfg.halving_blocks);
                json!({
                    "current": current.to_string(),
                    "base": cfg.subsidy_base.to_string(),
                    "halving_blocks": cfg.halving_blocks,
                    "sealed_blocks": sealed,
                    "next_halving_at": next_halving_at,
                })
            });
            Ok(json!({ "inflation": "0", "subsidy": subsidy, "faucet": faucet }))
        }
        other => Err(RpcError { code: -32601, message: format!("unknown method {other}") }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fixtures::{self, alloc_note, bundle_fee, bundle_tx, genesis_with, key, make_block, make_block_unchecked};
    use std::collections::BTreeMap;
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::genesis::GenesisState;
    use randprotocol_core::notes::DEPTH;
    use randprotocol_core::Word8;

    /// An `RpcState` over a fresh database holding `gs`.
    ///
    /// Most methods answer straight from storage, but the register and epoch views ask the node
    /// loop where the chain is in its epoch schedule — so a stand-in loop answers that one
    /// command from the genesis state and ignores the rest. It outlives the test by holding the
    /// receiver; without it those methods would only ever report "node loop closed".
    fn state_for(gs: &GenesisState) -> (tempfile::TempDir, RpcState) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::storage::Storage::open(dir.path()).unwrap());
        storage.init_genesis(gs).unwrap();
        (dir, state_over(storage, gs))
    }

    /// The same state over a database a storage fixture already opened and initialised.
    fn state_over(storage: Arc<crate::storage::Storage>, gs: &GenesisState) -> RpcState {
        let (tx, mut rx) = mpsc::channel(4);
        let info = EpochInfo {
            epoch: 0,
            epoch_blocks: gs.epoch_blocks,
            current: gs.validators.iter().map(|v| v.address()).collect(),
            next: gs.ledger.derive_next_set().iter().map(|v| v.address()).collect(),
        };
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                match cmd {
                    NodeCommand::Epoch { reply } => {
                        let _ = reply.send(info.clone());
                    }
                    NodeCommand::MempoolInfo { reply } => {
                        let _ = reply.send(crate::mempool::MempoolInfo {
                            count: 2,
                            bytes: 100,
                            oldest_ms: Some(5),
                            max_count: 10_000,
                        });
                    }
                    NodeCommand::TxStatus { hashes, reply } => {
                        let out = hashes
                            .iter()
                            .map(|h| {
                                if *h == Hash([0xAA; 32]) {
                                    PoolStatus::Pending
                                } else if *h == Hash([0xBB; 32]) {
                                    PoolStatus::Rejected("bad mint signature".into())
                                } else {
                                    PoolStatus::Unknown
                                }
                            })
                            .collect();
                        let _ = reply.send(out);
                    }
                    NodeCommand::Finality { hash, reply } => {
                        let f = if hash == Hash([0xAA; 32]) {
                            Finality::Certified { height: 9, hash, qc_view: 12 }
                        } else if hash == Hash([0xBB; 32]) {
                            Finality::Proposed { height: 9, hash }
                        } else {
                            Finality::Unknown
                        };
                        let _ = reply.send(f);
                    }
                    NodeCommand::Proposer { views, reply } => {
                        let _ = reply.send((3, views.iter().map(|v| randprotocol_core::Address([*v as u8; 32])).collect()));
                    }
                    _ => {}
                }
            }
        });
        RpcState {
            storage,
            status: Arc::new(RwLock::new(NodeStatus::default())),
            node: tx,
            chain_id: gs.chain_id,
            max_program_words: gs.ledger.max_program_words(),
            executor: Arc::new(StubExecutor),
            heads: tokio::sync::broadcast::channel(HEAD_CHANNEL).0,
            commits: tokio::sync::broadcast::channel(HEAD_CHANNEL).0,
            refusals: tokio::sync::broadcast::channel(HEAD_CHANNEL).0,
            ws_conns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            viewing: Arc::new(RwLock::new(crate::viewing::Registry::default())),
        }
    }

    async fn call(st: &RpcState, method: &str, params: Value) -> Result<Value, RpcError> {
        dispatch(st, &Request { jsonrpc: None, method: method.into(), params, id: Some(Value::Null) }).await
    }

    async fn ok(st: &RpcState, method: &str, params: Value) -> Value {
        call(st, method, params).await.unwrap_or_else(|e| panic!("{method}: {}", e.message))
    }

    fn nf(n: u8) -> Word8 {
        [n as u32 + 1000; 8]
    }

    fn cm(n: u8) -> Word8 {
        [n as u32 + 2000; 8]
    }

    /// Genesis with two deposit notes, plus one committed block spending two notes and creating
    /// two more: four leaves, two nullifiers, an anchor at height 1.
    /// A gated chain with a committed aggregate (block aggregation, spec §8's fixture): block 1
    /// carries the covered bundle (a real fixture proof, excess 60 over the floor) and the
    /// aggregator's registration; block 2 carries the aggregate covering it. Built exactly as
    /// the seal tests' chain — the applied sets use the stub twins where the stored bytes are a
    /// real proof.
    fn gated_chain() -> (tempfile::TempDir, RpcState, GenesisState, Transaction, Transaction) {
        use randprotocol_core::ledger::aggregation::{AdmittedShape, AggregationConfig};
        use randprotocol_core::types::actions::{aggregate_signing_hash, aggregator_register_message, AggregatorRegistration};
        use randprotocol_core::types::{CoveredBundle, DeclaredShape, FriProfile};

        let proof = crate::agg_executor::fixture_proof(0);
        let shape = DeclaredShape {
            profile: FriProfile::Test,
            tier: proof.tier.0 as u8,
            program_log_height: proof.program_log_height,
            input_log_height: proof.input_log_height,
            keccak_log_height: proof.keccak_log_height,
            sha256_log_height: proof.sha256_log_height,
            public_log_height: proof.public_log_height,
            mem_log_height: proof.mem_log_height,
        };
        let hc_words: [u32; 8] = std::array::from_fn(|k| {
            u32::try_from(proof.public_values[randprotocol_core::types::pv::HC0 + k]).unwrap()
        });
        let hc = Hash(randprotocol_core::notes::word8_to_bytes(&hc_words));
        let bond = 100 * randprotocol_core::UNITS_PER_RAND;
        let mut gs = genesis_with(7, vec![alloc_note(20, 200 * randprotocol_core::UNITS_PER_RAND)]);
        gs.ledger.set_aggregation(Some(AggregationConfig {
            bond,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![AdmittedShape { shape, hc, aggregate_program_digest: [1; 4] }],
        }));
        let (dir, st) = state_for(&gs);

        let fee = bundle_fee() + 60;
        let mut covered_tx = bundle_tx(&gs.ledger, [nf(1), nf(2)], [cm(1), cm(2)], fee);
        covered_tx.bundle.as_mut().unwrap().proof = proof.to_bytes();
        let stub_twin = bundle_tx(&gs.ledger, [nf(1), nf(2)], [cm(1), cm(2)], fee);
        let kp = key(7);
        let payout = ShieldedAddress { pk: [7; 8], kem_ek: vec![8; randprotocol_core::notes::KEM_EK_BYTES] };
        let registration = AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(aggregator_register_message(7, &payout).as_bytes()),
        };
        let mut b = randprotocol_core::notes::Bundle {
            anchor: gs.ledger.root(),
            nullifiers: [nf(3), nf(4)],
            commitments: [cm(3), cm(4)],
            fee: bundle_fee(),
            burn: bond,
            asset: 0,
            time: 1,
            envelopes: [fixtures::env(1), fixtures::env(2)],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&fixtures::HC, &d);
        let register = Transaction::shielded(7, b, Action::RegisterAggregator { registration });
        let mut l1 = gs.ledger.clone();
        l1.set_height(1);
        l1.set_timestamp_ms(1);
        l1.apply_transactions(&[stub_twin.clone(), register.clone()], &key(1).address(), &StubExecutor).unwrap();
        l1.record_anchor(1);
        // The ledger applied the stub twin, so its coverable entry is keyed by the twin's hash;
        // the stored bundle (and the aggregate's cover) is the real-proof one. Re-key it.
        let mut fees = l1.unsealed_fees().clone();
        let entry = fees.remove(&stub_twin.hash()).expect("the twin was bucketed");
        fees.insert(covered_tx.hash(), entry);
        l1.set_unsealed_fees(fees);
        let b1 = make_block_unchecked(&gs.block, &l1, vec![covered_tx.clone(), register], &key(1));
        st.storage.commit(std::slice::from_ref(&b1), &l1, &[], &StubExecutor).unwrap();

        let r = [9u32; 8];
        let covers = vec![covered_tx.hash()];
        let proof_bytes = b"ok".to_vec();
        let signature = kp.sign(aggregate_signing_hash(7, 0, 2, &r, &covers, &Hash::digest(&proof_bytes)).as_bytes());
        let aggregate = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::Aggregate {
                covers,
                proof: proof_bytes,
                aggregator: kp.public_key().address(),
                nonce: 0,
                time: 2,
                r,
                envelope: fixtures::env(9),
                signature,
            },
        };
        let record = st.storage.covered_record(&covered_tx.hash(), FriProfile::Test).unwrap().unwrap();
        let sidecar: BTreeMap<usize, Vec<CoveredBundle>> = [(0usize, vec![record])].into_iter().collect();
        let mut l2 = l1.clone();
        l2.set_height(2);
        l2.set_timestamp_ms(2);
        l2.apply_transactions_with_covered(&[aggregate.clone()], &key(1).address(), &sidecar, &StubExecutor).unwrap();
        l2.record_anchor(2);
        let b2 = make_block_unchecked(&b1.block, &l2, vec![aggregate.clone()], &key(1));
        st.storage.commit(std::slice::from_ref(&b2), &l2, &[], &StubExecutor).unwrap();
        (dir, st, gs, covered_tx, aggregate)
    }

    fn chain() -> (tempfile::TempDir, RpcState, GenesisState) {
        let gs = genesis_with(1, vec![alloc_note(20, 1_000), alloc_note(21, 2_000)]);
        let (dir, st) = state_for(&gs);
        let mut ledger = gs.ledger.clone();
        let tx = bundle_tx(&ledger, [nf(1), nf(2)], [cm(1), cm(2)], bundle_fee());
        let b1 = make_block(&gs.block, &mut ledger, vec![tx], &key(1));
        st.storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        (dir, st, gs)
    }

    /// The aggregation surface (spec §8): the block's `sealed` flag and the per-bundle
    /// `sealed_by`, `rand_getAggregate`'s public fields, the register, the work list, and the
    /// status section — all against a committed aggregate.
    #[tokio::test]
    async fn the_aggregation_rpc_surface_reports_seals_payments_the_register_and_the_work_list() {
        let (_d, st, _gs, covered_tx, aggregate) = gated_chain();
        let (h_seal, _) = st.storage.tx_location(&aggregate.hash()).unwrap().unwrap();

        // Blocks: the sealed flag and the per-bundle mark.
        let b1 = ok(&st, "rand_getBlockByHeight", json!([1])).await;
        assert_eq!(b1["sealed"], false, "block 1's covered bundle is the only one sealed yet");
        let txs = b1["transactions"].as_array().unwrap();
        assert_eq!(txs[0]["sealed_by"], aggregate.hash().to_hex(), "the covered bundle names its aggregate");
        assert_eq!(txs[1]["sealed_by"], Value::Null, "the register's bundle is uncovered");
        let b2 = ok(&st, "rand_getBlockByHeight", json!([2])).await;
        assert_eq!(b2["transactions"].as_array().unwrap()[0]["action"]["kind"], "aggregate");

        // `rand_getAggregate`: the public fields of the sealing aggregate (spec §8).
        let v = ok(&st, "rand_getAggregate", json!([aggregate.hash().to_hex()])).await;
        assert_eq!(v["covers"], json!([covered_tx.hash().to_hex()]));
        assert_eq!(v["aggregator"], aggregate_agg_addr(&st));
        assert_eq!(v["subsidy"], "100000000000");
        assert_eq!(v["proving_share"], "60", "the covered bundle's excess over the floor");
        assert_eq!(v["n"], 0, "the first sealed block of the schedule");
        assert_eq!(v["height"], h_seal);
        // A transaction that is not an aggregate, and one that does not exist.
        assert_eq!(ok(&st, "rand_getAggregate", json!([covered_tx.hash().to_hex()])).await, Value::Null);
        assert_eq!(ok(&st, "rand_getAggregate", json!([Hash::ZERO.to_hex()])).await, Value::Null);

        // The register, public by design (spec §2): one row, the fields an operator watches.
        let v = ok(&st, "rand_getAggregators", json!([])).await;
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["address"], rows[0]["address"].as_str().unwrap().to_string());
        assert_eq!(rows[0]["bond"], "100000000000");
        assert_eq!(rows[0]["nonce"], 1, "the aggregate moved it");
        assert_eq!(rows[0]["unbonding"], Value::Null);

        // The work list (R8): after the seal the covered bundle is gone from it, and nothing
        // bundle-less ever appears.
        let v = ok(&st, "rand_getUnsealed", json!([0, 10])).await;
        let bundles = v["bundles"].as_array().unwrap();
        assert!(bundles.iter().all(|b| b["hash"] != covered_tx.hash().to_hex()), "a sealed bundle is not work");
        assert!(bundles.iter().all(|b| b["hash"] != aggregate.hash().to_hex()), "an aggregate is not a bundle");
        // But before the seal it was exactly the work an aggregator wanted: hash, height, excess.
        let register_tx = &st.storage.block_by_height(1).unwrap().unwrap().transactions[1];
        assert!(
            bundles.iter().any(|b| b["hash"] == register_tx.hash().to_hex() && b["height"] == 1 && b["excess"] == "0"),
            "the register's bundle (no excess) is still coverable: {v}"
        );

        // The status section: registered aggregators, the unsealed count, the verify queue.
        // `publish_status` writes these per commit on the loop, which this harness does not
        // run — set them the way the loop would (the shape is what is asserted here).
        {
            let mut s = st.status.write().unwrap();
            s.aggregation.registered = st.storage.aggregators().unwrap().len();
            s.aggregation.unsealed = crate::rpc::unsealed_bundles(&st.storage, 2, 256, 0, usize::MAX).0.len();
            s.aggregation.verify_queue = 0;
        }
        let v = ok(&st, "rand_status", json!([])).await;
        assert_eq!(v["aggregation"]["registered"], 1);
        assert!(v["aggregation"]["unsealed"].as_u64().unwrap() >= 1, "{v}");
        assert_eq!(v["aggregation"]["verify_queue"], 0);
    }

    fn aggregate_agg_addr(_st: &RpcState) -> String {
        key(7).public_key().address().to_base58()
    }

    /// `tx_json`'s five renderings (spec §8): every aggregation action is named with its public
    /// fields, nothing more.
    #[test]
    fn tx_json_renders_the_five_aggregation_actions() {
        use randprotocol_core::types::actions::{AggregatorRegistration, SignedAggregateHeader};
        let kp = key(7);
        let addr = kp.public_key().address();
        let payout = ShieldedAddress { pk: [7; 8], kem_ek: vec![8; 32] };
        let sig = randprotocol_core::Signature::empty();
        let envelope = Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] };
        let tx = |action| Transaction {
            chain_id: 7,
            bundle: None,
            action,
        };
        let registration = AggregatorRegistration { public_key: kp.public_key().clone(), payout: payout.clone(), signature: sig.clone() };
        let header = |covers: Vec<Hash>| SignedAggregateHeader {
            aggregator: addr,
            nonce: 3,
            time: 9,
            r: [1; 8],
            covers,
            proof_hash: Hash::digest(b"p"),
            signature: sig.clone(),
        };
        let cases: Vec<(Transaction, &str, Value)> = vec![
            (
                tx(Action::RegisterAggregator { registration }),
                "register_aggregator",
                json!({ "aggregator": addr.to_base58() }),
            ),
            (
                tx(Action::UnbondAggregator { aggregator: addr, nonce: 1, signature: sig.clone() }),
                "unbond_aggregator",
                json!({ "aggregator": addr.to_base58(), "nonce": 1 }),
            ),
            (
                tx(Action::WithdrawAggregator {
                    aggregator: addr,
                    nonce: 2,
                    time: 9,
                    r: [3; 8],
                    envelope: envelope.clone(),
                    signature: sig.clone(),
                }),
                "withdraw_aggregator",
                json!({ "aggregator": addr.to_base58(), "nonce": 2, "time": 9 }),
            ),
            (
                tx(Action::SlashAggregator {
                    a: Box::new(header(vec![Hash::digest(b"x")])),
                    b: Box::new(header(vec![Hash::digest(b"y")])),
                }),
                "slash_aggregator",
                json!({ "aggregator": addr.to_base58(), "nonce": 3, "headers": [Hash::digest(b"p").to_hex(), Hash::digest(b"p").to_hex()] }),
            ),
            (
                tx(Action::Aggregate {
                    covers: vec![Hash::digest(b"one"), Hash::digest(b"two")],
                    proof: vec![9; 64],
                    aggregator: addr,
                    nonce: 3,
                    time: 9,
                    r: [4; 8],
                    envelope,
                    signature: sig,
                }),
                "aggregate",
                json!({
                    "covers": 2,
                    "aggregator": addr.to_base58(),
                    "nonce": 3,
                    "time": 9,
                    "proof_len": 64,
                }),
            ),
        ];
        for (t, kind, want) in cases {
            let j = tx_json(&t, None, &StubExecutor);
            assert_eq!(j["action"]["kind"], kind, "{t:?}");
            for (k, v) in want.as_object().unwrap() {
                assert_eq!(&j["action"][k], v, "{kind}.{k}: {j}");
            }
        }
    }

    #[tokio::test]
    async fn get_commitments_pages_in_order() {
        let (_d, st, _gs) = chain();
        let all = ok(&st, "rand_getCommitments", json!([0, 100])).await;
        let all = all.as_array().unwrap();
        assert_eq!(all.len(), 4);
        // Indexes are dense and ascending; the genesis notes are at height 0 and the bundle's
        // outputs at height 1.
        for (i, row) in all.iter().enumerate() {
            assert_eq!(row["index"], i as u64);
        }
        assert_eq!(all[0]["height"], 0);
        assert_eq!(all[3]["height"], 1);
        assert_eq!(all[2]["cm"], word8_to_hex(&cm(1)));
        assert_eq!(all[3]["cm"], word8_to_hex(&cm(2)));
        // An envelope comes back in its four hex parts.
        assert!(all[2]["envelope"]["kem_ct"].is_string());

        // Paging from the middle returns the tail, in the same order.
        let page = ok(&st, "rand_getCommitments", json!([2, 100])).await;
        assert_eq!(page.as_array().unwrap(), &all[2..]);
        // A limit smaller than the tail truncates it, and one past the end is empty.
        assert_eq!(ok(&st, "rand_getCommitments", json!([0, 2])).await.as_array().unwrap().len(), 2);
        assert_eq!(ok(&st, "rand_getCommitments", json!([9, 100])).await, json!([]));
        // An oversized limit is clamped, not refused.
        assert_eq!(ok(&st, "rand_getCommitments", json!([0, 10_000])).await.as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn get_nullifiers_and_tree_info_track_the_chain() {
        let (_d, st, _gs) = chain();
        let nfs = ok(&st, "rand_getNullifiers", json!([0, 100])).await;
        let nfs = nfs.as_array().unwrap();
        assert_eq!(nfs.len(), 2);
        for row in nfs {
            assert_eq!(row["height"], 1);
        }
        let seen: Vec<&str> = nfs.iter().map(|r| r["nullifier"].as_str().unwrap()).collect();
        assert!(seen.contains(&word8_to_hex(&nf(1)).as_str()));
        assert!(seen.contains(&word8_to_hex(&nf(2)).as_str()));
        // Asking from a later height skips them.
        assert_eq!(ok(&st, "rand_getNullifiers", json!([2, 100])).await, json!([]));

        let info = ok(&st, "rand_getTreeInfo", json!([])).await;
        assert_eq!(info["next_index"], 4);
        assert_eq!(info["nullifiers"], 2);
        assert_eq!(info["root"], word8_to_hex(&st.storage.tree().unwrap().root()));
    }

    #[tokio::test]
    async fn get_anchor_serves_the_head_and_a_named_height() {
        let (_d, st, _gs) = chain();
        let head = ok(&st, "rand_getAnchor", json!([])).await;
        assert_eq!(head["height"], 1);
        assert_eq!(head["root"], word8_to_hex(&st.storage.tree().unwrap().root()));
        let genesis = ok(&st, "rand_getAnchor", json!([0])).await;
        assert_eq!(genesis["height"], 0);
        assert_ne!(genesis["root"], head["root"], "the block changed the tree");
        // A height the chain has not reached is not-found, not an internal error.
        assert_eq!(call(&st, "rand_getAnchor", json!([99])).await.unwrap_err().code, -32001);
    }

    #[tokio::test]
    async fn get_witness_matches_storage() {
        let (_d, st, _gs) = chain();
        for index in 0..4u64 {
            let v = ok(&st, "rand_getWitness", json!([index])).await;
            let (root, path) = st.storage.witness(index, &StubExecutor).unwrap().unwrap();
            assert_eq!(v["index"], index);
            assert_eq!(v["root"], word8_to_hex(&root));
            let got: Vec<String> = v["path"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().into()).collect();
            assert_eq!(got, path.iter().map(word8_to_hex).collect::<Vec<_>>());
            assert_eq!(got.len(), DEPTH);
        }
        // A leaf past the end is null, not an error.
        assert_eq!(ok(&st, "rand_getWitness", json!([4])).await, Value::Null);
    }

    #[tokio::test]
    async fn mint_rejects_a_bad_address() {
        let gs = fixtures::genesis(1);
        let (_d, st) = state_for(&gs);
        let err = call(&st, "rand_mint", json!(["not-an-address"])).await.unwrap_err();
        assert_eq!(err.code, -32602);
        // The message carries the address parser's own reason, not a generic one.
        let reason = ShieldedAddress::parse("not-an-address").unwrap_err().to_string();
        assert!(err.message.contains(&reason), "{} does not contain {reason}", err.message);
        // A well-formed address gets past parsing and dies at the (dropped) node channel.
        let good = randprotocol_zkvm::address::address_of(&randprotocol_zkvm::notes::SpendKey([7; 8]).viewing_key()).to_string();
        assert_eq!(call(&st, "rand_mint", json!([good])).await.unwrap_err().code, -32603);
    }

    /// An over-long address parameter is refused on its length, before it reaches the base58
    /// decoder — which is quadratic in its input and runs on a worker the node loop shares.
    #[tokio::test]
    async fn an_oversized_address_is_refused_before_it_is_parsed() {
        let gs = fixtures::genesis(1);
        let (_d, st) = state_for(&gs);
        let huge = format!("rand1{}", "1".repeat(3000));
        let err = call(&st, "rand_mint", json!([huge])).await.unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("3005 characters"), "{}", err.message);
        assert!(err.message.contains(&MAX_ADDRESS_CHARS.to_string()), "{}", err.message);
        // The cap is generous: a real address is well under it and still parses.
        let good = randprotocol_zkvm::address::address_of(&randprotocol_zkvm::notes::SpendKey([7; 8]).viewing_key()).to_string();
        assert!(good.len() < MAX_ADDRESS_CHARS, "a real address is {} characters", good.len());
        assert!(ShieldedAddress::parse(&good).is_ok());
    }

    #[tokio::test]
    async fn estimate_fee_answers_per_action_kind() {
        let gs = fixtures::genesis(1);
        let (_d, st) = state_for(&gs);
        let fee = |spec| ok(&st, "rand_estimateFee", json!([spec]));
        assert_eq!(fee(json!({"kind": "bundle"})).await, randprotocol_core::gas::BUNDLE_BASE.to_string());
        assert_eq!(
            fee(json!({"kind": "deploy", "words": 10})).await,
            randprotocol_core::gas::fee_floor(&Action::Deploy { base_pc: 0, words: vec![0; 10], public: vec![] }).to_string()
        );
        assert_eq!(
            fee(json!({"kind": "call", "tier": 12})).await,
            (randprotocol_core::gas::BUNDLE_BASE + randprotocol_core::gas::call_fee(12, 0)).to_string()
        );
        // An odd or out-of-range tier is a parameter error, never a truncated `as u8`.
        for bad in [11u64, 9, 22, 256] {
            let e = call(&st, "rand_estimateFee", json!([{"kind": "call", "tier": bad}])).await.unwrap_err();
            assert_eq!(e.code, -32602, "tier {bad}");
        }
        assert_eq!(call(&st, "rand_estimateFee", json!([{"kind": "transfer"}])).await.unwrap_err().code, -32602);
    }

    /// The deploy estimate refuses what the chain's own cap refuses — the genesis cap, not the
    /// constant — so a wallet asking first learns about an oversized program before it proves.
    #[tokio::test]
    async fn estimate_fee_for_a_deploy_reads_the_chains_program_cap() {
        let spec = |words: usize| json!([{"kind": "deploy", "words": words}]);
        let floor = |words: usize| {
            randprotocol_core::gas::fee_floor(&Action::Deploy { base_pc: 0, words: vec![0; words], public: vec![] }).to_string()
        };
        // A chain without `max_program_words`: today's 4 096.
        let gs = fixtures::genesis(1);
        let (_d, st) = state_for(&gs);
        assert_eq!(ok(&st, "rand_estimateFee", spec(4096)).await, floor(4096));
        let e = call(&st, "rand_estimateFee", spec(5000)).await.unwrap_err();
        assert_eq!(e.code, -32602);
        assert!(e.message.contains("4096"), "the error names the cap: {}", e.message);
        // A chain cut with the zkVM's limit.
        let mut gs = fixtures::genesis(1);
        gs.ledger.set_max_program_words(randprotocol_core::gas::MAX_PROGRAM_WORDS_LIMIT);
        let (_d, st) = state_for(&gs);
        assert_eq!(ok(&st, "rand_estimateFee", spec(5000)).await, floor(5000));
        assert_eq!(ok(&st, "rand_estimateFee", spec(65_535)).await, floor(65_535));
        let e = call(&st, "rand_estimateFee", spec(65_536)).await.unwrap_err();
        assert!(e.message.contains("65535"), "{}", e.message);
    }

    #[tokio::test]
    async fn send_transaction_rejects_a_stale_anchor() {
        let (_d, st, gs) = chain();
        // A bundle anchored to a root the ledger has never recorded. The node channel is dropped
        // in these tests, so drive the ledger's own admission check — the error the node relays.
        let ledger = gs.ledger.clone();
        let mut tx = bundle_tx(&ledger, [nf(5), nf(6)], [cm(5), cm(6)], bundle_fee());
        ledger.validate(&tx, &StubExecutor).expect("the honest bundle is admissible");
        tx.bundle.as_mut().unwrap().anchor = [0xdead; 8];
        let err = ledger.validate(&tx, &StubExecutor).unwrap_err();
        assert!(
            matches!(err, randprotocol_core::TxError::UnknownAnchor),
            "the anchor is checked before the digest it no longer matches: {err}"
        );
        assert!(err.to_string().contains("anchor"), "{err}");
        // The transport half: a malformed transaction is -32602 before the node is ever asked.
        assert_eq!(call(&st, "rand_sendTransaction", json!(["zz"])).await.unwrap_err().code, -32602);
        assert_eq!(call(&st, "rand_sendTransaction", json!(["00"])).await.unwrap_err().code, -32602);
    }

    #[tokio::test]
    async fn status_reports_note_and_nullifier_counts() {
        let (_d, st, _gs) = chain();
        {
            let mut s = st.status.write().unwrap();
            s.notes = st.storage.notes_count().unwrap();
            s.nullifiers = st.storage.nullifiers_count().unwrap();
            s.tree_root = word8_to_hex(&st.storage.tree().unwrap().root());
            s.hc_bundle = word8_to_hex(&st.storage.hc_bundle().unwrap());
        }
        let v = ok(&st, "rand_status", json!([])).await;
        assert_eq!(v["notes"], 4);
        assert_eq!(v["nullifiers"], 2);
        assert_eq!(v["tree_root"], word8_to_hex(&st.storage.tree().unwrap().root()));
        assert_eq!(v["hc_bundle"], word8_to_hex(&fixtures::HC));
        // Written by the node loop's publish_status, which these tests don't run: zero here, and
        // present — an operator must be able to see the node is holding keys at all.
        assert_eq!(v["viewing_keys"], 0);
    }

    #[tokio::test]
    async fn a_transaction_reads_back_without_naming_a_party() {
        let (_d, st, _gs) = chain();
        let b1 = st.storage.block_by_height(1).unwrap().unwrap();
        let tx = &b1.transactions[0];
        let v = ok(&st, "rand_getTransaction", json!([tx.hash().to_hex()])).await;
        assert_eq!(v["height"], 1);
        let j = &v["tx"];
        assert_eq!(j["action"]["kind"], "none");
        assert_eq!(j["bundle"]["fee"], bundle_fee());
        assert_eq!(j["bundle"]["nullifiers"][0], word8_to_hex(&nf(1)));
        // No sender, no recipient, no amount: the redacted shape is the point.
        let text = serde_json::to_string(j).unwrap();
        for banned in ["\"from\"", "\"to\"", "\"nonce\"", "\"sender\""] {
            assert!(!text.contains(banned), "{banned} leaked into tx_json: {text}");
        }
        assert_eq!(ok(&st, "rand_getTransaction", json!([Hash::ZERO.to_hex()])).await, Value::Null);
    }

    /// A deploy and two calls — one with a sealed input envelope, one without — committed at
    /// height 1 under one program. Shared by the call-envelope test and the receipts-paging
    /// tests below, which only need the program id and the two call hashes.
    async fn receipt_chain() -> (tempfile::TempDir, RpcState, ProgramId, Transaction, Transaction) {
        let gs = genesis_with(1, vec![alloc_note(20, 1_000), alloc_note(21, 2_000)]);
        let (dir, st) = state_for(&gs);
        let mut ledger = gs.ledger.clone();
        let mut probe = gs.ledger.clone();

        let words = vec![0x13u32; 4];
        let pid = randprotocol_core::program::program_id(0, &words);
        let deploy_fee = randprotocol_core::gas::fee_floor(&Action::Deploy { base_pc: 0, words: words.clone(), public: vec![] });
        let call_fee = randprotocol_core::gas::BUNDLE_BASE + randprotocol_core::gas::call_fee(12, 0);
        let with_bundle = |nfs: [Word8; 2], cms: [Word8; 2], fee: u64, action| {
            let b = bundle_tx(&ledger, nfs, cms, fee).bundle.expect("bundle_tx always carries one");
            Transaction::shielded(gs.chain_id, b, action)
        };
        let h_in: Word8 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let envelope = randprotocol_core::types::CallEnvelope {
            kem_ct: vec![0xab; 1088],
            to_sender: vec![0xcd; 60],
            to_auditor: vec![0xef; 60],
            body: vec![0x12; 96],
        };
        let deploy = with_bundle([nf(1), nf(2)], [cm(1), cm(2)], deploy_fee, Action::Deploy { base_pc: 0, words, public: vec![] });
        let sealed = with_bundle(
            [nf(3), nf(4)],
            [cm(3), cm(4)],
            call_fee,
            Action::Call {
                program: pid,
                proof: StubExecutor::make_proof_with_h_in(&pid, 12, [7; 8], h_in),
                input_envelope: Some(envelope.clone()),
            },
        );
        let bare = with_bundle(
            [nf(5), nf(6)],
            [cm(5), cm(6)],
            call_fee,
            Action::Call {
                program: pid,
                proof: StubExecutor::make_proof(&pid, 12, [8; 8]),
                input_envelope: None,
            },
        );
        let txs = vec![deploy.clone(), sealed.clone(), bare.clone()];
        let mut b1 = make_block(&gs.block, &mut ledger, txs, &key(1));
        // The receipts the ledger itself produced for that block — what a node commits.
        b1.receipts = probe.apply_block(&b1.block, &StubExecutor).unwrap();
        st.storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

        (dir, st, pid, sealed, bare)
    }

    /// The call-input envelope's read path (spec §6.1): a receipt carries the sealed transcript,
    /// and one method hands it back verbatim in hex so a viewing key — never the node — can open
    /// it. A call made without one, or a transaction that is not a call at all, is `null`.
    #[tokio::test]
    async fn get_call_envelope_serves_the_sealed_transcript_of_a_call() {
        let (_d, st, pid, sealed, bare) = receipt_chain().await;
        // The deploy `receipt_chain` committed alongside `sealed` and `bare`, at index 0 of the
        // same block — a transaction that is not a call at all.
        let deploy = st.storage.block_by_height(1).unwrap().unwrap().transactions[0].clone();
        let h_in: Word8 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let envelope = randprotocol_core::types::CallEnvelope {
            kem_ct: vec![0xab; 1088],
            to_sender: vec![0xcd; 60],
            to_auditor: vec![0xef; 60],
            body: vec![0x12; 96],
        };

        let v = ok(&st, "rand_getCallEnvelope", json!([sealed.hash().to_hex()])).await;
        assert_eq!(v["tx"], sealed.hash().to_hex());
        // The associated data the four parts below are bound to: without it nothing opens.
        assert_eq!(v["h_in"], word8_to_hex(&h_in));
        assert_eq!(v["kem_ct"], hex::encode(&envelope.kem_ct));
        assert_eq!(v["to_sender"], hex::encode(&envelope.to_sender));
        assert_eq!(v["to_auditor"], hex::encode(&envelope.to_auditor));
        assert_eq!(v["body"], hex::encode(&envelope.body));

        // The receipt itself still reports only the public outcome; the transcript is a
        // separate, explicit request.
        let r = ok(&st, "rand_getReceipt", json!([sealed.hash().to_hex()])).await;
        assert_eq!((&r["program"], &r["tier"], &r["height"]), (&json!(pid.to_hex()), &json!(12), &json!(1)));
        assert_eq!(r["h_in"], word8_to_hex(&h_in), "the receipt carries H_IN whether or not there is an envelope");
        assert!(r["kem_ct"].is_null(), "the transcript itself is a separate request");
        let bare_receipt = ok(&st, "rand_getReceipt", json!([bare.hash().to_hex()])).await;
        assert_eq!(bare_receipt["h_in"], word8_to_hex(&[0; 8]));

        // A call that forfeited disclosure, a transaction that is not a call, and a hash the
        // chain has never seen are all null rather than errors.
        for h in [bare.hash(), deploy.hash(), Hash::ZERO] {
            assert_eq!(ok(&st, "rand_getCallEnvelope", json!([h.to_hex()])).await, Value::Null, "{h}");
        }
    }

    /// A program's receipts, height then index, paged the way `rand_getCompactBlocks` pages
    /// blocks: an unbounded or oversized `limit` is clamped, an empty range is an empty page,
    /// `next_height` is the first height the page did not serve, and a page never splits a
    /// height — a `limit` that lands inside one still returns that whole height's receipts.
    #[tokio::test]
    async fn get_receipts_pages_one_program_by_height_and_index() {
        let (_d, st, pid, sealed, bare) = receipt_chain().await;
        let v = ok(&st, "rand_getReceipts", json!([pid.to_hex(), 0, 10])).await;
        let txs: Vec<&str> = v["receipts"].as_array().unwrap().iter().map(|r| r["tx"].as_str().unwrap()).collect();
        assert_eq!(txs, vec![sealed.hash().to_hex(), bare.hash().to_hex()]);
        assert!(v["next_height"].is_null());
        assert_eq!(v["receipts"][0], ok(&st, "rand_getReceipt", json!([sealed.hash().to_hex()])).await, "one object shape");
        // `limit` 1 lands inside height 1's pair of receipts: the page still holds both rather
        // than splitting the height, and there is nothing above it to resume from.
        let v = ok(&st, "rand_getReceipts", json!([pid.to_hex(), 0, 10, 1])).await;
        assert_eq!(v["receipts"].as_array().unwrap().len(), 2);
        assert!(v["next_height"].is_null());
        let v = ok(&st, "rand_getReceipts", json!([pid.to_hex(), 2, 10])).await;
        assert!(v["receipts"].as_array().unwrap().is_empty());
        let e = call(&st, "rand_getReceipts", json!([pid.to_hex(), 5, 2])).await.err().unwrap();
        assert_eq!(e.code, -32602);
        let v = ok(&st, "rand_getReceipts", json!([pid.to_hex(), 0, 10, 100_000])).await;
        assert_eq!(v["receipts"].as_array().unwrap().len(), 2, "the limit is capped, not refused");
    }

    /// `rand_getWitness`, folded over several leaves at once: one root, one path per index, and
    /// an index past the tree is `null` rather than an error.
    #[tokio::test]
    async fn get_witnesses_folds_many_paths_from_one_tree() {
        let gs = genesis_with(1, vec![alloc_note(20, 1_000), alloc_note(21, 2_000)]);
        let (_d, st) = state_for(&gs);
        let v = ok(&st, "rand_getWitnesses", json!([[0, 1, 7]])).await;
        let one = ok(&st, "rand_getWitness", json!([1])).await;
        assert_eq!(v["root"], one["root"]);
        assert_eq!(v["witnesses"][1]["path"], one["path"]);
        assert_eq!(v["witnesses"][1]["index"], 1);
        assert!(v["witnesses"][2]["path"].is_null(), "past the tree is null, not an error");
        let too_many: Vec<u64> = (0..33).collect();
        let e = call(&st, "rand_getWitnesses", json!([too_many])).await.err().unwrap();
        assert_eq!(e.code, -32602);
    }

    /// Phase S2: the register, not the genesis set. A validator that has bonded in but whose
    /// epoch has not arrived is listed with everything the register holds about it and
    /// `active: false` — which is the whole reason the row carries the flag.
    #[tokio::test]
    async fn validators_report_the_whole_register_and_who_is_active() {
        let (_d, st, _gs) = chain();
        let newcomer = key(9);
        let payout = ShieldedAddress { pk: [3; 8], kem_ek: vec![4; randprotocol_core::notes::KEM_EK_BYTES] };
        st.storage
            .overwrite_validator_for_testing(
                &newcomer.address(),
                &randprotocol_core::ledger::ValidatorEntry {
                    public_key: newcomer.public_key().clone(),
                    stake: 700,
                    pending: vec![(4, 250)],
                    rewards: 11,
                    payout: payout.clone(),
                    nonce: 3,
                },
            )
            .unwrap();

        let v = ok(&st, "rand_getValidators", json!([])).await;
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 2, "every registered validator, in address order");
        let row = |addr: randprotocol_core::Address| {
            rows.iter().find(|r| r["address"] == addr.to_base58()).expect("listed").clone()
        };

        let genesis = row(key(1).address());
        // Every amount is a decimal string: JSON numbers are not safe integers past 2^53, and a
        // stake is 10^9 units per RAND.
        assert_eq!(genesis["stake"], Value::String(randprotocol_core::ledger::staking::MIN_STAKE.to_string()));
        assert_eq!(genesis["rewards"], Value::String(bundle_fee().to_string()), "the block's fee");
        assert_eq!(genesis["pending"], json!([]));
        assert_eq!(genesis["nonce"], 0);
        assert_eq!(genesis["active"], true);

        let new = row(newcomer.address());
        assert_eq!(new["stake"], Value::String("700".into()));
        assert_eq!(new["pending"], json!([{ "release_epoch": 4, "amount": "250" }]));
        assert_eq!(new["rewards"], Value::String("11".into()));
        assert_eq!(new["payout"], Value::String(payout.to_string()));
        assert_eq!(new["nonce"], 3);
        assert_eq!(new["active"], false, "in the register, not in the current set");
    }

    #[tokio::test]
    async fn get_epoch_reports_the_schedule_and_the_set_the_register_would_derive_next() {
        let (_d, st, gs) = chain();
        let v = ok(&st, "rand_getEpoch", json!([])).await;
        assert_eq!(v["epoch"], 0);
        assert_eq!(v["epoch_blocks"], gs.epoch_blocks);
        // The only validator meets the minimum, so it is what the next epoch would run with.
        assert_eq!(v["next_set"], json!([key(1).address().to_base58()]));
    }

    #[tokio::test]
    async fn get_mempool_info_reports_the_node_loops_answer() {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let (_d, st) = state_for(&gs);
        let v = ok(&st, "rand_getMempoolInfo", json!([])).await;
        assert_eq!(v, json!({ "count": 2, "bytes": 100, "oldest_ms": 5, "max_count": 10_000 }));
    }

    /// Four hashes, four outcomes: committed (found in storage), pending and rejected (the
    /// node loop's stub answers, keyed by the `0xAA`/`0xBB` fixture bytes), and unknown (neither).
    #[tokio::test]
    async fn get_transaction_status_distinguishes_committed_pending_rejected_unknown() {
        let (_d, storage, gs, blocks) = fixtures::chain_fixture(1);
        let st = state_over(Arc::new(storage), &gs);
        let committed = blocks[0].block.transactions[0].hash();
        let v = ok(
            &st,
            "rand_getTransactionStatus",
            json!([[committed.to_hex(), Hash([0xAA; 32]).to_hex(), Hash([0xBB; 32]).to_hex(), Hash([0xCC; 32]).to_hex()]]),
        )
        .await;
        assert_eq!(v[0]["status"], "committed");
        assert_eq!(v[0]["height"], 1);
        assert_eq!(v[0]["index"], 0);
        assert_eq!(v[1]["status"], "pending");
        assert_eq!(v[2]["status"], "rejected");
        assert_eq!(v[2]["reason"], "bad mint signature");
        assert_eq!(v[3]["status"], "unknown");
        assert_eq!(v[3]["hash"], Hash([0xCC; 32]).to_hex());
        let many: Vec<String> = (0..65).map(|i| Hash([i as u8; 32]).to_hex()).collect();
        assert_eq!(call(&st, "rand_getTransactionStatus", json!([many])).await.err().unwrap().code, -32602);
    }

    /// A height or a hash, each answered by storage when committed; a hash storage has never
    /// heard of falls through to the node loop's tree state (the `0xAA`/`0xBB`/else stub).
    #[tokio::test]
    async fn get_finality_by_height_hash_and_tree_state() {
        let (_d, storage, gs, blocks) = fixtures::chain_fixture(2);
        let st = state_over(Arc::new(storage), &gs);
        let v = ok(&st, "rand_getFinality", json!([1])).await;
        assert_eq!(v["status"], "committed");
        assert_eq!(v["hash"], blocks[0].block.hash().to_hex());
        let v = ok(&st, "rand_getFinality", json!([blocks[1].block.hash().to_hex()])).await;
        assert_eq!(v["status"], "committed");
        assert_eq!(v["height"], 2);
        let v = ok(&st, "rand_getFinality", json!([Hash([0xAA; 32]).to_hex()])).await;
        assert_eq!(v["status"], "certified");
        assert_eq!(v["qc_view"], 12);
        let v = ok(&st, "rand_getFinality", json!([Hash([0xBB; 32]).to_hex()])).await;
        assert_eq!(v["status"], "proposed");
        assert_eq!(ok(&st, "rand_getFinality", json!([99])).await["status"], "unknown");
        assert_eq!(ok(&st, "rand_getFinality", json!([Hash([0xCC; 32]).to_hex()])).await["status"], "unknown");
    }

    /// The race M3 names: storage misses, the block commits, and the node loop — which prunes a
    /// committed block from its tree — answers `unknown`. The dispatcher's second storage look
    /// must turn that into `committed`. The stand-in loop commits the block itself, between
    /// the dispatcher's first look and its reply, to place the commit exactly there.
    #[tokio::test]
    async fn get_finality_by_hash_reads_committed_when_the_block_commits_mid_lookup() {
        let (_d, storage, gs, blocks) = fixtures::chain_fixture(2);
        let storage = Arc::new(storage);
        let mut ledger = storage.load_ledger(&StubExecutor).unwrap();
        ledger.set_height(3);
        let cb3 = make_block(&blocks[1].block, &mut ledger, vec![], &key(1));
        let hash = cb3.block.hash();
        let mut st = state_over(storage.clone(), &gs);
        let (tx, mut rx) = mpsc::channel(4);
        st.node = tx;
        tokio::spawn(async move {
            let mut pending = Some(cb3);
            while let Some(cmd) = rx.recv().await {
                if let NodeCommand::Finality { reply, .. } = cmd {
                    if let Some(cb) = pending.take() {
                        storage.commit(std::slice::from_ref(&cb), &ledger, &[], &StubExecutor).unwrap();
                    }
                    let _ = reply.send(Finality::Unknown);
                }
            }
        });
        let v = ok(&st, "rand_getFinality", json!([hash.to_hex()])).await;
        assert_eq!(v, json!({ "status": "committed", "height": 3, "hash": hash.to_hex() }));
        // A hash nobody has stays `unknown` through the second look.
        assert_eq!(ok(&st, "rand_getFinality", json!([Hash([0xCC; 32]).to_hex()])).await["status"], "unknown");
    }

    /// A single view or an inclusive `[from, to]` range, under the current set (epoch 3, per the
    /// node loop's stub); a range wider than `MAX_PROPOSER_VIEWS` is refused, without ever
    /// allocating the range first — `[0, u64::MAX]` must answer promptly rather than try to
    /// build a 2^64-entry `Vec`.
    #[tokio::test]
    async fn get_proposer_maps_views_under_the_current_set() {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let (_d, st) = state_for(&gs);
        let v = ok(&st, "rand_getProposer", json!([5])).await;
        assert_eq!(v["epoch"], 3);
        assert_eq!(v["proposers"].as_array().unwrap().len(), 1);
        assert_eq!(v["proposers"][0]["view"], 5);
        assert_eq!(v["proposers"][0]["proposer"], randprotocol_core::Address([5u8; 32]).to_base58());
        let v = ok(&st, "rand_getProposer", json!([5, 8])).await;
        let proposers = v["proposers"].as_array().unwrap();
        assert_eq!(proposers.len(), 4);
        assert_eq!(proposers[3]["view"], 8);
        assert_eq!(proposers[3]["proposer"], randprotocol_core::Address([8u8; 32]).to_base58());
        assert_eq!(call(&st, "rand_getProposer", json!([1, 100])).await.err().unwrap().code, -32602);
        assert_eq!(call(&st, "rand_getProposer", json!([8, 5])).await.err().unwrap().code, -32602);
        // Overflow-safe count check: refused before any allocation, and no timeout/OOM.
        assert_eq!(call(&st, "rand_getProposer", json!([0, u64::MAX])).await.err().unwrap().code, -32602);
        let v = ok(&st, "rand_getProposer", json!([u64::MAX - 1, u64::MAX])).await;
        assert_eq!(v["proposers"].as_array().unwrap().len(), 2);
    }

    /// The supply audit: hidden note values, public boundary crossings. The one number that
    /// matters is `invariant_holds` — everything issued is either in the pool or in the register.
    #[tokio::test]
    async fn get_supply_accounts_for_everything_the_chain_issued() {
        // Enough in the pool to pay a fee out of: `chain()`'s two tiny alloc notes are smaller
        // than one bundle base, which is a fixture artefact rather than a chain that could exist.
        let gs = fixtures::genesis_with(1, vec![alloc_note(20, 5 * randprotocol_core::UNITS_PER_RAND)]);
        let (_d, st) = state_for(&gs);
        let mut ledger = gs.ledger.clone();
        let tx = bundle_tx(&ledger, [nf(1), nf(2)], [cm(1), cm(2)], bundle_fee());
        let b1 = make_block(&gs.block, &mut ledger, vec![tx], &key(1));
        st.storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

        let v = ok(&st, "rand_getSupply", json!([])).await;
        let stake = randprotocol_core::ledger::staking::MIN_STAKE;
        let alloc = 5 * randprotocol_core::UNITS_PER_RAND;
        assert_eq!(v["height"], 1);
        assert_eq!(v["genesis_deposited"], Value::String(alloc.to_string()));
        assert_eq!(v["genesis_staked"], Value::String(stake.to_string()));
        assert_eq!(v["faucet_minted"], Value::String("0".into()));
        assert_eq!(v["withdraw_deposited"], Value::String("0".into()));
        assert_eq!(v["burned"], Value::String("0".into()));
        // The block's one bundle moved its fee out of the pool and into the proposer's rewards.
        assert_eq!(v["fees_paid"], Value::String(bundle_fee().to_string()));
        assert_eq!(v["pool_value"], Value::String((alloc - bundle_fee()).to_string()));
        assert_eq!(v["register_total"], Value::String((stake + bundle_fee()).to_string()));
        assert_eq!(v["total_supply"], Value::String((alloc + stake).to_string()));
        assert_eq!(v["invariant_holds"], true);
    }

    /// The aggregation counters (spec §5.3): reported separately, and the invariant holds on a
    /// chain with a live registration — which needs the aggregator register's bonds counted in
    /// the register half, `Ledger::audit()`'s own rule.
    #[tokio::test]
    async fn get_supply_reports_the_aggregation_counters_on_a_gated_chain() {
        let bond = 100 * randprotocol_core::UNITS_PER_RAND;
        let mut gs = fixtures::genesis_with(1, vec![alloc_note(20, 200 * randprotocol_core::UNITS_PER_RAND)]);
        gs.ledger.set_aggregation(Some(randprotocol_core::ledger::aggregation::AggregationConfig {
            bond,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![],
        }));
        let (_d, st) = state_for(&gs);
        // Block 1: a registration, whose bundle burns exactly the bond.
        let mut ledger = gs.ledger.clone();
        let kp = key(7);
        let payout = randprotocol_core::notes::ShieldedAddress {
            pk: [7; 8],
            kem_ek: vec![8; randprotocol_core::notes::KEM_EK_BYTES],
        };
        let registration = randprotocol_core::types::actions::AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(
                randprotocol_core::types::actions::aggregator_register_message(1, &payout).as_bytes(),
            ),
        };
        let mut b = randprotocol_core::notes::Bundle {
            anchor: ledger.root(),
            nullifiers: [nf(1), nf(2)],
            commitments: [cm(1), cm(2)],
            fee: bundle_fee(),
            burn: bond,
            asset: 0,
            time: 1,
            envelopes: [fixtures::env(1), fixtures::env(2)],
            proof: vec![],
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&fixtures::HC, &d);
        let register = Transaction::shielded(1, b, randprotocol_core::types::Action::RegisterAggregator { registration });
        let b1 = make_block(&gs.block, &mut ledger, vec![register], &key(1));
        st.storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

        let v = ok(&st, "rand_getSupply", json!([])).await;
        assert_eq!(v["height"], 1);
        assert_eq!(v["subsidised"], Value::String("0".into()));
        assert_eq!(v["sealed_blocks"], Value::String("0".into()));
        assert_eq!(v["aggregator_bonds"], Value::String(bond.to_string()));
        assert_eq!(v["slashed"], Value::String("0".into()));
        assert_eq!(v["burned"], Value::String(bond.to_string()));
        assert_eq!(v["invariant_holds"], true, "{v}");
    }

    /// Emission (spec §5.1): inflation is a fixed zero (every RAND in existence traces to a
    /// genesis allocation or a bounded subsidy, never an unbounded mint), and the subsidy
    /// schedule is `null` on a chain with no aggregation section at all — `rand_getSupply`'s
    /// counters exist regardless, but the schedule they are measured against does not.
    #[tokio::test]
    async fn get_emission_is_zero_inflation_and_the_subsidy_schedule() {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let (_d, st) = state_for(&gs);
        let v = ok(&st, "rand_getEmission", json!([])).await;
        assert_eq!(v["inflation"], "0");
        assert!(v["subsidy"].is_null(), "no aggregation section on this genesis");
        assert_eq!(v["faucet"], false);

        let (_d2, st2, ..) = gated_chain();
        let v = ok(&st2, "rand_getEmission", json!([])).await;
        let s = &v["subsidy"];
        assert_eq!(s["base"], (100 * randprotocol_core::UNITS_PER_RAND).to_string());
        assert_eq!(s["halving_blocks"], 210_000);
        assert_eq!(s["sealed_blocks"], 1, "the fixture's one committed aggregate");
        assert_eq!(s["current"], (100 * randprotocol_core::UNITS_PER_RAND).to_string());
        assert_eq!(s["next_halving_at"], 210_000);
    }

    /// The emission arm reads the config and `sealed_blocks` from meta alone (no ledger
    /// rebuild), and its halving math saturates instead of overflowing at the top of `u64`.
    /// Needs no recursion fixture: the section is synthetic, since only its numbers are read.
    #[tokio::test]
    async fn get_emission_reads_meta_and_saturates_the_next_halving() {
        use randprotocol_core::ledger::aggregation::AggregationConfig;
        let mut gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let cfg = AggregationConfig {
            bond: 100,
            max_covers: 4,
            subsidy_base: 1_000,
            halving_blocks: 3,
            window: 16,
            admitted_shapes: vec![],
        };
        gs.ledger.set_aggregation(Some(cfg));
        let mut supply = gs.ledger.supply();
        supply.sealed_blocks = 7;
        gs.ledger.set_supply(supply);
        let (_d, st) = state_for(&gs);
        let s = &ok(&st, "rand_getEmission", json!([])).await["subsidy"];
        assert_eq!(s["sealed_blocks"], 7);
        assert_eq!(s["current"], "250", "two halvings in: 1000 >> 2");
        assert_eq!(s["next_halving_at"], 9);

        let mut top = gs.clone();
        let mut supply = top.ledger.supply();
        supply.sealed_blocks = u64::MAX;
        top.ledger.set_supply(supply);
        let (_d2, st2) = state_for(&top);
        let s = &ok(&st2, "rand_getEmission", json!([])).await["subsidy"];
        assert_eq!(s["current"], "0");
        assert_eq!(s["next_halving_at"], u64::MAX, "saturates rather than overflowing");
    }

    /// An explorer can name and summarise every new action. Amounts that are public by design
    /// (the staking register, a burn, a deposit) are shown; ciphertexts are lengths only. This
    /// case passes no registry, which is what a bridge-less chain has: an attestation's asset
    /// index and amount then come back `null` rather than guessed at.
    #[test]
    fn tx_json_renders_every_new_action_kind() {
        let gs = fixtures::genesis_with(1, vec![]);
        let b = |nfs: [Word8; 2], cms: [Word8; 2]| {
            let t = fixtures::bundle_tx(&gs.ledger, nfs, cms, bundle_fee());
            t.bundle.expect("bundle_tx always carries one")
        };
        let v = randprotocol_core::Address([3; 32]);
        let sig = randprotocol_core::Signature::empty();
        let recipient = ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] };
        let envelope = Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] };

        let j = |action| {
            let tx = Transaction::shielded(1, b([nf(1), nf(2)], [cm(1), cm(2)]), action);
            tx_json(&tx, None, &StubExecutor)["action"].clone()
        };

        let bond = j(Action::Bond { validator: v, amount: 500, registration: None });
        assert_eq!(bond["kind"], "bond");
        assert_eq!(bond["validator"], v.to_base58());
        assert_eq!(bond["amount"], 500);
        assert_eq!(bond["registered"], false);

        // The two validator-signed actions ride bundle-less, so they are rendered as they ride.
        let bundle_less =
            |action| tx_json(&Transaction { chain_id: 1, bundle: None, action }, None, &StubExecutor);
        let unbond = bundle_less(Action::Unbond { validator: v, amount: 7, nonce: 2, signature: sig.clone() });
        assert!(unbond["bundle"].is_null(), "an unbond carries no bundle");
        let unbond = unbond["action"].clone();
        assert_eq!((&unbond["kind"], &unbond["amount"], &unbond["nonce"]), (&json!("unbond"), &json!(7), &json!(2)));
        assert!(!serde_json::to_string(&unbond).unwrap().contains("signature"), "a signature is not explorer data");

        let w = bundle_less(Action::Withdraw {
            validator: v,
            amount: 9,
            nonce: 3,
            time: 42,
            r: [5; 8],
            envelope: envelope.clone(),
            signature: sig,
        });
        assert!(w["bundle"].is_null(), "a withdraw carries no bundle");
        let w = w["action"].clone();
        assert_eq!(
            (&w["kind"], &w["validator"], &w["amount"], &w["nonce"], &w["time"]),
            (&json!("withdraw"), &json!(v.to_base58()), &json!(9), &json!(3), &json!(42))
        );
        assert!(!serde_json::to_string(&w).unwrap().contains("\"r\""), "the note's blinding is not explorer data");

        let at = j(Action::BridgeAttest {
            attestation: vec![9; 520],
            recipient: recipient.clone(),
            r: [5; 8],
            time: 4,
            asset: 1,
            envelope,
        });
        assert_eq!(at["kind"], "bridge_attest");
        assert_eq!(at["attestation_len"], 520);
        assert_eq!(at["recipient"], recipient.to_string());
        assert_eq!(at["asset"], 1, "the index the action names, which is a field of it");
        assert_eq!(at["time"], 4);
        // Public, and the last word a recipient needs to rebuild the deposit note itself.
        assert_eq!(at["r"], word8_to_hex(&[5; 8]));
        assert!(at["amount"].is_null(), "an attestation's amount is inside it, not on the action");
        assert!(at["asset_index"].is_null(), "and its asset index is in the registry, which there is none of");
        assert!(at["commitment"].is_null(), "with no registry there is no index to compute a leaf under");

        let asset_bundle = b([nf(3), nf(4)], [cm(3), cm(4)]);
        let burn = j(Action::BridgeBurn {
            asset_bundle,
            asset: 2,
            amount: 400,
            relayer_fee: 100,
            to_chain: 5,
            to: [0xab; 32],
        });
        assert_eq!(burn["kind"], "bridge_burn");
        assert_eq!(
            (&burn["asset"], &burn["amount"], &burn["relayer_fee"], &burn["to_chain"]),
            (&json!(2), &json!(400), &json!(100), &json!(5))
        );
        assert_eq!(burn["to"], "ab".repeat(32));
        // The asset bundle renders exactly like the fee bundle: same public fields, no more.
        assert_eq!(burn["asset_bundle"]["nullifiers"][0], word8_to_hex(&nf(3)));
        assert_eq!(burn["asset_bundle"]["fee"], bundle_fee());

        // A call reports its envelope's size, or null when it carries none.
        let plain = j(Action::Call { program: Hash::ZERO, proof: vec![1; 40], input_envelope: None });
        assert_eq!(plain["kind"], "call");
        assert_eq!(plain["input_envelope_len"], Value::Null);
        let sealed = j(Action::Call {
            program: Hash::ZERO,
            proof: vec![1; 40],
            input_envelope: Some(randprotocol_core::CallEnvelope {
                kem_ct: vec![1; 1088],
                to_sender: vec![2; 48],
                to_auditor: vec![3; 48],
                body: vec![4; 96],
            }),
        });
        assert_eq!(sealed["input_envelope_len"], 1088 + 48 + 48 + 96);
        // Still redacted: no ciphertext of any kind reaches the explorer.
        let text = serde_json::to_string(&sealed).unwrap();
        assert!(!text.contains("body") && !text.contains("kem_ct"), "{text}");
    }

    /// A bridged chain with one committed attestation (1000 units of the test token to the
    /// fixture recipient, registering it as asset 1) and one committed burn of 400 with a
    /// relayer fee of 100.
    fn bridged_chain() -> (tempfile::TempDir, RpcState, GenesisState, randprotocol_core::Transaction) {
        let (gs, secrets) = fixtures::bridged_genesis(1);
        let (dir, st) = state_for(&gs);
        let mut ledger = gs.ledger.clone();
        let att = fixtures::attest_tx(&ledger, fixtures::attestation(&secrets, &fixtures::recipient(), 1_000, 0), 20);
        let b1 = make_block(&gs.block, &mut ledger, vec![att.clone()], &key(1));
        st.storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        let burn = fixtures::burn_tx(&ledger, 1, 400, 100, 30);
        let b2 = make_block(&b1.block, &mut ledger, vec![burn], &key(1));
        st.storage.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();
        (dir, st, gs, att)
    }

    /// The bridge's public state, as a relayer and a guardian read it: who signs, who may
    /// emit, what is registered and how many messages have gone out. No balance anywhere —
    /// bridged value is notes.
    #[tokio::test]
    async fn bridge_state_reports_guardians_emitters_and_the_registry() {
        let (_d, st, _gs, _) = bridged_chain();
        let v = ok(&st, "rand_getBridgeState", json!([])).await;
        assert_eq!(v["enabled"], true);
        assert_eq!(v["emitter"], hex::encode([1u8; 32]));
        assert_eq!(v["emitters"]["2"], hex::encode([2u8; 32]));
        assert_eq!(v["guardian_set_index"], 0);
        assert_eq!(v["guardians"].as_array().unwrap().len(), 6);
        assert_eq!(v["burn_sequence"], 1);
        assert_eq!(v["next_index"], 2, "one asset registered, so the next one gets index 2");
        assert!(!serde_json::to_string(&v).unwrap().contains("balance"));

        // The registry alone, which is what a wallet needs to read a note's `asset` word.
        let asset = randprotocol_core::bridge::asset_id(2, &fixtures::TOKEN);
        let row = json!({
            "index": 1, "chain": 2, "token": hex::encode(fixtures::TOKEN), "asset_id": asset.to_hex(),
        });
        assert_eq!(ok(&st, "rand_getAssets", json!([])).await, json!([row]));
        assert_eq!(v["assets"], json!([row]));

        // And the id the registry is keyed by is derivable from the two wire fields.
        let id = ok(&st, "rand_bridgeAssetId", json!([2, hex::encode(fixtures::TOKEN)])).await;
        assert_eq!(id, asset.to_hex());
        let bad = call(&st, "rand_bridgeAssetId", json!([2, "aabb"])).await.unwrap_err();
        assert_eq!(bad.code, -32602);
    }

    /// The outbound message a burn emitted, for guardians to sign, keyed by its sequence.
    #[tokio::test]
    async fn bridge_burn_serves_the_outbound_message() {
        let (_d, st, _gs, _) = bridged_chain();
        let v = ok(&st, "rand_getBridgeBurn", json!([0])).await;
        assert_eq!(v["sequence"], 0);
        assert_eq!(v["height"], 2);
        let body = hex::decode(v["body_hex"].as_str().unwrap()).unwrap();
        assert_eq!(v["digest"], hex::encode(randprotocol_core::bridge::digest(&body)));
        assert_eq!(ok(&st, "rand_getBridgeBurn", json!([1])).await, Value::Null);
    }

    /// A chain whose genesis has no `bridge` section answers every bridge read rather than
    /// erroring: disabled, and empty.
    #[tokio::test]
    async fn the_bridge_reads_degrade_on_an_unbridged_chain() {
        let (_d, st, _gs) = chain();
        assert_eq!(ok(&st, "rand_getBridgeState", json!([])).await, json!({ "enabled": false }));
        assert_eq!(ok(&st, "rand_getAssets", json!([])).await, json!([]));
        assert_eq!(ok(&st, "rand_getBridgeBurn", json!([0])).await, Value::Null);
        // The asset id is arithmetic on its two arguments, so it answers anywhere.
        assert!(ok(&st, "rand_bridgeAssetId", json!([2, hex::encode([7u8; 32])])).await.is_string());
    }

    /// On a bridged chain the explorer resolves an attestation against the registry: the
    /// deposit's amount and the note's asset index, neither of which is a field of the action.
    #[tokio::test]
    async fn an_attestation_renders_its_deposit_against_the_registry() {
        let (_d, st, _gs, att) = bridged_chain();
        let v = ok(&st, "rand_getTransaction", json!([att.hash().to_hex()])).await;
        let action = &v["tx"]["action"];
        assert_eq!(action["kind"], "bridge_attest");
        assert_eq!(action["amount"], 1_000);
        assert_eq!(action["asset_index"], 1);
        // On a committed attest the two indices agree by rule, not by luck: admission refuses a
        // transaction whose `asset` is not the one the registry resolves.
        assert_eq!(action["asset"], action["asset_index"]);
        assert_eq!(action["recipient"], fixtures::recipient().to_string());
        // Every word of the deposit note is here, `r` included, so its recipient can rebuild the
        // note from the wire alone — the recovery path for a hostile or garbage envelope
        // (`docs/bridge.md` §8). Nothing about a deposit is secret; only later spends are.
        assert_eq!(action["r"], word8_to_hex(&[7; 8]), "the note's blinding, as the action published it");
        assert_eq!(action["time"], 0, "the note's own time word, not the height it applied at");
        // And the commitment the chain computed from exactly those fields is the leaf it appended.
        let cm = randprotocol_core::ledger::bridge_notes::deposit_commitment(
            &fixtures::recipient(),
            1_000,
            1,
            0,
            &[7; 8],
            &StubExecutor,
        );
        assert_eq!(action["commitment"], word8_to_hex(&cm));
        let leaves = st.storage.notes_from(0, 100).unwrap();
        assert!(leaves.iter().any(|(_, row)| row.cm == cm), "the rendered commitment is a leaf of the tree");
        // The same transaction inside its block renders the same way.
        let block = ok(&st, "rand_getBlockByHeight", json!([1])).await;
        assert_eq!(block["transactions"][0]["action"], *action);
    }

    #[tokio::test]
    async fn unknown_methods_still_report_method_not_found() {
        let gs = fixtures::genesis(1);
        let (_d, st) = state_for(&gs);
        assert_eq!(call(&st, "rand_getBalance", json!([])).await.unwrap_err().code, -32601);
        assert_eq!(call(&st, "rand_getAccount", json!([])).await.unwrap_err().code, -32601);
        // The bridge holds notes, not per-address balances, so the account-era balance read is
        // gone for good rather than waiting on a later phase.
        assert_eq!(call(&st, "rand_getAssetBalance", json!([])).await.unwrap_err().code, -32601);
    }

    // --------------------------------------------------------- the request body limit
    //
    // The retired limit was `2 * MAX_PROOF_BYTES + 256 KiB` — sized for *one* hex-encoded proof.
    // A constraint-set-5 `Call` carries two proofs (the fee bundle's, measured 1 321 773 bytes on
    // chain 8, plus the call's own ~1.2 MB), so its hex JSON is ~5 MB: axum refused the body with a
    // plain-text 413, and the wallet reported the unparseable reply as
    // "expected value at line 1 column 1" after ~100 s of proving.

    /// The largest transaction the *per-part* caps allow: a bundle at `MAX_PROOF_BYTES` with two
    /// maximal output envelopes, and a `Call` carrying a second `MAX_PROOF_BYTES` proof and a
    /// maximal input envelope.
    ///
    /// Deliberately **not** an admissible transaction: two maximal proofs are over
    /// `MAX_BLOCK_BYTES`, so no block can carry it and admission refuses it as
    /// `TxError::TransactionTooLarge`. It is the right fixture for the *body* limit, which has to be
    /// wide enough that the limit is never what refuses a transaction — the block rule is.
    fn largest_transaction_the_part_caps_allow() -> Transaction {
        use randprotocol_core::notes::{Bundle, MAX_ENVELOPE_BYTES};
        use randprotocol_core::types::actions::{CallEnvelope, MAX_CALL_ENVELOPE_BYTES};

        let big_envelope = || Envelope {
            kem_ct: vec![1u8; MAX_ENVELOPE_BYTES / 4],
            to_receiver: vec![2u8; MAX_ENVELOPE_BYTES / 4],
            to_sender: vec![3u8; MAX_ENVELOPE_BYTES / 4],
            body: vec![4u8; MAX_ENVELOPE_BYTES / 4],
        };
        let bundle = Bundle {
            anchor: [1; 8],
            nullifiers: [nf(1), nf(2)],
            commitments: [cm(1), cm(2)],
            fee: randprotocol_core::gas::BUNDLE_BASE,
            burn: 0,
            asset: 0,
            time: 1,
            envelopes: [big_envelope(), big_envelope()],
            proof: vec![9u8; randprotocol_core::gas::MAX_PROOF_BYTES],
        };
        let call = Action::Call {
            program: Hash::digest(b"program"),
            proof: vec![8u8; randprotocol_core::gas::MAX_PROOF_BYTES],
            input_envelope: Some(CallEnvelope {
                kem_ct: vec![1u8; MAX_CALL_ENVELOPE_BYTES / 4],
                to_sender: vec![2u8; MAX_CALL_ENVELOPE_BYTES / 4],
                to_auditor: vec![3u8; MAX_CALL_ENVELOPE_BYTES / 4],
                body: vec![4u8; MAX_CALL_ENVELOPE_BYTES / 4],
            }),
        };
        Transaction::shielded(7, bundle, call)
    }

    /// A deploy at the zkVM's own limit (`max_program_words` = 65 535, a v0.4 genesis's ceiling)
    /// fits every byte cap on its way to a block, even beside a bundle proof at the proof cap: the
    /// ledger's whole-transaction cap (`MAX_BLOCK_BYTES`, which is also the block's), the RPC
    /// request body, gossip's transmit size (`network::GOSSIP_MAX_TRANSMIT_SIZE`, `network::start`),
    /// and the sync reader's limit on a `CommittedBlock` carrying it
    /// (`network::SYNC_RESPONSE_WIRE_LIMIT`, `network::codec::cbor_size`). So raising the program
    /// cap needs no byte cap raised with it.
    #[test]
    fn a_deploy_at_the_zkvm_program_limit_fits_every_byte_cap() {
        let mut tx = largest_transaction_the_part_caps_allow();
        tx.action = Action::Deploy { base_pc: 0, words: vec![0x13; randprotocol_core::gas::MAX_PROGRAM_WORDS_LIMIT], public: vec![] };
        let encoded = tx.encode();
        assert!(encoded.len() > 4 * randprotocol_core::gas::MAX_PROGRAM_WORDS_LIMIT, "the words are all there");
        assert!(
            encoded.len() <= randprotocol_core::gas::MAX_BLOCK_BYTES,
            "{} B against the {} B transaction and block cap",
            encoded.len(),
            randprotocol_core::gas::MAX_BLOCK_BYTES
        );
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_sendTransaction", "params": [hex::encode(&encoded)] });
        let posted = serde_json::to_vec(&body).unwrap().len();
        assert!(posted <= RPC_MAX_BODY_BYTES, "{posted} B posted against a {RPC_MAX_BODY_BYTES} B limit");
        assert!(
            encoded.len() <= crate::network::GOSSIP_MAX_TRANSMIT_SIZE,
            "gossip carries bincode, under its {} B transmit size",
            crate::network::GOSSIP_MAX_TRANSMIT_SIZE
        );

        // The sync reader's limit: a peer catching up receives this transaction wrapped in a
        // `CommittedBlock`, cbor-encoded (`network::codec`), not the bincode `encoded` above — a
        // different wire form with its own overhead, so it gets its own assertion against its own
        // limit rather than reusing `encoded.len()`.
        let gs = fixtures::genesis(1);
        let cb = make_block_unchecked(&gs.block, &gs.ledger, vec![tx], &key(1));
        let wire = crate::network::codec::cbor_size(&cb).unwrap() as u64;
        assert!(
            wire <= crate::network::SYNC_RESPONSE_WIRE_LIMIT,
            "{wire} B against the {} B sync reader limit",
            crate::network::SYNC_RESPONSE_WIRE_LIMIT
        );
    }

    /// The body limit is never the thing that refuses a transaction: it is wide enough for anything
    /// the per-part caps allow, so what refuses an over-large one is the block rule, with a message
    /// about blocks.
    #[test]
    fn the_body_limit_is_wider_than_any_transaction_the_part_caps_allow() {
        let tx = largest_transaction_the_part_caps_allow();
        let encoded = tx.encode();
        // Two proofs' worth, not one: this is the term the old limit was missing.
        assert!(
            encoded.len() > 2 * randprotocol_core::gas::MAX_PROOF_BYTES,
            "the fixture should carry two maximal proofs: {} B",
            encoded.len()
        );

        // What `send_transaction` actually posts.
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_sendTransaction", "params": [hex::encode(&encoded)] });
        let posted = serde_json::to_vec(&body).unwrap().len();
        assert!(
            posted <= RPC_MAX_BODY_BYTES,
            "the widest transaction the part caps allow must fit: {posted} B posted against a {RPC_MAX_BODY_BYTES} B limit"
        );

        // And the retired limit would have refused it, which is the bug.
        let old_limit = 2 * randprotocol_core::gas::MAX_PROOF_BYTES + 256 * 1024;
        assert!(posted > old_limit, "the old limit should have refused this: {posted} B against {old_limit} B");
    }

    /// A transaction larger than a block is refused at the RPC, before it reaches the node loop, and
    /// the message names the block limit rather than the body limit.
    ///
    /// The body limit admits it on purpose (above): the two caps answer different questions, and
    /// without this check a transaction no block could ever carry would be handed to the mempool.
    #[tokio::test]
    async fn a_transaction_larger_than_a_block_is_refused_naming_the_block_limit() {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let (_dir, st) = state_for(&gs);
        let tx = largest_transaction_the_part_caps_allow();
        let encoded_len = tx.encoded_len();
        assert!(encoded_len > randprotocol_core::gas::MAX_BLOCK_BYTES, "the fixture must be unminable: {encoded_len} B");

        let err = call(&st, "rand_sendTransaction", json!([hex::encode(tx.encode())])).await.unwrap_err();
        assert_eq!(err.code, -32000, "{}", err.message);
        assert!(err.message.contains(&randprotocol_core::gas::MAX_BLOCK_BYTES.to_string()), "{}", err.message);
        assert!(err.message.contains(&encoded_len.to_string()), "{}", err.message);
    }

    /// A body over the limit comes back as a JSON-RPC error naming the limit — parseable, where the
    /// plain-text 413 was not.
    #[tokio::test]
    async fn a_body_over_the_limit_is_refused_as_json_naming_the_limit() {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let (_dir, st) = state_for(&gs);
        let (addr, task) = serve("127.0.0.1:0".parse().unwrap(), st).await.unwrap();

        // Just over: a valid JSON-RPC envelope whose hex payload pushes it past the limit.
        let filler = "ab".repeat(RPC_MAX_BODY_BYTES / 2);
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_sendTransaction", "params": [filler] });
        let raw = serde_json::to_vec(&body).unwrap();
        assert!(raw.len() > RPC_MAX_BODY_BYTES, "the fixture must exceed the limit: {} B", raw.len());

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}"))
            .header("content-type", "application/json")
            .body(raw)
            .send()
            .await
            .expect("the server answers");
        assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE, "the HTTP status stays honest");

        // The point: the body parses as JSON-RPC rather than being plain text.
        let v: Value = resp.json().await.expect("an oversized body must still answer JSON");
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["error"]["code"], -32600);
        let msg = v["error"]["message"].as_str().unwrap_or_default();
        assert!(msg.contains(&RPC_MAX_BODY_BYTES.to_string()), "the message must name the limit: {msg}");

        task.abort();
    }

    /// A body within the limit still reaches the dispatcher, and a malformed one answers JSON too.
    #[tokio::test]
    async fn a_malformed_body_answers_json_rather_than_plain_text() {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let (_dir, st) = state_for(&gs);
        let (addr, task) = serve("127.0.0.1:0".parse().unwrap(), st).await.unwrap();

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}"))
            .header("content-type", "application/json")
            .body("{not json".to_string())
            .send()
            .await
            .expect("the server answers");
        let v: Value = resp.json().await.expect("a malformed body must still answer JSON");
        assert_eq!(v["error"]["code"], -32600);

        // A well-formed request over the same server still works.
        let ok: Value = reqwest::Client::new()
            .post(format!("http://{addr}"))
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_chainId", "params": [] }))
            .send()
            .await
            .expect("answers")
            .json()
            .await
            .expect("json");
        assert_eq!(ok["result"], 7);

        task.abort();
    }

    /// Everything a light wallet needs to trial-decrypt and track spends, per block, with no proof
    /// bytes: the leaf index, the commitment, the envelope, and the nullifiers the transaction spent.
    #[tokio::test]
    async fn compact_blocks_carry_every_note_and_nullifier_per_transaction() {
        let (_d, st, _gs) = chain();
        let v = ok(&st, "rand_getCompactBlocks", json!([0, 1])).await;
        let blocks = v.as_array().unwrap();
        assert_eq!(blocks.len(), 2, "genesis and the one committed block");

        // Height 0 owns the genesis deposits, which belong to no transaction.
        assert_eq!(blocks[0]["height"], 0);
        assert_eq!(blocks[0]["transactions"], json!([]));
        let genesis_notes = blocks[0]["commitments"].as_array().unwrap();
        assert_eq!(genesis_notes.len(), 2);
        assert_eq!(genesis_notes[0]["index"], 0);

        let b1 = &blocks[1];
        let head = st.storage.block_by_height(1).unwrap().unwrap();
        assert_eq!(b1["hash"], head.hash().to_hex());
        assert_eq!(b1["timestamp_ms"], head.header.timestamp_ms);
        assert_eq!(b1["commitments"], json!([]), "every note of this block belongs to a transaction");
        let txs = b1["transactions"].as_array().unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0]["hash"], head.transactions[0].hash().to_hex());
        assert_eq!(txs[0]["nullifiers"], json!([word8_to_hex(&nf(1)), word8_to_hex(&nf(2))]));
        let cms = txs[0]["commitments"].as_array().unwrap();
        assert_eq!(cms.len(), 2);
        assert_eq!((&cms[0]["index"], &cms[0]["cm"]), (&json!(2), &json!(word8_to_hex(&cm(1)))));
        assert_eq!((&cms[1]["index"], &cms[1]["cm"]), (&json!(3), &json!(word8_to_hex(&cm(2)))));
        // The envelope goes out in its four hex parts, exactly as getCommitments serves it.
        assert!(cms[0]["envelope"]["kem_ct"].is_string());
        // And no proof bytes anywhere: that is the whole point of a compact block.
        let text = serde_json::to_string(&v).unwrap();
        assert!(!text.contains("proof"), "a compact block carries no proof: {}", &text[..200.min(text.len())]);
    }

    /// The range is clamped, not refused; a backwards range is a parameter error.
    #[tokio::test]
    async fn compact_blocks_clamp_the_range_and_stop_at_the_head() {
        let (_d, st, _gs) = chain();
        // Past the head: a short reply, never an error.
        let v = ok(&st, "rand_getCompactBlocks", json!([0, 99])).await;
        assert_eq!(v.as_array().unwrap().len(), 2);
        // A range longer than the cap is truncated to MAX_COMPACT_BLOCKS blocks, from `from_height`.
        let v = ok(&st, "rand_getCompactBlocks", json!([0, MAX_COMPACT_BLOCKS + 500])).await;
        assert_eq!(v.as_array().unwrap().len(), 2, "the head stops it first here");
        // Backwards is a parameter error, and so is a missing bound.
        assert_eq!(call(&st, "rand_getCompactBlocks", json!([1, 0])).await.unwrap_err().code, -32602);
        assert_eq!(call(&st, "rand_getCompactBlocks", json!([0])).await.unwrap_err().code, -32602);
        // A range that starts past the head is empty, not an error.
        assert_eq!(ok(&st, "rand_getCompactBlocks", json!([50, 60])).await, json!([]));
    }

    /// A chain long enough for the block cap to be the binding one: the reply stops at
    /// `MAX_COMPACT_BLOCKS` blocks counted from `from_height`, and the caller resumes from the
    /// last height it got plus one.
    #[tokio::test]
    async fn compact_blocks_stop_at_the_block_cap() {
        let gs = genesis_with(1, vec![alloc_note(20, 1_000)]);
        let (_d, st) = state_for(&gs);
        let mut ledger = gs.ledger.clone();
        let mut parent = gs.block.clone();
        let blocks = MAX_COMPACT_BLOCKS as u32 + 5;
        for i in 0..blocks {
            let w = 1_000 + i * 4;
            let tx = bundle_tx(&ledger, [[w; 8], [w + 1; 8]], [[w + 2; 8], [w + 3; 8]], bundle_fee());
            let b = make_block(&parent, &mut ledger, vec![tx], &key(1));
            st.storage.commit(std::slice::from_ref(&b), &ledger, &[], &StubExecutor).unwrap();
            parent = b.block.clone();
        }
        // 2 notes a block is well under the row cap, so the block cap is what ends this reply.
        let v = ok(&st, "rand_getCompactBlocks", json!([0, blocks])).await;
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), MAX_COMPACT_BLOCKS as usize);
        assert_eq!(rows[0]["height"], 0);
        assert_eq!(rows[MAX_COMPACT_BLOCKS as usize - 1]["height"], MAX_COMPACT_BLOCKS - 1);
        // Resuming from the last height plus one picks up exactly where it stopped.
        let next = ok(&st, "rand_getCompactBlocks", json!([MAX_COMPACT_BLOCKS, blocks])).await;
        assert_eq!(next.as_array().unwrap()[0]["height"], MAX_COMPACT_BLOCKS);
    }

    /// The row cap ends a reply early, but never before one whole block: a block holding more
    /// notes than the cap still comes back complete, and it comes back alone.
    #[tokio::test]
    async fn compact_blocks_serve_a_fat_block_whole_and_alone() {
        let gs = genesis_with(1, vec![alloc_note(20, 1_000)]);
        let (_d, st) = state_for(&gs);
        let mut ledger = gs.ledger.clone();
        // One block of 600 transfers: 1200 leaves, well past the 1000-row cap.
        let fat: Vec<_> = (0..600u32)
            .map(|i| {
                let w = 1_000 + i * 4;
                bundle_tx(&ledger, [[w; 8], [w + 1; 8]], [[w + 2; 8], [w + 3; 8]], bundle_fee())
            })
            .collect();
        let b1 = make_block(&gs.block, &mut ledger, fat, &key(1));
        st.storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();
        let tx = bundle_tx(&ledger, [[9001; 8], [9002; 8]], [[9003; 8], [9004; 8]], bundle_fee());
        let b2 = make_block(&b1.block, &mut ledger, vec![tx], &key(1));
        st.storage.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();

        let v = ok(&st, "rand_getCompactBlocks", json!([1, 2])).await;
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 1, "the fat block fills the page on its own");
        assert_eq!(rows[0]["height"], 1);
        let txs = rows[0]["transactions"].as_array().unwrap();
        assert_eq!(txs.len(), 600);
        let notes: usize = txs.iter().map(|t| t["commitments"].as_array().unwrap().len()).sum();
        assert_eq!(notes, 1200, "the block is served whole however far past the cap it is");
        assert_eq!(rows[0]["commitments"], json!([]), "and every leaf is attributed to its transaction");
        // The caller resumes at the last height it got plus one and gets the next block.
        let next = ok(&st, "rand_getCompactBlocks", json!([2, 2])).await;
        assert_eq!(next.as_array().unwrap().len(), 1);
        assert_eq!(next[0]["height"], 2);
    }

    /// The two notes the wire does not carry, rendered end to end: a `Withdraw`'s deposit, which
    /// reaches storage as a `cb.deposits` entry, and a `BridgeAttest`'s, which reaches it through
    /// `created_notes`. Both live in one block, in both orders, and both must come back under the
    /// transaction that produced them — which is what `docs/rpc.md` promises a wallet.
    #[tokio::test]
    async fn compact_blocks_attribute_the_notes_the_ledger_derives() {
        for attest_first in [false, true] {
            let (_d, storage, gs, secrets, b1, mut ledger, v) = fixtures::bridged_chain_funded_for_a_withdraw(40);
            let storage = Arc::new(storage);
            let st = state_over(storage.clone(), &gs);
            let time = ledger.height() as u32;
            let withdraw = fixtures::withdraw_tx(gs.chain_id, &v, 2 * bundle_fee(), 0, time, [13; 8]);
            let att =
                fixtures::attest_tx(&ledger, fixtures::attestation(&secrets, &fixtures::recipient(), 1_000, 0), 20);
            let txs = if attest_first { vec![att.clone(), withdraw] } else { vec![withdraw, att.clone()] };
            let b2 = fixtures::make_block_voted(&b1.block, &mut ledger, txs, &v, &[&v]);
            let withdraw_leaf = b2.deposits[0].index;
            storage.commit(&[b1, b2], &ledger, &[], &StubExecutor).unwrap();
            let expected_deposit = randprotocol_core::ledger::bridge_notes::deposit_note(
                &att,
                ledger.bridge().expect("bridged genesis"),
                &StubExecutor,
            )
            .expect("the attestation deposits into a registered asset");

            let v_json = ok(&st, "rand_getCompactBlocks", json!([2, 2])).await;
            let rows = v_json.as_array().unwrap();
            assert_eq!(rows.len(), 1);
            let rendered = rows[0]["transactions"].as_array().unwrap();
            let block = storage.block_by_height(2).unwrap().unwrap();
            assert_eq!(rendered.len(), block.transactions.len(), "attest_first={attest_first}");
            assert_eq!(
                rows[0]["commitments"],
                json!([]),
                "attest_first={attest_first}: every leaf of this block belongs to a transaction"
            );

            // Each transaction owns exactly the slice `commit` appended for it, derived notes
            // included, and the block's transactions together own every leaf stored at height 2.
            let mut total = 0usize;
            for (row, tx) in rendered.iter().zip(&block.transactions) {
                let want = tx.commitments().len() + crate::storage::derived_note_count(tx);
                let got = row["commitments"].as_array().unwrap();
                assert_eq!(got.len(), want, "attest_first={attest_first}: {} owns {want} leaves", tx.hash().to_hex());
                total += got.len();
            }
            assert_eq!(
                total,
                storage.notes_in_heights(2, 2, usize::MAX).unwrap().len(),
                "attest_first={attest_first}: nothing of this block is dropped or double-counted"
            );

            // The withdraw's one note is the leaf the ledger itself named...
            let wi = block.transactions.iter().position(|t| matches!(t.action, Action::Withdraw { .. })).unwrap();
            let w_notes = rendered[wi]["commitments"].as_array().unwrap();
            assert_eq!(w_notes.len(), 1, "attest_first={attest_first}");
            assert_eq!(w_notes[0]["index"], withdraw_leaf, "attest_first={attest_first}");
            // ...and the attest's deposit rides with its fee bundle's two slots, last of the three.
            let ai = block.transactions.iter().position(|t| matches!(t.action, Action::BridgeAttest { .. })).unwrap();
            let a_notes = rendered[ai]["commitments"].as_array().unwrap();
            assert_eq!(a_notes.len(), 3, "attest_first={attest_first}: two bundle slots and the deposit");
            assert_eq!(a_notes[2]["cm"], word8_to_hex(&expected_deposit.0), "attest_first={attest_first}");
            assert_eq!(
                a_notes[2]["envelope"],
                envelope_json(&expected_deposit.1),
                "attest_first={attest_first}: the envelope the chain sealed, not the action's"
            );
        }
    }

    /// Headers over a range, capped like `rand_getCompactBlocks` and truncated at the head — no
    /// `transactions` field, since that is `rand_getBlockByHeight`'s job.
    #[tokio::test]
    async fn get_blocks_serves_headers_in_a_capped_range() {
        let (_d, storage, gs, blocks) = fixtures::chain_fixture(3);
        let st = state_over(Arc::new(storage), &gs);
        let v = ok(&st, "rand_getBlocks", json!([1, 3])).await;
        let list = v.as_array().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0]["height"], 1);
        assert_eq!(list[2]["hash"], blocks[2].block.hash().to_hex());
        assert!(list[0].get("transactions").is_none(), "headers only");
        assert_eq!(list[0]["tx_count"], blocks[0].block.transactions.len());
        let v = ok(&st, "rand_getBlocks", json!([2, 500])).await;
        assert_eq!(v.as_array().unwrap().len(), 2, "past the head is truncated");
        let e = call(&st, "rand_getBlocks", json!([3, 1])).await.err().unwrap();
        assert_eq!(e.code, -32602);
    }

    // --------------------------------------------------------- viewing keys
    //
    // Node-side import (`rand_importViewingKey` + `rand_getViewingNotes`, the Zcash
    // `z_importviewingkey` analogue) and the per-transaction disclosure check
    // (`rand_checkTransaction`, Monero's `check_tx_proof`). The fixture chain every case here
    // runs on: block 1 pays Alice 500 (sealed by Bob) and Bob 700 (sealed by Alice) in one
    // bundle, block 2 pays Alice 900 — on top of one genesis alloc, so five leaves.

    /// The two-block chain above, plus the running ledger and tip so a test can extend it, and
    /// the three notes (which cannot be rebuilt later: `Note::new` draws a fresh `r`).
    fn viewing_chain() -> (
        tempfile::TempDir,
        RpcState,
        randprotocol_core::Ledger,
        randprotocol_core::Block,
        randprotocol_zkvm::notes::Note,
        randprotocol_zkvm::notes::Note,
        randprotocol_zkvm::notes::Note,
    ) {
        use crate::viewing::testkit::{key_vk, note_for, sealed_to};
        use randprotocol_zkvm::viewing::TxKey;

        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let (dir, st) = state_for(&gs);
        let mut ledger = gs.ledger.clone();
        let (alice, bob) = (key_vk(1), key_vk(2));

        let a500 = note_for(&alice, &bob, 500);
        let b700 = note_for(&bob, &alice, 700);
        let mut bundle =
            fixtures::bundle(&ledger, [[31; 8], [32; 8]], [a500.commitment(), b700.commitment()], bundle_fee());
        bundle.envelopes = [
            sealed_to(&bob, &alice, &a500, &TxKey([11; 32])),
            sealed_to(&alice, &bob, &b700, &TxKey([12; 32])),
        ];
        let tx1 = Transaction::shielded(gs.chain_id, bundle, Action::None);
        let b1 = make_block(&gs.block, &mut ledger, vec![tx1], &key(1));
        st.storage.commit(std::slice::from_ref(&b1), &ledger, &[], &StubExecutor).unwrap();

        let a900 = note_for(&alice, &bob, 900);
        let mut bundle = fixtures::bundle(&ledger, [[33; 8], [34; 8]], [a900.commitment(), [44; 8]], bundle_fee());
        bundle.envelopes = [sealed_to(&bob, &alice, &a900, &TxKey([13; 32])), fixtures::env(9)];
        let tx2 = Transaction::shielded(gs.chain_id, bundle, Action::None);
        let b2 = make_block(&b1.block, &mut ledger, vec![tx2], &key(1));
        st.storage.commit(std::slice::from_ref(&b2), &ledger, &[], &StubExecutor).unwrap();

        (dir, st, ledger, b2.block, a500, b700, a900)
    }

    /// Import a key, scan, and read back exactly that key's view of the pool: Alice's two
    /// receipts and the note she sent, in tree order — and, for Bob, the mirror image.
    #[tokio::test]
    async fn import_and_scan_finds_the_keys_notes_and_nobody_elses() {
        use crate::viewing::testkit::{key_vk, nk_hex};
        let (_d, st, ..) = viewing_chain();
        let (alice, bob) = (key_vk(1), key_vk(2));

        let v = ok(&st, "rand_importViewingKey", json!([nk_hex(&alice)])).await;
        assert_eq!(v, json!({ "imported": true, "rescan_from_height": 0, "viewing_keys": 1 }));
        // Re-importing the same key is a no-op, not a second key and not a rescan.
        let v = ok(&st, "rand_importViewingKey", json!([nk_hex(&alice)])).await;
        assert_eq!((&v["imported"], &v["viewing_keys"]), (&json!(false), &json!(1)));

        let v = ok(&st, "rand_getViewingNotes", json!([nk_hex(&alice)])).await;
        assert_eq!((&v["scanned_index"], &v["next_index"], &v["complete"]), (&json!(5), &json!(5), &json!(true)));
        let rows = v["notes"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        // In tree order: received 500 at height 1, sent 700 at height 1, received 900 at 2.
        assert_eq!((&rows[0]["index"], &rows[0]["role"], &rows[0]["height"]), (&json!(1), &json!("received"), &json!(1)));
        assert_eq!((&rows[1]["index"], &rows[1]["role"]), (&json!(2), &json!("sent")));
        assert_eq!((&rows[2]["index"], &rows[2]["role"], &rows[2]["height"]), (&json!(3), &json!("received"), &json!(2)));
        // Amounts are strings, like every amount this RPC reports as chain state.
        assert_eq!(rows[0]["note"]["amount"], "500");
        assert_eq!(rows[1]["note"]["amount"], "700");
        assert_eq!(rows[2]["note"]["amount"], "900");
        // A received row carries the nullifier (a function of this key) and its spent state; a
        // sent row has neither — the note belongs to someone else.
        assert!(rows[0]["nullifier"].is_string());
        assert_eq!(rows[0]["spent"], false);
        assert!(rows[1]["nullifier"].is_null());
        assert!(rows[1]["spent"].is_null());

        // Bob's key sees the mirror image: he sent the 500 and the 900, and owns the 700.
        ok(&st, "rand_importViewingKey", json!([nk_hex(&bob)])).await;
        let v = ok(&st, "rand_getViewingNotes", json!([nk_hex(&bob)])).await;
        let roles: Vec<&str> = v["notes"].as_array().unwrap().iter().map(|r| r["role"].as_str().unwrap()).collect();
        assert_eq!(roles, ["sent", "received", "sent"]);

        // A key nobody imported is not-found; a malformed one is a parameter error, on both
        // methods, before any storage read.
        let err = call(&st, "rand_getViewingNotes", json!([nk_hex(&key_vk(9))])).await.unwrap_err();
        assert_eq!(err.code, -32001);
        for bad in ["zz", "00", "abab"] {
            assert_eq!(call(&st, "rand_importViewingKey", json!([bad])).await.unwrap_err().code, -32602, "{bad}");
            assert_eq!(call(&st, "rand_getViewingNotes", json!([bad])).await.unwrap_err().code, -32602, "{bad}");
        }
    }

    /// The rescan floor: importing from height 2 never touches block 1's leaves, so the one note
    /// found is the 900 — and the reply still reports the whole tree was walked from there.
    #[tokio::test]
    async fn import_with_a_rescan_height_skips_earlier_notes() {
        use crate::viewing::testkit::{key_vk, nk_hex};
        let (_d, st, ..) = viewing_chain();
        let alice = key_vk(1);
        let v = ok(&st, "rand_importViewingKey", json!([nk_hex(&alice), 2])).await;
        assert_eq!(v, json!({ "imported": true, "rescan_from_height": 2, "viewing_keys": 1 }));
        let v = ok(&st, "rand_getViewingNotes", json!([nk_hex(&alice)])).await;
        assert_eq!(v["complete"], true);
        let rows = v["notes"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((&rows[0]["index"], &rows[0]["note"]["amount"]), (&json!(3), &json!("900".to_string())));
    }

    /// A spend shows up as soon as its nullifier is committed: the received note's `spent` flips
    /// and the nullifier the row already carried is the one the chain published.
    #[tokio::test]
    async fn viewing_notes_report_a_spend_once_its_nullifier_lands() {
        use crate::viewing::testkit::{key_vk, nk_hex};
        let (_d, st, mut ledger, parent, a500, _, _) = viewing_chain();
        let alice = key_vk(1);
        ok(&st, "rand_importViewingKey", json!([nk_hex(&alice)])).await;

        let nf = alice.nullifier(&a500.commitment());
        let tx = fixtures::bundle_tx(&ledger, [nf, [77; 8]], [[55; 8], [56; 8]], bundle_fee());
        let b3 = make_block(&parent, &mut ledger, vec![tx], &key(1));
        st.storage.commit(std::slice::from_ref(&b3), &ledger, &[], &StubExecutor).unwrap();

        let v = ok(&st, "rand_getViewingNotes", json!([nk_hex(&alice)])).await;
        let rows = v["notes"].as_array().unwrap();
        // The scan also picked up the new block's two leaves (placeholder envelopes, no match),
        // and the 500 is now spent — by exactly the nullifier the row reports.
        assert_eq!(v["scanned_index"], 7);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["nullifier"], word8_to_hex(&nf));
        assert_eq!(rows[0]["spent"], true);
        assert_eq!(rows[2]["spent"], false, "the 900 is untouched");
    }

    /// The import cap: `MAX_VIEWING_KEYS` distinct keys and no more; a key already held is still
    /// a no-op at the cap.
    #[tokio::test]
    async fn the_import_cap_is_enforced() {
        let gs = fixtures::genesis(7);
        let (_d, st) = state_for(&gs);
        for i in 0..crate::viewing::MAX_VIEWING_KEYS {
            let v = ok(&st, "rand_importViewingKey", json!([word8_to_hex(&[i as u32 + 1; 8])])).await;
            assert_eq!(v["viewing_keys"], i + 1);
        }
        let err = call(&st, "rand_importViewingKey", json!([word8_to_hex(&[0xbeef; 8])])).await.unwrap_err();
        assert_eq!(err.code, -32000);
        assert!(err.message.contains(&crate::viewing::MAX_VIEWING_KEYS.to_string()), "{}", err.message);
        let v = ok(&st, "rand_importViewingKey", json!([word8_to_hex(&[1u32; 8])])).await;
        assert_eq!(v["imported"], false);
    }

    /// Monero's `check_tx_proof` shape: the key that sealed a slot discloses exactly that slot's
    /// note, bound to its on-chain commitment and leaf; any other key discloses nothing.
    #[tokio::test]
    async fn check_transaction_discloses_what_the_key_sealed_and_nothing_more() {
        let (_d, st, _ledger, _parent, a500, b700, _a900) = viewing_chain();
        let tx1 = st.storage.block_by_height(1).unwrap().unwrap().transactions[0].clone();

        // The key that sealed the 500 discloses exactly it: slot 0 of the bundle, at leaf 1.
        let v = ok(&st, "rand_checkTransaction", json!([tx1.hash().to_hex(), hex::encode([11u8; 32])])).await;
        assert_eq!((&v["tx"], &v["height"]), (&json!(tx1.hash().to_hex()), &json!(1)));
        let d = v["disclosed"].as_array().unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0]["output"], "bundle:0");
        assert_eq!((&d[0]["cm"], &d[0]["index"]), (&json!(word8_to_hex(&a500.commitment())), &json!(1)));
        assert_eq!((&d[0]["note"]["amount"], &d[0]["note"]["pk"]), (&json!("500".to_string()), &json!(word8_to_hex(&a500.pk))));

        // The other slot's key discloses the 700; a key that sealed nothing in this transaction
        // discloses nothing — the negative case is an empty list, never an error.
        let v = ok(&st, "rand_checkTransaction", json!([tx1.hash().to_hex(), hex::encode([12u8; 32])])).await;
        let d = v["disclosed"].as_array().unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!((&d[0]["output"], &d[0]["note"]["pk"]), (&json!("bundle:1".to_string()), &json!(word8_to_hex(&b700.pk))));
        let v = ok(&st, "rand_checkTransaction", json!([tx1.hash().to_hex(), hex::encode([99u8; 32])])).await;
        assert_eq!(v["disclosed"], json!([]));

        // An unknown transaction is null; malformed parameters are -32602, and the key is parsed
        // before the hash is ever looked up (cheap before expensive).
        assert_eq!(ok(&st, "rand_checkTransaction", json!([Hash::ZERO.to_hex(), hex::encode([11u8; 32])])).await, Value::Null);
        for bad in ["zz", "00", "abab"] {
            assert_eq!(call(&st, "rand_checkTransaction", json!([Hash::ZERO.to_hex(), bad])).await.unwrap_err().code, -32602, "{bad}");
        }
        assert_eq!(call(&st, "rand_checkTransaction", json!(["zz", hex::encode([11u8; 32])])).await.unwrap_err().code, -32602);
    }

    /// The new methods sit inside the same sequential batch as every other: the import lands
    /// before the read that follows it in the array, and the replies line up by position.
    #[tokio::test]
    async fn the_viewing_methods_are_batch_safe() {
        use crate::viewing::testkit::{key_vk, nk_hex};
        let (_d, st, ..) = viewing_chain();
        let tx1 = st.storage.block_by_height(1).unwrap().unwrap().transactions[0].clone();
        let (_, Json(v)) = handle(
            State(st.clone()),
            Ok(Json(json!([
                { "jsonrpc": "2.0", "id": 1, "method": "rand_importViewingKey", "params": [nk_hex(&key_vk(1))] },
                { "jsonrpc": "2.0", "id": 2, "method": "rand_getViewingNotes", "params": [nk_hex(&key_vk(1))] },
                { "jsonrpc": "2.0", "id": 3, "method": "rand_checkTransaction", "params": [tx1.hash().to_hex(), hex::encode([11u8; 32])] }
            ]))),
        )
        .await;
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["result"]["imported"], true);
        assert_eq!(rows[1]["result"]["notes"].as_array().unwrap().len(), 3);
        assert_eq!(rows[2]["result"]["disclosed"].as_array().unwrap().len(), 1);
    }

    // --------------------------------------------------------- batch requests
    //
    // These drive the axum handler directly rather than through `call`/`ok`, which go straight to
    // `dispatch`: batching lives in `handle`, above the dispatcher, and the shape under test is
    // the HTTP reply — its status as well as its body.

    /// A JSON array of request objects comes back as an array of responses, in order, one per
    /// request — including the errors, so a client can correlate by position as well as by id.
    #[tokio::test]
    async fn a_batch_answers_every_request_in_order() {
        let (_d, st, _gs) = chain();
        let (code, Json(v)) = handle(
            State(st.clone()),
            Ok(Json(json!([
                { "jsonrpc": "2.0", "id": 1, "method": "rand_chainId", "params": [] },
                { "jsonrpc": "2.0", "id": "two", "method": "rand_getTreeInfo", "params": [] },
                { "jsonrpc": "2.0", "id": 3, "method": "rand_nope", "params": [] }
            ]))),
        )
        .await;
        assert_eq!(code, StatusCode::OK, "a parsed body is always 200, errors inside it or not");
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!((&rows[0]["id"], &rows[0]["result"]), (&json!(1), &json!(st.chain_id)));
        assert_eq!(rows[1]["id"], json!("two"));
        assert_eq!(rows[1]["result"]["next_index"], 4);
        assert_eq!((&rows[2]["id"], &rows[2]["error"]["code"]), (&json!(3), &json!(-32601)));
        // A single request object still answers with a single object, exactly as before.
        let (_, Json(one)) = handle(
            State(st.clone()),
            Ok(Json(json!({ "jsonrpc": "2.0", "id": 9, "method": "rand_chainId", "params": [] }))),
        )
        .await;
        assert_eq!(one["result"], json!(st.chain_id));
        assert!(one.get("error").is_none());
    }

    /// The three shapes a batch can get wrong, each a single error object rather than an array —
    /// there is no per-request id to attach them to.
    #[tokio::test]
    async fn a_malformed_batch_is_one_invalid_request_error() {
        let (_d, st, _gs) = chain();
        let err = |v: Value| async {
            let (_, Json(r)) = handle(State(st.clone()), Ok(Json(v))).await;
            r
        };

        let empty = err(json!([])).await;
        assert_eq!(empty["error"]["code"], -32600);
        assert_eq!(empty["id"], Value::Null);

        let over: Vec<Value> = (0..=MAX_BATCH)
            .map(|i| json!({ "jsonrpc": "2.0", "id": i, "method": "rand_chainId", "params": [] }))
            .collect();
        let big = err(json!(over)).await;
        assert_eq!(big["error"]["code"], -32600);
        assert!(big["error"]["message"].as_str().unwrap().contains(&MAX_BATCH.to_string()));

        // Not an object and not an array.
        assert_eq!(err(json!("hello")).await["error"]["code"], -32600);
    }

    /// Notifications are refused rather than silently dropped: every request here either reads (the
    /// answer is the point) or submits (a dropped submission is an invisible wallet bug), and
    /// refusing keeps one response per request so a client can correlate by position.
    #[tokio::test]
    async fn a_notification_is_refused_with_a_null_id() {
        let (_d, st, _gs) = chain();
        let (_, Json(v)) = handle(
            State(st.clone()),
            Ok(Json(json!([
                { "jsonrpc": "2.0", "method": "rand_chainId", "params": [] },
                { "jsonrpc": "2.0", "id": null, "method": "rand_chainId", "params": [] }
            ]))),
        )
        .await;
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 2, "one response per request, notifications included");
        assert_eq!(rows[0]["error"]["code"], -32600);
        assert!(rows[0]["error"]["message"].as_str().unwrap().contains("notification"));
        assert_eq!(rows[0]["id"], Value::Null);
        // An explicit null id is a request, not a notification, and is answered as always.
        assert_eq!(rows[1]["result"], json!(st.chain_id));
    }

    /// A request object that does not deserialize at all still gets a response, with the id it
    /// carried if it carried a readable one.
    #[tokio::test]
    async fn an_undecodable_request_object_still_gets_a_response() {
        let (_d, st, _gs) = chain();
        let (_, Json(v)) = handle(
            State(st.clone()),
            Ok(Json(json!([
                { "jsonrpc": "2.0", "id": 4 },                      // no method
                { "jsonrpc": "2.0", "id": 5, "method": 7 }          // method is not a string
            ]))),
        )
        .await;
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(row["error"]["code"], -32600, "row {i}");
            assert_eq!(row["id"], json!(4 + i as u64), "the id is echoed even when nothing else parses");
        }
    }

    /// An element that is not an object at all is an element like any other: it gets its own error
    /// response with a null id, and the valid requests around it are still answered.
    ///
    /// The nested arrays are the case worth pinning: batching is decided once, on the *body*, so an
    /// array inside a batch is a bad request object rather than a second batch to recurse into.
    #[tokio::test]
    async fn a_batch_element_that_is_not_an_object_does_not_lose_its_neighbours() {
        let (_d, st, _gs) = chain();
        let (code, Json(v)) = handle(
            State(st.clone()),
            Ok(Json(json!([
                { "jsonrpc": "2.0", "id": 1, "method": "rand_chainId", "params": [] },
                7,
                "not a request",
                [],
                [{ "jsonrpc": "2.0", "id": 8, "method": "rand_chainId", "params": [] }],
                { "jsonrpc": "2.0", "id": 2, "method": "rand_chainId", "params": [] }
            ]))),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 6, "one response per element, whatever the element was");
        assert_eq!(rows[0]["result"], json!(st.chain_id));
        assert_eq!(rows[5]["result"], json!(st.chain_id));
        for i in 1..5 {
            assert_eq!(rows[i]["error"]["code"], -32600, "row {i}");
            assert_eq!(rows[i]["id"], Value::Null, "row {i}: nothing to echo");
            assert!(rows[i].get("result").is_none(), "row {i}: an error response carries no result");
        }
    }

    #[tokio::test]
    async fn version_reports_build_and_chain() {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let (_d, st) = state_for(&gs);
        let v = ok(&st, "rand_getVersion", json!([])).await;
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
        // The full 40-hex commit, `-dirty` when tracked files differed at build time, or
        // "unknown" when neither git nor a `.git-rev` could say — never a short or stale form.
        let sha = v["git_sha"].as_str().unwrap();
        let commit = sha.strip_suffix("-dirty").unwrap_or(sha);
        assert!(
            sha == "unknown" || (commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
            "{v}"
        );
        assert_eq!(v["chain_id"], 7);
        assert!(v["hc_bundle"].is_string());
        assert!(v["fri_profile"].is_string());
    }

    #[tokio::test]
    async fn genesis_hash_is_the_stored_one() {
        let gs = genesis_with(7, vec![alloc_note(20, 1_000)]);
        let (_d, st) = state_for(&gs);
        let v = ok(&st, "rand_getGenesisHash", json!([])).await;
        assert_eq!(v, json!(gs.hash().to_hex()));
    }

    #[test]
    fn health_reads_ok_syncing_and_behind() {
        let mut s = NodeStatus { height: 100, sync_target: 101, ..NodeStatus::default() };
        assert_eq!(health_json(&s), json!({ "status": "ok" }));
        s.sync_target = 140;
        s.sync_inflight_age_ms = Some(20);
        assert_eq!(health_json(&s), json!({ "status": "syncing", "behind": 40 }));
        s.sync_inflight_age_ms = None;
        assert_eq!(health_json(&s), json!({ "status": "behind", "behind": 40 }));
    }
}
