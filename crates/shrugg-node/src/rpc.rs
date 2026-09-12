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
use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shrugg_core::confidential::ConfidentialExecutor;
use shrugg_core::notes::{word8_to_hex, Envelope};
use shrugg_core::{Action, Hash, ShieldedAddress, Transaction, TOKEN_DECIMALS, TOKEN_SYMBOL};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot};

/// The most rows one paged read may return. A wallet scanning from zero pages through the tree;
/// an unbounded `limit` would let one request pull the whole pool into memory.
const MAX_PAGE: usize = 1000;

/// The longest string any RPC parameter may offer as a shielded address (spec ruling 3). See
/// `parse_shielded` for why this is checked before the address is parsed rather than after.
const MAX_ADDRESS_CHARS: usize = 2000;

/// Snapshot the node loop keeps up to date for RPC readers.
#[derive(Clone, Debug, Default, Serialize)]
pub struct NodeStatus {
    pub height: u64,
    pub head_hash: String,
    pub view: u64,
    pub high_qc_view: u64,
    pub syncing: bool,
    pub sync_target: u64,
    pub peer_count: usize,
    pub mempool_size: usize,
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
}

/// The answer to [`NodeCommand::Epoch`]: the current epoch, its length, and the sets of this
/// epoch and the next, as addresses.
#[derive(Clone, Debug, Default)]
pub struct EpochInfo {
    pub epoch: u64,
    pub epoch_blocks: u64,
    /// The set the next block is proposed and voted by.
    pub current: Vec<shrugg_core::Address>,
    /// What the next epoch's set would be if this epoch ended now (spec §8). It is a projection,
    /// not a commitment: every bond and unbond before the boundary still moves it.
    pub next: Vec<shrugg_core::Address>,
}

#[derive(Clone)]
pub struct RpcState {
    pub storage: Arc<Storage>,
    pub status: Arc<RwLock<NodeStatus>>,
    pub node: mpsc::Sender<NodeCommand>,
    pub chain_id: u64,
    /// Needed by `shrugg_getWitness`, which rebuilds the tree to fold a path.
    pub executor: Arc<dyn ConfidentialExecutor>,
}

#[derive(Deserialize)]
struct Request {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    id: Value,
}

struct RpcError {
    code: i64,
    message: String,
}

impl RpcError {
    fn invalid_params(m: impl Into<String>) -> RpcError {
        RpcError { code: -32602, message: m.into() }
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

pub async fn serve(addr: SocketAddr, state: RpcState) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    // Axum's default body limit is 2 MiB, but a bundle-carrying transaction with a
    // near-maximum proof is larger than that once hex-encoded inside JSON.
    let body_limit = 2 * shrugg_core::gas::MAX_PROOF_BYTES + 256 * 1024;
    let app = Router::new()
        .route("/", post(handle))
        .layer(axum::extract::DefaultBodyLimit::max(body_limit))
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

async fn handle(State(st): State<RpcState>, Json(req): Json<Request>) -> Json<Value> {
    let id = req.id.clone();
    match dispatch(&st, &req).await {
        Ok(result) => Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
        Err(e) => Json(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": e.code, "message": e.message } })),
    }
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

fn param<T: serde::de::DeserializeOwned>(params: &Value, idx: usize, name: &str) -> Result<T, RpcError> {
    let v = params.get(idx).ok_or_else(|| RpcError::invalid_params(format!("missing param {name}")))?;
    serde_json::from_value(v.clone()).map_err(|e| RpcError::invalid_params(format!("bad param {name}: {e}")))
}

fn parse_hash(params: &Value, idx: usize) -> Result<Hash, RpcError> {
    let s: String = param(params, idx, "hash")?;
    Hash::from_hex(&s).map_err(|e| RpcError::invalid_params(format!("hash: {e}")))
}

/// A `shrugg1…` shielded address.
///
/// The length is checked *before* parsing: `ShieldedAddress::parse` base58-decodes the whole
/// string before it ever looks at the decoded length, and base58 decoding is quadratic in the
/// input. This runs on a tokio worker shared with the node loop, so an unbounded parameter would
/// let one request stall consensus. A real address is `shrugg1` plus ~1663 base58 characters
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

fn block_json(b: &shrugg_core::Block) -> Value {
    json!({
        "hash": b.hash().to_hex(),
        "height": b.height(),
        "view": b.view(),
        "parent": b.parent().to_hex(),
        "proposer": b.proposer().to_base58(),
        "timestamp_ms": b.header.timestamp_ms,
        "tx_root": b.header.tx_root.to_hex(),
        "state_root": b.header.state_root.to_hex(),
        "justify_view": b.header.justify.view,
        "tx_count": b.transactions.len(),
        "transactions": b.transactions.iter().map(tx_json).collect::<Vec<_>>(),
    })
}

/// What a block explorer can say about a transaction — which is, deliberately, almost nothing:
/// the bundle's public fields (none of which name a party) and the shape of its action. Envelope
/// and proof are reported by length only; anyone who wants the bytes can fetch the block.
/// A bundle's public fields — none of which names a party. Used for the transaction's own
/// bundle and, since S3's `BridgeBurn`, for the asset bundle riding inside the action.
fn bundle_json(b: &shrugg_core::Bundle) -> Value {
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

fn tx_json(t: &Transaction) -> Value {
    let bundle = t.bundle.as_ref().map(bundle_json);
    let action = match &t.action {
        Action::None => json!({ "kind": "none" }),
        Action::Mint { cm, amount, minter, .. } => json!({
            "kind": "mint", "cm": word8_to_hex(cm), "amount": amount, "minter": minter.address().to_base58()
        }),
        Action::Deploy { base_pc, words } => json!({
            "kind": "deploy", "program": shrugg_core::program::program_id(*base_pc, words).to_hex(), "words": words.len()
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
        // No amount: it is inside the attestation, which S3's bridge decoder reads. The
        // recipient is public in this transaction only — the note's later spend is not.
        Action::BridgeAttest { attestation, recipient, .. } => json!({
            "kind": "bridge_attest", "attestation_len": attestation.len(), "recipient": recipient.to_string()
        }),
        Action::BridgeBurn { asset_bundle, asset, amount, relayer_fee, to_chain, to } => json!({
            "kind": "bridge_burn", "asset": asset, "amount": amount, "relayer_fee": relayer_fee,
            "to_chain": to_chain, "to": hex::encode(to),
            "asset_bundle": bundle_json(asset_bundle),
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
        "shrugg_chainId" => Ok(json!(st.chain_id)),
        "shrugg_tokenInfo" => Ok(json!({ "symbol": TOKEN_SYMBOL, "decimals": TOKEN_DECIMALS })),
        "shrugg_sendTransaction" => {
            let raw: String = param(p, 0, "tx")?;
            let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(&raw))
                .map_err(|_| RpcError::invalid_params("tx must be hex"))?;
            let tx = Transaction::decode(&bytes).map_err(|e| RpcError::invalid_params(format!("tx decode: {e}")))?;
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
        "shrugg_mint" => {
            let to = parse_shielded(p, 0)?;
            let amount: u64 = match p.get(1) {
                None | Some(Value::Null) => shrugg_core::FAUCET_MAX_UNITS,
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
        "shrugg_getCommitments" => {
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
        "shrugg_getNullifiers" => {
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
        // A node that caught up in one sync batch longer than the anchor window only stores
        // rows for the heights that batch covered, so `getAnchor` can answer "no anchor at
        // height h" for a height the chain really did pass through; ask for the head instead,
        // which is the only anchor a prover should build against anyway.
        "shrugg_getAnchor" => {
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
        "shrugg_getWitness" => {
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
        "shrugg_getTreeInfo" => {
            let next_index = st.storage.notes_count().map_err(RpcError::internal)?;
            let root = st.storage.tree().map_err(RpcError::internal)?.root();
            let nullifiers = st.storage.nullifiers_count().map_err(RpcError::internal)?;
            Ok(json!({ "next_index": next_index, "root": word8_to_hex(&root), "nullifiers": nullifiers }))
        }
        // ---- confidential computation ----
        "shrugg_getProgram" => {
            let id = parse_hash(p, 0)?;
            match st.storage.program(&id).map_err(RpcError::internal)? {
                None => Ok(Value::Null),
                Some(r) => Ok(json!({
                    "id": r.id.to_hex(), "base_pc": r.base_pc, "words_len": r.words.len(),
                    "code_hash": hex::encode(&r.code_hash), "deployed_at": r.deployed_at
                })),
            }
        }
        "shrugg_getProgramCode" => {
            let id = parse_hash(p, 0)?;
            Ok(st
                .storage
                .program(&id)
                .map_err(RpcError::internal)?
                .map(|r| json!({ "base_pc": r.base_pc, "words": r.words }))
                .unwrap_or(Value::Null))
        }
        "shrugg_getReceipt" => {
            let h = parse_hash(p, 0)?;
            Ok(st
                .storage
                .receipt(&h)
                .map_err(RpcError::internal)?
                .map(|r| {
                    json!({
                        "tx": r.tx.to_hex(), "program": r.program.to_hex(), "tier": r.tier, "outputs": r.outputs,
                        "height": r.height, "index": r.index
                    })
                })
                .unwrap_or(Value::Null))
        }
        "shrugg_estimateFee" => {
            let spec: Value = param(p, 0, "spec")?;
            let kind = spec.get("kind").and_then(|k| k.as_str()).unwrap_or_default();
            let fee = match kind {
                // Every transaction that carries a bundle pays the base; `Action::None` is the
                // plain shielded transfer, so its floor is the base alone.
                "bundle" => shrugg_core::gas::BUNDLE_BASE,
                "deploy" => {
                    let words = spec.get("words").and_then(|w| w.as_u64()).unwrap_or(0) as usize;
                    if words > shrugg_core::gas::MAX_PROGRAM_WORDS {
                        return Err(RpcError::invalid_params(format!(
                            "words must be at most {}",
                            shrugg_core::gas::MAX_PROGRAM_WORDS
                        )));
                    }
                    shrugg_core::gas::fee_floor(&Action::Deploy { base_pc: 0, words: vec![0; words] })
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
                    if !(shrugg_core::gas::MIN_TIER..=shrugg_core::gas::MAX_TIER).contains(&tier) || tier % 2 != 0 {
                        return Err(RpcError::invalid_params("tier must be one of 10, 12, 14, 16, 18, 20"));
                    }
                    shrugg_core::gas::BUNDLE_BASE + shrugg_core::gas::call_fee(tier)
                }
                _ => return Err(RpcError::invalid_params("kind must be bundle, deploy or call")),
            };
            Ok(json!(fee.to_string()))
        }
        "shrugg_getTransaction" => {
            let h = parse_hash(p, 0)?;
            match st.storage.tx_location(&h).map_err(RpcError::internal)? {
                None => Ok(Value::Null),
                Some((height, index)) => {
                    let b = st
                        .storage
                        .block_by_height(height)
                        .map_err(RpcError::internal)?
                        .ok_or_else(|| RpcError::not_found("block missing"))?;
                    let tx = b.transactions.get(index as usize).ok_or_else(|| RpcError::not_found("tx index"))?;
                    Ok(json!({ "height": height, "index": index, "block_hash": b.hash().to_hex(), "tx": tx_json(tx) }))
                }
            }
        }
        "shrugg_getBlockByHeight" => {
            let h: u64 = param(p, 0, "height")?;
            Ok(st.storage.block_by_height(h).map_err(RpcError::internal)?.map(|b| block_json(&b)).unwrap_or(Value::Null))
        }
        "shrugg_getBlockByHash" => {
            let h = parse_hash(p, 0)?;
            Ok(st.storage.block_by_hash(&h).map_err(RpcError::internal)?.map(|b| block_json(&b)).unwrap_or(Value::Null))
        }
        "shrugg_getHead" => {
            let head = st.storage.head().map_err(RpcError::internal)?;
            let s = st.status.read().unwrap_or_else(|e| e.into_inner()).clone();
            Ok(json!({ "height": head.height, "hash": head.hash.to_hex(), "view": s.view }))
        }
        "shrugg_syncStatus" | "shrugg_status" => {
            let s = st.status.read().unwrap_or_else(|e| e.into_inner()).clone();
            Ok(serde_json::to_value(s).map_err(RpcError::internal)?)
        }
        "shrugg_getPeers" => {
            let (reply, rx) = oneshot::channel();
            st.node.send(NodeCommand::Peers { reply }).await.map_err(|_| RpcError::internal("node loop closed"))?;
            let peers = rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))?;
            Ok(serde_json::to_value(peers).map_err(RpcError::internal)?)
        }
        // Since phase S2 this is the *register* (spec §8), not the genesis set: every address
        // that has ever bonded, whether or not it is in an epoch's set today. `active` is what
        // says which of them are running the current epoch.
        "shrugg_getValidators" => {
            let register = st.storage.register().map_err(RpcError::internal)?;
            let active = epoch_info(st).await?.current;
            let out: Vec<Value> = register
                .iter()
                .map(|(addr, e)| {
                    json!({
                        "address": addr.to_base58(),
                        // Amounts go out as decimal strings: JSON numbers are not safe integers
                        // past 2^53, and a stake is 10^9 units per SHRUGG.
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
        "shrugg_getEpoch" => {
            let info = epoch_info(st).await?;
            Ok(json!({
                "epoch": info.epoch,
                "epoch_blocks": info.epoch_blocks,
                "next_set": info.next.iter().map(|a| a.to_base58()).collect::<Vec<_>>(),
            }))
        }
        // The supply audit (`ledger::supply`). Note values are hidden, but every crossing of the
        // pool's boundary is public, so this is exact rather than an estimate — and
        // `--verify-chain` recomputes every counter in it by replaying the chain.
        "shrugg_getSupply" => {
            let height = st.storage.head().map_err(RpcError::internal)?.height;
            let supply = st.storage.supply().map_err(RpcError::internal)?;
            let register = st.storage.register().map_err(RpcError::internal)?;
            let audit = shrugg_core::ledger::Audit::new(supply, shrugg_core::ledger::register_total(&register));
            Ok(json!({
                "height": height,
                "genesis_deposited": supply.genesis_deposited.to_string(),
                "genesis_staked": supply.genesis_staked.to_string(),
                "faucet_minted": supply.faucet_minted.to_string(),
                "withdraw_deposited": supply.withdraw_deposited.to_string(),
                "fees_paid": supply.fees_paid.to_string(),
                "burned": supply.burned.to_string(),
                "pool_value": audit.pool_value.to_string(),
                "register_total": audit.register_total.to_string(),
                "total_supply": audit.total_supply().to_string(),
                "invariant_holds": audit.invariant_holds(),
            }))
        }
        other => Err(RpcError { code: -32601, message: format!("unknown method {other}") }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::fixtures::{self, alloc_note, bundle_fee, bundle_tx, genesis_with, key, make_block};
    use shrugg_core::confidential::StubExecutor;
    use shrugg_core::genesis::GenesisState;
    use shrugg_core::notes::DEPTH;
    use shrugg_core::Word8;

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
        let (tx, mut rx) = mpsc::channel(4);
        let info = EpochInfo {
            epoch: 0,
            epoch_blocks: gs.epoch_blocks,
            current: gs.validators.iter().map(|v| v.address()).collect(),
            next: gs.ledger.derive_next_set().iter().map(|v| v.address()).collect(),
        };
        tokio::spawn(async move {
            while let Some(cmd) = rx.recv().await {
                if let NodeCommand::Epoch { reply } = cmd {
                    let _ = reply.send(info.clone());
                }
            }
        });
        let st = RpcState {
            storage,
            status: Arc::new(RwLock::new(NodeStatus::default())),
            node: tx,
            chain_id: gs.chain_id,
            executor: Arc::new(StubExecutor),
        };
        (dir, st)
    }

    async fn call(st: &RpcState, method: &str, params: Value) -> Result<Value, RpcError> {
        dispatch(st, &Request { jsonrpc: None, method: method.into(), params, id: Value::Null }).await
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
    fn chain() -> (tempfile::TempDir, RpcState, GenesisState) {
        let gs = genesis_with(1, vec![alloc_note(20, 1_000), alloc_note(21, 2_000)]);
        let (dir, st) = state_for(&gs);
        let mut ledger = gs.ledger.clone();
        let tx = bundle_tx(&ledger, [nf(1), nf(2)], [cm(1), cm(2)], bundle_fee());
        let b1 = make_block(&gs.block, &mut ledger, vec![tx], &key(1));
        st.storage.commit(std::slice::from_ref(&b1), &ledger, &[]).unwrap();
        (dir, st, gs)
    }

    #[tokio::test]
    async fn get_commitments_pages_in_order() {
        let (_d, st, _gs) = chain();
        let all = ok(&st, "shrugg_getCommitments", json!([0, 100])).await;
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
        let page = ok(&st, "shrugg_getCommitments", json!([2, 100])).await;
        assert_eq!(page.as_array().unwrap(), &all[2..]);
        // A limit smaller than the tail truncates it, and one past the end is empty.
        assert_eq!(ok(&st, "shrugg_getCommitments", json!([0, 2])).await.as_array().unwrap().len(), 2);
        assert_eq!(ok(&st, "shrugg_getCommitments", json!([9, 100])).await, json!([]));
        // An oversized limit is clamped, not refused.
        assert_eq!(ok(&st, "shrugg_getCommitments", json!([0, 10_000])).await.as_array().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn get_nullifiers_and_tree_info_track_the_chain() {
        let (_d, st, _gs) = chain();
        let nfs = ok(&st, "shrugg_getNullifiers", json!([0, 100])).await;
        let nfs = nfs.as_array().unwrap();
        assert_eq!(nfs.len(), 2);
        for row in nfs {
            assert_eq!(row["height"], 1);
        }
        let seen: Vec<&str> = nfs.iter().map(|r| r["nullifier"].as_str().unwrap()).collect();
        assert!(seen.contains(&word8_to_hex(&nf(1)).as_str()));
        assert!(seen.contains(&word8_to_hex(&nf(2)).as_str()));
        // Asking from a later height skips them.
        assert_eq!(ok(&st, "shrugg_getNullifiers", json!([2, 100])).await, json!([]));

        let info = ok(&st, "shrugg_getTreeInfo", json!([])).await;
        assert_eq!(info["next_index"], 4);
        assert_eq!(info["nullifiers"], 2);
        assert_eq!(info["root"], word8_to_hex(&st.storage.tree().unwrap().root()));
    }

    #[tokio::test]
    async fn get_anchor_serves_the_head_and_a_named_height() {
        let (_d, st, _gs) = chain();
        let head = ok(&st, "shrugg_getAnchor", json!([])).await;
        assert_eq!(head["height"], 1);
        assert_eq!(head["root"], word8_to_hex(&st.storage.tree().unwrap().root()));
        let genesis = ok(&st, "shrugg_getAnchor", json!([0])).await;
        assert_eq!(genesis["height"], 0);
        assert_ne!(genesis["root"], head["root"], "the block changed the tree");
        // A height the chain has not reached is not-found, not an internal error.
        assert_eq!(call(&st, "shrugg_getAnchor", json!([99])).await.unwrap_err().code, -32001);
    }

    #[tokio::test]
    async fn get_witness_matches_storage() {
        let (_d, st, _gs) = chain();
        for index in 0..4u64 {
            let v = ok(&st, "shrugg_getWitness", json!([index])).await;
            let (root, path) = st.storage.witness(index, &StubExecutor).unwrap().unwrap();
            assert_eq!(v["index"], index);
            assert_eq!(v["root"], word8_to_hex(&root));
            let got: Vec<String> = v["path"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().into()).collect();
            assert_eq!(got, path.iter().map(word8_to_hex).collect::<Vec<_>>());
            assert_eq!(got.len(), DEPTH);
        }
        // A leaf past the end is null, not an error.
        assert_eq!(ok(&st, "shrugg_getWitness", json!([4])).await, Value::Null);
    }

    #[tokio::test]
    async fn mint_rejects_a_bad_address() {
        let gs = fixtures::genesis(1);
        let (_d, st) = state_for(&gs);
        let err = call(&st, "shrugg_mint", json!(["not-an-address"])).await.unwrap_err();
        assert_eq!(err.code, -32602);
        // The message carries the address parser's own reason, not a generic one.
        let reason = ShieldedAddress::parse("not-an-address").unwrap_err().to_string();
        assert!(err.message.contains(&reason), "{} does not contain {reason}", err.message);
        // A well-formed address gets past parsing and dies at the (dropped) node channel.
        let good = shrugg_zkvm::address::address_of(&shrugg_zkvm::notes::SpendKey([7; 8]).viewing_key()).to_string();
        assert_eq!(call(&st, "shrugg_mint", json!([good])).await.unwrap_err().code, -32603);
    }

    /// An over-long address parameter is refused on its length, before it reaches the base58
    /// decoder — which is quadratic in its input and runs on a worker the node loop shares.
    #[tokio::test]
    async fn an_oversized_address_is_refused_before_it_is_parsed() {
        let gs = fixtures::genesis(1);
        let (_d, st) = state_for(&gs);
        let huge = format!("shrugg1{}", "1".repeat(3000));
        let err = call(&st, "shrugg_mint", json!([huge])).await.unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("3007 characters"), "{}", err.message);
        assert!(err.message.contains(&MAX_ADDRESS_CHARS.to_string()), "{}", err.message);
        // The cap is generous: a real address is well under it and still parses.
        let good = shrugg_zkvm::address::address_of(&shrugg_zkvm::notes::SpendKey([7; 8]).viewing_key()).to_string();
        assert!(good.len() < MAX_ADDRESS_CHARS, "a real address is {} characters", good.len());
        assert!(ShieldedAddress::parse(&good).is_ok());
    }

    #[tokio::test]
    async fn estimate_fee_answers_per_action_kind() {
        let gs = fixtures::genesis(1);
        let (_d, st) = state_for(&gs);
        let fee = |spec| ok(&st, "shrugg_estimateFee", json!([spec]));
        assert_eq!(fee(json!({"kind": "bundle"})).await, shrugg_core::gas::BUNDLE_BASE.to_string());
        assert_eq!(
            fee(json!({"kind": "deploy", "words": 10})).await,
            shrugg_core::gas::fee_floor(&Action::Deploy { base_pc: 0, words: vec![0; 10] }).to_string()
        );
        assert_eq!(
            fee(json!({"kind": "call", "tier": 12})).await,
            (shrugg_core::gas::BUNDLE_BASE + shrugg_core::gas::call_fee(12)).to_string()
        );
        // An odd or out-of-range tier is a parameter error, never a truncated `as u8`.
        for bad in [11u64, 9, 22, 256] {
            let e = call(&st, "shrugg_estimateFee", json!([{"kind": "call", "tier": bad}])).await.unwrap_err();
            assert_eq!(e.code, -32602, "tier {bad}");
        }
        assert_eq!(call(&st, "shrugg_estimateFee", json!([{"kind": "transfer"}])).await.unwrap_err().code, -32602);
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
            matches!(err, shrugg_core::TxError::UnknownAnchor),
            "the anchor is checked before the digest it no longer matches: {err}"
        );
        assert!(err.to_string().contains("anchor"), "{err}");
        // The transport half: a malformed transaction is -32602 before the node is ever asked.
        assert_eq!(call(&st, "shrugg_sendTransaction", json!(["zz"])).await.unwrap_err().code, -32602);
        assert_eq!(call(&st, "shrugg_sendTransaction", json!(["00"])).await.unwrap_err().code, -32602);
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
        let v = ok(&st, "shrugg_status", json!([])).await;
        assert_eq!(v["notes"], 4);
        assert_eq!(v["nullifiers"], 2);
        assert_eq!(v["tree_root"], word8_to_hex(&st.storage.tree().unwrap().root()));
        assert_eq!(v["hc_bundle"], word8_to_hex(&fixtures::HC));
    }

    #[tokio::test]
    async fn a_transaction_reads_back_without_naming_a_party() {
        let (_d, st, _gs) = chain();
        let b1 = st.storage.block_by_height(1).unwrap().unwrap();
        let tx = &b1.transactions[0];
        let v = ok(&st, "shrugg_getTransaction", json!([tx.hash().to_hex()])).await;
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
        assert_eq!(ok(&st, "shrugg_getTransaction", json!([Hash::ZERO.to_hex()])).await, Value::Null);
    }

    /// Phase S2: the register, not the genesis set. A validator that has bonded in but whose
    /// epoch has not arrived is listed with everything the register holds about it and
    /// `active: false` — which is the whole reason the row carries the flag.
    #[tokio::test]
    async fn validators_report_the_whole_register_and_who_is_active() {
        let (_d, st, _gs) = chain();
        let newcomer = key(9);
        let payout = ShieldedAddress { pk: [3; 8], kem_ek: vec![4; shrugg_core::notes::KEM_EK_BYTES] };
        st.storage
            .overwrite_validator_for_testing(
                &newcomer.address(),
                &shrugg_core::ledger::ValidatorEntry {
                    public_key: newcomer.public_key().clone(),
                    stake: 700,
                    pending: vec![(4, 250)],
                    rewards: 11,
                    payout: payout.clone(),
                    nonce: 3,
                },
            )
            .unwrap();

        let v = ok(&st, "shrugg_getValidators", json!([])).await;
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 2, "every registered validator, in address order");
        let row = |addr: shrugg_core::Address| {
            rows.iter().find(|r| r["address"] == addr.to_base58()).expect("listed").clone()
        };

        let genesis = row(key(1).address());
        // Every amount is a decimal string: JSON numbers are not safe integers past 2^53, and a
        // stake is 10^9 units per SHRUGG.
        assert_eq!(genesis["stake"], Value::String(shrugg_core::ledger::staking::MIN_STAKE.to_string()));
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
        let v = ok(&st, "shrugg_getEpoch", json!([])).await;
        assert_eq!(v["epoch"], 0);
        assert_eq!(v["epoch_blocks"], gs.epoch_blocks);
        // The only validator meets the minimum, so it is what the next epoch would run with.
        assert_eq!(v["next_set"], json!([key(1).address().to_base58()]));
    }

    /// The supply audit: hidden note values, public boundary crossings. The one number that
    /// matters is `invariant_holds` — everything issued is either in the pool or in the register.
    #[tokio::test]
    async fn get_supply_accounts_for_everything_the_chain_issued() {
        // Enough in the pool to pay a fee out of: `chain()`'s two tiny alloc notes are smaller
        // than one bundle base, which is a fixture artefact rather than a chain that could exist.
        let gs = fixtures::genesis_with(1, vec![alloc_note(20, 5 * shrugg_core::UNITS_PER_SHRUGG)]);
        let (_d, st) = state_for(&gs);
        let mut ledger = gs.ledger.clone();
        let tx = bundle_tx(&ledger, [nf(1), nf(2)], [cm(1), cm(2)], bundle_fee());
        let b1 = make_block(&gs.block, &mut ledger, vec![tx], &key(1));
        st.storage.commit(std::slice::from_ref(&b1), &ledger, &[]).unwrap();

        let v = ok(&st, "shrugg_getSupply", json!([])).await;
        let stake = shrugg_core::ledger::staking::MIN_STAKE;
        let alloc = 5 * shrugg_core::UNITS_PER_SHRUGG;
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

    /// S2/S3 scaffold: an explorer can name and summarise every new action the moment one can
    /// be submitted. Amounts that are public by design (the staking register, a burn) are shown;
    /// ciphertexts are lengths only, and an attestation's amount is not guessed at here — S3's
    /// bridge decoder is what reads it.
    #[test]
    fn tx_json_renders_every_new_action_kind() {
        let gs = fixtures::genesis_with(1, vec![]);
        let b = |nfs: [Word8; 2], cms: [Word8; 2]| {
            let t = fixtures::bundle_tx(&gs.ledger, nfs, cms, bundle_fee());
            t.bundle.expect("bundle_tx always carries one")
        };
        let v = shrugg_core::Address([3; 32]);
        let sig = shrugg_core::Signature::empty();
        let recipient = ShieldedAddress { pk: [4; 8], kem_ek: vec![6; 32] };
        let envelope = Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] };

        let j = |action| tx_json(&Transaction::shielded(1, b([nf(1), nf(2)], [cm(1), cm(2)]), action))["action"].clone();

        let bond = j(Action::Bond { validator: v, amount: 500, registration: None });
        assert_eq!(bond["kind"], "bond");
        assert_eq!(bond["validator"], v.to_base58());
        assert_eq!(bond["amount"], 500);
        assert_eq!(bond["registered"], false);

        // The two validator-signed actions ride bundle-less, so they are rendered as they ride.
        let bundle_less = |action| tx_json(&Transaction { chain_id: 1, bundle: None, action });
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

        let at = j(Action::BridgeAttest { attestation: vec![9; 520], recipient: recipient.clone(), r: [5; 8], envelope });
        assert_eq!(at["kind"], "bridge_attest");
        assert_eq!(at["attestation_len"], 520);
        assert_eq!(at["recipient"], recipient.to_string());
        assert!(at["amount"].is_null(), "an attestation's amount is inside it, not on the action");

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
            input_envelope: Some(shrugg_core::CallEnvelope {
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

    #[tokio::test]
    async fn unknown_methods_still_report_method_not_found() {
        let gs = fixtures::genesis(1);
        let (_d, st) = state_for(&gs);
        assert_eq!(call(&st, "shrugg_getBalance", json!([])).await.unwrap_err().code, -32601);
        assert_eq!(call(&st, "shrugg_getAccount", json!([])).await.unwrap_err().code, -32601);
        assert_eq!(call(&st, "shrugg_getBridgeState", json!([])).await.unwrap_err().code, -32601);
    }
}
