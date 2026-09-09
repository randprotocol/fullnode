//! JSON-RPC 2.0 over HTTP. Reads come straight from storage and the shared
//! status snapshot; transaction submission goes to the node loop.

use crate::mempool::MempoolError;
use crate::network::PeerInfo;
use crate::storage::Storage;
use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shrugg_core::{Address, Hash, Transaction, ValidatorSet, TOKEN_DECIMALS, TOKEN_SYMBOL};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot};

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
    pub is_validator: bool,
    pub faucet: bool,
    pub confidential: bool,
    pub fri_profile: String,
    pub programs: u64,
    pub address: Option<String>,
    pub peer_id: String,
}

pub enum NodeCommand {
    SubmitTx { tx: Transaction, reply: oneshot::Sender<Result<Hash, MempoolError>> },
    Peers { reply: oneshot::Sender<Vec<PeerInfo>> },
    /// Testnet faucet: mint `amount` units to `to`, signed by this node.
    Mint { to: Address, amount: u128, reply: oneshot::Sender<Result<Hash, MempoolError>> },
}

#[derive(Clone)]
pub struct RpcState {
    pub storage: Arc<Storage>,
    pub status: Arc<RwLock<NodeStatus>>,
    pub node: mpsc::Sender<NodeCommand>,
    pub validators: ValidatorSet,
    pub chain_id: u64,
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
    let app = Router::new().route("/", post(handle)).with_state(state);
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

fn param<T: serde::de::DeserializeOwned>(params: &Value, idx: usize, name: &str) -> Result<T, RpcError> {
    let v = params.get(idx).ok_or_else(|| RpcError::invalid_params(format!("missing param {name}")))?;
    serde_json::from_value(v.clone()).map_err(|e| RpcError::invalid_params(format!("bad param {name}: {e}")))
}

fn parse_address(params: &Value, idx: usize) -> Result<Address, RpcError> {
    let s: String = param(params, idx, "address")?;
    Address::from_base58(&s).map_err(|e| RpcError::invalid_params(format!("address: {e}")))
}

fn parse_hash(params: &Value, idx: usize) -> Result<Hash, RpcError> {
    let s: String = param(params, idx, "hash")?;
    Hash::from_hex(&s).map_err(|e| RpcError::invalid_params(format!("hash: {e}")))
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

fn tx_json(t: &Transaction) -> Value {
    let kind = match &t.body.kind {
        shrugg_core::TxKind::Transfer { to, amount } => json!({ "type": "transfer", "to": to.to_base58(), "amount": amount.to_string() }),
        shrugg_core::TxKind::Deploy { base_pc, words } => json!({
            "type": "deploy", "base_pc": base_pc, "words_len": words.len(),
            "program": shrugg_core::program::program_id(*base_pc, words).to_hex()
        }),
        shrugg_core::TxKind::Call { program, proof, recipients } => json!({
            "type": "call", "program": program.to_hex(), "proof_len": proof.len(),
            "recipients": recipients.iter().map(|a| a.to_base58()).collect::<Vec<_>>()
        }),
        shrugg_core::TxKind::Mint { to, amount } => json!({ "type": "mint", "to": to.to_base58(), "amount": amount.to_string() }),
        shrugg_core::TxKind::BridgeAttest { attestation } => json!({
            "type": "bridge_attest", "attestation": hex::encode(attestation)
        }),
        shrugg_core::TxKind::BridgeBurn { asset, amount, to_chain, to, fee } => json!({
            "type": "bridge_burn", "asset": asset.to_hex(), "amount": amount.to_string(),
            "to_chain": to_chain, "to": hex::encode(to), "fee": fee.to_string()
        }),
    };
    json!({
        "hash": t.hash().to_hex(),
        "from": t.sender().to_base58(),
        "nonce": t.body.nonce,
        "fee": t.body.fee.to_string(),
        "chain_id": t.body.chain_id,
        "kind": kind,
    })
}

async fn dispatch(st: &RpcState, req: &Request) -> Result<Value, RpcError> {
    let p = &req.params;
    match req.method.as_str() {
        "shrugg_chainId" => Ok(json!(st.chain_id)),
        "shrugg_tokenInfo" => Ok(json!({ "symbol": TOKEN_SYMBOL, "decimals": TOKEN_DECIMALS })),
        "shrugg_getBalance" => {
            let a = parse_address(p, 0)?;
            let acct = st.storage.account(&a).map_err(RpcError::internal)?;
            Ok(json!(acct.balance.to_string()))
        }
        "shrugg_getAccount" => {
            let a = parse_address(p, 0)?;
            let acct = st.storage.account(&a).map_err(RpcError::internal)?;
            Ok(json!({ "address": a.to_base58(), "nonce": acct.nonce, "balance": acct.balance.to_string() }))
        }
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
            let to = parse_address(p, 0)?;
            let amount: u128 = match p.get(1) {
                None | Some(Value::Null) => shrugg_core::FAUCET_MAX_UNITS,
                Some(v) => {
                    let s: String = serde_json::from_value(v.clone()).map_err(|_| RpcError::invalid_params("amount must be a string of units"))?;
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
                Err(e) => Err(RpcError::rejected(e.to_string())),
            }
        }
        "shrugg_getProgram" => {
            let id = parse_hash(p, 0)?;
            match st.storage.program(&id).map_err(RpcError::internal)? {
                None => Ok(Value::Null),
                Some(r) => Ok(json!({
                    "id": r.id.to_hex(), "base_pc": r.base_pc, "words_len": r.words.len(),
                    "code_hash": hex::encode(&r.code_hash), "deployer": r.deployer.to_base58(), "deployed_at": r.deployed_at
                })),
            }
        }
        "shrugg_getProgramCode" => {
            let id = parse_hash(p, 0)?;
            Ok(st.storage.program(&id).map_err(RpcError::internal)?.map(|r| json!({ "base_pc": r.base_pc, "words": r.words })).unwrap_or(Value::Null))
        }
        "shrugg_getReceipt" => {
            let h = parse_hash(p, 0)?;
            Ok(st.storage.receipt(&h).map_err(RpcError::internal)?.map(|r| json!({
                "tx": r.tx.to_hex(), "program": r.program.to_hex(), "tier": r.tier, "outputs": r.outputs,
                "effect": r.effect.map(|(to, amt)| json!({ "to": to.to_base58(), "amount": amt.to_string() })),
                "height": r.height, "index": r.index
            })).unwrap_or(Value::Null))
        }
        "shrugg_estimateFee" => {
            let kind: String = param(p, 0, "kind")?;
            let n: u64 = param(p, 1, "size_or_tier")?;
            let fee = match kind.as_str() {
                "deploy" => shrugg_core::gas::deploy_fee(n as usize),
                "call" => shrugg_core::gas::call_fee(n as u8),
                _ => return Err(RpcError::invalid_params("kind must be deploy or call")),
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
            let s = st.status.read().unwrap().clone();
            Ok(json!({ "height": head.height, "hash": head.hash.to_hex(), "view": s.view }))
        }
        "shrugg_syncStatus" | "shrugg_status" => {
            let s = st.status.read().unwrap().clone();
            Ok(serde_json::to_value(s).map_err(RpcError::internal)?)
        }
        "shrugg_getPeers" => {
            let (reply, rx) = oneshot::channel();
            st.node.send(NodeCommand::Peers { reply }).await.map_err(|_| RpcError::internal("node loop closed"))?;
            let peers = rx.await.map_err(|_| RpcError::internal("node loop dropped reply"))?;
            Ok(serde_json::to_value(peers).map_err(RpcError::internal)?)
        }
        "shrugg_getValidators" => Ok(json!(st
            .validators
            .iter()
            .map(|v| json!({ "address": v.address().to_base58(), "stake": v.stake.to_string() }))
            .collect::<Vec<_>>())),
        other => Err(RpcError { code: -32601, message: format!("unknown method {other}") }),
    }
}
