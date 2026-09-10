//! JSON-RPC 2.0 over HTTP. Reads come straight from storage and the shared
//! status snapshot; transaction submission goes to the node loop.

use crate::mempool::MempoolError;
use crate::network::PeerInfo;
use crate::storage::Storage;
use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shrugg_core::bridge::{asset_id, AssetId};
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

/// A bridged asset id: 64 hex characters, with or without `0x`.
fn parse_asset(params: &Value, idx: usize) -> Result<AssetId, RpcError> {
    let s: String = param(params, idx, "asset")?;
    Hash::from_hex(&s).map_err(|e| RpcError::invalid_params(format!("asset: {e}")))
}

/// A 32-byte token address: 64 hex characters, with or without `0x`. EVM and
/// Tron addresses are the 20 bytes left-padded to 32.
fn parse_bytes32(params: &Value, idx: usize, name: &str) -> Result<[u8; 32], RpcError> {
    let s: String = param(params, idx, name)?;
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(&s))
        .map_err(|_| RpcError::invalid_params(format!("{name} must be hex")))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| RpcError::invalid_params(format!("{name} must be 32 bytes, got {}", v.len())))
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
        // ---- bridged assets ----
        "shrugg_getAssetBalance" => {
            let a = parse_address(p, 0)?;
            let asset = parse_asset(p, 1)?;
            Ok(json!(st.storage.asset_balance(&asset, &a).map_err(RpcError::internal)?.to_string()))
        }
        "shrugg_getAssets" => {
            let a = parse_address(p, 0)?;
            Ok(json!(st
                .storage
                .assets_of(&a)
                .map_err(RpcError::internal)?
                .into_iter()
                .map(|(asset, chain, token, balance)| json!({
                    "asset": asset.to_hex(),
                    "token_chain": chain,
                    "token_address": hex::encode(token),
                    "balance": balance.to_string(),
                }))
                .collect::<Vec<_>>()))
        }
        "shrugg_getBridgeState" => {
            let Some(meta) = st.storage.bridge_meta().map_err(RpcError::internal)? else {
                return Ok(json!({ "enabled": false }));
            };
            let guardians = meta
                .guardian_sets
                .get(&meta.current_set)
                .map(|s| s.keys.iter().map(hex::encode).collect::<Vec<_>>())
                .unwrap_or_default();
            Ok(json!({
                "enabled": true,
                "emitter": hex::encode(meta.emitter),
                "emitters": meta.emitters.iter().map(|(c, a)| (c.to_string(), json!(hex::encode(a)))).collect::<serde_json::Map<String, Value>>(),
                "guardian_set_index": meta.current_set,
                "guardians": guardians,
                "burn_sequence": meta.burn_sequence,
                "assets": meta.assets.iter().map(|(asset, (chain, token))| json!({
                    "asset": asset.to_hex(), "token_chain": chain, "token_address": hex::encode(token),
                })).collect::<Vec<_>>(),
            }))
        }
        "shrugg_getBridgeBurn" => {
            let sequence: u64 = param(p, 0, "sequence")?;
            Ok(st.storage.bridge_burn(sequence).map_err(RpcError::internal)?.map(|r| json!({
                "sequence": r.sequence, "body_hex": hex::encode(&r.body), "digest": hex::encode(r.digest),
                "tx": r.tx.to_hex(), "height": r.height
            })).unwrap_or(Value::Null))
        }
        "shrugg_bridgeAssetId" => {
            let token_chain: u16 = param(p, 0, "token_chain")?;
            let token_address = parse_bytes32(p, 1, "token_address")?;
            Ok(json!(asset_id(token_chain, &token_address).to_hex()))
        }
        "shrugg_getValidators" => Ok(json!(st
            .validators
            .iter()
            .map(|v| json!({ "address": v.address().to_base58(), "stake": v.stake.to_string() }))
            .collect::<Vec<_>>())),
        other => Err(RpcError { code: -32601, message: format!("unknown method {other}") }),
    }
}

#[cfg(test)]
mod tests {

    /// A well-formed EVM recipient: 12 zero bytes then 20 address bytes
    /// (spec 3.5), the shape `BridgeState::check_burn` requires for the
    /// EVM-family chains 2, 3 and 4.
    fn evm_to() -> [u8; 32] {
        let mut t = [0u8; 32];
        t[12..].copy_from_slice(&[0x22u8; 20]);
        t
    }
    use super::*;
    use crate::storage::fixtures::{attestation, bridged_asset, bridged_genesis, genesis, key, make_block, TOKEN};
    use shrugg_core::genesis::GenesisState;
    use shrugg_core::Transaction;

    /// An `RpcState` over a fresh database holding `gs`, with a node channel
    /// nothing reads (these methods answer straight from storage).
    fn state_for(gs: &GenesisState) -> (tempfile::TempDir, RpcState) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(crate::storage::Storage::open(dir.path()).unwrap());
        storage.init_genesis(gs).unwrap();
        // No test here reaches the node loop: every bridge read is answered
        // from storage, so the receiver is dropped straight away.
        let (tx, _) = mpsc::channel(4);
        let st = RpcState {
            storage,
            status: Arc::new(RwLock::new(NodeStatus::default())),
            node: tx,
            validators: gs.validators.clone(),
            chain_id: gs.chain_id,
        };
        (dir, st)
    }

    async fn call(st: &RpcState, method: &str, params: Value) -> Result<Value, RpcError> {
        dispatch(st, &Request { jsonrpc: None, method: method.into(), params, id: Value::Null }).await
    }

    async fn ok(st: &RpcState, method: &str, params: Value) -> Value {
        call(st, method, params).await.unwrap_or_else(|e| panic!("{method}: {}", e.message))
    }

    /// A bridged chain with one committed mint: 1000 units to bob, 10 of them
    /// the submitter's bridge fee.
    fn bridged_chain() -> (tempfile::TempDir, RpcState, GenesisState) {
        let gs = bridged_genesis(1);
        let (dir, st) = state_for(&gs);
        let (alice, bob) = (key(1), key(2));
        let mut ledger = gs.ledger.clone();
        ledger.set_timestamp_ms(1);
        ledger.set_height(1);
        let att = Transaction::bridge_attest(&alice, 1, 0, attestation(0, &bob.address(), 1_000, 10), 1);
        let b1 = make_block(&gs.block, &mut ledger, vec![att], &alice);
        st.storage.commit(std::slice::from_ref(&b1), &ledger).unwrap();
        (dir, st, gs)
    }

    /// Shorthand: `shrugg_getAssetBalance` of `addr` in the test asset.
    async fn asset_balance(st: &RpcState, addr: &str, asset: &str) -> Value {
        ok(st, "shrugg_getAssetBalance", json!([addr, asset])).await
    }

    #[tokio::test]
    async fn asset_balance_and_assets_report_bridged_holdings() {
        let (_d, st, _gs) = bridged_chain();
        let (alice, bob) = (key(1).address().to_base58(), key(2).address().to_base58());
        let asset = bridged_asset().to_hex();
        assert_eq!(asset_balance(&st, &bob, &asset).await, "990");
        assert_eq!(asset_balance(&st, &alice, &asset).await, "10");
        // An address holding nothing, and an unknown asset, are both "0".
        let carol = key(3).address().to_base58();
        assert_eq!(asset_balance(&st, &carol, &asset).await, "0");
        assert_eq!(asset_balance(&st, &bob, &Hash::ZERO.to_hex()).await, "0");

        let assets = ok(&st, "shrugg_getAssets", json!([bob.clone()])).await;
        assert_eq!(
            assets,
            json!([{ "asset": asset, "token_chain": 2, "token_address": hex::encode(TOKEN), "balance": "990" }])
        );
        assert_eq!(ok(&st, "shrugg_getAssets", json!([carol])).await, json!([]));

        // Bad parameters are -32602, not a panic.
        let bad = |params| async { call(&st, "shrugg_getAssetBalance", params).await.unwrap_err().code };
        assert_eq!(bad(json!(["not-base58", asset])).await, -32602);
        assert_eq!(bad(json!([bob.clone(), "zz"])).await, -32602);
        assert_eq!(bad(json!([bob])).await, -32602);
    }

    #[tokio::test]
    async fn bridge_state_reports_guardians_emitters_and_registry() {
        let (_d, st, _gs) = bridged_chain();
        let v = ok(&st, "shrugg_getBridgeState", json!([])).await;
        assert_eq!(v["enabled"], true);
        assert_eq!(v["emitter"], hex::encode([1u8; 32]));
        assert_eq!(v["emitters"]["2"], hex::encode([0xeeu8; 32]));
        assert_eq!(v["guardian_set_index"], 0);
        assert_eq!(v["guardians"].as_array().unwrap().len(), 4);
        // The guardian addresses are 40 lowercase hex characters.
        for g in v["guardians"].as_array().unwrap() {
            let s = g.as_str().unwrap();
            assert_eq!(s.len(), 40);
            assert_eq!(s, s.to_lowercase());
        }
        assert_eq!(v["burn_sequence"], 0);
        assert_eq!(
            v["assets"],
            json!([{ "asset": bridged_asset().to_hex(), "token_chain": 2, "token_address": hex::encode(TOKEN) }])
        );
    }

    #[tokio::test]
    async fn bridge_state_is_just_disabled_without_a_bridge_section() {
        let gs = genesis(1);
        let (_d, st) = state_for(&gs);
        assert_eq!(ok(&st, "shrugg_getBridgeState", json!([])).await, json!({ "enabled": false }));
        // The per-asset reads degrade to empty rather than erroring.
        let a = key(1).address().to_base58();
        assert_eq!(asset_balance(&st, &a, &Hash::ZERO.to_hex()).await, "0");
        assert_eq!(ok(&st, "shrugg_getAssets", json!([a])).await, json!([]));
        assert_eq!(ok(&st, "shrugg_getBridgeBurn", json!([0])).await, Value::Null);
    }

    #[tokio::test]
    async fn bridge_burn_serves_the_outbound_message() {
        let (_d, st, _gs) = bridged_chain();
        let (alice, bob) = (key(1), key(2));
        let asset = bridged_asset();
        // Block 2: bob sends 500 of his 990 back to chain 2.
        let mut ledger = st.storage.load_ledger().unwrap();
        ledger.set_timestamp_ms(1);
        ledger.set_height(2);
        let b1 = st.storage.block_by_height(1).unwrap().unwrap();
        let burn = Transaction::bridge_burn(&bob, 1, 0, asset, 500, 2, evm_to(), 5, 0);
        let b2 = make_block(&b1, &mut ledger, vec![burn.clone()], &alice);
        st.storage.commit(std::slice::from_ref(&b2), &ledger).unwrap();

        let v = ok(&st, "shrugg_getBridgeBurn", json!([0])).await;
        assert_eq!(v["sequence"], 0);
        assert_eq!(v["height"], 2);
        assert_eq!(v["tx"], burn.hash().to_hex());
        let body = hex::decode(v["body_hex"].as_str().unwrap()).unwrap();
        assert_eq!(v["digest"], hex::encode(shrugg_core::bridge::digest(&body)));
        assert_eq!(ok(&st, "shrugg_getBridgeBurn", json!([1])).await, Value::Null);
        // ... and the burn advanced the sequence the bridge state reports.
        assert_eq!(ok(&st, "shrugg_getBridgeState", json!([])).await["burn_sequence"], 1);
        assert_eq!(asset_balance(&st, &bob.address().to_base58(), &asset.to_hex()).await, "490");
    }

    #[tokio::test]
    async fn bridge_asset_id_is_the_domain_separated_hash() {
        let gs = genesis(1);
        let (_d, st) = state_for(&gs);
        // Works on a chain without a bridge: it is a pure function of its arguments.
        let v = ok(&st, "shrugg_bridgeAssetId", json!([2, hex::encode(TOKEN)])).await;
        assert_eq!(v, bridged_asset().to_hex());
        // 0x prefix accepted; the chain id is part of the identity.
        assert_eq!(ok(&st, "shrugg_bridgeAssetId", json!([2, format!("0x{}", hex::encode(TOKEN))])).await, v);
        assert_ne!(ok(&st, "shrugg_bridgeAssetId", json!([3, hex::encode(TOKEN)])).await, v);
        // A 20-byte EVM address must be left-padded by the caller.
        let err = call(&st, "shrugg_bridgeAssetId", json!([2, hex::encode([0xaau8; 20])])).await.unwrap_err();
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("must be 32 bytes"), "{}", err.message);
    }

    #[tokio::test]
    async fn unknown_methods_still_report_method_not_found() {
        let gs = genesis(1);
        let (_d, st) = state_for(&gs);
        assert_eq!(call(&st, "shrugg_getBridgeStat", json!([])).await.unwrap_err().code, -32601);
    }
}
