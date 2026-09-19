//! JSON-RPC client for a RAND full node, plus wallet helpers.
//!
//! Phase S1 redacted the chain: there are no accounts and no balances, so the account-shaped
//! calls this module used to carry are gone with the RPC methods that answered them. What remains
//! is the chain-state surface a wallet still needs
//! (`rand_getCommitments`/`getNullifiers`/`getAnchor`/`getWitness`/`getTreeInfo`, decoded here
//! into the `randprotocol-core` types [`wallet`] scans with) plus the faucet mint the cluster tests
//! drive their traffic with.
//!
//! The bridge reads are back in phase S3 and are deliberately not account-shaped either: a
//! bridged holding is a note like any other, so what the node can answer about the bridge is its
//! *public* state — guardians, emitters, the asset registry, the outbound burn log — and never a
//! balance. A wallet turns a note's `asset` word into a token through [`RpcClient::assets`].

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use randprotocol_core::notes::{word8_from_hex, Envelope, Word8, DEPTH};
use randprotocol_core::program::ProgramId;
use randprotocol_core::types::CallEnvelope;
use randprotocol_core::{Hash, Transaction};
use std::time::{Duration, Instant};

pub mod governance;
pub mod wallet;

/// A node's JSON-RPC error reply. It prints as it always has, `"<message> (rpc <code>)"`, and
/// keeps its code, so a caller can tell an older node (no such method, [`METHOD_NOT_FOUND`]) from
/// every other failure: `err.downcast_ref::<RpcError>()`, or [`is_method_not_found`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (rpc {})", self.message, self.code)
    }
}

impl std::error::Error for RpcError {}

/// A JSON-RPC error reply **to `rand_sendTransaction` itself** — the one call whose failure means
/// nothing was admitted (node I1).
///
/// Every submission path wraps that one call's [`RpcError`] in this, and nothing else does, so a
/// caller can tell "the node refused the transaction, synchronously" from "the node answered some
/// *later* call with an error" — `rand_getTransactionStatus` during the wait, or any of the six
/// methods the post-commit rescan makes. Both look identical as an `RpcError`, and the difference
/// decides whether a freshly generated secret may be deleted: a `-32603` on a restart or a
/// `-32000` on backpressure *after* a committed registration used to orphan the token's only
/// authority key.
///
/// It prints exactly as the reply it wraps and keeps it reachable by
/// `err.downcast_ref::<SubmitRefused>()` / `.0`. A transport failure is deliberately **not**
/// wrapped: the submission's fate is then unknown, which is not the same thing as refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitRefused(pub RpcError);

impl std::fmt::Display for SubmitRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for SubmitRefused {}

/// Re-label a `rand_sendTransaction` failure that is a JSON-RPC error reply as
/// [`SubmitRefused`], and leave every other failure exactly as it is.
pub fn submit_refused(e: anyhow::Error) -> anyhow::Error {
    match e.downcast::<RpcError>() {
        Ok(rpc) => anyhow::Error::new(SubmitRefused(rpc)),
        Err(other) => other,
    }
}

/// JSON-RPC's "method not found": what a node too old to know a method answers.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// True when `e` is a node saying it has no such method — the one error a wallet falls back on.
pub fn is_method_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<RpcError>().is_some_and(|r| r.code == METHOD_NOT_FOUND)
}

/// `rand_getLimits`: the chain's five genesis limits, which a wallet derives its caps from
/// instead of hard-coding them (spec §6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct ChainLimits {
    pub max_program_words: usize,
    pub max_proof_bytes: usize,
    pub max_block_bytes: usize,
    pub max_call_envelope_bytes: usize,
    pub max_program_public_words: usize,
}

/// Words from `rand_getProgramPublic`'s one hex string: each word as its four little-endian bytes,
/// so eight hex digits a word; `""` is no words.
pub fn words_from_le_hex(s: &str) -> Result<Vec<u32>> {
    let bytes = hex::decode(s).context("the public input is not hex")?;
    if bytes.len() % 4 != 0 {
        return Err(anyhow!("the public input is {} bytes, not whole words", bytes.len()));
    }
    Ok(bytes.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes"))).collect())
}

/// One leaf of the commitment tree as `rand_getCommitments` reports it: the leaf index, the
/// commitment, the envelope published with it, and the block it landed in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentRow {
    pub index: u64,
    pub cm: Word8,
    pub envelope: Envelope,
    pub height: u64,
}

/// `rand_getTreeInfo`: how far a wallet still has to scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeInfo {
    pub next_index: u64,
    pub root: Word8,
    pub nullifiers: u64,
}

/// A `Word8` field of an RPC reply, as 64 hex characters.
fn word8_at(v: &Value, field: &str) -> Result<Word8> {
    let s = v.get(field).and_then(|x| x.as_str()).with_context(|| format!("{field} missing"))?;
    word8_from_hex(s).with_context(|| format!("{field} is not 64 hex characters"))
}

/// A hex byte string field of an RPC reply.
fn bytes_at(v: &Value, field: &str) -> Result<Vec<u8>> {
    let s = v.get(field).and_then(|x| x.as_str()).with_context(|| format!("{field} missing"))?;
    hex::decode(s).with_context(|| format!("{field} is not hex"))
}

fn envelope_at(v: &Value) -> Result<Envelope> {
    Ok(Envelope {
        kem_ct: bytes_at(v, "kem_ct")?,
        to_receiver: bytes_at(v, "to_receiver")?,
        to_sender: bytes_at(v, "to_sender")?,
        body: bytes_at(v, "body")?,
    })
}

#[derive(Clone)]
pub struct RpcClient {
    url: String,
    http: reqwest::Client,
    /// Set on the first `-32601` `rand_getTransactionStatus` reply: this node predates v0.3, so
    /// `wait_for_transaction` stops asking for it and falls back to the pre-v0.3
    /// `rand_getTransaction` polling loop instead of paying for a round trip to a method the
    /// node does not have on every subsequent call.
    legacy_status: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone, Debug)]
pub struct TxReceipt {
    pub hash: Hash,
    pub height: u64,
    pub index: u32,
    pub block_hash: Hash,
}

/// The flat allowance for a request that only *asks* for something. A read measured ~1.3 s against
/// a droplet over an SSH tunnel, so 15 s is already generous and a read that takes longer is broken
/// rather than slow.
const READ_TIMEOUT: Duration = Duration::from_secs(15);

/// A body at or above this gets [`upload_timeout`] instead of [`READ_TIMEOUT`]. Every read this
/// client makes is far below it; only a proof-carrying transaction is above.
const UPLOAD_THRESHOLD: usize = 64 * 1024;

/// Assumed upload rate, deliberately pessimistic: measured ~92 KB/s from a laptop to a droplet over
/// an SSH tunnel (a 1.7 MB POST took 18.8 s), so budgeting a third of that leaves a link three
/// times slower than the one we measured still finishing.
const UPLOAD_BYTES_PER_SEC: usize = 32 * 1024;

/// Fixed allowance on top of the transfer itself: connection, TLS, and the node's own handling.
const UPLOAD_SETUP: Duration = Duration::from_secs(30);

/// Never wait longer than this, however large the body.
const UPLOAD_TIMEOUT_CAP: Duration = Duration::from_secs(600);

/// How long to allow a request that uploads `body_bytes`.
///
/// A read's flat 15 s cannot serve an upload. A constraint-set-5 bundle is ~1.3 MB of proof, and it
/// goes out hex-encoded inside JSON, so the POST is ~2.7 MB — over the measured ~92 KB/s link that
/// is ~30 s of transfer alone. `rand send` therefore proved for ~100 s and then lost the
/// transaction to a 15 s timeout, which is the one failure in this flow that wastes the proof.
pub fn upload_timeout(body_bytes: usize) -> Duration {
    let transfer = Duration::from_secs((body_bytes / UPLOAD_BYTES_PER_SEC) as u64);
    (UPLOAD_SETUP + transfer).min(UPLOAD_TIMEOUT_CAP)
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> RpcClient {
        RpcClient {
            url: url.into(),
            // The per-request timeout for an upload is set on the request itself, which overrides
            // this one; this is the read timeout.
            http: reqwest::Client::builder().timeout(READ_TIMEOUT).build().expect("client"),
            legacy_status: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Raw JSON-RPC call. Returns the `result`, or an error carrying the node's message.
    ///
    /// The body is serialized here rather than handed to `.json()` so its size is known: a request
    /// big enough to be an upload gets [`upload_timeout`] on the request itself, which overrides the
    /// client's read timeout, and names both numbers if it does fire.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let raw = serde_json::to_vec(&body).context("encoding rpc request")?;
        let bytes = raw.len();
        let mut req = self
            .http
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(raw);
        let timeout = if bytes >= UPLOAD_THRESHOLD {
            let t = upload_timeout(bytes);
            req = req.timeout(t);
            t
        } else {
            READ_TIMEOUT
        };
        let resp: Value = req
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    // The message an operator needs: which numbers were in play, not just "operation
                    // timed out".
                    anyhow!(
                        "{method} timed out after {:.0?} sending a {bytes}-byte body to {} \
                         (allowance is {:.0?} plus one second per {} KiB)",
                        timeout,
                        self.url,
                        UPLOAD_SETUP,
                        UPLOAD_BYTES_PER_SEC / 1024
                    )
                } else {
                    anyhow!(e).context(format!("connecting to {}", self.url))
                }
            })?
            .json()
            .await
            .context("decoding rpc response")?;
        if let Some(err) = resp.get("error") {
            let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown").to_string();
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            return Err(RpcError { code, message }.into());
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn chain_id(&self) -> Result<u64> {
        self.call("rand_chainId", json!([])).await?.as_u64().context("chain id")
    }

    pub async fn send_transaction(&self, tx: &Transaction) -> Result<Hash> {
        let v = self.call("rand_sendTransaction", json!([hex::encode(tx.encode())])).await?;
        Hash::from_hex(v.as_str().unwrap_or("")).map_err(|e| anyhow!("bad hash in reply: {e}"))
    }

    /// The committed transaction itself, decoded from `rand_getRawTransaction` — what reading its
    /// envelopes needs, which `rand_getTransaction`'s rendering deliberately leaves out. `None` for
    /// a hash this node has not committed.
    pub async fn raw_transaction(&self, hash: &Hash) -> Result<Option<Transaction>> {
        let v = self.call("rand_getRawTransaction", json!([hash.to_hex()])).await?;
        let Some(raw) = v.as_str() else { return Ok(None) };
        let bytes = hex::decode(raw).map_err(|e| anyhow!("raw transaction is not hex: {e}"))?;
        Ok(Some(Transaction::decode(&bytes).map_err(|e| anyhow!("raw transaction does not decode: {e}"))?))
    }

    /// `None` until the transaction is in a committed block.
    pub async fn transaction(&self, hash: &Hash) -> Result<Option<TxReceipt>> {
        let v = self.call("rand_getTransaction", json!([hash.to_hex()])).await?;
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(TxReceipt {
            hash: *hash,
            height: v["height"].as_u64().context("height")?,
            index: v["index"].as_u64().unwrap_or(0) as u32,
            block_hash: Hash::from_hex(v["block_hash"].as_str().unwrap_or("")).map_err(|e| anyhow!("{e}"))?,
        }))
    }

    /// `rand_getTransactionStatus`: committed (with height and index), pending, rejected (with the
    /// admission reason), or unknown, one entry per hash asked about. Kept as raw `Value`s —
    /// `wait_for_transaction` is the only caller today, and it only ever reads
    /// `status`/`reason`/`hash`.
    pub async fn transaction_status(&self, hashes: &[Hash]) -> Result<Vec<Value>> {
        let v = self
            .call("rand_getTransactionStatus", json!([hashes.iter().map(|h| h.to_hex()).collect::<Vec<_>>()]))
            .await?;
        v.as_array().cloned().context("status list")
    }

    /// Poll until the transaction is committed, fails fast on a rejection, or `timeout` elapses.
    ///
    /// A rejection — a bad proof or mint signature, say — is permanent, so there is no reason to
    /// keep polling until `timeout`: `rand_getTransactionStatus` reports it directly, with the
    /// admission reason, and this returns as soon as it sees one. Only refusals about the
    /// transaction's own bytes are reported that way: one that depends on the node's state (a
    /// spent nullifier, an expired anchor) is not remembered, reads `unknown` once the
    /// transaction leaves the pool, and so still runs to `timeout` here. Against a node older than
    /// v0.3, which has no such method and answers `-32601`, it falls back to the old
    /// `rand_getTransaction` loop for good — `legacy_status` remembers that so later calls do
    /// not pay for the round trip that will only fail again.
    pub async fn wait_for_transaction(&self, hash: &Hash, timeout: Duration) -> Result<TxReceipt> {
        use std::sync::atomic::Ordering;

        if self.legacy_status.load(Ordering::Relaxed) {
            return self.wait_for_transaction_legacy(hash, timeout).await;
        }
        let start = Instant::now();
        loop {
            let status = match self.transaction_status(std::slice::from_ref(hash)).await {
                Ok(s) => s,
                Err(e) if is_method_not_found(&e) => {
                    self.legacy_status.store(true, Ordering::Relaxed);
                    return self.wait_for_transaction_legacy(hash, timeout).await;
                }
                Err(e) => return Err(e),
            };
            match status.first().and_then(|s| s["status"].as_str()) {
                Some("committed") => {
                    if let Some(r) = self.transaction(hash).await? {
                        return Ok(r);
                    }
                }
                Some("rejected") => {
                    let reason = status[0]["reason"].as_str().unwrap_or("refused");
                    return Err(anyhow!("transaction {hash} rejected: {reason}"));
                }
                _ => {}
            }
            if start.elapsed() > timeout {
                return Err(anyhow!("transaction {hash} not committed within {timeout:?}"));
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// The pre-v0.3 wait: poll `rand_getTransaction` until it is committed or `timeout` elapses.
    /// It never sees a rejection — that node has nowhere to report one — so it can only time out.
    /// Shared by [`wait_for_transaction`](Self::wait_for_transaction)'s legacy fallback, so the
    /// two paths keep one loop body between them.
    async fn wait_for_transaction_legacy(&self, hash: &Hash, timeout: Duration) -> Result<TxReceipt> {
        let start = Instant::now();
        loop {
            if let Some(r) = self.transaction(hash).await? {
                return Ok(r);
            }
            if start.elapsed() > timeout {
                return Err(anyhow!("transaction {hash} not committed within {timeout:?}"));
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// Testnet faucet: ask a *validator* node to mint `amount` units into a note owned by the
    /// shielded address `to` (the `rand1…` text form). `amount` is in units; `None` asks for
    /// the node's default (100 RAND). The node signs the mint itself — a non-validator node
    /// answers with an error rather than forwarding, since only a validator's signature admits
    /// a mint (spec §6).
    pub async fn mint_shielded(&self, to: &str, amount: Option<u64>) -> Result<Hash> {
        let params = match amount {
            Some(a) => json!([to, a.to_string()]),
            None => json!([to]),
        };
        let v = self.call("rand_mint", params).await?;
        Hash::from_hex(v.as_str().unwrap_or("")).map_err(|e| anyhow!("bad hash in reply: {e}"))
    }

    // ---- confidential computation ----

    pub async fn program(&self, id: &ProgramId) -> Result<Option<Value>> {
        let v = self.call("rand_getProgram", json!([id.to_hex()])).await?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    pub async fn program_code(&self, id: &ProgramId) -> Result<Option<(u32, Vec<u32>)>> {
        let v = self.call("rand_getProgramCode", json!([id.to_hex()])).await?;
        if v.is_null() {
            return Ok(None);
        }
        let base_pc = v["base_pc"].as_u64().context("base_pc")? as u32;
        let words = v["words"].as_array().context("words")?.iter().map(|w| w.as_u64().unwrap_or(0) as u32).collect();
        Ok(Some((base_pc, words)))
    }

    /// A program's deploy-time public input (`rand_getProgramPublic`): its words, empty for a
    /// program deployed without one, `None` for an unknown program. A node that predates the
    /// method predates public inputs too, so every program it holds has none.
    pub async fn program_public(&self, id: &ProgramId) -> Result<Option<Vec<u32>>> {
        let v = match self.call("rand_getProgramPublic", json!([id.to_hex()])).await {
            Ok(v) => v,
            Err(e) if is_method_not_found(&e) => return Ok(Some(Vec::new())),
            Err(e) => return Err(e),
        };
        if v.is_null() {
            return Ok(None);
        }
        let hex = v.as_str().context("rand_getProgramPublic did not return a hex string")?;
        words_from_le_hex(hex).map(Some)
    }

    /// The chain's limits (`rand_getLimits`), or `None` from a node that predates the method —
    /// the one case a wallet falls back to the old fixed caps for. Any other failure is an error.
    pub async fn limits(&self) -> Result<Option<ChainLimits>> {
        match self.call("rand_getLimits", json!([])).await {
            Ok(v) => Ok(Some(serde_json::from_value(v).context("decoding rand_getLimits")?)),
            Err(e) if is_method_not_found(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn receipt(&self, tx: &Hash) -> Result<Option<Value>> {
        let v = self.call("rand_getReceipt", json!([tx.to_hex()])).await?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    /// Poll until a call's receipt is stored (the tx is committed) or `timeout` elapses.
    pub async fn wait_for_receipt(&self, tx: &Hash, timeout: Duration) -> Result<Value> {
        let start = Instant::now();
        loop {
            if let Some(r) = self.receipt(tx).await? {
                return Ok(r);
            }
            if start.elapsed() > timeout {
                return Err(anyhow!("no receipt for {tx} within {timeout:?}"));
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    /// The fee floor for one action, in units. `params` is the node's `rand_estimateFee`
    /// object — `{"kind":"bundle"}`, `{"kind":"deploy","words":n,"public_words":m}` or
    /// `{"kind":"call","tier":t,"bytes":b}` (`public_words` and `bytes` optional).
    pub async fn estimate_fee(&self, params: Value) -> Result<u64> {
        let v = self.call("rand_estimateFee", json!([params])).await?;
        v.as_str().unwrap_or("0").parse().context("fee")
    }

    pub async fn head(&self) -> Result<Value> {
        self.call("rand_getHead", json!([])).await
    }
    pub async fn status(&self) -> Result<Value> {
        self.call("rand_status", json!([])).await
    }
    pub async fn peers(&self) -> Result<Value> {
        self.call("rand_getPeers", json!([])).await
    }
    pub async fn validators(&self) -> Result<Value> {
        self.call("rand_getValidators", json!([])).await
    }
    /// `{epoch, epoch_blocks, next_set}` — where the chain is in its epoch schedule, and the set
    /// the next epoch would start with if this one ended now. `next_set` is a projection: every
    /// bond and unbond before the boundary still moves it.
    pub async fn epoch(&self) -> Result<Value> {
        self.call("rand_getEpoch", json!([])).await
    }
    pub async fn block_by_height(&self, h: u64) -> Result<Value> {
        self.call("rand_getBlockByHeight", json!([h])).await
    }
    pub async fn block_by_hash(&self, h: &Hash) -> Result<Value> {
        self.call("rand_getBlockByHash", json!([h.to_hex()])).await
    }
    /// `rand_getBlocks`: the headers of `from..=to`, oldest first — each with its `height` and
    /// `tx_count`. The node caps one reply (at 128 headers today) and at its head, so a caller
    /// advances from the last height it got back rather than from `to`.
    pub async fn blocks(&self, from: u64, to: u64) -> Result<Vec<Value>> {
        let v = self.call("rand_getBlocks", json!([from, to])).await?;
        Ok(v.as_array().context("getBlocks did not return a list")?.clone())
    }

    // ---- shielded chain state (the wallet's scan surface) ----

    /// A page of the commitment tree's leaves from leaf index `from`, oldest first. The node
    /// caps a page at 1000 rows however large `limit` is, so a caller pages until the reply is
    /// short or empty rather than trusting one call to return everything.
    pub async fn commitments(&self, from: u64, limit: usize) -> Result<Vec<CommitmentRow>> {
        let v = self.call("rand_getCommitments", json!([from, limit])).await?;
        let rows = v.as_array().context("getCommitments did not return a list")?;
        rows.iter()
            .map(|r| {
                Ok(CommitmentRow {
                    index: r["index"].as_u64().context("index")?,
                    cm: word8_at(r, "cm")?,
                    envelope: envelope_at(r.get("envelope").context("envelope")?)?,
                    height: r["height"].as_u64().context("height")?,
                })
            })
            .collect()
    }

    /// Every nullifier published from block `from_height` onwards, as `(height, nullifier)`.
    pub async fn nullifiers(&self, from_height: u64, limit: usize) -> Result<Vec<(u64, Word8)>> {
        let v = self.call("rand_getNullifiers", json!([from_height, limit])).await?;
        let rows = v.as_array().context("getNullifiers did not return a list")?;
        rows.iter().map(|r| Ok((r["height"].as_u64().context("height")?, word8_at(r, "nullifier")?))).collect()
    }

    /// The tree root a prover anchors against: the head's (`None`), or a specific height's.
    pub async fn anchor(&self, height: Option<u64>) -> Result<(u64, Word8)> {
        let params = match height {
            Some(h) => json!([h]),
            None => json!([]),
        };
        let v = self.call("rand_getAnchor", params).await?;
        Ok((v["height"].as_u64().context("height")?, word8_at(&v, "root")?))
    }

    /// The Merkle witness of leaf `index` — `(root, siblings leaf-first)`. The root is the
    /// tree's *current* root, which is why a wallet checks it against the anchor it proved
    /// under rather than assuming the two agree.
    pub async fn witness(&self, index: u64) -> Result<(Word8, [Word8; DEPTH])> {
        let v = self.call("rand_getWitness", json!([index])).await?;
        if v.is_null() {
            return Err(anyhow!("no leaf at index {index}"));
        }
        let root = word8_at(&v, "root")?;
        let list = v["path"].as_array().context("path")?;
        if list.len() != DEPTH {
            return Err(anyhow!("witness path is {} levels, expected {DEPTH}", list.len()));
        }
        let mut path = [[0u32; 8]; DEPTH];
        for (slot, w) in path.iter_mut().zip(list) {
            *slot = word8_from_hex(w.as_str().unwrap_or_default()).context("path level is not 64 hex characters")?;
        }
        Ok((root, path))
    }

    /// `{next_index, root, nullifiers}` — enough for a wallet to know how far it has scanned.
    pub async fn tree_info(&self) -> Result<TreeInfo> {
        let v = self.call("rand_getTreeInfo", json!([])).await?;
        Ok(TreeInfo {
            next_index: v["next_index"].as_u64().context("next_index")?,
            root: word8_at(&v, "root")?,
            nullifiers: v["nullifiers"].as_u64().context("nullifiers")?,
        })
    }

    /// The sealed transcript of a call's private inputs and the `H_IN` it is bound to, as
    /// `rand_getCallEnvelope` serves them. `None` for a call that published none, for a
    /// transaction that is not a call, and for a hash this node has no receipt for.
    ///
    /// The node holds no key that opens this; `randprotocol_zkvm::call_envelope` does the opening, with
    /// the `H_IN` returned here as the associated data every part of it is bound to.
    pub async fn call_envelope(&self, tx: &Hash) -> Result<Option<(Word8, CallEnvelope)>> {
        let v = self.call("rand_getCallEnvelope", json!([tx.to_hex()])).await?;
        if v.is_null() {
            return Ok(None);
        }
        let e = CallEnvelope {
            kem_ct: bytes_at(&v, "kem_ct")?,
            to_sender: bytes_at(&v, "to_sender")?,
            to_auditor: bytes_at(&v, "to_auditor")?,
            body: bytes_at(&v, "body")?,
        };
        Ok(Some((word8_at(&v, "h_in")?, e)))
    }

    // ---- node-side viewing keys and payment proofs ----

    /// `rand_importViewingKey`: hand the node a viewing key (`nk` as 64 hex) to scan with,
    /// from `rescan_from_height` onwards (default 0, the whole chain). The node holds it in
    /// memory only — capped at 64 keys, cleared at restart — and never on disk; see `docs/rpc.md`
    /// for what that changes about the node's trust profile.
    pub async fn import_viewing_key(&self, nk_hex: &str, rescan_from_height: Option<u64>) -> Result<Value> {
        let params = match rescan_from_height {
            Some(h) => json!([nk_hex, h]),
            None => json!([nk_hex]),
        };
        self.call("rand_importViewingKey", params).await
    }

    /// `rand_getViewingNotes`: one page of the notes an imported key has matched, by leaf
    /// index, plus the scan's progress (`scanned_index` / `next_index` / `complete` — a rescan
    /// longer than one call's 10 000-leaf bound completes over several calls).
    pub async fn viewing_notes(&self, nk_hex: &str, from_index: u64, limit: usize) -> Result<Value> {
        self.call("rand_getViewingNotes", json!([nk_hex, from_index, limit])).await
    }

    /// `rand_checkTransaction`: what `key_hex` — a per-transaction `TxKey` as 64 hex —
    /// discloses about the committed transaction `hash` (Monero's `check_tx_proof` shape).
    /// Stateless: the key is dropped with the call. `None` for a hash the node has no committed
    /// transaction for; a key that sealed nothing in it gets `{ "disclosed": [] }`.
    pub async fn check_transaction(&self, hash: &Hash, key_hex: &str) -> Result<Option<Value>> {
        let v = self.call("rand_checkTransaction", json!([hash.to_hex(), key_hex])).await?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    // ---- the bridge (spec §10) ----

    /// The bridge's own public state: guardians, source emitters, the asset registry (the token
    /// registry's bridged rows) and the outbound burn sequence. `{"enabled": false}` on a chain
    /// without a bridge. There is no `next_index`: a bridged token is listed before it can be
    /// deposited, so its index is a fact to read rather than a number to predict.
    pub async fn bridge_state(&self) -> Result<Value> {
        self.call("rand_getBridgeState", json!([])).await
    }

    /// The asset registry, ascending by index: what a wallet reads to turn a note's `asset` word
    /// into a token, or a token into the index its notes carry — the `Bridge`-authority rows of
    /// this chain's token registry. Empty without a bridge.
    pub async fn assets(&self) -> Result<Vec<AssetRow>> {
        let v = self.call("rand_getAssets", json!([])).await?;
        let rows = v.as_array().context("getAssets did not return a list")?;
        rows.iter()
            .map(|r| {
                Ok(AssetRow {
                    index: r["index"].as_u64().context("index")? as u32,
                    chain: r["chain"].as_u64().context("chain")? as u16,
                    token: bytes_at(r, "token")?,
                    asset_id: r["asset_id"].as_str().context("asset_id")?.to_string(),
                })
            })
            .collect()
    }

    /// The outbound burn message with this sequence, verbatim, for guardians to sign. `None` for
    /// a sequence this chain has not emitted.
    pub async fn bridge_burn(&self, sequence: u64) -> Result<Option<Value>> {
        let v = self.call("rand_getBridgeBurn", json!([sequence])).await?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    /// The 32-byte asset id of a token, as the registry keys it. Pure arithmetic on the two wire
    /// fields, so it answers on any chain — including one whose registry has never seen the
    /// token, which is exactly when a caller needs it.
    pub async fn bridge_asset_id(&self, token_chain: u16, token_address: &[u8; 32]) -> Result<String> {
        let v = self.call("rand_bridgeAssetId", json!([token_chain, hex::encode(token_address)])).await?;
        Ok(v.as_str().context("bridgeAssetId did not return a hash")?.to_string())
    }
}

/// One row of the bridge's asset registry as `rand_getAssets` reports it: the `asset` word that
/// asset's notes carry, and the wire identity the guardians sign about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRow {
    pub index: u32,
    pub chain: u16,
    pub token: Vec<u8>,
    /// The registry's key, 64 hex characters (`rand_bridgeAssetId` returns the same spelling).
    pub asset_id: String,
}

/// A 32-byte value as 64 hex characters, with or without `0x`.
pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).with_context(|| format!("{s:?} is not hex"))?;
    bytes.try_into().map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))
}

/// A scripted JSON-RPC node for the unit tests here and in [`wallet`]: every connection gets one
/// reply, chosen by the request's `method` from `script` (a `result` value, or an `error` with
/// its code), and a method the script does not name gets `-32601`, as a real node answers an
/// unknown method. It answers with `connection: close`, so each call is a fresh connection.
#[cfg(test)]
pub(crate) mod test_rpc {
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub enum Reply {
        Ok(Value),
        Err(i64, &'static str),
    }

    pub async fn scripted_rpc(script: Vec<(&'static str, Reply)>) -> String {
        let script = std::sync::Arc::new(script);
        rpc_fn(move |method, _| match script.iter().find(|(m, _)| *m == method) {
            Some((_, Reply::Ok(v))) => Reply::Ok(v.clone()),
            Some((_, Reply::Err(code, msg))) => Reply::Err(*code, msg),
            None => Reply::Err(-32601, "unknown method"),
        })
        .await
    }

    /// A node whose every reply is computed by `answer(method, params)` — for a test that needs
    /// state behind the replies (a paged tree, blocks, a captured submission), which a fixed
    /// script cannot page through.
    pub async fn rpc_fn<F>(answer: F) -> String
    where
        F: Fn(&str, &Value) -> Reply + Send + Sync + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let answer = std::sync::Arc::new(answer);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let answer = answer.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 16 * 1024];
                    let header_end = loop {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                    let len: usize = headers
                        .split("content-length:")
                        .nth(1)
                        .and_then(|r| r.split("\r\n").next())
                        .and_then(|v| v.trim().parse().ok())
                        .unwrap_or(0);
                    while buf.len() - header_end < len {
                        let n = sock.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let req: Value = serde_json::from_slice(&buf[header_end..]).unwrap_or(Value::Null);
                    let method = req["method"].as_str().unwrap_or_default().to_string();
                    let body = match answer(&method, &req["params"]) {
                        Reply::Ok(v) => json!({ "jsonrpc": "2.0", "id": 1, "result": v }),
                        Reply::Err(code, msg) => {
                            json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": msg } })
                        }
                    }
                    .to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        format!("http://{addr}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex32_takes_both_spellings_and_rejects_the_wrong_length() {
        let bare = "11".repeat(32);
        assert_eq!(hex32(&bare).unwrap(), [0x11u8; 32]);
        assert_eq!(hex32(&format!("0x{bare}")).unwrap(), [0x11u8; 32]);
        assert!(hex32("0x1122").unwrap_err().to_string().contains("got 2"));
        assert!(hex32("nothex").unwrap_err().to_string().contains("not hex"));
    }

    // ---------------------------------------------------- the upload timeout
    //
    // `rand send` of a constraint-set-5 bundle proved for ~100 s and then died on the submit with
    // "operation timed out": the client had one flat 15 s timeout, and the POST is ~2.7 MB of
    // hex-in-JSON over a link measured at ~92 KB/s.

    #[test]
    fn the_upload_allowance_grows_with_the_body_and_is_capped() {
        // An empty body still gets the setup allowance.
        assert_eq!(upload_timeout(0), Duration::from_secs(30));

        // A constraint-set-5 bundle: ~1.3 MB of proof, hex-encoded inside JSON.
        let bundle_post = 2 * 1_321_773 + 512;
        let t = upload_timeout(bundle_post);
        assert_eq!(t, Duration::from_secs(30 + (bundle_post / (32 * 1024)) as u64));
        // Comfortably past both the 15 s that failed and the 18.8 s a 1.7 MB POST measured.
        assert!(t > Duration::from_secs(100), "{t:?}");

        // A 4 MiB body — the largest block, so the largest transaction.
        assert_eq!(upload_timeout(4 << 20), Duration::from_secs(30 + 128));

        // And the cap holds however absurd the body.
        assert_eq!(upload_timeout(usize::MAX / 2), Duration::from_secs(600));
        assert!(upload_timeout(1 << 30) <= Duration::from_secs(600));
    }

    #[test]
    fn a_read_sized_body_is_below_the_upload_threshold() {
        // What a read actually posts, so reads keep the flat 15 s.
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "rand_getAnchor", "params": [] });
        assert!(serde_json::to_vec(&body).unwrap().len() < UPLOAD_THRESHOLD);
    }

    /// A hand-rolled HTTP server: reads the whole request, waits `delay`, then answers `body`.
    /// Returns its address and the number of body bytes it received.
    async fn slow_server(delay: Duration, body: &'static str) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Read headers, find Content-Length, then read exactly that much body.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 16 * 1024];
            let header_end = loop {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
            let len: usize = headers
                .split("content-length:")
                .nth(1)
                .and_then(|r| r.split("\r\n").next())
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut got = buf.len() - header_end;
            while got < len {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                got += n;
            }
            counter.store(got, Ordering::SeqCst);
            // The whole point: answer only after the client's old 15 s would have expired.
            tokio::time::sleep(delay).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
        });
        (format!("http://{addr}"), seen)
    }

    /// A 1.3 MB transaction against a server that takes 20 s to answer: the old flat 15 s lost the
    /// proof here, the size-based allowance (~110 s for this body) does not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_large_send_outlives_the_read_timeout() {
        use randprotocol_core::notes::{Bundle, Envelope};
        use randprotocol_core::Action;

        let env = || Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![], body: vec![3; 16] };
        let bundle = Bundle {
            anchor: [1; 8],
            nullifiers: [[2; 8], [3; 8], [6; 8], [7; 8]],
            commitments: [[4; 8], [5; 8], [8; 8], [9; 8]],
            fee: 1,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 1,
            envelopes: [env(), env(), env(), env()],
            // A constraint-set-5 bundle proof, to the byte measured on chain 8.
            proof: vec![7u8; 1_321_773],
        };
        let tx = Transaction::shielded(7, bundle, Action::None);
        let posted = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "rand_sendTransaction", "params": [hex::encode(tx.encode())]
        }))
        .unwrap()
        .len();
        assert!(posted >= UPLOAD_THRESHOLD, "this must count as an upload: {posted} B");
        let allowance = upload_timeout(posted);
        assert!(allowance > Duration::from_secs(30), "{allowance:?}");

        let reply = r#"{"jsonrpc":"2.0","id":1,"result":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        let (url, seen) = slow_server(Duration::from_secs(20), reply).await;

        let client = RpcClient::new(url);
        let started = Instant::now();
        let got = client.send_transaction(&tx).await;
        let waited = started.elapsed();

        assert!(got.is_ok(), "a large send must survive a 20 s server: {:?}", got.err());
        assert!(waited > Duration::from_secs(15), "the server should have outlasted the read timeout: {waited:?}");
        assert!(waited < allowance, "and still finished inside its allowance: {waited:?} of {allowance:?}");
        assert!(
            seen.load(std::sync::atomic::Ordering::SeqCst) >= posted - 1024,
            "the server should have received the whole body"
        );
    }

    // ------------------------------------------------- the transaction-status fast fail
    //
    // A rejection (a bad mint signature, say — a refusal about the transaction's own bytes) is
    // permanent: `wait_for_transaction` should report it as soon as `rand_getTransactionStatus`
    // says so, rather than polling until its timeout as the pre-v0.3 client did.

    #[tokio::test]
    async fn wait_for_transaction_fails_fast_on_a_rejected_status() {
        let hash = Hash([9u8; 32]);
        let reply = format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":[{{"hash":"{}","status":"rejected","reason":"bad mint signature"}}]}}"#,
            hash.to_hex()
        );
        // `slow_server` answers one connection with one canned reply — exactly what this needs:
        // `wait_for_transaction` returns on the very first status call, so there is no second
        // request to answer.
        let (url, _seen) = slow_server(Duration::ZERO, Box::leak(reply.into_boxed_str())).await;
        let client = RpcClient::new(url);

        let timeout = Duration::from_secs(5);
        let started = Instant::now();
        let err = client.wait_for_transaction(&hash, timeout).await.unwrap_err();
        let waited = started.elapsed();

        assert!(err.to_string().contains("rejected: bad mint signature"), "{err}");
        assert!(waited < timeout, "should fail fast, not wait out the timeout: {waited:?}");
    }

    // ---------------------------------------------------- the call limits (Task 5)

    /// `rand_getProgramPublic`'s one hex string: each word as its four little-endian bytes, the
    /// example in `docs/rpc.md`; `""` is the empty public input.
    #[test]
    fn public_words_decode_from_little_endian_hex() {
        assert_eq!(words_from_le_hex("0100000002000000efbeadde").unwrap(), vec![1, 2, 0xdead_beef]);
        assert_eq!(words_from_le_hex("").unwrap(), Vec::<u32>::new());
        assert!(words_from_le_hex("010000").unwrap_err().to_string().contains("whole words"));
        assert!(words_from_le_hex("zz000000").is_err());
    }

    /// An error reply keeps its code, so a caller can tell "this node has no such method" (an older
    /// node) from every other failure, and the message still reads as it always did.
    #[tokio::test]
    async fn an_rpc_error_keeps_its_code() {
        use test_rpc::{scripted_rpc, Reply};
        let url = scripted_rpc(vec![("rand_estimateFee", Reply::Err(-32602, "words must be at most 4096"))]).await;
        let rpc = RpcClient::new(url);
        let e = rpc.call("rand_estimateFee", json!([])).await.unwrap_err();
        assert_eq!(e.to_string(), "words must be at most 4096 (rpc -32602)");
        assert_eq!(e.downcast_ref::<RpcError>().map(|e| e.code), Some(-32602));
        assert!(!is_method_not_found(&e));
        let e = rpc.call("rand_nope", json!([])).await.unwrap_err();
        assert!(is_method_not_found(&e), "{e}");
    }

    /// `rand_getLimits`, decoded; `None` from a node that predates it, and an error for anything
    /// else going wrong (never a silent fallback on a real failure).
    #[tokio::test]
    async fn limits_are_read_or_absent_on_an_older_node() {
        use test_rpc::{scripted_rpc, Reply};
        let reply = json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64
        });
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(reply))]).await);
        assert_eq!(
            rpc.limits().await.unwrap(),
            Some(ChainLimits {
                max_program_words: 4096,
                max_proof_bytes: 2_097_152,
                max_block_bytes: 4_194_304,
                max_call_envelope_bytes: 18_432,
                max_program_public_words: 64,
            })
        );
        let older = RpcClient::new(scripted_rpc(vec![]).await);
        assert_eq!(older.limits().await.unwrap(), None);
        let broken = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Err(-32603, "db closed"))]).await);
        assert!(broken.limits().await.is_err());
    }

    /// `rand_getProgramPublic`: words for a program with a public input, none for one without,
    /// `None` for an unknown program — and an older node without the method has no public inputs.
    #[tokio::test]
    async fn a_programs_public_input_is_read_back_as_words() {
        use test_rpc::{scripted_rpc, Reply};
        let id = Hash([3; 32]);
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getProgramPublic", Reply::Ok(json!("0100000002000000")))]).await);
        assert_eq!(rpc.program_public(&id).await.unwrap(), Some(vec![1, 2]));
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getProgramPublic", Reply::Ok(json!("")))]).await);
        assert_eq!(rpc.program_public(&id).await.unwrap(), Some(vec![]));
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getProgramPublic", Reply::Ok(Value::Null))]).await);
        assert_eq!(rpc.program_public(&id).await.unwrap(), None);
        let older = RpcClient::new(scripted_rpc(vec![]).await);
        assert_eq!(older.program_public(&id).await.unwrap(), Some(vec![]));
    }
}
