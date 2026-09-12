//! JSON-RPC client for a SHRUGG full node, plus wallet helpers.
//!
//! Phase S1 redacted the chain: there are no accounts, no balances and no bridge, so the
//! account-shaped and bridge-shaped calls this module used to carry are gone with the RPC
//! methods that answered them. What remains is the chain-state surface a wallet still needs
//! (`shrugg_getCommitments`/`getNullifiers`/`getAnchor`/`getWitness`/`getTreeInfo`, decoded
//! here into the `shrugg-core` types [`wallet`] scans with) plus the faucet mint the cluster
//! tests drive their traffic with.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use shrugg_core::notes::{word8_from_hex, Envelope, Word8, DEPTH};
use shrugg_core::program::ProgramId;
use shrugg_core::{Hash, Transaction};
use std::time::{Duration, Instant};

pub mod wallet;

/// One leaf of the commitment tree as `shrugg_getCommitments` reports it: the leaf index, the
/// commitment, the envelope published with it, and the block it landed in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentRow {
    pub index: u64,
    pub cm: Word8,
    pub envelope: Envelope,
    pub height: u64,
}

/// `shrugg_getTreeInfo`: how far a wallet still has to scan.
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
}

#[derive(Clone, Debug)]
pub struct TxReceipt {
    pub hash: Hash,
    pub height: u64,
    pub index: u32,
    pub block_hash: Hash,
}

impl RpcClient {
    pub fn new(url: impl Into<String>) -> RpcClient {
        RpcClient { url: url.into(), http: reqwest::Client::builder().timeout(Duration::from_secs(15)).build().expect("client") }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Raw JSON-RPC call. Returns the `result`, or an error carrying the node's message.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("connecting to {}", self.url))?
            .json()
            .await
            .context("decoding rpc response")?;
        if let Some(err) = resp.get("error") {
            let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown");
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            return Err(anyhow!("{msg} (rpc {code})"));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    pub async fn chain_id(&self) -> Result<u64> {
        self.call("shrugg_chainId", json!([])).await?.as_u64().context("chain id")
    }

    pub async fn send_transaction(&self, tx: &Transaction) -> Result<Hash> {
        let v = self.call("shrugg_sendTransaction", json!([hex::encode(tx.encode())])).await?;
        Hash::from_hex(v.as_str().unwrap_or("")).map_err(|e| anyhow!("bad hash in reply: {e}"))
    }

    /// `None` until the transaction is in a committed block.
    pub async fn transaction(&self, hash: &Hash) -> Result<Option<TxReceipt>> {
        let v = self.call("shrugg_getTransaction", json!([hash.to_hex()])).await?;
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

    /// Poll until the transaction is committed or `timeout` elapses.
    pub async fn wait_for_transaction(&self, hash: &Hash, timeout: Duration) -> Result<TxReceipt> {
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
    /// shielded address `to` (the `shrugg1…` text form). `amount` is in units; `None` asks for
    /// the node's default (100 SHRUGG). The node signs the mint itself — a non-validator node
    /// answers with an error rather than forwarding, since only a validator's signature admits
    /// a mint (spec §6).
    pub async fn mint_shielded(&self, to: &str, amount: Option<u64>) -> Result<Hash> {
        let params = match amount {
            Some(a) => json!([to, a.to_string()]),
            None => json!([to]),
        };
        let v = self.call("shrugg_mint", params).await?;
        Hash::from_hex(v.as_str().unwrap_or("")).map_err(|e| anyhow!("bad hash in reply: {e}"))
    }

    // ---- confidential computation ----

    pub async fn program(&self, id: &ProgramId) -> Result<Option<Value>> {
        let v = self.call("shrugg_getProgram", json!([id.to_hex()])).await?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    pub async fn program_code(&self, id: &ProgramId) -> Result<Option<(u32, Vec<u32>)>> {
        let v = self.call("shrugg_getProgramCode", json!([id.to_hex()])).await?;
        if v.is_null() {
            return Ok(None);
        }
        let base_pc = v["base_pc"].as_u64().context("base_pc")? as u32;
        let words = v["words"].as_array().context("words")?.iter().map(|w| w.as_u64().unwrap_or(0) as u32).collect();
        Ok(Some((base_pc, words)))
    }

    pub async fn receipt(&self, tx: &Hash) -> Result<Option<Value>> {
        let v = self.call("shrugg_getReceipt", json!([tx.to_hex()])).await?;
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

    /// The fee floor for one action, in units. `params` is the node's `shrugg_estimateFee`
    /// object — `{"kind":"bundle"}`, `{"kind":"deploy","words":n}` or `{"kind":"call","tier":t}`.
    pub async fn estimate_fee(&self, params: Value) -> Result<u64> {
        let v = self.call("shrugg_estimateFee", json!([params])).await?;
        v.as_str().unwrap_or("0").parse().context("fee")
    }

    pub async fn head(&self) -> Result<Value> {
        self.call("shrugg_getHead", json!([])).await
    }
    pub async fn status(&self) -> Result<Value> {
        self.call("shrugg_status", json!([])).await
    }
    pub async fn peers(&self) -> Result<Value> {
        self.call("shrugg_getPeers", json!([])).await
    }
    pub async fn validators(&self) -> Result<Value> {
        self.call("shrugg_getValidators", json!([])).await
    }
    /// `{epoch, epoch_blocks, next_set}` — where the chain is in its epoch schedule, and the set
    /// the next epoch would start with if this one ended now. `next_set` is a projection: every
    /// bond and unbond before the boundary still moves it.
    pub async fn epoch(&self) -> Result<Value> {
        self.call("shrugg_getEpoch", json!([])).await
    }
    pub async fn block_by_height(&self, h: u64) -> Result<Value> {
        self.call("shrugg_getBlockByHeight", json!([h])).await
    }
    pub async fn block_by_hash(&self, h: &Hash) -> Result<Value> {
        self.call("shrugg_getBlockByHash", json!([h.to_hex()])).await
    }

    // ---- shielded chain state (the wallet's scan surface) ----

    /// A page of the commitment tree's leaves from leaf index `from`, oldest first. The node
    /// caps a page at 1000 rows however large `limit` is, so a caller pages until the reply is
    /// short or empty rather than trusting one call to return everything.
    pub async fn commitments(&self, from: u64, limit: usize) -> Result<Vec<CommitmentRow>> {
        let v = self.call("shrugg_getCommitments", json!([from, limit])).await?;
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
        let v = self.call("shrugg_getNullifiers", json!([from_height, limit])).await?;
        let rows = v.as_array().context("getNullifiers did not return a list")?;
        rows.iter().map(|r| Ok((r["height"].as_u64().context("height")?, word8_at(r, "nullifier")?))).collect()
    }

    /// The tree root a prover anchors against: the head's (`None`), or a specific height's.
    pub async fn anchor(&self, height: Option<u64>) -> Result<(u64, Word8)> {
        let params = match height {
            Some(h) => json!([h]),
            None => json!([]),
        };
        let v = self.call("shrugg_getAnchor", params).await?;
        Ok((v["height"].as_u64().context("height")?, word8_at(&v, "root")?))
    }

    /// The Merkle witness of leaf `index` — `(root, siblings leaf-first)`. The root is the
    /// tree's *current* root, which is why a wallet checks it against the anchor it proved
    /// under rather than assuming the two agree.
    pub async fn witness(&self, index: u64) -> Result<(Word8, [Word8; DEPTH])> {
        let v = self.call("shrugg_getWitness", json!([index])).await?;
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
        let v = self.call("shrugg_getTreeInfo", json!([])).await?;
        Ok(TreeInfo {
            next_index: v["next_index"].as_u64().context("next_index")?,
            root: word8_at(&v, "root")?,
            nullifiers: v["nullifiers"].as_u64().context("nullifiers")?,
        })
    }
}

/// A 32-byte value as 64 hex characters, with or without `0x`.
pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).with_context(|| format!("{s:?} is not hex"))?;
    bytes.try_into().map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))
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
}
