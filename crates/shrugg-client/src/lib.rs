//! JSON-RPC client for a SHRUGG full node, plus wallet helpers.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use shrugg_core::bridge::AssetId;
use shrugg_core::program::{program_id, ProgramId};
use shrugg_core::{gas, Address, Hash, Keypair, Transaction, TxKind};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RpcClient {
    url: String,
    http: reqwest::Client,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountInfo {
    pub nonce: u64,
    pub balance: u128,
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

    pub async fn account(&self, addr: &Address) -> Result<AccountInfo> {
        let v = self.call("shrugg_getAccount", json!([addr.to_base58()])).await?;
        Ok(AccountInfo {
            nonce: v["nonce"].as_u64().unwrap_or(0),
            balance: v["balance"].as_str().unwrap_or("0").parse().context("balance")?,
        })
    }

    pub async fn balance(&self, addr: &Address) -> Result<u128> {
        Ok(self.account(addr).await?.balance)
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

    /// Testnet faucet: ask the node to mint `amount` units (default 100 SHRUGG) to `to`.
    pub async fn mint(&self, to: &Address, amount: Option<u128>) -> Result<Hash> {
        let params = match amount {
            Some(a) => json!([to.to_base58(), a.to_string()]),
            None => json!([to.to_base58()]),
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

    pub async fn estimate_fee(&self, kind: &str, n: u64) -> Result<u128> {
        let v = self.call("shrugg_estimateFee", json!([kind, n])).await?;
        v.as_str().unwrap_or("0").parse().context("fee")
    }

    /// Deploy a program (fee = the schedule minimum). Returns (program id, tx hash).
    pub async fn deploy(&self, key: &Keypair, base_pc: u32, words: Vec<u32>) -> Result<(ProgramId, Hash)> {
        let chain_id = self.chain_id().await?;
        let acct = self.account(&key.address()).await?;
        let fee = gas::deploy_fee(words.len());
        if acct.balance < fee {
            return Err(anyhow!("insufficient balance: deploy needs {} SHRUGG", shrugg_core::format_amount(fee)));
        }
        let id = program_id(base_pc, &words);
        let tx = Transaction::deploy(key, chain_id, acct.nonce, base_pc, words, fee);
        let hash = self.send_transaction(&tx).await?;
        Ok((id, hash))
    }

    /// Submit a confidential call with an already computed proof.
    pub async fn call_program(&self, key: &Keypair, program: ProgramId, proof: Vec<u8>, recipients: Vec<Address>, fee: u128) -> Result<Hash> {
        let chain_id = self.chain_id().await?;
        let acct = self.account(&key.address()).await?;
        let tx = Transaction::call(key, chain_id, acct.nonce, program, proof, recipients, fee);
        self.send_transaction(&tx).await
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
    pub async fn block_by_height(&self, h: u64) -> Result<Value> {
        self.call("shrugg_getBlockByHeight", json!([h])).await
    }
    pub async fn block_by_hash(&self, h: &Hash) -> Result<Value> {
        self.call("shrugg_getBlockByHash", json!([h.to_hex()])).await
    }

    /// Build, sign, and submit a transfer using the sender's current on-chain nonce.
    /// Fails before submitting if the balance cannot cover amount + fee.
    pub async fn transfer(&self, key: &Keypair, to: Address, amount: u128, fee: u128) -> Result<Hash> {
        let chain_id = self.chain_id().await?;
        let acct = self.account(&key.address()).await?;
        let need = amount.checked_add(fee).context("amount overflow")?;
        if acct.balance < need {
            return Err(anyhow!(
                "insufficient balance: have {} SHRUGG, need {} SHRUGG",
                shrugg_core::format_amount(acct.balance),
                shrugg_core::format_amount(need)
            ));
        }
        let tx = Transaction::transfer(key, chain_id, acct.nonce, to, amount, fee);
        debug_assert!(matches!(tx.body.kind, TxKind::Transfer { .. }));
        self.send_transaction(&tx).await
    }
}

/// One bridged asset an address holds, as reported by `shrugg_getAssets`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetHolding {
    pub asset: AssetId,
    /// Chain the token is native to (2 Ethereum, 3 BSC, 4 Tron, 5 Solana).
    pub token_chain: u16,
    /// The token's address on its home chain, left-padded to 32 bytes.
    pub token_address: [u8; 32],
    /// Balance in bridged units (8 decimals).
    pub balance: u128,
}

/// A 32-byte value as 64 hex characters, with or without `0x`.
pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).with_context(|| format!("{s:?} is not hex"))?;
    bytes.try_into().map_err(|v: Vec<u8>| anyhow!("expected 32 bytes, got {}", v.len()))
}

/// Bridged assets. Amounts here are in bridged units — 8 decimals, not
/// SHRUGG's 9 — so they are passed and printed as plain unit integers.
impl RpcClient {
    /// `addr`'s balance of one bridged asset, in units. Zero for an unknown
    /// asset, an untouched address, or a chain without a bridge.
    pub async fn asset_balance(&self, addr: &Address, asset: &AssetId) -> Result<u128> {
        let v = self.call("shrugg_getAssetBalance", json!([addr.to_base58(), asset.to_hex()])).await?;
        v.as_str().unwrap_or("0").parse().context("asset balance")
    }

    /// Every bridged asset `addr` holds a non-zero balance of.
    pub async fn assets(&self, addr: &Address) -> Result<Vec<AssetHolding>> {
        let v = self.call("shrugg_getAssets", json!([addr.to_base58()])).await?;
        v.as_array()
            .context("assets: expected an array")?
            .iter()
            .map(|a| {
                Ok(AssetHolding {
                    asset: Hash::from_hex(a["asset"].as_str().unwrap_or("")).map_err(|e| anyhow!("asset: {e}"))?,
                    token_chain: a["token_chain"].as_u64().context("token_chain")? as u16,
                    token_address: hex32(a["token_address"].as_str().unwrap_or(""))?,
                    balance: a["balance"].as_str().unwrap_or("0").parse().context("balance")?,
                })
            })
            .collect()
    }

    /// The chain's bridge configuration and guardian set. Always answers;
    /// `{"enabled": false}` on a chain without a bridge.
    pub async fn bridge_state(&self) -> Result<Value> {
        self.call("shrugg_getBridgeState", json!([])).await
    }

    /// One outbound burn message for guardians to sign, or `None` if that
    /// sequence has not been produced yet.
    pub async fn bridge_burn_record(&self, sequence: u64) -> Result<Option<Value>> {
        let v = self.call("shrugg_getBridgeBurn", json!([sequence])).await?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    /// The asset id of a token: `blake3("shrugg-bridge-asset" || chain || address)`.
    /// Asked of the node so the wallet and the chain cannot disagree.
    pub async fn bridge_asset_id(&self, token_chain: u16, token_address: &[u8; 32]) -> Result<AssetId> {
        let v = self.call("shrugg_bridgeAssetId", json!([token_chain, hex::encode(token_address)])).await?;
        Hash::from_hex(v.as_str().unwrap_or("")).map_err(|e| anyhow!("bad asset id in reply: {e}"))
    }

    /// Submit a guardian-signed attestation: mints the bridged asset it
    /// carries (or rotates the guardian set). `fee` is the SHRUGG transaction
    /// fee; the bridge fee inside the attestation goes to the submitter.
    pub async fn bridge_attest(&self, key: &Keypair, attestation: Vec<u8>, fee: u128) -> Result<Hash> {
        let chain_id = self.chain_id().await?;
        let acct = self.account(&key.address()).await?;
        if acct.balance < fee {
            return Err(anyhow!("insufficient balance for the {} SHRUGG fee", shrugg_core::format_amount(fee)));
        }
        let tx = Transaction::bridge_attest(key, chain_id, acct.nonce, attestation, fee);
        self.send_transaction(&tx).await
    }

    /// Burn `amount` units of a bridged asset and emit the outbound message a
    /// source-chain contract releases against. `bridge_fee` (in the same
    /// bridged units, at most `amount`) is carried in that message for
    /// whoever relays it; `fee` is the SHRUGG transaction fee.
    #[allow(clippy::too_many_arguments)]
    pub async fn bridge_burn(
        &self,
        key: &Keypair,
        asset: AssetId,
        amount: u128,
        to_chain: u16,
        to: [u8; 32],
        bridge_fee: u128,
        fee: u128,
    ) -> Result<Hash> {
        let chain_id = self.chain_id().await?;
        let acct = self.account(&key.address()).await?;
        if acct.balance < fee {
            return Err(anyhow!("insufficient balance for the {} SHRUGG fee", shrugg_core::format_amount(fee)));
        }
        let have = self.asset_balance(&key.address(), &asset).await?;
        if have < amount {
            return Err(anyhow!("insufficient bridged balance: have {have} units, need {amount}"));
        }
        let tx = Transaction::bridge_burn(key, chain_id, acct.nonce, asset, amount, to_chain, to, bridge_fee, fee);
        self.send_transaction(&tx).await
    }
}
