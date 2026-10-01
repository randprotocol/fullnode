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
use randprotocol_core::notes::{word8_from_hex, Envelope, EnvelopeFormat, Word8, DEPTH};
use randprotocol_core::program::ProgramId;
use randprotocol_core::types::CallEnvelope;
use randprotocol_core::{BindingDomain, Hash, Transaction};
use std::time::{Duration, Instant};

pub mod contacts;
pub mod governance;
pub mod memo_display;
pub mod prover;
pub mod qr;
pub mod tree;
pub mod wallet;

/// A node's JSON-RPC error reply. It prints as it always has, `"<message> (rpc <code>)"`, and
/// keeps its code, so a caller can tell an older node (no such method, [`METHOD_NOT_FOUND`]) from
/// every other failure: `err.downcast_ref::<RpcError>()`, or [`is_method_not_found`]. `data` is
/// the reply's `data` member when it had one — a pruned node's `-32010` names its floor there
/// ([`pruned_floor`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
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

/// A u64 amount off an RPC reply, however the node encoded it: a JSON number or a decimal
/// string.
///
/// Since chain 14 the node's rule is that every u64 *amount* — RAND units or token units — is a
/// decimal string, while indices, heights, nonces, counts, lengths, decimals and days stay
/// numbers (node I3): a 9-decimal token with a 10 M supply is 1e16, past a JS client's
/// `Number.MAX_SAFE_INTEGER`, and zUSD passes it at ~90 M locked. Older nodes send numbers, and
/// a wallet has to talk to both — so every amount this crate reads goes through here rather than
/// through `as_u64()`, which silently answers `None` for a string and turns a correct reply into
/// "an asset row without a locked amount".
///
/// `None` for absent, null, a non-integral number, a non-numeral string or anything else.
pub fn amount_field(v: &serde_json::Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Re-label a `rand_sendTransaction` failure as [`SubmitRefused`] only when the reply is a
/// **verdict** on the transaction — `-32000` (`RpcError::rejected`, admission refused it) or
/// `-32602` (`RpcError::invalid_params`, it could not even be decoded) — and leave every other
/// failure, error codes included, exactly as it is (node N-2).
///
/// `-32603` (`RpcError::internal`, "node loop closed" / "node loop dropped reply") is not a
/// verdict: `Node::on_verdict`'s RPC arm pools and broadcasts the transaction *before* it replies,
/// so a node that stops or drops the channel in that window can have already admitted and gossiped
/// what it never got to answer for. Labelling that `-32603` as refused was node I1's bug reborn
/// through a narrower window — deleting the only copy of a fresh key for a registration that may
/// still commit through another validator. Any code besides `-32000`/`-32602` therefore keeps the
/// caller's fate-unknown handling (the `.pending` key stays, in `wallet.rs`'s terms).
pub fn submit_refused(e: anyhow::Error) -> anyhow::Error {
    match e.downcast::<RpcError>() {
        Ok(rpc) if rpc.code == -32000 || rpc.code == -32602 => anyhow::Error::new(SubmitRefused(rpc)),
        Ok(rpc) => anyhow::Error::new(rpc),
        Err(other) => other,
    }
}

/// JSON-RPC's "method not found": what a node too old to know a method answers.
pub const METHOD_NOT_FOUND: i64 = -32601;

/// True when `e` is a node saying it has no such method — the one error a wallet falls back on.
pub fn is_method_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<RpcError>().is_some_and(|r| r.code == METHOD_NOT_FOUND)
}

/// A node started with `--prune-history` answers a height below its retention floor with this
/// code, naming the floor in `data.floor` (`docs/rpc.md`).
pub const PRUNED: i64 = -32010;

/// The retention floor `e` names, when `e` is a pruned node's `-32010` that carries one.
pub fn pruned_floor(e: &anyhow::Error) -> Option<u64> {
    let r = e.downcast_ref::<RpcError>().filter(|r| r.code == PRUNED)?;
    r.data.as_ref()?.get("floor")?.as_u64()
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
    /// Spec 2026-09-26 §2.4: the exact note-envelope size this chain's genesis sets, `null`
    /// (the legacy shape) where it keeps today's at-most rule. `#[serde(default)]` so a reply
    /// from a node that predates this field — task 5's genesis field, not just the method —
    /// still decodes, at `None`.
    #[serde(default)]
    pub envelope_bytes: Option<usize>,
    /// Whether the chain's genesis sets `hardening_v6`: then a call proves over
    /// `Transaction::call_binding` (INT-4) and `rand call` takes that path. `false` from a node
    /// that predates the field, which is right — such a node runs no chain with the flag.
    #[serde(default)]
    pub hardening_v6: bool,
    /// Gas units per RAND-unit, under the node's gas policy (spec 2026-09-28 §4.1/§8). `None`
    /// from a node that runs no policy or predates the field — paired with `byte_price` below to
    /// decide [`ChainLimits::gas_policy`]. `gas_metering` is decoded only as
    /// [`ChainLimits::gas_circuit`], the one fact about it the wallet acts on.
    ///
    /// A price is a RAND amount, so the node sends a decimal string (docs/rpc.md); a number is
    /// accepted too, for a node built before that rule reached these two fields.
    #[serde(default, deserialize_with = "opt_u64_string_or_number")]
    pub gas_price: Option<u64>,
    /// Byte-units per RAND-unit, under the node's gas policy. See `gas_price` above.
    #[serde(default, deserialize_with = "opt_u64_string_or_number")]
    pub byte_price: Option<u64>,
    /// Spec 2026-09-28 §3.3, §9: `gas_metering == "circuit"` — the chain's genesis carries a
    /// `gas` section, so a call pays for the `GAS_LIMIT` its proof declares
    /// (`gas::circuit_call_floor`), not for its header's ceiling. `"header"` (a node's Phase 0
    /// policy), `null`, an absent key and any value this wallet does not know all read `false`.
    #[serde(default, rename = "gas_metering", deserialize_with = "metering_is_circuit")]
    pub gas_circuit: bool,
    /// The bundle guest's flat declared gas under a `gas` section (genesis
    /// `gas.bundle_gas_limit`); `None` without one. The wallet proves only the guest whose
    /// ceiling it is (`wallet::check_bundle_gas_limit`).
    #[serde(default)]
    pub bundle_gas_limit: Option<u64>,
    /// The dynamic price controller's step, in basis points (genesis `gas.dynamic.adjust_bps`),
    /// `None` on a chain whose prices never move. The wallet pays two steps of headroom over the
    /// tip's floor (spec §7.1: the served prices are the committed head's, and a transaction lands
    /// two or three certified blocks later).
    #[serde(default)]
    pub adjust_bps: Option<u32>,
    /// Issue #118: the genesis `proof_window_blocks` — how old, in blocks, a bundle's anchor and
    /// `time` may be on this chain — `None` where the genesis has none (both windows 256) and from
    /// a node that predates the field. The wallet reads it only for when a `--no-wait` spend can
    /// no longer commit (`wallet::clear_pending`), clamped to the bounds a genesis can carry.
    #[serde(default)]
    pub proof_window_blocks: Option<u64>,
    /// RPL-2 (program state): the genesis `program_state` section and the invoke limits with
    /// it, `None` on a chain without the section — where no invoke is admitted — and from a
    /// node that predates the field, which runs no chain with it.
    #[serde(default)]
    pub program_state: Option<ProgramStateLimits>,
}

/// `rand_getLimits.program_state` (RPL-2): what an invoke is sized and priced by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct ProgramStateLimits {
    /// RAND units added to an invoke's fee floor per cell it creates. A decimal string on the
    /// wire, like every amount.
    #[serde(deserialize_with = "u64_string_or_number")]
    pub cell_fee: u64,
    pub max_reads: usize,
    pub max_writes: usize,
    pub max_payouts: usize,
}

/// A u64 sent as a decimal string or as a JSON number (the required-field twin of
/// [`opt_u64_string_or_number`]).
fn u64_string_or_number<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    opt_u64_string_or_number(d)?.ok_or_else(|| serde::de::Error::custom("a u64 amount, not null"))
}

/// `gas_metering` as the one fact the wallet acts on: is it `"circuit"`?
fn metering_is_circuit<'de, D: serde::Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    Ok(<Option<String> as serde::Deserialize>::deserialize(d)?.as_deref() == Some("circuit"))
}

/// An optional u64 sent as a decimal string or as a JSON number; `None` for `null` (and, with
/// `#[serde(default)]`, for an absent key). Anything else — a negative, a fraction, a string
/// that is not a decimal u64 — is a decode error, never a guess.
fn opt_u64_string_or_number<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Amount {
        Number(u64),
        Text(String),
    }
    match <Option<Amount> as serde::Deserialize>::deserialize(d)? {
        None => Ok(None),
        Some(Amount::Number(n)) => Ok(Some(n)),
        Some(Amount::Text(t)) => {
            if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(serde::de::Error::custom(format!("not a decimal amount: {t:?}")));
            }
            t.parse().map(Some).map_err(serde::de::Error::custom)
        }
    }
}

impl ChainLimits {
    /// The node's gas policy (spec 2026-09-28 §8), `None` from a node that runs none or
    /// predates the fields.
    pub fn gas_policy(&self) -> Option<randprotocol_core::gas::GasPolicy> {
        match (self.gas_price, self.byte_price) {
            (Some(gas_price), Some(byte_price)) => Some(randprotocol_core::gas::GasPolicy { gas_price, byte_price }),
            _ => None,
        }
    }
}

/// Words from `rand_getProgramPublic`'s one hex string: each word as its four little-endian bytes,
/// so eight hex digits a word; `""` is no words.
pub fn words_from_le_hex(s: &str) -> Result<Vec<u32>> {
    let bytes = hex::decode(s).context("the public input is not hex")?;
    if bytes.len() % 4 != 0 {
        return Err(anyhow!("the public input is {} bytes, not whole words", bytes.len()));
    }
    Ok(bytes.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect())
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

/// The chain ids of every public chain whose genesis carries no `envelope_bytes` (issue #64):
/// chains 14–17, every chain that ran a build able to seal the memo form. Chains before 14 are
/// retired and their data deleted fleet-wide, so nothing admits a transaction for them. **Every
/// chain cut without `envelope_bytes` is added here** — `every_committed_genesis_without_
/// envelope_bytes_is_pinned` fails until it is.
pub const LEGACY_ENVELOPE_CHAIN_IDS: &[u64] = &[14, 15, 16, 17];

/// The envelope format for a transaction on `chain_id` given the node's `envelope_bytes` claim:
/// [`EnvelopeFormat::Legacy`] on a chain id pinned in [`LEGACY_ENVELOPE_CHAIN_IDS`] whatever the
/// node claimed (issue #64), the claim's format everywhere else.
pub fn envelope_format_for(chain_id: u64, node_envelope_bytes: Option<u32>) -> EnvelopeFormat {
    if LEGACY_ENVELOPE_CHAIN_IDS.contains(&chain_id) {
        return EnvelopeFormat::Legacy;
    }
    EnvelopeFormat::for_chain(node_envelope_bytes)
}

/// BIND-1 (audit v6, issue #79): the chain ids of every public chain whose genesis carries no
/// `binding_domain` — chains 14–19 (19 the v0.6.7 re-genesis, cut without it), where a transaction's binding and every signed action message
/// bind the chain id alone. On these, and only on these, a wallet proves and signs the chain-id
/// form. **Every chain cut without `binding_domain` is added here** —
/// `every_committed_genesis_without_binding_domain_is_pinned` fails until it is.
pub const CHAIN_ID_BINDING_CHAIN_IDS: &[u64] = &[14, 15, 16, 17, 18, 19];

/// The [`BindingDomain`] a wallet uses for a transaction it builds for `chain_id`, given the
/// genesis hash its note store is bound to (BIND-1).
///
/// Whether a chain uses `binding_domain` is decided by the transaction's own chain id, never by
/// the node's `rand_getLimits.binding_domain` — nothing in that reply is authenticated (the
/// `envelope_bytes` trap, issue #64). A chain id in [`CHAIN_ID_BINDING_CHAIN_IDS`] gets the
/// chain-id form whatever the node says: the real chain with that id accepts nothing else. Every
/// other chain id gets the genesis-bound form, over `genesis`.
///
/// `genesis` is itself the node's word (`rand_getGenesisHash`, which the store was bound to at
/// its first scan), and that is the safe direction to be lied to in. A genesis-bound binding or
/// signature is valid on exactly one chain: the one whose genesis hash is the hash inside it. A
/// node that reports a hash other than the real chain's makes this wallet's transactions invalid
/// on the real chain — refused `InvalidBundleProof` / a bad signature, nothing admitted, nothing
/// spent — and valid only on a chain whose genesis *is* the hash it reported, which is the chain
/// the liar described. It can never make them valid on a second chain, which is the whole of what
/// BIND-1 is about. The reverse lie does not exist: there is no answer a node can give that makes
/// this function return the chain-id form on a chain id outside the list.
pub fn binding_domain_for(chain_id: u64, genesis: Hash) -> BindingDomain {
    if CHAIN_ID_BINDING_CHAIN_IDS.contains(&chain_id) {
        return BindingDomain::ChainId;
    }
    BindingDomain::Genesis(genesis)
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
    /// [`RpcClient::envelope_format`]'s cache: one `rand_getLimits` read for the life of this
    /// client and everything cloned from it (the `Arc` is shared, like `legacy_status` above),
    /// not one per bundle a wallet builds.
    ///
    /// BIND-1: the same one read carries the node's `binding_domain` claim beside it
    /// ([`RpcClient::claimed_binding_domain`]) — `(envelope_bytes, binding_domain)`.
    envelope_format: std::sync::Arc<tokio::sync::OnceCell<(Option<u32>, u32)>>,
    /// The first wait after a rate-limit refusal (issue #117); doubled per retry up to
    /// [`RATE_LIMIT_RETRIES`] retries. A second in production; tests shorten it.
    rate_limit_wait: Duration,
}

/// How many times a call refused for rate limiting is retried, with waits of `rate_limit_wait`
/// × 1, 2, 4, 8, 16: about 31 s in all at the production base. A first sync used to make several
/// hundred calls in one burst and give up at the first `-32005` with nothing saved, so every
/// retry started from zero (issue #117).
pub const RATE_LIMIT_RETRIES: u32 = 5;

/// Whether `code`/`message` is a proxy's or a node's "slow down": the sale proxy's `-32005`, HTTP
/// 429's usual text, and the node's own `-32000` refusals that say so ("rate limited", "busy").
pub fn is_rate_limited(code: i64, message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    code == -32005 || m.contains("rate limit") || m.contains("slow down") || m.contains("too many requests") || (code == -32000 && m.contains("busy"))
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
/// The most of a node's reply [`RpcClient::call`] reads before refusing it (wallet scan, minor):
/// 64 MiB. `.json()` buffered whatever a node sent and parsed it whole. The largest honest replies
/// are a few MiB — a full block with its proofs in hex, a commitments page, a 1024-header
/// `rand_getBlocks` page — so this leaves them an order of magnitude and more.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// A reply [`read_capped`] refused for passing its cap — typed, so a caller that can ask for
/// less (the wallet's header walk, audit v7 RPC-5) tells it from any other failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyTooLarge {
    pub limit: usize,
}

impl std::fmt::Display for ReplyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the reply is larger than {} MiB; refusing it", self.limit / (1024 * 1024))
    }
}

impl std::error::Error for ReplyTooLarge {}

/// Whether `e` is a reply refused for its size ([`ReplyTooLarge`]), under any context.
pub fn reply_too_large(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ReplyTooLarge>().is_some()
}

/// Read `resp`'s body, refusing it once it passes `limit` bytes — up front on a declared
/// `Content-Length`, otherwise chunk by chunk as it arrives.
pub(crate) async fn read_capped(mut resp: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let too_big = || anyhow::Error::new(ReplyTooLarge { limit });
    if resp.content_length().is_some_and(|n| n > limit as u64) {
        return Err(too_big());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading rpc response")? {
        if body.len() + chunk.len() > limit {
            return Err(too_big());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

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
            envelope_format: std::sync::Arc::new(tokio::sync::OnceCell::new()),
            rate_limit_wait: Duration::from_secs(1),
        }
    }

    /// This client with another first rate-limit wait (tests: milliseconds instead of a second).
    pub fn with_rate_limit_wait(mut self, wait: Duration) -> RpcClient {
        self.rate_limit_wait = wait;
        self
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
        let mut wait = self.rate_limit_wait;
        for retry in 0..=RATE_LIMIT_RETRIES {
            match self.call_once(method, params.clone()).await {
                Err(e) if retry < RATE_LIMIT_RETRIES && e.downcast_ref::<RpcError>().is_some_and(|r| is_rate_limited(r.code, &r.message)) => {
                    // A refusal to slow down is not a failure of the call (issue #117): wait and
                    // ask again, longer each time, and say so once so a long first sync is not
                    // mistaken for a hang.
                    if retry == 0 {
                        eprintln!("{method}: the node asked this wallet to slow down; waiting and retrying");
                    }
                    tokio::time::sleep(wait).await;
                    wait *= 2;
                }
                r => return r,
            }
        }
        unreachable!("the loop returns on its last iteration")
    }

    async fn call_once(&self, method: &str, params: Value) -> Result<Value> {
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
        let resp = req
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
            })?;
        let resp: Value = serde_json::from_slice(&read_capped(resp, MAX_RESPONSE_BYTES).await?).context("decoding rpc response")?;
        if let Some(err) = resp.get("error") {
            let message = err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown").to_string();
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let data = err.get("data").filter(|d| !d.is_null()).cloned();
            return Err(RpcError { code, message, data }.into());
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

    // ---- program state (RPL-2) ----

    /// One cell of `program` (`rand_getProgramCell`): its value, 64 zeros when absent. `None` on
    /// a chain without the `program_state` section.
    pub async fn program_cell(&self, program: &ProgramId, key: &Word8) -> Result<Option<Word8>> {
        let v = self.call("rand_getProgramCell", json!([program.to_hex(), randprotocol_core::notes::word8_to_hex(key)])).await?;
        if v["enabled"] == json!(false) {
            return Ok(None);
        }
        let value = v["value"].as_str().context("rand_getProgramCell did not return a value")?;
        word8_from_hex(value).map(Some).ok_or_else(|| anyhow!("rand_getProgramCell's value is not 64 hex: {value}"))
    }

    /// A page of `program`'s cells in key order (`rand_getProgramCells`), starting after `after`:
    /// the cells and the key to continue from (`None` on the last page). `None` on a chain
    /// without the section.
    pub async fn program_cells(
        &self,
        program: &ProgramId,
        after: Option<&Word8>,
        limit: usize,
    ) -> Result<Option<(Vec<randprotocol_core::ledger::program_state::Cell>, Option<Word8>)>> {
        let page = json!({ "after": after.map(randprotocol_core::notes::word8_to_hex), "limit": limit });
        let v = self.call("rand_getProgramCells", json!([program.to_hex(), page])).await?;
        if v["enabled"] == json!(false) {
            return Ok(None);
        }
        let cell = |c: &Value| -> Result<randprotocol_core::ledger::program_state::Cell> {
            let word = |name: &str| {
                let s = c[name].as_str().with_context(|| format!("a cell without its {name}"))?;
                word8_from_hex(s).ok_or_else(|| anyhow!("a cell's {name} is not 64 hex: {s}"))
            };
            Ok(randprotocol_core::ledger::program_state::Cell { key: word("key")?, value: word("value")? })
        };
        let cells = v["cells"].as_array().context("rand_getProgramCells did not return cells")?.iter().map(cell).collect::<Result<Vec<_>>>()?;
        let next = match v["next"].as_str() {
            Some(s) => Some(word8_from_hex(s).ok_or_else(|| anyhow!("rand_getProgramCells's next is not 64 hex: {s}"))?),
            None => None,
        };
        Ok(Some((cells, next)))
    }

    /// `program`'s vault (`rand_getProgramVault`): `(asset, amount)` ascending by asset, 0 being
    /// RAND. `None` on a chain without the section.
    pub async fn program_vault(&self, program: &ProgramId) -> Result<Option<Vec<(u32, u64)>>> {
        let v = self.call("rand_getProgramVault", json!([program.to_hex()])).await?;
        if v["enabled"] == json!(false) {
            return Ok(None);
        }
        v.as_array()
            .context("rand_getProgramVault did not return a list")?
            .iter()
            .map(|row| {
                let asset = u32::try_from(row["asset"].as_u64().context("a vault row without its asset")?).context("asset index")?;
                let amount = amount_field(&row["amount"]).context("a vault row without its amount")?;
                Ok((asset, amount))
            })
            .collect::<Result<Vec<_>>>()
            .map(Some)
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

    /// This chain's note-envelope format (spec 2026-09-26 §2.4) for a transaction built for
    /// `chain_id` — the chain id the caller puts on that very transaction.
    ///
    /// `rand_getLimits.envelope_bytes` is the node's word, and nothing in its reply is
    /// authenticated (issue #64). On a chain whose genesis sets no `envelope_bytes` the ledger
    /// still admits any note envelope up to 2 048 bytes, so a node — or anything between the
    /// wallet and it — answering `1860` there would make this wallet seal every output at
    /// 1 860 bytes among everyone else's 1 348: a permanent, public tag on each of its
    /// transactions. The node cannot serve the genesis file itself (`rand-node run` keeps only
    /// its hash), so the claim cannot be checked against the genesis; instead the memo form is
    /// refused outright on every chain id in [`LEGACY_ENVELOPE_CHAIN_IDS`], whatever the node
    /// says. The chain id is the one thing here a lying node cannot move: it is bound into the
    /// transaction, and a transaction carrying the wrong one is refused `WrongChain` by the real
    /// chain — no admission, so no tag. The reverse lie (a memo chain answered as legacy) only
    /// gets this wallet's transactions refused `EnvelopeSize`: a liveness nuisance, not a leak.
    ///
    /// The node's answer is cached for the life of this client: the first call pays one
    /// `rand_getLimits` round trip and every later call reuses it. A node too old for
    /// `rand_getLimits`, or whose reply predates the field, reads `envelope_bytes` as `None`,
    /// which `EnvelopeFormat::for_chain` turns into [`EnvelopeFormat::Legacy`]. A failed read is
    /// never cached (`get_or_try_init` only stores the `Ok` arm), so a transient RPC failure does
    /// not wrongly pin this client to `Legacy` for the rest of its life.
    pub async fn envelope_format(&self, chain_id: u64) -> Result<EnvelopeFormat> {
        let (envelope_bytes, _) = self.cached_limits().await?;
        Ok(envelope_format_for(chain_id, envelope_bytes))
    }

    /// The one cached `rand_getLimits` read behind [`RpcClient::envelope_format`] and
    /// [`RpcClient::claimed_binding_domain`]: `(envelope_bytes, binding_domain)`, `(None, 0)` from
    /// a node too old for the method or for either field. A failed read is never cached.
    async fn cached_limits(&self) -> Result<(Option<u32>, u32)> {
        let cached = self
            .envelope_format
            .get_or_try_init(|| async {
                let v = match self.call("rand_getLimits", json!([])).await {
                    Ok(v) => v,
                    Err(e) if is_method_not_found(&e) => return Ok((None, 0)),
                    Err(e) => return Err(e),
                };
                // The envelope size through the typed reply, exactly as before; the binding
                // domain off the same JSON, absent (an older node) read as 0.
                let limits: ChainLimits = serde_json::from_value(v.clone()).context("decoding rand_getLimits")?;
                let bytes = limits.envelope_bytes.and_then(|n| u32::try_from(n).ok());
                let binding = v.get("binding_domain").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).unwrap_or(0);
                Ok::<_, anyhow::Error>((bytes, binding))
            })
            .await?;
        Ok(*cached)
    }

    /// What this node says the chain's genesis `binding_domain` is (BIND-1): `0` or `1`, `0` from
    /// a node that predates the field. **The node's unauthenticated word** — it never decides
    /// which binding a wallet proves ([`binding_domain_for`] does, from the chain id); it is read
    /// only to refuse early, with a reason, what the chain would refuse after a proof
    /// ([`RpcClient::binding_domain`], `wallet::binding_domain`).
    pub async fn claimed_binding_domain(&self) -> Result<u32> {
        Ok(self.cached_limits().await?.1)
    }

    /// Refuse, before anything is proved or signed, a chain this wallet could not transact on
    /// (BIND-1): `chain_id` is not one of the chains cut before `binding_domain`
    /// ([`CHAIN_ID_BINDING_CHAIN_IDS`]), so this wallet signs only genesis-bound messages for it —
    /// and the node says its genesis has no `binding_domain`, so its ledger would refuse every one
    /// of them. A lying node can only make this wallet refuse to send; it cannot make it sign the
    /// chain-id form.
    pub async fn require_binding_domain(&self, chain_id: u64) -> Result<()> {
        if CHAIN_ID_BINDING_CHAIN_IDS.contains(&chain_id) || self.claimed_binding_domain().await? >= 1 {
            return Ok(());
        }
        Err(anyhow!(
            "this node reports no binding_domain for chain {chain_id}, and chain {chain_id} is not one of the chains cut before it \
             ({CHAIN_ID_BINDING_CHAIN_IDS:?}): this wallet signs only genesis-bound transactions there (BIND-1), which a chain \
             without binding_domain refuses. Cut the genesis with `rand-node genesis --binding-domain 1`, or use a node on a \
             build that serves rand_getLimits.binding_domain"
        ))
    }

    /// The [`BindingDomain`] of a transaction or a signed message for `chain_id`, for a tool that
    /// holds no note store — an operator's `rand-node unbond`, a governance submission: the
    /// chain-id domain on the chains cut before `binding_domain`, otherwise the genesis-bound one
    /// over this node's own `rand_getGenesisHash` ([`binding_domain_for`] says why a lie there is
    /// harmless), refused early when the node says the chain has no such domain. A wallet with a
    /// store takes the hash from the store instead (`wallet::binding_domain`).
    pub async fn binding_domain(&self, chain_id: u64) -> Result<BindingDomain> {
        if CHAIN_ID_BINDING_CHAIN_IDS.contains(&chain_id) {
            return Ok(BindingDomain::ChainId);
        }
        self.require_binding_domain(chain_id).await?;
        Ok(binding_domain_for(chain_id, self.genesis_hash().await?))
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
    /// `rand_getGenesisHash`: which chain this node serves. A wallet's note store is bound to it,
    /// so a store carried across a chain cut is started over rather than scanned past the end of
    /// the new chain's tree.
    pub async fn genesis_hash(&self) -> Result<Hash> {
        let v = self.call("rand_getGenesisHash", json!([])).await?;
        Hash::from_hex(v.as_str().unwrap_or("")).map_err(|e| anyhow!("bad genesis hash in reply: {e}"))
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
    /// `tx_count`. The node caps one reply (1,024 headers, a byte budget since audit v7 RPC-5)
    /// and at its head, so a caller advances from the last height it got back rather than from
    /// `to`. A node without the byte budget can answer a page past this client's reply cap: that
    /// is a [`ReplyTooLarge`] error, and the caller asks for a shorter range.
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
        /// An error reply that carries `data`, as the node's `-32010` does (`{"floor": f}`).
        ErrData(i64, String, Value),
        /// Close the connection without answering (a reset, as a network blip or a restart shows it).
        Drop,
        /// Answer `200 OK` with this body, which is not JSON-RPC (a proxy's error page).
        Malformed(&'static str),
        /// Announce a body past the client's 64 MiB reply cap (`content-length` alone, no body
        /// sent), as a node without a reply budget answers an oversized page (audit v7, RPC-5).
        TooLarge,
    }

    pub async fn scripted_rpc(script: Vec<(&'static str, Reply)>) -> String {
        let script = std::sync::Arc::new(script);
        rpc_fn(move |method, _| match script.iter().find(|(m, _)| *m == method) {
            Some((_, Reply::Ok(v))) => Reply::Ok(v.clone()),
            Some((_, Reply::Err(code, msg))) => Reply::Err(*code, msg),
            Some((_, Reply::ErrData(code, msg, data))) => Reply::ErrData(*code, msg.clone(), data.clone()),
            Some((_, Reply::Drop)) => Reply::Drop,
            Some((_, Reply::Malformed(body))) => Reply::Malformed(body),
            Some((_, Reply::TooLarge)) => Reply::TooLarge,
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
                        Reply::Drop => return,
                        Reply::TooLarge => {
                            let head = format!(
                                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n",
                                super::MAX_RESPONSE_BYTES + 1
                            );
                            let _ = sock.write_all(head.as_bytes()).await;
                            let _ = sock.flush().await;
                            return;
                        }
                        Reply::Malformed(body) => body.to_string(),
                        Reply::Ok(v) => json!({ "jsonrpc": "2.0", "id": 1, "result": v }).to_string(),
                        Reply::Err(code, msg) => {
                            json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": msg } }).to_string()
                        }
                        Reply::ErrData(code, msg, data) => {
                            json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": msg, "data": data } }).to_string()
                        }
                    };
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

    /// `--rpc https://…` must reach the wire. The client was once built without a TLS backend,
    /// and reqwest then refused every https URL before connecting ("URL scheme is not allowed"),
    /// which made the public endpoint (`https://rpc.randprotocol.org`) unusable from the CLI.
    /// Nothing listens on this port, so a TLS-capable client fails at the connection, never at
    /// the scheme.
    #[tokio::test]
    async fn an_https_url_is_attempted_not_refused_for_its_scheme() {
        let rpc = RpcClient::new("https://127.0.0.1:1/");
        let err = format!("{:#}", rpc.head().await.expect_err("nothing listens on port 1"));
        assert!(!err.to_lowercase().contains("scheme"), "{err}");
        assert!(err.contains("connecting to https://127.0.0.1:1/"), "{err}");
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

    /// A node's reply is read with a bound: past 64 MiB (the whole JSON body) the call is refused
    /// rather than buffered and parsed whole. The largest honest replies — a 1024-header
    /// `rand_getBlocks` page, a commitments page, a full block — are a few MiB at most.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_oversized_reply_is_refused_not_buffered() {
        let pad = "x".repeat(64 * 1024 * 1024);
        let reply = format!(r#"{{"jsonrpc":"2.0","id":1,"result":"{pad}"}}"#);
        let (url, _seen) = slow_server(Duration::ZERO, Box::leak(reply.into_boxed_str())).await;
        let e = match RpcClient::new(url).call("rand_getHead", json!([])).await {
            Ok(v) => panic!("a reply past the cap is refused, got {} bytes of result", v.as_str().map_or(0, str::len)),
            Err(e) => e,
        };
        assert!(format!("{e:#}").contains("larger than"), "{e:#}");
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
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
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
    /// Issue #117: a "slow down" from the proxy (`-32005`) or the node (`-32000` rate limited /
    /// busy) is waited out and the call retried, with the wait doubling; any other error, and a
    /// refusal that outlasts every retry, is the caller's as before.
    #[tokio::test]
    async fn a_rate_limited_call_waits_and_retries_and_gives_up_after_the_last_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let url = test_rpc::rpc_fn(move |method, _| {
            let n = h.fetch_add(1, Ordering::SeqCst);
            match method {
                "rand_chainId" if n < 2 => test_rpc::Reply::Err(-32005, "rate limit: slow down"),
                "rand_chainId" => test_rpc::Reply::Ok(json!(7)),
                "rand_getHead" => test_rpc::Reply::Err(-32000, "this node's RPC is busy; retry shortly"),
                _ => test_rpc::Reply::Err(-32602, "bad params"),
            }
        })
        .await;
        let rpc = RpcClient::new(url).with_rate_limit_wait(Duration::from_millis(2));
        assert_eq!(rpc.chain_id().await.unwrap(), 7, "two refusals, then served");
        assert_eq!(hits.load(Ordering::SeqCst), 3);
        // A refusal that never lifts is reported after the last retry, as the refusal it was.
        hits.store(0, Ordering::SeqCst);
        let e = rpc.call("rand_getHead", json!([])).await.unwrap_err();
        assert!(e.downcast_ref::<RpcError>().is_some_and(|r| r.code == -32000 && r.message.contains("busy")), "{e}");
        assert_eq!(hits.load(Ordering::SeqCst), 1 + RATE_LIMIT_RETRIES as usize);
        // Not a rate limit: no retry.
        hits.store(0, Ordering::SeqCst);
        assert!(rpc.call("rand_other", json!([])).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        assert!(is_rate_limited(-32005, "anything") && is_rate_limited(-32000, "rate limited: this node serves 120") && is_rate_limited(0, "Too Many Requests"));
        assert!(!is_rate_limited(-32000, "rejected: fee too low") && !is_rate_limited(-32010, "pruned"));
    }

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
                // The scripted reply above carries no `envelope_bytes` key at all — exactly a
                // node that predates the field — and it still decodes, at `None`.
                envelope_bytes: None,
                // Nor `hardening_v6`: at `false`, the old call rule.
                hardening_v6: false,
                // Nor a gas policy: no `gas_price`/`byte_price` key in this reply either.
                gas_price: None,
                byte_price: None,
                // Nor a gas section.
                gas_circuit: false,
                bundle_gas_limit: None,
                adjust_bps: None,
                // Nor a proof window (issue #118): 256 blocks.
                proof_window_blocks: None,
                // Nor a program_state section.
                program_state: None,
            })
        );
        let older = RpcClient::new(scripted_rpc(vec![]).await);
        assert_eq!(older.limits().await.unwrap(), None);
        let broken = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Err(-32603, "db closed"))]).await);
        assert!(broken.limits().await.is_err());
    }

    /// `gas_policy()`: `None` from a node that predates the fields or runs no policy;
    /// `gas_metering: "header"` decodes as no gas section (`limits_decode_the_gas_section`).
    #[tokio::test]
    async fn limits_gas_policy_is_none_without_both_prices() {
        use test_rpc::{scripted_rpc, Reply};
        let no_fields = json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64
        });
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(no_fields))]).await);
        let limits = rpc.limits().await.unwrap().unwrap();
        assert_eq!(limits.gas_policy(), None);

        let priced = json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64,
            "gas_price": 100, "byte_price": 800, "gas_metering": "header"
        });
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(priced))]).await);
        let limits = rpc.limits().await.unwrap().unwrap();
        assert_eq!(limits.gas_policy(), Some(randprotocol_core::gas::GasPolicy::DEFAULT));

        // The node serves the prices as decimal strings (they are RAND amounts, docs/rpc.md);
        // the number form above decodes too, and an explicit `null` is no policy.
        let strings = json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64,
            "gas_price": "100", "byte_price": "800", "gas_metering": "header"
        });
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(strings))]).await);
        let limits = rpc.limits().await.unwrap().unwrap();
        assert_eq!(limits.gas_policy(), Some(randprotocol_core::gas::GasPolicy::DEFAULT));
        let nulls = json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64,
            "gas_price": null, "byte_price": null, "gas_metering": null
        });
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(nulls))]).await);
        assert_eq!(rpc.limits().await.unwrap().unwrap().gas_policy(), None);
        let junk = json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64,
            "gas_price": "1e2", "byte_price": "800"
        });
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(junk))]).await);
        assert!(rpc.limits().await.is_err(), "a price that is not a decimal u64 is an error, not a guess");
    }

    /// Task B5/B7: a chain with a `gas` section serves `gas_metering: "circuit"`, the bundle's
    /// pinned limit and (under `dynamic`) the controller's step; the wallet reads `gas_circuit`
    /// from the first and never mistakes `"header"`, `null` or an unknown value for it.
    #[tokio::test]
    async fn limits_decode_the_gas_section() {
        use test_rpc::{scripted_rpc, Reply};
        let base = || json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64,
            "gas_price": "100", "byte_price": "800"
        });
        let mut circuit = base();
        circuit["gas_metering"] = json!("circuit");
        circuit["bundle_gas_limit"] = json!(20479);
        circuit["adjust_bps"] = json!(1250);
        let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(circuit))]).await);
        let l = rpc.limits().await.unwrap().unwrap();
        assert!(l.gas_circuit);
        assert_eq!((l.bundle_gas_limit, l.adjust_bps), (Some(20_479), Some(1_250)));
        for metering in [json!("header"), json!(null), json!("quantum")] {
            let mut other = base();
            other["gas_metering"] = metering.clone();
            let rpc = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(other))]).await);
            let l = rpc.limits().await.unwrap().unwrap();
            assert!(!l.gas_circuit, "{metering} is not circuit metering");
            assert_eq!((l.bundle_gas_limit, l.adjust_bps), (None, None));
        }
    }

    /// [`RpcClient::envelope_format`] reads `rand_getLimits` at most once, however many times it
    /// is asked (Task 7: it is asked once per output a wallet seals), and `Legacy` covers every
    /// shape of "this chain has no memo": a node too old for the method, and one whose reply
    /// carries no `envelope_bytes` at all.
    #[tokio::test]
    async fn envelope_format_is_read_once_and_cached() {
        use randprotocol_core::notes::MEMO_ENVELOPE_BYTES;
        use test_rpc::{rpc_fn, scripted_rpc, Reply};
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = calls.clone();
        let rpc = RpcClient::new(
            rpc_fn(move |m, _p| {
                assert_eq!(m, "rand_getLimits", "envelope_format asks nothing else");
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Reply::Ok(json!({
                    "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
                    "max_call_envelope_bytes": 18432, "max_program_public_words": 64,
                    "envelope_bytes": MEMO_ENVELOPE_BYTES,
                }))
            })
            .await,
        );
        assert_eq!(rpc.envelope_format(7).await.unwrap(), EnvelopeFormat::Memo);
        assert_eq!(rpc.envelope_format(7).await.unwrap(), EnvelopeFormat::Memo);
        // Issue #64: the same claim on a chain id pinned as pre-`envelope_bytes` is not believed.
        assert_eq!(rpc.envelope_format(15).await.unwrap(), EnvelopeFormat::Legacy);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1, "the later calls must not repeat the read");

        let old = RpcClient::new(scripted_rpc(vec![]).await);
        assert_eq!(old.envelope_format(7).await.unwrap(), EnvelopeFormat::Legacy, "a node with no rand_getLimits at all");

        let reply = json!({
            "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
            "max_call_envelope_bytes": 18432, "max_program_public_words": 64
        });
        let no_field = RpcClient::new(scripted_rpc(vec![("rand_getLimits", Reply::Ok(reply))]).await);
        assert_eq!(no_field.envelope_format(7).await.unwrap(), EnvelopeFormat::Legacy, "a reply that predates the field");
    }

    /// Issue #64: every committed genesis file (`deploy/genesis-chain*.json`) of a chain that
    /// could still run — chain 14 on — and carries no `envelope_bytes` has its chain id in
    /// [`LEGACY_ENVELOPE_CHAIN_IDS`], so a node claiming the memo form there is never believed.
    /// A new cut without the field fails here until it is pinned.
    #[test]
    fn every_committed_genesis_without_envelope_bytes_is_pinned() {
        let deploy = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
        let mut seen = 0;
        for entry in std::fs::read_dir(&deploy).expect("deploy/") {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !(name.starts_with("genesis-chain") && name.ends_with(".json")) {
                continue;
            }
            let g: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let chain_id = g["chain_id"].as_u64().expect("chain_id");
            if chain_id < 14 {
                continue;
            }
            seen += 1;
            match g.get("envelope_bytes") {
                None | Some(Value::Null) => {
                    assert!(LEGACY_ENVELOPE_CHAIN_IDS.contains(&chain_id), "{name}: chain {chain_id} has no envelope_bytes and is not pinned")
                }
                Some(_) => assert!(!LEGACY_ENVELOPE_CHAIN_IDS.contains(&chain_id), "{name}: chain {chain_id} sets envelope_bytes but is pinned legacy"),
            }
        }
        assert!(seen >= 4, "chains 14–17 are committed");
        assert_eq!(envelope_format_for(17, Some(1860)), EnvelopeFormat::Legacy);
        assert_eq!(envelope_format_for(20, Some(1860)), EnvelopeFormat::Memo);
        assert_eq!(envelope_format_for(20, None), EnvelopeFormat::Legacy);
    }

    /// BIND-1: every committed genesis file (`deploy/genesis-chain*.json`) of a chain that could
    /// still run — chain 14 on — and carries no `binding_domain` (or `0`) has its chain id in
    /// [`CHAIN_ID_BINDING_CHAIN_IDS`], and no chain that sets it is pinned there. A new cut
    /// without the field fails here until it is pinned — and should not be cut without it: on
    /// any other chain id this wallet signs only the genesis-bound form.
    #[test]
    fn every_committed_genesis_without_binding_domain_is_pinned() {
        let deploy = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
        let mut seen = 0;
        for entry in std::fs::read_dir(&deploy).expect("deploy/") {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !(name.starts_with("genesis-chain") && name.ends_with(".json")) {
                continue;
            }
            let g: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let chain_id = g["chain_id"].as_u64().expect("chain_id");
            if chain_id < 14 {
                continue;
            }
            seen += 1;
            match g.get("binding_domain").and_then(Value::as_u64) {
                None | Some(0) => {
                    assert!(CHAIN_ID_BINDING_CHAIN_IDS.contains(&chain_id), "{name}: chain {chain_id} has no binding_domain and is not pinned")
                }
                Some(_) => assert!(!CHAIN_ID_BINDING_CHAIN_IDS.contains(&chain_id), "{name}: chain {chain_id} sets binding_domain but is pinned chain-id"),
            }
        }
        assert!(seen >= 5, "chains 14–18 are committed");
        let g = Hash([7; 32]);
        for pinned in [14, 15, 16, 17, 18, 19] {
            assert_eq!(binding_domain_for(pinned, g), BindingDomain::ChainId, "chain {pinned}");
        }
        for other in [0, 1, 7, 13, 20, 21, 99, u64::MAX] {
            assert_eq!(binding_domain_for(other, g), BindingDomain::Genesis(g), "chain {other}");
        }
    }

    /// BIND-1: which binding a tool without a store uses is the chain id's to decide, never the
    /// node's claim. On a pinned chain id a node claiming `binding_domain: 1` is not believed (and
    /// not even asked); on any other the genesis-bound form is the only one there is, and a node
    /// claiming the chain has no such domain — or too old to say — gets a refusal, not a chain-id
    /// signature.
    #[tokio::test]
    async fn the_binding_domain_is_the_chain_ids_never_the_nodes_claim() {
        use test_rpc::{rpc_fn, scripted_rpc, Reply};
        let limits = |binding: Option<u32>| {
            let mut v = json!({
                "max_program_words": 4096, "max_proof_bytes": 2097152, "max_block_bytes": 4194304,
                "max_call_envelope_bytes": 18432, "max_program_public_words": 64,
            });
            if let Some(b) = binding {
                v["binding_domain"] = json!(b);
            }
            v
        };
        let genesis = Hash([0x5a; 32]);
        let node = |binding: Option<u32>| async move {
            RpcClient::new(
                rpc_fn(move |m, _p| match m {
                    "rand_getLimits" => Reply::Ok(limits(binding)),
                    "rand_getGenesisHash" => Reply::Ok(json!(genesis.to_hex())),
                    other => panic!("unexpected {other}"),
                })
                .await,
            )
        };
        // A pinned chain: the chain-id form, whatever the node claims.
        assert_eq!(node(Some(1)).await.binding_domain(18).await.unwrap(), BindingDomain::ChainId);
        assert_eq!(node(None).await.binding_domain(14).await.unwrap(), BindingDomain::ChainId);
        let silent = RpcClient::new(scripted_rpc(vec![]).await);
        assert_eq!(silent.binding_domain(18).await.unwrap(), BindingDomain::ChainId, "not even asked");
        // Any other chain: genesis-bound over the node's hash when it says the chain has the domain…
        assert_eq!(node(Some(1)).await.binding_domain(20).await.unwrap(), BindingDomain::Genesis(genesis));
        assert_eq!(node(Some(1)).await.claimed_binding_domain().await.unwrap(), 1);
        // …and a refusal — never the chain-id form — when it says it has none, or cannot say.
        for claim in [Some(0), None] {
            let e = node(claim).await.binding_domain(20).await.unwrap_err().to_string();
            assert!(e.contains("binding_domain") && e.contains("chain 20"), "{e}");
            assert!(node(claim).await.require_binding_domain(20).await.is_err());
            assert!(node(claim).await.require_binding_domain(18).await.is_ok());
        }
        let e = silent.binding_domain(20).await.unwrap_err().to_string();
        assert!(e.contains("binding_domain"), "a node with no rand_getLimits at all: {e}");
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
