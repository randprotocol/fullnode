//! Delegated proving, the wallet's side (`docs/superpowers/specs/2026-09-28-delegated-proving-design.md`):
//! the pairing this wallet keeps with one prover (`<key>.prover.json`), and [`RemoteProver`], which
//! seals a bundle's witness to that prover, polls for the sealed reply, opens it and checks it —
//! the digest this wallet built, the chain's proof-size cap, and a local verify — before the wallet
//! puts the proof in a transaction. A prover that answers with anything else is refused, and the
//! job is cancelled.

use crate::RpcError;
use anyhow::{anyhow, Context, Result};
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::notes::{word8_to_hex, Word8};
use randprotocol_core::types::TX_BINDING_WORDS;
use randprotocol_prover::key::fingerprint_of;
use randprotocol_prover::pairing::PairingLink;
use randprotocol_prover::wire::{fresh_reply_key, open_reply, seal_job, ProveJob, WitnessKind, WIRE_VERSION};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::FriProfile;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The refusal for a spend-key witness bound for a prover that is not the owner's own.
pub const NOT_OWN: &str = "this build's witness carries the spend key; only a prover paired as your own (own=1) may receive it";

/// Printed once, before a viewing-key witness goes to a prover that is not the owner's own: the
/// v3 witness carries `nk`, which opens every note this wallet ever received or spent, and moves
/// none of them (the auth proof, made on this machine over the spend key, is what spends).
pub const VIEWING_KEY_WARNING: &str = "this prover can read this wallet's whole history; it cannot spend";

/// A sealed reply carries a ~1.2 MB proof as hex; 64 MiB is the wallet's own RPC reply cap.
const MAX_REPLY_BYTES: usize = 64 * 1024 * 1024;

/// The pairing this wallet keeps with one prover, at `<key>.prover.json` (mode 0600: the token is
/// a bearer credential). `Debug` and [`show`](Self::show) never print the token.
#[derive(Clone, Serialize, Deserialize)]
pub struct PairedProver {
    pub url: String,
    /// The prover's ML-KEM-768 encapsulation key, hex.
    pub kem_ek: String,
    /// The pairing token, hex.
    pub token: String,
    /// Paired as the wallet owner's own machine: it may receive spend-key witnesses.
    pub own: bool,
    /// `fingerprint_of(kem_ek)`, `XXXX-XXXX-XXXX-XXXX`.
    pub fingerprint: String,
    pub name: Option<String>,
}

impl std::fmt::Debug for PairedProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairedProver")
            .field("url", &self.url)
            .field("fingerprint", &self.fingerprint)
            .field("own", &self.own)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl PairedProver {
    pub fn path_for(key_file: &Path) -> PathBuf {
        let mut s = key_file.as_os_str().to_os_string();
        s.push(".prover.json");
        PathBuf::from(s)
    }

    pub fn from_link(link: &PairingLink, name: Option<String>) -> PairedProver {
        PairedProver {
            url: link.url.clone(),
            kem_ek: hex::encode(&link.kem_ek),
            token: hex::encode(link.token),
            own: link.own,
            fingerprint: link.fingerprint().to_string(),
            name,
        }
    }

    pub fn load(key_file: &Path) -> Result<Option<PairedProver>> {
        let path = PairedProver::path_for(key_file);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(anyhow!(e).context(format!("reading {}", path.display()))),
        };
        let p: PairedProver = serde_json::from_str(&text).with_context(|| format!("decoding {}", path.display()))?;
        // The file names its own fingerprint; a key edited under it is caught here, not at the prover.
        let ek = p.kem_ek_bytes()?;
        if fingerprint_of(&ek).to_string() != p.fingerprint {
            return Err(anyhow!("{}: the prover key does not match the fingerprint recorded beside it", path.display()));
        }
        p.token_bytes()?;
        Ok(Some(p))
    }

    /// Writes `<key>.prover.json`, mode 0600, replacing any earlier pairing (a re-pair).
    pub fn save(&self, key_file: &Path) -> Result<()> {
        let p = PairedProver::path_for(key_file);
        let tmp = p.with_extension("json.tmp");
        // As `Contacts::save`: a stale temp file keeps its own mode through `open(create)`, so it
        // is removed and created afresh, then pinned 0600 anyway.
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, p)?;
        Ok(())
    }

    /// Deletes the pairing; `false` when there was none.
    pub fn forget(key_file: &Path) -> Result<bool> {
        match std::fs::remove_file(PairedProver::path_for(key_file)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// What `rand prover show` prints: everything but the token.
    pub fn show(&self) -> String {
        format!(
            "name: {}\nurl: {}\nfingerprint: {}\nown: {}\nkem_ek: {}",
            self.name.as_deref().unwrap_or("-"),
            self.url,
            self.fingerprint,
            if self.own { "yes" } else { "no" },
            self.kem_ek
        )
    }

    /// The name to print for this prover: its `--name`, else its URL.
    pub fn label(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.url)
    }

    fn kem_ek_bytes(&self) -> Result<Vec<u8>> {
        hex::decode(&self.kem_ek).map_err(|e| anyhow!("the paired prover's key is not hex: {e}"))
    }

    fn token_bytes(&self) -> Result<Zeroizing<[u8; 32]>> {
        let mut t = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(&self.token, &mut t[..]).map_err(|e| anyhow!("the pairing token is not 64 hex digits: {e}"))?;
        Ok(t)
    }
}

/// The clients' rule for a prover URL: `https://` anywhere, plain `http://` only to this machine
/// (`localhost`, `127.0.0.1`, `[::1]`). A job is sealed either way, but the pairing token travels
/// in it and the reply's timing and size are visible to anyone on the path.
pub fn check_prover_url(url: &str) -> Result<()> {
    let u = reqwest::Url::parse(url).map_err(|e| anyhow!("{url}: not a URL ({e}); a prover URL is https:// (or http:// to 127.0.0.1/localhost)"))?;
    // `http://localhost:80@evil.com/` names host evil.com: credentials in a prover URL are refused
    // outright, and the host checked is the one the URL resolves to, never a prefix of its text.
    if !u.username().is_empty() || u.password().is_some() {
        return Err(anyhow!("{url}: a prover URL carries no user name or password"));
    }
    let host = u.host_str().unwrap_or("");
    match u.scheme() {
        "https" if !host.is_empty() => Ok(()),
        "http" if matches!(host, "localhost" | "127.0.0.1" | "[::1]") => Ok(()),
        "http" => Err(anyhow!("{url}: a prover is reached over https anywhere but 127.0.0.1/localhost")),
        _ => Err(anyhow!("{url}: a prover URL is https:// (or http:// to 127.0.0.1/localhost)")),
    }
}

/// The name a FRI profile goes by on the wire (`ZkExecutor::profile_from_str`'s inverse).
fn profile_name(p: FriProfile) -> &'static str {
    match p {
        FriProfile::Test => "test",
        FriProfile::Production => "production",
    }
}

/// A paired prover, reached over HTTP.
pub struct RemoteProver {
    paired: PairedProver,
    http: reqwest::Client,
    /// How often `prover_status` is asked (1 s).
    pub(crate) poll: Duration,
    /// How long a job may take, queue included (20 minutes), before it is cancelled.
    pub(crate) max_wait: Duration,
    /// Verify the returned proof on this machine before using it (on unless `RAND_PROVER_NO_VERIFY=1`).
    pub(crate) verify_locally: bool,
    info: tokio::sync::OnceCell<Value>,
    /// The digest a proof's own public values publish (`bundle_proof_digest`, structural and
    /// cheap). A seam so the unit tests' fake proofs need not decode; the real executor otherwise.
    pub(crate) published_digest: PublishedDigest,
    /// Set once [`VIEWING_KEY_WARNING`] has been printed, so it is said once per prover, not once
    /// per job.
    warned_history: std::sync::atomic::AtomicBool,
}

/// Reads the digest a bundle proof of the guest `hc` publishes, at a FRI profile.
pub(crate) type PublishedDigest = std::sync::Arc<dyn Fn(FriProfile, &Word8, &[u8]) -> Result<Word8> + Send + Sync>;

/// Keyed by the chain's `hc_bundle` — the heights a proof must declare are that guest's
/// ([`ZkExecutor::bundle_heights_for`]), exactly as the ledger reads them.
fn executor_digest(profile: FriProfile, hc: &Word8, proof: &[u8]) -> Result<Word8> {
    ZkExecutor::new(profile).hidden_bundle_proof_digest_for(hc, proof).map_err(|e| anyhow!("{e}"))
}

impl RemoteProver {
    pub fn new(paired: PairedProver) -> RemoteProver {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .expect("an http client");
        let no_verify = std::env::var("RAND_PROVER_NO_VERIFY").is_ok_and(|v| v == "1");
        RemoteProver {
            paired,
            http,
            poll: Duration::from_secs(1),
            max_wait: Duration::from_secs(20 * 60),
            verify_locally: !no_verify,
            info: tokio::sync::OnceCell::new(),
            published_digest: std::sync::Arc::new(executor_digest),
            warned_history: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Whether [`VIEWING_KEY_WARNING`] has been printed for this prover.
    pub fn warned_history(&self) -> bool {
        self.warned_history.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn paired(&self) -> &PairedProver {
        &self.paired
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))?;
        let resp = self
            .http
            .post(&self.paired.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| anyhow!(e).context(format!("{method}: reaching the prover at {}", self.paired.url)))?;
        let bytes = crate::read_capped(resp, MAX_REPLY_BYTES).await?;
        let resp: Value = serde_json::from_slice(&bytes).with_context(|| format!("{method}: the prover's reply is not JSON"))?;
        if let Some(err) = resp.get("error") {
            let message = err.get("message").and_then(Value::as_str).unwrap_or("unknown").to_string();
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let data = err.get("data").filter(|d| !d.is_null()).cloned();
            return Err(RpcError { code, message, data }.into());
        }
        resp.get("result").cloned().with_context(|| format!("{method}: the prover's reply has no result"))
    }

    /// `prover_info`, once per `RemoteProver`; refused when its key's fingerprint is not the one
    /// this wallet paired with.
    pub async fn info(&self) -> Result<Value> {
        let info = self
            .info
            .get_or_try_init(|| async {
                let info = self.call("prover_info", json!([])).await?;
                let got = info["kem_fingerprint"].as_str().unwrap_or("");
                if got != self.paired.fingerprint {
                    return Err(anyhow!(
                        "the prover at {} answers with key fingerprint {got:?}, but this wallet paired with {} — not sending it anything",
                        self.paired.url,
                        self.paired.fingerprint
                    ));
                }
                Ok(info)
            })
            .await?;
        Ok(info.clone())
    }

    /// Seal, submit, poll, open, check. `expected` and `proof_cap` are the wallet's own numbers:
    /// the digest it computed from its own plaintext and the chain's `max_proof_bytes`.
    #[allow(clippy::too_many_arguments)]
    pub async fn prove(
        &self,
        hc: &Word8,
        profile: FriProfile,
        witness_kind: WitnessKind,
        inputs: &[u32],
        binding: &[u32; TX_BINDING_WORDS],
        expected: &Word8,
        proof_cap: usize,
    ) -> Result<(Vec<u8>, u8)> {
        if witness_kind == WitnessKind::SpendKey && !self.paired.own {
            return Err(anyhow!(NOT_OWN));
        }
        // A viewing-key witness (bundle guest v3) may go to any paired prover; one that is not the
        // owner's own is told what it can then see, once, before anything is sent.
        if witness_kind == WitnessKind::ViewingKey && !self.paired.own && !self.warned_history.swap(true, std::sync::atomic::Ordering::Relaxed) {
            eprintln!("warning: {} — {VIEWING_KEY_WARNING}", self.paired.label());
        }
        let info = self.info().await?;
        let has = |field: &str, want: &str| info[field].as_array().is_some_and(|a| a.iter().any(|v| v.as_str() == Some(want)));
        let hc_hex = word8_to_hex(hc);
        if !has("hc_bundles", &hc_hex) {
            return Err(anyhow!("the prover {} does not prove this chain's bundle guest ({hc_hex})", self.paired.label()));
        }
        let pname = profile_name(profile);
        if !has("profiles", pname) {
            return Err(anyhow!("the prover {} does not prove under this chain's FRI profile ({pname})", self.paired.label()));
        }
        if !has("witness_kinds", witness_kind.as_str()) {
            return Err(anyhow!(
                "the prover {} does not accept {} witnesses (its operator started it without them)",
                self.paired.label(),
                witness_kind.as_str()
            ));
        }
        let ek = self.paired.kem_ek_bytes()?;
        let reply_key = Zeroizing::new(fresh_reply_key());
        let sealed = {
            let job = ProveJob {
                version: WIRE_VERSION,
                token: *self.paired.token_bytes()?,
                witness_kind,
                hc_bundle: *hc,
                profile: pname.to_string(),
                binding: *binding,
                inputs: inputs.to_vec(),
                reply_key: *reply_key,
            };
            seal_job(&ek, &job).map_err(|e| anyhow!("sealing the job: {e}"))?
            // `job` (the witness, the token, the reply key) is zeroized here.
        };
        let job = match self.call("prover_submit", json!([hex::encode(&sealed)])).await {
            Ok(v) => v["job"].as_str().context("prover_submit returned no job id")?.to_string(),
            Err(e) => return Err(submit_error(e, self.paired.label())),
        };
        match self.finish(&job, &reply_key, hc, profile, binding, expected, proof_cap).await {
            Ok(out) => Ok(out),
            Err(e) => {
                // Best effort: a job that will not be used should not hold the prover's queue.
                let _ = self.call("prover_cancel", json!([job])).await;
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn finish(
        &self,
        job: &str,
        reply_key: &[u8; 32],
        hc: &Word8,
        profile: FriProfile,
        binding: &[u32; TX_BINDING_WORDS],
        expected: &Word8,
        proof_cap: usize,
    ) -> Result<(Vec<u8>, u8)> {
        let started = Instant::now();
        let mut shown = String::new();
        // Set while `prover_status` cannot be reached, so an outage is announced once, not per poll.
        let mut unreachable = false;
        let sealed_reply = loop {
            if started.elapsed() > self.max_wait {
                return Err(anyhow!("the prover did not finish within {:.0?}; the job was cancelled", self.max_wait));
            }
            // A transport failure (a reset, the client's timeout, a proxy's 502 page) says nothing
            // about the job, which may be seconds from done: keep polling until `max_wait`. Only
            // the prover's own JSON-RPC error (an unknown job after a restart, say) ends the wait.
            let s = match self.call("prover_status", json!([job])).await {
                Ok(s) => {
                    unreachable = false;
                    s
                }
                Err(e) if is_transport_error(&e) => {
                    if !unreachable {
                        eprintln!("prover {} unreachable ({e:#}), retrying…", self.paired.label());
                        unreachable = true;
                        // The next state line is printed again once it answers.
                        shown.clear();
                    }
                    tokio::time::sleep(self.poll).await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let line = match s["state"].as_str().unwrap_or("") {
                "queued" => match s["position"].as_u64() {
                    Some(p) => format!("queued on {} at position {p}…", self.paired.label()),
                    None => format!("queued on {}…", self.paired.label()),
                },
                "proving" => format!("proving on {}…", self.paired.label()),
                "done" => {
                    let hex_reply = s["reply"].as_str().context("the prover said done but sent no reply")?;
                    break hex::decode(hex_reply).map_err(|_| anyhow!("the prover's reply is not hex"))?;
                }
                "failed" => {
                    return Err(anyhow!("the prover failed the job: {}", s["error"].as_str().unwrap_or("no reason given")));
                }
                "expired" => {
                    return Err(anyhow!("the prover did not finish within its own reply window (the job expired)"));
                }
                other => return Err(anyhow!("the prover reported job state {other:?}")),
            };
            if line != shown {
                eprintln!("{line}");
                shown = line;
            }
            tokio::time::sleep(self.poll).await;
        };
        let reply = open_reply(reply_key, &sealed_reply).map_err(|e| anyhow!("opening the prover's reply: {e}"))?;
        // `wallet::check_proof_size`'s rule, in a bundle's words (its message names a call proof).
        if reply.proof.len() > proof_cap {
            return Err(anyhow!(
                "the prover's bundle proof is {} bytes, over this chain's {proof_cap}-byte cap (max_proof_bytes); not using it",
                reply.proof.len()
            ));
        }
        // The digest is read off the proof itself — `verify_bundle` never looks at it, and the
        // reply's `digest` field is only the prover's word — and checked whatever `verify_locally`.
        let label = self.paired.label();
        let published = (self.published_digest)(profile, hc, &reply.proof)
            .map_err(|e| anyhow!("the prover {label}'s proof does not decode as a bundle proof: {e}; not using it"))?;
        if published != *expected {
            return Err(anyhow!(
                "the prover {label}'s proof publishes digest {} but this wallet built {} — not using it",
                word8_to_hex(&published),
                word8_to_hex(expected)
            ));
        }
        if reply.digest != published {
            return Err(anyhow!(
                "the prover {label} claimed digest {} but its proof publishes {} — not using it",
                word8_to_hex(&reply.digest),
                word8_to_hex(&published)
            ));
        }
        if self.verify_locally {
            eprintln!("verifying the prover's proof on this machine…");
            ZkExecutor::new(profile)
                .verify_bundle(hc, &reply.proof, binding)
                .map_err(|e| anyhow!("the prover's proof did not verify on this machine: {e}"))?;
        }
        Ok((reply.proof, reply.tier))
    }
}

/// Whether a failed [`RemoteProver::call`] never got a JSON-RPC answer from the prover — the
/// request did not go through, or what came back was not the prover's (not JSON, no result, over
/// the cap) — as opposed to the prover's own [`RpcError`].
fn is_transport_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<RpcError>().is_none()
}

/// A `prover_submit` refusal in words: `busy` names the queue, the others what the prover said.
fn submit_error(e: anyhow::Error, label: &str) -> anyhow::Error {
    let Some(r) = e.downcast_ref::<RpcError>() else { return e };
    let data = r.data.clone().unwrap_or(Value::Null);
    match r.code {
        -32005 => anyhow!(
            "the prover {label} is busy: its queue holds {} of {} jobs; try again later",
            data["depth"].as_u64().map_or("?".into(), |d| d.to_string()),
            data["max"].as_u64().map_or("?".into(), |d| d.to_string())
        ),
        -32003 => anyhow!("the prover {label} does not know this wallet's pairing token: pair again (rand prover pair <link>)"),
        -32004 => anyhow!("the prover {label} refused the witness kind: {}", data["reason"].as_str().unwrap_or(&r.message)),
        -32000 => anyhow!("the prover {label} refused the job: {}", data["reason"].as_str().unwrap_or(&r.message)),
        _ => e,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rpc::{rpc_fn, Reply};
    use randprotocol_core::notes::word8_to_hex;
    use randprotocol_prover::key::ProverKey;
    use randprotocol_prover::wire::{open_job, seal_reply, ProveReply};
    use randprotocol_zkvm::executor::ZkExecutor;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    const EXPECTED: Word8 = [7; 8];
    const BINDING: [u32; TX_BINDING_WORDS] = [3; TX_BINDING_WORDS];

    /// What the fake answers `prover_status` with once a job is in.
    #[derive(Clone, Copy)]
    enum Finish {
        /// `done`: the reply claims digest `EXPECTED` xor `flip`; its proof is `proof_len` bytes whose
        /// first 32 carry the digest it "publishes" (`EXPECTED` xor `publish_flip`, read by [`stub_digest`]).
        Done { flip: u32, publish_flip: u32, proof_len: usize },
        /// `proving`, for ever.
        Never,
        /// `failed`, with this error.
        Failed(&'static str),
        /// `expired`.
        Expired,
    }

    struct Fake {
        key: ProverKey,
        info: Value,
        finish: Finish,
        /// Every method asked, in order.
        seen: Vec<String>,
        reply_key: Option<[u8; 32]>,
        /// Answers to the first `prover_status` calls, one each, before `finish` takes over.
        status_first: std::collections::VecDeque<Reply>,
        /// The witness kind of the last job submitted.
        kind: Option<WitnessKind>,
    }

    fn info_for(key: &ProverKey) -> Value {
        json!({
            "version": "0.6.2",
            "kem_fingerprint": key.fingerprint().to_string(),
            "kem_ek": hex::encode(key.kem_ek()),
            "hc_bundles": [word8_to_hex(&ZkExecutor::hc_bundle())],
            "profiles": ["test", "production"],
            "backend": "cpu",
            "witness_kinds": ["spend_key"],
            "queue": { "depth": 0, "max": 8, "proving": 0 },
            "fee": null,
        })
    }

    /// A prover behind a real socket, answering from `Fake`; returns the pairing and the state.
    async fn fake(finish: Finish, own: bool, edit_info: impl FnOnce(&mut Value)) -> (PairedProver, Arc<Mutex<Fake>>) {
        let key = ProverKey::generate();
        let mut info = info_for(&key);
        edit_info(&mut info);
        let kem_ek = key.kem_ek().to_vec();
        let state = Arc::new(Mutex::new(Fake { key, info, finish, seen: Vec::new(), reply_key: None, status_first: Default::default(), kind: None }));
        let s = state.clone();
        let url = rpc_fn(move |method, params| {
            let mut f = s.lock().unwrap();
            f.seen.push(method.to_string());
            match method {
                "prover_info" => Reply::Ok(f.info.clone()),
                "prover_submit" => {
                    let sealed = hex::decode(params[0].as_str().unwrap()).unwrap();
                    let job = open_job(f.key.dk(), &sealed).expect("the wallet sealed the job to this prover");
                    assert_eq!(job.binding, BINDING);
                    assert_eq!(job.profile, "test");
                    assert_eq!(job.inputs, vec![1, 2, 3]);
                    f.kind = Some(job.witness_kind);
                    assert_eq!(job.hc_bundle, ZkExecutor::hc_bundle());
                    assert_eq!(job.token, [9; 32]);
                    assert_eq!(job.version, WIRE_VERSION);
                    f.reply_key = Some(job.reply_key);
                    Reply::Ok(json!({ "job": "j1" }))
                }
                "prover_status" if !f.status_first.is_empty() => f.status_first.pop_front().unwrap(),
                "prover_status" => match f.finish {
                    Finish::Never => Reply::Ok(json!({ "state": "proving" })),
                    Finish::Failed(error) => Reply::Ok(json!({ "state": "failed", "error": error })),
                    Finish::Expired => Reply::Ok(json!({ "state": "expired" })),
                    Finish::Done { flip, publish_flip, proof_len } => {
                        let mut digest = EXPECTED;
                        digest[0] ^= flip;
                        let mut published = EXPECTED;
                        published[0] ^= publish_flip;
                        let mut proof = vec![0; proof_len];
                        for (i, w) in published.iter().enumerate() {
                            proof[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
                        }
                        let reply = ProveReply { proof, digest, tier: 14 };
                        let sealed = seal_reply(&f.reply_key.unwrap(), &reply);
                        Reply::Ok(json!({ "state": "done", "reply": hex::encode(sealed) }))
                    }
                },
                "prover_cancel" => Reply::Ok(json!({ "cancelled": true })),
                _ => Reply::Err(-32601, "method not found"),
            }
        })
        .await;
        let link = PairingLink { kem_ek, url, token: [9; 32], own };
        (PairedProver::from_link(&link, Some("box".into())), state)
    }

    fn quick(paired: PairedProver) -> RemoteProver {
        let mut r = RemoteProver::new(paired);
        r.poll = Duration::from_millis(20);
        // A guard that stops checking should fail its test, not hang it.
        r.max_wait = Duration::from_secs(5);
        r.verify_locally = false;
        r.published_digest = Arc::new(stub_digest);
        r
    }

    /// The fake's proofs publish their first 32 bytes as the digest.
    fn stub_digest(_: FriProfile, _: &Word8, proof: &[u8]) -> Result<Word8> {
        let mut d = [0u32; 8];
        for (i, w) in d.iter_mut().enumerate() {
            *w = u32::from_le_bytes(proof.get(4 * i..4 * i + 4).context("short")?.try_into().unwrap());
        }
        Ok(d)
    }

    async fn prove(r: &RemoteProver, cap: usize) -> Result<(Vec<u8>, u8)> {
        r.prove(&ZkExecutor::hc_bundle(), FriProfile::Test, WitnessKind::SpendKey, &[1, 2, 3], &BINDING, &EXPECTED, cap).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_honest_reply_is_accepted() {
        let (paired, state) = fake(Finish::Done { flip: 0, publish_flip: 0, proof_len: 100 }, true, |_| {}).await;
        let (proof, tier) = prove(&quick(paired), 1000).await.unwrap();
        assert_eq!((proof.len(), tier), (100, 14));
        assert_eq!(state.lock().unwrap().seen, ["prover_info", "prover_submit", "prover_status"], "one info, no cancel");
        assert_eq!(state.lock().unwrap().kind, Some(WitnessKind::SpendKey));
    }

    async fn vk(r: &RemoteProver) -> Result<(Vec<u8>, u8)> {
        r.prove(&ZkExecutor::hc_bundle(), FriProfile::Test, WitnessKind::ViewingKey, &[1, 2, 3], &BINDING, &EXPECTED, 1000).await
    }

    /// Split authorisation: a viewing-key witness (bundle guest v3) goes to any paired prover —
    /// `own` or not — and a prover that is not the owner's own is warned about once, before the
    /// first job, never again for the same prover.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_viewing_key_witness_goes_to_any_paired_prover_with_one_warning() {
        let (paired, state) = fake(Finish::Done { flip: 0, publish_flip: 0, proof_len: 100 }, false, |i| {
            i["witness_kinds"] = json!(["viewing_key"]);
        })
        .await;
        let r = quick(paired);
        assert!(!r.warned_history());
        vk(&r).await.expect("a viewing-key job needs no own pairing");
        assert!(r.warned_history(), "a prover not the owner's own is told what it can read");
        assert_eq!(state.lock().unwrap().kind, Some(WitnessKind::ViewingKey));
        vk(&r).await.expect("and again");
        // The same prover, own: no warning.
        let (paired, _) = fake(Finish::Done { flip: 0, publish_flip: 0, proof_len: 100 }, true, |i| {
            i["witness_kinds"] = json!(["spend_key", "viewing_key"]);
        })
        .await;
        let r = quick(paired);
        vk(&r).await.unwrap();
        assert!(!r.warned_history(), "the owner's own prover already holds the spend key");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_claimed_digest_the_proof_does_not_publish_is_refused() {
        // The reply claims the right digest; the proof itself publishes another.
        let (paired, state) = fake(Finish::Done { flip: 0, publish_flip: 1, proof_len: 100 }, true, |_| {}).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("publishes digest") && e.contains("box") && !e.contains("wallet bug"), "{e}");
        assert_eq!(state.lock().unwrap().seen.last().map(String::as_str), Some("prover_cancel"));
        // The proof publishes the right digest; the reply claims another.
        let (paired, _) = fake(Finish::Done { flip: 1, publish_flip: 0, proof_len: 100 }, true, |_| {}).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("claimed digest"), "{e}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_proof_the_real_executor_cannot_read_is_refused_without_the_local_verify() {
        let (paired, state) = fake(Finish::Done { flip: 0, publish_flip: 0, proof_len: 100 }, true, |_| {}).await;
        let mut r = quick(paired);
        r.published_digest = Arc::new(executor_digest);
        assert!(!r.verify_locally);
        let e = prove(&r, 1000).await.unwrap_err().to_string();
        assert!(e.contains("does not decode"), "{e}");
        assert_eq!(state.lock().unwrap().seen.last().map(String::as_str), Some("prover_cancel"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reply_with_the_wrong_digest_is_refused() {
        let (paired, state) = fake(Finish::Done { flip: 1, publish_flip: 1, proof_len: 100 }, true, |_| {}).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("digest"), "{e}");
        assert_eq!(state.lock().unwrap().seen.last().map(String::as_str), Some("prover_cancel"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_oversized_proof_is_refused() {
        let (paired, state) = fake(Finish::Done { flip: 0, publish_flip: 0, proof_len: 1001 }, true, |_| {}).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("bytes"), "{e}");
        assert!(state.lock().unwrap().seen.contains(&"prover_cancel".to_string()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_proof_that_does_not_verify_locally_is_refused() {
        let (paired, _) = fake(Finish::Done { flip: 0, publish_flip: 0, proof_len: 100 }, true, |_| {}).await;
        let mut r = quick(paired);
        r.verify_locally = true;
        let e = prove(&r, 1000).await.unwrap_err().to_string();
        assert!(e.contains("did not verify"), "{e}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_spend_key_witness_goes_only_to_an_own_prover() {
        let (paired, state) = fake(Finish::Done { flip: 0, publish_flip: 0, proof_len: 100 }, false, |_| {}).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("only a prover paired as your own (own=1) may receive it"), "{e}");
        assert!(state.lock().unwrap().seen.is_empty(), "no request before the refusal");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fingerprint_mismatch_is_refused_at_info() {
        let (paired, state) = fake(Finish::Done { flip: 0, publish_flip: 0, proof_len: 100 }, true, |i| {
            i["kem_fingerprint"] = json!(ProverKey::generate().fingerprint().to_string());
        })
        .await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("fingerprint"), "{e}");
        assert_eq!(state.lock().unwrap().seen, vec!["prover_info".to_string()], "no submit");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_prover_that_never_finishes_times_out() {
        let (paired, state) = fake(Finish::Never, true, |_| {}).await;
        let mut r = quick(paired);
        r.poll = Duration::from_millis(50);
        r.max_wait = Duration::from_millis(300);
        let e = prove(&r, 1000).await.unwrap_err().to_string();
        assert!(e.contains("did not finish"), "{e}");
        assert_eq!(state.lock().unwrap().seen.last().map(String::as_str), Some("prover_cancel"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_transient_poll_failure_is_retried_not_cancelled() {
        // A reset, then a proxy's error page, then `proving`, then done: the wallet waits it out.
        let (paired, state) = fake(Finish::Done { flip: 0, publish_flip: 0, proof_len: 100 }, true, |_| {}).await;
        state.lock().unwrap().status_first.extend([
            Reply::Drop,
            Reply::Malformed("<html>502 Bad Gateway</html>"),
            Reply::Ok(json!({ "state": "proving" })),
        ]);
        let (proof, tier) = prove(&quick(paired), 1000).await.unwrap();
        assert_eq!((proof.len(), tier), (100, 14));
        let seen = state.lock().unwrap().seen.clone();
        assert!(!seen.contains(&"prover_cancel".to_string()), "no cancel: {seen:?}");
        assert_eq!(seen.iter().filter(|m| *m == "prover_status").count(), 4, "{seen:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_poll_answered_with_the_provers_own_error_ends_the_wait() {
        // A prover that restarted no longer knows the job: its JSON-RPC error is definite.
        let (paired, state) = fake(Finish::Never, true, |_| {}).await;
        state.lock().unwrap().status_first.push_back(Reply::Err(-32001, "unknown job"));
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("unknown job"), "{e}");
        let seen = state.lock().unwrap().seen.clone();
        assert_eq!(seen.iter().filter(|m| *m == "prover_status").count(), 1, "no retry: {seen:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_prover_that_stays_unreachable_times_out() {
        let (paired, state) = fake(Finish::Never, true, |_| {}).await;
        state.lock().unwrap().status_first.extend((0..1000).map(|_| Reply::Drop));
        let mut r = quick(paired);
        r.poll = Duration::from_millis(20);
        r.max_wait = Duration::from_millis(300);
        let e = prove(&r, 1000).await.unwrap_err().to_string();
        assert!(e.contains("did not finish"), "{e}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_job_surfaces_the_provers_error() {
        let (paired, state) = fake(Finish::Failed("out of memory at tier 14"), true, |_| {}).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("the prover failed the job: out of memory at tier 14"), "{e}");
        let seen = state.lock().unwrap().seen.clone();
        // One status answer ends it; the best-effort cancel follows, as for every refused job.
        assert_eq!(seen, ["prover_info", "prover_submit", "prover_status", "prover_cancel"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_expired_job_is_a_definite_error() {
        let (paired, state) = fake(Finish::Expired, true, |_| {}).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("expired"), "{e}");
        let seen = state.lock().unwrap().seen.clone();
        assert_eq!(seen, ["prover_info", "prover_submit", "prover_status", "prover_cancel"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn info_that_lacks_the_guest_or_the_kind_is_an_error_that_says_so() {
        let (paired, state) = fake(Finish::Never, true, |i| i["hc_bundles"] = json!([])).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("guest"), "{e}");
        assert!(!state.lock().unwrap().seen.contains(&"prover_submit".to_string()));
        let (paired, _) = fake(Finish::Never, true, |i| i["witness_kinds"] = json!([])).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("spend_key"), "{e}");
        let (paired, _) = fake(Finish::Never, true, |i| i["profiles"] = json!(["production"])).await;
        let e = prove(&quick(paired), 1000).await.unwrap_err().to_string();
        assert!(e.contains("profile"), "{e}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_busy_prover_names_its_depth() {
        let key = ProverKey::generate();
        let info = info_for(&key);
        let url = rpc_fn(move |method, _| match method {
            "prover_info" => Reply::Ok(info.clone()),
            "prover_submit" => Reply::ErrData(-32005, "busy".into(), json!({ "depth": 8, "max": 8 })),
            _ => Reply::Err(-32601, "method not found"),
        })
        .await;
        let link = PairingLink { kem_ek: key.kem_ek().to_vec(), url, token: [9; 32], own: true };
        let e = prove(&quick(PairedProver::from_link(&link, None)), 1000).await.unwrap_err().to_string();
        assert!(e.contains("busy") && e.contains('8'), "{e}");
    }

    #[test]
    fn a_pairing_file_is_0600_and_show_never_prints_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("w.key.json");
        let key = ProverKey::generate();
        let link = PairingLink { kem_ek: key.kem_ek().to_vec(), url: "https://prover.example".into(), token: [0xab; 32], own: true };
        let p = PairedProver::from_link(&link, Some("box".into()));
        assert_eq!(p.fingerprint, key.fingerprint().to_string());
        assert_eq!(PairedProver::load(&key_file).unwrap().map(|p| p.url), None);
        p.save(&key_file).unwrap();
        let path = PairedProver::path_for(&key_file);
        assert!(path.to_string_lossy().ends_with("w.key.json.prover.json"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let back = PairedProver::load(&key_file).unwrap().unwrap();
        assert_eq!((back.url.as_str(), back.token.as_str(), back.own), ("https://prover.example", p.token.as_str(), true));
        let shown = back.show();
        assert!(shown.contains(&p.fingerprint) && shown.contains("https://prover.example"), "{shown}");
        assert!(!shown.contains(&"ab".repeat(32)), "the token is never shown: {shown}");
        assert!(!format!("{back:?}").contains(&"ab".repeat(32)), "nor in Debug");
        p.save(&key_file).expect("re-pairing overwrites");
        assert!(PairedProver::forget(&key_file).unwrap());
        assert!(!PairedProver::forget(&key_file).unwrap());
    }

    #[test]
    fn a_plain_http_link_off_loopback_is_refused() {
        for ok in ["https://prover.example", "https://1.2.3.4:9000/", "http://127.0.0.1:9000", "http://localhost:9000/", "http://[::1]:9000", "http://localhost"] {
            check_prover_url(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in ["http://prover.example", "http://10.0.0.2:9000", "http://localhost.evil.com", "http://127.0.0.1.evil.com:80", "ftp://127.0.0.1", "prover.example", "http://localhost:80@evil.com/", "http://[::1]@evil.com/", "http://127.0.0.1@evil.com", "https://user:pw@prover.example"] {
            assert!(check_prover_url(bad).is_err(), "{bad}");
        }
        let key = ProverKey::generate();
        let link = PairingLink { kem_ek: key.kem_ek().to_vec(), url: "http://prover.example:9000".into(), token: [1; 32], own: false };
        let p = PairedProver::from_link(&link, None);
        assert!(check_prover_url(&p.url).unwrap_err().to_string().contains("https"));
    }
}
