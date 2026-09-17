//! Where a proof is made: on this machine, or at a `rand-prover` the user trusts
//! (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md` §7).
//!
//! Both arms return exactly what `executor`'s functions return, so `wallet.rs` neither knows
//! nor cares. The remote arm posts a sealed job, polls, fetches and opens the sealed result. A
//! remote failure is an error that names the local alternative — never a silent fallback: a
//! user who chose delegation for a phone would rather be told than wait a hundred seconds.

use anyhow::{anyhow, Context, Result};
use randprotocol_core::notes::{ShieldedAddress, Word8};
use randprotocol_zkvm::delegate::{self, JobKind, JobRequest, JobResult, ReplyKey, VERSION};
use randprotocol_zkvm::executor;
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::{Backend, FriProfile};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const LOCAL_HINT: &str = "drop --prover to prove here (about a minute and a half per bundle on a laptop)";

pub fn profile_name(p: FriProfile) -> &'static str {
    match p {
        FriProfile::Production => "production",
        FriProfile::Test => "test",
    }
}

pub enum Prover {
    Local(Backend),
    Remote(RemoteProver),
}

pub struct RemoteProver {
    url: String,
    address: ShieldedAddress,
    token: Option<String>,
    deadline_secs: u32,
    http: reqwest::Client,
    checked: AtomicBool,
}

impl RemoteProver {
    pub fn new(url: String, address: ShieldedAddress, token: Option<String>, deadline_secs: u32) -> RemoteProver {
        let url = url.trim_end_matches('/').to_string();
        RemoteProver { url, address, token, deadline_secs, http: reqwest::Client::new(), checked: AtomicBool::new(false) }
    }

    fn req(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => r.bearer_auth(t),
            None => r,
        }
    }

    /// `/v1/health` once per process: the address the service reports must be the one pinned.
    async fn check_once(&self) -> Result<()> {
        if self.checked.load(Ordering::Relaxed) {
            return Ok(());
        }
        let v: serde_json::Value = self
            .http
            .get(format!("{}/v1/health", self.url))
            .send()
            .await
            .with_context(|| format!("the prover at {} is unreachable; {LOCAL_HINT}", self.url))?
            .json()
            .await
            .context("the prover's /v1/health is not JSON")?;
        check_pin(&self.address, v["address"].as_str().unwrap_or(""))?;
        if v["backend"] == "cpu" {
            eprintln!("note: the prover at {} proves on a CPU; expect laptop speed, not GPU speed", self.url);
        }
        self.checked.store(true, Ordering::Relaxed);
        Ok(())
    }

    async fn run(&self, profile: FriProfile, kind: JobKind) -> Result<JobResult> {
        self.check_once().await?;
        let reply = ReplyKey::generate();
        let job = JobRequest {
            version: VERSION,
            profile: profile_name(profile).into(),
            kind,
            deadline_secs: self.deadline_secs,
            reply_ek: reply.ek.clone(),
        };
        let sealed = delegate::seal_job(&self.address, &job).map_err(|e| anyhow!("sealing the job: {e}"))?;
        let r = self
            .req(self.http.post(format!("{}/v1/jobs", self.url)))
            .body(delegate::encode(&sealed))
            .send()
            .await
            .with_context(|| format!("the prover at {} is unreachable; {LOCAL_HINT}", self.url))?;
        let status = r.status().as_u16();
        let v: serde_json::Value = r.json().await.unwrap_or_default();
        if status != 202 {
            return Err(map_refusal(status, &v));
        }
        let id = v["id"].as_str().ok_or_else(|| anyhow!("the prover accepted the job but returned no id"))?.to_string();
        eprintln!("prover accepted job {} at queue position {}", &id[..8], v["position"]);
        let mut wait = Duration::from_secs(1);
        let started = std::time::Instant::now();
        loop {
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(Duration::from_secs(5));
            let s: serde_json::Value = self.req(self.http.get(format!("{}/v1/jobs/{id}", self.url))).send().await?.json().await?;
            match s["state"].as_str().unwrap_or("") {
                "queued" => eprintln!("  queued, position {} ({:.0?})", s["position"], started.elapsed()),
                "proving" => eprintln!("  proving ({:.0?})", started.elapsed()),
                "done" | "failed" => break,
                "expired" => {
                    return Err(anyhow!(
                        "the prover could not start the job within {} s; run the command again, or raise --prover-deadline; {LOCAL_HINT}",
                        self.deadline_secs
                    ))
                }
                other => return Err(anyhow!("the prover reports an unknown state {other:?}")),
            }
        }
        let bytes = self.req(self.http.get(format!("{}/v1/jobs/{id}/result", self.url))).send().await?.bytes().await?;
        let sealed = delegate::decode(&bytes).map_err(|e| anyhow!("the prover's result is not a sealed result: {e}"))?;
        delegate::open_result(&reply, &sealed)
            .map_err(|e| anyhow!("the prover's result did not open under this job's key ({e}); not retrying"))
    }
}

pub(crate) fn map_refusal(status: u16, v: &serde_json::Value) -> anyhow::Error {
    let error = v["error"].as_str().unwrap_or("no detail");
    match status {
        401 => anyhow!("the prover refused the token (401): set --prover-token / RAND_PROVER_TOKEN"),
        429 => {
            let retry = v["retry_after_secs"].as_u64().unwrap_or(0);
            anyhow!("the prover is busy (429): {error}; it estimates {retry} s — try again then, raise --prover-deadline, or {LOCAL_HINT}")
        }
        400 => anyhow!("the prover rejected the job (400): {error}"),
        s => anyhow!("the prover answered {s}: {error}"),
    }
}

pub(crate) fn check_pin(pinned: &ShieldedAddress, reported: &str) -> Result<()> {
    if reported != pinned.to_string() {
        return Err(anyhow!("the prover reports a different address than --prover-address pins; refusing to send it anything"));
    }
    Ok(())
}

impl Prover {
    pub fn where_(&self) -> String {
        match self {
            Prover::Local(_) => "locally".into(),
            Prover::Remote(r) => format!("at {}", r.url),
        }
    }

    pub async fn prove_bundle(&self, profile: FriProfile, inputs: &[u32]) -> Result<(Vec<u8>, Word8, u8)> {
        match self {
            Prover::Local(backend) => {
                executor::prove_bundle(profile, inputs, *backend).map_err(|e| anyhow!("proving the bundle failed: {e}"))
            }
            Prover::Remote(r) => match r.run(profile, JobKind::Bundle { inputs: inputs.to_vec() }).await? {
                JobResult::Bundle { proof, digest, tier } => Ok((proof, digest, tier)),
                JobResult::Failed { error } => Err(anyhow!("prover: {error}")),
                other => Err(anyhow!("the prover answered a bundle job with {}", kind_of(&other))),
            },
        }
    }

    pub async fn prove_program(
        &self,
        profile: FriProfile,
        program: &Program,
        inputs: &[u32],
        tier: Option<u8>,
        want_salt: bool,
    ) -> Result<(Vec<u8>, [u32; 8], u8, Option<[u32; 4]>)> {
        match self {
            Prover::Local(backend) => {
                if want_salt {
                    let (proof, outputs, tier, salt) =
                        executor::prove_call(profile, program, inputs, tier, *backend).map_err(|e| anyhow!(e))?;
                    Ok((proof, outputs, tier, Some(salt)))
                } else {
                    let (proof, outputs, tier) =
                        executor::prove(profile, program, inputs, tier, *backend).map_err(|e| anyhow!(e))?;
                    Ok((proof, outputs, tier, None))
                }
            }
            Prover::Remote(r) => {
                let kind = JobKind::Program {
                    base_pc: program.base_pc,
                    words: program.words.clone(),
                    inputs: inputs.to_vec(),
                    tier,
                    want_salt,
                };
                match r.run(profile, kind).await? {
                    JobResult::Program { proof, outputs, tier, salt } => {
                        if want_salt && salt.is_none() {
                            return Err(anyhow!("the prover returned no salt for a call that publishes an input envelope"));
                        }
                        Ok((proof, outputs, tier, salt))
                    }
                    JobResult::Failed { error } => Err(anyhow!("prover: {error}")),
                    other => Err(anyhow!("the prover answered a program job with {}", kind_of(&other))),
                }
            }
        }
    }
}

fn kind_of(r: &JobResult) -> &'static str {
    match r {
        JobResult::Bundle { .. } => "a bundle result",
        JobResult::Program { .. } => "a program result",
        JobResult::Failed { .. } => "a failure",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_round_trip_through_the_executor_parser() {
        use randprotocol_zkvm::executor::ZkExecutor;
        for p in [FriProfile::Production, FriProfile::Test] {
            assert_eq!(ZkExecutor::profile_from_str(profile_name(p)), Some(p));
        }
    }

    #[test]
    fn a_429_names_the_estimate_and_the_local_alternative() {
        let e = map_refusal(429, &serde_json::json!({ "error": "queue full", "retry_after_secs": 90 }));
        let text = e.to_string();
        assert!(text.contains("queue full") && text.contains("90 s") && text.contains(LOCAL_HINT), "{text}");
    }

    #[test]
    fn a_401_says_token() {
        assert!(map_refusal(401, &serde_json::json!({})).to_string().contains("token"));
    }

    #[test]
    fn a_wrong_pin_is_refused_before_any_job() {
        let ours = randprotocol_core::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] };
        let theirs = randprotocol_core::notes::ShieldedAddress { pk: [3; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] };
        assert!(check_pin(&ours, &theirs.to_string()).is_err());
        assert!(check_pin(&ours, &ours.to_string()).is_ok());
    }
}
