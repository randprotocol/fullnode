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

/// On top of `--prover-deadline`, which bounds only the wait for a slot: how long the proof
/// itself may take before this wallet stops waiting for it.
const PROVING_ALLOWANCE_SECS: u64 = 900;

/// Polls in a row that may fail at the transport before the job is given up on.
const POLL_RETRIES: u32 = 5;

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
        // Without these a socket that opens and then says nothing holds the wallet for as long as
        // the OS will let it, and neither the poll budget below nor `--prover-deadline` ever gets
        // to run: both are measured between requests, not inside one. Every request here is a
        // small JSON exchange or a proof fetch, so a minute is generous for all of them.
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .build()
            .expect("a reqwest client with timeouts builds");
        RemoteProver { url, address, token, deadline_secs, http, checked: AtomicBool::new(false) }
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
        let r = self
            .http
            .get(format!("{}/v1/health", self.url))
            .send()
            .await
            .with_context(|| format!("the prover at {} is unreachable; {LOCAL_HINT}", self.url))?;
        // A 502 from a proxy or a 404 from something that is not a prover has no `address` field,
        // and reading one out of it would blame the pin for what is really "nothing answered".
        let status = r.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(anyhow!("the prover's /v1/health answered {status}; {LOCAL_HINT}"));
        }
        let v: serde_json::Value = r.json().await.context("the prover's /v1/health is not JSON")?;
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
        // The witness is on the wire now; the plaintext copy has no further use, and `JobRequest`
        // zeroizes its inputs on drop.
        drop(job);
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
        let short = id.get(..8).unwrap_or(&id).to_string();
        match v["position"].as_u64() {
            Some(p) => eprintln!("prover accepted job {short} at queue position {p}"),
            None => eprintln!("prover accepted job {short}"),
        }
        let mut wait = Duration::from_secs(1);
        let started = std::time::Instant::now();
        let budget = Duration::from_secs(u64::from(self.deadline_secs) + PROVING_ALLOWANCE_SECS);
        let mut silent = 0u32;
        loop {
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(Duration::from_secs(5));
            if started.elapsed() > budget {
                return Err(anyhow!(
                    "the prover has not finished job {short} after {} s; {LOCAL_HINT}",
                    started.elapsed().as_secs()
                ));
            }
            // A dropped connection is not a lost job: the proof is still being made, and the next
            // poll can find it. Only a prover that has gone silent for `POLL_RETRIES` polls running
            // is one this wallet gives up on.
            let r = match self.req(self.http.get(format!("{}/v1/jobs/{id}", self.url))).send().await {
                Ok(r) => r,
                Err(e) => {
                    silent += 1;
                    if silent >= POLL_RETRIES {
                        return Err(anyhow!(
                            "the prover at {} stopped answering about job {short} ({e}); {LOCAL_HINT}",
                            self.url
                        ));
                    }
                    eprintln!("  the prover did not answer ({e}); asking again");
                    continue;
                }
            };
            let status = r.status().as_u16();
            let body = r.json::<serde_json::Value>().await;
            if !(200..300).contains(&status) {
                return Err(map_refusal(status, &body.unwrap_or_default()));
            }
            // A 200 whose body did not arrive whole — a truncated response, a proxy that cut the
            // connection mid-body — is the transport failing, not the prover reporting a state
            // this wallet does not know. It costs a retry, not the job.
            let s = match body {
                Ok(s) => s,
                Err(e) => {
                    silent += 1;
                    if silent >= POLL_RETRIES {
                        return Err(anyhow!(
                            "the prover at {} answered about job {short} but the body did not parse ({e}); {LOCAL_HINT}",
                            self.url
                        ));
                    }
                    eprintln!("  the prover's answer did not parse ({e}); asking again");
                    continue;
                }
            };
            silent = 0;
            match s["state"].as_str().unwrap_or("") {
                "queued" => match s["position"].as_u64() {
                    Some(p) => eprintln!("  queued, position {p} ({:.0?})", started.elapsed()),
                    None => eprintln!("  queued ({:.0?})", started.elapsed()),
                },
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
        let r = self
            .req(self.http.get(format!("{}/v1/jobs/{id}/result", self.url)))
            .send()
            .await
            .with_context(|| format!("fetching the result of job {short} from {}; {LOCAL_HINT}", self.url))?;
        let status = r.status().as_u16();
        if !(200..300).contains(&status) {
            let v: serde_json::Value = r.json().await.unwrap_or_default();
            return Err(map_refusal(status, &v));
        }
        let bytes = r.bytes().await.context("reading the prover's result")?;
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
        404 => anyhow!("the prover no longer knows this job (404): it expired or the service restarted; run the command again"),
        s => anyhow!("the prover answered {s}: {error}; {LOCAL_HINT}"),
    }
}

/// A program result's salt must match what was asked for, in both directions: without it the
/// wallet cannot seal the transcript it promised, and *with* one it did not ask for a remote could
/// turn `--no-envelope` into a published input envelope.
pub(crate) fn check_salt(want_salt: bool, salt: Option<[u32; 4]>) -> Result<()> {
    match (want_salt, salt.is_some()) {
        (true, false) => Err(anyhow!("the prover returned no salt for a call that publishes an input envelope")),
        (false, true) => Err(anyhow!("the prover returned a salt for a call that must publish no input envelope; refusing it")),
        _ => Ok(()),
    }
}

/// The salt a remote returns must be the salt the proof was made with.
///
/// `check_salt` only asks whether there is one. But the wallet is about to publish an input
/// envelope sealed against `input_digest(salt, inputs)` and a proof that publishes its own
/// `H_IN`: if the two disagree the chain accepts the call and the transcript opens to something
/// the proof never committed to — the envelope is then a lie the wallet signed. A prover that
/// proved the right computation and returned a different salt is caught here, before submission,
/// by recomputing `H_IN` from the salt it handed back and asking the proof what it published.
pub(crate) fn check_h_in(proof: &[u8], salt: [u32; 4], inputs: &[u32]) -> Result<()> {
    use randprotocol_zkvm::tables::cpu::pv;
    let decoded: randprotocol_zkvm::machine::Proof =
        postcard::from_bytes(proof).map_err(|e| anyhow!("the prover's proof does not decode: {e}"))?;
    let published = decoded
        .public_values
        .get(pv::IN0..pv::IN0 + 8)
        .ok_or_else(|| anyhow!("the prover's proof publishes {} public values, too few to carry H_IN", decoded.public_values.len()))?;
    let want = randprotocol_zkvm::hash::input_digest(salt, inputs);
    if published.iter().zip(want).any(|(got, w)| *got != u64::from(w)) {
        return Err(anyhow!(
            "the proof publishes an input commitment that is not the one this salt makes: the prover returned a salt the proof was not made with",
        ));
    }
    Ok(())
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
                        check_salt(want_salt, salt)?;
                        if let Some(salt) = salt {
                            check_h_in(&proof, salt, inputs).map_err(|e| {
                                anyhow!("{e} — refusing to submit a call proved at {} against a transcript it does not commit to", r.url)
                            })?;
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
    fn a_404_on_a_poll_or_a_result_says_the_job_is_gone() {
        let text = map_refusal(404, &serde_json::json!({})).to_string();
        assert!(text.contains("no longer knows this job") && text.contains("run the command again"), "{text}");
    }

    #[test]
    fn a_salt_nobody_asked_for_is_refused_along_with_a_missing_one() {
        assert!(check_salt(false, Some([1, 2, 3, 4])).unwrap_err().to_string().contains("must publish no input envelope"));
        assert!(check_salt(true, None).unwrap_err().to_string().contains("no salt"));
        assert!(check_salt(true, Some([1, 2, 3, 4])).is_ok());
        assert!(check_salt(false, None).is_ok());
    }

    /// One real proof on the test profile (seconds on a CPU), then the check the wallet runs
    /// before it publishes a transcript: the salt the proof was made with is accepted, and any
    /// other salt — which is what a prover that proved something else would hand back — is not.
    #[test]
    fn a_salt_the_proof_was_not_made_with_is_caught_before_submission() {
        let prog = randprotocol_zkvm::guests::fib(20);
        let (proof, _outputs, _tier, salt) =
            executor::prove_call(FriProfile::Test, &prog, &[], None, Backend::Cpu).expect("fib(20) proves");
        check_h_in(&proof, salt, &[]).expect("the real salt matches the H_IN the proof publishes");
        let other = [salt[0] ^ 1, salt[1], salt[2], salt[3]];
        let e = check_h_in(&proof, other, &[]).unwrap_err().to_string();
        assert!(e.contains("not the one this salt makes"), "{e}");
    }

    #[test]
    fn a_wrong_pin_is_refused_before_any_job() {
        let ours = randprotocol_core::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] };
        let theirs = randprotocol_core::notes::ShieldedAddress { pk: [3; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] };
        assert!(check_pin(&ours, &theirs.to_string()).is_err());
        assert!(check_pin(&ours, &ours.to_string()).is_ok());
    }
}
