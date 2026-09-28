//! The proving queue: pairing-gated admission, one worker per proving slot, sealed replies kept
//! for `result_ttl` after they finish.
//!
//! What never leaves this module: a job's witness (`inputs`), its bearer `token` and its
//! `reply_key`. A job is opened in [`Service::submit`], checked, and — if refused — dropped
//! (zeroized) on the spot; if admitted it waits in the queue and is moved into the blocking
//! proving task, which drops it the moment the prover returns. Logs carry the job id, the
//! pairing label, the witness kind, the tier and seconds, nothing else.

use crate::key::ProverKey;
use crate::pairing::{token_hash, Pairings};
use crate::wire::{open_job, seal_reply, ProveJob, ProveReply, WitnessKind, MAX_SEALED_JOB_BYTES};
use rand::Rng;
use randprotocol_core::notes::{word8_to_hex, Word8};
use randprotocol_core::types::TX_BINDING_WORDS;
use randprotocol_zkvm::executor::{prove_bundle_for, ZkExecutor};
use randprotocol_zkvm::hidden::hidden_input;
use randprotocol_zkvm::machine::{Backend, FriProfile};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// The proving function: `(hc_bundle, profile, inputs, binding, backend) -> (proof, digest, tier)`.
pub type ProveFn = Arc<dyn Fn(&Word8, FriProfile, &[u32], &[u32; TX_BINDING_WORDS], Backend) -> Result<(Vec<u8>, Word8, u8), String> + Send + Sync>;

pub struct Config {
    pub key: ProverKey,
    /// Reloaded in place by the CLI (later); admission reads it under the lock.
    pub pairings: Arc<RwLock<Pairings>>,
    pub backend: Backend,
    /// Workers, i.e. proofs at once; at least 1 (the CLI refuses 0).
    pub max_parallel: usize,
    /// Jobs waiting beyond the ones proving.
    pub max_queue: usize,
    /// Whether spend-key witnesses are accepted at all; off by default.
    pub accept_spend_key: bool,
    /// Jobs one token may have queued or proving at once.
    pub per_token: usize,
    /// How long a finished job's sealed reply is kept for the wallet to collect.
    pub result_ttl: Duration,
    pub prove: ProveFn,
}

impl Config {
    /// CPU, one worker, a queue of 8, spend keys refused, 2 jobs per token, replies kept 600 s,
    /// the real prover.
    pub fn new(key: ProverKey, pairings: Pairings) -> Config {
        Config {
            key,
            pairings: Arc::new(RwLock::new(pairings)),
            backend: Backend::Cpu,
            max_parallel: 1,
            max_queue: 8,
            accept_spend_key: false,
            per_token: 2,
            result_ttl: Duration::from_secs(600),
            prove: Arc::new(prove_bundle_for),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Queued, Proving, Done, Failed, Expired }

impl State {
    pub fn as_str(self) -> &'static str {
        match self { State::Queued => "queued", State::Proving => "proving", State::Done => "done", State::Failed => "failed", State::Expired => "expired" }
    }
}

pub struct Status {
    pub state: State,
    /// 1-based, while `Queued`.
    pub position: Option<usize>,
    /// The sealed reply, while `Done`; only the job's `reply_key` opens it.
    pub reply: Option<Vec<u8>>,
    /// While `Failed`.
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct Info {
    pub version: String,
    pub kem_fingerprint: String,
    /// Hex of the ML-KEM-768 encapsulation key.
    pub kem_ek: String,
    /// The bundle guests this build proves, in `known_hc_bundles()` order, each in the hex form
    /// `rand_status.hc_bundle` serves (`randprotocol_core::notes::word8_to_hex`).
    pub hc_bundles: Vec<String>,
    pub profiles: Vec<&'static str>,
    pub backend: &'static str,
    pub witness_kinds: Vec<&'static str>,
    pub queue: QueueInfo,
    /// No fees in this build.
    pub fee: Option<()>,
}

#[derive(Serialize)]
pub struct QueueInfo { pub depth: usize, pub max: usize, pub proving: usize }

#[derive(Debug)]
pub enum Refusal {
    /// Too long, not sealed to this prover, or a job this build cannot prove.
    Bad(String),
    /// The token is not paired.
    Unpaired,
    /// A witness kind this prover does not accept.
    WitnessKind(String),
    /// The token's cap or the queue is full; `depth` is the queued count, `max` the queue's size.
    Busy { depth: usize, max: usize },
}

struct Entry {
    state: State,
    label: String,
    kind: WitnessKind,
    token_hash: [u8; 32],
    #[allow(dead_code)] // kept for the listener's status (Task 4) and for debugging
    submitted: Instant,
    finished: Option<Instant>,
    reply: Option<Vec<u8>>,
    error: Option<String>,
    cancelled: bool,
}

struct Inner {
    entries: HashMap<String, Entry>,
    /// Boxed so a job's token, reply key and witness live in one heap cell that its drop
    /// zeroizes: the deque's buffer holds only the pointer, never a copy of the secrets.
    queue: VecDeque<(String, Box<ProveJob>)>,
    proving: usize,
}

pub struct Service {
    cfg: Config,
    inner: Mutex<Inner>,
    wake: tokio::sync::Notify,
}

pub type Shared = Arc<Service>;

impl Service {
    /// Spawns `max_parallel` workers on the current tokio runtime.
    pub fn start(cfg: Config) -> Shared {
        let svc = Arc::new(Service {
            cfg,
            inner: Mutex::new(Inner { entries: HashMap::new(), queue: VecDeque::new(), proving: 0 }),
            wake: tokio::sync::Notify::new(),
        });
        for _ in 0..svc.cfg.max_parallel.max(1) {
            let s = svc.clone();
            tokio::spawn(async move { s.worker().await });
        }
        svc
    }

    fn backend_name(&self) -> &'static str {
        match self.cfg.backend { Backend::Cpu => "cpu", #[allow(unreachable_patterns)] _ => "cuda" }
    }

    pub fn info(&self) -> Info {
        let (depth, proving) = {
            let g = self.inner.lock().unwrap();
            (g.queue.len(), g.proving)
        };
        Info {
            version: env!("CARGO_PKG_VERSION").to_string(),
            kem_fingerprint: self.cfg.key.fingerprint().to_string(),
            kem_ek: hex::encode(self.cfg.key.kem_ek()),
            hc_bundles: ZkExecutor::known_hc_bundles().iter().map(word8_to_hex).collect(),
            profiles: vec!["test", "production"],
            backend: self.backend_name(),
            witness_kinds: if self.cfg.accept_spend_key { vec![WitnessKind::SpendKey.as_str()] } else { vec![] },
            queue: QueueInfo { depth, max: self.cfg.max_queue, proving },
            fee: None,
        }
    }

    /// Admission, cheap before expensive: size, open, pairing, witness kind, guest, profile,
    /// witness length, the token's cap, the queue's cap. A refused job is dropped (zeroized)
    /// before this returns. Returns the job id: 128 random bits, hex.
    pub fn submit(&self, sealed: &[u8]) -> Result<String, Refusal> {
        if sealed.len() > MAX_SEALED_JOB_BYTES {
            return Err(Refusal::Bad(format!("sealed job of {} bytes exceeds {MAX_SEALED_JOB_BYTES}", sealed.len())));
        }
        let job = Box::new(open_job(self.cfg.key.dk(), sealed).map_err(|e| Refusal::Bad(e.to_string()))?);
        let label = {
            let pairings = self.cfg.pairings.read().unwrap();
            pairings.lookup(&job.token).ok_or(Refusal::Unpaired)?.label.clone()
        };
        match job.witness_kind {
            WitnessKind::SpendKey if !self.cfg.accept_spend_key => {
                return Err(Refusal::WitnessKind("this prover does not accept spend-key witnesses".into()));
            }
            WitnessKind::SpendKey => {}
            WitnessKind::ViewingKey => {
                return Err(Refusal::WitnessKind("viewing-key witnesses are not supported: this build's bundle guests take a spend key".into()));
            }
        }
        if !ZkExecutor::known_hc_bundles().contains(&job.hc_bundle) {
            return Err(Refusal::Bad(format!("unknown bundle guest {}", word8_to_hex(&job.hc_bundle))));
        }
        if ZkExecutor::profile_from_str(&job.profile).is_none() {
            // Not echoed: the profile string is the submitter's, and refusals reach logs and callers.
            return Err(Refusal::Bad("unknown fri profile".into()));
        }
        if job.inputs.len() != hidden_input::COUNT {
            return Err(Refusal::Bad(format!("witness of {} words, expected {}", job.inputs.len(), hidden_input::COUNT)));
        }
        let th = token_hash(&job.token);
        let kind = job.witness_kind;
        let mut g = self.inner.lock().unwrap();
        self.sweep(&mut g);
        let busy = Refusal::Busy { depth: g.queue.len(), max: self.cfg.max_queue };
        let mine = g.entries.values().filter(|e| e.token_hash == th && matches!(e.state, State::Queued | State::Proving)).count();
        if mine >= self.cfg.per_token {
            return Err(busy);
        }
        // Queued plus proving against the whole capacity, so a job admitted but not yet picked
        // up by a worker still counts.
        if g.queue.len() + g.proving >= self.cfg.max_queue + self.cfg.max_parallel.max(1) {
            return Err(busy);
        }
        let mut raw = [0u8; 16];
        rand::rng().fill_bytes(&mut raw);
        let id = hex::encode(raw);
        g.entries.insert(id.clone(), Entry {
            state: State::Queued,
            label: label.clone(),
            kind,
            token_hash: th,
            submitted: Instant::now(),
            finished: None,
            reply: None,
            error: None,
            cancelled: false,
        });
        g.queue.push_back((id.clone(), job));
        drop(g);
        tracing::info!(job = %id, label = %label, kind = kind.as_str(), "queued");
        self.wake.notify_one();
        Ok(id)
    }

    /// A finished entry past `result_ttl` becomes `Expired` and loses its reply; an expired
    /// entry is forgotten a further `max(result_ttl, 60 s)` later, so `Expired` stays observable
    /// for at least a minute and the map stays bounded.
    fn sweep(&self, g: &mut Inner) {
        let ttl = self.cfg.result_ttl;
        let forget = ttl.saturating_add(ttl.max(Duration::from_secs(60)));
        g.entries.retain(|_, e| {
            let Some(t) = e.finished else { return true };
            let age = t.elapsed();
            if age >= forget { return false; }
            if age >= ttl && e.state != State::Expired {
                e.state = State::Expired;
                e.reply = None;
                e.error = None;
            }
            true
        });
    }

    /// A job's state. A `Done` reply is served on every poll until the ttl sweeps it.
    pub fn status(&self, id: &str) -> Option<Status> {
        let mut g = self.inner.lock().unwrap();
        self.sweep(&mut g);
        let e = g.entries.get(id)?;
        let state = e.state;
        let reply = if state == State::Done { e.reply.clone() } else { None };
        let error = if state == State::Failed { e.error.clone() } else { None };
        let position = if state == State::Queued { g.queue.iter().position(|(i, _)| i == id).map(|p| p + 1) } else { None };
        Some(Status { state, position, reply, error })
    }

    /// Removes a queued job outright (its witness zeroized now); flags a proving one so its
    /// reply is discarded when the proof returns. `true` if the job was queued or proving.
    pub fn cancel(&self, id: &str) -> bool {
        let mut g = self.inner.lock().unwrap();
        let Some(e) = g.entries.get_mut(id) else { return false };
        match e.state {
            State::Proving => {
                e.cancelled = true;
                true
            }
            State::Queued => {
                g.entries.remove(id);
                g.queue.retain(|(i, _)| i != id);
                true
            }
            State::Done | State::Failed | State::Expired => false,
        }
    }

    async fn worker(self: Arc<Self>) {
        loop {
            let next = {
                let mut g = self.inner.lock().unwrap();
                match g.queue.pop_front() {
                    Some((id, job)) => match g.entries.get_mut(&id) {
                        Some(e) => {
                            e.state = State::Proving;
                            let (label, kind) = (e.label.clone(), e.kind);
                            g.proving += 1;
                            Some((id, job, label, kind))
                        }
                        // No entry: nothing to record against; the job drops (zeroizes) here.
                        None => continue,
                    },
                    None => None,
                }
            };
            let Some((id, job, label, kind)) = next else {
                self.wake.notified().await;
                continue;
            };
            tracing::info!(job = %id, label = %label, kind = kind.as_str(), "proving");
            let mut reply_key = job.reply_key;
            let hc = job.hc_bundle;
            let binding = job.binding;
            let profile = ZkExecutor::profile_from_str(&job.profile);
            let (prove, backend) = (self.cfg.prove.clone(), self.cfg.backend);
            let started = Instant::now();
            let out = tokio::task::spawn_blocking(move || {
                let out = match profile {
                    Some(p) => (prove)(&hc, p, &job.inputs, &binding, backend),
                    None => Err("unknown fri profile".into()),
                };
                drop(job);
                out
            })
            .await
            .unwrap_or_else(|_| Err("the prover panicked".into()));
            let secs = started.elapsed().as_secs_f64();
            let sealed = out.as_ref().ok().map(|(proof, digest, tier)| seal_reply(&reply_key, &ProveReply { proof: proof.clone(), digest: *digest, tier: *tier }));
            reply_key.zeroize();
            let mut g = self.inner.lock().unwrap();
            g.proving -= 1;
            let mut cancelled = false;
            if let Some(e) = g.entries.get_mut(&id) {
                e.finished = Some(Instant::now());
                if e.cancelled {
                    cancelled = true;
                    e.state = State::Failed;
                    e.error = Some("cancelled".into());
                } else {
                    match &out {
                        Ok(_) => {
                            e.state = State::Done;
                            e.reply = sealed;
                        }
                        Err(err) => {
                            e.state = State::Failed;
                            e.error = Some(err.clone());
                        }
                    }
                }
            }
            // Nothing logs under the store's lock.
            drop(g);
            match &out {
                _ if cancelled => tracing::info!(job = %id, label = %label, kind = kind.as_str(), error = "cancelled", secs, "failed"),
                Ok((_, _, tier)) => tracing::info!(job = %id, label = %label, kind = kind.as_str(), tier, secs, "done"),
                Err(err) => tracing::info!(job = %id, label = %label, kind = kind.as_str(), error = %err, secs, "failed"),
            }
        }
    }
}
