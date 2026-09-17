//! `rand-prover`: a trusted proving service for wallets that cannot prove in useful time
//! (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md`). A pure function of the
//! sealed jobs it receives — it never reads the chain — behind a bounded queue and one proving
//! slot per backend. The job's inputs are the wallet's witness, spend key included: whoever
//! runs this holds custody of every wallet that delegates to it (spec §9).

pub mod http;

use randprotocol_zkvm::delegate::{self, JobKind, JobRequest, JobResult, ProverKey, Sealed};
use randprotocol_zkvm::executor::{self, ZkExecutor};
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::Backend;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use http::serve;

pub struct Config {
    pub key: ProverKey,
    pub backend: Backend,
    /// Concurrent proofs. One per GPU; on a CPU box, one. Zero spawns no workers at all, so
    /// nothing is ever proved — only the tests that want a job to sit in the queue use that,
    /// and `rand-prover run` rejects `--slots 0`.
    pub slots: usize,
    /// Jobs waiting beyond the ones proving. Zero means "only what the slots can take now".
    pub max_queue: usize,
    /// The bearer wallets must send. `None` is loopback-only unless `allow_open`.
    pub token: Option<String>,
    /// Jobs a single client IP may have queued or proving at once.
    pub per_ip: usize,
    /// How long a finished job's sealed result is kept for the wallet to fetch.
    pub result_ttl: Duration,
    pub allow_open: bool,
    /// What the running averages start at, `(bundle, program)` seconds on the CPU (spec §5),
    /// before any job has been timed. CUDA scales both down; see [`Averages::seed`].
    pub seed_secs: (f64, f64),
}

impl Config {
    /// The in-process configuration the tests use: CPU, one slot, a short queue, no token.
    pub fn test(key: ProverKey) -> Config {
        Config { key, backend: Backend::Cpu, slots: 1, max_queue: 8, token: None, per_ip: 64, result_ttl: Duration::from_secs(600), allow_open: true, seed_secs: (100.0, 30.0) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Queued, Proving, Done, Failed, Expired }

impl State {
    pub fn as_str(self) -> &'static str {
        match self { State::Queued => "queued", State::Proving => "proving", State::Done => "done", State::Failed => "failed", State::Expired => "expired" }
    }
}

pub struct Entry {
    pub state: State,
    pub kind: &'static str,
    pub ip: IpAddr,
    pub submitted: Instant,
    pub deadline: Duration,
    pub started: Option<Instant>,
    pub finished: Option<Instant>,
    pub result: Option<Sealed>,
}

/// Running averages of proving time per kind, seeded from [`Config::seed_secs`] so the very
/// first estimate is not zero: per spec §5, 100 s for a bundle and 30 s for a program on the
/// CPU, a tenth of that on CUDA.
pub struct Averages { pub bundle: f64, pub program: f64 }

impl Averages {
    fn seed(backend: Backend, seed_secs: (f64, f64)) -> Averages {
        let scale = if backend == Backend::Cpu { 1.0 } else { 0.1 };
        Averages { bundle: seed_secs.0 * scale, program: seed_secs.1 * scale }
    }
    fn get(&self, kind: &str) -> f64 { if kind == "bundle" { self.bundle } else { self.program } }
    fn update(&mut self, kind: &str, secs: f64) {
        let slot = if kind == "bundle" { &mut self.bundle } else { &mut self.program };
        *slot = 0.7 * *slot + 0.3 * secs;
    }
}

pub struct Inner {
    pub entries: HashMap<String, Entry>,
    pub queue: VecDeque<(String, JobRequest)>,
    pub proving: usize,
    pub avg: Averages,
}

pub struct Service {
    pub cfg: Config,
    pub inner: Mutex<Inner>,
    pub wake: tokio::sync::Notify,
}

pub type Shared = Arc<Service>;

pub enum Refusal {
    /// Not a sealed job, or sealed to some other prover, or a version we do not speak.
    Bad(String),
    /// Queue full, per-IP cap, or the deadline cannot be met; with the seconds to wait.
    Busy(String, u64),
}

impl Service {
    pub fn new(cfg: Config) -> Shared {
        let avg = Averages::seed(cfg.backend, cfg.seed_secs);
        let svc = Arc::new(Service { cfg, inner: Mutex::new(Inner { entries: HashMap::new(), queue: VecDeque::new(), proving: 0, avg }), wake: tokio::sync::Notify::new() });
        // No clamp: `slots: 0` deliberately spawns no workers, which is how a test parks a job
        // in the queue. `rand-prover run` rejects it so a real deployment cannot sit idle.
        for _ in 0..svc.cfg.slots {
            let s = svc.clone();
            tokio::spawn(async move { s.worker().await });
        }
        svc
    }

    pub fn backend_name(&self) -> &'static str {
        match self.cfg.backend { Backend::Cpu => "cpu", #[allow(unreachable_patterns)] _ => "cuda" }
    }

    /// Admission: open the job, apply the caps, estimate the start, enqueue. Returns the id
    /// and the queue position.
    pub fn submit(&self, bytes: &[u8], ip: IpAddr) -> Result<(String, usize), Refusal> {
        let sealed = delegate::decode(bytes).map_err(Refusal::Bad)?;
        let job = delegate::open_job(&self.cfg.key, &sealed).map_err(Refusal::Bad)?;
        if ZkExecutor::profile_from_str(&job.profile).is_none() {
            return Err(Refusal::Bad(format!("unknown fri profile {:?}", job.profile)));
        }
        // The result is sealed to `reply_ek`. A key we cannot seal to would only be discovered
        // after the proof was made, and the job would end `Failed` carrying no result — a
        // `/result` 404 the wallet polls until it gives up, having paid for the proving. Probe
        // the seal now, on an empty body, and refuse the job instead.
        if let Err(e) = delegate::seal_result(&job.reply_ek, &JobResult::Failed { error: String::new() }) {
            return Err(Refusal::Bad(format!("reply_ek is not a valid ML-KEM-768 encapsulation key: {e}")));
        }
        let kind = job.kind.name();
        let mut g = self.inner.lock().unwrap();
        self.sweep(&mut g);
        let mine = g.entries.values().filter(|e| e.ip == ip && matches!(e.state, State::Queued | State::Proving)).count();
        if mine >= self.cfg.per_ip {
            return Err(Refusal::Busy(format!("{mine} jobs already in flight from this address"), 30));
        }
        // In flight is queued *plus* proving, against `max_queue + slots`. Testing the two
        // halves separately would let a job that has been admitted but not yet picked up by a
        // worker count toward neither cap, so the bound would hold only once a slot had
        // actually claimed the work — a window in which the service over-admits.
        if g.queue.len() + g.proving >= self.cfg.max_queue + self.cfg.slots.max(1) {
            let wait = self.estimate(&g);
            return Err(Refusal::Busy("queue full".into(), wait.ceil() as u64));
        }
        let wait = self.estimate(&g);
        if wait > job.deadline_secs as f64 {
            return Err(Refusal::Busy(format!("cannot start within {} s; the estimate is {:.0} s", job.deadline_secs, wait), wait.ceil() as u64));
        }
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
        let id = hex::encode(id);
        g.entries.insert(id.clone(), Entry { state: State::Queued, kind, ip, submitted: Instant::now(), deadline: Duration::from_secs(job.deadline_secs as u64), started: None, finished: None, result: None });
        g.queue.push_back((id.clone(), job));
        let position = g.queue.len();
        drop(g);
        self.wake.notify_one();
        Ok((id, position))
    }

    /// Seconds until a job submitted now would start: the work already in flight, spread over
    /// the slots.
    ///
    /// Each job ahead is costed at the running average *for its own kind*, not for the kind of
    /// the job being admitted — a program queued behind eight bundles waits eight bundle
    /// proofs, and saying otherwise would under-quote it by most of an order of magnitude. The
    /// number gates the deadline and is what `retry_after_secs` tells the wallet, so it has to
    /// describe the queue rather than the caller.
    fn estimate(&self, g: &Inner) -> f64 {
        let ahead: f64 = g
            .entries
            .values()
            .filter(|e| matches!(e.state, State::Queued | State::Proving))
            .map(|e| g.avg.get(e.kind))
            .sum();
        ahead / self.cfg.slots.max(1) as f64
    }

    /// Drop finished entries past the result TTL.
    fn sweep(&self, g: &mut Inner) {
        let ttl = self.cfg.result_ttl;
        g.entries.retain(|_, e| match e.finished { Some(t) => t.elapsed() < ttl, None => true });
    }

    /// A job's state, its queue position while it is queued, and how long it has been proving.
    ///
    /// A queued job past its deadline is expired here, the moment anyone looks, and dropped
    /// from the queue: waiting for a slot to reach it would have the service answer "queued"
    /// long after the wallet's deadline had gone, and on a busy prover that could be the whole
    /// life of the job. The worker repeats the check when it pops, as the second line of
    /// defence for a job nobody polls.
    pub fn status(&self, id: &str) -> Option<(State, Option<usize>, Option<u128>)> {
        let mut g = self.inner.lock().unwrap();
        self.sweep(&mut g);
        let inner = &mut *g;
        let e = inner.entries.get_mut(id)?;
        let expired_now = e.state == State::Queued && e.submitted.elapsed() > e.deadline;
        if expired_now {
            e.state = State::Expired;
            e.finished = Some(Instant::now());
        }
        let state = e.state;
        let elapsed = e.started.map(|s| e.finished.unwrap_or_else(Instant::now).duration_since(s).as_millis());
        if expired_now {
            inner.queue.retain(|(i, _)| i != id);
        }
        let position = if state == State::Queued { inner.queue.iter().position(|(i, _)| i == id).map(|p| p + 1) } else { None };
        Some((state, position, elapsed))
    }

    pub fn result(&self, id: &str) -> Option<Sealed> {
        let g = self.inner.lock().unwrap();
        g.entries.get(id).and_then(|e| e.result.clone())
    }

    pub fn queue_depth(&self) -> (usize, usize) {
        let g = self.inner.lock().unwrap();
        (g.queue.len(), g.proving)
    }

    async fn worker(self: Arc<Self>) {
        loop {
            let next = {
                let mut g = self.inner.lock().unwrap();
                match g.queue.pop_front() {
                    Some((id, job)) => {
                        // Swept out from under us, or expired by `status` — either way there
                        // is nothing to record against, so drop the job (zeroizing it) and
                        // take the next one rather than panicking under the lock.
                        let Some(e) = g.entries.get_mut(&id) else { continue };
                        if e.submitted.elapsed() > e.deadline {
                            e.state = State::Expired;
                            e.finished = Some(Instant::now());
                            drop(g);
                            tracing::info!(job = %id, "expired before it could start");
                            continue;
                        }
                        e.state = State::Proving;
                        e.started = Some(Instant::now());
                        g.proving += 1;
                        Some((id, job))
                    }
                    None => None,
                }
            };
            let Some((id, job)) = next else {
                self.wake.notified().await;
                continue;
            };
            let kind = job.kind.name();
            let backend = self.cfg.backend;
            let reply_ek = job.reply_ek.clone();
            let started = Instant::now();
            tracing::info!(job = %id, kind, "proving");
            let result = tokio::task::spawn_blocking(move || prove(job, backend)).await.unwrap_or_else(|e| JobResult::Failed { error: format!("prover panicked: {e}") });
            let secs = started.elapsed().as_secs_f64();
            let (state, sealed) = match delegate::seal_result(&reply_ek, &result) {
                Ok(s) => (if matches!(result, JobResult::Failed { .. }) { State::Failed } else { State::Done }, Some(s)),
                Err(e) => {
                    tracing::warn!(job = %id, "could not seal the result: {e}");
                    (State::Failed, None)
                }
            };
            let mut g = self.inner.lock().unwrap();
            g.proving -= 1;
            // Only a proof that was actually made says anything about how long proving takes. A
            // job that failed in a millisecond — a bad profile, a witness the guest rejects — is
            // not a fast proof, and folding a stream of them into the average would drive the
            // estimate toward zero, which is exactly the estimate that stops refusing deadlines
            // the prover cannot meet.
            if !matches!(result, JobResult::Failed { .. }) {
                g.avg.update(kind, secs);
            }
            if let Some(e) = g.entries.get_mut(&id) {
                e.state = state;
                e.finished = Some(Instant::now());
                e.result = sealed;
            }
            // Nothing logs while the store mutex is held: a slow or blocking subscriber would
            // otherwise stall every admission and status poll behind it.
            drop(g);
            tracing::info!(job = %id, kind, state = state.as_str(), secs = format!("{secs:.1}"), "finished");
        }
    }
}

/// The proof itself: the three `executor` entry points a wallet would have called locally.
/// `job` is consumed and dropped here, which zeroizes its inputs.
fn prove(job: JobRequest, backend: Backend) -> JobResult {
    let Some(profile) = ZkExecutor::profile_from_str(&job.profile) else {
        return JobResult::Failed { error: format!("unknown fri profile {:?}", job.profile) };
    };
    match &job.kind {
        JobKind::Bundle { inputs } => match executor::prove_bundle(profile, inputs, backend) {
            Ok((proof, digest, tier)) => JobResult::Bundle { proof, digest, tier },
            Err(error) => JobResult::Failed { error },
        },
        JobKind::Program { base_pc, words, inputs, tier, want_salt } => {
            if base_pc % 4 != 0 {
                return JobResult::Failed { error: "base_pc is not word-aligned".into() };
            }
            let program = Program { base_pc: *base_pc, words: words.clone() };
            if *want_salt {
                match executor::prove_call(profile, &program, inputs, *tier, backend) {
                    Ok((proof, outputs, tier, salt)) => JobResult::Program { proof, outputs, tier, salt: Some(salt) },
                    Err(error) => JobResult::Failed { error },
                }
            } else {
                match executor::prove(profile, &program, inputs, *tier, backend) {
                    Ok((proof, outputs, tier)) => JobResult::Program { proof, outputs, tier, salt: None },
                    Err(error) => JobResult::Failed { error },
                }
            }
        }
    }
}

/// Refuse to listen on a non-loopback address without a token, unless told to.
pub fn check_bind(addr: SocketAddr, cfg: &Config) -> anyhow::Result<()> {
    if cfg.token.is_none() && !addr.ip().is_loopback() && !cfg.allow_open {
        anyhow::bail!("refusing to listen on {addr} without --token: every job is seconds of GPU or a minute of CPU. Pass --token <bearer>, or --allow-open to accept that");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_zkvm::delegate::ProverKey;
    use randprotocol_zkvm::notes::SpendKey;

    fn cfg(token: Option<&str>, allow_open: bool) -> Config {
        let key = ProverKey::from_viewing_key(&SpendKey([5; 8]).viewing_key());
        Config { token: token.map(str::to_string), allow_open, ..Config::test(key) }
    }

    /// The one thing standing between a laptop's spare cycles and the open internet: a prover
    /// that listens off loopback says who may use it, or says out loud that anyone may.
    #[test]
    fn an_open_bind_needs_a_token_or_an_explicit_blessing() {
        let loopback: SocketAddr = "127.0.0.1:8600".parse().unwrap();
        let open: SocketAddr = "0.0.0.0:8600".parse().unwrap();
        assert!(check_bind(loopback, &cfg(None, false)).is_ok(), "loopback with no token is the default");
        let e = check_bind(open, &cfg(None, false)).unwrap_err().to_string();
        assert!(e.contains("refusing to listen") && e.contains("--allow-open"), "{e}");
        assert!(check_bind(open, &cfg(None, true)).is_ok(), "--allow-open accepts the risk");
        assert!(check_bind(open, &cfg(Some("hunter2"), false)).is_ok(), "a token is the other way to say who may use it");
    }
}
