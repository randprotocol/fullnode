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
    /// Concurrent proofs. One per GPU; on a CPU box, one.
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
}

impl Config {
    /// The in-process configuration the tests use: CPU, one slot, a short queue, no token.
    pub fn test(key: ProverKey) -> Config {
        Config { key, backend: Backend::Cpu, slots: 1, max_queue: 8, token: None, per_ip: 64, result_ttl: Duration::from_secs(600), allow_open: true }
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

/// Running averages of proving time per kind, seeded per spec §5 so the very first estimate
/// is not zero: 100 s for a bundle and 30 s for a program on the CPU, a tenth of that on CUDA.
pub struct Averages { pub bundle: f64, pub program: f64 }

impl Averages {
    fn seed(backend: Backend) -> Averages {
        let scale = if backend == Backend::Cpu { 1.0 } else { 0.1 };
        Averages { bundle: 100.0 * scale, program: 30.0 * scale }
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
        let avg = Averages::seed(cfg.backend);
        let svc = Arc::new(Service { cfg, inner: Mutex::new(Inner { entries: HashMap::new(), queue: VecDeque::new(), proving: 0, avg }), wake: tokio::sync::Notify::new() });
        for _ in 0..svc.cfg.slots.max(1) {
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
            let wait = self.estimate(&g, kind);
            return Err(Refusal::Busy("queue full".into(), wait.ceil() as u64));
        }
        let wait = self.estimate(&g, kind);
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

    /// Seconds until a job of `kind` submitted now would start: everything ahead of it,
    /// queued or proving, at the running average, spread over the slots.
    fn estimate(&self, g: &Inner, kind: &str) -> f64 {
        let ahead = g.queue.len() + g.proving;
        if ahead == 0 { return 0.0; }
        ahead as f64 * g.avg.get(kind) / self.cfg.slots.max(1) as f64
    }

    /// Drop finished entries past the result TTL.
    fn sweep(&self, g: &mut Inner) {
        let ttl = self.cfg.result_ttl;
        g.entries.retain(|_, e| match e.finished { Some(t) => t.elapsed() < ttl, None => true });
    }

    pub fn status(&self, id: &str) -> Option<(State, Option<usize>, Option<u128>)> {
        let mut g = self.inner.lock().unwrap();
        self.sweep(&mut g);
        let e = g.entries.get(id)?;
        let position = if e.state == State::Queued { g.queue.iter().position(|(i, _)| i == id).map(|p| p + 1) } else { None };
        let elapsed = e.started.map(|s| e.finished.unwrap_or_else(Instant::now).duration_since(s).as_millis());
        Some((e.state, position, elapsed))
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
                        let e = g.entries.get_mut(&id).expect("queued entries exist");
                        if e.submitted.elapsed() > e.deadline {
                            e.state = State::Expired;
                            e.finished = Some(Instant::now());
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
            g.avg.update(kind, secs);
            if let Some(e) = g.entries.get_mut(&id) {
                e.state = state;
                e.finished = Some(Instant::now());
                e.result = sealed;
            }
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
