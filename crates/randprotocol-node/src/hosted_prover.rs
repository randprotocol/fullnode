//! `rand-node run --prover`: the delegated prover hosted beside a node (`docs/prover.md` §4), on
//! its own listener, never a method of the public RPC. [`prepare`] makes every check that can
//! refuse — the key, the pairings, the backend, the free-memory gate and the bind itself — before
//! the node key is read or the database opened; [`start`] serves the bound listener once the node
//! is up; [`run`] ties the two together, so either one exiting stops the other. On the way out
//! `run` calls [`Service::shutdown`](randprotocol_prover::service::Service::shutdown) (queue
//! dropped, workers stopped) first, then stops the node, then aborts the listener task.

use crate::node::NodeHandle;
use anyhow::{Context, Result};
use randprotocol_prover::key::ProverKey;
use randprotocol_prover::origins::AllowedOrigins;
use randprotocol_prover::pairing::Pairings;
use randprotocol_prover::service::{Config, Fee, Shared};
use randprotocol_zkvm::machine::Backend;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::task::JoinHandle;

/// `run`'s `--prover*` flags.
#[derive(Clone, Debug)]
pub struct Options {
    /// `--prover`.
    pub addr: SocketAddr,
    /// `--rpc`, which the prover's address must not overlap.
    pub rpc: SocketAddr,
    /// `--prover-home` (default `<datadir>/prover`).
    pub home: PathBuf,
    pub max_parallel: usize,
    pub max_queue: usize,
    pub cuda: bool,
    /// `--prover-cpu`.
    pub cpu: bool,
    /// `--prover-threads`.
    pub threads: Option<usize>,
    pub skip_memory_check: bool,
    /// `--prover-allow-origin` values: empty = the default list (extensions and loopback pages),
    /// otherwise the whole list; `*` = every origin.
    pub allow_origins: Vec<String>,
    /// `--prover-fee`: the fee every job must pay, in RAND display units; both it and
    /// `fee_address` or neither (spec §5).
    pub fee: Option<String>,
    /// `--prover-fee-address`: the `rand1…` address the fee is paid to.
    pub fee_address: Option<String>,
}

/// What `run --prover` loaded before the node started: everything that can refuse has done so,
/// and the prover's address is already bound (not yet served).
pub struct HostedProver {
    cfg: Config,
    listener: std::net::TcpListener,
    fingerprint: String,
}

impl HostedProver {
    /// The address the prover's listener is bound to (the port, for `:0`).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

/// `run --prover`'s checks, as `rand-prover run` makes them: a listener distinct from the RPC, a
/// key that already exists (a node never mints one), the pairings (none = a warning), the
/// backend (no CUDA fallback), the free-memory gate — and the bind, so a port already in use
/// fails here rather than after the node's startup verify.
pub fn prepare(o: &Options) -> Result<HostedProver> {
    let (addr, rpc, home) = (o.addr, o.rpc, &o.home);
    // A wildcard bind on either side overlaps the other on the same port (and macOS's
    // SO_REUSEADDR lets a specific bind sit beside a wildcard one), so that is the same listener too.
    let overlaps = addr.ip() == rpc.ip() || addr.ip().is_unspecified() || rpc.ip().is_unspecified();
    // Port 0 on both sides is two ephemeral ports, never one listener.
    if overlaps && addr.port() != 0 && addr.port() == rpc.port() {
        anyhow::bail!("--prover {addr} is the --rpc address: the prover is never a method of the public RPC; give it its own listener");
    }
    if o.max_parallel == 0 {
        anyhow::bail!("--prover-max-parallel must be at least 1");
    }
    let fee = match (&o.fee, &o.fee_address) {
        (Some(amount), Some(to)) => Some(Fee::from_flags(amount, to).map_err(|e| anyhow::anyhow!(e.replace("--fee", "--prover-fee")))?),
        (None, None) => None,
        _ => anyhow::bail!("--prover-fee and --prover-fee-address go together: give both or neither"),
    };
    let allowed_origins = AllowedOrigins::from_flags(&o.allow_origins).map_err(|e| anyhow::anyhow!(e.replace("--allow-origin", "--prover-allow-origin")))?;
    let key_path = home.join("prover.key.json");
    let key = match ProverKey::load(&key_path) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
            "no prover key at {}: run `rand-prover --home {} keygen` and `pair` first",
            key_path.display(),
            home.display()
        ),
        Err(e) => return Err(anyhow::Error::new(e).context(format!("loading {}", key_path.display()))),
    };
    let backend = {
        use randprotocol_prover::proving::{self, Choice};
        let (choice, note) = proving::choose_backend(o.cuda, o.cpu, proving::BUILD_HAS_CUDA, proving::gpu_visible()).map_err(anyhow::Error::msg)?;
        if let Some(n) = note {
            eprintln!("{n}");
            tracing::info!("{n}");
        }
        match choice {
            Choice::Cpu => Backend::Cpu,
            #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
            Choice::Cuda => Backend::Cuda,
            #[cfg(not(any(feature = "cuda", feature = "mock-cuda")))]
            Choice::Cuda => unreachable!("choose_backend never picks the GPU for a build without it"),
        }
    };
    {
        use randprotocol_prover::proving;
        let n = proving::threads_for(o.threads, std::env::var("RAYON_NUM_THREADS").ok().as_deref(), proving::available_threads(), proving::Role::Service)
            .map_err(anyhow::Error::msg)?;
        if let Err(e) = proving::install_thread_pool(n) {
            tracing::warn!("{e}");
        }
        tracing::info!(threads = n, backend = ?backend, "hosted prover proving");
    }
    let pairings_path = home.join("pairings.json");
    let pairings = Pairings::load(&pairings_path).with_context(|| format!("loading {}", pairings_path.display()))?;
    if o.skip_memory_check {
        tracing::warn!("prover memory check skipped");
    } else {
        // `memory::check` names `rand-prover`'s flags; this node's are prefixed.
        randprotocol_prover::memory::check(o.max_parallel).map_err(|e| {
            anyhow::anyhow!(e.replace("--max-parallel", "--prover-max-parallel").replace("--skip-memory-check", "--prover-skip-memory-check"))
        })?;
    }
    let listener = std::net::TcpListener::bind(addr).with_context(|| format!("binding the prover on {addr}"))?;
    listener.set_nonblocking(true)?;
    if pairings.pairings.is_empty() {
        // Printed, not only logged: a log filter must never hide a misconfiguration.
        let line = format!("no prover pairings: every job will be refused — run `rand-prover --home {} pair`", home.display());
        eprintln!("{line}");
        tracing::warn!("{line}");
    }
    let fingerprint = key.fingerprint().to_string();
    let mut cfg = Config::new(key, pairings);
    cfg.backend = backend;
    cfg.max_parallel = o.max_parallel;
    cfg.max_queue = o.max_queue;
    if allowed_origins == AllowedOrigins::Any {
        let line = "--prover-allow-origin '*': every website can read this prover's replies, its key included (a cross-site identifier)";
        eprintln!("{line}");
        tracing::warn!("{line}");
    }
    cfg.allowed_origins = allowed_origins;
    if let Some(f) = &fee {
        let line = format!("the prover charges {} RAND per job to {}", randprotocol_core::format_amount(f.amount), f.address.fingerprint());
        eprintln!("{line}");
        tracing::info!("{line}");
    }
    cfg.fee = fee;
    Ok(HostedProver { cfg, listener, fingerprint })
}

/// A served prover: its queue and its listener task, which [`run`] stops together.
pub struct Served {
    pub svc: Shared,
    pub task: JoinHandle<()>,
}

/// Serves the listener [`prepare`] bound: the prover's address, and its service and server task.
pub async fn start(hp: HostedProver) -> Result<(SocketAddr, Served)> {
    let listener = tokio::net::TcpListener::from_std(hp.listener)?;
    let (bound, svc, task) = randprotocol_prover::http::serve_on(listener, hp.cfg).await?;
    tracing::info!("prover listening on {bound}, fingerprint {}", hp.fingerprint);
    Ok((bound, Served { svc, task }))
}

/// Runs the node until it ends, `shutdown` fires, or the hosted prover's task (when there is one)
/// exits — which stops the node and is an error. On the way out the prover's service is shut down
/// (queued jobs dropped; a proof in flight, up to ~100 s, finishes with its reply discarded, and
/// the runtime waits for it before the process exits) and its listener task aborted.
///
/// The order is load-bearing: `Service::shutdown` first, then the node, then the listener. Stopping
/// the node first (it can take seconds) would leave the prover admitting jobs — and starting a
/// ~100 s proof — while the process is already on its way out.
pub async fn run(mut handle: NodeHandle, mut prover: Option<Served>, shutdown: impl Future<Output = ()>) -> Result<()> {
    enum Why {
        NodeEnded(Result<()>),
        ProverExited,
        Requested,
    }
    let prover_exit = async {
        match prover.as_mut() {
            Some(p) => {
                let _ = (&mut p.task).await;
            }
            None => std::future::pending::<()>().await,
        }
    };
    let why = tokio::select! {
        r = &mut handle.task => Why::NodeEnded(r.map_err(anyhow::Error::from).and_then(|r| r)),
        _ = prover_exit => Why::ProverExited,
        _ = shutdown => Why::Requested,
    };
    // 1. The prover's queue closes before anything else: no job is admitted from here on.
    if let Some(p) = prover.as_ref() {
        tracing::info!("stopping the prover: queued jobs dropped; a proof in flight (up to ~100 s) finishes first and its reply is discarded");
        p.svc.shutdown();
    }
    // 2. The node.
    let out = match why {
        Why::NodeEnded(r) => r,
        Why::ProverExited => {
            tracing::error!("the prover listener exited; stopping the node");
            handle.shutdown().await;
            Err(anyhow::anyhow!("the prover listener exited"))
        }
        Why::Requested => {
            tracing::info!("shutting down");
            handle.shutdown().await;
            Ok(())
        }
    };
    // 3. The listener. Not awaited when `prover_exit` already consumed it: a JoinHandle is polled
    // once to completion.
    if let Some(p) = prover {
        if !p.task.is_finished() {
            p.task.abort();
            let _ = p.task.await;
        }
    }
    out
}

/// Ctrl-C or SIGTERM (systemd's default stop signal), whichever comes first.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!("cannot listen for SIGTERM ({e}); stopping on ctrl-c only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
