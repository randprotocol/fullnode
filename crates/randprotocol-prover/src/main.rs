//! `rand-prover`: the delegated prover's key, its pairings and its listener.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use randprotocol_prover::http;
use randprotocol_prover::key::ProverKey;
use randprotocol_prover::memory;
use randprotocol_prover::pairing::{PairingLink, Pairings};
use randprotocol_prover::service::Config;
use randprotocol_zkvm::machine::Backend;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "rand-prover", version, about = "RandProtocol delegated prover")]
struct Cli {
    /// Directory holding prover.key.json and pairings.json.
    #[arg(long, global = true, env = "RAND_PROVER_HOME", default_value = "~/.rand-prover")]
    home: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the prover key (refuses to overwrite one) and print its fingerprint.
    Keygen,
    /// Pair a wallet: mint a token and print the pairing link (the token is shown once, never stored).
    Pair {
        #[arg(long)]
        name: String,
        /// The URL the wallet reaches this prover at.
        #[arg(long, default_value = "http://127.0.0.1:8600")]
        url: String,
        /// This prover is the wallet owner's own machine.
        #[arg(long)]
        own: bool,
        /// Also print the link as a QR code.
        #[arg(long)]
        qr: bool,
    },
    /// Remove a pairing.
    Unpair {
        #[arg(long)]
        name: String,
    },
    /// List pairings: label, own, created.
    Pairings,
    /// Serve prover_* JSON-RPC until ctrl-c.
    Run {
        #[arg(long, default_value = "127.0.0.1:8600")]
        listen: SocketAddr,
        /// Accept spend-key witnesses (only for wallets you own).
        #[arg(long)]
        accept_spend_key: bool,
        #[arg(long, default_value_t = 1)]
        max_parallel: usize,
        #[arg(long, default_value_t = 8)]
        max_queue: usize,
        #[arg(long, default_value_t = 2)]
        per_token: usize,
        #[arg(long)]
        cuda: bool,
        #[arg(long)]
        skip_memory_check: bool,
    },
}

fn expand_home(s: &str) -> Result<PathBuf> {
    if s == "~" || s.starts_with("~/") {
        let home = std::env::var("HOME").context("HOME is not set; pass --home")?;
        return Ok(PathBuf::from(home).join(s.trim_start_matches('~').trim_start_matches('/')));
    }
    Ok(PathBuf::from(s))
}

fn ensure_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir).with_context(|| format!("creating {}", dir.display()))
}

/// No fallback: `--cuda` on a build that cannot run it is an error, so a proof is never quietly
/// produced somewhere other than where it was asked for.
fn backend_for(cuda: bool) -> Result<Backend> {
    if !cuda {
        return Ok(Backend::Cpu);
    }
    #[cfg(any(feature = "cuda", feature = "mock-cuda"))]
    {
        Ok(Backend::Cuda)
    }
    #[cfg(not(any(feature = "cuda", feature = "mock-cuda")))]
    {
        anyhow::bail!("built without CUDA support; rebuild rand-prover with --features cuda")
    }
}

/// `YYYY-MM-DD` (UTC) of a unix time, days-from-civil inverted (Howard Hinnant's algorithm).
fn date_of(unix: u64) -> String {
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

fn load_key(path: &Path) -> Result<ProverKey> {
    ProverKey::load(path).with_context(|| format!("loading {} (run `rand-prover keygen` first)", path.display()))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let home = expand_home(&cli.home)?;
    let key_path = home.join("prover.key.json");
    let pairings_path = home.join("pairings.json");
    match cli.cmd {
        Cmd::Keygen => {
            ensure_dir(&home)?;
            if key_path.exists() {
                bail!("{} already exists; a prover key is never overwritten", key_path.display());
            }
            let key = ProverKey::generate();
            key.save_new(&key_path).with_context(|| format!("writing {}", key_path.display()))?;
            eprintln!("wrote {}", key_path.display());
            println!("{}", key.fingerprint());
        }
        Cmd::Pair { name, url, own, qr } => {
            ensure_dir(&home)?;
            let key = load_key(&key_path)?;
            let mut pairings = Pairings::load(&pairings_path)?;
            let token = pairings.pair(&name, own).map_err(anyhow::Error::msg)?;
            pairings.save(&pairings_path).with_context(|| format!("writing {}", pairings_path.display()))?;
            let mut link = PairingLink { kem_ek: key.kem_ek().to_vec(), url, token, own };
            let mut text = link.format();
            link.token.zeroize();
            eprintln!("paired {name:?}{}; prover fingerprint {}", if own { " (own)" } else { "" }, key.fingerprint());
            eprintln!("the link below carries the pairing token and is shown only this once:");
            println!("{text}");
            if qr {
                let code = qrcode::QrCode::new(text.as_bytes())?;
                println!("{}", code.render::<qrcode::render::unicode::Dense1x2>().build());
            }
            text.zeroize();
        }
        Cmd::Unpair { name } => {
            let mut pairings = Pairings::load(&pairings_path)?;
            if !pairings.unpair(&name) {
                bail!("no pairing labelled {name:?}");
            }
            pairings.save(&pairings_path).with_context(|| format!("writing {}", pairings_path.display()))?;
            eprintln!("unpaired {name:?}; a running prover picks this up on restart");
        }
        Cmd::Pairings => {
            let pairings = Pairings::load(&pairings_path)?;
            for p in &pairings.pairings {
                println!("{}  {}  {}", p.label, if p.own { "own" } else { "-" }, date_of(p.created_unix));
            }
        }
        Cmd::Run { listen, accept_spend_key, max_parallel, max_queue, per_token, cuda, skip_memory_check } => {
            if max_parallel == 0 {
                bail!("--max-parallel must be at least 1");
            }
            let backend = backend_for(cuda)?;
            let key = load_key(&key_path)?;
            let pairings = Pairings::load(&pairings_path)?;
            if skip_memory_check {
                tracing::warn!("memory check skipped");
            } else {
                memory::check(max_parallel).map_err(anyhow::Error::msg)?;
            }
            if pairings.pairings.is_empty() {
                // Printed, not only logged: a log filter must never hide a misconfiguration.
                eprintln!("no pairings: every job will be refused — run `rand-prover pair`");
                tracing::warn!("no pairings: every job will be refused — run `rand-prover pair`");
            }
            if accept_spend_key {
                // The spec's disclosure sentence: printed, so no log filter can hide it.
                eprintln!("every SpendKey job holds the sending wallet's spend key: run this only for wallets you own");
                tracing::warn!("every SpendKey job holds the sending wallet's spend key: run this only for wallets you own");
            }
            let fingerprint = key.fingerprint();
            let mut cfg = Config::new(key, pairings);
            cfg.backend = backend;
            cfg.max_parallel = max_parallel;
            cfg.max_queue = max_queue;
            cfg.per_token = per_token;
            cfg.accept_spend_key = accept_spend_key;
            let (bound, svc, mut task) = http::serve(listen, cfg).await?;
            eprintln!("rand-prover {fingerprint} listening on http://{bound}");
            tokio::select! {
                r = shutdown_signal() => {
                    r?;
                    // Queued jobs are dropped now; the runtime still waits for a proof already on
                    // the blocking pool, whose reply is discarded.
                    eprintln!("shutting down: queued jobs dropped; a proof in flight (up to ~100 s) finishes first and its reply is discarded");
                    svc.shutdown();
                    task.abort();
                    let _ = task.await;
                }
                _ = &mut task => {
                    svc.shutdown();
                    bail!("the listener exited");
                }
            }
        }
    }
    Ok(())
}

/// Ctrl-C or SIGTERM (systemd's default stop signal), whichever comes first: both stop the same
/// graceful way, waiting for a proof in flight.
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn date_of_known_days() {
        assert_eq!(super::date_of(0), "1970-01-01");
        assert_eq!(super::date_of(951_782_400), "2000-02-29");
        assert_eq!(super::date_of(1_790_553_600), "2026-09-28");
    }
}
