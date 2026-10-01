//! `rand-prover`: the delegated prover's key, its pairings and its listener.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use randprotocol_prover::http;
use randprotocol_prover::key::ProverKey;
use randprotocol_prover::memory;
use randprotocol_prover::origins::AllowedOrigins;
use randprotocol_prover::pairing::{PairingLink, Pairings};
use randprotocol_prover::service::{Config, Fee};
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
        /// Label the pairing as the wallet owner's own machine (`own=1` in the link). A label
        /// only: every pairing is sent the same viewing-key witness, never a spend key.
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
        /// Retired (VK-4): still parsed, so a unit file that passes it fails with the reason
        /// instead of an "unexpected argument"; `run` refuses to start when it is given.
        #[arg(long, hide = true)]
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
        /// The longest one proof may take, in seconds (audit v7, VK-12); 0 = no limit. A proof
        /// past it fails its job and this process exits with status 75 so its supervisor
        /// (systemd's `Restart=`) starts a clean one: a proving thread cannot be stopped from
        /// outside, and one that never returns would otherwise hold its slot for ever.
        #[arg(long, default_value_t = 600)]
        prove_timeout_secs: u64,
        /// A web origin whose pages may read this prover's replies (repeatable). Given at least
        /// once, the values are the whole list; absent, the default is browser extensions and
        /// loopback pages (`chrome-extension://*`, `moz-extension://*`, `safari-web-extension://*`,
        /// `http://localhost:*`, `http://127.0.0.1:*`, `http://[::1]:*`). `*` allows every
        /// website, which can then read this prover's key as a cross-site identifier.
        #[arg(long = "allow-origin", value_name = "ORIGIN")]
        allow_origin: Vec<String>,
        /// The fee every job must pay, in RAND (display units, up to 9 decimals): one RAND output
        /// to --fee-address inside the bundle being proved (spec §5). Needs --fee-address.
        #[arg(long, value_name = "RAND", requires = "fee_address")]
        fee: Option<String>,
        /// The shielded address (`rand1…`) the fee is paid to. Needs --fee.
        #[arg(long, value_name = "ADDRESS", requires = "fee")]
        fee_address: Option<String>,
    },
}

/// `--allow-origin` → the listener's list, with the one-line warning `*` earns (printed, so no
/// log filter can hide it).
fn allowed_origins(values: &[String], flag: &str) -> Result<AllowedOrigins> {
    let allowed = AllowedOrigins::from_flags(values).map_err(|e| anyhow::anyhow!(e.replace("--allow-origin", flag)))?;
    if allowed == AllowedOrigins::Any {
        eprintln!("{flag} '*': every website can read this prover's replies, its key included (a cross-site identifier)");
    }
    Ok(allowed)
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
            // Before the pairing is recorded: a link no wallet would parse is never minted (VK-5).
            randprotocol_prover::pairing::check_link_url(&url).map_err(|e| anyhow::anyhow!("--url: {e}"))?;
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
        Cmd::Run { listen, accept_spend_key, max_parallel, max_queue, per_token, cuda, skip_memory_check, prove_timeout_secs, allow_origin, fee, fee_address } => {
            // First, before the key or anything else is looked at: the flag's absence of effect
            // must never be silent (VK-4).
            if accept_spend_key {
                bail!(randprotocol_prover::service::spend_key_flag_retired("--accept-spend-key"));
            }
            if max_parallel == 0 {
                bail!("--max-parallel must be at least 1");
            }
            // clap's `requires` makes it both or neither.
            let fee = match (fee, fee_address) {
                (Some(a), Some(to)) => Some(Fee::from_flags(&a, &to).map_err(anyhow::Error::msg)?),
                _ => None,
            };
            let allowed = allowed_origins(&allow_origin, "--allow-origin")?;
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
            let fingerprint = key.fingerprint();
            let mut cfg = Config::new(key, pairings);
            cfg.backend = backend;
            cfg.max_parallel = max_parallel;
            cfg.max_queue = max_queue;
            cfg.per_token = per_token;
            cfg.allowed_origins = allowed;
            cfg.prove_timeout = (prove_timeout_secs > 0).then(|| std::time::Duration::from_secs(prove_timeout_secs));
            cfg.on_wedged = std::sync::Arc::new(|after| {
                eprintln!("a proof outlived --prove-timeout-secs ({}s): exiting so the supervisor restarts a clean prover", after.as_secs());
                std::process::exit(75);
            });
            if let Some(f) = &fee {
                eprintln!("charging {} RAND per job to {}", randprotocol_core::format_amount(f.amount), f.address.fingerprint());
            }
            cfg.fee = fee;
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
    use clap::Parser;

    #[test]
    fn run_takes_the_fee_flags_both_or_neither() {
        let run = |extra: &[&str]| super::Cli::try_parse_from([&["rand-prover", "run"][..], extra].concat());
        assert!(run(&[]).is_ok());
        assert!(run(&["--fee", "1.5", "--fee-address", "rand1x"]).is_ok());
        assert!(run(&["--fee", "1.5"]).is_err(), "--fee needs --fee-address");
        assert!(run(&["--fee-address", "rand1x"]).is_err(), "--fee-address needs --fee");
    }

    #[test]
    fn date_of_known_days() {
        assert_eq!(super::date_of(0), "1970-01-01");
        assert_eq!(super::date_of(951_782_400), "2000-02-29");
        assert_eq!(super::date_of(1_790_553_600), "2026-09-28");
    }
}
