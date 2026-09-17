//! `rand-prover`: run the service, print the address wallets pin, or make a key.
//!
//! The key file is an ordinary wallet key file (`rand keygen` makes one too): the address
//! wallets seal jobs to is that key's `rand1…` address, and its decapsulation key is derived
//! from it exactly as a receiving wallet's is. The spend key in it is never used to spend.

use anyhow::Result;
use clap::{Parser, Subcommand};
use randprotocol_client::wallet::Wallet;
use randprotocol_prover::{serve, Config};
use randprotocol_zkvm::delegate::ProverKey;
use randprotocol_zkvm::machine::Backend;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "rand-prover", version, about = "RAND delegated prover: proves sealed jobs for wallets")]
struct Cli {
    /// Key file (a wallet key file). Its address is what wallets pin.
    #[arg(long, global = true, env = "RAND_PROVER_KEY", default_value = "prover.key.json")]
    key: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve jobs.
    Run {
        #[arg(long, default_value = "127.0.0.1:8600")]
        listen: SocketAddr,
        /// Bearer token wallets must send. Required off loopback unless --allow-open.
        #[arg(long, env = "RAND_PROVER_TOKEN")]
        token: Option<String>,
        /// Prove on an attached NVIDIA GPU (needs a build with --features cuda).
        #[arg(long)]
        cuda: bool,
        /// Concurrent proofs; one per GPU.
        #[arg(long, default_value_t = 1)]
        slots: usize,
        /// Jobs waiting beyond the ones proving.
        #[arg(long, default_value_t = 8)]
        max_queue: usize,
        /// Jobs one client address may have in flight.
        #[arg(long, default_value_t = 2)]
        per_ip: usize,
        /// Seconds a finished result is kept for the wallet to fetch.
        #[arg(long, default_value_t = 600)]
        result_ttl_secs: u64,
        /// Listen off loopback with no token. Every job is then free compute for anyone.
        #[arg(long)]
        allow_open: bool,
    },
    /// Print the address wallets pin (`--prover-address`).
    Address,
    /// Create a new key file (refuses to overwrite).
    Keygen,
}

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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => {
            let w = Wallet::generate();
            w.save_new(&cli.key)?;
            println!("wrote {}\naddress: {}", cli.key.display(), w.address);
        }
        Cmd::Address => println!("{}", Wallet::load(&cli.key)?.address),
        Cmd::Run { listen, token, cuda, slots, max_queue, per_ip, result_ttl_secs, allow_open } => {
            if slots == 0 {
                anyhow::bail!("--slots must be at least 1: a prover with no slots accepts jobs and never proves any of them");
            }
            let w = Wallet::load(&cli.key)?;
            let key = ProverKey::from_viewing_key(&w.vk);
            let cfg = Config { key, backend: backend_for(cuda)?, slots, max_queue, token, per_ip, result_ttl: Duration::from_secs(result_ttl_secs), allow_open, seed_secs: (100.0, 30.0) };
            eprintln!("rand-prover: every job holds the sending wallet's spend key; run this only for wallets that trust you with custody");
            let (bound, task) = serve(listen, cfg).await?;
            eprintln!("listening on {bound}; address {}", w.address);
            task.await?;
        }
    }
    Ok(())
}
