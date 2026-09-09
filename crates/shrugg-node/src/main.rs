use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use libp2p::Multiaddr;
use shrugg_core::genesis::{Genesis, GenesisValidator};
use shrugg_core::{Address, Keypair, PublicKey, Transaction, UNITS_PER_SHRUGG};
use shrugg_node::keyfile::{load_keypair, KeyFile};
use shrugg_node::node::{self, NodeConfig};
use shrugg_client::RpcClient;
use shrugg_core::{format_amount, parse_amount};
use shrugg_node::storage::{Storage, VerifyMode};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "shrugg-node", version, about = "SHRUGG full node: HotStuff BFT consensus, p2p discovery, account ledger")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new Dilithium2 key file.
    Keygen {
        #[arg(long, default_value = "node.key.json")]
        out: PathBuf,
    },
    /// Print the address, public key, and libp2p peer id of a key file.
    Address {
        #[arg(long)]
        key: PathBuf,
    },
    /// Write a genesis.json: every validator key is staked and allocated SHRUGG.
    Genesis {
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
        /// Validator key files (seed) or hex public keys, repeatable.
        #[arg(long = "validator", required = true)]
        validators: Vec<String>,
        #[arg(long, default_value_t = 100_000)]
        stake: u128,
        /// Initial balance in SHRUGG for each validator address.
        #[arg(long, default_value = "1000000")]
        alloc_each: String,
        /// Extra allocations `address=amountSHRUGG`, repeatable.
        #[arg(long = "alloc")]
        allocs: Vec<String>,
        #[arg(long, default_value = "genesis.json")]
        out: PathBuf,
        /// Testnet only: enable the faucet (`shrugg_mint`, up to 100 SHRUGG per call).
        #[arg(long)]
        faucet: bool,
        /// Disable confidential computation (Deploy/Call transactions) on this chain.
        #[arg(long)]
        no_confidential: bool,
        /// zkVM FRI profile: production (default) or test (fast, insecure; tests only).
        #[arg(long, default_value = "production")]
        fri_profile: String,
    },
    /// Initialise a data directory from a genesis file.
    Init {
        #[arg(long)]
        datadir: PathBuf,
        #[arg(long)]
        genesis: PathBuf,
    },
    /// Run the node.
    Run {
        #[arg(long)]
        datadir: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "/ip4/0.0.0.0/tcp/30303")]
        listen: Vec<Multiaddr>,
        /// Bootstrap peer multiaddr (with /p2p/<peer-id>), repeatable.
        #[arg(long)]
        bootstrap: Vec<Multiaddr>,
        #[arg(long, default_value = "127.0.0.1:8545")]
        rpc: SocketAddr,
        /// Participate in consensus (key must be in the genesis validator set).
        #[arg(long)]
        validator: bool,
        /// Disable LAN discovery via mDNS.
        #[arg(long)]
        no_mdns: bool,
        #[arg(long, default_value_t = 1000)]
        block_interval_ms: u64,
        #[arg(long, default_value_t = 3000)]
        view_timeout_ms: u64,
        /// Startup chain integrity check: off, quick (structure + ledger replay), full (also signatures).
        #[arg(long, default_value = "quick")]
        verify_chain: String,
    },
    /// Verify the chain in a data directory without running the node.
    Verify {
        #[arg(long)]
        datadir: PathBuf,
        #[arg(long, default_value = "full")]
        mode: String,
        /// Truncate the damaged tail (safety state is kept). Without this, only report.
        #[arg(long)]
        repair: bool,
    },
    /// Query an account balance.
    Balance {
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        address: String,
    },
    /// Sign and submit a transfer.
    Transfer {
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        to: String,
        /// Amount in SHRUGG, e.g. 1.5
        #[arg(long)]
        amount: String,
        #[arg(long, default_value = "0.000001")]
        fee: String,
    },
    /// Show node status.
    Status {
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,libp2p=warn,libp2p_mdns=off".into()))
        .init();
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            let kp = Keypair::generate();
            KeyFile::from_keypair(&kp).write(&out)?;
            println!("wrote {}\naddress: {}", out.display(), kp.address());
        }
        Cmd::Address { key } => {
            let kp = load_keypair(&key)?;
            let id = libp2p::identity::Keypair::ed25519_from_bytes(kp.derive_subkey(b"shrugg-p2p-identity"))?;
            println!("address: {}\npublic_key: {}\npeer_id: {}", kp.address(), kp.public_key().to_hex(), id.public().to_peer_id());
        }
        Cmd::Genesis { chain_id, validators, stake, alloc_each, allocs, out, faucet, no_confidential, fri_profile } => {
            let mut gen = Genesis {
                chain_id,
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis() as u64,
                validators: Vec::new(),
                alloc: Default::default(),
                faucet,
                confidential: !no_confidential,
                fri_profile,
            };
            let each = parse_amount(&alloc_each)?;
            for v in validators {
                let pk = if PathBuf::from(&v).exists() {
                    load_keypair(&PathBuf::from(&v))?.public_key().clone()
                } else {
                    PublicKey::from_hex(&v).with_context(|| format!("{v} is neither a key file nor a hex public key"))?
                };
                *gen.alloc.entry(pk.address().to_base58()).or_default() += each;
                gen.validators.push(GenesisValidator { public_key: pk, stake });
            }
            for a in allocs {
                let (addr, amt) = a.split_once('=').context("--alloc must be address=amount")?;
                Address::from_base58(addr)?;
                *gen.alloc.entry(addr.to_string()).or_default() += parse_amount(amt)?;
            }
            let state = gen.build()?;
            std::fs::write(&out, gen.to_json())?;
            println!(
                "wrote {} (genesis hash {}, faucet {}, confidential {}, fri {})",
                out.display(), state.hash(), if faucet { "on" } else { "off" }, if no_confidential { "off" } else { "on" }, state.fri_profile
            );
        }
        Cmd::Init { datadir, genesis } => {
            std::fs::create_dir_all(&datadir)?;
            let text = std::fs::read_to_string(&genesis)?;
            let gs = Genesis::from_json(&text)?.build()?;
            std::fs::write(datadir.join("genesis.json"), &text)?;
            let storage = Storage::open(&datadir)?;
            storage.init_genesis(&gs)?;
            println!("initialised {} at genesis {} (chain id {})", datadir.display(), gs.hash(), gs.chain_id);
        }
        Cmd::Verify { datadir, mode, repair } => {
            let mode: VerifyMode = mode.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let gs = node::load_genesis(&datadir)?;
            let storage = Storage::open(&datadir)?;
            let executor = node::executor_for(&gs)?;
            let check = storage.verify_chain(&gs, mode, executor.as_ref())?;
            match &check.problem {
                None => println!("ok: {} blocks verified ({mode:?})", check.head + 1),
                Some(p) => {
                    println!("CORRUPT: {p}\nhead {} last good {} genesis_ok {}", check.head, check.last_good, check.genesis_ok);
                    if repair {
                        node::check_and_repair_chain(&storage, &gs, mode, executor.as_ref())?;
                        println!("repaired: head is now {}", storage.head()?.height);
                    } else {
                        std::process::exit(2);
                    }
                }
            }
        }
        Cmd::Run { datadir, key, listen, bootstrap, rpc, validator, no_mdns, block_interval_ms, view_timeout_ms, verify_chain } => {
            let kp = load_keypair(&key)?;
            let handle = node::start(NodeConfig {
                datadir,
                seed: *kp.seed(),
                listen,
                bootstrap,
                rpc_addr: rpc,
                enable_mdns: !no_mdns,
                validator,
                block_interval: Duration::from_millis(block_interval_ms),
                base_timeout: Duration::from_millis(view_timeout_ms),
                max_timeout: Duration::from_millis(view_timeout_ms * 8),
                verify: verify_chain.parse().map_err(|e: String| anyhow::anyhow!(e))?,
            })
            .await?;
            let mut handle = handle;
            tokio::select! {
                r = &mut handle.task => { r??; }
                _ = tokio::signal::ctrl_c() => { tracing::info!("shutting down"); handle.shutdown().await; }
            }
        }
        Cmd::Balance { rpc, address } => {
            let addr = Address::from_base58(&address)?;
            let acct = RpcClient::new(rpc).account(&addr).await?;
            println!("{} SHRUGG (nonce {})", format_amount(acct.balance), acct.nonce);
        }
        Cmd::Transfer { rpc, key, to, amount, fee } => {
            let kp = load_keypair(&key)?;
            let to = Address::from_base58(&to)?;
            let client = RpcClient::new(rpc);
            let chain_id = client.chain_id().await?;
            let acct = client.account(&kp.address()).await?;
            let (nonce, balance) = (acct.nonce, acct.balance);
            let amount = parse_amount(&amount)?;
            let fee = parse_amount(&fee)?;
            if balance < amount + fee {
                anyhow::bail!("insufficient balance: have {} SHRUGG", format_amount(balance));
            }
            let tx = Transaction::transfer(&kp, chain_id, nonce, to, amount, fee);
            let hash = client.send_transaction(&tx).await?;
            println!("submitted {hash} ({} SHRUGG to {to}, nonce {nonce})", format_amount(amount));
        }
        Cmd::Status { rpc } => {
            let v = RpcClient::new(rpc).status().await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
    }
    let _ = UNITS_PER_SHRUGG;
    Ok(())
}
