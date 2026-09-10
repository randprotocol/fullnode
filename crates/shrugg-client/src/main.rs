//! `shrugg`: command-line wallet talking to a SHRUGG full node over JSON-RPC.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use shrugg_client::RpcClient;
use shrugg_core::{format_amount, parse_amount, Address, Hash, Keypair};
use shrugg_zkvm::{codec, executor, guests, isa::Program, machine::FriProfile};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "shrugg", version, about = "SHRUGG wallet: query balances and send SHRUGG through a full node's RPC")]
struct Cli {
    /// Full node JSON-RPC endpoint.
    #[arg(long, global = true, env = "SHRUGG_RPC", default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Key file used for signing (send) and as the default address (balance).
    #[arg(long, global = true, env = "SHRUGG_KEY", default_value = "wallet.key.json")]
    key: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new wallet key file (refuses to overwrite).
    Keygen,
    /// Show this wallet's address.
    Address,
    /// Show balance and nonce of an address (default: this wallet).
    Balance { address: Option<String> },
    /// Send SHRUGG to an address and wait for it to be committed.
    Send {
        to: String,
        /// Amount in SHRUGG, e.g. 1.5
        amount: String,
        #[arg(long, default_value = "0.000001")]
        fee: String,
        /// Return immediately after submission instead of waiting for commit.
        #[arg(long)]
        no_wait: bool,
    },
    /// Testnet faucet: mint SHRUGG to an address (default: this wallet, 100 SHRUGG).
    Faucet {
        address: Option<String>,
        /// Amount in SHRUGG (max 100).
        #[arg(long, default_value = "100")]
        amount: String,
    },
    /// Submit a guardian-signed attestation, minting the bridged asset it carries.
    ///
    /// The attestation is hex, or `@path` to read it from a file (hex or raw bytes).
    BridgeMint {
        /// Attestation hex, or `@file`.
        attestation: String,
        /// SHRUGG transaction fee.
        #[arg(long, default_value = "0.000001")]
        fee: String,
    },
    /// Burn a bridged asset and emit the message a source-chain contract releases against.
    BridgeBurn {
        /// Asset id (64 hex); `shrugg bridge-status` lists the registered ones.
        asset: String,
        /// Amount in bridged units (8 decimals), as a plain integer.
        amount: String,
        /// Destination chain: 2 Ethereum, 3 BSC, 4 Tron, 5 Solana.
        to_chain: u16,
        /// Recipient on that chain, 32 bytes of hex (EVM addresses left-padded).
        to: String,
        /// Relayer fee carried in the message, in bridged units (at most `amount`).
        #[arg(long, default_value = "0")]
        bridge_fee: String,
        /// SHRUGG transaction fee.
        #[arg(long, default_value = "0.000001")]
        fee: String,
    },
    /// Bridged-asset balance: `asset-balance <asset>` or `asset-balance <address> <asset>`.
    AssetBalance {
        /// An asset id, or an address when a second argument follows.
        first: String,
        /// The asset id, when the first argument is an address.
        second: Option<String>,
    },
    /// Bridge configuration, guardian set, and registered assets.
    BridgeStatus,
    /// Confidential programs: build, deploy, show.
    #[command(subcommand)]
    Program(ProgramCmd),
    /// Run a confidential call: prove locally, submit, wait for the receipt.
    Call {
        /// Program id (hex).
        program: String,
        /// Private inputs (u32), in order; never leave this machine.
        #[arg(long = "input")]
        inputs: Vec<u32>,
        /// Public recipient list the program may pay (index 0, 1, ...).
        #[arg(long = "to")]
        recipients: Vec<String>,
        /// Force a gas tier (10, 12, ..., 20); default: smallest that fits.
        #[arg(long)]
        tier: Option<u8>,
        /// Fee in SHRUGG; default: the schedule minimum for the tier.
        #[arg(long)]
        fee: Option<String>,
    },
    /// Show the receipt of a confidential call.
    Receipt { tx: String },
    /// Minimum fee: `fee deploy <words>` or `fee call <tier>`.
    Fee { kind: String, n: u64 },
    /// Look up a transaction by hash.
    Tx { hash: String },
    /// Show a block by height or hash.
    Block { id: String },
    /// Current head of the chain.
    Head,
    /// Node status.
    Status,
    /// Connected peers.
    Peers,
    /// Validator set.
    Validators,
}

#[derive(Subcommand)]
enum ProgramCmd {
    /// Assemble a built-in guest program to a JSON file.
    Build {
        /// fib | memcpy | bubble_sort | balance_check | private_payment
        #[arg(long)]
        guest: String,
        /// Guest argument(s): fib n, memcpy n, bubble_sort v..., balance_check threshold, private_payment threshold
        #[arg(long = "arg")]
        args: Vec<u32>,
        #[arg(long, default_value = "program.json")]
        out: PathBuf,
    },
    /// Deploy a program from a .json ({base_pc, words}) or .bin (raw LE words) file.
    Deploy { file: PathBuf },
    /// Show a deployed program.
    Show { id: String },
}

fn build_guest(name: &str, args: &[u32]) -> Result<Program> {
    let need = |n: usize| -> Result<()> { if args.len() < n { anyhow::bail!("{name} needs {n} --arg value(s)") } else { Ok(()) } };
    Ok(match name {
        "fib" => { need(1)?; guests::fib(args[0]) }
        "memcpy" => { need(1)?; guests::memcpy(args[0]) }
        "bubble_sort" => { need(1)?; guests::bubble_sort(args) }
        "balance_check" => { need(1)?; guests::balance_check(args[0]) }
        "private_payment" => { need(1)?; guests::private_payment(args[0]) }
        other => anyhow::bail!("unknown guest {other}"),
    })
}

fn load_program(file: &Path) -> Result<Program> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    if file.extension().and_then(|e| e.to_str()) == Some("json") {
        codec::program_from_json(std::str::from_utf8(&bytes)?).map_err(|e| anyhow::anyhow!(e))
    } else {
        codec::program_from_bytes(&bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    seed: String,
    address: String,
    public_key: String,
}

fn load_key(path: &Path) -> Result<Keypair> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading key file {}", path.display()))?;
    let kf: KeyFile = serde_json::from_str(&s)?;
    let seed: [u8; 32] = hex::decode(&kf.seed)?.try_into().map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;
    Ok(Keypair::from_seed(seed)?)
}

fn write_key(path: &Path, kp: &Keypair) -> Result<()> {
    if path.exists() {
        anyhow::bail!("{} already exists; refusing to overwrite", path.display());
    }
    let kf = KeyFile { seed: hex::encode(kp.seed()), address: kp.address().to_base58(), public_key: kp.public_key().to_hex() };
    std::fs::write(path, serde_json::to_string_pretty(&kf)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// An attestation given as hex, or as `@path` to a file holding either hex
/// (with optional whitespace) or the raw bytes.
fn read_attestation(arg: &str) -> Result<Vec<u8>> {
    let text = match arg.strip_prefix('@') {
        None => arg.to_string(),
        Some(path) => {
            let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
            match std::str::from_utf8(&bytes) {
                Ok(s) if s.trim().chars().all(|c| c.is_ascii_hexdigit()) => s.to_string(),
                // Not hex: take the file as the raw attestation.
                _ => return Ok(bytes),
            }
        }
    };
    let text = text.trim();
    let text = text.strip_prefix("0x").unwrap_or(text);
    hex::decode(text).context("attestation must be hex, or @file")
}

/// Print every bridged asset an address holds, one per line.
async fn print_holdings(rpc: &RpcClient, addr: &Address) -> Result<()> {
    let holdings = rpc.assets(addr).await?;
    if holdings.is_empty() {
        println!("{addr} holds no bridged assets");
        return Ok(());
    }
    println!("{addr} bridged holdings (units, 8 decimals):");
    for h in holdings {
        println!("  {} chain {} token {}  {}", h.asset, h.token_chain, hex::encode(h.token_address), h.balance);
    }
    Ok(())
}

fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = RpcClient::new(cli.rpc.clone());
    match cli.cmd {
        Cmd::Keygen => {
            let kp = Keypair::generate();
            write_key(&cli.key, &kp)?;
            println!("wrote {}\naddress: {}", cli.key.display(), kp.address());
        }
        Cmd::Address => println!("{}", load_key(&cli.key)?.address()),
        Cmd::Balance { address } => {
            let addr = match address {
                Some(a) => Address::from_base58(&a).context("invalid address")?,
                None => load_key(&cli.key)?.address(),
            };
            let acct = rpc.account(&addr).await?;
            println!("{addr}\nbalance: {} SHRUGG\nnonce:   {}", format_amount(acct.balance), acct.nonce);
        }
        Cmd::Send { to, amount, fee, no_wait } => {
            let kp = load_key(&cli.key)?;
            let to = Address::from_base58(&to).context("invalid destination address")?;
            let amount = parse_amount(&amount)?;
            let fee = parse_amount(&fee)?;
            let hash = rpc.transfer(&kp, to, amount, fee).await?;
            println!("submitted {hash}\n  {} SHRUGG from {} to {to}, fee {} SHRUGG", format_amount(amount), kp.address(), format_amount(fee));
            if !no_wait {
                let r = rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await?;
                let acct = rpc.account(&kp.address()).await?;
                println!("committed in block {} (index {})\nnew balance: {} SHRUGG", r.height, r.index, format_amount(acct.balance));
            }
        }
        Cmd::Faucet { address, amount } => {
            let to = match address {
                Some(a) => Address::from_base58(&a).context("invalid address")?,
                None => load_key(&cli.key)?.address(),
            };
            let units = parse_amount(&amount)?;
            let hash = rpc.mint(&to, Some(units)).await?;
            println!("submitted mint {hash} ({} SHRUGG to {to})", format_amount(units));
            let r = rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await?;
            let acct = rpc.account(&to).await?;
            println!("committed in block {}\nbalance: {} SHRUGG", r.height, format_amount(acct.balance));
        }
        Cmd::BridgeMint { attestation, fee } => {
            let kp = load_key(&cli.key)?;
            let bytes = read_attestation(&attestation)?;
            let fee = parse_amount(&fee)?;
            let hash = rpc.bridge_attest(&kp, bytes, fee).await?;
            println!("submitted attestation {hash} (fee {} SHRUGG)", format_amount(fee));
            let r = rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await?;
            println!("committed in block {} (index {})", r.height, r.index);
            print_holdings(&rpc, &kp.address()).await?;
        }
        Cmd::BridgeBurn { asset, amount, to_chain, to, bridge_fee, fee } => {
            let kp = load_key(&cli.key)?;
            let asset = Hash::from_hex(&asset).context("invalid asset id")?;
            let amount: u128 = amount.parse().context("amount must be an integer of bridged units")?;
            let bridge_fee: u128 = bridge_fee.parse().context("bridge fee must be an integer of bridged units")?;
            let to = shrugg_client::hex32(&to).context("invalid destination")?;
            let fee = parse_amount(&fee)?;
            let hash = rpc.bridge_burn(&kp, asset, amount, to_chain, to, bridge_fee, fee).await?;
            println!("submitted burn {hash}\n  {amount} units of {asset} to chain {to_chain}, relayer fee {bridge_fee} units");
            let r = rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await?;
            println!("committed in block {} (index {})", r.height, r.index);
            let sequence = rpc.bridge_state().await?["burn_sequence"].as_u64().unwrap_or(0).saturating_sub(1);
            match rpc.bridge_burn_record(sequence).await? {
                Some(v) => println!("outbound message (sequence {sequence}):\n{}", pretty(&v)),
                None => println!("outbound message not readable yet; try `shrugg bridge-status`"),
            }
        }
        Cmd::AssetBalance { first, second } => {
            let (addr, asset) = match second {
                Some(asset) => (Address::from_base58(&first).context("invalid address")?, asset),
                None => (load_key(&cli.key)?.address(), first),
            };
            let asset = Hash::from_hex(&asset).context("invalid asset id")?;
            println!("{}", rpc.asset_balance(&addr, &asset).await?);
        }
        Cmd::BridgeStatus => {
            let v = rpc.bridge_state().await?;
            if v["enabled"].as_bool() != Some(true) {
                println!("this chain has no bridge");
            } else {
                println!("{}", pretty(&v));
            }
        }
        Cmd::Program(ProgramCmd::Build { guest, args, out }) => {
            let p = build_guest(&guest, &args)?;
            std::fs::write(&out, codec::program_to_json(&p))?;
            println!("wrote {} ({} words, program id {})", out.display(), p.words.len(), shrugg_core::program::program_id(p.base_pc, &p.words));
        }
        Cmd::Program(ProgramCmd::Deploy { file }) => {
            let kp = load_key(&cli.key)?;
            let p = load_program(&file)?;
            let (id, tx) = rpc.deploy(&kp, p.base_pc, p.words.clone()).await?;
            println!("submitted deploy {tx}\nprogram id: {id} ({} words, fee {} SHRUGG)", p.words.len(), format_amount(shrugg_core::gas::deploy_fee(p.words.len())));
            let r = rpc.wait_for_transaction(&tx, Duration::from_secs(90)).await?;
            println!("committed in block {}", r.height);
        }
        Cmd::Program(ProgramCmd::Show { id }) => {
            let id = Hash::from_hex(&id).context("invalid program id")?;
            match rpc.program(&id).await? {
                Some(v) => println!("{}", pretty(&v)),
                None => println!("unknown program"),
            }
        }
        Cmd::Call { program, inputs, recipients, tier, fee } => {
            let kp = load_key(&cli.key)?;
            let pid = Hash::from_hex(&program).context("invalid program id")?;
            let (base_pc, words) = rpc.program_code(&pid).await?.context("program not found on chain")?;
            let prog = Program { base_pc, words };
            let status = rpc.status().await?;
            let profile_name = status["fri_profile"].as_str().unwrap_or("production");
            let profile = executor::ZkExecutor::profile_from_str(profile_name).context("node reports an unknown fri profile")?;
            if profile == FriProfile::Test {
                eprintln!("warning: chain uses the insecure test FRI profile");
            }
            let recips: Vec<Address> = recipients.iter().map(|r| Address::from_base58(r).context("invalid recipient")).collect::<Result<_>>()?;
            eprintln!("proving locally ({} inputs stay private)...", inputs.len());
            let t = std::time::Instant::now();
            let (proof, outputs, tier) = executor::prove(profile, &prog, &inputs, tier).map_err(|e| anyhow::anyhow!(e))?;
            eprintln!("proved in {:.1?}: tier {tier}, {} bytes, outputs {:?}", t.elapsed(), proof.len(), outputs);
            let fee_units = match fee { Some(f) => parse_amount(&f)?, None => shrugg_core::gas::call_fee(tier) };
            let tx = rpc.call_program(&kp, pid, proof, recips, fee_units).await?;
            println!("submitted call {tx} (fee {} SHRUGG)", format_amount(fee_units));
            let receipt = rpc.wait_for_receipt(&tx, Duration::from_secs(120)).await?;
            println!("{}", pretty(&receipt));
        }
        Cmd::Receipt { tx } => {
            let h = Hash::from_hex(&tx).context("invalid hash")?;
            match rpc.receipt(&h).await? {
                Some(v) => println!("{}", pretty(&v)),
                None => println!("no receipt (not a call, or not yet committed)"),
            }
        }
        Cmd::Fee { kind, n } => println!("{} SHRUGG", format_amount(rpc.estimate_fee(&kind, n).await?)),
        Cmd::Tx { hash } => {
            let h = Hash::from_hex(&hash).context("invalid hash")?;
            let v = rpc.call("shrugg_getTransaction", serde_json::json!([h.to_hex()])).await?;
            if v.is_null() {
                println!("not found (not yet committed, or unknown)");
            } else {
                println!("{}", pretty(&v));
            }
        }
        Cmd::Block { id } => {
            let v = match id.parse::<u64>() {
                Ok(h) => rpc.block_by_height(h).await?,
                Err(_) => rpc.block_by_hash(&Hash::from_hex(&id).context("block id must be a height or a hash")?).await?,
            };
            println!("{}", pretty(&v));
        }
        Cmd::Head => println!("{}", pretty(&rpc.head().await?)),
        Cmd::Status => println!("{}", pretty(&rpc.status().await?)),
        Cmd::Peers => println!("{}", pretty(&rpc.peers().await?)),
        Cmd::Validators => println!("{}", pretty(&rpc.validators().await?)),
    }
    Ok(())
}
