//! `shrugg`: the shielded command-line wallet, talking to a SHRUGG full node over JSON-RPC.
//!
//! Phase S1 redacted the chain: there are no accounts and no balances to ask a node about, so
//! every command that used to be a question for the node ("what is this address worth?") is now
//! a question for this machine. The wallet keeps a spend key (`--key`) and a note store next to
//! it (`<key>.notes.json`), scans the commitment tree for notes only that key can open, and
//! spends them by proving a 2-in-2-out bundle locally. The node is asked for chain state —
//! leaves, nullifiers, anchors, witnesses — and handed a finished bundle; it is never told who
//! anyone is.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use shrugg_client::wallet::{self, NoteStore, Wallet};
use shrugg_client::RpcClient;
use shrugg_client::wallet::Submission;
use shrugg_core::ledger::staking::MIN_STAKE;
use shrugg_core::notes::ShieldedAddress;
use shrugg_core::types::actions::Registration;
use shrugg_core::{format_amount, gas, parse_amount, Action, Address, Hash};
use shrugg_zkvm::machine::{Backend, FriProfile};
use shrugg_zkvm::{codec, executor, guests, isa::Program};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "shrugg", version, about = "SHRUGG shielded wallet: scan, send and prove through a full node's RPC")]
struct Cli {
    /// Full node JSON-RPC endpoint.
    #[arg(long, global = true, env = "SHRUGG_RPC", default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Spend-key file. The note store lives next to it, at `<key>.notes.json`.
    #[arg(long, global = true, env = "SHRUGG_KEY", default_value = "wallet.key.json")]
    key: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new spend-key file (refuses to overwrite).
    Keygen,
    /// Show this wallet's shielded address.
    Address,
    /// Scan, then show what this wallet can spend.
    Balance,
    /// Scan the chain for notes and spends without printing a balance.
    Sync,
    /// List every note this wallet has ever been able to open.
    Notes,
    /// List every note this wallet created for someone else.
    History,
    /// Send SHRUGG to a shielded address: scan, select, prove and submit.
    Send {
        /// A `shrugg1…` shielded address.
        to: String,
        /// Amount in SHRUGG, e.g. 1.5
        amount: String,
        /// Fee in SHRUGG; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the bundle instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
        #[arg(long)]
        cuda: bool,
    },
    /// Stake SHRUGG onto a validator: the bundle burns the stake out of this wallet's notes.
    ///
    /// A validator the register does not know yet needs `--registration`, the hex blob its
    /// operator gets from `shrugg-node register --payout <shrugg1…>`; one it already knows must
    /// not carry one. Bonded weight counts from the next epoch, and unbonding it is the
    /// validator's own command (`shrugg-node unbond`), not this wallet's.
    Bond {
        /// The validator's address (base58), as `shrugg validators` lists it.
        validator: String,
        /// Amount in SHRUGG. Registering a new validator needs at least the staking minimum.
        amount: String,
        /// The hex `Registration` from `shrugg-node register`, for a validator not yet in the
        /// register.
        #[arg(long)]
        registration: Option<String>,
        /// Fee in SHRUGG; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the bundle instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
        #[arg(long)]
        cuda: bool,
    },
    /// Testnet faucet: ask a validator to mint SHRUGG into a note (default: this wallet).
    Faucet {
        /// A `shrugg1…` shielded address; defaults to this wallet's.
        address: Option<String>,
        /// Amount in SHRUGG (max 100).
        #[arg(long, default_value = "100")]
        amount: String,
    },
    /// Confidential programs: build, deploy, show.
    #[command(subcommand)]
    Program(ProgramCmd),
    /// Run a confidential call: prove locally, pay from a bundle, wait for the receipt.
    Call {
        /// Program id (hex).
        program: String,
        /// Private inputs (u32), in order; never leave this machine.
        #[arg(long = "input")]
        inputs: Vec<u32>,
        /// Force a gas tier (10, 12, ..., 20); default: smallest that fits.
        #[arg(long)]
        tier: Option<u8>,
        /// Fee in SHRUGG; default: the schedule minimum for the tier.
        #[arg(long)]
        fee: Option<String>,
        /// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
        #[arg(long)]
        cuda: bool,
    },
    /// Show the receipt of a confidential call.
    Receipt { tx: String },
    /// Minimum fee: `fee bundle`, `fee deploy <words>` or `fee call <tier>`.
    Fee {
        /// bundle | deploy | call
        kind: String,
        /// Program words for `deploy`, the tier for `call`.
        n: Option<u64>,
    },
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
    Deploy {
        file: PathBuf,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
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

fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

fn parse_address(s: &str) -> Result<ShieldedAddress> {
    ShieldedAddress::parse(s).map_err(|e| anyhow::anyhow!("{e}")).context("invalid shielded address")
}

/// The wallet, where its note store lives, and the store itself.
fn open_wallet(key: &Path) -> Result<(Wallet, PathBuf, NoteStore)> {
    let w = Wallet::load(key)?;
    let path = wallet::store_path(key);
    let store = NoteStore::load(&path);
    Ok((w, path, store))
}

/// The FRI profile the chain runs; a test-profile chain is announced, because a proof under it
/// is not a security claim.
async fn profile_of(rpc: &RpcClient) -> Result<FriProfile> {
    let status = rpc.status().await?;
    let name = status["fri_profile"].as_str().unwrap_or("production");
    let profile = executor::ZkExecutor::profile_from_str(name).context("node reports an unknown fri profile")?;
    if profile == FriProfile::Test {
        eprintln!("warning: chain uses the insecure test FRI profile");
    }
    Ok(profile)
}

/// No fallback: `--cuda` on a build or a machine that cannot run it is an error, so a proof is
/// never quietly produced somewhere other than where it was asked for.
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
        anyhow::bail!("built without CUDA support; rebuild shrugg with --features cuda")
    }
}

fn report(s: &Submission, what: &str) {
    // A burn is the bond's stake leaving the pool; every other action leaves it zero, and saying
    // "0 SHRUGG burned" on a transfer would only invite the question.
    let burned = if s.burn > 0 { format!("{} SHRUGG burned, ", format_amount(s.burn)) } else { String::new() };
    println!(
        "submitted {what} {}\n  {} SHRUGG out, {burned}{} SHRUGG change, fee {} SHRUGG, anchored at height {}",
        s.hash,
        format_amount(s.amount),
        format_amount(s.change),
        format_amount(s.fee),
        s.time,
    );
}

/// Decode a `Registration` as `shrugg-node register` prints it: its bincode form as hex.
fn parse_registration(text: &str) -> Result<Registration> {
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text)).context("--registration must be hex")?;
    Registration::decode(&bytes).context("--registration is not a registration from `shrugg-node register`")
}

/// A validator's bonded stake as the register reports it, or `None` when it holds no entry for
/// that address. Amounts come out as decimal strings: a stake in units outgrows a JSON number.
async fn register_stake(rpc: &RpcClient, address: &str) -> Result<Option<u64>> {
    let rows = rpc.validators().await?;
    let Some(row) = rows.as_array().and_then(|rows| rows.iter().find(|r| r["address"].as_str() == Some(address))) else {
        return Ok(None);
    };
    let stake = row["stake"].as_str().context("getValidators reply has no stake")?;
    Ok(Some(stake.parse().context("the register's stake is not a number")?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = RpcClient::new(cli.rpc.clone());
    match cli.cmd {
        Cmd::Keygen => {
            let w = Wallet::generate();
            w.save_new(&cli.key)?;
            println!("wrote {}\naddress: {}", cli.key.display(), w.address);
        }
        Cmd::Address => println!("{}", Wallet::load(&cli.key)?.address),
        Cmd::Balance => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            wallet::scan(&rpc, &w, &mut store).await?;
            store.save(&path)?;
            println!("balance: {} SHRUGG\nnotes: {} unspent", format_amount(store.balance()), store.spendable().len());
        }
        Cmd::Sync => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            wallet::scan(&rpc, &w, &mut store).await?;
            store.save(&path)?;
            println!("scanned {} leaves and {} blocks; {} notes, {} unspent", store.scanned_index, store.scanned_height, store.notes.len(), store.spendable().len());
        }
        Cmd::Notes => {
            let (_, _, store) = open_wallet(&cli.key)?;
            if store.notes.is_empty() {
                println!("no notes (run `shrugg sync`)");
            } else {
                // `pending` is a note this wallet has submitted a spend for without waiting for
                // the commit: not spent, not spendable, and the next `sync` decides which.
                println!("{:>8}  {:>18}  {:>8}  {:>7}  {}", "index", "amount", "height", "spent", "pending");
                for n in &store.notes {
                    let pending = match n.pending {
                        Some(time) => format!("since {time}"),
                        None => "-".into(),
                    };
                    println!(
                        "{:>8}  {:>18}  {:>8}  {:>7}  {}",
                        n.index,
                        format_amount(n.note.amount),
                        n.height,
                        n.spent,
                        pending
                    );
                }
            }
        }
        Cmd::History => {
            let (_, _, store) = open_wallet(&cli.key)?;
            if store.sent.is_empty() {
                println!("no notes sent from this wallet");
            } else {
                println!("{:>8}  {:>18}  {:>8}  {}", "index", "amount", "height", "to (pk)");
                for s in &store.sent {
                    println!("{:>8}  {:>18}  {:>8}  {}", s.index, format_amount(s.amount), s.height, shrugg_core::notes::word8_to_hex(&s.to_pk));
                }
            }
        }
        Cmd::Send { to, amount, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let to = parse_address(&to)?;
            let amount = parse_amount(&amount)?;
            let fee = match fee { Some(f) => parse_amount(&f)?, None => gas::BUNDLE_BASE };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::send(&rpc, &w, &mut store, &to, amount, fee, profile, backend_for(cuda)?, chain_id, !no_wait).await;
            store.save(&path)?;
            report(&s?, "transfer");
            if !no_wait {
                println!("balance: {} SHRUGG", format_amount(store.balance()));
            }
        }
        Cmd::Bond { validator, amount, registration, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let validator = Address::from_base58(&validator)
                .with_context(|| format!("{validator} is not a validator address"))?;
            let address = validator.to_base58();
            let amount = parse_amount(&amount)?;
            anyhow::ensure!(amount > 0, "a bond of 0 SHRUGG moves no stake and still pays a fee and a proof");
            let registration = registration.as_deref().map(parse_registration).transpose()?;
            // The register decides which of the two shapes a bond has (`staking::check_bond`), so
            // asking it first turns a rejected transaction into an answer before anything is
            // proved — a minute of proving, on a stake this wallet would not get back.
            let staked = register_stake(&rpc, &address).await?;
            match (staked, &registration) {
                (Some(_), Some(_)) => {
                    anyhow::bail!("{address} is already in the register; drop --registration")
                }
                (None, None) => anyhow::bail!(
                    "{address} is not in the register; its operator must send you the registration from `shrugg-node register --payout <shrugg1…>` and it goes here as --registration <hex>"
                ),
                (None, Some(r)) => {
                    anyhow::ensure!(
                        r.public_key.address() == validator,
                        "that registration is for validator {}, not {address}",
                        r.public_key.address()
                    );
                    anyhow::ensure!(
                        amount >= MIN_STAKE,
                        "registering a validator bonds at least {} SHRUGG, not {}",
                        format_amount(MIN_STAKE),
                        format_amount(amount)
                    );
                }
                (Some(_), None) => {}
            }
            let action = Action::Bond { validator, amount, registration };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            // `burn = amount`: the stake leaves the shielded pool instead of becoming a note, and
            // the ledger admits a bond only when the two are equal.
            let s = wallet::submit(&rpc, &w, &mut store, None, action, fee, amount, profile, backend_for(cuda)?, chain_id, !no_wait).await;
            store.save(&path)?;
            report(&s?, "bond");
            if !no_wait {
                // The set for the next epoch is derived from the register as it stands at this
                // epoch's last block (spec §8), so a bond that has just committed is weight from
                // the next epoch on — not in the one it landed in.
                let epoch = rpc.epoch().await?["epoch"].as_u64().context("getEpoch reply has no epoch")?;
                if let Some(stake) = register_stake(&rpc, &address).await? {
                    println!(
                        "{address}: stake {} SHRUGG, counting as consensus weight from epoch {}",
                        format_amount(stake),
                        epoch + 1
                    );
                }
                println!("balance: {} SHRUGG", format_amount(store.balance()));
            }
        }
        Cmd::Faucet { address, amount } => {
            let to = match address {
                Some(a) => parse_address(&a)?,
                None => Wallet::load(&cli.key)?.address,
            };
            let units = parse_amount(&amount)?;
            // An observer node answers "only a validator can mint"; that is the node's own
            // wording and is shown as it came, since it says exactly what to do next.
            let hash = rpc.mint_shielded(&to.to_string(), Some(units)).await?;
            println!("submitted mint {hash} ({} SHRUGG to {to})", format_amount(units));
            let r = rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await?;
            println!("committed in block {} (index {})", r.height, r.index);
        }
        Cmd::Program(ProgramCmd::Build { guest, args, out }) => {
            let p = build_guest(&guest, &args)?;
            std::fs::write(&out, codec::program_to_json(&p))?;
            println!("wrote {} ({} words, program id {})", out.display(), p.words.len(), shrugg_core::program::program_id(p.base_pc, &p.words));
        }
        Cmd::Program(ProgramCmd::Deploy { file, cuda }) => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let p = load_program(&file)?;
            let id = shrugg_core::program::program_id(p.base_pc, &p.words);
            let action = Action::Deploy { base_pc: p.base_pc, words: p.words.clone() };
            let fee = wallet::deploy_fee_default(&action);
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit(&rpc, &w, &mut store, None, action, fee, 0, profile, backend_for(cuda)?, chain_id, true).await;
            store.save(&path)?;
            report(&s?, "deploy");
            println!("program id: {id} ({} words)", p.words.len());
        }
        Cmd::Program(ProgramCmd::Show { id }) => {
            let id = Hash::from_hex(&id).context("invalid program id")?;
            match rpc.program(&id).await? {
                Some(v) => println!("{}", pretty(&v)),
                None => println!("unknown program"),
            }
        }
        Cmd::Call { program, inputs, tier, fee, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let pid = Hash::from_hex(&program).context("invalid program id")?;
            let (base_pc, words) = rpc.program_code(&pid).await?.context("program not found on chain")?;
            let prog = Program { base_pc, words };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let backend = backend_for(cuda)?;
            eprintln!("proving the call locally ({} inputs stay private)…", inputs.len());
            let t = std::time::Instant::now();
            let (proof, outputs, tier) = executor::prove(profile, &prog, &inputs, tier, backend).map_err(|e| anyhow::anyhow!(e))?;
            eprintln!("proved in {:.1?}: tier {tier}, {} bytes, outputs {outputs:?}", t.elapsed(), proof.len());
            // S3 Task 4 seals the call-input envelope here; the scaffold submits calls without one.
            let action = Action::Call { program: pid, proof, input_envelope: None };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => wallet::call_fee_default(tier),
            };
            let s = wallet::submit(&rpc, &w, &mut store, None, action, fee, 0, profile, backend, chain_id, true).await;
            store.save(&path)?;
            let s = s?;
            report(&s, "call");
            println!("{}", pretty(&rpc.wait_for_receipt(&s.hash, Duration::from_secs(120)).await?));
        }
        Cmd::Receipt { tx } => {
            let h = Hash::from_hex(&tx).context("invalid hash")?;
            match rpc.receipt(&h).await? {
                Some(v) => println!("{}", pretty(&v)),
                None => println!("no receipt (not a call, or not yet committed)"),
            }
        }
        Cmd::Fee { kind, n } => {
            let spec = match (kind.as_str(), n) {
                ("bundle", _) => serde_json::json!({ "kind": "bundle" }),
                ("deploy", Some(words)) => serde_json::json!({ "kind": "deploy", "words": words }),
                ("call", Some(tier)) => serde_json::json!({ "kind": "call", "tier": tier }),
                ("deploy", None) => anyhow::bail!("`fee deploy` needs a word count"),
                ("call", None) => anyhow::bail!("`fee call` needs a tier"),
                (other, _) => anyhow::bail!("unknown fee kind {other}; expected bundle, deploy or call"),
            };
            println!("{} SHRUGG", format_amount(rpc.estimate_fee(spec).await?));
        }
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
