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
use shrugg_zkvm::machine::{Backend, FriProfile, Tier, TIERS};
use shrugg_zkvm::{call_envelope, codec, emulator, executor, guests, hash, isa::Program};
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
    /// Scan, then show what this wallet holds in a bridged asset (or in every asset).
    ///
    /// Amounts are in the asset's own smallest unit: only SHRUGG (index 0) has this chain's nine
    /// decimals, and what a bridged token's unit means is the source chain's business.
    AssetBalance {
        /// The registry index a note's `asset` word carries; omit for every asset held.
        index: Option<u32>,
    },
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
    ///
    /// By default the call also publishes a sealed transcript of its private inputs (spec §6.1),
    /// which nobody but this wallet — and an auditor it names — can open. `--no-envelope` keeps
    /// even that from the chain, at the price of a call whose inputs nobody can ever recover.
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
        /// Also seal the transcript to this `shrugg1…` address, which can then open this one call.
        #[arg(long)]
        auditor: Option<String>,
        /// Publish no input transcript at all.
        #[arg(long)]
        no_envelope: bool,
        /// Print this call's per-call disclosure key: whoever holds it can open this call's inputs.
        #[arg(long)]
        print_call_key: bool,
        /// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
        #[arg(long)]
        cuda: bool,
    },
    /// Open a call's input transcript and check it against the receipt (spec §6.1).
    ///
    /// With no flag it opens as the caller, through this wallet's outgoing viewing key — the key
    /// that opens every call this wallet made. Then it re-runs the program on the inputs it
    /// recovered, so the receipt's outputs can be read next to the ones those inputs produce.
    OpenCall {
        /// The call's transaction hash.
        txhash: String,
        /// Open with one call's disclosure key (64 hex characters) instead.
        #[arg(long)]
        call_key: Option<String>,
        /// Open as the auditor the caller named, through this wallet's viewing key.
        #[arg(long)]
        as_auditor: bool,
    },
    /// Show the receipt of a confidential call.
    Receipt { tx: String },
    /// Mint a bridge deposit: submit a guardian-signed attestation as a note for its recipient.
    BridgeMint {
        /// The attestation as hex, or `@path` to read the hex from a file.
        attestation: String,
        /// The shielded address the depositor named; defaults to this wallet's.
        #[arg(long)]
        to: Option<String>,
        /// Fee in SHRUGG; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Burn a bridged asset to another chain: two bundles, two proofs, one transaction.
    BridgeBurn {
        /// The asset's registry index (`shrugg asset-balance`).
        asset: u32,
        /// Amount in the asset's own smallest unit.
        amount: u64,
        /// Destination chain id.
        to_chain: u16,
        /// 32-byte destination address, hex.
        to: String,
        /// A portion of AMOUNT paid to the relayer on the destination chain, in the same asset.
        #[arg(long, default_value_t = 0)]
        relayer_fee: u64,
        /// Fee in SHRUGG; the floor is 0.002 — the bundle base for each of the two bundles.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove both bundles on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// The bridge's public state: guardians, emitters, the asset registry, the burn sequence.
    Bridge,
    /// The outbound burn message with this sequence, for a guardian to sign.
    BridgeMessage { sequence: u64 },
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
    // A bridge burn's figures are its asset bundle's, in that asset's own units; everything else
    // moves SHRUGG. The fee is always SHRUGG.
    let (out, change) = if s.asset == 0 {
        (format!("{} SHRUGG", format_amount(s.amount)), format!("{} SHRUGG", format_amount(s.change)))
    } else {
        (format!("{} of asset {}", s.amount, s.asset), format!("{} of asset {}", s.change, s.asset))
    };
    // On a SHRUGG bundle a burn is a bond's stake leaving the pool; every other action leaves it
    // zero, and saying "0 SHRUGG burned" on a transfer would only invite the question. A bridge
    // burn's burn word *is* its `amount`, already printed as `out`.
    let burned = if s.asset == 0 && s.burn > 0 { format!("{} SHRUGG burned, ", format_amount(s.burn)) } else { String::new() };
    println!(
        "submitted {what} {}\n  {out} out, {burned}{change} change, fee {} SHRUGG, anchored at height {}",
        s.hash,
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

/// A command-line argument that is either hex outright or `@path` to read the hex from a file.
/// Whitespace is ignored, so a file written by `xxd` or an editor works as it is.
fn read_hex_arg(arg: &str) -> Result<Vec<u8>> {
    let text = match arg.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?,
        None => arg.to_string(),
    };
    let compact: String = text.split_whitespace().collect();
    let compact = compact.strip_prefix("0x").unwrap_or(&compact);
    hex::decode(compact).context("expected hex, or @path to a file of hex")
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
        Cmd::AssetBalance { index } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            wallet::scan(&rpc, &w, &mut store).await?;
            store.save(&path)?;
            // The registry names the token behind an index; a note whose asset it does not name is
            // still reported, under its own index, because the note is real either way. Same for a
            // chain with no bridge at all, which answers with an empty registry — or a node too old
            // to answer: the balance is this wallet's own, and the registry only adds a name to it.
            let assets = rpc.assets().await.unwrap_or_default();
            let token_of = |index: u32| match assets.iter().find(|a| a.index == index) {
                Some(a) => format!("chain {} token {}", a.chain, hex::encode(&a.token)),
                None if index == 0 => "SHRUGG".to_string(),
                None => "not in this chain's registry".to_string(),
            };
            match index {
                Some(index) => {
                    println!(
                        "asset {index}: {} units ({}), {} notes unspent",
                        store.balance_of(index),
                        token_of(index),
                        store.spendable_of(index).len()
                    );
                }
                None => {
                    let rows = store.asset_balances();
                    if rows.is_empty() {
                        println!("no notes (run `shrugg sync`)");
                    } else {
                        println!("{:>8}  {:>22}  {}", "asset", "units", "token");
                        for (index, units) in rows {
                            println!("{index:>8}  {units:>22}  {}", token_of(index));
                        }
                    }
                }
            }
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
                // `amount` is in the asset's own smallest unit, so only asset 0 is a SHRUGG figure;
                // a bridged asset's decimals belong to its source chain, not to this one.
                println!("{:>8}  {:>5}  {:>22}  {:>8}  {:>7}  {}", "index", "asset", "amount", "height", "spent", "pending");
                for n in &store.notes {
                    let pending = match n.pending {
                        Some(time) => format!("since {time}"),
                        None => "-".into(),
                    };
                    let amount = if n.note.asset == 0 {
                        format_amount(n.note.amount)
                    } else {
                        n.note.amount.to_string()
                    };
                    println!(
                        "{:>8}  {:>5}  {:>22}  {:>8}  {:>7}  {}",
                        n.index, n.note.asset, amount, n.height, n.spent, pending
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
        Cmd::Call { program, inputs, tier, fee, auditor, no_envelope, print_call_key, cuda } => {
            if no_envelope && (auditor.is_some() || print_call_key) {
                anyhow::bail!("--no-envelope publishes no transcript, so there is no auditor and no call key");
            }
            let auditor = auditor.as_deref().map(parse_address).transpose()?;
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let pid = Hash::from_hex(&program).context("invalid program id")?;
            let (base_pc, words) = rpc.program_code(&pid).await?.context("program not found on chain")?;
            let prog = Program { base_pc, words };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let backend = backend_for(cuda)?;
            eprintln!("proving the call locally ({} inputs stay private)…", inputs.len());
            let t = std::time::Instant::now();
            // Two provers, one difference: `prove_call` returns the `H_IN` salt as well, which is
            // what the transcript is sealed with. It is CPU-only — every other backend draws that
            // salt inside the prover and drops it — so a GPU proof has to go without an envelope,
            // and says so in its own words rather than being quietly downgraded here.
            let (proof, outputs, tier, envelope, call_key) = if no_envelope {
                let (proof, outputs, tier) =
                    executor::prove(profile, &prog, &inputs, tier, backend).map_err(|e| anyhow::anyhow!(e))?;
                (proof, outputs, tier, None, None)
            } else {
                let (proof, outputs, tier, salt) =
                    executor::prove_call(profile, &prog, &inputs, tier, backend).map_err(|e| anyhow::anyhow!(e))?;
                let h_in = hash::input_digest(salt, &inputs);
                let (e, key) = call_envelope::seal_call_envelope(&w.vk, auditor.as_ref(), &h_in, salt, &inputs)
                    .map_err(|e| anyhow::anyhow!(e))?;
                (proof, outputs, tier, Some(e), Some(key))
            };
            eprintln!("proved in {:.1?}: tier {tier}, {} bytes, outputs {outputs:?}", t.elapsed(), proof.len());
            let action = Action::Call { program: pid, proof, input_envelope: envelope };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => wallet::call_fee_default(tier),
            };
            let s = wallet::submit(&rpc, &w, &mut store, None, action, fee, 0, profile, backend, chain_id, true).await;
            store.save(&path)?;
            let s = s?;
            report(&s, "call");
            let receipt = rpc.wait_for_receipt(&s.hash, Duration::from_secs(120)).await?;
            println!("{}", pretty(&receipt));
            if let Some(key) = call_key {
                println!(
                    "input transcript published{}; open it with `shrugg open-call {}`",
                    match &auditor {
                        Some(a) => format!(" (also readable by the auditor {a})"),
                        None => String::new(),
                    },
                    s.hash
                );
                if print_call_key {
                    // A per-call key is exactly as secret as the inputs it opens, and this is the
                    // only moment it exists outside the envelope: it is not derived from any other
                    // key, so it cannot be recovered later.
                    println!("call key: {} — whoever holds this can read this call's inputs", hex::encode(key.0));
                }
            }
        }
        Cmd::OpenCall { txhash, call_key, as_auditor } => {
            let h = Hash::from_hex(&txhash).context("invalid hash")?;
            let receipt = rpc.receipt(&h).await?.context("no receipt for this hash (not a call, or not yet committed)")?;
            let (h_in, envelope) =
                rpc.call_envelope(&h).await?.context("this call published no input transcript")?;
            let receipt_h_in = shrugg_core::notes::word8_from_hex(receipt["h_in"].as_str().unwrap_or_default())
                .context("the receipt's h_in is not 64 hex characters")?;
            if receipt_h_in != h_in {
                anyhow::bail!("the node's receipt and envelope disagree about this call's H_IN");
            }
            let (how, salt, inputs) = match (&call_key, as_auditor) {
                (Some(_), true) => anyhow::bail!("--call-key and --as-auditor are two different keys; pass one"),
                (Some(hex), false) => {
                    let key = call_envelope::CallKey(shrugg_client::hex32(hex).context("--call-key must be 32 bytes of hex")?);
                    let (salt, inputs) =
                        call_envelope::open_call_with_key(&envelope, &h_in, &key).context("this call key does not open it")?;
                    ("the per-call key", salt, inputs)
                }
                (None, auditor) => {
                    let w = Wallet::load(&cli.key)?;
                    let opened = if auditor {
                        call_envelope::open_call_as_auditor(&envelope, &h_in, &w.vk)
                            .context("this wallet is not the auditor of this call")?
                    } else {
                        call_envelope::open_call_as_sender(&envelope, &h_in, &w.vk)
                            .context("this wallet did not make this call (try --as-auditor, or --call-key)")?
                    };
                    let (_, salt, inputs) = opened;
                    (if auditor { "the auditor's viewing key" } else { "the caller's viewing key" }, salt, inputs)
                }
            };
            println!("opened with {how}: {} input word(s)\ninputs: {inputs:?}", inputs.len());
            // The chain checks nothing about a transcript's *contents*: what makes one faithful is
            // that it hashes to the `H_IN` the proof published, which commits in-circuit to every
            // word the guest read. A transcript that fails this is a lie the holder can show to
            // anyone (spec §6.1).
            if call_envelope::call_envelope_is_faithful(&h_in, salt, &inputs) {
                println!("H_IN: faithful — these are the words the proof was made over");
            } else {
                println!("H_IN: NOT FAITHFUL — this transcript is not the preimage of the receipt's H_IN");
            }
            // Re-run the program on the transcript. The receipt's outputs came out of a proof; these
            // come out of the emulator, which is the reference semantics for the same program, so a
            // difference means the transcript is not what produced that receipt.
            let pid = Hash::from_hex(receipt["program"].as_str().unwrap_or_default()).context("receipt program id")?;
            let (base_pc, words) = rpc.program_code(&pid).await?.context("the program is no longer on chain")?;
            let exec = emulator::execute(&Program { base_pc, words }, &inputs, Tier(*TIERS.last().expect("a tier")).max_cycles())
                .map_err(|e| anyhow::anyhow!("re-running the program on these inputs failed: {e:?}"))?;
            println!("emulator outputs: {:?}\nreceipt outputs:  {}", exec.outputs, receipt["outputs"]);
        }
        Cmd::BridgeMint { attestation, to, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let bytes = read_hex_arg(&attestation)?;
            let d = wallet::attested_deposit(&bytes)?;
            let recipient = match &to {
                Some(a) => parse_address(a)?,
                None => w.address.clone(),
            };
            // The guardians signed a 32-byte hash of the recipient's address, and the ledger
            // refuses a transaction whose address does not hash to it — so this wallet checks
            // before paying for a proof it could not get admitted.
            if recipient.recipient_hash() != d.to_hash {
                anyhow::bail!(
                    "this attestation deposits to the address hashing to {}, and {} does not; \
                     pass --to with the address the depositor named",
                    hex::encode(d.to_hash),
                    if to.is_some() { "the address given" } else { "this wallet's address" }
                );
            }
            // The asset id comes from the node, over the two wire fields the guardians signed — a
            // disagreement with the one this wallet computed would mean the two are not speaking
            // about the same chain.
            let asset_id = rpc.bridge_asset_id(d.token_chain, &d.token).await?;
            if asset_id != d.asset.to_hex() {
                anyhow::bail!("the node computes a different asset id ({asset_id}) than this wallet ({})", d.asset.to_hex());
            }
            // The index a note carries is state, so it is asked of the node too. For a token the
            // registry already names it is a fact; for a first sighting it is a prediction this
            // wallet has to check afterwards (`wallet::DepositIndex`).
            let asset = wallet::deposit_index(&rpc.bridge_state().await?, &rpc.assets().await?, &asset_id)?;
            let index = asset.index();
            // The note is stamped with a `time` this wallet chooses, inside the window admission
            // allows, which is what makes its commitment predictable enough to seal an envelope
            // against (`Action::BridgeAttest`). The head is the freshest such time.
            let time = u32::try_from(rpc.head().await?["height"].as_u64().context("head height")?)
                .context("chain height does not fit a note's time field")?;
            let (note, envelope) = wallet::deposit_note_for(&w, &recipient, d.amount, index, time)?;
            let owner = recipient.to_string();
            // The action names the index this envelope was sealed for, and admission refuses a
            // mismatch (`Action::BridgeAttest`): if a competing first sighting registers while
            // this bundle is being proved, the transaction is rejected and re-proved rather than
            // depositing a note under an `asset` word the envelope does not match.
            let action = Action::BridgeAttest { attestation: bytes, recipient, r: note.r, time, asset: index, envelope };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit(&rpc, &w, &mut store, None, action, fee, 0, profile, backend_for(cuda)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "bridge attestation");
            // Everything the deposit note is made of, every time. `r` and `time` are already public
            // in this transaction, so printing them discloses nothing — and they are the only way to
            // rebuild the note by hand if the index turns out not to be the predicted one below.
            println!(
                "deposit: {} units of asset {index}{}\n  note {}\n  owner {owner}, from 0, time {time}, r {}",
                d.amount,
                if asset.is_first_sighting() { " (first sighting — this transaction registers it)" } else { "" },
                shrugg_core::notes::word8_to_hex(&note.commitment()),
                shrugg_core::notes::word8_to_hex(&note.r),
            );
            if !no_wait {
                // Belt and braces. A first sighting's index was a prediction, but the action names
                // it and admission refuses a transaction that disagrees with the registry, so a
                // *committed* attest cannot have landed under another index — a lost race is a
                // rejected submission above, not a note in the wrong asset. What is left for this
                // to catch is a node whose registry disagrees with the one the prediction came
                // from, which is worth a line rather than a silence.
                let committed = rpc.call("shrugg_getTransaction", serde_json::json!([s.hash.to_hex()])).await?;
                let landed = match wallet::deposit_index_check(index, &committed) {
                    wallet::DepositIndexCheck::Agrees => index,
                    wallet::DepositIndexCheck::Mismatch { predicted, committed } => {
                        println!(
                            "warning: this node says the deposit landed under asset {committed}, not the {predicted} \
                             the envelope was sealed for — which admission should have refused, so treat this node's \
                             registry as suspect.\n  \
                             If it is right, the envelope opens nothing: rebuild the note as (owner {owner}, from 0, \
                             amount {}, asset {committed}, time {time}, r {}) and import it by hand.",
                            d.amount,
                            shrugg_core::notes::word8_to_hex(&note.r),
                        );
                        committed
                    }
                    // Only reachable if this node cannot render the action it just committed.
                    wallet::DepositIndexCheck::Unknown => {
                        println!("warning: the node cannot say which asset this deposit landed under; check `shrugg tx {}`", s.hash);
                        index
                    }
                };
                println!("asset {landed} balance: {} units", store.balance_of(landed));
            }
        }
        Cmd::BridgeBurn { asset, amount, to_chain, to, relayer_fee, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let to = shrugg_client::hex32(&to).context("the destination address must be 32 bytes of hex")?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => wallet::burn_fee_default(),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            eprintln!("a burn is two bundles, so this proves twice");
            let s = wallet::submit_burn(
                &rpc,
                &w,
                &mut store,
                asset,
                amount,
                relayer_fee,
                to_chain,
                to,
                fee,
                profile,
                backend_for(cuda)?,
                chain_id,
                !no_wait,
            )
            .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "bridge burn");
            println!(
                "burned {amount} units of asset {asset} to chain {to_chain} ({}), of which {relayer_fee} pays the relayer there, change {}",
                hex::encode(to),
                s.change
            );
            if !no_wait {
                println!("asset {asset} balance: {} units", store.balance_of(asset));
            }
        }
        Cmd::Bridge => println!("{}", pretty(&rpc.bridge_state().await?)),
        Cmd::BridgeMessage { sequence } => match rpc.bridge_burn(sequence).await? {
            Some(v) => println!("{}", pretty(&v)),
            None => println!("no burn with sequence {sequence}"),
        },
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
