//! `rand`: the shielded command-line wallet, talking to a RAND full node over JSON-RPC.
//!
//! Phase S1 redacted the chain: there are no accounts and no balances to ask a node about, so
//! every command that used to be a question for the node ("what is this address worth?") is now
//! a question for this machine. The wallet keeps a spend key (`--key`) and a note store next to
//! it (`<key>.notes.json`), scans the commitment tree for notes only that key can open, and
//! spends them by proving a four-slot hidden-asset bundle locally (any asset in slots 0–1, the
//! RAND fee in slots 2–3). The node is asked for chain state —
//! leaves, nullifiers, anchors, witnesses — and handed a finished bundle; it is never told who
//! anyone is.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use randprotocol_client::governance;
use randprotocol_client::wallet::{self, NoteStore, Wallet};
use randprotocol_client::RpcClient;
use randprotocol_client::wallet::{Burn, Submission};
use randprotocol_core::ledger::staking::MIN_STAKE;
use randprotocol_core::ledger::tokens::{native_asset_id, MintAuthority};
use randprotocol_core::notes::ShieldedAddress;
use randprotocol_core::types::actions::Registration;
use randprotocol_core::{format_amount, gas, parse_amount, Action, Address, Hash, Keypair};
use randprotocol_zkvm::machine::{Backend, FriProfile, Tier, TIERS};
use randprotocol_zkvm::{call_envelope, codec, emulator, executor, guests, hash, isa::Program};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "rand", version, about = "RAND shielded wallet: scan, send and prove through a full node's RPC")]
struct Cli {
    /// Full node JSON-RPC endpoint.
    #[arg(long, global = true, env = "RAND_RPC", default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Spend-key file. The note store lives next to it, at `<key>.notes.json`.
    #[arg(long, global = true, env = "RAND_KEY", default_value = "wallet.key.json")]
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
    /// Print this wallet's viewing key: 64 hex, the form `rand_importViewingKey` takes.
    ///
    /// It reads every note this wallet has sent or received and can spend none of them. Anyone
    /// holding it sees this wallet's whole history, so hand it only to whoever should.
    ViewingKey,
    /// Print the per-transaction key of each output of a transaction this wallet sent or received.
    ///
    /// Each key discloses exactly one output: hand the `sent` row's key to a payee or an auditor
    /// and `rand_checkTransaction <hash> <key>` shows them that payment and nothing else. The keys
    /// are recovered from the chain, so this works for any transaction, however old.
    TxKey {
        /// The transaction hash.
        hash: String,
    },
    /// Scan, then show what this wallet can spend.
    Balance,
    /// Scan, then show what this wallet holds in a bridged asset (or in every asset).
    ///
    /// Amounts are in the asset's own smallest unit: only RAND (index 0) has this chain's nine
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
    /// Send RAND or a token to a shielded address: scan, select, prove and submit.
    ///
    /// Either way the transaction is a plain four-slot bundle that does not say which asset moved,
    /// and the fee is RAND — a token transfer needs RAND in the wallet for it.
    Send {
        /// A `rand1…` shielded address.
        to: String,
        /// Amount: in RAND for RAND (e.g. 1.5); in the token's own smallest unit for a token.
        amount: String,
        /// The asset to send: a registry index (0, the default, is RAND), or a token id — `rpl1…`
        /// or 64 hex — found in the node's whole token listing (never a lookup of that one token,
        /// which would tell the node what is about to move).
        #[arg(long, default_value = "0")]
        asset: String,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the bundle instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
        #[arg(long)]
        cuda: bool,
    },
    /// Stake RAND onto a validator: the bundle burns the stake out of this wallet's notes.
    ///
    /// A validator the register does not know yet needs `--registration`, the hex blob its
    /// operator gets from `rand-node register --payout <rand1…>`; one it already knows must
    /// not carry one. Bonded weight counts from the next epoch, and unbonding it is the
    /// validator's own command (`rand-node unbond`), not this wallet's.
    Bond {
        /// The validator's address (base58), as `rand validators` lists it.
        validator: String,
        /// Amount in RAND. Registering a new validator needs at least the staking minimum.
        amount: String,
        /// The hex `Registration` from `rand-node register`, for a validator not yet in the
        /// register.
        #[arg(long)]
        registration: Option<String>,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the bundle instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove on an attached NVIDIA GPU (requires a build with `--features cuda`).
        #[arg(long)]
        cuda: bool,
    },
    /// Testnet faucet: ask a validator to mint RAND into a note (default: this wallet).
    Faucet {
        /// A `rand1…` shielded address; defaults to this wallet's.
        address: Option<String>,
        /// Amount in RAND (max 100).
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
        /// Refuse, before proving, unless the program's deploy-time public input is exactly this
        /// file's words (same forms as `program deploy --public`). A call carries no public words
        /// of its own: it always proves over the program's.
        #[arg(long)]
        expect_public: Option<PathBuf>,
        /// Force a gas tier (10, 12, ..., 20); default: smallest that fits.
        #[arg(long)]
        tier: Option<u8>,
        /// Fee in RAND; default: the schedule minimum for the tier.
        #[arg(long)]
        fee: Option<String>,
        /// Also seal the transcript to this `rand1…` address, which can then open this one call.
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
        /// The guardians' Dilithium2 co-signatures, required on every mint: a JSON array
        /// `[{"index":0,"signature":"<4840 hex>"},…]`, or `@path` to read it from a file.
        #[arg(long)]
        pq: String,
        /// The shielded address the depositor named; defaults to this wallet's.
        #[arg(long)]
        to: Option<String>,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Submit a guardian-set rotation (payload 2) with its Dilithium2 co-signature quorum: a
    /// `BridgeAttest` whose fee bundle pays for it and which deposits nothing. Prints the
    /// guardian-set index Rand is on afterwards.
    BridgeRotate {
        /// The rotation attestation as hex, or `@path` to read the hex from a file.
        rotation: String,
        /// The current PQ guardian set's co-signatures: a JSON array
        /// `[{"index":0,"signature":"<4840 hex>"},…]`, or `@path` to read it from a file.
        #[arg(long)]
        pq: String,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Pause bridge minting with the pause key's signature (bridge hardening B1): a bundle-less,
    /// fee-less `PauseMints` — no spend key and no RAND needed. The file is what
    /// `rand-bridge-gov pause` writes, a 2 420-byte signature as hex, made for the bridge's current
    /// `pause_nonce`; one made for another nonce is refused here, naming it. Burns and rotations
    /// stay open while paused; only a PQ guardian quorum can unpause.
    BridgePause {
        /// The signature as hex, or `@path` to read it from a file.
        #[arg(long)]
        sig: String,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
    },
    /// Lift a mint pause with a PQ guardian quorum (bridge hardening B1): a bundle-less, fee-less
    /// `UnpauseMints`. The file is what `rand-bridge-gov pq-unpause` writes,
    /// `[{"index":0,"signature":"<4840 hex>"},…]`, made for the bridge's current `pause_nonce`.
    BridgeUnpause {
        /// The quorum as JSON, or `@path` to read it from a file.
        #[arg(long)]
        pq: String,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
    },
    /// Burn a bridged asset to another chain: one bundle burns the asset and pays the RAND fee.
    BridgeBurn {
        /// The asset's registry index (`rand asset-balance`).
        asset: u32,
        /// Amount in the asset's own smallest unit.
        amount: u64,
        /// Destination chain id.
        to_chain: u16,
        /// The source-chain token address to release, 32 bytes of hex: which of the asset's
        /// backings this burn redeems (`rand bridge` lists them, one row per coin with its
        /// locked amount). One bridged token is backed by several coins on several chains.
        token: String,
        /// 32-byte destination address, hex.
        to: String,
        /// A portion of AMOUNT paid to the relayer on the destination chain, in the same asset.
        #[arg(long, default_value_t = 0)]
        relayer_fee: u64,
        /// Fee in RAND; the floor is 0.01 — the bridge fee, which covers the bundle's base.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// RPL tokens: burn one this wallet holds; register a bridged token and list its backings
    /// after genesis (bridge hardening B4).
    #[command(subcommand)]
    Token(TokenCmd),
    /// The bridge's public state: guardians, emitters, the asset registry, the burn sequence.
    Bridge,
    /// The outbound burn message with this sequence, for a guardian to sign.
    BridgeMessage { sequence: u64 },
    /// Minimum fee: `fee bundle`, `fee deploy <words> [--public-words M]` or
    /// `fee call <tier> [--bytes B]`.
    Fee {
        /// bundle | deploy | call
        kind: String,
        /// Program words for `deploy`, the tier for `call`.
        n: Option<u64>,
        /// `deploy`: public-input words, priced like code words.
        #[arg(long)]
        public_words: Option<u64>,
        /// `call`: the call's proof plus input-envelope bytes; only bytes past the free allowance
        /// (2 MiB + 18 432) add to the fee.
        #[arg(long)]
        bytes: Option<u64>,
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
enum TokenCmd {
    /// Destroy some of a token this wallet holds: its public supply drops by exactly AMOUNT.
    ///
    /// One bundle burns the token and pays the RAND fee. A bridged token is burned with
    /// `rand bridge-burn` instead, which names the coin released on the other chain.
    Burn {
        /// The token: its registry index, or its id (`rpl1…` or 64 hex).
        asset: String,
        /// Amount in the token's own smallest unit.
        amount: u64,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Register a bridged token with its first backing, authorised by a PQ guardian quorum
    /// (`rand-bridge-gov pq-register`'s file) and paid by this wallet's fee bundle: the bundle base
    /// plus the registry's registration fee. The token is eight decimals on Rand, at the next
    /// index. List on Rand FIRST, `setToken` on the endpoint SECOND.
    RegisterBridged {
        /// Display name, 1 to 32 bytes.
        #[arg(long)]
        name: String,
        /// Ticker, 1 to 12 ASCII graphic characters.
        #[arg(long)]
        symbol: String,
        /// The 32-byte salt the asset id is over, hex.
        #[arg(long)]
        salt: String,
        /// The first backing's bridge chain id (2 Ethereum, 3 BSC, 4 Tron, 5 Solana).
        #[arg(long)]
        chain: u16,
        /// The first backing's 32-byte wire token address, hex.
        #[arg(long)]
        token: String,
        /// The first backing's decimals on its own chain (the source coin's, not the eight on Rand).
        #[arg(long)]
        decimals: u8,
        /// The PQ guardian quorum over the registration, as JSON or `@path`.
        #[arg(long)]
        pq: String,
        /// Fee in RAND; default the bundle base plus the registration fee.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Add a backing to a bridged token, authorised by a PQ guardian quorum
    /// (`rand-bridge-gov pq-list`'s file) and paid by this wallet's fee bundle.
    ListBacking {
        /// The bridged token's registry index.
        #[arg(long)]
        asset: u32,
        /// The backing's bridge chain id (2 Ethereum, 3 BSC, 4 Tron, 5 Solana).
        #[arg(long)]
        chain: u16,
        /// The backing's 32-byte wire token address, hex.
        #[arg(long)]
        token: String,
        /// The backing's decimals on its own chain.
        #[arg(long)]
        decimals: u8,
        /// The PQ guardian quorum over the listing, as JSON or `@path`.
        #[arg(long)]
        pq: String,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Create an RPL token at the registry's next index: fixed supply (`--fixed-supply`, minted
    /// once, at registration) or `Key`-authorised (`--authority-key-out`, mintable again with
    /// `rand token mint`), with or without an initial mint.
    Create {
        /// Display name, 1 to 32 bytes.
        #[arg(long)]
        name: String,
        /// Ticker, 1 to 12 ASCII graphic characters.
        #[arg(long)]
        symbol: String,
        /// Smallest-unit decimals, 0 to 9.
        #[arg(long)]
        decimals: u8,
        /// The 32-byte salt the asset id is over, hex. Random if not given.
        #[arg(long)]
        salt: Option<String>,
        /// Fixed supply: mint exactly this many units at registration, forever — `authority` is
        /// `none`. Needs `--to`; mutually exclusive with `--authority-key-out`.
        #[arg(long)]
        fixed_supply: Option<u64>,
        /// A fresh Dilithium2 key file is written here (0600, refusing to overwrite) and becomes
        /// the token's mint authority. Mutually exclusive with `--fixed-supply`.
        #[arg(long)]
        authority_key_out: Option<PathBuf>,
        /// With `--authority-key-out`: mint this many units at registration too. Needs `--to`.
        #[arg(long)]
        initial: Option<u64>,
        /// The initial mint's recipient. Required with `--fixed-supply` or `--initial`.
        #[arg(long)]
        to: Option<String>,
        /// Fee in RAND; default the bundle base plus the registry's registration fee.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Mint more of a `Key`-authorised token, signed by its authority key.
    Mint {
        /// The token: its registry index, or its id (`rpl1…` or 64 hex).
        #[arg(long)]
        asset: String,
        /// The recipient's shielded address.
        #[arg(long)]
        to: String,
        /// Amount in the token's own smallest unit.
        #[arg(long)]
        amount: u64,
        /// The token's mint authority: a Dilithium2 key file (`rand-node keygen`'s shape, or
        /// `rand token create --authority-key-out`'s).
        #[arg(long)]
        authority_key: PathBuf,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// Hand a `Key`-authorised token to another key, or renounce minting for good.
    SetAuthority {
        /// The token: its registry index, or its id (`rpl1…` or 64 hex).
        #[arg(long)]
        asset: String,
        /// The token's current mint authority: a Dilithium2 key file.
        #[arg(long)]
        authority_key: PathBuf,
        /// Hand the token to this key file's public key. Mutually exclusive with `--renounce`.
        #[arg(long)]
        new_key: Option<PathBuf>,
        /// Retire minting for good: no key can ever mint this token again. Mutually exclusive
        /// with `--new-key`.
        #[arg(long)]
        renounce: bool,
        /// Fee in RAND; the floor is 0.001.
        #[arg(long)]
        fee: Option<String>,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
        /// Prove the paying bundle on an attached NVIDIA GPU.
        #[arg(long)]
        cuda: bool,
    },
    /// One token's public row: name, symbol, decimals, authority, supply, registration height,
    /// id (hex and `rpl1…`) and, if bridged, each backing (chain, token, decimals, locked,
    /// minted_today).
    Info {
        /// The token: its registry index, or its id (`rpl1…` or 64 hex).
        token: String,
    },
    /// Every registered token, paged.
    List {
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = 1000)]
        limit: u64,
    },
}

#[derive(Subcommand)]
enum ProgramCmd {
    /// Assemble a built-in guest program to a JSON file.
    Build {
        /// fib | memcpy | bubble_sort | balance_check | private_payment | public_echo
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
        /// Deploy-time public input: a file of whitespace-separated u32 words (decimal or 0x hex),
        /// or an ELF `.so`, word-encoded as the sBPF guest reads it. The chain stores it with the
        /// program, and every call proves over it.
        #[arg(long)]
        public: Option<PathBuf>,
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
        // Reads four public words (deploy it with `--public`): out0 = their sum + public[1].
        "public_echo" => guests::public_echo(),
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

/// `hc` in the one form the chain ever shows it in: `rand_getProgram` / `rand program show` hex
/// `ProgramRecord.code_hash`, which `check_program` (`executor.rs`) fills as `Program::digest`'s
/// eight `u32` words, each in *little-endian* byte order, concatenated. `Program::code_hash()`
/// hex-encodes the same words big-endian instead (`{w:08x}` per word) — a different string for
/// the same digest — so the wallet must not call it here; this function is the RPC's spelling,
/// computed locally before any proof or submission exists to ask the RPC for it.
fn rpc_hc_hex(p: &Program) -> String {
    let mut bytes = Vec::with_capacity(32);
    for w in p.digest() {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    hex::encode(bytes)
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
        anyhow::bail!("built without CUDA support; rebuild rand with --features cuda")
    }
}

/// The summary line, printed. The wording lives in [`Submission::summary`], where a test can read
/// it back.
fn report(s: &Submission, what: &str) {
    println!("{}", s.summary(what));
}

/// Decode a `Registration` as `rand-node register` prints it: its bincode form as hex.
fn parse_registration(text: &str) -> Result<Registration> {
    let bytes = hex::decode(text.strip_prefix("0x").unwrap_or(text)).context("--registration must be hex")?;
    Registration::decode(&bytes).context("--registration is not a registration from `rand-node register`")
}

/// 32 fresh random bytes, for `rand token create --salt` when none is given. Reuses
/// `randprotocol_zkvm`'s own random source (`TxKey::random`, already a dependency here for
/// sealing envelopes) rather than adding a direct `rand` crate dependency to this binary.
fn random_salt() -> [u8; 32] {
    randprotocol_zkvm::viewing::TxKey::random().0
}

/// `TokenError::IndexMismatch`'s wire text (`"token: wrong token index: expected {expected}, got
/// {got}"`, `ledger::tokens::TokenError`'s `Display`, wrapped once by `TxError::Token`) —
/// `rand token create`'s only refusal that a fresh chain read cannot prevent, because it is a
/// race: another registration can commit between this wallet's read of `next_index` and its own
/// submission. `None` for any other message, which is reported as it always is.
fn parse_index_mismatch(message: &str) -> Option<(u32, u32)> {
    let rest = message.strip_prefix("token: wrong token index: expected ")?;
    let (expected, rest) = rest.split_once(", got ")?;
    Some((expected.parse().ok()?, rest.trim().parse().ok()?))
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

/// The verdict `rand open-call` returns to its caller: `Ok` only when the opened transcript is
/// both faithful and consistent with the receipt it came with.
///
/// Two independent checks, and the chain makes neither. `faithful` is that the transcript hashes to
/// the `H_IN` the proof published, which commits in-circuit to every word the guest read — so an
/// unfaithful transcript is a lie its holder can show to anyone (spec §6.1). The second is that
/// re-running the program on those words reproduces the outputs the receipt reports; the emulator is
/// the reference semantics for the same program, so a difference means these inputs are not what
/// produced that receipt even if they hash correctly.
///
/// An `Err` is the point: this is what makes the command exit non-zero, so a script that opens a
/// transcript to check a claim gets an answer it cannot mistake for a yes.
fn transcript_verdict(faithful: bool, emulated: &[u32], receipt_outputs: &serde_json::Value) -> Result<()> {
    if !faithful {
        anyhow::bail!(
            "NOT FAITHFUL: this transcript is not the preimage of the receipt's H_IN — \
             whoever published it did not run the program on these words"
        );
    }
    // The receipt's outputs are JSON numbers; anything else means this is not a call receipt at all,
    // which is worth failing on rather than comparing against nothing.
    let from_receipt: Option<Vec<u32>> = receipt_outputs
        .as_array()
        .map(|a| a.iter().map(|v| v.as_u64().and_then(|n| u32::try_from(n).ok())).collect::<Option<Vec<u32>>>())
        .unwrap_or(None);
    let Some(from_receipt) = from_receipt else {
        anyhow::bail!("the receipt's outputs are not eight numbers ({receipt_outputs}) — nothing to compare against");
    };
    if from_receipt != emulated {
        anyhow::bail!(
            "OUTPUT MISMATCH: re-running the program on this transcript gives {emulated:?}, \
             and the receipt reports {from_receipt:?} — these inputs are not what produced that receipt"
        );
    }
    Ok(())
}

/// A command-line argument that is either text outright or `@path` to read it from a file.
fn read_text_arg(arg: &str) -> Result<String> {
    match arg.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).with_context(|| format!("reading {path}")),
        None => Ok(arg.to_string()),
    }
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
        Cmd::ViewingKey => {
            println!("{}", Wallet::load(&cli.key)?.viewing_key_hex());
            eprintln!("reads every note this wallet sent or received; spends nothing. A node imports it with rand_importViewingKey.");
        }
        Cmd::TxKey { hash } => {
            let w = Wallet::load(&cli.key)?;
            let h = Hash::from_hex(&hash).context("invalid hash")?;
            let tx = rpc
                .raw_transaction(&h)
                .await?
                .ok_or_else(|| anyhow::anyhow!("{} is not a committed transaction on this node", h.to_hex()))?;
            let rows = wallet::output_keys(&w, &tx);
            if rows.is_empty() {
                anyhow::bail!("this wallet neither sent nor received an output of {}", h.to_hex());
            }
            println!("{:<15} {:<9} {:>22}  tx key", "output", "role", "amount");
            for r in &rows {
                let amount = if r.note.asset == 0 {
                    format!("{} RAND", format_amount(r.note.amount))
                } else {
                    format!("{} (asset {})", r.note.amount, r.note.asset)
                };
                println!("{:<15} {:<9} {:>22}  {}", format!("{}:{}", r.output, r.slot), r.role.as_str(), amount, hex::encode(r.key.0));
            }
            eprintln!("each key discloses exactly its own output: rand_checkTransaction <hash> <key> shows it to anyone holding it.");
        }
        Cmd::Balance => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            wallet::scan(&rpc, &w, &mut store).await?;
            store.save(&path)?;
            println!("balance: {} RAND\nnotes: {} unspent", format_amount(store.balance()), store.spendable().len());
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
            // One bridged token can be backed by several coins (spec §12), and the registry
            // serves one row per coin under the one index — so every coin behind an index is
            // named, not just whichever happens to be listed first.
            let token_of = |index: u32| {
                let coins: Vec<String> = assets
                    .iter()
                    .filter(|a| a.index == index)
                    .map(|a| format!("chain {} token {}", a.chain, hex::encode(&a.token)))
                    .collect();
                match (coins.is_empty(), index) {
                    (false, _) => coins.join(", "),
                    (true, 0) => "RAND".to_string(),
                    (true, _) => "not in this chain's registry".to_string(),
                }
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
                        println!("no notes (run `rand sync`)");
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
                println!("no notes (run `rand sync`)");
            } else {
                // `pending` is a note this wallet has submitted a spend for without waiting for
                // the commit: not spent, not spendable, and the next `sync` decides which.
                // `amount` is in the asset's own smallest unit, so only asset 0 is a RAND figure;
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
                    println!("{:>8}  {:>18}  {:>8}  {}", s.index, format_amount(s.amount), s.height, randprotocol_core::notes::word8_to_hex(&s.to_pk));
                }
            }
        }
        Cmd::Send { to, amount, asset, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let to = parse_address(&to)?;
            let asset = wallet::resolve_asset(&rpc, &asset).await?;
            // RAND has this chain's nine decimals; a token's unit is its own, so its amount is a
            // whole number of that unit.
            let amount = if asset == 0 {
                parse_amount(&amount)?
            } else {
                amount.parse::<u64>().with_context(|| format!("{amount} is not a whole number of asset {asset}'s units"))?
            };
            let fee = match fee { Some(f) => parse_amount(&f)?, None => gas::BUNDLE_BASE };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::send_asset(&rpc, &w, &mut store, &to, asset, amount, fee, profile, backend_for(cuda)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            report(&s?, "transfer");
            if !no_wait {
                if asset != 0 {
                    println!("asset {asset} balance: {} units", store.balance_of(asset));
                }
                println!("balance: {} RAND", format_amount(store.balance()));
            }
        }
        Cmd::Bond { validator, amount, registration, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let validator = Address::from_base58(&validator)
                .with_context(|| format!("{validator} is not a validator address"))?;
            let address = validator.to_base58();
            let amount = parse_amount(&amount)?;
            anyhow::ensure!(amount > 0, "a bond of 0 RAND moves no stake and still pays a fee and a proof");
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
                    "{address} is not in the register; its operator must send you the registration from `rand-node register --payout <rand1…>` and it goes here as --registration <hex>"
                ),
                (None, Some(r)) => {
                    anyhow::ensure!(
                        r.public_key.address() == validator,
                        "that registration is for validator {}, not {address}",
                        r.public_key.address()
                    );
                    anyhow::ensure!(
                        amount >= MIN_STAKE,
                        "registering a validator bonds at least {} RAND, not {}",
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
            // `Burn::rand(amount)`: the stake leaves the shielded pool instead of becoming a
            // note, and the ledger admits a bond only when the bundle burns exactly what is
            // bonded. The unit is RAND, which is now in the type rather than in this comment.
            let s =
                wallet::submit(&rpc, &w, &mut store, None, action, fee, Burn::rand(amount), profile, backend_for(cuda)?, chain_id, !no_wait)
                    .await;
            store.save(&path)?;
            report(&s?, "bond");
            if !no_wait {
                // The set for the next epoch is derived from the register as it stands at this
                // epoch's last block (spec §8), so a bond that has just committed is weight from
                // the next epoch on — not in the one it landed in.
                let epoch = rpc.epoch().await?["epoch"].as_u64().context("getEpoch reply has no epoch")?;
                if let Some(stake) = register_stake(&rpc, &address).await? {
                    println!(
                        "{address}: stake {} RAND, counting as consensus weight from epoch {}",
                        format_amount(stake),
                        epoch + 1
                    );
                }
                println!("balance: {} RAND", format_amount(store.balance()));
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
            println!("submitted mint {hash} ({} RAND to {to})", format_amount(units));
            let r = rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await?;
            println!("committed in block {} (index {})", r.height, r.index);
        }
        Cmd::Program(ProgramCmd::Build { guest, args, out }) => {
            let p = build_guest(&guest, &args)?;
            std::fs::write(&out, codec::program_to_json(&p))?;
            // No public input at build time; `program deploy --public` gives the id one changes it to.
            println!(
                "wrote {} ({} words, program id {})",
                out.display(),
                p.words.len(),
                randprotocol_core::program::program_id_with_public(p.base_pc, &p.words, &[])
            );
        }
        Cmd::Program(ProgramCmd::Deploy { file, public, cuda }) => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let p = load_program(&file)?;
            let public = public.as_deref().map(wallet::public_file_words).transpose()?.unwrap_or_default();
            // The id binds the public input too (`program_id_with_public`); without one it is the
            // plain `program_id`, unchanged.
            let id = randprotocol_core::program::program_id_with_public(p.base_pc, &p.words, &public);
            // Printed before anything is proved: the program id and `hc` are what `rand program
            // show`/`rand_getProgram` will report back for this same program once it lands, so
            // this is the wallet's confirmation that the file it loaded is the one that will show
            // up on chain — in the same spelling, not `Program::code_hash()`'s byte-swapped one
            // (see `rpc_hc_hex`).
            if public.is_empty() {
                println!("program id: {id} ({} words, hc {})", p.words.len(), rpc_hc_hex(&p));
            } else {
                println!(
                    "program id: {id} ({} words, hc {}, public input {} words, digest {})",
                    p.words.len(),
                    rpc_hc_hex(&p),
                    public.len(),
                    randprotocol_core::notes::word8_to_hex(&hash::public_digest(&public))
                );
            }
            // Before any proof: `rand_getLimits` and `rand_estimateFee` apply this chain's own
            // `max_program_words` and `max_program_public_words` admission, so a program over
            // either cap is refused here rather than after a proof the ledger would throw away.
            wallet::deploy_precheck(&rpc, p.words.len(), public.len()).await?;
            let action = Action::Deploy { base_pc: p.base_pc, words: p.words.clone(), public };
            let fee = wallet::deploy_fee_default(&action);
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit(&rpc, &w, &mut store, None, action, fee, Burn::None, profile, backend_for(cuda)?, chain_id, true).await;
            store.save(&path)?;
            // No repeat of the program id/hc line after submission: both are pure functions of
            // the file the wallet loaded (checked above, before the proof), never of the chain's
            // response, so printing them again here would only be a duplicate of the pre-proof
            // line — `report` below is what actually changed.
            report(&s?, "deploy");
        }
        Cmd::Program(ProgramCmd::Show { id }) => {
            let id = Hash::from_hex(&id).context("invalid program id")?;
            match rpc.program(&id).await? {
                Some(v) => println!("{}", pretty(&v)),
                None => println!("unknown program"),
            }
        }
        Cmd::Call { program, inputs, expect_public, tier, fee, auditor, no_envelope, print_call_key, cuda } => {
            if no_envelope && (auditor.is_some() || print_call_key) {
                anyhow::bail!("--no-envelope publishes no transcript, so there is no auditor and no call key");
            }
            let auditor = auditor.as_deref().map(parse_address).transpose()?;
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let pid = Hash::from_hex(&program).context("invalid program id")?;
            // The code and the deploy-time public input, checked against the id before proving.
            let (prog, public) = wallet::load_call_program(&rpc, &pid).await?;
            if let Some(file) = &expect_public {
                wallet::check_expected_public(&public, &wallet::public_file_words(file)?)?;
            }
            // The caps come from the chain (`rand_getLimits`); an older node gets the old ones.
            let limits = rpc.limits().await?;
            let caps = wallet::call_caps(limits.as_ref());
            if !no_envelope && inputs.len() > caps.max_input_words {
                anyhow::bail!(
                    "{} input words is over this chain's call-input cap of {} (from max_call_envelope_bytes {})",
                    inputs.len(),
                    caps.max_input_words,
                    caps.max_envelope_bytes
                );
            }
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let backend = backend_for(cuda)?;
            if public.is_empty() {
                eprintln!("proving the call locally ({} inputs stay private)…", inputs.len());
            } else {
                eprintln!(
                    "proving the call locally ({} inputs stay private, over the program's {}-word public input)…",
                    inputs.len(),
                    public.len()
                );
            }
            let t = std::time::Instant::now();
            // Two provers, one difference: `prove_call` returns the `H_IN` salt as well, which is
            // what the transcript is sealed with. It is CPU-only — every other backend draws that
            // salt inside the prover and drops it — so a GPU proof has to go without an envelope,
            // and says so in its own words rather than being quietly downgraded here.
            let (proof, outputs, tier, envelope, call_key) = if no_envelope {
                let (proof, outputs, tier) =
                    executor::prove(profile, &prog, &inputs, &public, tier, backend).map_err(|e| anyhow::anyhow!(e))?;
                (proof, outputs, tier, None, None)
            } else {
                let (proof, outputs, tier, salt) =
                    executor::prove_call(profile, &prog, &inputs, &public, tier, backend, caps.max_input_words).map_err(|e| anyhow::anyhow!(e))?;
                let h_in = hash::input_digest(salt, &inputs);
                let (e, key) = call_envelope::seal_call_envelope(&w.vk, auditor.as_ref(), &h_in, salt, &inputs, caps)
                    .map_err(|e| anyhow::anyhow!(e))?;
                (proof, outputs, tier, Some(e), Some(key))
            };
            eprintln!("proved in {:.1?}: tier {tier}, {} bytes, outputs {outputs:?}", t.elapsed(), proof.len());
            // Before the paying bundle is proved: a proof over the chain's cap would be refused.
            wallet::check_proof_size(proof.len(), wallet::proof_cap(limits.as_ref()))?;
            // The fee's byte term counts the proof and the envelope (spec §7); a call under the
            // free allowance, every call a default chain admits, pays the tier's fee alone.
            let bytes = gas::call_bytes(&proof, envelope.as_ref());
            let action = Action::Call { program: pid, proof, input_envelope: envelope };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => wallet::call_fee_default(tier, bytes),
            };
            let s = wallet::submit(&rpc, &w, &mut store, None, action, fee, Burn::None, profile, backend, chain_id, true).await;
            store.save(&path)?;
            let s = s?;
            report(&s, "call");
            let receipt = rpc.wait_for_receipt(&s.hash, Duration::from_secs(120)).await?;
            println!("{}", pretty(&receipt));
            if let Some(key) = call_key {
                println!(
                    "input transcript published{}; open it with `rand open-call {}`",
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
            let receipt_h_in = randprotocol_core::notes::word8_from_hex(receipt["h_in"].as_str().unwrap_or_default())
                .context("the receipt's h_in is not 64 hex characters")?;
            if receipt_h_in != h_in {
                anyhow::bail!("the node's receipt and envelope disagree about this call's H_IN");
            }
            let (how, salt, inputs) = match (&call_key, as_auditor) {
                (Some(_), true) => anyhow::bail!("--call-key and --as-auditor are two different keys; pass one"),
                (Some(hex), false) => {
                    let key = call_envelope::CallKey(randprotocol_client::hex32(hex).context("--call-key must be 32 bytes of hex")?);
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
            let faithful = call_envelope::call_envelope_is_faithful(&h_in, salt, &inputs);
            // Re-run the program on the transcript. The receipt's outputs came out of a proof; these
            // come out of the emulator, which is the reference semantics for the same program, so a
            // difference means the transcript is not what produced that receipt.
            let pid = Hash::from_hex(receipt["program"].as_str().unwrap_or_default()).context("receipt program id")?;
            let (base_pc, words) = rpc.program_code(&pid).await?.context("the program is no longer on chain")?;
            let exec = emulator::execute(&Program { base_pc, words }, &inputs, &[], Tier(*TIERS.last().expect("a tier")).max_cycles())
                .map_err(|e| anyhow::anyhow!("re-running the program on these inputs failed: {e:?}"))?;
            println!("emulator outputs: {:?}\nreceipt outputs:  {}", exec.outputs, receipt["outputs"]);
            // The verdict is the exit status, not a line of output: whoever runs this in a script is
            // asking "is this transcript the one that produced that receipt", and a printed
            // NOT FAITHFUL beside a zero exit reads as a yes.
            transcript_verdict(faithful, &exec.outputs, &receipt["outputs"])?;
            println!("verdict: faithful — these are the words the proof was made over, and they reproduce its outputs");
        }
        Cmd::BridgeMint { attestation, pq, to, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let bytes = read_hex_arg(&attestation)?;
            let d = wallet::attested_deposit(&bytes)?;
            // The Dilithium2 co-signatures (B3), checked here under the chain's own rules against
            // the node's PQ set and chain id — before anything is proved.
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            wallet::check_pq_cosignatures(&rpc.bridge_state().await?, rpc.chain_id().await?, &bytes, &pq_signatures)?;
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
            // The index a note carries is state, so it is asked of the node too — and it is a
            // fact, not a guess: a bridged token is listed before any attestation of it is
            // admissible, and a listing's index never moves. A token this chain has not listed is
            // an error here rather than a refused transaction an hour later (`wallet::deposit_index`).
            let index = wallet::deposit_index(&rpc.bridge_state().await?, &rpc.assets().await?, &asset_id)?;
            // The note is stamped with a `time` this wallet chooses, inside the window admission
            // allows, which is what makes its commitment predictable enough to seal an envelope
            // against (`Action::BridgeAttest`). The head is the freshest such time.
            let time = u32::try_from(rpc.head().await?["height"].as_u64().context("head height")?)
                .context("chain height does not fit a note's time field")?;
            let (note, envelope) = wallet::deposit_note_for(&w, &recipient, d.amount, index, time)?;
            let owner = recipient.to_string();
            // The action names the index this envelope was sealed for, and admission refuses a
            // mismatch (`Action::BridgeAttest`) — which nothing on a listed token can now cause,
            // since no transaction hands an index out and a listing's index never moves.
            let action = Action::BridgeAttest {
                attestation: bytes,
                recipient,
                r: note.r,
                time,
                asset: index,
                envelope,
                pq_signatures,
            };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_bridge_action(&rpc, &w, &mut store, action, fee, profile, backend_for(cuda)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "bridge attestation");
            // Everything the deposit note is made of, every time. `r` and `time` are already public
            // in this transaction, so printing them discloses nothing — and they are the only way to
            // rebuild the note by hand if the node's registry turns out to disagree, below.
            println!(
                "deposit: {} units of asset {index}\n  note {}\n  owner {owner}, from 0, time {time}, r {}",
                d.amount,
                randprotocol_core::notes::word8_to_hex(&note.commitment()),
                randprotocol_core::notes::word8_to_hex(&note.r),
            );
            if !no_wait {
                // Belt and braces. The action names its index and admission refuses a transaction
                // that disagrees with the registry, so a *committed* attest cannot have landed
                // under another index. What is left for this to catch is a node whose registry
                // disagrees with the one the index was read from, which is worth a line rather
                // than a silence.
                let committed = rpc.call("rand_getTransaction", serde_json::json!([s.hash.to_hex()])).await?;
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
                            randprotocol_core::notes::word8_to_hex(&note.r),
                        );
                        committed
                    }
                    // Only reachable if this node cannot render the action it just committed.
                    wallet::DepositIndexCheck::Unknown => {
                        println!("warning: the node cannot say which asset this deposit landed under; check `rand tx {}`", s.hash);
                        index
                    }
                };
                println!("asset {landed} balance: {} units", store.balance_of(landed));
            }
        }
        Cmd::BridgeRotate { rotation, pq, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let bytes = read_hex_arg(&rotation)?;
            let new_index = wallet::attested_rotation(&bytes)?;
            let state = rpc.bridge_state().await?;
            let chain_id = rpc.chain_id().await?;
            // A rotation must step the current set by one (the ledger's `BadUpgradeIndex`); said
            // here, before a proof, rather than after one.
            let current = state["guardian_set_index"].as_u64().context("the node serves no guardian_set_index")?;
            if u64::from(new_index) != current + 1 {
                anyhow::bail!("this rotation is to guardian set {new_index}, but Rand is on set {current}: it must be {}", current + 1);
            }
            // Every attest carries the PQ quorum, a rotation's included — by the *current* PQ set,
            // which a payload-2 rotation does not change.
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            wallet::check_pq_cosignatures(&state, chain_id, &bytes, &pq_signatures)?;
            // A rotation deposits nothing: the deposit fields are placeholders the ledger reads for
            // a transfer only — this wallet's address, a zero blinding, asset 0 and an empty
            // envelope. `time` still gets the admission window every attest's does.
            let time = u32::try_from(rpc.head().await?["height"].as_u64().context("head height")?)
                .context("chain height does not fit a note's time field")?;
            let empty = randprotocol_core::notes::Envelope {
                kem_ct: Vec::new(),
                to_receiver: Vec::new(),
                to_sender: Vec::new(),
                body: Vec::new(),
            };
            let action = Action::BridgeAttest {
                attestation: bytes,
                recipient: w.address.clone(),
                r: [0; 8],
                time,
                asset: 0,
                envelope: empty,
                pq_signatures,
            };
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_bridge_action(&rpc, &w, &mut store, action, fee, profile, backend_for(cuda)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "guardian-set rotation");
            if no_wait {
                println!("submitted the rotation to guardian set {new_index}; `rand` did not wait for it to commit");
            } else {
                let after = rpc.bridge_state().await?;
                println!("guardian_set_index: {}", after["guardian_set_index"]);
            }
        }
        Cmd::BridgeBurn { asset, amount, to_chain, token, to, relayer_fee, fee, no_wait, cuda } => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let to = randprotocol_client::hex32(&to).context("the destination address must be 32 bytes of hex")?;
            let token = randprotocol_client::hex32(&token)
                .context("the source-chain token address must be 32 bytes of hex")?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => wallet::burn_fee_default(),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_burn(
                &rpc,
                &w,
                &mut store,
                asset,
                amount,
                relayer_fee,
                to_chain,
                token,
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
        Cmd::Token(TokenCmd::Burn { asset, amount, fee, no_wait, cuda }) => {
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let asset = wallet::resolve_asset(&rpc, &asset).await?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&Action::TokenBurn { asset, amount }),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_token_burn(&rpc, &w, &mut store, asset, amount, fee, profile, backend_for(cuda)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            report(&s?, "token burn");
            if !no_wait {
                println!("asset {asset} balance: {} units", store.balance_of(asset));
            }
        }
        Cmd::Token(TokenCmd::RegisterBridged { name, symbol, salt, chain, token, decimals, pq, fee, no_wait, cuda }) => {
            let salt = randprotocol_client::hex32(&salt).context("--salt must be 32 bytes of hex")?;
            let token = randprotocol_client::hex32(&token).context("--token must be 32 bytes of hex")?;
            let state = governance::GovState::from_bridge_state(&rpc.bridge_state().await?)?;
            let chain_id = rpc.chain_id().await?;
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            // Everything refusable is refused here, before a key file is opened or a bundle
            // proved: the name rules, the backing, and the quorum at the bridge's list_nonce.
            let action = governance::register_bridged_action(&state, chain_id, &name, &symbol, salt, chain, token, decimals, pq_signatures)?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action).saturating_add(
                    state.registration_fee.context("the node serves no registration_fee: pass --fee")?,
                ),
            };
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_bridge_action(&rpc, &w, &mut store, action, fee, profile, backend_for(cuda)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "bridged-token registration");
            let id = randprotocol_core::ledger::tokens::bridged_asset_id(&name, &symbol, &salt);
            println!("registered {symbol} ({name}), asset id {id}, at list_nonce {}", state.list_nonce);
        }
        Cmd::Token(TokenCmd::ListBacking { asset, chain, token, decimals, pq, fee, no_wait, cuda }) => {
            let token = randprotocol_client::hex32(&token).context("--token must be 32 bytes of hex")?;
            let state = governance::GovState::from_bridge_state(&rpc.bridge_state().await?)?;
            let chain_id = rpc.chain_id().await?;
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            let action = governance::list_backing_action(&state, chain_id, asset, chain, token, decimals, pq_signatures)?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_bridge_action(&rpc, &w, &mut store, action, fee, profile, backend_for(cuda)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = s?;
            report(&s, "backing listing");
            println!("listed chain {chain} token {} under asset {asset}, at list_nonce {}", hex::encode(token), state.list_nonce);
        }
        Cmd::Token(TokenCmd::Create { name, symbol, decimals, salt, fixed_supply, authority_key_out, initial, to, fee, no_wait, cuda }) => {
            // Every cheap refusal — the flag combination — before any key file, network read or
            // proof.
            if fixed_supply.is_some() == authority_key_out.is_some() {
                anyhow::bail!("pass exactly one of --fixed-supply or --authority-key-out");
            }
            let (authority_keypair, initial_amount) = if let Some(supply) = fixed_supply {
                if initial.is_some() {
                    anyhow::bail!("--fixed-supply is the whole initial supply; do not also pass --initial");
                }
                if supply == 0 {
                    anyhow::bail!("a fixed supply of zero mints nothing");
                }
                if to.is_none() {
                    anyhow::bail!("--fixed-supply needs --to (the initial mint's recipient)");
                }
                (None, Some(supply))
            } else {
                if initial.is_some() != to.is_some() {
                    anyhow::bail!("--initial and --to must be given together");
                }
                if initial == Some(0) {
                    anyhow::bail!("an initial mint of zero mints nothing");
                }
                (Some(Keypair::generate()), initial)
            };
            let recipient = to.as_deref().map(parse_address).transpose()?;
            let salt = match salt {
                Some(s) => randprotocol_client::hex32(&s).context("--salt must be 32 bytes of hex")?,
                None => random_salt(),
            };
            let authority = match &authority_keypair {
                Some(kp) => MintAuthority::Key(kp.public_key().clone()),
                None => MintAuthority::None,
            };
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let plan = wallet::build_register_token(
                &rpc,
                &w,
                &name,
                &symbol,
                decimals,
                authority.clone(),
                initial_amount.map(|amount| (amount, recipient.clone().expect("checked above"))),
                salt,
            )
            .await?;
            let id = match &plan.action {
                Action::RegisterToken { name, symbol, decimals, authority, initial, salt, .. } => {
                    native_asset_id(name, symbol, *decimals, authority, initial, salt)
                }
                _ => unreachable!("build_register_token always returns a RegisterToken action"),
            };
            // The key file is written only now, right before proving: every refusal above and
            // `build_register_token`'s own reads (the registry gate, a zero initial mint) have
            // already run, so a rejected combination never strands a key file on disk.
            if let (Some(out), Some(kp)) = (&authority_key_out, &authority_keypair) {
                wallet::write_authority_key(kp, out)?;
                println!("wrote authority key {}", out.display());
            }
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&plan.action).saturating_add(plan.registration_fee),
            };
            let chain_id = rpc.chain_id().await?;
            let profile = profile_of(&rpc).await?;
            let index = plan.index;
            let s = wallet::submit_register_token(&rpc, &w, &mut store, plan.action, fee, profile, backend_for(cuda)?, chain_id, !no_wait)
                .await;
            store.save(&path)?;
            let s = match s {
                Ok(s) => s,
                Err(e) => {
                    if let Some(rpc_err) = e.downcast_ref::<randprotocol_client::RpcError>() {
                        if let Some((expected, got)) = parse_index_mismatch(&rpc_err.message) {
                            eprintln!("another token took index {got} first — re-run to register at {expected}");
                        }
                    }
                    return Err(e);
                }
            };
            report(&s, "token registration");
            println!("index {index}, id {} ({})", id.to_hex(), randprotocol_core::token_id::encode(&id));
            if !no_wait {
                let committed = rpc.call("rand_getTransaction", serde_json::json!([s.hash.to_hex()])).await?;
                println!("committed at height {}", committed["height"]);
            }
        }
        Cmd::Token(TokenCmd::Mint { asset, to, amount, authority_key, fee, no_wait, cuda }) => {
            let asset = wallet::resolve_asset(&rpc, &asset).await?;
            let recipient = parse_address(&to)?;
            let authority = wallet::load_authority_key(&authority_key)?;
            let chain_id = rpc.chain_id().await?;
            let (w, path, mut store) = open_wallet(&cli.key)?;
            // Refused up front (not the token's authority, or not Key-authorised at all) inside
            // `build_token_mint`, before any RAND is touched.
            let action = wallet::build_token_mint(&rpc, &w, chain_id, asset, &recipient, amount, &authority).await?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let profile = profile_of(&rpc).await?;
            let s = wallet::submit_token_mint(&rpc, &w, &mut store, action, fee, profile, backend_for(cuda)?, chain_id, !no_wait).await;
            store.save(&path)?;
            report(&s?, "token mint");
            println!("minted {amount} of asset {asset} to {to}");
        }
        Cmd::Token(TokenCmd::SetAuthority { asset, authority_key, new_key, renounce, fee, no_wait, cuda }) => {
            if renounce == new_key.is_some() {
                anyhow::bail!("pass exactly one of --new-key or --renounce");
            }
            let asset = wallet::resolve_asset(&rpc, &asset).await?;
            let authority = wallet::load_authority_key(&authority_key)?;
            let new = match &new_key {
                Some(path) => Some(wallet::load_authority_key(path)?.public_key().clone()),
                None => None,
            };
            let chain_id = rpc.chain_id().await?;
            let action = wallet::build_token_set_authority(&rpc, chain_id, asset, &authority, new.clone()).await?;
            let fee = match fee {
                Some(f) => parse_amount(&f)?,
                None => gas::fee_floor(&action),
            };
            let (w, path, mut store) = open_wallet(&cli.key)?;
            let profile = profile_of(&rpc).await?;
            let s =
                wallet::submit_token_set_authority(&rpc, &w, &mut store, action, fee, profile, backend_for(cuda)?, chain_id, !no_wait)
                    .await;
            store.save(&path)?;
            report(&s?, "set token authority");
            match new {
                Some(pk) => println!("asset {asset}'s mint authority is now {}", pk.to_hex()),
                None => println!("asset {asset}'s mint authority is renounced for good"),
            }
        }
        Cmd::Token(TokenCmd::Info { token }) => {
            let row = wallet::find_token_row(&rpc, &token).await?;
            println!("{}", pretty(&row));
        }
        Cmd::Token(TokenCmd::List { from, limit }) => {
            let reply = rpc.call("rand_getTokens", serde_json::json!([from, limit])).await?;
            println!("{}", pretty(&reply));
        }
        Cmd::BridgePause { sig, no_wait } => {
            // No key file: a pause must work from a machine holding no spend key and no RAND.
            let state = governance::GovState::from_bridge_state(&rpc.bridge_state().await?)?;
            let chain_id = rpc.chain_id().await?;
            let signature = governance::parse_pause_signature(&read_text_arg(&sig)?)?;
            let action = governance::pause_action(&state, chain_id, signature)?;
            let hash = governance::submit_bundle_less(&rpc, chain_id, action, !no_wait).await?;
            if no_wait {
                println!("submitted the pause at pause_nonce {} as {hash}", state.pause_nonce);
            } else {
                let after = rpc.bridge_state().await?;
                println!("paused: bridge minting is off (tx {hash}); mint_paused {}, pause_nonce {}", after["mint_paused"], after["pause_nonce"]);
            }
        }
        Cmd::BridgeUnpause { pq, no_wait } => {
            let state = governance::GovState::from_bridge_state(&rpc.bridge_state().await?)?;
            let chain_id = rpc.chain_id().await?;
            let pq_signatures = wallet::parse_pq_signatures(&read_text_arg(&pq)?)?;
            let action = governance::unpause_action(&state, chain_id, pq_signatures)?;
            let hash = governance::submit_bundle_less(&rpc, chain_id, action, !no_wait).await?;
            if no_wait {
                println!("submitted the unpause at pause_nonce {} as {hash}", state.pause_nonce);
            } else {
                let after = rpc.bridge_state().await?;
                println!("unpaused: bridge minting is on (tx {hash}); mint_paused {}, pause_nonce {}", after["mint_paused"], after["pause_nonce"]);
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
        Cmd::Fee { kind, n, public_words, bytes } => {
            if public_words.is_some() && kind != "deploy" {
                anyhow::bail!("--public-words is for `fee deploy`");
            }
            if bytes.is_some() && kind != "call" {
                anyhow::bail!("--bytes is for `fee call`");
            }
            // The optional fields are sent only when given, so an older node is asked exactly
            // what it always was.
            let spec = match (kind.as_str(), n) {
                ("bundle", _) => serde_json::json!({ "kind": "bundle" }),
                ("deploy", Some(words)) => match public_words {
                    Some(m) => serde_json::json!({ "kind": "deploy", "words": words, "public_words": m }),
                    None => serde_json::json!({ "kind": "deploy", "words": words }),
                },
                ("call", Some(tier)) => match bytes {
                    Some(b) => serde_json::json!({ "kind": "call", "tier": tier, "bytes": b }),
                    None => serde_json::json!({ "kind": "call", "tier": tier }),
                },
                ("deploy", None) => anyhow::bail!("`fee deploy` needs a word count"),
                ("call", None) => anyhow::bail!("`fee call` needs a tier"),
                (other, _) => anyhow::bail!("unknown fee kind {other}; expected bundle, deploy or call"),
            };
            println!("{} RAND", format_amount(rpc.estimate_fee(spec).await?));
        }
        Cmd::Tx { hash } => {
            let h = Hash::from_hex(&hash).context("invalid hash")?;
            let v = rpc.call("rand_getTransaction", serde_json::json!([h.to_hex()])).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The four bridge-governance command lines parse under the names agreed with the bridge
    /// session (`docs/mainnet-launch.md` §5 in the bridge repo).
    #[test]
    fn the_bridge_governance_commands_parse_as_the_launch_doc_writes_them() {
        let parse = |args: &[&str]| Cli::try_parse_from(std::iter::once("rand").chain(args.iter().copied())).map(|c| c.cmd);
        let salt = "27e77272ee77a47a6b66a62f3452dac66e681c79be6750d5e236e99f0d1e1d60";
        let usdt = "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7";
        let Ok(Cmd::Token(TokenCmd::RegisterBridged { name, symbol, chain, decimals, pq, .. })) = parse(&[
            "token", "register-bridged", "--name", "Shielded USD", "--symbol", "zUSD", "--salt", salt, "--chain", "2", "--token", usdt,
            "--decimals", "6", "--pq", "@zusd-0-register.json",
        ]) else {
            panic!("register-bridged parses")
        };
        assert_eq!((name.as_str(), symbol.as_str(), chain, decimals, pq.as_str()), ("Shielded USD", "zUSD", 2, 6, "@zusd-0-register.json"));
        let Ok(Cmd::Token(TokenCmd::ListBacking { asset, chain, decimals, .. })) = parse(&[
            "token", "list-backing", "--asset", "1", "--chain", "3", "--token", usdt, "--decimals", "18", "--pq", "@zusd-2.json",
        ]) else {
            panic!("list-backing parses")
        };
        assert_eq!((asset, chain, decimals), (1, 3, 18));
        assert!(matches!(parse(&["bridge-pause", "--sig", "@pause.sig"]), Ok(Cmd::BridgePause { .. })));
        assert!(matches!(parse(&["bridge-unpause", "--pq", "@unpause.json", "--no-wait"]), Ok(Cmd::BridgeUnpause { no_wait: true, .. })));
    }

    /// The five `rand token` commands (T8b): `create` (both authority branches), `mint`,
    /// `set-authority` (both of `--new-key`/`--renounce`), `info` and `list`.
    #[test]
    fn the_token_standard_commands_parse_with_their_documented_flags() {
        let parse = |args: &[&str]| Cli::try_parse_from(std::iter::once("rand").chain(args.iter().copied())).map(|c| c.cmd);
        let to = "rand1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

        let Ok(Cmd::Token(TokenCmd::Create { name, symbol, decimals, fixed_supply, to: to_arg, .. })) =
            parse(&["token", "create", "--name", "Fixed Coin", "--symbol", "FIX", "--decimals", "6", "--fixed-supply", "1000000", "--to", to])
        else {
            panic!("create --fixed-supply parses")
        };
        assert_eq!((name.as_str(), symbol.as_str(), decimals, fixed_supply, to_arg.as_deref()), ("Fixed Coin", "FIX", 6, Some(1_000_000), Some(to)));

        let Ok(Cmd::Token(TokenCmd::Create { authority_key_out, initial, .. })) = parse(&[
            "token", "create", "--name", "Keyed Coin", "--symbol", "KEY", "--decimals", "8",
            "--authority-key-out", "authority.key.json", "--initial", "500", "--to", to,
        ]) else {
            panic!("create --authority-key-out parses")
        };
        assert_eq!((authority_key_out.as_deref(), initial), (Some(Path::new("authority.key.json")), Some(500)));

        let Ok(Cmd::Token(TokenCmd::Mint { asset, to: to_arg, amount, authority_key, .. })) =
            parse(&["token", "mint", "--asset", "rpl1keyed", "--to", to, "--amount", "500", "--authority-key", "authority.key.json"])
        else {
            panic!("mint parses")
        };
        assert_eq!((asset.as_str(), to_arg.as_str(), amount, authority_key.as_path()), ("rpl1keyed", to, 500, Path::new("authority.key.json")));

        let Ok(Cmd::Token(TokenCmd::SetAuthority { asset, new_key, renounce, .. })) =
            parse(&["token", "set-authority", "--asset", "2", "--authority-key", "authority.key.json", "--new-key", "successor.key.json"])
        else {
            panic!("set-authority --new-key parses")
        };
        assert_eq!((asset.as_str(), new_key.as_deref(), renounce), ("2", Some(Path::new("successor.key.json")), false));
        assert!(matches!(
            parse(&["token", "set-authority", "--asset", "2", "--authority-key", "authority.key.json", "--renounce"]),
            Ok(Cmd::Token(TokenCmd::SetAuthority { renounce: true, new_key: None, .. }))
        ));

        assert!(matches!(parse(&["token", "info", "2"]), Ok(Cmd::Token(TokenCmd::Info { token })) if token == "2"));
        assert!(matches!(parse(&["token", "list"]), Ok(Cmd::Token(TokenCmd::List { from: 0, limit: 1000 }))));
        assert!(matches!(
            parse(&["token", "list", "--from", "5", "--limit", "10"]),
            Ok(Cmd::Token(TokenCmd::List { from: 5, limit: 10 }))
        ));
    }

    /// `parse_index_mismatch` reads `TokenError::IndexMismatch`'s exact wire text
    /// (`TxError::Token`'s `"token: {0}"` wrapping the ledger's own `Display`) and nothing else,
    /// so `rand token create`'s lost-race hint fires only on that one refusal.
    #[test]
    fn parse_index_mismatch_reads_the_ledgers_own_error_text_and_nothing_else() {
        assert_eq!(parse_index_mismatch("token: wrong token index: expected 3, got 2"), Some((3, 2)));
        assert_eq!(parse_index_mismatch("token: wrong token index: expected 10, got 9"), Some((10, 9)));
        assert_eq!(parse_index_mismatch("token: registration fee 100 is below the minimum 1000000"), None);
        assert_eq!(parse_index_mismatch("wrong mint nonce: expected 1, got 0"), None);
        assert_eq!(parse_index_mismatch(""), None);
    }

    /// `open-call`'s verdict is its exit status. A transcript that is not the preimage of the
    /// receipt's `H_IN` is a lie its holder can show to anyone, and one whose words do not
    /// reproduce the receipt's outputs is not what produced that receipt — either way the command
    /// has to fail, or a script checking a disclosure reads a printed warning beside a zero exit as
    /// a yes.
    #[test]
    fn a_transcript_that_is_not_the_one_behind_the_receipt_fails() {
        let outputs = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let receipt = json!(outputs);

        // Faithful and reproducing: the only case that passes.
        transcript_verdict(true, &outputs, &receipt).expect("a faithful, consistent transcript opens");

        // Unfaithful, even with matching outputs — H_IN is the commitment, and it is checked first.
        let e = transcript_verdict(false, &outputs, &receipt).unwrap_err().to_string();
        assert!(e.contains("NOT FAITHFUL"), "{e}");

        // Faithful, but the program run on these words produces something else.
        let mut other = outputs;
        other[7] = 9;
        let e = transcript_verdict(true, &other, &receipt).unwrap_err().to_string();
        assert!(e.contains("OUTPUT MISMATCH") && e.contains("[1, 2, 3, 4, 5, 6, 7, 9]"), "{e}");
        // And a length disagreement is a mismatch too, not a silent prefix compare.
        assert!(transcript_verdict(true, &outputs[..7], &receipt).is_err());

        // A receipt that is not shaped like outputs at all fails rather than comparing to nothing.
        for bad in [json!(null), json!("nope"), json!([1, "two"]), json!([1, -2]), json!([1, 4294967296u64])] {
            let e = transcript_verdict(true, &outputs, &bad).unwrap_err().to_string();
            assert!(e.contains("not eight numbers"), "{bad}: {e}");
        }
    }

    /// The two-spellings-of-`hc` bug (final review, item 1): `rpc_hc_hex` is what `rand program
    /// deploy` now prints before proving, and it must equal what a node's `check_program` — the
    /// function `rand_getProgram`'s `code_hash` field is built from — computes for the very same
    /// program. Exercised against the vendored `evm.bin`, the one image `rand program deploy`
    /// actually ships in this repo, so this is not just `rpc_hc_hex` checked against its own
    /// formula: `check_program` is the real admission path (`ConfidentialExecutor`), run here the
    /// same way a node would run it at deploy time.
    #[test]
    fn the_wallets_hc_string_matches_what_the_rpc_would_return_for_the_same_program() {
        use randprotocol_core::confidential::ConfidentialExecutor;

        let p = guests::compiled::evm();
        let node_code_hash = executor::ZkExecutor::new(FriProfile::Test)
            .check_program(p.base_pc, &p.words)
            .expect("evm.bin is a committed, known-good build");

        assert_eq!(rpc_hc_hex(&p), hex::encode(&node_code_hash));
        // And it must differ from `Program::code_hash()`'s big-endian spelling of the same eight
        // words — that mismatch is exactly the bug this fixes.
        assert_ne!(rpc_hc_hex(&p), p.code_hash());
    }
}
