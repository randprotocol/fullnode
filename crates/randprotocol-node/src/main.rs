use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use libp2p::Multiaddr;
use randprotocol_client::wallet;
use randprotocol_client::RpcClient;
use randprotocol_core::genesis::{EnvelopeHex, Genesis, GenesisNote, GenesisOpening, GenesisValidator, TokensConfig};
use randprotocol_core::notes::{word8_to_hex, Envelope, ShieldedAddress};
use randprotocol_core::types::actions::{
    aggregate_signing_hash, aggregator_register_message, aggregator_unbond_message, aggregator_withdraw_message,
    registration_message, unbond_message, withdraw_message, AggregatorRegistration, Registration,
};
use randprotocol_zkvm::machine::FriProfile;
use randprotocol_core::{format_amount, parse_amount};
use randprotocol_core::{Keypair, PublicKey, UNITS_PER_RAND};
use randprotocol_node::keyfile::{load_keypair, KeyFile};
use randprotocol_node::node::{self, NodeConfig};
use randprotocol_node::storage::{Storage, VerifyMode};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::notes::{Note, SpendKey};
use randprotocol_zkvm::viewing::TxKey;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// One genesis deposit note: `amount` units owned by the shielded address `addr`.
///
/// The note carries fresh commitment randomness, so writing the same allocation twice produces
/// two different notes with two different genesis hashes. That used to be the whole privacy
/// story: a deterministic `r` would let anyone confirm a guess at who a genesis note pays and how
/// much it holds, simply by recomputing the commitment. It no longer is — core I-2 (chain 14)
/// makes this command always write the note's opening (`pk`, `time`, `r`) beside `cm` and
/// `amount`, required on any chain with a `tokens` section, so who a genesis note pays and its
/// amount are public by design once the file is published; only *when* and into what it is later
/// spent stays private. A genesis file is written once and its hash is fixed from then on.
fn deposit_note(addr: &str, amount: u64) -> Result<GenesisNote> {
    let to = ShieldedAddress::parse(addr).with_context(|| format!("{addr} is not a shielded address"))?;
    seal_deposit(&to, &Note::new(to.pk, [0; 8], amount, 0, 0))
}

/// Seal an already-built deposit note to its owner.
///
/// Sealed under a throwaway sender key, exactly as a faucet mint is — a genesis has no identity
/// to keep an outgoing-viewing record for, and the key is dropped before this returns, so only
/// the holder of the owner's spend key can ever open the note. The envelope does not enter the
/// genesis hash (which binds the commitment and the amount), so its randomness is free.
fn seal_deposit(to: &ShieldedAddress, note: &Note) -> Result<GenesisNote> {
    let throwaway = SpendKey::random().viewing_key();
    let envelope = randprotocol_zkvm::address::seal_note(&throwaway, to, note, &TxKey::random())
        .map_err(|e| anyhow::anyhow!("sealing a note to {}: {e}", to.to_string()))?;
    Ok(GenesisNote {
        cm: word8_to_hex(&note.commitment()),
        envelope: EnvelopeHex::from_envelope(&envelope),
        amount: note.amount,
        // Core I-2: what the commitment opens to. `from` and `asset` are not written down —
        // `Genesis::build` recomputes the commitment as a RAND note (asset 0, `from` zero),
        // which is what makes an alloc note auditable as RAND rather than an opaque leaf.
        // Required on any chain with a `tokens` section; emitted always, so a file cut with this
        // build is verifiable whatever section it ends up carrying.
        opening: Some(GenesisOpening {
            pk: word8_to_hex(&note.pk),
            time: note.time,
            r: word8_to_hex(&note.r),
        }),
    })
}

/// The note a `withdraw` pays and the envelope that opens it, sealed to `payout` under a
/// throwaway sender key — the same shape a genesis deposit uses (see [`seal_deposit`]).
///
/// `amount` is what the note is worth, i.e. the withdrawal less the bundle base. The chain never
/// sees this note: it recomputes the commitment from the action's public fields
/// (`ledger::staking::withdraw_note`), so these five fields have to be exactly the five the ledger
/// hashes, or the withdraw pays a note whose envelope opens to nothing the payee can use. That
/// agreement is what `the_cli_withdraw_note_is_the_note_the_ledger_derives` pins.
fn sealed_withdraw_note(payout: &ShieldedAddress, amount: u64, time: u32) -> Result<(Note, Envelope)> {
    let note = Note::new(payout.pk, [0; 8], amount, 0, time);
    let throwaway = SpendKey::random().viewing_key();
    let envelope = randprotocol_zkvm::address::seal_note(&throwaway, payout, &note, &TxKey::random())
        .map_err(|e| anyhow::anyhow!("sealing the payout note: {e}"))?;
    Ok((note, envelope))
}

/// The `--aggregation` flag: `<bond RAND>,<max_covers>,<subsidy_base RAND>,<halving_blocks>,<window>`.
/// The admitted shapes ride separately (`--admitted-shape`), so this is exactly the genesis
/// section's other five fields (spec §2.3).
fn parse_aggregation_config(spec: &str) -> Result<randprotocol_core::ledger::aggregation::AggregationConfig> {
    let parts: Vec<&str> = spec.split(',').collect();
    let [bond, max_covers, subsidy_base, halving_blocks, window] = parts.as_slice() else {
        anyhow::bail!("--aggregation takes <bond>,<max_covers>,<subsidy_base>,<halving_blocks>,<window>, got {spec}");
    };
    Ok(randprotocol_core::ledger::aggregation::AggregationConfig {
        bond: parse_amount(bond)?,
        max_covers: max_covers.parse().with_context(|| format!("max_covers: {max_covers}"))?,
        subsidy_base: parse_amount(subsidy_base)?,
        halving_blocks: halving_blocks.parse().with_context(|| format!("halving_blocks: {halving_blocks}"))?,
        window: window.parse().with_context(|| format!("window: {window}"))?,
        admitted_shapes: Vec::new(),
    })
}

/// One `--admitted-shape`: `<profile>,<tier>,<program>,<input>,<keccak>,<sha256>,<public>,
/// <mem>,<hc hex>,<program digest hex>` — the declared shape of every coverable bundle and the
/// aggregate program's digest for it (spec §2.3). The digest is the four words as 16 lowercase
/// hex chars each, concatenated — the circuits docs' own spelling.
fn parse_admitted_shape(spec: &str) -> Result<randprotocol_core::ledger::aggregation::AdmittedShape> {
    use randprotocol_core::ledger::aggregation::AdmittedShape;
    use randprotocol_core::types::{DeclaredShape, FriProfile};
    let parts: Vec<&str> = spec.split(',').collect();
    let [profile, tier, program, input, keccak, sha256, public, mem, hc, digest] = parts.as_slice() else {
        anyhow::bail!(
            "--admitted-shape takes <profile>,<tier>,<program>,<input>,<keccak>,<sha256>,<public>,<mem>,<hc>,<digest>, got {spec}"
        );
    };
    let profile = match *profile {
        "test" => FriProfile::Test,
        "production" => FriProfile::Production,
        other => anyhow::bail!("--admitted-shape's profile is test or production, got {other}"),
    };
    let u8_of = |name: &str, v: &str| v.parse::<u8>().with_context(|| format!("--admitted-shape's {name}: {v}"));
    let hc_bytes = hex::decode(hc).with_context(|| format!("--admitted-shape's hc is not hex: {hc}"))?;
    if hc_bytes.len() != 32 {
        anyhow::bail!("--admitted-shape's hc must be 32 bytes (64 hex chars), got {}", hc_bytes.len());
    }
    let hc = randprotocol_core::Hash(hc_bytes.try_into().expect("length checked above"));
    let digest_bytes = hex::decode(digest).with_context(|| format!("--admitted-shape's digest is not hex: {digest}"))?;
    if digest_bytes.len() != 32 {
        anyhow::bail!("--admitted-shape's digest must be four 16-hex words (64 hex chars, 32 bytes), got {}", digest_bytes.len());
    }
    let mut words = [0u64; 4];
    for (i, w) in words.iter_mut().enumerate() {
        *w = u64::from_str_radix(&digest[16 * i..16 * i + 16], 16)
            .with_context(|| format!("--admitted-shape's digest word {i}: {digest}"))?;
    }
    Ok(AdmittedShape {
        shape: DeclaredShape {
            profile,
            tier: u8_of("tier", tier)?,
            program_log_height: u8_of("program", program)?,
            input_log_height: u8_of("input", input)?,
            keccak_log_height: u8_of("keccak", keccak)?,
            sha256_log_height: u8_of("sha256", sha256)?,
            public_log_height: u8_of("public", public)?,
            mem_log_height: u8_of("mem", mem)?,
        },
        hc,
        aggregate_program_digest: words,
    })
}

/// One `--validator key,stake,payout` triple. The three fields travel together because they are
/// one register entry (spec §8): three parallel repeatable flags would silently pair the wrong
/// stake with the wrong key the moment one of them was left out.
fn parse_genesis_validator(spec: &str) -> Result<GenesisValidator> {
    let parts: Vec<&str> = spec.split(',').collect();
    let [key, stake, payout] = parts.as_slice() else {
        anyhow::bail!("--validator takes <key file or hex public key>,<stake in RAND>,<payout rand1…>, got {spec}");
    };
    let public_key = if PathBuf::from(key).exists() {
        load_keypair(&PathBuf::from(key))?.public_key().clone()
    } else {
        PublicKey::from_hex(key).with_context(|| format!("{key} is neither a key file nor a hex public key"))?
    };
    let stake = parse_amount(stake).with_context(|| format!("{stake} is not an amount in RAND"))?;
    ShieldedAddress::parse(payout).with_context(|| format!("{payout} is not a shielded address"))?;
    // `Genesis::build` is what refuses a stake below the minimum; saying so here too means the
    // operator hears it before a genesis hash has been printed anywhere.
    anyhow::ensure!(
        stake >= randprotocol_core::ledger::staking::MIN_STAKE,
        "stake {} RAND is below the staking minimum of {} RAND",
        format_amount(stake),
        format_amount(randprotocol_core::ledger::staking::MIN_STAKE)
    );
    Ok(GenesisValidator { public_key, stake: stake as u128, payout: (*payout).to_string() })
}


/// This validator's row of the register, as `rand_getValidators` reports it: the nonce its
/// next signed action must carry, and the payout address a withdraw pays to. A node that is not
/// in the register has nothing to sign yet — it has to be bonded in first.
async fn register_row(rpc: &RpcClient, me: &randprotocol_core::Address) -> Result<(u64, ShieldedAddress)> {
    let rows = rpc.validators().await?;
    let want = me.to_base58();
    let row = rows
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["address"].as_str() == Some(want.as_str())))
        .with_context(|| format!("{want} is not in the validator register; bond it in first (`rand-node register`)"))?;
    let nonce = row["nonce"].as_u64().context("the node's getValidators reply has no nonce")?;
    let payout = row["payout"].as_str().context("the node's getValidators reply has no payout address")?;
    let payout = ShieldedAddress::parse(payout).map_err(|e| anyhow::anyhow!("register payout address: {e}"))?;
    Ok((nonce, payout))
}

/// Submit a bundle-less validator-signed action and report where it landed.
///
/// There is nothing to prove and nothing to pay: the action is signed by the node's own key and
/// the register's nonce is its replay protection, so the transaction is the action alone.
async fn submit_staking(args: &StakingArgs, chain_id: u64, action: randprotocol_core::Action, what: &str) -> Result<()> {
    let rpc = RpcClient::new(args.rpc.clone());
    let tx = randprotocol_core::Transaction { chain_id, bundle: None, action };
    let hash = rpc.send_transaction(&tx).await?;
    if args.no_wait {
        println!("submitted {what} {hash}");
        return Ok(());
    }
    let receipt = rpc.wait_for_transaction(&hash, wallet::COMMIT_TIMEOUT).await?;
    println!("submitted {what} {hash}\n  committed in block {}", receipt.height);
    Ok(())
}

#[derive(Parser)]
#[command(name = "rand-node", version, about = "RAND full node: HotStuff BFT consensus, p2p discovery, shielded note ledger")]
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
    /// Write a genesis.json: every validator key is staked, and each `--alloc` becomes one
    /// shielded deposit note.
    Genesis {
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
        /// A validator, as `<key file or hex public key>,<stake in RAND>,<payout rand1…>`;
        /// repeatable. The stake must be at least the staking minimum (1000 RAND) or the
        /// validator would be in the register but in no epoch's set. The payout address is where
        /// this validator's rewards and unbonded stake are paid, and it is part of the genesis
        /// hash: it is register state.
        #[arg(long = "validator", required = true, value_name = "KEY,STAKE,PAYOUT")]
        validators: Vec<String>,
        /// Blocks per epoch (spec §8): the validator set for epoch `e` is derived from the
        /// register as of the last block of epoch `e - 1`. Part of the genesis hash.
        #[arg(long, default_value_t = randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT)]
        epoch_blocks: u64,
        /// The largest program a `Deploy` may carry, in words (1..=65535, the zkVM's limit).
        /// Omitted, the file has no such field and the chain runs the 4 096-word default with a
        /// genesis hash byte-for-byte what it would have been before the flag existed; given,
        /// it is part of the genesis hash.
        #[arg(long)]
        max_program_words: Option<u32>,
        /// The largest proof a transaction may carry, in bytes (1048576..=33554432). Omitted,
        /// the file has no such field and the chain runs today's 2 MiB; given, it is part of the
        /// genesis hash.
        #[arg(long)]
        max_proof_bytes: Option<u32>,
        /// The largest block, and so the largest transaction, in bytes (4194304..=67108864, and
        /// at least 2 * the proof cap + 1 MiB). Omitted, today's 4 MiB; given, it is part of the
        /// genesis hash.
        #[arg(long)]
        max_block_bytes: Option<u32>,
        /// The largest call input envelope, in bytes (18432..=1048576). Omitted, today's 18 432;
        /// given, it is part of the genesis hash.
        #[arg(long)]
        max_call_envelope_bytes: Option<u32>,
        /// The largest public input a `Deploy` may fix, in words (0..=65535). Omitted, 0 (no
        /// public input); given, it is part of the genesis hash.
        #[arg(long)]
        max_program_public_words: Option<u32>,
        /// Deposit notes `rand1<address>=<amount in RAND>`, repeatable. A redacted chain has
        /// no accounts, so there is no per-validator allocation: value only exists as a note
        /// someone holds the spend key for.
        #[arg(long = "alloc")]
        allocs: Vec<String>,
        #[arg(long, default_value = "genesis.json")]
        out: PathBuf,
        /// Testnet only: enable the faucet (`rand_mint`, up to 100 RAND per call).
        #[arg(long)]
        faucet: bool,
        /// Disable confidential computation (Deploy/Call transactions) on this chain.
        #[arg(long)]
        no_confidential: bool,
        /// zkVM FRI profile: production (default) or test (fast, insecure; tests only).
        #[arg(long, default_value = "production")]
        fri_profile: String,
        /// The aggregation section (chain 9), as
        /// `<bond RAND>,<max_covers>,<subsidy_base RAND>,<halving_blocks>,<window>`.
        /// Omitted entirely when absent, so an aggregation-less chain's file and hash are
        /// byte-for-byte today's.
        #[arg(long, value_name = "BOND,MAX_COVERS,SUBSIDY,HALVING,WINDOW")]
        aggregation: Option<String>,
        /// One admitted shape, as
        /// `<profile>,<tier>,<program>,<input>,<keccak>,<sha256>,<public>,<mem>,<hc hex>,<program digest hex>`;
        /// repeatable, required with `--aggregation`. The digest is 64 lowercase hex chars (the
        /// four words as 16 each); the activation placeholder must never ship — genesis
        /// validation refuses a zero digest.
        #[arg(long = "admitted-shape", value_name = "PROFILE,TIER,HEIGHTS…,HC,DIGEST")]
        admitted_shapes: Vec<String>,
        /// The RPL `tokens` section, as a `TokensConfig` JSON file (`{"registration_fee": …,
        /// "mint_cap_per_day": …, "tokens": [...]}`). Omitted entirely when absent, so a chain
        /// without one hashes byte-for-byte as before. A `bridge` section needs one, with a
        /// non-zero `mint_cap_per_day` (bridge hardening B1: per backing, per UTC day, in the
        /// token's eight-decimal units); a listed token needs a `bridge` section
        /// (`Genesis::build` validates both).
        #[arg(long, value_name = "TOKENS.JSON")]
        tokens: Option<PathBuf>,
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
        /// Take part in consensus with this node's key. A key in no current epoch's validator
        /// set observes until an epoch admits it (spec §8), so a validator that bonds in after
        /// genesis does not need a restart.
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
        /// Keep the raw proofs of sealed bundles (block aggregation, spec §6.2): an archive
        /// node. By default the pruning pass rewrites a sealed bundle's record to its pruned
        /// form (34 public values + the declared shape) once the window passes.
        #[arg(long)]
        keep_raw_proofs: bool,
        /// Let the viewing-key methods answer callers that are not on loopback.
        ///
        /// Off by default (audit v3, VK-3): nothing in the RPC authenticates anyone, and the
        /// facility exists for this node's own explorer. Open it only behind something that does
        /// authenticate — otherwise a stranger can fill every viewing-key slot and keep scans
        /// running against this node.
        #[arg(long)]
        rpc_viewing_open: bool,
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
    /// Database maintenance on a stopped node's data directory.
    Db {
        #[command(subcommand)]
        cmd: DbCmd,
    },
    /// Show node status.
    Status {
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Print this node's `Registration` (hex) for a wallet to attach to the bond that registers
    /// it. The bond itself is a wallet transaction: it burns the stake out of the wallet's own
    /// notes, which a node has none of.
    Register {
        #[arg(long)]
        key: PathBuf,
        /// Where this validator's rewards and unbonded stake are paid (`rand1…`).
        #[arg(long)]
        payout: String,
        /// The chain to register on is read from here: a registration is signed over the chain
        /// id, so one written for the wrong chain is simply refused.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Move bonded stake into unbonding. Withdrawable two epochs later; free.
    Unbond {
        /// Amount in RAND.
        amount: String,
        #[command(flatten)]
        staking: StakingArgs,
    },
    /// Pay released stake and rewards into a note at this validator's payout address, less the
    /// bundle base the withdraw pays the block's proposer.
    Withdraw {
        /// Amount in RAND.
        amount: String,
        #[command(flatten)]
        staking: StakingArgs,
    },
    /// The aggregator role on a chain with an `aggregation` section (block aggregation,
    /// spec §2.2): register, unbond, withdraw. The register's twins, one register over.
    Aggregator {
        #[command(subcommand)]
        cmd: AggregatorCmd,
    },
    /// The aggregate daemon (spec §8): poll the unsealed work list, fetch the raw bundles,
    /// prove one aggregate over them, and submit it — a separate process from the validator,
    /// needing only an RPC endpoint and the registered key.
    Aggregate {
        /// The aggregator key file: the key the register knows, and the key that signs.
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Keep polling instead of submitting once and exiting.
        #[arg(long)]
        watch: bool,
        /// Seconds between polls in `--watch` mode.
        #[arg(long, default_value_t = 15)]
        interval_secs: u64,
        /// Return once the node accepts the aggregate instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
    },
}

/// `rand-node db …`: offline maintenance, run with the node stopped (RocksDB's lock refuses a
/// second opener).
#[derive(Subcommand)]
enum DbCmd {
    /// Before rolling back to a pre-v0.3 build: drop the `receipts_by_program` column family and
    /// its built marker. The old build lists fifteen families and RocksDB refuses to open a
    /// database with a sixteenth, so without this the downgraded node never starts. A later
    /// v0.3 start rebuilds the index from the receipts.
    DropReceiptsIndex {
        #[arg(long)]
        datadir: PathBuf,
    },
}

/// `rand-node aggregator …`: the register actions.
#[derive(Subcommand)]
enum AggregatorCmd {
    /// Print a signed registration for this key and payout (`--bond` is the genesis bond you
    /// *intend* to burn through the wallet's `submit`; the chain's config rules the value).
    Register {
        #[arg(long)]
        key: PathBuf,
        /// The bond you will burn at registration, in RAND — a note to yourself: the
        /// registration's signature does not carry it, the genesis config decides it.
        #[arg(long)]
        bond: String,
        /// Where this aggregator's payments are paid (`rand1…`).
        #[arg(long)]
        payout: String,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Stop this aggregator submitting; the bond releases after the chain's window.
    Unbond {
        #[command(flatten)]
        staking: StakingArgs,
    },
    /// Pay the released bond into a note at the payout address, less the bundle base.
    Withdraw {
        #[command(flatten)]
        staking: StakingArgs,
    },
}

/// What `unbond` and `withdraw` both need.
///
/// Both are signed by the *node's* key and ride without a bundle, like a faucet mint: a validator
/// key owns no notes, so there is nothing to pay a fee from and nothing to prove. An unbond is
/// free; a withdraw pays the bundle base out of the amount it withdraws, to the proposer of the
/// block that applies it. So neither command takes a wallet, and both return in a block's time
/// rather than a proof's.
#[derive(clap::Args)]
struct StakingArgs {
    /// The validator key file: the key the register knows, and the key that signs the action.
    #[arg(long)]
    key: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Return once the node accepts the transaction instead of waiting for it to commit.
    #[arg(long)]
    no_wait: bool,
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
            let id = libp2p::identity::Keypair::ed25519_from_bytes(kp.derive_subkey(b"rand-p2p-identity"))?;
            println!("address: {}\npublic_key: {}\npeer_id: {}", kp.address(), kp.public_key().to_hex(), id.public().to_peer_id());
        }
        Cmd::Genesis {
            chain_id,
            validators,
            epoch_blocks,
            max_program_words,
            max_proof_bytes,
            max_block_bytes,
            max_call_envelope_bytes,
            max_program_public_words,
            allocs,
            out,
            faucet,
            no_confidential,
            fri_profile,
            aggregation,
            admitted_shapes,
            tokens,
        } => {
            let mut gen = Genesis {
                chain_id,
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis() as u64,
                validators: Vec::new(),
                alloc: Vec::new(),
                faucet,
                confidential: !no_confidential,
                fri_profile,
                hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
                // A bridged chain is cut by adding a `bridge` section to this file by hand:
                // `Genesis::build` accepts and validates one (`check_bridge`) and the node
                // persists and reloads it, but a guardian set plus a per-chain emitter table is
                // more than a flag's worth of surface and belongs with whoever holds the
                // guardian keys, not with this command.
                bridge: None,
                // The RPL `tokens` section: read from a `TokensConfig` JSON file when `--tokens`
                // is given, so `Genesis::build` can validate it (the gate: a `bridge` section
                // needs one, a listed token needs a `bridge` section); omitted entirely
                // otherwise, so a chain without the flag hashes byte-for-byte as before.
                tokens: match &tokens {
                    Some(path) => Some(
                        serde_json::from_str::<TokensConfig>(
                            &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
                        )
                        .with_context(|| format!("{} is not a valid tokens config", path.display()))?,
                    ),
                    None => None,
                },
                // An aggregating chain is cut with the section spelled out on the command
                // line (chain 9, spec §2.3): the bond, the subsidy schedule and the registered
                // shapes with their measured program digests.
                aggregation: match (&aggregation, &admitted_shapes) {
                    (Some(spec), shapes) if !shapes.is_empty() => {
                        let mut cfg = parse_aggregation_config(spec)?;
                        cfg.admitted_shapes = shapes
                            .iter()
                            .map(|s| {
                                // The literal `hc_bundle` means this build's pinned guest
                                // digest — the only value a chain-9 genesis may take, so the
                                // flag cannot quietly carry a stale one.
                                parse_admitted_shape(&s.replace(
                                    ",hc_bundle,",
                                    &format!(",{},", word8_to_hex(&ZkExecutor::hc_bundle())),
                                ))
                            })
                            .collect::<Result<Vec<_>>>()?;
                        Some(cfg)
                    }
                    (Some(spec), _) => anyhow::bail!(
                        "--aggregation {spec} needs at least one --admitted-shape (a chain that admits no shape seals nothing)"
                    ),
                    (None, _) => None,
                },
                epoch_blocks,
                max_program_words,
                max_proof_bytes,
                max_block_bytes,
                max_call_envelope_bytes,
                max_program_public_words,
            };
            for v in &validators {
                gen.validators.push(parse_genesis_validator(v)?);
            }
            for a in &allocs {
                let (addr, amt) = a.split_once('=').context("--alloc must be rand1address=amount")?;
                let amount = parse_amount(amt)?;
                gen.alloc.push(deposit_note(addr, amount)?);
                println!("  alloc {} RAND to {addr}", format_amount(amount));
            }
            let executor = node::executor_for_profile(&gen.fri_profile)?;
            let state = gen.build(executor.as_ref())?;
            std::fs::write(&out, gen.to_json())?;
            println!(
                "wrote {} (genesis hash {}, {} validators, {} notes, {} blocks/epoch, programs up to {} words, proofs up to {} bytes, blocks up to {} bytes, call envelopes up to {} bytes, program public input up to {} words, faucet {}, confidential {}, fri {}, hc_bundle {})",
                out.display(),
                state.hash(),
                state.validators.len(),
                state.notes.len(),
                state.epoch_blocks,
                state.ledger.max_program_words(),
                state.ledger.max_proof_bytes(),
                state.ledger.max_block_bytes(),
                state.ledger.max_call_envelope_bytes(),
                state.ledger.max_program_public_words(),
                if faucet { "on" } else { "off" },
                if no_confidential { "off" } else { "on" },
                state.fri_profile,
                gen.hc_bundle,
            );
        }
        Cmd::Init { datadir, genesis } => {
            std::fs::create_dir_all(&datadir)?;
            let text = std::fs::read_to_string(&genesis)?;
            let g = Genesis::from_json(&text)?;
            let executor = node::executor_for_profile(&g.fri_profile)?;
            let gs = g.build(executor.as_ref())?;
            std::fs::write(datadir.join("genesis.json"), &text)?;
            let storage = Storage::open(&datadir)?;
            storage.init_genesis(&gs)?;
            println!("initialised {} at genesis {} (chain id {})", datadir.display(), gs.hash(), gs.chain_id);
        }
        Cmd::Verify { datadir, mode, repair } => {
            let mode: VerifyMode = mode.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let (gs, executor) = node::load_genesis(&datadir)?;
            let storage = Storage::open(&datadir)?;
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
        Cmd::Run { datadir, key, listen, bootstrap, rpc, validator, no_mdns, block_interval_ms, view_timeout_ms, verify_chain, keep_raw_proofs, rpc_viewing_open } => {
            let kp = load_keypair(&key)?;
            let handle = node::start(NodeConfig {
                viewing_open: rpc_viewing_open,
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
                keep_raw_proofs,
            })
            .await?;
            let mut handle = handle;
            tokio::select! {
                r = &mut handle.task => { r??; }
                _ = tokio::signal::ctrl_c() => { tracing::info!("shutting down"); handle.shutdown().await; }
            }
        }
        Cmd::Db { cmd: DbCmd::DropReceiptsIndex { datadir } } => {
            let dropped = Storage::drop_receipts_index(&datadir)?;
            let db = datadir.join("db");
            match dropped.family {
                true => println!("dropped column family receipts_by_program from {}", db.display()),
                false => println!("no receipts_by_program column family in {}", db.display()),
            }
            match dropped.marker {
                true => println!("deleted meta key receipts_by_program_built"),
                false => println!("no meta key receipts_by_program_built"),
            }
            println!("a pre-v0.3 build can open this database; a v0.3 start rebuilds the index");
        }
        Cmd::Status { rpc } => {
            let v = RpcClient::new(rpc).status().await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Cmd::Register { key, payout, rpc } => {
            let kp = load_keypair(&key)?;
            let chain_id = RpcClient::new(rpc).chain_id().await?;
            let payout = ShieldedAddress::parse(&payout)
                .map_err(|e| anyhow::anyhow!("{payout} is not a shielded address: {e}"))?;
            let signature = kp.sign(registration_message(chain_id, &payout).as_bytes());
            let registration = Registration { public_key: kp.public_key().clone(), payout, signature };
            println!(
                "validator {} on chain {chain_id}\nregistration: {}",
                kp.address(),
                hex::encode(registration.encode())
            );
        }
        Cmd::Unbond { amount, staking } => {
            let kp = load_keypair(&staking.key)?;
            let amount = parse_amount(&amount)?;
            let rpc = RpcClient::new(staking.rpc.clone());
            let chain_id = rpc.chain_id().await?;
            let (nonce, _) = register_row(&rpc, &kp.address()).await?;
            let signature = kp.sign(unbond_message(chain_id, &kp.address(), amount, nonce).as_bytes());
            let action = randprotocol_core::Action::Unbond { validator: kp.address(), amount, nonce, signature };
            submit_staking(&staking, chain_id, action, &format!("unbond of {} RAND", format_amount(amount))).await?;
        }
        Cmd::Withdraw { amount, staking } => {
            let kp = load_keypair(&staking.key)?;
            let amount = parse_amount(&amount)?;
            let base = randprotocol_core::gas::BUNDLE_BASE;
            anyhow::ensure!(
                amount > base,
                "a withdraw pays the {} RAND bundle base out of its amount, so {} RAND buys no note",
                format_amount(base),
                format_amount(amount)
            );
            let rpc = RpcClient::new(staking.rpc.clone());
            let chain_id = rpc.chain_id().await?;
            let (nonce, payout) = register_row(&rpc, &kp.address()).await?;
            // The chain computes the deposit note itself, from the register's payout address, the
            // amount less the base, the blinding below and this `time` — the head height, which
            // the signature binds. The envelope only the payee can open is sealed against that
            // same note here, which is why the note cannot be bound to the height that ends up
            // applying the transaction: that height does not exist yet. Admission takes any
            // `time` within the window (256 blocks), so the head is simply the freshest one.
            let time = rpc.head().await?["height"].as_u64().context("head has no height")? as u32;
            let (note, envelope) = sealed_withdraw_note(&payout, amount - base, time)?;
            let signature = kp
                .sign(withdraw_message(chain_id, &kp.address(), amount, nonce, time, &note.r, &envelope).as_bytes());
            let action = randprotocol_core::Action::Withdraw {
                validator: kp.address(),
                amount,
                nonce,
                time,
                r: note.r,
                envelope,
                signature,
            };
            println!(
                "withdrawing {} RAND: a note worth {} RAND to {}, the {} RAND base to the block's proposer\n  note blinding r {} at time {time}",
                format_amount(amount),
                format_amount(amount - base),
                payout,
                format_amount(base),
                word8_to_hex(&note.r)
            );
            submit_staking(&staking, chain_id, action, &format!("withdraw of {} RAND", format_amount(amount))).await?;
        }
        Cmd::Aggregator { cmd } => match cmd {
            AggregatorCmd::Register { key, bond, payout, rpc } => {
                let kp = load_keypair(&key)?;
                let chain_id = RpcClient::new(rpc).chain_id().await?;
                let payout = ShieldedAddress::parse(&payout)
                    .map_err(|e| anyhow::anyhow!("{payout} is not a shielded address: {e}"))?;
                let signature = kp.sign(aggregator_register_message(chain_id, &payout).as_bytes());
                let registration = AggregatorRegistration { public_key: kp.public_key().clone(), payout, signature };
                println!(
                    "aggregator {} on chain {chain_id}\nregistration: {}\n  bond {} RAND rides through the wallet's `submit` as the register bundle's burn",
                    kp.address(),
                    hex::encode(bincode::serialize(&registration).expect("a registration serialises")),
                    bond
                );
            }
            AggregatorCmd::Unbond { staking } => {
                let kp = load_keypair(&staking.key)?;
                let rpc = RpcClient::new(staking.rpc.clone());
                let chain_id = rpc.chain_id().await?;
                let nonce = aggregator_row(&rpc, &kp.address()).await?.0;
                let signature = kp.sign(aggregator_unbond_message(chain_id, &kp.address(), nonce).as_bytes());
                let action = randprotocol_core::Action::UnbondAggregator { aggregator: kp.address(), nonce, signature };
                submit_staking(&staking, chain_id, action, "aggregator unbond").await?;
            }
            AggregatorCmd::Withdraw { staking } => {
                let kp = load_keypair(&staking.key)?;
                let rpc = RpcClient::new(staking.rpc.clone());
                let chain_id = rpc.chain_id().await?;
                let (nonce, payout, _) = aggregator_row(&rpc, &kp.address()).await?;
                // The note is the bond less the base, derived by the chain from the register —
                // the amount itself is not in the action, exactly like the aggregate's payout.
                let bond = aggregator_row(&rpc, &kp.address()).await?.2;
                let base = randprotocol_core::gas::BUNDLE_BASE;
                anyhow::ensure!(bond > base, "the bond does not cover the bundle base");
                let time = rpc.head().await?["height"].as_u64().context("head has no height")? as u32;
                let (note, envelope) = sealed_withdraw_note(&payout, bond - base, time)?;
                let signature = kp.sign(
                    aggregator_withdraw_message(chain_id, &kp.address(), nonce, time, &note.r, &envelope).as_bytes(),
                );
                let action = randprotocol_core::Action::WithdrawAggregator {
                    aggregator: kp.address(),
                    nonce,
                    time,
                    r: note.r,
                    envelope,
                    signature,
                };
                submit_staking(&staking, chain_id, action, "aggregator withdraw").await?;
            }
        },
        Cmd::Aggregate { key, rpc, watch, interval_secs, no_wait } => {
            aggregate_daemon(&key, &rpc, watch, interval_secs, no_wait).await?;
        }
    }
    let _ = UNITS_PER_RAND;
    Ok(())
}

/// The aggregator register row for `me`: nonce, payout and bond, from `rand_getAggregators`.
async fn aggregator_row(rpc: &RpcClient, me: &randprotocol_core::Address) -> Result<(u64, ShieldedAddress, u64)> {
    let rows = rpc.call("rand_getAggregators", serde_json::json!([])).await?;
    let want = me.to_base58();
    let row = rows
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["address"].as_str() == Some(want.as_str())))
        .with_context(|| format!("{want} is not in the aggregator register; register it first (`rand-node aggregator register`)"))?;
    let nonce = row["nonce"].as_u64().context("the node's getAggregators reply has no nonce")?;
    let payout = row["payout"].as_str().context("the node's getAggregators reply has no payout address")?;
    let payout = ShieldedAddress::parse(payout).map_err(|e| anyhow::anyhow!("register payout address: {e}"))?;
    let bond = row["bond"].as_str().and_then(|b| b.parse::<u64>().ok()).context("the node's getAggregators reply has no bond")?;
    Ok((nonce, payout, bond))
}

/// The aggregate daemon's one pass (spec §8's shape): the unsealed work list, up to
/// `max_covers` of it, the raw bundles fetched back, one rVM proof over them, and the signed
/// aggregate submitted. `--watch` loops it on the interval; every pass is one proving job.
async fn aggregate_daemon(key: &std::path::Path, rpc_url: &str, watch: bool, interval_secs: u64, no_wait: bool) -> Result<()> {
    let kp = load_keypair(key)?;
    let rpc = RpcClient::new(rpc_url.to_string());
    let chain_id = rpc.chain_id().await?;
    loop {
        let status = rpc.status().await?;
        let agg = &status["aggregation"];
        let profile = match status["fri_profile"].as_str().unwrap_or("production") {
            "test" => FriProfile::Test,
            _ => FriProfile::Production,
        };
        let max_covers = agg["max_covers"].as_u64().unwrap_or(0) as usize;
        // `subsidy_base` is a decimal string since node N-3 (2026-09-20); `amount_field` reads
        // either encoding, so this daemon works against an older node too.
        let subsidy_base = randprotocol_client::amount_field(&agg["subsidy_base"]).unwrap_or(0);
        let halving = agg["halving_blocks"].as_u64().unwrap_or(1).max(1);
        let n = agg["sealed_blocks"].as_u64().unwrap_or(0);
        let height = status["height"].as_u64().unwrap_or(0);
        let work = rpc.call("rand_getUnsealed", serde_json::json!([0, max_covers.max(1)])).await?;
        let bundles = work["bundles"].as_array().cloned().unwrap_or_default();
        if !bundles.is_empty() && max_covers > 0 {
            let chosen = &bundles[..bundles.len().min(max_covers)];
            // The raw bundles, back from the node: each one's stored proof is the tape input.
            let mut proofs = Vec::with_capacity(chosen.len());
            let mut covers = Vec::with_capacity(chosen.len());
            let mut shares = 0u64;
            for b in chosen {
                let hash = randprotocol_core::Hash::from_hex(b["hash"].as_str().context("work row has no hash")?)
                    .map_err(|e| anyhow::anyhow!("work row hash: {e}"))?;
                let raw = rpc.call("rand_getRawTransaction", serde_json::json!([b["hash"].clone()])).await?;
                let bytes = hex::decode(raw.as_str().context("getRawTransaction answer is not hex")?)?;
                let tx: randprotocol_core::Transaction = bincode::deserialize(&bytes)?;
                let bundle = tx.bundle.as_ref().context("a work row with no bundle")?;
                let proof: randprotocol_zkvm::machine::Proof = postcard::from_bytes(&bundle.proof)
                    .map_err(|_| anyhow::anyhow!("a work row's proof does not decode"))?;
                covers.push(hash);
                shares = shares.saturating_add(bundle.fee.saturating_sub(randprotocol_core::gas::BUNDLE_BASE));
                proofs.push(proof);
            }
            // The shape is the first proof's; every proof in the set must share it (the
            // chain's admission checks it again).
            let first = &proofs[0];
            let shape = randprotocol_rvm::shape::InnerShape::of(
                profile,
                first.tier,
                first.program_log_height,
                first.input_log_height,
                first.keccak_log_height,
                first.sha256_log_height,
                first.public_log_height,
                first.mem_log_height,
            );
            let key_inner = randprotocol_rvm::shape::InnerKey::of(profile, &shape);
            let vk = randprotocol_rvm::aggregate::InnerVerifierKey { shape, key: key_inner };
            let m = randprotocol_rvm::machine::Machine::new(profile);
            let t0 = std::time::Instant::now();
            let a = randprotocol_rvm::aggregate::aggregate(&m, &vk, &proofs, None)
                .map_err(|e| anyhow::anyhow!("aggregating {} bundles: {e:?}", proofs.len()))?;
            let proof_bytes = a.proof.to_bytes();
            tracing::info!(
                "aggregated {} bundles in {:.1?} ({} proof bytes)",
                proofs.len(),
                t0.elapsed(),
                proof_bytes.len()
            );
            // The payment note: the subsidy at the schedule's current index plus the proving
            // shares, sealed to the register's payout address (spec §5.4).
            let subsidy = subsidy_base.checked_shr((n / halving) as u32).unwrap_or(0);
            let (_, payout, _) = aggregator_row(&rpc, &kp.address()).await?;
            let time = height as u32 + 1;
            let (note, envelope) = sealed_withdraw_note(&payout, subsidy + shares, time)?;
            let nonce = aggregator_row(&rpc, &kp.address()).await?.0;
            let signature = kp.sign(
                aggregate_signing_hash(chain_id, nonce, time, &note.r, &covers, &randprotocol_core::Hash::digest(&proof_bytes))
                    .as_bytes(),
            );
            let tx = randprotocol_core::Transaction {
                chain_id,
                bundle: None,
                action: randprotocol_core::Action::Aggregate {
                    covers,
                    proof: proof_bytes,
                    aggregator: kp.address(),
                    nonce,
                    time,
                    r: note.r,
                    envelope,
                    signature,
                },
            };
            let hash = rpc.send_transaction(&tx).await?;
            if no_wait {
                println!("submitted aggregate {hash} ({} covered)", proofs.len());
            } else {
                let receipt = rpc.wait_for_transaction(&hash, wallet::COMMIT_TIMEOUT).await?;
                println!("submitted aggregate {hash} ({} covered)
  committed in block {}", proofs.len(), receipt.height);
            }
            if !watch {
                return Ok(());
            }
        }
        if !watch {
            if bundles.is_empty() {
                println!("nothing to cover right now");
            }
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::ledger::staking::MIN_STAKE;
    use randprotocol_zkvm::machine::FriProfile;

    /// The chain-9 genesis arms (spec §2.3): the section parses from the flag spellings, the
    /// digest round-trips as the circuits docs spell it, and the activation placeholder dies at
    /// validation — a fleet can never be cut from FILL-AT-ACTIVATION values.
    #[test]
    fn the_aggregation_flags_parse_and_the_zero_digest_placeholder_is_refused() {
        use randprotocol_core::types::{DeclaredShape, FriProfile as CoreProfile};
        let digest_hex = "33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8";
        let hc_hex = "00".repeat(31) + "2a";
        let mut cfg = parse_aggregation_config("100,3,100,210000,256").unwrap();
        assert_eq!(cfg.bond, 100 * UNITS_PER_RAND);
        assert_eq!(cfg.max_covers, 3);
        assert_eq!(cfg.subsidy_base, 100 * UNITS_PER_RAND);
        assert_eq!(cfg.halving_blocks, 210_000);
        assert_eq!(cfg.window, 256);
        let shape = parse_admitted_shape(&format!("production,21,12,10,0,0,2,16,{hc_hex},{digest_hex}")).unwrap();
        assert_eq!(
            shape.shape,
            DeclaredShape {
                profile: CoreProfile::Production,
                tier: 21,
                program_log_height: 12,
                input_log_height: 10,
                keccak_log_height: 0,
                sha256_log_height: 0,
                public_log_height: 2,
                mem_log_height: 16,
            }
        );
        assert_eq!(shape.hc, randprotocol_core::Hash([0u8; 31].into_iter().chain([0x2a]).collect::<Vec<u8>>().try_into().unwrap()));
        assert_eq!(
            shape.aggregate_program_digest,
            [0x33a94ec690bb7cbe, 0x5a3d456496746099, 0x6277ac61b539f652, 0x5b5fe7f92992a1c8],
            "the digest words, in the docs' own order"
        );
        // The placeholder: all-zero digest words, refused by name.
        let mut placeholder = parse_aggregation_config("100,3,100,210000,256").unwrap();
        let mut bad = parse_admitted_shape(&format!("production,21,12,10,0,0,2,16,{hc_hex},{digest_hex}")).unwrap();
        bad.aggregate_program_digest = [0; 4];
        placeholder.admitted_shapes = vec![bad];
        let mut g = pinned_genesis();
        g.aggregation = Some(placeholder);
        match g.build(&ZkExecutor::new(FriProfile::Test)) {
            Err(randprotocol_core::genesis::GenesisError::BadAggregationConfig(m)) => {
                assert!(m.contains("placeholder"), "{m}");
            }
            other => panic!("the placeholder must be refused, got {other:?}"),
        }
        // CHAIN9-1: a Production shape on this test-profile genesis is refused by name — the
        // admitted profile must be the chain's own (audit v3).
        let mut g_bad_profile = pinned_genesis();
        let mut bad_profile = cfg.clone();
        bad_profile.admitted_shapes = vec![shape.clone()];
        g_bad_profile.aggregation = Some(bad_profile);
        match g_bad_profile.build(&ZkExecutor::new(FriProfile::Test)) {
            Err(randprotocol_core::genesis::GenesisError::BadAggregationConfig(m)) => {
                assert!(m.contains("Production"), "{m}");
            }
            other => panic!("a Production shape on a test chain must be refused, got {other:?}"),
        }
        // And the real thing builds, with the register empty and the gated root — at the chain's
        // own profile (tier 19 is the test profile's admitted tier).
        let test_shape = parse_admitted_shape(&format!("test,19,12,10,0,0,2,16,{hc_hex},{digest_hex}")).unwrap();
        cfg.admitted_shapes = vec![test_shape];
        let mut g2 = pinned_genesis();
        g2.aggregation = Some(cfg);
        let built = g2.build(&ZkExecutor::new(FriProfile::Test)).unwrap();
        assert!(built.ledger.aggregators().is_empty());
        assert!(built.ledger.aggregation().is_some());
    }

    /// Chain 12, the running chain, byte for byte: its genesis file has no `max_program_words`,
    /// so it must build the very hash its fleet runs on (`deploy/run-a.sh`'s `data-a-605eb783`):
    /// an optional genesis field must never move a genesis that leaves it out.
    ///
    /// That is all this pins. It does **not** make this build safe to run on chain 12: the build
    /// is chain-13-only. `Action::Deploy`, `ProgramRecord` and `CallReceipt` changed encoding (the
    /// public words, `public_digest`/`public_len`, `h_pub`), non-canonical proof encodings are now
    /// refused, and the sync wire carries byte strings, so it must not be same-chain-updated onto
    /// chain 12 (CHANGELOG, v0.4 Known limits).
    #[test]
    fn chain_12s_genesis_file_still_builds_chain_12() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain12.json");
        let gen = Genesis::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(gen.max_program_words, None, "chain 12 predates the field");
        assert_eq!(
            (gen.max_proof_bytes, gen.max_block_bytes, gen.max_call_envelope_bytes, gen.max_program_public_words),
            (None, None, None, None),
            "and the call-limits fields"
        );
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let state = gen.build(executor.as_ref()).unwrap();
        assert_eq!(state.hash().to_hex(), "605eb7830963833ef897455b98cd2a641aec58e0291460898a5d19ab88760ef0");
        assert_eq!(state.ledger.max_program_words(), randprotocol_core::gas::MAX_PROGRAM_WORDS);
        assert_eq!(state.ledger.max_proof_bytes(), randprotocol_core::gas::MAX_PROOF_BYTES);
        assert_eq!(state.ledger.max_block_bytes(), randprotocol_core::gas::MAX_BLOCK_BYTES);
        assert_eq!(state.ledger.max_call_envelope_bytes(), randprotocol_core::types::actions::MAX_CALL_ENVELOPE_BYTES);
        assert_eq!(state.ledger.max_program_public_words(), 0);
        // Rewriting the file through today's serializer adds none of the new fields.
        let rewritten = gen.to_json();
        for name in ["max_proof_bytes", "max_block_bytes", "max_call_envelope_bytes", "max_program_public_words"] {
            assert!(!rewritten.contains(name), "{name} appeared in chain 12's file");
        }
    }

    /// Chain 13, the running chain, byte for byte, after the RPL `tokens` gate (Task 2 of the
    /// RPL token standard): it has no `bridge` and no `tokens` section, so the gate must not
    /// move its hash by so much as one bit.
    #[test]
    fn chain_13s_genesis_file_still_builds_chain_13() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain13.json");
        let gen = Genesis::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(gen.bridge.is_none() && gen.tokens.is_none());
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let state = gen.build(executor.as_ref()).unwrap();
        assert_eq!(state.hash().to_hex(), "8123ccac1883a45750e4df6964fb7cd3f0b321798cde4c0ef406a0293939ece3");
        assert!(state.ledger.tokens().is_none());
        // Since the hidden-asset bundle (H3) the file still *builds* to chain 13's hash — the hash
        // commits to the file's own `hc_bundle`, not to this build's guest — but it pins the
        // retired 2-in-2-out guest, so this build refuses to run it: a chain-14 build is not a
        // chain-13 node.
        assert_eq!(state.hc_bundle, ZkExecutor::hc_legacy_bundle(), "chain 13 pins the retired guest");
        assert_ne!(state.hc_bundle, ZkExecutor::hc_bundle());
        let refused = node::check_build_runs_genesis(&state, &ZkExecutor::hc_bundle()).unwrap_err().to_string();
        assert!(refused.contains("differs from the genesis hc_bundle"), "{refused}");
    }

    /// `rand-node genesis --max-program-words N` writes the field; without the flag the file has
    /// no such field at all.
    #[test]
    fn the_genesis_command_takes_max_program_words() {
        let parse = |extra: &[&str]| {
            let mut args = vec!["rand-node", "genesis", "--validator", "k,1000,p"];
            args.extend_from_slice(extra);
            match Cli::try_parse_from(args).unwrap().cmd {
                Cmd::Genesis { max_program_words, .. } => max_program_words,
                _ => unreachable!(),
            }
        };
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["--max-program-words", "65535"]), Some(65_535));
        let mut g = pinned_genesis();
        g.max_program_words = Some(65_535);
        let built = g.build(&ZkExecutor::new(FriProfile::Test)).unwrap();
        assert_eq!(built.ledger.max_program_words(), 65_535);
        assert_ne!(built.hash(), pinned_genesis().build(&ZkExecutor::new(FriProfile::Test)).unwrap().hash());
    }

    /// `rand-node genesis` takes the four call-limits flags; each writes its field, and without
    /// them the file has none of them.
    #[test]
    fn the_genesis_command_takes_the_call_limits() {
        let parse = |extra: &[&str]| {
            let mut args = vec!["rand-node", "genesis", "--validator", "k,1000,p"];
            args.extend_from_slice(extra);
            match Cli::try_parse_from(args).unwrap().cmd {
                Cmd::Genesis { max_proof_bytes, max_block_bytes, max_call_envelope_bytes, max_program_public_words, .. } => {
                    (max_proof_bytes, max_block_bytes, max_call_envelope_bytes, max_program_public_words)
                }
                _ => unreachable!(),
            }
        };
        assert_eq!(parse(&[]), (None, None, None, None));
        let chain13 = parse(&[
            "--max-proof-bytes",
            "8388608",
            "--max-block-bytes",
            "20971520",
            "--max-call-envelope-bytes",
            "65536",
            "--max-program-public-words",
            "32768",
        ]);
        assert_eq!(chain13, (Some(8 << 20), Some(20 << 20), Some(65_536), Some(32_768)));
        let mut g = pinned_genesis();
        (g.max_proof_bytes, g.max_block_bytes, g.max_call_envelope_bytes, g.max_program_public_words) = chain13;
        let json = g.to_json();
        assert!(json.contains("\"max_proof_bytes\": 8388608"));
        assert!(json.contains("\"max_block_bytes\": 20971520"));
        assert!(json.contains("\"max_call_envelope_bytes\": 65536"));
        assert!(json.contains("\"max_program_public_words\": 32768"));
        let built = g.build(&ZkExecutor::new(FriProfile::Test)).unwrap();
        assert_eq!(built.ledger.max_proof_bytes(), 8 << 20);
        assert_eq!(built.ledger.max_block_bytes(), 20 << 20);
        assert_eq!(built.ledger.max_call_envelope_bytes(), 65_536);
        assert_eq!(built.ledger.max_program_public_words(), 32_768);
        assert_ne!(built.hash(), pinned_genesis().build(&ZkExecutor::new(FriProfile::Test)).unwrap().hash());
    }

    /// The owner of the pinned genesis's one deposit note.
    fn pinned_payee() -> ShieldedAddress {
        randprotocol_zkvm::address::address_of(&SpendKey([7; 8]).viewing_key())
    }

    /// The exact genesis this test builds, so the pinned hash below has one definition.
    ///
    /// The note's commitment randomness is fixed here rather than drawn, which is the one thing
    /// that separates this from what `Cmd::Genesis` writes: a real genesis note must be
    /// unguessable (see `deposit_note`), and an unguessable note cannot be pinned. Everything
    /// the hash is meant to catch — the bundle guest, the note word layout, the genesis binding
    /// — is unaffected by holding `r` still.
    fn pinned_genesis() -> Genesis {
        let to = pinned_payee();
        let note = Note { pk: to.pk, from: [0; 8], amount: 5 * UNITS_PER_RAND, asset: 0, time: 0, r: [7; 8] };
        Genesis {
            chain_id: 7,
            timestamp_ms: 1_700_000_000_000,
            validators: vec![
                GenesisValidator {
                    public_key: Keypair::from_seed([1; 32]).unwrap().public_key().clone(),
                    stake: MIN_STAKE as u128,
                    payout: pinned_payee().to_string(),
                },
                GenesisValidator {
                    public_key: Keypair::from_seed([2; 32]).unwrap().public_key().clone(),
                    stake: 2 * MIN_STAKE as u128,
                    payout: pinned_payee().to_string(),
                },
            ],
            alloc: vec![seal_deposit(&to, &note).unwrap()],
            faucet: true,
            confidential: true,
            fri_profile: "test".into(),
            hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
            bridge: None,
            tokens: None,
            aggregation: None,
            epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
            max_program_words: None,
            max_proof_bytes: None,
            max_block_bytes: None,
            max_call_envelope_bytes: None,
            max_program_public_words: None,
        }
    }

    /// A chain's identity, pinned. This hex changes whenever the bundle guest, the note format,
    /// or the genesis binding changes — all three are consensus-breaking, so a diff here is the
    /// intended alarm, not a nuisance. Regenerate it deliberately (print `state.hash()`), and
    /// only together with a chain restart.
    ///
    /// Re-pinned 2026-09-22, with the drift explained: the v0.3-era hash computed as `78390828…`
    /// against the old pin `fb5881c8…`, and the v0.5 chain-14 build computed `69010a43…`. Between
    /// those pins all three alarm categories fired deliberately: the transaction binding
    /// (`rand-tx-bind-1`, v0.5), the hidden-asset bundle guest replacing the two-bundle guest
    /// (`hc_bundle` moves, v0.5 chain 14), and the new genesis sections (tokens, bridge, the call
    /// limits, v0.4/v0.5). Chain 14 was the restart this re-pin rides.
    #[test]
    fn the_genesis_hash_is_pinned() {
        let ex = ZkExecutor::new(FriProfile::Test);
        let state = pinned_genesis().build(&ex).unwrap();
        // S2 Task 1: the register. This moved from 19df87d5… (itself moved from 700f28e8… by
        // the scaffold's `epoch_blocks` binding) for deliberate, consensus-breaking reasons: the
        // genesis binding now covers every validator's payout address, the state root's
        // validator leaf is `rand-validator-leaf-2` over the v2 entry (a length-prefixed
        // unbonding queue, the payout address, the nonce), and this genesis's stakes are the
        // staking minimum, which genesis now requires.
        assert_eq!(state.hash().to_hex(), "69010a43a7275d1ff2c25d8b774728f4a31148968dcd186f89da16550e87ffb5");
        // The envelope is resealed on every call and must not move the hash: only the
        // commitment and the amount are bound.
        let again = pinned_genesis().build(&ex).unwrap();
        assert_ne!(again.notes[0].1, state.notes[0].1, "a fresh envelope per build");
        assert_eq!(again.hash(), state.hash());
    }

    /// The one place a note is built outside the chain and then recomputed by it: a withdraw.
    ///
    /// The CLI seals its envelope against a note it constructs itself, and the ledger derives the
    /// commitment it will actually append from the action's public fields. If those two ever
    /// disagree the withdraw still pays — into a note the payee cannot find, because the envelope
    /// beside it opens to a different commitment. So this pins the CLI's note to
    /// `ConfidentialExecutor::note_commitment` field for field, and checks that the payout wallet
    /// really opens it.
    #[test]
    fn the_cli_withdraw_note_is_the_note_the_ledger_derives() {
        use randprotocol_core::confidential::ConfidentialExecutor;
        let payee = SpendKey([7; 8]);
        let payout = randprotocol_zkvm::address::address_of(&payee.viewing_key());
        let base = randprotocol_core::gas::BUNDLE_BASE;
        let amount = 5 * UNITS_PER_RAND;
        let time = 1994;
        let (note, envelope) = sealed_withdraw_note(&payout, amount - base, time).unwrap();

        // Exactly what `ledger::staking::withdraw_note` hashes: the payout key, no sender, the
        // amount less the base, asset 0, the action's `time`, and the blinding the action carries.
        let ex = ZkExecutor::new(FriProfile::Test);
        let cm = ex.note_commitment(&payout.pk, &[0; 8], amount - base, 0, time, &note.r);
        assert_eq!(note.commitment(), cm, "the CLI's note is not the note the chain will derive");
        // The base really is taken off here: a note for the gross amount is a different note.
        assert_ne!(ex.note_commitment(&payout.pk, &[0; 8], amount, 0, time, &note.r), cm);
        // And a note at another time is another note, which is why the action carries `time`.
        assert_ne!(ex.note_commitment(&payout.pk, &[0; 8], amount - base, 0, time + 1, &note.r), cm);

        // The envelope opens to that note for the payout wallet, so the payee finds it by
        // scanning rather than by being told it exists.
        let (_, opened) = randprotocol_zkvm::address::envelope_from_core(&envelope)
            .open_as_receiver(cm, &payee.viewing_key())
            .expect("the payout wallet opens its own note");
        assert_eq!(opened, note);
        assert_eq!(opened.amount, amount - base);
    }

    /// Two allocations of the same amount to the same address are two different notes. A
    /// deterministic commitment would let anyone confirm a guess at a genesis note's owner and
    /// value by recomputing it, which is the property the whole scheme exists to deny.
    #[test]
    fn deposit_notes_are_never_the_same_note_twice() {
        let addr = pinned_payee().to_string();
        let a = deposit_note(&addr, 5).unwrap();
        let b = deposit_note(&addr, 5).unwrap();
        assert_eq!(a.amount, b.amount);
        assert_ne!(a.cm, b.cm, "genesis notes must carry fresh commitment randomness");
        assert_ne!(a.envelope.kem_ct, b.envelope.kem_ct, "a fresh KEM ciphertext per note");
        // Anything that is not a shielded address is refused, with the address in the message.
        let err = deposit_note("not-an-address", 1).unwrap_err().to_string();
        assert!(err.contains("not-an-address"), "{err}");
    }
}
