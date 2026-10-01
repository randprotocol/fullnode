use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use libp2p::Multiaddr;
use randprotocol_client::wallet;
use randprotocol_client::RpcClient;
use randprotocol_core::genesis::{EnvelopeHex, Genesis, GenesisNote, GenesisOpening, GenesisValidator, TokensConfig};
use randprotocol_core::notes::{word8_to_hex, Envelope, EnvelopeFormat, ShieldedAddress};
use randprotocol_core::types::actions::{admit_validator_message, registration_message_v2, AggregatorRegistration, Registration};
use randprotocol_zkvm::machine::FriProfile;
use randprotocol_core::{format_amount, parse_amount};
use randprotocol_core::{Keypair, PublicKey, UNITS_PER_RAND};
use randprotocol_node::keyfile::{load_keypair, KeyFile};
use randprotocol_node::node::{self, NodeConfig};
use randprotocol_node::storage::{Storage, VerifyMode};
use randprotocol_node::hosted_prover::{self, HostedProver};
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
fn deposit_note(addr: &str, amount: u64, format: EnvelopeFormat) -> Result<GenesisNote> {
    alloc_note(addr, amount, 0, format)
}

/// [`deposit_note`] at any asset: 0 is RAND, a non-zero `asset` the registry index of a bridged
/// token the genesis lists (`rand-node alloc-note --asset`). `from` is the zero word at every
/// asset — the note `Genesis::build` recomputes, and the deposit commitment a `BridgeAttest`
/// would append for the same token.
/// `alloc-note --amount` in base units: RAND's nine decimals at asset 0, a bridged token's
/// `BRIDGE_DECIMALS` (eight) at any other index. One scale for both put 10 zUSD at 10^10 units.
fn alloc_note_units(amount: &str, asset: u32) -> Result<u64> {
    let rand_units = parse_amount(amount)?;
    if asset == 0 {
        return Ok(rand_units);
    }
    let shift = 10u64.pow(randprotocol_core::types::TOKEN_DECIMALS - u32::from(randprotocol_core::ledger::tokens::BRIDGE_DECIMALS));
    anyhow::ensure!(rand_units % shift == 0, "{amount} has more than eight decimals, a bridged token's precision");
    Ok(rand_units / shift)
}

/// `rand-node alloc-note`: the amount in its display units, sealed in the envelope format the
/// genesis's `envelope_bytes` names (`--envelope-bytes`), legacy when it names none.
fn alloc_note_cmd(to: &str, amount: &str, asset: u32, envelope_bytes: Option<u32>) -> Result<GenesisNote> {
    let amount = alloc_note_units(amount, asset)?;
    alloc_note(to, amount, asset, EnvelopeFormat::for_chain(envelope_bytes))
}

/// The gas section's one-line summary, printed by `genesis` and `init` alike (design
/// 2026-09-28 §4.2, §4.3, §7.1): `gas: none` on a chain without one.
fn gas_summary(g: Option<&randprotocol_core::gas::GasConfig>) -> String {
    match g {
        None => "gas: none".to_string(),
        Some(g) => {
            let dynamic = match &g.dynamic {
                None => "off".to_string(),
                Some(d) => format!(
                    "target {} B / {} gas, adjust {} bps, floor {}/{}, ceiling {}/{}, byte load {}",
                    d.target_block_bytes,
                    d.target_block_gas,
                    d.adjust_bps,
                    d.min_gas_price,
                    d.min_byte_price,
                    d.max_gas_price.map_or("none".to_string(), |m| m.to_string()),
                    d.max_byte_price.map_or("none".to_string(), |m| m.to_string()),
                    if d.byte_load.is_some() { "paying" } else { "all" },
                ),
            };
            format!(
                "gas: price {}/gas, {}/KiB, bundle limit {}, dynamic: {dynamic}",
                g.gas_price, g.byte_price, g.bundle_gas_limit
            )
        }
    }
}

fn alloc_note(addr: &str, amount: u64, asset: u32, format: EnvelopeFormat) -> Result<GenesisNote> {
    let to = ShieldedAddress::parse(addr).with_context(|| format!("{addr} is not a shielded address"))?;
    seal_deposit(&to, &Note::new(to.pk, [0; 8], amount, asset, 0), format)
}

/// Seal an already-built deposit note to its owner, in the chain's envelope `format`
/// (`EnvelopeFormat::for_chain(genesis.envelope_bytes)`, spec 2026-09-26 §2.4).
///
/// Sealed under a throwaway sender key, exactly as a faucet mint is — a genesis has no identity
/// to keep an outgoing-viewing record for, and the key is dropped before this returns, so only
/// the holder of the owner's spend key can ever open the note. The envelope does not enter the
/// genesis hash (which binds the commitment and the amount), so its randomness is free. No
/// memo: a genesis alloc has no sender to write one for.
fn seal_deposit(to: &ShieldedAddress, note: &Note, format: EnvelopeFormat) -> Result<GenesisNote> {
    let throwaway = SpendKey::random().viewing_key();
    let envelope = randprotocol_zkvm::address::seal_note_as(format, &throwaway, to, note, &TxKey::random(), "")
        .map_err(|e| anyhow::anyhow!("sealing a note to {}: {e}", to.to_string()))?;
    Ok(GenesisNote {
        cm: word8_to_hex(&note.commitment()),
        envelope: EnvelopeHex::from_envelope(&envelope),
        amount: note.amount,
        // Core I-2: what the commitment opens to. `from` is not written down — `Genesis::build`
        // recomputes the commitment with `from` zero at the note's `asset` (0, RAND, is left out
        // of the file), which is what makes an alloc note auditable as the asset and amount it
        // declares rather than an opaque leaf.
        // Required on any chain with a `tokens` section; emitted always, so a file cut with this
        // build is verifiable whatever section it ends up carrying.
        opening: Some(GenesisOpening {
            pk: word8_to_hex(&note.pk),
            time: note.time,
            r: word8_to_hex(&note.r),
            asset: note.asset,
        }),
    })
}

/// The note a `withdraw` pays and the envelope that opens it, sealed to `payout` under a
/// throwaway sender key — the same shape a genesis deposit uses (see [`seal_deposit`]), in the
/// chain's envelope `format` (its caller reads `rand_getLimits`' `envelope_bytes`; absent on an
/// older node, `EnvelopeFormat::for_chain` falls back to `Legacy`).
///
/// `amount` is what the note is worth, i.e. the withdrawal less the bundle base. The chain never
/// sees this note: it recomputes the commitment from the action's public fields
/// (`ledger::staking::withdraw_note`), so these five fields have to be exactly the five the ledger
/// hashes, or the withdraw pays a note whose envelope opens to nothing the payee can use. That
/// agreement is what `the_cli_withdraw_note_is_the_note_the_ledger_derives` pins. No memo: none of
/// `withdraw`, `withdraw-aggregator` or `aggregate` has a memo to write.
fn sealed_withdraw_note(payout: &ShieldedAddress, amount: u64, time: u32, format: EnvelopeFormat) -> Result<(Note, Envelope)> {
    let note = Note::new(payout.pk, [0; 8], amount, 0, time);
    let throwaway = SpendKey::random().viewing_key();
    let envelope = randprotocol_zkvm::address::seal_note_as(format, &throwaway, payout, &note, &TxKey::random(), "")
        .map_err(|e| anyhow::anyhow!("sealing the payout note: {e}"))?;
    Ok((note, envelope))
}

/// `sealed_withdraw_note`'s format, read off the live chain: one `rand_getLimits` call (cached by
/// `rpc` itself, task 7) for its `envelope_bytes` field. A node old enough to have no such
/// method, or whose reply carries no such field (it predates the genesis field), leaves
/// `envelope_bytes` at `None` — the same input that makes `EnvelopeFormat::for_chain` answer
/// `Legacy` for a chain that never declared one at all, so `withdraw`, `aggregator withdraw` and
/// `aggregate` all fall back the same way. `chain_id` is the transaction's own: on a chain pinned
/// as pre-`envelope_bytes` the node's memo claim is not believed (issue #64,
/// `randprotocol_client::LEGACY_ENVELOPE_CHAIN_IDS`).
async fn envelope_format(rpc: &RpcClient, chain_id: u64) -> Result<EnvelopeFormat> {
    rpc.envelope_format(chain_id).await
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

/// The candidate an `admit` command names (audit v6, STAKE-2), in any of the forms an operator
/// has to hand: the validator public key in hex (`rand-node address` prints it), the
/// registration blob `rand-node register` prints (the candidate's key is inside it), or a file
/// holding either — the last whitespace-separated word of the file, so the two lines `register`
/// prints can be saved as they are.
fn parse_candidate(spec: &str) -> Result<PublicKey> {
    let text = std::fs::read_to_string(spec).unwrap_or_else(|_| spec.to_string());
    let word = text.split_whitespace().last().context("--candidate is empty")?;
    let word = word.strip_prefix("0x").unwrap_or(word);
    if let Ok(key) = PublicKey::from_hex(word) {
        return Ok(key);
    }
    let bytes = hex::decode(word)
        .map_err(|_| anyhow::anyhow!("--candidate is neither a validator public key in hex, a registration blob, nor a file holding one"))?;
    let registration = Registration::decode(&bytes)
        .map_err(|_| anyhow::anyhow!("--candidate is hex, but neither a {}-byte validator public key nor a registration blob", randprotocol_core::crypto::PUBLIC_KEY_LEN))?;
    anyhow::ensure!(
        registration.public_key.as_bytes().len() == randprotocol_core::crypto::PUBLIC_KEY_LEN,
        "the registration's key is not a validator public key"
    );
    Ok(registration.public_key)
}

/// One validator's vote to admit `candidate` on the chain of `genesis`, as the line `admit sign`
/// prints and `admit submit --signature` reads: `<voter public key hex>:<signature hex>`.
fn admit_vote_line(voter: &Keypair, genesis: &randprotocol_core::Hash, candidate: &PublicKey) -> String {
    let signature = voter.sign(admit_validator_message(genesis, &candidate.address()).as_bytes());
    format!("{}:{}", voter.public_key().to_hex(), hex::encode(signature.as_bytes()))
}

/// The `AdmitValidator` action over `lines` (each an [`admit_vote_line`]): every vote checked
/// against this chain's admission message before anything is sent — a vote signed for another
/// genesis or another candidate is named here rather than refused by the node — a voter listed
/// once, and the votes in the ascending voter order the ledger requires.
fn admit_action(genesis: &randprotocol_core::Hash, candidate: &PublicKey, lines: &[String]) -> Result<randprotocol_core::Action> {
    let message = admit_validator_message(genesis, &candidate.address());
    let mut signatures = Vec::with_capacity(lines.len());
    for line in lines {
        let (key, sig) = line.trim().split_once(':').context("a --signature is `<voter public key hex>:<signature hex>`, as `admit sign` prints it")?;
        let key = PublicKey::from_hex(key).map_err(|e| anyhow::anyhow!("a --signature's voter key: {e}"))?;
        let sig = randprotocol_core::Signature::from_bytes(&hex::decode(sig).context("a --signature's signature is not hex")?)
            .map_err(|e| anyhow::anyhow!("the vote by {}: {e}", key.address()))?;
        anyhow::ensure!(
            key.verify(message.as_bytes(), &sig),
            "the vote by {} is not a signature over this chain's admission of {} (another genesis hash, or another candidate?)",
            key.address(),
            candidate.address()
        );
        signatures.push((key, sig));
    }
    signatures.sort_by_key(|(key, _)| key.address());
    if let Some(w) = signatures.windows(2).find(|w| w[0].0.address() == w[1].0.address()) {
        anyhow::bail!("validator {} votes twice; list each vote once", w[0].0.address());
    }
    Ok(randprotocol_core::Action::AdmitValidator { candidate: candidate.clone(), signatures })
}

#[derive(Parser)]
#[command(name = "rand-node", version, about = "RAND full node: HotStuff BFT consensus, p2p discovery, shielded note ledger")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Audit v6, ZK-5a: run `init`, `run` or `verify` on a genesis whose `fri_profile` is `test`
    /// — 16 FRI queries and 4 grinding bits, about 17 bits of soundness, no protection against a
    /// forged proof. A release node refuses such a genesis without this (or
    /// `RAND_ALLOW_TEST_FRI_PROFILE=1`, for the test harnesses). Never on a chain with value.
    #[arg(long, global = true)]
    allow_test_fri_profile: bool,
}

/// Audit v6, ZK-5a: whoever writes or alters a genesis file can name the `test` FRI profile, and
/// a validator started from that file would run it — proving under 16 queries and 4 grinding
/// bits, ~17 bits, where a forgery is a few thousand attempts. The library (`node::start`, the
/// suites' path) is unchanged; the *binary* refuses the profile at `init`, `run` and `verify`
/// unless told, in so many words, that this is a test.
fn refuse_test_fri_profile(profile: &str, allowed: bool) -> Result<()> {
    if profile == "test" && !allowed {
        anyhow::bail!(
            "this genesis names fri_profile \"test\": 16 FRI queries and 4 grinding bits, about 17 bits of soundness — a \
             forged proof is a few thousand attempts, so it protects nothing. A release node refuses it; pass \
             --allow-test-fri-profile (or set RAND_ALLOW_TEST_FRI_PROFILE=1) only for a test harness"
        );
    }
    Ok(())
}

/// The flag, or the environment variable the test harnesses set.
fn test_fri_profile_allowed(cli: &Cli) -> bool {
    cli.allow_test_fri_profile || std::env::var("RAND_ALLOW_TEST_FRI_PROFILE").is_ok_and(|v| v == "1")
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new Dilithium2 key file (refuses to overwrite an existing one).
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
        /// at least 2 * the proof cap + 1 MiB,
        /// 3 * the proof cap + 1 MiB with --auth-guest, where a `Call` carries three proofs). Omitted, today's 4 MiB; given, it is part of the
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
        /// The exact note-envelope size (spec 2026-09-26 §2.4): every note envelope — a bundle
        /// output, a faucet mint, a withdraw, a bridge deposit, a genesis alloc — must be exactly
        /// this many bytes, which lets every one of them carry a memo. Only `notes::
        /// MEMO_ENVELOPE_BYTES` (1860) is accepted today. Omitted entirely when absent, so a
        /// chain without the flag hashes byte-for-byte as before; given, it is part of the
        /// genesis hash and is set before this command's own `--alloc` notes are sealed, so they
        /// come out the declared length too.
        #[arg(long)]
        envelope_bytes: Option<u32>,
        /// Genesis vesting (`docs/vesting.md`): the timelocked allocations, as a `VestingConfig`
        /// JSON file (`{"entries": [{"id", "class", "beneficiary", "revoker"?, "amount",
        /// "start_ms", "cliff_ms", "linear_ms", "step_ms"?}]}`). Omitted entirely when absent.
        #[arg(long, value_name = "VESTING.JSON")]
        vesting: Option<PathBuf>,
        /// The bundle guest the chain pins as `hc_bundle`: `v1` (the hidden-asset guest chains 14
        /// and 15 run) or `v2`, the branch-free guest whose instruction and lookup counts do not
        /// depend on which input slots are real or on the spent leaves' indices (INT-2 / GV-1).
        /// Both are the same statement and proof shape; this build verifies either. `v3` is the
        /// split-authorisation guest (delegated proving Phase 2): it takes the viewing key's `nk`
        /// and a salt instead of the spend key and publishes `c = H(AUTH, nk, salt)`, which a
        /// second, tiny auth proof over the spend key must match — so it needs `--auth-guest`.
        #[arg(long, value_name = "v1|v2|v3", default_value = "v1", value_parser = ["v1", "v2", "v3"])]
        bundle_guest: String,
        /// Pin this build's auth guest as the genesis `hc_auth` (split authorisation): every
        /// bundle then carries an auth proof over the spend key, bound to its transaction, whose
        /// output equals the bundle's `auth_commit`. Required with `--bundle-guest v3` and refused
        /// with `v1`/`v2` — the two come as a pair (only v3 publishes the commitment).
        #[arg(long)]
        auth_guest: bool,
        /// Turn on the v0.6 rules as validity rules (`hardening_v6`): the pc window, uncallable
        /// deploys, canonical proof shapes and proof-of-work words, the call binding and the
        /// program-table floor. Absent, a node still refuses those at its pool, as policy.
        #[arg(long)]
        hardening_v6: bool,
        /// The gas section (design 2026-09-28 §4.2, §4.3, §7.1): units of RAND per gas. Given,
        /// the file gets a `gas` section (`metering: "circuit"`) and the price is part of the
        /// genesis hash; omitted, the file has none, byte-for-byte today's shape. The section is
        /// written only when this flag is given.
        #[arg(long)]
        gas_price: Option<u64>,
        /// The gas section's price per KiB (or part of one) of call proof and input envelope,
        /// from byte 0. Refused without `--gas-price`; defaults to
        /// [`randprotocol_core::gas::BYTE_PRICE_DEFAULT`] when that is given and this is not.
        #[arg(long)]
        byte_price: Option<u64>,
        /// The gas section's flat bundle gas limit (spec §4.3): every bundle proof's declared
        /// `GAS_LIMIT` must equal this exactly, and genesis accepts only `gas_max(14, 0, 0)` =
        /// `20 479` (today's tier-14 bundle guest), the default when `--gas-price` is given and
        /// this is not. Refused without `--gas-price`.
        #[arg(long)]
        bundle_gas_limit: Option<u64>,
        /// Phase 2 (spec §7.1): the dynamic price controller, as
        /// `<target_block_bytes>,<target_block_gas>,<adjust_bps>`. The floors (`min_gas_price`,
        /// `min_byte_price`) are set to the section's own starting prices. Refused without
        /// `--gas-price`; omitted, the prices this command writes never move.
        #[arg(long, value_name = "TARGET_BYTES,TARGET_GAS,ADJUST_BPS")]
        gas_dynamic: Option<String>,
        /// Audit v6, POOL-2: the ceiling the controller never lifts `gas_price` over (units);
        /// at least `--gas-price`. Refused without `--gas-dynamic`; omitted, no ceiling.
        #[arg(long)]
        max_gas_price: Option<u64>,
        /// The ceiling on `byte_price`, the same way; at least `--byte-price`.
        #[arg(long)]
        max_byte_price: Option<u64>,
        /// Audit v6, POOL-2: which bytes move `byte_price` — `paying` for a call's proof and
        /// input envelope only (a transfer, which pays no byte price, then moves none). Refused
        /// without `--gas-dynamic`; omitted, every transaction's bytes count (chain 18's rule).
        #[arg(long, value_name = "paying")]
        gas_byte_load: Option<String>,
        /// The `staking` section, as a `StakingConfig` JSON file (`{"faucet_budget_per_epoch": …,
        /// "bond_activation_epochs": …, …}`; `docs/staking.md` lists every field, audit v6's
        /// `admission_by_vote` among them). `Genesis::build` validates it. Omitted entirely when
        /// absent, so a chain without the flag hashes byte-for-byte as before — a cut script may
        /// still splice the section in by hand, as chains 15–18 were cut.
        #[arg(long, value_name = "STAKING.JSON")]
        staking: Option<PathBuf>,
        /// The consensus signing domain (audit v4): `1` binds every vote, new-view and proposal
        /// to this genesis. Omitted, the file has no such field (domain 0, chain 14's messages).
        #[arg(long, value_name = "0|1")]
        consensus_domain: Option<u32>,
        /// The testnet marker (audit v6, STAKE-2): the file says `"testnet": true`, which is
        /// what lets `--faucet` sit beside a `bridge` section spliced in later — a chain holding
        /// custody hands out no free RAND unless its genesis says it is a testnet. Part of the
        /// genesis hash when given; omitted, the file has no such field.
        #[arg(long)]
        testnet: bool,
        /// BIND-1 (audit v6): the top-level `binding_domain`. `1` binds the genesis hash into
        /// every transaction binding and every signed action message (a faucet mint, unbond,
        /// withdraw, the RPL token messages, the aggregator actions, the bridge governance
        /// messages), so a proof or a signature for this chain verifies on no other chain that
        /// shares its chain id; part of the genesis hash. Omitted, the file has no field —
        /// chains 14 to 19's rules, byte for byte — and **a wallet signs nothing for a chain id
        /// outside 14–19 without it**: every new chain from chain 20 is cut with `--binding-domain 1`.
        #[arg(long, value_name = "0|1")]
        binding_domain: Option<u32>,
        /// Issue #118: the top-level `proof_window_blocks`, 256..=4096 — how old, in blocks, a
        /// bundle's anchor and its `time` may be (one window for both). Omitted, the file has no
        /// field: 256 blocks, ~300 s at chain 18's 1.17 s blocks, which a delegated proof on a slow
        /// prover can miss. Part of the genesis hash when given; `docs/deploy.md` recommends 1024.
        #[arg(long, value_name = "BLOCKS")]
        proof_window_blocks: Option<u64>,
    },
    /// Print one genesis alloc note as JSON — the object that goes into a genesis file's `alloc`
    /// list — sealed to `--to` exactly as `genesis --alloc` seals one, so the owner's wallet finds
    /// it on its first scan. With `--asset <index>` it is a note of the bridged token the genesis
    /// lists at that index (the first listed token is 1): its opening carries the `asset`, and the
    /// genesis must give that token's backings `locked` amounts summing to exactly its notes
    /// (chain 15's genesis custody). A bridged genesis cannot be written by `genesis` itself —
    /// its `bridge` section is spliced in afterwards — so a token note is spliced in the same way.
    AllocNote {
        /// The owner, a `rand1…` shielded address.
        #[arg(long)]
        to: String,
        /// The amount in whole units, scaled by the asset's own decimals: nine for RAND at asset 0
        /// (`10` is 10 RAND), eight for a bridged token (`10` at asset 1 is 10 zUSD = 10^9 units).
        #[arg(long)]
        amount: String,
        /// The note's asset: 0 (RAND, the default) or a listed token's registry index.
        #[arg(long, default_value_t = 0)]
        asset: u32,
        /// The genesis's `envelope_bytes` (spec 2026-09-26 §2.4), when it sets one: the note is
        /// sealed in that envelope format, as `genesis --envelope-bytes` seals its own `--alloc`
        /// notes. Omitted, the legacy format — a genesis carrying `envelope_bytes` refuses such a
        /// note (`AllocEnvelopeSize`).
        #[arg(long)]
        envelope_bytes: Option<u32>,
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
        /// Bootstrap peer multiaddr (with /p2p/<peer-id>), repeatable. Its peer id is reserved:
        /// admitted past the inbound connection cap.
        #[arg(long)]
        bootstrap: Vec<Multiaddr>,
        /// A peer id admitted past the inbound connection cap and served from the validators'
        /// share of the sync budget (audit v6, NET-1), repeatable. Validators' ids are learned
        /// from their signed bindings and remembered across restarts; list them here for a freshly
        /// cut chain, whose store has none yet.
        #[arg(long = "reserved-peer", value_name = "PEER_ID")]
        reserved_peer: Vec<libp2p::PeerId>,
        /// Accept only gossip that carries a valid author signature, sequence number and source
        /// (gossipsub's strict validation; audit v6, CH-7). Every node signs what it publishes,
        /// so this drops only forged unsigned messages, and a strict node and a permissive one
        /// exchange honest gossip both ways.
        #[arg(long)]
        strict_gossip: bool,
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
        /// form (`pv::NUM` = 35 public values + the declared shape) once the window passes.
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
        /// A second, public JSON-RPC listener (audit v6, VK-2 / RPC-4): point a reverse proxy or
        /// an SSH forward at this, never at `--rpc`. It answers a fixed set of read methods and
        /// `rand_sendTransaction` — no viewing-key methods, no `rand_mint`, no `rand_getPeers` —
        /// takes no batch and no WebSocket, and meters every caller together (behind a proxy
        /// they all arrive from one address, and that address is loopback, which `--rpc` trusts).
        #[arg(long)]
        public_rpc: Option<SocketAddr>,
        /// Require a bearer token on the viewing-key methods of `--rpc`: the first line of this
        /// file, at least 32 characters, sent by the explorer as `Authorization: Bearer <token>`.
        /// With it, being on loopback is no longer enough (every process on the host is), and a
        /// caller anywhere that presents it is served. A file, so the token is not in `ps`.
        #[arg(long)]
        rpc_viewing_token_file: Option<PathBuf>,
        /// Refuse to start with less than this many MB free on the data directory's filesystem,
        /// and report `disk_low` in `rand_getHealth` under four times it (audit v4 OPS-3). Zero
        /// disables the guard.
        #[arg(long, default_value_t = 1024)]
        min_free_disk_mb: u64,
        /// Keep only this much block history (history pruning spec §1): `<n>m`, `<n>h` or
        /// `<n>d`, at least `1h`. Blocks whose timestamp is older than the head's minus this
        /// window lose their block, QC, transactions and receipts; the ledger stays. Never set
        /// on a mainnet node or on the testnet's archive.
        #[arg(long, value_parser = parse_prune_history)]
        prune_history: Option<Duration>,
        /// Host the delegated prover (`prover_*` JSON-RPC) on this address: its own listener,
        /// never a method of the public RPC, so it must differ from `--rpc`. The node refuses to
        /// start without `<prover-home>/prover.key.json` (make it with `rand-prover keygen`).
        #[arg(long)]
        prover: Option<SocketAddr>,
        /// Directory holding the prover's prover.key.json and pairings.json [default: <datadir>/prover].
        #[arg(long)]
        prover_home: Option<PathBuf>,
        /// Retired (VK-4): still parsed, so a unit file that passes it fails with the reason
        /// instead of an "unexpected argument"; `run` refuses to start when it is given.
        #[arg(long, hide = true)]
        prover_accept_spend_key: bool,
        /// Proofs the hosted prover runs at once.
        #[arg(long, default_value_t = 1)]
        prover_max_parallel: usize,
        /// Jobs the hosted prover queues beyond those running.
        #[arg(long, default_value_t = 8)]
        prover_max_queue: usize,
        /// Prove on the CUDA backend (a build with the `cuda` feature); no CPU fallback.
        #[arg(long)]
        prover_cuda: bool,
        /// Skip the free-memory gate that refuses a prover the machine cannot hold.
        #[arg(long)]
        prover_skip_memory_check: bool,
        /// A web origin whose pages may read the hosted prover's replies (repeatable). Given at
        /// least once, the values are the whole list; absent, browser extensions and loopback
        /// pages only (`docs/prover.md` §6.1). `*` allows every website.
        #[arg(long = "prover-allow-origin", value_name = "ORIGIN")]
        prover_allow_origin: Vec<String>,
        /// The fee every job sent to the hosted prover must pay, in RAND (display units, up to
        /// 9 decimals): one RAND output to --prover-fee-address inside the bundle proved.
        #[arg(long, value_name = "RAND", requires = "prover_fee_address")]
        prover_fee: Option<String>,
        /// The shielded address (`rand1…`) the hosted prover's fee is paid to.
        #[arg(long, value_name = "ADDRESS", requires = "prover_fee")]
        prover_fee_address: Option<String>,
        /// Units (10⁻⁹ RAND) per gas the pool demands of a call, over `gas_max` of its proof
        /// header (spec 2026-09-28 §4.1). Admission policy, not a chain rule. `0` with
        /// `--byte-price 0` runs no policy: the ledger's tier schedule alone.
        #[arg(long, default_value_t = randprotocol_core::gas::GAS_PRICE_DEFAULT)]
        gas_price: u64,
        /// Units per KiB (or part) of a call's proof and input envelope, from byte 0.
        #[arg(long, default_value_t = randprotocol_core::gas::BYTE_PRICE_DEFAULT)]
        byte_price: u64,
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
    /// A stopped validator's consensus safety state: read it, clear a recorded safety halt, or
    /// release a lock on a block that is lost for good. Every one of these opens the data
    /// directory itself, so none runs beside a live node.
    Safety {
        #[command(subcommand)]
        cmd: SafetyCmd,
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
        /// Sign the v2 registration (`rand-register-2`: the chain's genesis hash, read from
        /// `--rpc`, and the validator's address beside the chain id and payout). Required on a
        /// chain whose genesis sets `staking.registration_v2`; a v1 registration is refused
        /// there, and a v2 one everywhere else.
        #[arg(long)]
        v2: bool,
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
    /// Admission by vote (audit v6, STAKE-2; `docs/staking.md`): on a chain whose genesis sets
    /// `staking.admission_by_vote`, a new validator key registers only once validators holding
    /// more than two thirds of the voting weight have signed it in. `sign` is each validator's
    /// half (offline: a key file and the genesis hash); `submit` assembles the votes and sends the
    /// fee-less `AdmitValidator`.
    Admit {
        #[command(subcommand)]
        cmd: AdmitCmd,
    },
    /// Genesis vesting (`docs/vesting.md`): a timelocked allocation's holder and revoker side —
    /// status, claim, revoke, and bonding locked RAND. The key is made with `keygen` and its
    /// public key read with `address`; `--key` below is the entry's beneficiary (or revoker) key.
    Vesting {
        #[command(subcommand)]
        cmd: VestingCmd,
    },
    /// Audit v6, BRG-14: sign and submit the bridge's post-quantum rotations (`docs/bridge.md`
    /// §21.1, §21.5) — the PQ guardian set, the pause key, and a cancel of a pending rotation.
    /// Each is `message` (print what will be signed, for every signer to compare), `sign` (one
    /// key file → one `index:signature` line) and `submit` (assemble the collected lines).
    BridgeGov {
        #[command(subcommand)]
        cmd: BridgeGovCmd,
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

/// `rand-node safety …` (audit v6, CON-4 and CON-5).
#[derive(Subcommand)]
enum SafetyCmd {
    /// Print the view, the last voted view, the high QC, the lock and any recorded safety halt.
    Status {
        #[arg(long)]
        datadir: PathBuf,
    },
    /// Clear a recorded safety halt so the node may start again. The node stopped because a
    /// certified three-chain tried to commit a block that does not descend from its committed
    /// head: read `safety status`, compare this node's head with the fleet's, and re-sync from
    /// an archive if it differs, before clearing anything.
    ClearHalt {
        #[arg(long)]
        datadir: PathBuf,
        /// Required: this is the acknowledgement that the halt was read and acted on.
        #[arg(long)]
        i_have_compared_this_node_with_the_fleet: bool,
    },
    /// Lower the persisted lock to the committed head's certificate. The lock is this
    /// validator's promise not to vote for a branch that does not extend the locked block;
    /// releasing it gives that promise up. For a validator whose locked block is lost for good
    /// (no peer serves it, no proposal outranks the lock) — never to hurry one along.
    ReleaseLock {
        #[arg(long)]
        datadir: PathBuf,
        /// Required: this is the acknowledgement of what is given up.
        #[arg(long)]
        i_give_up_this_validators_lock: bool,
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
/// `rand-node bridge-gov …` (audit v6, BRG-14).
#[derive(Subcommand)]
enum BridgeGovCmd {
    /// Replace the whole PQ guardian set (`RotatePqGuardians`, or `…V2` with possession).
    RotatePq {
        #[command(subcommand)]
        step: RotateStep,
    },
    /// Replace the pause key (`RotatePauseKey`, or `…V2` with possession).
    RotatePause {
        #[command(subcommand)]
        step: RotateStep,
    },
    /// Drop a pending rotation before it takes effect (`CancelRotation`), signed by the current
    /// pause key; only on a chain with `bridge.rotation.delay_secs`.
    CancelRotation {
        #[command(subcommand)]
        step: CancelStep,
    },
}

/// The new keys a rotation brings in: each a hex Dilithium2 public key, or `@path` to a file
/// holding one in hex, or a key file (its public key is read; the seed is never needed).
#[derive(clap::Args, Clone)]
struct NewKeys {
    /// Repeat once per key, in the new set's index order (one for a pause key).
    #[arg(long = "new-key", required = true)]
    new_key: Vec<String>,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

#[derive(Subcommand)]
enum RotateStep {
    /// Print the hex rotation message for the chain's current `rotation_nonce`.
    Message {
        #[command(flatten)]
        keys: NewKeys,
    },
    /// Sign the message with one key file and print `index:signature`. A current PQ guardian
    /// signs for the quorum (`--index` its place in the current set); with `--possession` a NEW
    /// key signs to prove it is held (`--index` its place in the new set, 0 for a pause key).
    Sign {
        #[command(flatten)]
        keys: NewKeys,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        index: u8,
        #[arg(long)]
        possession: bool,
    },
    /// Assemble and send the rotation from the collected lines (`@file` or the text itself).
    /// With `--possession` the `…V2` action is sent; without it, the v1 action.
    Submit {
        #[command(flatten)]
        keys: NewKeys,
        #[arg(long)]
        quorum: String,
        #[arg(long)]
        possession: Option<String>,
        #[arg(long)]
        no_wait: bool,
    },
}

#[derive(Subcommand)]
enum CancelStep {
    /// Sign the cancel message with the current pause key and print `0:signature`.
    Sign {
        #[arg(long, value_parser = ["pq", "pause"])]
        kind: String,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Send the cancel with the signature `sign` printed (`@file` or the text itself).
    Submit {
        #[arg(long, value_parser = ["pq", "pause"])]
        kind: String,
        #[arg(long)]
        signature: String,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        #[arg(long)]
        no_wait: bool,
    },
}

/// `@path` reads the file; anything else is the text itself.
fn text_arg(arg: &str) -> Result<String> {
    match arg.strip_prefix('@') {
        Some(path) => std::fs::read_to_string(path).with_context(|| format!("reading {path}")),
        None => Ok(arg.to_string()),
    }
}

/// One `--new-key`: a key file (its public key), or hex inline or behind `@path`.
fn parse_new_key(arg: &str) -> Result<randprotocol_core::PublicKey> {
    if let Some(path) = arg.strip_prefix('@') {
        if let Ok(kp) = load_keypair(std::path::Path::new(path)) {
            return Ok(kp.public_key().clone());
        }
    }
    let text = text_arg(arg)?;
    let text = text.trim();
    randprotocol_core::PublicKey::from_hex(text.strip_prefix("0x").unwrap_or(text))
        .map_err(|e| anyhow::anyhow!("--new-key {arg:.24}…: not a Dilithium2 public key or key file: {e}"))
}

/// What every bridge-gov step reads from the node: the chain id, its binding domain (BIND-1),
/// the bridge's `rotation_nonce`, its current PQ set and pause key.
struct GovView {
    chain_id: u64,
    domain: randprotocol_core::BindingDomain,
    nonce: u64,
    pq_guardians: Vec<randprotocol_core::PublicKey>,
    pause_key: Option<randprotocol_core::PublicKey>,
    needs_possession: bool,
}

async fn gov_view(rpc: &RpcClient) -> Result<GovView> {
    let chain_id = rpc.chain_id().await?;
    let domain = rpc.binding_domain(chain_id).await?;
    let state = rpc.bridge_state().await?;
    anyhow::ensure!(state["enabled"] == serde_json::Value::Bool(true), "this chain has no bridge");
    anyhow::ensure!(!state["rules_v2"].is_null(), "this chain has no bridge rules v2: it has no rotations");
    let key = |v: &serde_json::Value| randprotocol_core::PublicKey::from_hex(v.as_str().unwrap_or_default()).map_err(|e| anyhow::anyhow!("{e}"));
    Ok(GovView {
        chain_id,
        domain,
        nonce: state["rotation_nonce"].as_u64().context("the node serves no rotation_nonce")?,
        pq_guardians: state["pq_guardians"].as_array().context("the node serves no pq_guardians")?.iter().map(key).collect::<Result<_>>()?,
        pause_key: match &state["pause_key"] {
            serde_json::Value::Null => None,
            k => Some(key(k)?),
        },
        needs_possession: state["rotation_rules"]["needs_possession"].as_bool() == Some(true),
    })
}

async fn bridge_gov(cmd: BridgeGovCmd) -> Result<()> {
    use randprotocol_core::bridge::RotationKind;
    use randprotocol_node::bridge_gov_tool as tool;
    let rotation_of = |pause: bool, keys: &NewKeys| -> Result<tool::Rotation> {
        let parsed = keys.new_key.iter().map(|k| parse_new_key(k)).collect::<Result<Vec<_>>>()?;
        if pause {
            anyhow::ensure!(parsed.len() == 1, "a pause-key rotation names exactly one --new-key");
            Ok(tool::Rotation::Pause(parsed[0].clone()))
        } else {
            Ok(tool::Rotation::Pq(parsed))
        }
    };
    let (pause, step) = match cmd {
        BridgeGovCmd::RotatePq { step } => (false, step),
        BridgeGovCmd::RotatePause { step } => (true, step),
        BridgeGovCmd::CancelRotation { step } => {
            let kind_of = |k: &str| if k == "pause" { RotationKind::PauseKey } else { RotationKind::PqGuardians };
            match step {
                CancelStep::Sign { kind, key, rpc } => {
                    let v = gov_view(&RpcClient::new(rpc)).await?;
                    let m = tool::cancel_message(&v.domain, v.chain_id, v.nonce, kind_of(&kind));
                    println!("{}", tool::sign_line(&load_keypair(&key)?, 0, &m, v.pause_key.as_ref())?);
                }
                CancelStep::Submit { kind, signature, rpc, no_wait } => {
                    let client = RpcClient::new(rpc.clone());
                    let v = gov_view(&client).await?;
                    let action = tool::assemble_cancel(kind_of(&kind), v.nonce, &text_arg(&signature)?)?;
                    let args = StakingArgs { key: PathBuf::new(), rpc, no_wait };
                    submit_staking(&args, v.chain_id, action, "rotation cancel").await?;
                }
            }
            return Ok(());
        }
    };
    match step {
        RotateStep::Message { keys } => {
            let v = gov_view(&RpcClient::new(keys.rpc.clone())).await?;
            let m = tool::rotation_message(&v.domain, v.chain_id, v.nonce, &rotation_of(pause, &keys)?);
            eprintln!("chain {} rotation_nonce {}{}", v.chain_id, v.nonce, if v.needs_possession { " (possession required)" } else { "" });
            println!("{}", hex::encode(m));
        }
        RotateStep::Sign { keys, key, index, possession } => {
            let v = gov_view(&RpcClient::new(keys.rpc.clone())).await?;
            let rotation = rotation_of(pause, &keys)?;
            let m = tool::rotation_message(&v.domain, v.chain_id, v.nonce, &rotation);
            let expected = match (&rotation, possession) {
                (tool::Rotation::Pq(new), true) => new.get(index as usize).cloned(),
                (tool::Rotation::Pause(new), true) => Some(new.clone()),
                (_, false) => v.pq_guardians.get(index as usize).cloned(),
            }
            .with_context(|| format!("there is no key at index {index}"))?;
            println!("{}", tool::sign_line(&load_keypair(&key)?, index, &m, Some(&expected))?);
        }
        RotateStep::Submit { keys, quorum, possession, no_wait } => {
            let v = gov_view(&RpcClient::new(keys.rpc.clone())).await?;
            let rotation = rotation_of(pause, &keys)?;
            let m = tool::rotation_message(&v.domain, v.chain_id, v.nonce, &rotation);
            let possession = match possession {
                Some(p) => tool::parse_signature_lines(&text_arg(&p)?)?,
                None => Vec::new(),
            };
            anyhow::ensure!(
                possession.is_empty() != v.needs_possession,
                "this chain {} a proof of possession: {} --possession",
                if v.needs_possession { "requires" } else { "does not take" },
                if v.needs_possession { "pass" } else { "drop" }
            );
            let action = tool::assemble_rotation(rotation, v.nonce, tool::parse_signature_lines(&text_arg(&quorum)?)?, possession, &m)?;
            let args = StakingArgs { key: PathBuf::new(), rpc: keys.rpc, no_wait };
            submit_staking(&args, v.chain_id, action, if pause { "pause-key rotation" } else { "PQ guardian rotation" }).await?;
        }
    }
    Ok(())
}

/// `rand-node vesting …` (genesis vesting).
#[derive(Subcommand)]
enum AdmitCmd {
    /// Sign this validator's vote to admit `--candidate` and print it as one line,
    /// `<voter public key hex>:<signature hex>`, for whoever runs `admit submit`. Reads no node:
    /// the vote is over the genesis hash and the candidate's address, nothing else.
    Sign {
        /// The candidate: its validator public key in hex, the registration blob `rand-node
        /// register` printed for it, or a file holding either.
        #[arg(long)]
        candidate: String,
        /// This validator's key file — a key in the chain's voting set.
        #[arg(long)]
        key: PathBuf,
        /// The chain's genesis hash, 64 hex characters (`rand-node init` prints it; a node
        /// serves it as `rand_getGenesisHash`). A vote is good on exactly this chain.
        #[arg(long)]
        genesis_hash: String,
    },
    /// Assemble validators' votes into one `AdmitValidator` and submit it. Each vote is checked
    /// here against the node's genesis hash first; the chain then needs the voters to hold more
    /// than two thirds of the voting set's weight. Bundle-less and fee-less: no wallet needed.
    Submit {
        /// The candidate, as for `admit sign`.
        #[arg(long)]
        candidate: String,
        /// One vote, as `admit sign` printed it; repeat for each voter.
        #[arg(long = "signature", required = true, value_name = "KEY:SIGNATURE")]
        signatures: Vec<String>,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
    },
}

#[derive(Subcommand)]
enum VestingCmd {
    /// Show an entry: its terms, what has vested, what is claimable now.
    Status {
        /// The entry id, 64 hex characters.
        entry: String,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Claim unlocked RAND into a note at `--to`, less the 0.001 RAND base the block's proposer
    /// is paid. Signed by the beneficiary key.
    Claim {
        /// The entry id, 64 hex characters.
        #[arg(long)]
        entry: String,
        /// The `rand1…` address the note is paid to — inside what the key signs.
        #[arg(long)]
        to: String,
        /// Amount in RAND; or `--all` for everything claimable now.
        #[arg(long, conflicts_with = "all", required_unless_present = "all")]
        amount: Option<String>,
        #[arg(long)]
        all: bool,
        #[command(flatten)]
        staking: StakingArgs,
    },
    /// Revoke a revocable entry: its unvested part is paid to the treasury the entry names in
    /// genesis and the entry is frozen. A revoke is signed by a threshold of the entry's revoker
    /// keys (audit v6, STAKE-3), so it is three steps, like a multisig: `prepare` writes the
    /// revoke, each revoker runs `sign` on that file, and `submit` sends it with the signatures.
    Revoke {
        #[command(subcommand)]
        cmd: RevokeCmd,
    },
    /// Bond an irrevocable entry's locked RAND as `--validator`'s stake (SAFT Schedule 2 §4).
    /// A validator not yet in the register needs `--registration` (what `rand-node register`
    /// prints for it).
    Bond {
        #[arg(long)]
        entry: String,
        /// The validator's address (base58).
        #[arg(long)]
        validator: String,
        /// Amount in RAND.
        amount: String,
        #[arg(long)]
        registration: Option<String>,
        #[command(flatten)]
        staking: StakingArgs,
    },
    /// Take bonded RAND back into the lock (claimable again after the unbonding epochs).
    Unbond {
        #[arg(long)]
        entry: String,
        /// Amount in RAND.
        amount: String,
        #[command(flatten)]
        staking: StakingArgs,
    },
}

/// `rand-node vesting revoke …` (audit v6, STAKE-3): a revoke needs a threshold of the entry's
/// revokers over one message, and that message holds a random blinding and a sealed envelope, so
/// the revoke is written once (`prepare`) and every revoker signs that file (`sign`).
#[derive(Subcommand)]
enum RevokeCmd {
    /// Write the revoke every revoker signs: the entry, the amount (what will still be unvested
    /// `--margin-secs` after the head, so a revoke that lands a little later still fits — the
    /// revoke takes the whole unvested part either way, and what the note leaves behind is
    /// swept by preparing again once the entry is revoked), the revokers' nonce, the treasury
    /// note and its envelope. Needs no key. The note's `time` is the head height, so the
    /// signatures must be gathered and submitted within the chain's time window (256 blocks) —
    /// prepare again if that passes.
    Prepare {
        #[arg(long)]
        entry: String,
        #[arg(long, default_value_t = 600)]
        margin_secs: u64,
        /// Where the revoke is written (an existing file is refused).
        #[arg(long, default_value = "revoke.json")]
        out: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Sign a prepared revoke with one revoker key and print `<index>:<signature hex>` — what
    /// `submit --signature` takes. Offline: it reads only the file and the key. It prints what
    /// is being signed on stderr; compare the treasury with the genesis file before trusting it.
    Sign {
        #[arg(long)]
        proposal: PathBuf,
        /// One of the entry's revoker keys.
        #[arg(long)]
        key: PathBuf,
        /// This key's position in the entry's `revokers` list. Default: looked up in the list
        /// the prepared file carries.
        #[arg(long)]
        index: Option<u8>,
    },
    /// Send a prepared revoke with at least the entry's threshold of signatures.
    Submit {
        #[arg(long)]
        proposal: PathBuf,
        /// A `sign` step's output; repeatable, one per revoker.
        #[arg(long = "signature", required = true, value_name = "INDEX:HEX")]
        signatures: Vec<String>,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
        /// Return once the node accepts the transaction instead of waiting for it to commit.
        #[arg(long)]
        no_wait: bool,
    },
}

/// A prepared revoke (`rand-node vesting revoke prepare`): every field of the message the
/// revokers sign, as text, so the file can be read before it is signed. `revokers` and
/// `threshold` are the node's word at `prepare` — a convenience for `sign`'s index lookup, not
/// part of what is signed (a wrong list yields a signature the chain refuses, nothing worse).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeProposal {
    chain_id: u64,
    /// The genesis hash, hex.
    genesis: String,
    /// The entry id, hex.
    entry: String,
    /// The gross amount revoked, in units, a decimal string.
    unvested: String,
    nonce: u64,
    /// The treasury, `rand1…`.
    to: String,
    time: u32,
    /// The note's blinding, hex.
    r: String,
    /// `bincode(Envelope)`, hex.
    envelope: String,
    #[serde(default)]
    revokers: Vec<String>,
    #[serde(default)]
    threshold: u8,
}

/// A [`RevokeProposal`]'s fields as the types the ledger reads.
struct RevokeParts {
    chain_id: u64,
    genesis: randprotocol_core::Hash,
    entry: [u8; 32],
    unvested: u64,
    nonce: u64,
    to: ShieldedAddress,
    time: u32,
    r: randprotocol_core::notes::Word8,
    envelope: Envelope,
}

impl RevokeProposal {
    /// Seal the treasury note and write the revoke down.
    #[allow(clippy::too_many_arguments)]
    fn new(
        chain_id: u64,
        genesis: &randprotocol_core::Hash,
        entry: &[u8; 32],
        unvested: u64,
        nonce: u64,
        to: &ShieldedAddress,
        time: u32,
        format: EnvelopeFormat,
    ) -> Result<RevokeProposal> {
        let base = randprotocol_core::gas::BUNDLE_BASE;
        anyhow::ensure!(unvested > base, "a revoke pays the {} RAND bundle base out of its amount", format_amount(base));
        let (note, envelope) = sealed_vesting_note(to, unvested - base, time, format)?;
        Ok(RevokeProposal {
            chain_id,
            genesis: genesis.to_hex(),
            entry: hex::encode(entry),
            unvested: unvested.to_string(),
            nonce,
            to: to.to_string(),
            time,
            r: word8_to_hex(&note.r),
            envelope: hex::encode(bincode::serialize(&envelope).context("encoding the envelope")?),
            revokers: Vec::new(),
            threshold: 0,
        })
    }

    fn read(path: &std::path::Path) -> Result<RevokeProposal> {
        serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)
            .with_context(|| format!("{} is not a prepared revoke", path.display()))
    }

    fn parts(&self) -> Result<RevokeParts> {
        Ok(RevokeParts {
            chain_id: self.chain_id,
            genesis: randprotocol_core::Hash::from_hex(&self.genesis).map_err(|e| anyhow::anyhow!("genesis: {e}"))?,
            entry: parse_entry_id(&self.entry)?,
            unvested: self.unvested.parse().with_context(|| format!("unvested: {} is not an amount in units", self.unvested))?,
            nonce: self.nonce,
            to: ShieldedAddress::parse(&self.to).map_err(|e| anyhow::anyhow!("to: {e}"))?,
            time: self.time,
            r: randprotocol_core::notes::word8_from_hex(&self.r).context("r: not a 32-byte hex blinding")?,
            envelope: bincode::deserialize(&hex::decode(&self.envelope).context("envelope: not hex")?).context("envelope: not an envelope")?,
        })
    }

    /// One revoker's signature over this revoke, as `<index>:<signature hex>`. `index` absent,
    /// the key is looked up in the file's `revokers`.
    fn sign(&self, kp: &Keypair, index: Option<u8>) -> Result<String> {
        let index = match index {
            Some(i) => i,
            None => {
                let me = kp.address().to_base58();
                let at = self.revokers.iter().position(|r| *r == me).with_context(|| {
                    format!("this key ({me}) is not among the revokers the prepared file lists; pass --index if the file's list is wrong")
                })?;
                at as u8
            }
        };
        let signature = kp.sign(self.parts()?.message().as_bytes());
        Ok(format!("{index}:{}", hex::encode(signature.as_bytes())))
    }

    /// The transaction's action with `signatures` (each a `sign` step's output), in index
    /// order. Refuses what the chain would: a position named twice.
    fn action(&self, signatures: &[String]) -> Result<randprotocol_core::Action> {
        use randprotocol_core::types::actions::RevokerSignature;
        let mut list = Vec::with_capacity(signatures.len());
        for s in signatures {
            let (index, sig) = s.trim().split_once(':').with_context(|| format!("--signature takes <index>:<hex>, got {s}"))?;
            let index: u8 = index.parse().with_context(|| format!("--signature index: {index}"))?;
            let signature = randprotocol_core::crypto::Signature::from_bytes(&hex::decode(sig).context("--signature: not hex")?)
                .map_err(|e| anyhow::anyhow!("--signature {index}: {e}"))?;
            anyhow::ensure!(list.iter().all(|x: &RevokerSignature| x.index != index), "revoker {index} is given twice");
            list.push(RevokerSignature { index, signature });
        }
        list.sort_by_key(|x| x.index);
        let p = self.parts()?;
        Ok(randprotocol_core::Action::RevokeVesting {
            entry: p.entry,
            unvested: p.unvested,
            nonce: p.nonce,
            to: p.to,
            time: p.time,
            r: p.r,
            envelope: p.envelope,
            signatures: list,
        })
    }
}

impl RevokeParts {
    fn message(&self) -> randprotocol_core::Hash {
        randprotocol_core::types::actions::revoke_vesting_message(
            &self.genesis,
            self.chain_id,
            &self.entry,
            self.unvested,
            self.nonce,
            &self.to,
            self.time,
            &self.r,
            &self.envelope,
        )
    }
}

/// The `--vesting` file: the section, its rules (`VestingConfig::check`), and — what the core
/// crate cannot test — that every treasury's ML-KEM key decodes, so the revoke that pays it can
/// be sealed at all.
fn read_vesting_config(path: &std::path::Path) -> Result<randprotocol_core::ledger::vesting::VestingConfig> {
    let cfg: randprotocol_core::ledger::vesting::VestingConfig =
        serde_json::from_str(&std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?)
            .with_context(|| format!("{} is not a valid vesting config", path.display()))?;
    cfg.check().map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    for e in &cfg.entries {
        if let Some(t) = e.treasury_address() {
            randprotocol_zkvm::address::to_research(&t)
                .map_err(|why| anyhow::anyhow!("{}: entry {}: the treasury cannot be sealed to: {why}", path.display(), hex::encode(e.id)))?;
        }
    }
    Ok(cfg)
}

/// A 64-hex vesting entry id.
fn parse_entry_id(s: &str) -> Result<[u8; 32]> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .ok()
        .and_then(|b| b.try_into().ok())
        .with_context(|| format!("{s} is not a vesting entry id (64 hex characters)"))
}

/// The entry as the node serves it (`rand_getVesting`), refusing a chain without the section
/// and an id the register does not hold. `at_ms` asks for the schedule at another time.
async fn vesting_entry(rpc: &RpcClient, id: &[u8; 32], at_ms: Option<u64>) -> Result<serde_json::Value> {
    let v = rpc.call("rand_getVesting", serde_json::json!([hex::encode(id), at_ms])).await?;
    anyhow::ensure!(v["enabled"] != serde_json::json!(false), "this chain has no vesting section");
    anyhow::ensure!(!v.is_null(), "no vesting entry {} on this chain", hex::encode(id));
    Ok(v)
}

fn amount_field(v: &serde_json::Value, name: &str) -> Result<u64> {
    v[name].as_str().and_then(|s| s.parse().ok()).with_context(|| format!("the node's vesting reply has no {name}"))
}

/// The note a claim or a revoke pays and the envelope that opens it: `to`, no sender, the
/// amount less the base, the native asset, `time` — what `ledger::vesting` derives, which
/// `the_cli_vesting_note_is_the_note_the_ledger_derives` pins.
fn sealed_vesting_note(to: &ShieldedAddress, net: u64, time: u32, format: EnvelopeFormat) -> Result<(Note, Envelope)> {
    sealed_withdraw_note(to, net, time, format)
}

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

/// Whether `cmd` opens a data directory's RocksDB, and so needs the open-files limit raised
/// before it does (issue #60).
///
/// #41 raised the limit only inside `node::start`, so `run` was covered and nothing else was:
/// `verify` (and `verify --repair`), `db drop-receipts-index` and `init` open the same database —
/// ~1000 table files on chain 15's archives — under whatever soft limit the operator's shell has
/// (1024 on a droplet's login shell, 256 on macOS). The fleet's systemd drop-in covers the unit,
/// not a hand-run command, and a hand-run command is exactly what an operator repairing a node
/// reaches for. Every arm that calls `Storage::open` (or `Storage::drop_receipts_index`, which
/// opens the families itself) belongs here; the RPC-client and key-file commands do not.
fn opens_storage(cmd: &Cmd) -> bool {
    matches!(cmd, Cmd::Run { .. } | Cmd::Verify { .. } | Cmd::Db { .. } | Cmd::Init { .. } | Cmd::Safety { .. })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,libp2p=warn,libp2p_mdns=off".into()))
        .init();
    let cli = Cli::parse();
    let test_profile_allowed = test_fri_profile_allowed(&cli);
    if opens_storage(&cli.cmd) {
        match randprotocol_node::rlimit::raise_nofile_limit() {
            Ok((soft, hard)) => tracing::debug!(soft, hard, "open-files limit"),
            Err(e) => tracing::warn!("could not raise the open-files limit: {e}"),
        }
    }
    match cli.cmd {
        Cmd::Keygen { out } => {
            let kp = Keypair::generate();
            // Never over an existing file (VK-7): the key at `out` may be the only copy of a seed.
            KeyFile::from_keypair(&kp).write_new(&out)?;
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
            envelope_bytes,
            vesting,
            bundle_guest,
            auth_guest,
            hardening_v6,
            gas_price,
            byte_price,
            bundle_gas_limit,
            gas_dynamic,
            max_gas_price,
            max_byte_price,
            gas_byte_load,
            staking,
            consensus_domain,
            testnet,
            binding_domain,
            proof_window_blocks,
        } => {
            let hc_bundle = match bundle_guest.as_str() {
                "v3" => ZkExecutor::hc_hidden_bundle_v3(),
                "v2" => ZkExecutor::hc_hidden_bundle_v2(),
                _ => ZkExecutor::hc_bundle(),
            };
            // Split authorisation pairs bundle guest v3 with the auth guest both ways (the node's
            // `check_build_runs_genesis` would refuse either half alone at startup; say so here,
            // before a file is written).
            match (bundle_guest.as_str(), auth_guest) {
                ("v3", false) => anyhow::bail!(
                    "--bundle-guest v3 needs --auth-guest: v3 takes nk, not the spend key, and only an auth proof \
                     pinned by the genesis hc_auth authorises its spends"
                ),
                (g, true) if g != "v3" => anyhow::bail!(
                    "--auth-guest needs --bundle-guest v3: the {g} guest does not publish the auth commitment, \
                     so no bundle on the chain could be admitted"
                ),
                _ => {}
            }
            // The gas section (spec §4.2, §4.3, §7.1): written only when `--gas-price` is given,
            // so a chain cut without it hashes byte-for-byte as before.
            let gas = gas_section(
                gas_price,
                byte_price,
                bundle_gas_limit,
                gas_dynamic.as_deref(),
                DynamicExtras { max_gas_price, max_byte_price, byte_load: gas_byte_load.as_deref() },
            )?;
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
                hc_bundle: word8_to_hex(&hc_bundle),
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
                // The consensus signing domain (audit v4): `--consensus-domain 1` from the next
                // cut on (chains 15–18 had it spliced in by the cut script, like the bridge
                // section). Omitted, this command writes chain 14's shape.
                consensus_domain,
                // An aggregating chain is cut with the section spelled out on the command
                // line (chain 9, spec §2.3): the bond, the subsidy schedule and the registered
                // shapes with their measured program digests.
                aggregation: match (&aggregation, &admitted_shapes) {
                    (Some(spec), shapes) if !shapes.is_empty() => {
                        let mut cfg = parse_aggregation_config(spec)?;
                        cfg.admitted_shapes = shapes
                            .iter()
                            .map(|s| {
                                // The literal `hc_bundle` means the guest this genesis pins
                                // (`--bundle-guest`) — the only value its aggregates may cover,
                                // so the flag cannot quietly carry a stale one.
                                let admitted = parse_admitted_shape(&s.replace(
                                    ",hc_bundle,",
                                    &format!(",{},", word8_to_hex(&hc_bundle)),
                                ))?;
                                // The half of the genesis check core cannot run (IFACE-9): the
                                // rVM must be able to build an inner verifier key for the shape,
                                // or no aggregate could ever be verified against it.
                                randprotocol_node::agg_executor::check_admitted_shape(&admitted.shape)
                                    .map_err(|e| anyhow::anyhow!("--admitted-shape {s}: {e}"))?;
                                Ok(admitted)
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
                // The exact envelope size (spec 2026-09-26 §2.4): given, part of the genesis
                // hash and set here — before the `--alloc` loop below seals a single note — so
                // every alloc note comes out the declared length; omitted, `None`, byte-for-byte
                // today's shape.
                envelope_bytes,
                // The `staking` section (audit v4 STAKE-2; audit v6's `admission_by_vote`): read
                // from a `StakingConfig` JSON file when `--staking` is given, so `Genesis::build`
                // validates it; omitted entirely otherwise (chains 15–18 had theirs spliced in
                // by hand, like the `bridge` section), so a chain without the flag hashes
                // byte-for-byte as before.
                staking: match &staking {
                    Some(path) => Some(
                        serde_json::from_str::<randprotocol_core::genesis::StakingConfig>(
                            &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
                        )
                        .with_context(|| format!("{} is not a valid staking config", path.display()))?,
                    ),
                    None => None,
                },
                // Genesis vesting: read from a `VestingConfig` JSON file when `--vesting` is given
                // (`Genesis::build` validates it); omitted entirely otherwise.
                vesting: match &vesting {
                    Some(path) => Some(read_vesting_config(path)?),
                    None => None,
                },
                // The v0.6 `hardening_v6` switch: absent unless asked for, so a genesis cut without
                // it hashes byte-for-byte as before.
                hardening_v6: hardening_v6.then_some(true),
                // Split authorisation's auth guest (`--auth-guest`, only with `--bundle-guest v3`):
                // absent otherwise, so a genesis cut without it hashes byte-for-byte as before.
                hc_auth: auth_guest.then(|| word8_to_hex(&ZkExecutor::hc_auth())),
                // The gas section: absent unless `--gas-price` is given, so a genesis cut
                // without it hashes byte-for-byte as before.
                gas,
                // The testnet marker (audit v6, STAKE-2): absent unless asked for.
                testnet: testnet.then_some(true),
                // BIND-1: absent unless asked for, so a genesis cut without it hashes
                // byte-for-byte as before.
                binding_domain,
                // Issue #118: absent unless asked for, so a genesis cut without it hashes
                // byte-for-byte as before.
                proof_window_blocks,
            };
            if binding_domain.is_none() && !randprotocol_client::CHAIN_ID_BINDING_CHAIN_IDS.contains(&chain_id) {
                eprintln!(
                    "warning: no --binding-domain 1: chain {chain_id} is not one of the chains cut before binding_domain \
                     ({:?}), and a wallet proves only the genesis-bound form there — no wallet will be able to transact on this \
                     chain (BIND-1, docs/deploy.md \"The next cut\")",
                    randprotocol_client::CHAIN_ID_BINDING_CHAIN_IDS
                );
            }
            for v in &validators {
                gen.validators.push(parse_genesis_validator(v)?);
            }
            // The format every `--alloc` note is sealed in: read off the field just set above, so
            // it is the chain's own declared envelope shape, not this command's default.
            let envelope_format = EnvelopeFormat::for_chain(gen.envelope_bytes);
            for a in &allocs {
                let (addr, amt) = a.split_once('=').context("--alloc must be rand1address=amount")?;
                let amount = parse_amount(amt)?;
                gen.alloc.push(deposit_note(addr, amount, envelope_format)?);
                println!("  alloc {} RAND to {addr}", format_amount(amount));
            }
            if gen.fri_profile == "test" {
                eprintln!(
                    "warning: fri_profile \"test\" proves about 17 bits and protects nothing; a release node refuses this genesis \
                     at init, run and verify without --allow-test-fri-profile"
                );
            }
            let executor = node::executor_for_profile(&gen.fri_profile)?;
            let state = gen.build(executor.as_ref())?;
            std::fs::write(&out, gen.to_json())?;
            println!(
                "wrote {} (genesis hash {}, {} validators, {} notes, {} blocks/epoch, programs up to {} words, proofs up to {} bytes, blocks up to {} bytes, call envelopes up to {} bytes, program public input up to {} words, faucet {}, confidential {}, fri {}, hc_bundle {}, hc_auth {})",
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
                gen.hc_auth.as_deref().unwrap_or("none"),
            );
            println!("{}", gas_summary(state.ledger.gas()));
        }
        Cmd::AllocNote { to, amount, asset, envelope_bytes } => {
            println!("{}", serde_json::to_string_pretty(&alloc_note_cmd(&to, &amount, asset, envelope_bytes)?)?);
        }
        Cmd::Init { datadir, genesis } => {
            std::fs::create_dir_all(&datadir)?;
            let text = std::fs::read_to_string(&genesis)?;
            let g = Genesis::from_json(&text)?;
            refuse_test_fri_profile(&g.fri_profile, test_profile_allowed)?;
            let executor = node::executor_for_profile(&g.fri_profile)?;
            let gs = g.build(executor.as_ref())?;
            std::fs::write(datadir.join("genesis.json"), &text)?;
            let storage = Storage::open(&datadir)?;
            storage.init_genesis(&gs)?;
            println!("initialised {} at genesis {} (chain id {})", datadir.display(), gs.hash(), gs.chain_id);
            println!("{}", gas_summary(gs.ledger.gas()));
        }
        Cmd::Verify { datadir, mode, repair } => {
            let mode: VerifyMode = mode.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            let (gs, executor) = node::load_genesis(&datadir)?;
            refuse_test_fri_profile(&gs.fri_profile, test_profile_allowed)?;
            node::refuse_chains_this_build_cannot_run(&gs)?;
            let storage = Storage::open(&datadir)?;
            let check = storage.verify_chain(&gs, mode, executor.as_ref())?;
            match &check.problem {
                None if check.floor > 0 => {
                    // The snapshot half (audit v6, OPS-5): the same comparison `run` makes.
                    let reloaded = node::reload_ledger(&storage, &gs, executor.as_ref())?;
                    node::snapshot_is_the_head_state(&storage.head_block()?, &reloaded)?;
                    println!(
                        "ok: {} blocks verified structurally from {} ({mode:?}); the ledger snapshot hashes to the head's state root",
                        check.head - check.floor + 1,
                        check.floor
                    )
                }
                None => println!("ok: {} blocks verified ({mode:?})", check.head + 1),
                Some(p) => {
                    println!("CORRUPT: {p}\nhead {} last good {} genesis_ok {}", check.head, check.last_good, check.genesis_ok);
                    if check.floor > 0 {
                        println!("pruned node (floor {}): history cannot be repaired locally — re-sync from the archive", check.floor);
                        std::process::exit(2);
                    }
                    if repair {
                        node::check_and_repair_chain(&storage, &gs, mode, executor.as_ref())?;
                        println!("repaired: head is now {}", storage.head()?.height);
                    } else {
                        std::process::exit(2);
                    }
                }
            }
        }
        Cmd::Run {
            datadir,
            key,
            listen,
            bootstrap,
            reserved_peer,
            strict_gossip,
            rpc,
            validator,
            no_mdns,
            block_interval_ms,
            view_timeout_ms,
            verify_chain,
            keep_raw_proofs,
            rpc_viewing_open,
            public_rpc,
            rpc_viewing_token_file,
            min_free_disk_mb,
            prune_history,
            prover,
            prover_home,
            prover_accept_spend_key,
            prover_max_parallel,
            prover_max_queue,
            prover_cuda,
            prover_skip_memory_check,
            prover_allow_origin,
            prover_fee,
            prover_fee_address,
            gas_price,
            byte_price,
        } => {
            // The retired flag first, with or without `--prover`: a unit file that still passes
            // it fails here, loudly, rather than starting as though it were honoured (VK-4).
            if prover_accept_spend_key {
                anyhow::bail!(randprotocol_prover::service::spend_key_flag_retired("--prover-accept-spend-key"));
            }
            // ZK-5a: the datadir's genesis file, read for its profile alone, before the key is
            // read or the database opened. A datadir without one is left to `node::start_with`
            // to report as it always has.
            if let Ok(text) = std::fs::read_to_string(datadir.join("genesis.json")) {
                refuse_test_fri_profile(&Genesis::from_json(&text)?.fri_profile, test_profile_allowed)?;
            }
            // Every prover check runs, and its address is bound, before the node key is read or
            // the database opened, so a misconfigured prover (or a port in use) exits at once.
            let hosted: Option<HostedProver> = match prover {
                None => None,
                Some(addr) => Some(hosted_prover::prepare(&hosted_prover::Options {
                    addr,
                    rpc,
                    home: prover_home.unwrap_or_else(|| datadir.join("prover")),
                    max_parallel: prover_max_parallel,
                    max_queue: prover_max_queue,
                    cuda: prover_cuda,
                    skip_memory_check: prover_skip_memory_check,
                    allow_origins: prover_allow_origin,
                    fee: prover_fee,
                    fee_address: prover_fee_address,
                })?),
            };
            let kp = load_keypair(&key)?;
            let viewing_token = match &rpc_viewing_token_file {
                None => None,
                Some(path) => {
                    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
                    let token = text.lines().next().unwrap_or("").trim();
                    if token.len() < 32 {
                        anyhow::bail!("{}: the viewing token must be at least 32 characters on the first line", path.display());
                    }
                    Some(std::sync::Arc::<str>::from(token))
                }
            };
            let rpc_options = node::RpcOptions { public_addr: public_rpc, viewing_token };
            let handle = node::start_with(NodeConfig {
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
                min_free_disk_bytes: min_free_disk_mb << 20,
                prune_history,
                gas_policy: randprotocol_core::gas::GasPolicy::from_prices(gas_price, byte_price),
            }, rpc_options, node::NetOptions { reserved_peers: reserved_peer, strict_gossip })
            .await?;
            // The prover is served once the node's RPC is up and stops with the node; a prover
            // that exits stops the node too.
            let prover_task = match hosted {
                None => None,
                Some(hp) => match hosted_prover::start(hp).await {
                    Ok((_bound, served)) => Some(served),
                    Err(e) => {
                        handle.shutdown().await;
                        return Err(e.context("serving the prover"));
                    }
                },
            };
            hosted_prover::run(handle, prover_task, hosted_prover::shutdown_signal()).await?;
        }
        Cmd::Safety { cmd } => match cmd {
            SafetyCmd::Status { datadir } => {
                let storage = Storage::open(&datadir)?;
                let head = storage.head()?;
                let head_qc = storage.head_qc()?;
                println!("committed head: height {} hash {:?} (QC view {})", head.height, head.hash, head_qc.view);
                match storage.load_safety()? {
                    None => println!("safety state: none recorded (this node has not voted)"),
                    Some(s) => {
                        println!("view {}  last voted view {}", s.view, s.last_voted_view);
                        println!("high QC: view {} block {:?}", s.high_qc.view, s.high_qc.block_hash);
                        match s.locked_qc.view > head_qc.view {
                            true => println!("LOCKED above the head: view {} block {:?}", s.locked_qc.view, s.locked_qc.block_hash),
                            false => println!("lock: at or under the committed head (view {})", s.locked_qc.view),
                        }
                        println!("votes remembered above the head: {}", s.voted.len());
                    }
                }
                println!("certified blocks persisted above the head: {}", storage.pending_blocks()?.len());
                match storage.safety_halt()? {
                    None => println!("safety halt: none"),
                    Some(h) => println!(
                        "SAFETY HALT recorded at {} ms, height {}: committed head {:?}; a three-chain tried to commit {:?}, which does not descend from it",
                        h.at_ms, h.height, h.committed, h.attempted
                    ),
                }
            }
            SafetyCmd::ClearHalt { datadir, i_have_compared_this_node_with_the_fleet } => {
                let storage = Storage::open(&datadir)?;
                let Some(h) = storage.safety_halt()? else {
                    println!("no safety halt is recorded in {}", datadir.display());
                    return Ok(());
                };
                println!(
                    "recorded at {} ms, height {}: committed head {:?}; a three-chain tried to commit {:?}, which does not descend from it",
                    h.at_ms, h.height, h.committed, h.attempted
                );
                if !i_have_compared_this_node_with_the_fleet {
                    anyhow::bail!(
                        "not cleared. Compare this node's committed head with the fleet's (rand_status on two other validators); \
                         if it differs, re-sync this node from an archive instead. Then pass --i-have-compared-this-node-with-the-fleet"
                    );
                }
                storage.clear_safety_halt()?;
                println!("cleared: the node will start again");
            }
            SafetyCmd::ReleaseLock { datadir, i_give_up_this_validators_lock } => {
                let storage = Storage::open(&datadir)?;
                let head_qc = storage.head_qc()?;
                let Some(s) = storage.load_safety()?.filter(|s| s.locked_qc.view > head_qc.view) else {
                    println!("no lock above the committed head (QC view {}) in {}: nothing to release", head_qc.view, datadir.display());
                    return Ok(());
                };
                println!(
                    "this validator is locked on block {:?} (view {}), above its committed head (QC view {}).",
                    s.locked_qc.block_hash, s.locked_qc.view, head_qc.view
                );
                println!(
                    "The lock is its promise not to vote for a branch that does not extend that block. Releasing it gives the \
                     promise up: if the block was certified and other validators still hold it, this validator's next vote can \
                     help certify a conflicting branch. Release only when no peer can serve the block and no proposal has \
                     outranked the lock, and never on more than one validator at a time."
                );
                if !i_give_up_this_validators_lock {
                    anyhow::bail!("not released. Pass --i-give-up-this-validators-lock to write it");
                }
                match storage.release_lock()? {
                    Some(was) => println!("released: the lock (view {}) is lowered to the committed head's certificate (view {})", was.view, head_qc.view),
                    None => println!("nothing to release"),
                }
            }
        },
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
        Cmd::Register { key, payout, rpc, v2 } => {
            let kp = load_keypair(&key)?;
            let client = RpcClient::new(rpc);
            let chain_id = client.chain_id().await?;
            let payout = ShieldedAddress::parse(&payout)
                .map_err(|e| anyhow::anyhow!("{payout} is not a shielded address: {e}"))?;
            // BIND-1: on a chain whose genesis sets `binding_domain: 1` the registration is the
            // genesis-bound (v2) message whether or not `--v2` was asked for; the chain-id-only
            // message registers nothing there.
            let domain = client.binding_domain(chain_id).await?;
            let message = match v2 {
                true => registration_message_v2(&client.genesis_hash().await?, chain_id, &kp.address(), &payout),
                false => domain.registration_message(chain_id, &kp.address(), &payout),
            };
            let signature = kp.sign(message.as_bytes());
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
            let domain = rpc.binding_domain(chain_id).await?;
            let signature = kp.sign(domain.unbond_message(chain_id, &kp.address(), amount, nonce).as_bytes());
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
            let (note, envelope) = sealed_withdraw_note(&payout, amount - base, time, envelope_format(&rpc, chain_id).await?)?;
            let domain = rpc.binding_domain(chain_id).await?;
            let signature = kp
                .sign(domain.withdraw_message(chain_id, &kp.address(), amount, nonce, time, &note.r, &envelope).as_bytes());
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
        Cmd::Admit { cmd } => match cmd {
            AdmitCmd::Sign { candidate, key, genesis_hash } => {
                let candidate = parse_candidate(&candidate)?;
                let kp = load_keypair(&key)?;
                let genesis = randprotocol_core::Hash::from_hex(&genesis_hash)
                    .map_err(|e| anyhow::anyhow!("--genesis-hash: {e}"))?;
                eprintln!("validator {} votes to admit {} on the chain of genesis {genesis}", kp.address(), candidate.address());
                println!("{}", admit_vote_line(&kp, &genesis, &candidate));
            }
            AdmitCmd::Submit { candidate, signatures, rpc, no_wait } => {
                let candidate = parse_candidate(&candidate)?;
                let client = RpcClient::new(rpc);
                let chain_id = client.chain_id().await?;
                let genesis = client.genesis_hash().await?;
                let action = admit_action(&genesis, &candidate, &signatures)?;
                let tx = randprotocol_core::Transaction { chain_id, bundle: None, action };
                let hash = client.send_transaction(&tx).await?;
                let what = format!("admission of {} by {} vote(s)", candidate.address(), signatures.len());
                if no_wait {
                    println!("submitted {what} {hash}");
                } else {
                    let receipt = client.wait_for_transaction(&hash, wallet::COMMIT_TIMEOUT).await?;
                    println!("submitted {what} {hash}\n  committed in block {}", receipt.height);
                }
            }
        },
        Cmd::BridgeGov { cmd } => bridge_gov(cmd).await?,
        Cmd::Vesting { cmd } => match cmd {
            VestingCmd::Status { entry, rpc } => {
                let v = vesting_entry(&RpcClient::new(rpc), &parse_entry_id(&entry)?, None).await?;
                println!("{}", serde_json::to_string_pretty(&v)?);
            }
            VestingCmd::Claim { entry, to, amount, all, staking } => {
                use randprotocol_core::types::actions::claim_vested_message;
                let kp = load_keypair(&staking.key)?;
                let id = parse_entry_id(&entry)?;
                let to = ShieldedAddress::parse(&to).map_err(|e| anyhow::anyhow!("{to} is not a shielded address: {e}"))?;
                let rpc = RpcClient::new(staking.rpc.clone());
                let v = vesting_entry(&rpc, &id, None).await?;
                let claimable = amount_field(&v, "claimable_now")?;
                let amount = match (amount, all) {
                    (Some(a), _) => parse_amount(&a)?,
                    (None, _) => claimable,
                };
                let base = randprotocol_core::gas::BUNDLE_BASE;
                anyhow::ensure!(
                    amount > base,
                    "a claim pays the {} RAND bundle base out of its amount, so {} RAND buys no note",
                    format_amount(base),
                    format_amount(amount)
                );
                anyhow::ensure!(
                    amount <= claimable,
                    "only {} RAND is claimable now, not {} RAND",
                    format_amount(claimable),
                    format_amount(amount)
                );
                let nonce = v["nonce"].as_u64().context("the node's vesting reply has no nonce")?;
                let chain_id = rpc.chain_id().await?;
                let genesis = rpc.genesis_hash().await?;
                let time = rpc.head().await?["height"].as_u64().context("head has no height")? as u32;
                let (note, envelope) = sealed_vesting_note(&to, amount - base, time, envelope_format(&rpc, chain_id).await?)?;
                let signature = kp.sign(
                    claim_vested_message(&genesis, chain_id, &id, amount, nonce, &to, time, &note.r, &envelope).as_bytes(),
                );
                println!(
                    "claiming {} RAND from entry {entry}: a note worth {} RAND to {to}, the {} RAND base to the block's proposer",
                    format_amount(amount),
                    format_amount(amount - base),
                    format_amount(base)
                );
                let action = randprotocol_core::Action::ClaimVested { entry: id, amount, nonce, to, time, r: note.r, envelope, signature };
                submit_staking(&staking, chain_id, action, &format!("claim of {} RAND", format_amount(amount))).await?;
            }
            VestingCmd::Revoke { cmd } => match cmd {
                RevokeCmd::Prepare { entry, margin_secs, out, rpc } => {
                    anyhow::ensure!(!out.exists(), "{} exists: a prepared revoke is never overwritten", out.display());
                    let id = parse_entry_id(&entry)?;
                    let rpc = RpcClient::new(rpc);
                    let now = vesting_entry(&rpc, &id, None).await?;
                    anyhow::ensure!(now["revocable"] == serde_json::json!(true), "entry {entry} has no revoker: it is irrevocable");
                    // A revoke pays the entry's treasury and no other address (STAKE-3): there
                    // is nothing to choose, so there is no `--to`.
                    let treasury = now["treasury"].as_str().context("the node's vesting reply has no treasury")?;
                    let to = ShieldedAddress::parse(treasury).map_err(|e| anyhow::anyhow!("the entry's treasury {treasury}: {e}"))?;
                    let base = randprotocol_core::gas::BUNDLE_BASE;
                    // Revoked already: the schedule has stopped, so what is left for the
                    // treasury is fixed — sweep it exactly, no margin (STAKE-4).
                    let revoked = !now["revoked_at"].is_null();
                    let unvested = if revoked {
                        let left = amount_field(&now, "unvested_now")?;
                        anyhow::ensure!(left > base, "entry {entry} is revoked and nothing above the {} RAND base is left to sweep ({} RAND)", format_amount(base), format_amount(left));
                        left
                    } else {
                        let head_ms = now["as_of_ms"].as_u64().context("the node's vesting reply has no as_of_ms")?;
                        let at = head_ms.saturating_add(margin_secs.saturating_mul(1_000));
                        let unvested = amount_field(&vesting_entry(&rpc, &id, Some(at)).await?, "unvested_now")?;
                        anyhow::ensure!(unvested > base, "nothing left to revoke: {} RAND unvested {margin_secs} s from now", format_amount(unvested));
                        unvested
                    };
                    let nonce = now["revoke_nonce"].as_u64().context("the node's vesting reply has no revoke_nonce")?;
                    let chain_id = rpc.chain_id().await?;
                    let genesis = rpc.genesis_hash().await?;
                    let time = rpc.head().await?["height"].as_u64().context("head has no height")? as u32;
                    let mut proposal =
                        RevokeProposal::new(chain_id, &genesis, &id, unvested, nonce, &to, time, envelope_format(&rpc, chain_id).await?)?;
                    proposal.revokers = now["revokers"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                        .unwrap_or_default();
                    proposal.threshold = now["threshold"].as_u64().unwrap_or(0) as u8;
                    std::fs::write(&out, serde_json::to_string_pretty(&proposal)?).with_context(|| format!("writing {}", out.display()))?;
                    println!(
                        "prepared the {} of entry {entry}: {} RAND to the treasury {}{}\n  written to {}: {} of {} revokers sign it (`vesting revoke sign`), then `vesting revoke submit`, within 256 blocks of height {time}",
                        if revoked { "sweep" } else { "revoke" },
                        format_amount(unvested),
                        to.fingerprint(),
                        if revoked { String::new() } else { format!(" (unvested {margin_secs} s from now; whatever the margin leaves is swept by preparing again once it lands)") },
                        out.display(),
                        proposal.threshold,
                        proposal.revokers.len(),
                    );
                }
                RevokeCmd::Sign { proposal, key, index } => {
                    let kp = load_keypair(&key)?;
                    let proposal = RevokeProposal::read(&proposal)?;
                    let p = proposal.parts()?;
                    // stderr, so stdout is exactly the signature line a script passes on.
                    eprintln!(
                        "signing the revoke of entry {} on chain {} (genesis {}):\n  {} RAND unvested, nonce {}, note time {}\n  paid to {} (fingerprint {})\n  check that address against the entry's `treasury` in the genesis file",
                        proposal.entry,
                        p.chain_id,
                        proposal.genesis,
                        format_amount(p.unvested),
                        p.nonce,
                        p.time,
                        proposal.to,
                        p.to.fingerprint(),
                    );
                    println!("{}", proposal.sign(&kp, index)?);
                }
                RevokeCmd::Submit { proposal, signatures, rpc, no_wait } => {
                    let proposal = RevokeProposal::read(&proposal)?;
                    let action = proposal.action(&signatures)?;
                    let rpc = RpcClient::new(rpc);
                    let chain_id = rpc.chain_id().await?;
                    anyhow::ensure!(chain_id == proposal.chain_id, "the revoke was prepared for chain {}, this node serves chain {chain_id}", proposal.chain_id);
                    let unvested = proposal.parts()?.unvested;
                    let tx = randprotocol_core::Transaction { chain_id, bundle: None, action };
                    let hash = rpc.send_transaction(&tx).await?;
                    let what = format!("revoke of {} RAND", format_amount(unvested));
                    if no_wait {
                        println!("submitted {what} {hash}");
                    } else {
                        let receipt = rpc.wait_for_transaction(&hash, wallet::COMMIT_TIMEOUT).await?;
                        println!("submitted {what} {hash}\n  committed in block {}", receipt.height);
                    }
                }
            },
            VestingCmd::Bond { entry, validator, amount, registration, staking } => {
                use randprotocol_core::types::actions::{bond_vested_message, Registration};
                let kp = load_keypair(&staking.key)?;
                let id = parse_entry_id(&entry)?;
                let validator = randprotocol_core::Address::from_base58(&validator)
                    .map_err(|e| anyhow::anyhow!("{validator} is not a validator address: {e}"))?;
                let amount = parse_amount(&amount)?;
                let registration = match registration {
                    Some(h) => Some(
                        Registration::decode(&hex::decode(&h).context("--registration is hex")?)
                            .map_err(|e| anyhow::anyhow!("--registration: {e}"))?,
                    ),
                    None => None,
                };
                let rpc = RpcClient::new(staking.rpc.clone());
                let v = vesting_entry(&rpc, &id, None).await?;
                anyhow::ensure!(v["revocable"] == serde_json::json!(false), "a revocable entry cannot bond");
                let nonce = v["nonce"].as_u64().context("the node's vesting reply has no nonce")?;
                let chain_id = rpc.chain_id().await?;
                let genesis = rpc.genesis_hash().await?;
                let signature =
                    kp.sign(bond_vested_message(&genesis, chain_id, &id, &validator, amount, nonce, registration.as_ref()).as_bytes());
                let action = randprotocol_core::Action::BondVested { entry: id, validator, amount, registration, nonce, signature };
                submit_staking(&staking, chain_id, action, &format!("bond of {} locked RAND to {validator}", format_amount(amount))).await?;
            }
            VestingCmd::Unbond { entry, amount, staking } => {
                use randprotocol_core::types::actions::unbond_vested_message;
                let kp = load_keypair(&staking.key)?;
                let id = parse_entry_id(&entry)?;
                let amount = parse_amount(&amount)?;
                let rpc = RpcClient::new(staking.rpc.clone());
                let v = vesting_entry(&rpc, &id, None).await?;
                let nonce = v["nonce"].as_u64().context("the node's vesting reply has no nonce")?;
                let chain_id = rpc.chain_id().await?;
                let genesis = rpc.genesis_hash().await?;
                let signature = kp.sign(unbond_vested_message(&genesis, chain_id, &id, amount, nonce).as_bytes());
                let action = randprotocol_core::Action::UnbondVested { entry: id, amount, nonce, signature };
                submit_staking(&staking, chain_id, action, &format!("unbond of {} locked RAND", format_amount(amount))).await?;
            }
        },
        Cmd::Aggregator { cmd } => match cmd {
            AggregatorCmd::Register { key, bond, payout, rpc } => {
                let kp = load_keypair(&key)?;
                let rpc = RpcClient::new(rpc);
                let chain_id = rpc.chain_id().await?;
                let payout = ShieldedAddress::parse(&payout)
                    .map_err(|e| anyhow::anyhow!("{payout} is not a shielded address: {e}"))?;
                let domain = rpc.binding_domain(chain_id).await?;
                let signature = kp.sign(domain.aggregator_register_message(chain_id, &kp.address(), &payout).as_bytes());
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
                let domain = rpc.binding_domain(chain_id).await?;
                let signature = kp.sign(domain.aggregator_unbond_message(chain_id, &kp.address(), nonce).as_bytes());
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
                let (note, envelope) = sealed_withdraw_note(&payout, bond - base, time, envelope_format(&rpc, chain_id).await?)?;
                let domain = rpc.binding_domain(chain_id).await?;
                let signature = kp.sign(
                    domain.aggregator_withdraw_message(chain_id, &kp.address(), nonce, time, &note.r, &envelope).as_bytes(),
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

/// What the aggregate daemon asks of its node: one JSON-RPC call. A trait so a test can stand in
/// for the node — and move the chain on while the prover runs, which is the whole of IFACE-8.
trait AggregateNode {
    async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value>;
    /// The chain's note-envelope format (`rand_getLimits.envelope_bytes`, v0.5.10): the payout
    /// note is sealed in it, or a memo-format chain refuses the aggregate's envelope. `chain_id` is
    /// the transaction's own (issue #64).
    async fn envelope_format(&self, chain_id: u64) -> Result<EnvelopeFormat>;
    /// The chain's binding domain for `chain_id` (BIND-1, `RpcClient::binding_domain`): what
    /// the aggregate binding the proof commits to and the signing hash carry.
    async fn binding_domain(&self, chain_id: u64) -> Result<randprotocol_core::BindingDomain>;
}

impl AggregateNode for RpcClient {
    async fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        RpcClient::call(self, method, params).await
    }
    async fn envelope_format(&self, chain_id: u64) -> Result<EnvelopeFormat> {
        envelope_format(self, chain_id).await
    }
    async fn binding_domain(&self, chain_id: u64) -> Result<randprotocol_core::BindingDomain> {
        RpcClient::binding_domain(self, chain_id).await
    }
}

/// The aggregator register row for `me`: nonce, payout and bond, from `rand_getAggregators`.
async fn aggregator_row(rpc: &impl AggregateNode, me: &randprotocol_core::Address) -> Result<(u64, ShieldedAddress, u64)> {
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

/// The one rVM aggregate proof over the raw bundle proofs, bound to `binding` — the daemon's
/// only expensive step (~26 min at the test profile), a function of its own so the pass around
/// it can be driven without the rVM.
fn prove_aggregate(profile: FriProfile, raw_proofs: &[Vec<u8>], binding: &[u32; 8]) -> Result<Vec<u8>> {
    let proofs = raw_proofs
        .iter()
        .map(|b| postcard::from_bytes::<randprotocol_zkvm::machine::Proof>(b).map_err(|_| anyhow::anyhow!("a work row's proof does not decode")))
        .collect::<Result<Vec<_>>>()?;
    // The shape is the first proof's; every proof in the set must share it (the chain's
    // admission checks it again).
    let first = proofs.first().context("nothing to aggregate")?;
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
    let a = randprotocol_rvm::aggregate::aggregate(&m, &vk, &proofs, binding, None)
        .map_err(|e| anyhow::anyhow!("aggregating {} bundles: {e:?}", proofs.len()))?;
    let proof_bytes = a.proof.to_bytes();
    tracing::info!("aggregated {} bundles in {:.1?} ({} proof bytes)", proofs.len(), t0.elapsed(), proof_bytes.len());
    Ok(proof_bytes)
}

/// One pass of the aggregate daemon up to the signed transaction (spec §8's shape): the
/// unsealed work list, up to `max_covers` of it, the raw bundles fetched back, one proof over
/// them (`prove`), and the signed aggregate — or `None` when there is nothing to cover.
///
/// What is read before the prove and what after is the point (the interface review's IFACE-8).
/// The prove takes tens of minutes; the payout note's `time` must sit inside the ledger's
/// `TIME_WINDOW` (256 blocks, ~6 min) of the head *at submission*, and its subsidy is the
/// schedule at the `sealed_blocks` of that moment — so both are read after the prove,
/// immediately before the transaction is built; read before it (as they were), every aggregate
/// arrived with a `time` long out of window. The nonce is the one thing the proof binds (audit
/// v3, AGG-2), so it is read before; it is read again after, and a pass whose nonce moved
/// meanwhile (another of this key's aggregates, or its unbond, committed) is abandoned rather
/// than submitted to certain refusal. The shares are each cover's bucketed excess, fixed at the
/// bundle's inclusion (IFACE-7) — a cover that left the bucket in the meantime makes the
/// aggregate invalid whatever it pays, and admission names it.
async fn aggregate_pass(
    rpc: &impl AggregateNode,
    kp: &Keypair,
    chain_id: u64,
    prove: impl FnOnce(FriProfile, &[Vec<u8>], &[u32; 8]) -> Result<Vec<u8>>,
) -> Result<Option<randprotocol_core::Transaction>> {
    let status = rpc.call("rand_status", serde_json::json!([])).await?;
    let profile = match status["fri_profile"].as_str().unwrap_or("production") {
        "test" => FriProfile::Test,
        _ => FriProfile::Production,
    };
    let max_covers = status["aggregation"]["max_covers"].as_u64().unwrap_or(0) as usize;
    let work = rpc.call("rand_getUnsealed", serde_json::json!([0, max_covers.max(1)])).await?;
    let bundles = work["bundles"].as_array().cloned().unwrap_or_default();
    if bundles.is_empty() || max_covers == 0 {
        return Ok(None);
    }
    let chosen = &bundles[..bundles.len().min(max_covers)];
    // The raw bundles, back from the node: each one's stored proof is the tape input.
    let mut raw_proofs = Vec::with_capacity(chosen.len());
    let mut covers = Vec::with_capacity(chosen.len());
    let mut shares = 0u64;
    for b in chosen {
        let hash = randprotocol_core::Hash::from_hex(b["hash"].as_str().context("work row has no hash")?)
            .map_err(|e| anyhow::anyhow!("work row hash: {e}"))?;
        let raw = rpc.call("rand_getRawTransaction", serde_json::json!([b["hash"].clone()])).await?;
        let bytes = hex::decode(raw.as_str().context("getRawTransaction answer is not hex")?)?;
        let tx: randprotocol_core::Transaction = bincode::deserialize(&bytes)?;
        let bundle = tx.bundle.as_ref().context("a work row with no bundle")?;
        covers.push(hash);
        // The node's own bucketed excess (IFACE-7), never `fee − BUNDLE_BASE` recomputed
        // here: a token registration under `tokens.burn_registration_fee` is bucketed net
        // of the burned fee, and a note over any other amount is refused at step 5.
        let excess = randprotocol_client::amount_field(&b["excess"]).context("work row has no excess")?;
        shares = shares.saturating_add(excess);
        raw_proofs.push(bundle.proof.clone());
    }
    // The proof binds this aggregator's own `(chain, address, nonce)` (audit v3, AGG-2): the
    // register nonce is read before proving, and the submission below signs the same nonce — a
    // proof made for one nonce verifies at no other.
    let nonce = aggregator_row(rpc, &kp.address()).await?.0;
    let domain = rpc.binding_domain(chain_id).await?;
    let binding = domain.aggregate_binding(chain_id, &kp.address(), nonce);
    let proof_bytes = prove(profile, &raw_proofs, &binding)?;

    // After the prove, immediately before the transaction: the head, the schedule, the payout
    // and the nonce as they are *now* (IFACE-8).
    let (nonce_now, payout, _) = aggregator_row(rpc, &kp.address()).await?;
    if nonce_now != nonce {
        anyhow::bail!(
            "the register nonce moved from {nonce} to {nonce_now} while proving; the proof is bound to {nonce} and \
             can never verify — abandoning this pass"
        );
    }
    let status = rpc.call("rand_status", serde_json::json!([])).await?;
    let agg = &status["aggregation"];
    // `subsidy_base` is a decimal string since node N-3 (2026-09-20); `amount_field` reads
    // either encoding, so this daemon works against an older node too.
    let subsidy_base = randprotocol_client::amount_field(&agg["subsidy_base"]).unwrap_or(0);
    let halving = agg["halving_blocks"].as_u64().unwrap_or(1).max(1);
    let n = agg["sealed_blocks"].as_u64().unwrap_or(0);
    let height = status["height"].as_u64().context("the node's status has no height")?;
    // The payment note: the subsidy at the schedule's current index plus the proving shares,
    // sealed to the register's payout address (spec §5.4).
    let subsidy = subsidy_base.checked_shr((n / halving) as u32).unwrap_or(0);
    let time = height as u32 + 1;
    let (note, envelope) = sealed_withdraw_note(&payout, subsidy.saturating_add(shares), time, rpc.envelope_format(chain_id).await?)?;
    let signature = kp.sign(
        domain
            .aggregate_signing_hash(chain_id, nonce, time, &note.r, &covers, &randprotocol_core::Hash::digest(&proof_bytes), &randprotocol_core::types::actions::envelope_digest(&envelope))
            .as_bytes(),
    );
    Ok(Some(randprotocol_core::Transaction {
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
    }))
}

/// The aggregate daemon: [`aggregate_pass`], submitted, and `--watch` loops it on the interval;
/// every pass is one proving job.
async fn aggregate_daemon(key: &std::path::Path, rpc_url: &str, watch: bool, interval_secs: u64, no_wait: bool) -> Result<()> {
    let kp = load_keypair(key)?;
    let rpc = RpcClient::new(rpc_url.to_string());
    let chain_id = rpc.chain_id().await?;
    loop {
        match aggregate_pass(&rpc, &kp, chain_id, prove_aggregate).await? {
            Some(tx) => {
                let covered = match &tx.action {
                    randprotocol_core::Action::Aggregate { covers, .. } => covers.len(),
                    _ => 0,
                };
                let hash = rpc.send_transaction(&tx).await?;
                if no_wait {
                    println!("submitted aggregate {hash} ({covered} covered)");
                } else {
                    let receipt = rpc.wait_for_transaction(&hash, wallet::COMMIT_TIMEOUT).await?;
                    println!("submitted aggregate {hash} ({covered} covered)\n  committed in block {}", receipt.height);
                }
                if !watch {
                    return Ok(());
                }
            }
            None if !watch => {
                println!("nothing to cover right now");
                return Ok(());
            }
            None => {}
        }
        tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
    }
}

/// The shortest history a node may keep: shorter than an hour and a node that restarts on the
/// hour has nothing for a peer to sync from.
pub const MIN_PRUNE_HISTORY: Duration = Duration::from_secs(3600);

/// `<n>m`, `<n>h` or `<n>d`.
pub fn parse_prune_history(s: &str) -> Result<Duration, String> {
    let usage = "prune-history takes <n>m, <n>h or <n>d";
    if !s.is_ascii() {
        return Err(usage.to_string());
    }
    let (num, unit) = s.split_at(s.len().checked_sub(1).ok_or(usage)?);
    let n: u64 = num.parse().map_err(|_| usage.to_string())?;
    let secs = match unit {
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3600),
        "d" => n.checked_mul(86_400),
        _ => return Err(usage.to_string()),
    }
    .ok_or(usage)?;
    let d = Duration::from_secs(secs);
    if d < MIN_PRUNE_HISTORY {
        return Err("prune-history must be at least 1h".to_string());
    }
    Ok(d)
}

/// `rand-node genesis`'s gas flags as the genesis `gas` section (spec §4.2, §4.3, §7.1):
/// `None` without `--gas-price`, so a chain cut without it hashes byte-for-byte as before — and
/// then any of the other three gas flags is an error, never a silently section-less genesis.
/// `rand-node genesis`'s three audit-v6 (POOL-2) additions to `--gas-dynamic`: the two ceilings
/// and the byte load. Each is refused without `--gas-dynamic` (there is no controller for a
/// ceiling to bound), never silently dropped.
#[derive(Clone, Copy, Default)]
struct DynamicExtras<'a> {
    max_gas_price: Option<u64>,
    max_byte_price: Option<u64>,
    byte_load: Option<&'a str>,
}

fn gas_section(
    gas_price: Option<u64>,
    byte_price: Option<u64>,
    bundle_gas_limit: Option<u64>,
    gas_dynamic: Option<&str>,
    extras: DynamicExtras<'_>,
) -> Result<Option<randprotocol_core::gas::GasConfig>> {
    if gas_dynamic.is_none() {
        let given: Vec<&str> = [
            extras.max_gas_price.map(|_| "--max-gas-price"),
            extras.max_byte_price.map(|_| "--max-byte-price"),
            extras.byte_load.map(|_| "--gas-byte-load"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !given.is_empty() {
            anyhow::bail!("{} given without --gas-dynamic: a ceiling or a byte load bounds the dynamic controller, which this genesis would not have", given.join(", "));
        }
    }
    if gas_price.is_none() {
        let given: Vec<&str> = [
            byte_price.map(|_| "--byte-price"),
            bundle_gas_limit.map(|_| "--bundle-gas-limit"),
            gas_dynamic.map(|_| "--gas-dynamic"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !given.is_empty() {
            anyhow::bail!(
                "{} given without --gas-price: the gas section is written only with --gas-price, so this genesis would \
                 have none",
                given.join(", ")
            );
        }
    }
    Ok(match gas_price {
        Some(gas_price) => Some(randprotocol_core::gas::GasConfig {
            gas_price,
            byte_price: byte_price.unwrap_or(randprotocol_core::gas::BYTE_PRICE_DEFAULT),
            bundle_gas_limit: bundle_gas_limit_or_default(bundle_gas_limit),
            metering: randprotocol_core::gas::GasMetering::Circuit,
            dynamic: match gas_dynamic {
                Some(spec) => {
                    let parts: Vec<&str> = spec.split(',').collect();
                    let [target_block_bytes, target_block_gas, adjust_bps] = parts.as_slice() else {
                        anyhow::bail!(
                            "--gas-dynamic {spec} must be <target_block_bytes>,<target_block_gas>,<adjust_bps>"
                        );
                    };
                    let byte_price = byte_price.unwrap_or(randprotocol_core::gas::BYTE_PRICE_DEFAULT);
                    Some(randprotocol_core::gas::DynamicGas {
                        target_block_bytes: target_block_bytes
                            .parse()
                            .with_context(|| format!("--gas-dynamic {spec}: bad target_block_bytes"))?,
                        target_block_gas: target_block_gas
                            .parse()
                            .with_context(|| format!("--gas-dynamic {spec}: bad target_block_gas"))?,
                        adjust_bps: adjust_bps
                            .parse()
                            .with_context(|| format!("--gas-dynamic {spec}: bad adjust_bps"))?,
                        min_gas_price: gas_price,
                        min_byte_price: byte_price,
                        max_gas_price: extras.max_gas_price,
                        max_byte_price: extras.max_byte_price,
                        byte_load: match extras.byte_load {
                            None => None,
                            Some("paying") => Some(randprotocol_core::gas::ByteLoad::Paying),
                            Some(other) => anyhow::bail!("--gas-byte-load {other}: only `paying` is a byte load"),
                        },
                    })
                }
                None => None,
            },
        }),
        None => None,
    })
}

/// `rand-node genesis --bundle-gas-limit`'s value, or its default: what every real hidden-asset
/// bundle proof declares, the tier-14 hash-free ceiling `gas_max(BUNDLE_PROOF_TIER, 0, 0)` (spec
/// §4.3) — also the only value `Genesis::build` accepts (`GasConfig::check`), so a flag naming
/// anything else is refused before the file is written.
fn bundle_gas_limit_or_default(v: Option<u64>) -> u64 {
    v.unwrap_or_else(randprotocol_core::gas::bundle_gas_limit_pin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::ledger::staking::MIN_STAKE;

    /// Issue #60: every subcommand that opens RocksDB raises the open-files limit first — not
    /// only `run`, whose `node::start` did it since #41. `verify --repair` is the one that
    /// matters most: it runs by hand, under a login shell's limit, on a node already in trouble.
    #[test]
    fn every_subcommand_that_opens_the_database_raises_the_open_files_limit() {
        let cmd = |args: &[&str]| Cli::try_parse_from(std::iter::once("rand-node").chain(args.iter().copied())).unwrap().cmd;
        for args in [
            &["verify", "--datadir", "d"][..],
            &["verify", "--datadir", "d", "--repair"],
            &["db", "drop-receipts-index", "--datadir", "d"],
            &["init", "--datadir", "d", "--genesis", "g.json"],
            &["run", "--datadir", "d", "--key", "k.json"],
        ] {
            assert!(opens_storage(&cmd(args)), "`rand-node {}` opens RocksDB under the shell's open-files limit", args.join(" "));
        }
        for args in [&["status"][..], &["keygen", "--out", "k.json"], &["address", "--key", "k.json"]] {
            assert!(!opens_storage(&cmd(args)), "`rand-node {}` opens no database", args.join(" "));
        }
    }
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
        bad_profile.admitted_shapes = vec![shape];
        g_bad_profile.aggregation = Some(bad_profile);
        match g_bad_profile.build(&ZkExecutor::new(FriProfile::Test)) {
            Err(randprotocol_core::genesis::GenesisError::BadAggregationConfig(m)) => {
                assert!(m.contains("Production"), "{m}");
            }
            other => panic!("a Production shape on a test chain must be refused, got {other:?}"),
        }
        // And the real thing builds, with the register empty and the gated root — at the chain's
        // own profile and the pinned bundle header (IFACE-9: the inner tier 14, the binding's
        // public height 7 under constraint set 7's 2^7 floor; 19 is an rVM *aggregate* tier, never a bundle's).
        let test_shape = parse_admitted_shape(&format!("test,14,12,10,0,0,7,16,{hc_hex},{digest_hex}")).unwrap();
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
    /// Audit v6, STAKE-2: the `admit` commands. `sign` prints one vote line; `submit` checks
    /// every line against the chain's own admission message before it sends anything — a vote for
    /// another genesis or another candidate is named, a voter listed twice is refused — and puts
    /// the votes in the ascending voter order the ledger requires. The candidate is taken as a
    /// key, as the registration `rand-node register` printed, or as a file holding either.
    #[test]
    fn the_admit_commands_sign_check_and_order_the_votes() {
        let cli = Cli::try_parse_from([
            "rand-node", "admit", "sign", "--candidate", "ab", "--key", "k.json", "--genesis-hash", "00",
        ])
        .unwrap();
        assert!(matches!(cli.cmd, Cmd::Admit { cmd: AdmitCmd::Sign { .. } }));
        let cli = Cli::try_parse_from([
            "rand-node", "admit", "submit", "--candidate", "ab", "--signature", "a:b", "--signature", "c:d",
        ])
        .unwrap();
        let Cmd::Admit { cmd: AdmitCmd::Submit { signatures, rpc, no_wait, .. } } = cli.cmd else { panic!("admit submit") };
        assert_eq!((signatures.len(), rpc.as_str(), no_wait), (2, "http://127.0.0.1:8545", false));
        assert!(Cli::try_parse_from(["rand-node", "admit", "submit", "--candidate", "ab"]).is_err(), "at least one vote");

        let key = |n: u8| Keypair::from_seed([n; 32]).unwrap();
        let (candidate, genesis) = (key(9), randprotocol_core::Hash::digest(b"this chain"));
        // The candidate, three ways.
        let as_key = parse_candidate(&candidate.public_key().to_hex()).unwrap();
        assert_eq!(&as_key, candidate.public_key());
        let payout = ShieldedAddress { pk: [1; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] };
        let registration = Registration {
            public_key: candidate.public_key().clone(),
            payout: payout.clone(),
            signature: candidate.sign(randprotocol_core::types::actions::registration_message(7, &payout).as_bytes()),
        };
        let blob = hex::encode(registration.encode());
        assert_eq!(&parse_candidate(&blob).unwrap(), candidate.public_key());
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("registration.txt");
        std::fs::write(&file, format!("validator {} on chain 7\nregistration: {blob}\n", candidate.address())).unwrap();
        assert_eq!(&parse_candidate(file.to_str().unwrap()).unwrap(), candidate.public_key());
        assert!(parse_candidate("not-hex").is_err());
        assert!(parse_candidate("abcd").is_err(), "hex, but neither a key nor a registration");

        // The votes: checked, sorted, each voter once.
        let lines: Vec<String> = [3u8, 1, 2].iter().map(|n| admit_vote_line(&key(*n), &genesis, candidate.public_key())).collect();
        let randprotocol_core::Action::AdmitValidator { candidate: named, signatures } =
            admit_action(&genesis, candidate.public_key(), &lines).unwrap()
        else {
            panic!("an admission")
        };
        assert_eq!(&named, candidate.public_key());
        let voters: Vec<_> = signatures.iter().map(|(k, _)| k.address()).collect();
        let mut sorted = voters.clone();
        sorted.sort();
        assert_eq!(voters, sorted, "ascending voter order");
        assert_eq!(voters.len(), 3);
        let message = admit_validator_message(&genesis, &candidate.address());
        assert!(signatures.iter().all(|(k, s)| k.verify(message.as_bytes(), s)));
        // A vote signed for another genesis, or for another candidate, is named before anything is sent.
        let foreign = admit_vote_line(&key(1), &randprotocol_core::Hash::digest(b"another chain"), candidate.public_key());
        let e = admit_action(&genesis, candidate.public_key(), &[lines[0].clone(), foreign]).unwrap_err().to_string();
        assert!(e.contains(&key(1).address().to_string()) && e.contains("another genesis"), "{e}");
        let other = admit_vote_line(&key(1), &genesis, key(10).public_key());
        assert!(admit_action(&genesis, candidate.public_key(), &[other]).is_err());
        // A voter twice.
        let e = admit_action(&genesis, candidate.public_key(), &[lines[0].clone(), lines[0].clone()]).unwrap_err().to_string();
        assert!(e.contains("votes twice"), "{e}");
        assert!(admit_action(&genesis, candidate.public_key(), &["nocolon".to_string()]).is_err());
    }

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
        let refused = node::check_build_runs_genesis(&state, &ZkExecutor::known_hc_bundles()).unwrap_err().to_string();
        assert!(refused.contains("differs from the genesis hc_bundle"), "{refused}");
    }

    /// Chain 14, the running chain, byte for byte, after the v4 re-review's `staking` fields
    /// (weight cap, entry budget, registration v2) and the bond queue: the file has no
    /// `staking` section, so none of it may move its hash, its state root domain or its epoch-0
    /// set by one bit — and it still loads and builds on this build.
    #[test]
    fn chain_14s_genesis_file_still_builds_chain_14() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain14.json");
        let gen = Genesis::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(gen.staking.is_none(), "chain 14 carries no staking section");
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let state = gen.build(executor.as_ref()).unwrap();
        assert_eq!(state.hash().to_hex(), "1cff3b7da248d93ab547aef5c05bb7d0d22da510b592dab9cf7374807de7c7ff");
        assert!(state.ledger.staking().is_none() && state.ledger.bond_queue().is_empty());
        // Every genesis validator's weight is its stake: no cap reached the set.
        for v in &gen.validators {
            assert_eq!(state.validators.get(&v.public_key.address()).unwrap().stake, v.stake);
        }
        assert!(!gen.to_json().contains("staking"), "rewriting the file adds no section");
    }

    /// Chain 15, the running chain, byte for byte, after RESCAN-LEDGER-1's
    /// `staking.faucet_minters`, C15-1's bridge replay floor and the v0.6 `hardening_v6` switch:
    /// the file lists none of them, so its
    /// hash may not move by one bit, its bridge root carries no floor, the ledger's minter rule
    /// stays the register row, every node's pool admits the genesis validators' mints only, and
    /// rewriting the file adds no field. Every later genesis-gated field is pinned against this
    /// file the way chain 14's are against its own.
    #[test]
    fn chain_15s_genesis_file_still_builds_chain_15() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain15.json");
        let gen = Genesis::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
        let staking = gen.staking.as_ref().expect("chain 15 carries a staking section");
        assert_eq!(staking.faucet_minters, None, "chain 15 predates the list");
        let bridge = gen.bridge.as_ref().expect("chain 15 is bridged");
        assert_eq!((bridge.guardian_set_index, bridge.burn_sequence), (Some(1), Some(7)));
        assert_eq!(bridge.min_inbound_sequence, None, "chain 15 carries no replay floor");
        assert_eq!(gen.hardening_v6, None, "chain 15 predates the v0.6 rules (ZKV-11 and the rest)");
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let state = gen.build(executor.as_ref()).unwrap();
        assert_eq!(state.hash().to_hex(), "cc30e0854fb25b3abcee96bb7bc206dcd6e37862f6dfe80a05b3e474c2d1b6b8");
        let live = state.ledger.bridge().unwrap();
        assert!(live.min_inbound_sequence.is_empty() && live.replay_floor().is_none());
        assert!(!state.ledger.hardening_v6(), "the ledger keeps the old rules; the pool refuses as policy");
        let json = gen.to_json();
        assert!(!json.contains("faucet_minters"), "rewriting the file adds no list");
        assert!(!json.contains("min_inbound_sequence"), "rewriting the file adds no field");
        assert!(!json.contains("hardening_v6"), "nor the v0.6 switch");
        let minters = randprotocol_node::admission::faucet_minters(&state);
        assert_eq!(minters.len(), gen.validators.len(), "the pool admits the genesis validators");
        assert!(gen.validators.iter().all(|v| minters.contains(&v.public_key.address())));
    }

    /// Split authorisation's genesis `hc_auth` is hashed only when present (after
    /// `hardening_v6`), so the committed chain-15 and chain-16 files — neither names one — still
    /// hash to their live genesis, build ledgers without the rule, and rewrite without the field.
    #[test]
    fn the_genesis_hash_is_unchanged_without_hc_auth() {
        for (file, hash) in [
            ("genesis-chain15.json", "cc30e0854fb25b3abcee96bb7bc206dcd6e37862f6dfe80a05b3e474c2d1b6b8"),
            ("genesis-chain16.json", "20925ae63cfa6e6c96f3ff369486ead8ea04821fec026a55df9e2893f3d53005"),
        ] {
            let path = format!("{}/../../deploy/{file}", env!("CARGO_MANIFEST_DIR"));
            let gen = Genesis::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
            assert_eq!(gen.hc_auth, None, "{file} predates split authorisation");
            let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
            let state = gen.build(executor.as_ref()).unwrap();
            assert_eq!(state.hash().to_hex(), hash, "{file}");
            assert_eq!(state.ledger.hc_auth(), None, "{file}: the ledger keeps the v1 digest");
            assert!(!gen.to_json().contains("hc_auth"), "{file}: rewriting the file adds no field");
            // And the same file naming the auth guest is another chain.
            // (With the chain-17 caps: a split-authorisation genesis needs block room for three
            // proofs, which neither file has.)
            let mut split = gen.clone();
            split.hc_auth = Some(word8_to_hex(&ZkExecutor::hc_auth()));
            split.max_proof_bytes = Some(4 << 20);
            split.max_block_bytes = Some(20 << 20);
            assert_ne!(split.build(executor.as_ref()).unwrap().hash().to_hex(), hash, "{file}");
        }
    }

    /// v0.6.1 was constraint set 7 and this build is 8: every verifier key moved, so no bundle or
    /// call proof chains 14 and 15 (constraint set 6) committed verifies on this build. Both genesis files pin guest v1, which this build
    /// still carries (a new chain may pin it), so the `hc_bundle` check alone let a v0.6.1 binary
    /// start on either chain — and its startup replay would then refuse the chain's own history.
    /// Chain 16 pins guest v2, also still carried, but this build (split authorisation) changes the
    /// bundle wire and every transaction id, so it would fail at chain 16's first bundle. Chain 17
    /// (v0.6.3, live since 2026-09-29) pins bundle guest v3 and `hc_auth`, both still carried, and
    /// committed its proofs under constraint set 7. The startup guard names all four and refuses
    /// them before any datadir is opened — at `run` (`check_build_runs_genesis`) and `verify`
    /// (`refuse_chains_this_build_cannot_run`).
    #[test]
    fn this_build_refuses_chains_14_to_17() {
        for (chain, file, why) in [
            (14, "genesis-chain14.json", "constraint set 6"),
            (15, "genesis-chain15.json", "constraint set 6"),
            (16, "genesis-chain16.json", "rand-txid-3, split authorisation"),
            (17, "genesis-chain17.json", "constraint set 7"),
        ] {
            let path = format!("{}/../../deploy/{file}", env!("CARGO_MANIFEST_DIR"));
            let gen = Genesis::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
            let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
            let state = gen.build(executor.as_ref()).unwrap();
            assert_eq!(state.chain_id, chain);
            assert!(ZkExecutor::known_hc_bundles().contains(&state.hc_bundle), "chain {chain} pins a guest this build carries");
            let refused = node::check_build_runs_genesis(&state, &ZkExecutor::known_hc_bundles())
                .expect_err(&format!("this build must refuse chain {chain} at run"))
                .to_string();
            assert!(refused.contains(why) && refused.contains(&format!("chain {chain}")), "{refused}");
            assert!(refused.contains("constraint set 8"), "names this build's set: {refused}");
            let at_verify = node::refuse_chains_this_build_cannot_run(&state)
                .expect_err(&format!("this build must refuse chain {chain} at verify"))
                .to_string();
            assert_eq!(at_verify, refused, "run and verify give the same reason");
        }
    }

    /// Chain 17, cut by `deploy/cut-chain17-genesis.sh` with the v0.6.3 release binary from a
    /// snapshot of chain 16 at height 30 191 (2026-09-29 03:03 UTC): the first split-authorisation
    /// chain — bundle guest v3 and `hc_auth`, the three-proof block rule (4 MiB proofs, 20 MiB
    /// blocks), chain 16's 26 validators, its bridge state (set 1, burn sequence 7, the replay
    /// floors at the snapshot's next sequences) and its zUSD, plus the RAND the operator's wallets
    /// held. `deploy/genesis-chain17.json` is committed and its hash is pinned in
    /// `node::CHAINS_THIS_BUILD_CANNOT_RUN`: this build is constraint set 8 (the gas meter) and
    /// refuses to run chain 17 — it verifies none of its cs7 proofs — but still names its exact
    /// genesis hash there, so the hash assertion below reads it from that one place (chain 16's
    /// test, the same way since v0.6.3).
    #[test]
    fn chain_17s_genesis_file_builds_chain_17() {
        let chain_17_hash = node::CHAINS_THIS_BUILD_CANNOT_RUN
            .iter()
            .find(|(chain, _, _)| *chain == 17)
            .map(|(_, hash, _)| *hash)
            .expect("chain 17 is pinned in CHAINS_THIS_BUILD_CANNOT_RUN");
        assert_eq!(chain_17_hash, "d1afefc3dd68f73e3799aa0803b692d0e6a5c7c27d228bdeb3d06cdf4027e7ff");
        let committed = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain17.json");
        let gen = Genesis::from_json(&std::fs::read_to_string(committed).unwrap()).unwrap();
        assert_eq!(gen.chain_id, 17);
        assert_eq!(gen.consensus_domain, Some(1));
        assert_eq!(gen.hardening_v6, Some(true));
        assert_eq!(gen.hc_bundle, word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()), "the v3 bundle guest");
        assert_eq!(gen.hc_auth.as_deref(), Some(word8_to_hex(&ZkExecutor::hc_auth()).as_str()), "the auth guest");
        assert_eq!(gen.max_proof_bytes, Some(4 << 20), "three proofs per transaction fit a 20 MiB block");
        assert_eq!(gen.max_block_bytes, Some(20 << 20));
        assert_eq!(gen.validators.len(), 26, "chain 16's register, carried");
        assert_eq!(gen.alloc.len(), 7, "six RAND allocs (shielded-1..5, the relayer) and the zUSD note");
        let bridge = gen.bridge.as_ref().expect("the bridge section");
        assert_eq!(bridge.burn_sequence, Some(7));
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let state = gen.build(executor.as_ref()).unwrap();
        assert_eq!(state.hash().to_hex(), chain_17_hash, "chain 17's live genesis");
        assert_eq!(state.ledger.hc_auth(), Some(ZkExecutor::hc_auth()), "the ledger enforces split authorisation");
        assert!(state.ledger.gas().is_none(), "chain 17 has no gas section");
        let refused = node::check_build_runs_genesis(&state, &ZkExecutor::known_hc_bundles())
            .expect_err("a constraint-set-8 build must refuse chain 17")
            .to_string();
        assert!(refused.contains("chain 17") && refused.contains("constraint set 7") && refused.contains("constraint set 8"), "{refused}");
    }

    /// The committed chain-18 genesis (LIVE 2026-09-29 04:56 UTC, cut by `deploy/cut-chain18-genesis.sh`
    /// from chain 17 at height 5 604 on the v0.6.7-rc1 build) builds chain 18: the hash the fleet runs,
    /// the gas section (Phase 1 prices 100/800, the bundle pin, the Phase 2 controller), the memo on,
    /// and this build accepts it — the counterpart of the chain-17 test above.
    #[test]
    fn chain_18s_genesis_file_builds_chain_18() {
        let chain_18_hash = "a7cb020cc99a33c83fc38cfa0ec1db357f67fbf8b6dab13ab1d9812280b4da76";
        let committed = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain18.json");
        let gen = Genesis::from_json(&std::fs::read_to_string(committed).unwrap()).unwrap();
        assert_eq!(gen.chain_id, 18);
        assert_eq!(gen.consensus_domain, Some(1));
        assert_eq!(gen.hardening_v6, Some(true));
        assert_eq!(gen.hc_bundle, word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()), "the v3 bundle guest, as chain 17");
        assert_eq!(gen.hc_auth.as_deref(), Some(word8_to_hex(&ZkExecutor::hc_auth()).as_str()), "the auth guest");
        assert_eq!(gen.max_proof_bytes, Some(4 << 20));
        assert_eq!(gen.max_block_bytes, Some(20 << 20));
        assert_eq!(gen.envelope_bytes, Some(1860), "the encrypted memo is on");
        assert!(gen.aggregation.is_none(), "no aggregation beside gas.dynamic");
        assert_eq!(gen.validators.len(), 26, "chain 17's register, carried");
        assert_eq!(gen.alloc.len(), 7, "six RAND allocs (shielded-1..5, the relayer) and the zUSD note");
        let gas = gen.gas.as_ref().expect("the gas section");
        assert_eq!(gas.gas_price, 100);
        assert_eq!(gas.byte_price, 800);
        assert_eq!(gas.bundle_gas_limit, randprotocol_core::gas::bundle_gas_limit_pin());
        assert_eq!(gas.bundle_gas_limit, 20_479);
        let dynamic = gas.dynamic.as_ref().expect("the Phase 2 controller");
        assert_eq!(dynamic.target_block_bytes, 10_485_760, "half the 20 MiB block cap");
        assert_eq!(dynamic.target_block_gas, 262_144);
        assert_eq!(dynamic.adjust_bps, 1250);
        let bridge = gen.bridge.as_ref().expect("the bridge section");
        assert_eq!(bridge.burn_sequence, Some(7));
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let state = gen.build(executor.as_ref()).unwrap();
        assert_eq!(state.hash().to_hex(), chain_18_hash, "chain 18's live genesis");
        assert!(state.ledger.gas().is_some(), "the ledger prices calls and pins the bundle limit");
        assert_eq!(state.ledger.envelope_bytes(), Some(1860));
        node::check_build_runs_genesis(&state, &ZkExecutor::known_hc_bundles()).expect("this build runs chain 18");
    }

    /// This build is constraint set 8 (the gas meter, chain 18): every verifier key moved again, so
    /// no proof chain 16 (constraint set 7, v0.6.1) committed verifies here. Chain 16 pins the v2
    /// guest, which this build still carries, so the `hc_bundle` check alone would let this binary
    /// start on chain 16 — and its startup replay (or a `verify --repair`) would then refuse, and
    /// truncate, the chain's own history. The guard names the chain, its set and the archive risk.
    #[test]
    fn a_constraint_set_8_build_refuses_chain_16() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain16.json");
        let gen = Genesis::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let state = gen.build(executor.as_ref()).unwrap();
        assert_eq!(state.hash().to_hex(), "20925ae63cfa6e6c96f3ff369486ead8ea04821fec026a55df9e2893f3d53005");
        let refused = node::check_build_runs_genesis(&state, &ZkExecutor::known_hc_bundles())
            .expect_err("a constraint-set-8 build must refuse chain 16")
            .to_string();
        assert!(
            refused.contains("chain 16") && refused.contains("constraint set 7") && refused.contains("constraint set 8"),
            "{refused}"
        );
        assert!(refused.contains("archive"), "the message names the archive risk: {refused}");
        // `verify` calls the same guard before it opens the datadir.
        let verify = node::refuse_chains_this_build_cannot_run(&state).expect_err("verify refuses chain 16 too").to_string();
        assert_eq!(verify, refused);
    }

    /// Chain 16, cut by `deploy/cut-chain16-genesis.sh` with the v0.6.1 release binary: every
    /// genesis-gated field chain 15 lacks is present and builds — `staking.faucet_minters`, C15-1's
    /// `bridge.min_inbound_sequence`, `hardening_v6` and the v2 bundle guest — beside chain 15's
    /// custody, carried at genesis. `deploy/genesis-chain16.json` is committed and its hash is
    /// pinned in `node::CHAINS_THIS_BUILD_CANNOT_RUN` (this build refuses to run chain 16, but
    /// still names its exact genesis hash there), so the hash assertion below reads it from that
    /// one place rather than duplicating the literal. `CHAIN16_GENESIS=<a dry-run cut> cargo test
    /// … --ignored` still checks the structure of any other cut (the hash assertion is skipped).
    #[test]
    fn chain_16s_genesis_file_builds_chain_16() {
        let chain_16_hash = node::CHAINS_THIS_BUILD_CANNOT_RUN
            .iter()
            .find(|(chain, _, _)| *chain == 16)
            .map(|(_, hash, _)| *hash)
            .expect("chain 16 is pinned in CHAINS_THIS_BUILD_CANNOT_RUN");
        let committed = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain16.json");
        let path = std::env::var("CHAIN16_GENESIS").unwrap_or_else(|_| committed.to_string());
        let gen = Genesis::from_json(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(gen.chain_id, 16);
        assert_eq!(gen.consensus_domain, Some(1));
        assert_eq!(gen.hardening_v6, Some(true), "the v0.6 rules are validity rules on chain 16");
        assert!(gen.aggregation.is_none() && gen.vesting.is_none() && gen.envelope_bytes.is_none());
        assert_eq!(gen.validators.len(), 26, "chain 15's eighteen genesis validators and the eight it bonded");
        assert!(gen.validators.iter().all(|v| v.stake == u128::from(1000 * UNITS_PER_RAND)));
        let chain15 = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain15.json");
        let g15 = Genesis::from_json(&std::fs::read_to_string(chain15).unwrap()).unwrap();
        assert!(g15.validators.iter().all(|v| gen.validators.iter().any(|w| w.public_key == v.public_key)));
        assert_ne!(gen.hc_bundle, g15.hc_bundle, "chain 16 pins the v2 guest, not chain 15's v1");
        let staking = gen.staking.as_ref().expect("a staking section");
        let minters = staking.faucet_minters.as_ref().expect("LEDGER-1's minter list");
        assert!(!minters.is_empty());
        assert_eq!(staking.faucet_recipients, g15.staking.as_ref().unwrap().faucet_recipients);
        let bridge = gen.bridge.as_ref().expect("chain 16 is bridged");
        let floor = bridge.min_inbound_sequence.as_ref().expect("C15-1's replay floor");
        assert!(!floor.is_empty() && floor.values().all(|&f| f > 0));
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let state = gen.build(executor.as_ref()).unwrap();
        if std::env::var("CHAIN16_GENESIS").is_err() {
            assert_eq!(state.hash().to_hex(), chain_16_hash);
        }
        assert!(state.ledger.hardening_v6());
        assert_eq!(state.ledger.bridge().unwrap().replay_floor(), Some(floor));
        let pool = randprotocol_node::admission::faucet_minters(&state);
        assert_eq!(pool.len(), minters.len(), "the pool admits the listed minters, not every genesis validator");
        // Σ carried zUSD == Σ locked: the custody chain 15 leaves behind, as notes at genesis.
        let locked: u64 = gen.tokens.as_ref().unwrap().tokens[0].backings.iter().map(|b| b.locked.unwrap_or(0)).sum();
        let notes: u64 = gen.alloc.iter().filter(|n| n.opening.as_ref().is_some_and(|o| o.asset == 1)).map(|n| n.amount).sum();
        assert!(locked > 0);
        assert_eq!(notes, locked);
    }

    /// Chain 15's genesis custody, end to end on the real chain-14 file: chain 14's zUSD listed
    /// at genesis (same name, symbol and salt, so the same asset id), 9 USDT locked on Tron and 1
    /// on Solana, and one ten-zUSD note written by `rand-node alloc-note --asset 1` — which the
    /// owner's wallet opens, at asset 1, from the envelope alone, exactly as a scan does.
    #[test]
    fn an_alloc_note_of_zusd_builds_on_chain_14s_file_and_its_owner_opens_it() {
        use randprotocol_core::genesis::{GenesisBacking, GenesisToken};
        let cli = Cli::try_parse_from(["rand-node", "alloc-note", "--to", "rand1x", "--amount", "10", "--asset", "1"]).unwrap();
        assert!(matches!(cli.cmd, Cmd::AllocNote { asset: 1, .. }));

        let payee = SpendKey([0x15; 8]);
        let to = randprotocol_zkvm::address::address_of(&payee.viewing_key());
        // `--amount 10 --asset 1` is ten zUSD at the token's eight decimals, not RAND's nine.
        let units = alloc_note_units("10", 1).unwrap();
        assert_eq!(units, 1_000_000_000, "10 zUSD is 10^9 units at eight decimals");
        assert_eq!(alloc_note_units("10", 0).unwrap(), 10 * UNITS_PER_RAND);
        assert!(alloc_note_units("0.000000001", 1).is_err(), "a ninth decimal does not exist on zUSD");
        let note = alloc_note(&to.to_string(), units, 1, EnvelopeFormat::Legacy).unwrap();
        assert_eq!(note.opening.as_ref().unwrap().asset, 1);

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/genesis-chain14.json");
        let mut gen = Genesis::from_json(&std::fs::read_to_string(path).unwrap()).unwrap();
        let hex32 = |s: &str| -> [u8; 32] { hex::decode(s).unwrap().try_into().unwrap() };
        let coins: [(u16, &str, u8, Option<u64>); 7] = [
            (2, "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7", 6, None),
            (2, "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6, None),
            (3, "00000000000000000000000055d398326f99059ff775485246999027b3197955", 18, None),
            (3, "0000000000000000000000008ac76a51cc950d9822d68b83fe1ad97b32cd580d", 18, None),
            (4, "000000000000000000000000a614f803b6fd780986a42c78ec9c7f77e6ded13c", 6, Some(900_000_000)),
            (5, "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264", 6, Some(100_000_000)),
            (5, "c6fa7af3bedbad3a3d65f36aabc97431b1bbe4c2d2f6e0e47ca60203452f5d61", 6, None),
        ];
        gen.tokens.as_mut().unwrap().tokens = vec![GenesisToken {
            name: "Shielded USD".into(),
            symbol: "zUSD".into(),
            salt: hex32("27e77272ee77a47a6b66a62f3452dac66e681c79be6750d5e236e99f0d1e1d60"),
            backings: coins
                .iter()
                .map(|&(chain, token, decimals, locked)| GenesisBacking { chain, token: hex32(token), decimals, locked })
                .collect(),
        }];
        gen.alloc.push(note);
        let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
        let state = gen.build(executor.as_ref()).unwrap();
        let z = state.ledger.tokens().unwrap().get(1).unwrap();
        assert_eq!(z.id.to_hex(), "32e5ab28c782c663e14da2650a3feb12f16a12db85599f4f62dc169d26f37b1f");
        assert_eq!(z.total_supply, 1_000_000_000);
        assert!(state.ledger.tokens().unwrap().backing_invariant_holds());

        let (cm, envelope, amount) = state.notes.last().unwrap();
        let (_, opened) = randprotocol_zkvm::address::envelope_from_core(envelope)
            .open_as_receiver(*cm, &payee.viewing_key())
            .expect("the owner opens its genesis zUSD note");
        assert_eq!((opened.asset, opened.amount, *amount), (1, 1_000_000_000, 1_000_000_000));
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

    /// `--bundle-gas-limit`'s default is what every real hidden-asset bundle proof declares:
    /// `gas_max(14, 0, 0)` = 20 479 (the absorb term included), not the bare cycle budget 16 383
    /// — a genesis cut at 16 383 would refuse every bundle.
    #[test]
    fn the_bundle_gas_limit_defaults_to_the_bundle_guests_ceiling() {
        assert_eq!(bundle_gas_limit_or_default(None), randprotocol_core::gas::gas_max(14, 0, 0));
        assert_eq!(bundle_gas_limit_or_default(None), 20_479);
        // Any other value passes the flag through and is refused when the genesis is built
        // (final-review I3), which `rand-node genesis` does before it writes the file.
        assert_eq!(bundle_gas_limit_or_default(Some(7)), 7);
        for bad in [7, 16_383, 20_478] {
            let mut g = pinned_genesis();
            g.gas = Some(randprotocol_core::gas::GasConfig {
                gas_price: 100,
                byte_price: 800,
                bundle_gas_limit: bundle_gas_limit_or_default(Some(bad)),
                metering: randprotocol_core::gas::GasMetering::Circuit,
                dynamic: None,
            });
            let e = g.build(&ZkExecutor::new(FriProfile::Test)).expect_err("refused").to_string();
            assert!(e.contains("bundle_gas_limit") && e.contains("20479"), "{e}");
        }
    }

    /// `rand-node genesis` takes the four gas flags (design 2026-09-28 §4.2, §4.3, §7.1); the
    /// section is written only when `--gas-price` is given, and `--gas-dynamic` sets the
    /// controller's floors to the section's own starting prices.
    #[test]
    fn the_genesis_command_takes_the_gas_flags() {
        let parse = |extra: &[&str]| {
            let mut args = vec!["rand-node", "genesis", "--validator", "k,1000,p"];
            args.extend_from_slice(extra);
            match Cli::try_parse_from(args).unwrap().cmd {
                Cmd::Genesis { gas_price, byte_price, bundle_gas_limit, gas_dynamic, .. } => {
                    (gas_price, byte_price, bundle_gas_limit, gas_dynamic)
                }
                _ => unreachable!(),
            }
        };
        // Audit v6, POOL-2: the two ceilings and the byte load ride `--gas-dynamic`.
        let section = |extra: &[&str]| {
            let mut args = vec!["rand-node", "genesis", "--validator", "k,1000,p"];
            args.extend_from_slice(extra);
            match Cli::try_parse_from(args).unwrap().cmd {
                Cmd::Genesis { gas_price, byte_price, bundle_gas_limit, gas_dynamic, max_gas_price, max_byte_price, gas_byte_load, .. } => {
                    gas_section(
                        gas_price,
                        byte_price,
                        bundle_gas_limit,
                        gas_dynamic.as_deref(),
                        DynamicExtras { max_gas_price, max_byte_price, byte_load: gas_byte_load.as_deref() },
                    )
                }
                _ => unreachable!(),
            }
        };
        let capped = section(&["--gas-price", "100", "--gas-dynamic", "10485760,262144,1250", "--max-gas-price", "1000", "--max-byte-price", "80000", "--gas-byte-load", "paying"])
            .unwrap()
            .unwrap();
        let d = capped.dynamic.unwrap();
        assert_eq!((d.max_gas_price, d.max_byte_price, d.byte_load), (Some(1_000), Some(80_000), Some(randprotocol_core::gas::ByteLoad::Paying)));
        let plain = section(&["--gas-price", "100", "--gas-dynamic", "10485760,262144,1250"]).unwrap().unwrap().dynamic.unwrap();
        assert_eq!((plain.max_gas_price, plain.max_byte_price, plain.byte_load), (None, None, None), "chain 18's shape without the flags");
        for extra in [&["--max-gas-price", "1000"][..], &["--max-byte-price", "9"], &["--gas-byte-load", "paying"]] {
            let mut args = vec!["--gas-price", "100"];
            args.extend_from_slice(extra);
            let err = section(&args).unwrap_err().to_string();
            assert!(err.contains("without --gas-dynamic"), "{err}");
        }
        assert!(section(&["--gas-price", "100", "--gas-dynamic", "1,1,1250", "--gas-byte-load", "all"]).unwrap_err().to_string().contains("only `paying`"));
        assert_eq!(parse(&[]), (None, None, None, None));
        assert_eq!(
            parse(&["--gas-price", "100", "--byte-price", "800", "--bundle-gas-limit", "20479"]),
            (Some(100), Some(800), Some(20_479), None)
        );
        assert_eq!(
            parse(&["--gas-price", "100", "--gas-dynamic", "10485760,262144,1250"]).3,
            Some("10485760,262144,1250".to_string())
        );

        // Without any gas flag no section is written: chain 15's shape, byte-for-byte (and any of
        // the other three without `--gas-price` is refused: `a_gas_flag_without_gas_price_is_refused`).
        let g = pinned_genesis();
        assert!(g.gas.is_none());
        assert!(!g.to_json().contains("\"gas\""));

        // With `--gas-price`, byte_price and bundle_gas_limit take their CLI values (or the
        // documented defaults), metering is "circuit", and gas_dynamic's three numbers plus the
        // starting prices as floors build the `dynamic` sub-section.
        let mut with_gas = pinned_genesis();
        with_gas.gas = Some(randprotocol_core::gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: 20_479,
            metering: randprotocol_core::gas::GasMetering::Circuit,
            dynamic: Some(randprotocol_core::gas::DynamicGas {
                target_block_bytes: 2_097_152,
                target_block_gas: 262_144,
                adjust_bps: 1250,
                min_gas_price: 100,
                min_byte_price: 800,
                max_gas_price: None,
                max_byte_price: None,
                byte_load: None,
            }),
        });
        let json = with_gas.to_json();
        assert!(json.contains("\"gas_price\": \"100\""));
        assert!(json.contains("\"metering\": \"circuit\""));
        let built = with_gas.build(&ZkExecutor::new(FriProfile::Test)).unwrap();
        assert_eq!(built.ledger.gas().unwrap().bundle_gas_limit, 20_479);
        assert_ne!(built.hash(), pinned_genesis().build(&ZkExecutor::new(FriProfile::Test)).unwrap().hash());
    }

    /// Final-review minor 4: `--byte-price`, `--bundle-gas-limit` or `--gas-dynamic` without
    /// `--gas-price` is an error naming the flag, not a genesis silently cut with no gas section.
    #[test]
    fn a_gas_flag_without_gas_price_is_refused() {
        assert_eq!(gas_section(None, None, None, None, DynamicExtras::default()).unwrap(), None, "no flags: no section");
        for (byte_price, bundle, dynamic, flag) in [
            (Some(800), None, None, "--byte-price"),
            (None, Some(20_479), None, "--bundle-gas-limit"),
            (None, None, Some("10485760,262144,1250"), "--gas-dynamic"),
        ] {
            let e = gas_section(None, byte_price, bundle, dynamic, DynamicExtras::default()).expect_err(&format!("{flag} alone must be refused")).to_string();
            assert!(e.contains(flag) && e.contains("--gas-price"), "{e}");
        }
        let with = gas_section(Some(100), Some(800), None, Some("10485760,262144,1250"), DynamicExtras::default()).unwrap().unwrap();
        assert_eq!(with.bundle_gas_limit, 20_479);
        assert_eq!(with.dynamic.unwrap().target_block_bytes, 10_485_760);
    }

    /// `rand-node alloc-note --envelope-bytes 1860` seals its note at exactly 1 860 bytes — the
    /// size a genesis carrying `envelope_bytes` demands of every alloc note — and without the
    /// flag at the legacy size (final review B4). The owner opens it either way.
    #[test]
    fn alloc_note_with_envelope_bytes_seals_at_1860() {
        use randprotocol_core::notes::MEMO_ENVELOPE_BYTES;
        let cli = Cli::try_parse_from(["rand-node", "alloc-note", "--to", "rand1x", "--amount", "5", "--envelope-bytes", "1860"]).unwrap();
        let Cmd::AllocNote { envelope_bytes, .. } = cli.cmd else { unreachable!() };
        assert_eq!(envelope_bytes, Some(1860));
        let payee = SpendKey([0x16; 8]);
        let to = randprotocol_zkvm::address::address_of(&payee.viewing_key());
        for (flag, len) in [(Some(1860u32), MEMO_ENVELOPE_BYTES), (None, 1348)] {
            let note = alloc_note_cmd(&to.to_string(), "5", 0, flag).unwrap();
            let envelope = note.envelope.to_envelope().unwrap();
            assert_eq!(envelope.len(), len, "--envelope-bytes {flag:?}");
            let cm = randprotocol_core::notes::word8_from_hex(&note.cm).unwrap();
            let (_, opened) = randprotocol_zkvm::address::envelope_from_core(&envelope)
                .open_as_receiver(cm, &payee.viewing_key())
                .expect("the owner opens it");
            assert_eq!(opened.amount, 5 * UNITS_PER_RAND);
        }
    }

    /// A node-sealed withdraw/payout note (`withdraw`, `aggregator withdraw`, `aggregate`) on a
    /// chain whose genesis sets `envelope_bytes` is sealed at exactly 1 860 bytes — the ledger
    /// refuses any other size there — carries no memo, and still opens for the payee.
    #[test]
    fn a_node_sealed_withdraw_note_in_the_memo_format_is_1860_bytes() {
        use randprotocol_core::notes::MEMO_ENVELOPE_BYTES;
        let payee = SpendKey([0x17; 8]);
        let payout = randprotocol_zkvm::address::address_of(&payee.viewing_key());
        let (note, envelope) = sealed_withdraw_note(&payout, 3 * UNITS_PER_RAND, 2026, EnvelopeFormat::Memo).unwrap();
        assert_eq!(envelope.len(), MEMO_ENVELOPE_BYTES);
        let (_, opened) = randprotocol_zkvm::address::envelope_from_core(&envelope)
            .open_as_receiver(note.commitment(), &payee.viewing_key())
            .expect("the payout wallet opens it");
        assert_eq!(opened, note);
    }

    /// `rand-node genesis --envelope-bytes 1860` writes the field, and reaches the `--alloc`
    /// loop before it seals a single note (task 6): every alloc note comes out exactly that
    /// long, or `Genesis::build` refuses it (`AllocEnvelopeSize`) rather than cut a file whose
    /// own notes disagree with its declared shape.
    #[test]
    fn the_genesis_command_takes_envelope_bytes_and_seals_allocs_at_it() {
        let parse = |extra: &[&str]| {
            let mut args = vec!["rand-node", "genesis", "--validator", "k,1000,p"];
            args.extend_from_slice(extra);
            match Cli::try_parse_from(args).unwrap().cmd {
                Cmd::Genesis { envelope_bytes, .. } => envelope_bytes,
                _ => unreachable!(),
            }
        };
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["--envelope-bytes", "1860"]), Some(randprotocol_core::notes::MEMO_ENVELOPE_BYTES as u32));

        let mut g = pinned_genesis();
        g.envelope_bytes = Some(randprotocol_core::notes::MEMO_ENVELOPE_BYTES as u32);
        let addr = pinned_payee().to_string();
        g.alloc = vec![deposit_note(&addr, 5, EnvelopeFormat::for_chain(g.envelope_bytes)).unwrap()];
        let built = g.build(&ZkExecutor::new(FriProfile::Test)).unwrap();
        assert_eq!(built.ledger.envelope_bytes(), Some(randprotocol_core::notes::MEMO_ENVELOPE_BYTES));
        assert_eq!(built.notes[0].1.len(), randprotocol_core::notes::MEMO_ENVELOPE_BYTES);
        assert!(g.to_json().contains("\"envelope_bytes\": 1860"));

        // Sealing the alloc note in the wrong format (this command's default, before the flag
        // sets the field) is exactly what a stale caller would do, and `Genesis::build` refuses
        // it rather than cut a file whose own note disagrees with its declared shape.
        let mut bad = pinned_genesis();
        bad.envelope_bytes = Some(randprotocol_core::notes::MEMO_ENVELOPE_BYTES as u32);
        bad.alloc = vec![deposit_note(&addr, 5, EnvelopeFormat::Legacy).unwrap()];
        assert!(bad.build(&ZkExecutor::new(FriProfile::Test)).is_err());
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
            alloc: vec![seal_deposit(&to, &note, EnvelopeFormat::Legacy).unwrap()],
            faucet: true,
            confidential: true,
            fri_profile: "test".into(),
            hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
            bridge: None,
            tokens: None,
            aggregation: None,
            consensus_domain: None,
            epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
            max_program_words: None,
            max_proof_bytes: None,
            max_block_bytes: None,
            max_call_envelope_bytes: None,
            max_program_public_words: None,
            envelope_bytes: None,
            hardening_v6: None,
            hc_auth: None,
            staking: None,
            vesting: None,
            gas: None,
            testnet: None,
            binding_domain: None,
            proof_window_blocks: None,
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
    // Pinned to the chain-14 genesis shape (v0.5.3 re-pin, audit v3 PROC-3). Every move of this
    // hash was deliberate and consensus-breaking: the transaction binding (`rand-tx-bind-1`), the
    // hidden-asset guest replacing the bundle guest (`hc_bundle`), and the v0.4/v0.5 genesis
    // sections (call limits, `tokens`, `bridge`) — before those, S2's register (the validator
    // leaf `rand-validator-leaf-2`, every payout address in the binding, stakes at the minimum).
    // A drift here with no such change in the log is a bug, and a tag is never cut over a red run
    // of this test (docs/deploy.md, "Release rule", audit v4 PROC-3).
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
    /// A stand-in node for the aggregate pass: one covered bundle 25 over its floor, one
    /// registered aggregator, and a head, a schedule index and a nonce the test moves while the
    /// "prover" runs — the tens of minutes a real rVM prove takes, in which the chain goes on.
    struct MovingNode {
        height: std::cell::Cell<u64>,
        sealed_blocks: std::cell::Cell<u64>,
        nonce: std::cell::Cell<u64>,
        me: randprotocol_core::Address,
        payout: ShieldedAddress,
        raw: randprotocol_core::Transaction,
    }

    impl AggregateNode for MovingNode {
        async fn call(&self, method: &str, _params: serde_json::Value) -> Result<serde_json::Value> {
            use serde_json::json;
            Ok(match method {
                "rand_status" => json!({
                    "fri_profile": "test",
                    "height": self.height.get(),
                    "aggregation": {
                        "max_covers": 3,
                        "subsidy_base": "1000",
                        "halving_blocks": 1,
                        "sealed_blocks": self.sealed_blocks.get(),
                    },
                }),
                "rand_getUnsealed" => json!({
                    "bundles": [{ "hash": self.raw.hash().to_hex(), "height": 1, "excess": "25" }],
                    "next_from": null,
                }),
                "rand_getRawTransaction" => json!(hex::encode(bincode::serialize(&self.raw).unwrap())),
                "rand_getAggregators" => json!([{
                    "address": self.me.to_base58(),
                    "nonce": self.nonce.get(),
                    "payout": self.payout.to_string(),
                    "bond": "100",
                    "unbonding": null,
                }]),
                other => anyhow::bail!("unexpected call {other}"),
            })
        }
        async fn envelope_format(&self, _chain_id: u64) -> Result<EnvelopeFormat> {
            // A chain without `envelope_bytes`, as chains 14 and 15.
            Ok(EnvelopeFormat::for_chain(None))
        }
        async fn binding_domain(&self, _chain_id: u64) -> Result<randprotocol_core::BindingDomain> {
            // A chain without `binding_domain`, as chains 14 to 19.
            Ok(randprotocol_core::BindingDomain::ChainId)
        }
    }

    fn moving_node(me: randprotocol_core::Address, payout: ShieldedAddress) -> MovingNode {
        let env = || Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] };
        let bundle = randprotocol_core::Bundle {
            anchor: [0; 8],
            nullifiers: [[1; 8], [2; 8], [3; 8], [4; 8]],
            commitments: [[5; 8], [6; 8], [7; 8], [8; 8]],
            fee: randprotocol_core::gas::BUNDLE_BASE + 25,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: 1,
            envelopes: [env(), env(), env(), env()],
            proof: b"the bundle proof".to_vec(),
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        MovingNode {
            height: std::cell::Cell::new(100),
            sealed_blocks: std::cell::Cell::new(0),
            nonce: std::cell::Cell::new(0),
            me,
            payout,
            raw: randprotocol_core::Transaction::shielded(7, bundle, randprotocol_core::Action::None),
        }
    }

    /// The interface review's IFACE-8: the prove takes ~26 minutes and the payout note's `time`
    /// must sit inside the ledger's 256-block window of the head at submission, so the pass
    /// reads the head — and the schedule index the subsidy is paid at — after the prove,
    /// immediately before building the transaction. Read before it (as the daemon did), the
    /// aggregate was built at `time = 101` against a head that had moved to 2000: out of window,
    /// refused. The nonce stays read before (the proof binds it, AGG-2).
    #[tokio::test]
    async fn the_aggregate_pass_reads_time_and_schedule_after_proving() {
        use randprotocol_core::confidential::ConfidentialExecutor;
        let kp = Keypair::from_seed([9; 32]).unwrap();
        let payee = SpendKey([7; 8]);
        let payout = randprotocol_zkvm::address::address_of(&payee.viewing_key());
        let node = moving_node(kp.address(), payout.clone());
        let tx = aggregate_pass(&node, &kp, 7, |profile, raw, binding| {
            assert_eq!(profile, FriProfile::Test);
            assert_eq!(raw, &[b"the bundle proof".to_vec()][..], "the tape is the stored bundle proof");
            assert_eq!(
                binding,
                &randprotocol_core::types::actions::aggregate_binding(7, &kp.address(), 0),
                "the proof binds the nonce read before proving"
            );
            // The chain moves on while the prover works: 1900 blocks, one sealed block.
            node.height.set(2000);
            node.sealed_blocks.set(1);
            Ok(b"the aggregate proof".to_vec())
        })
        .await
        .unwrap()
        .expect("one bundle to cover");
        let randprotocol_core::Action::Aggregate { covers, nonce, time, r, envelope, proof, .. } = &tx.action else {
            panic!("not an aggregate: {tx:?}")
        };
        assert_eq!(*time, 2001, "time is read from the head at submission, not before the prove");
        assert_eq!(*nonce, 0);
        assert_eq!(covers, &vec![node.raw.hash()]);
        assert_eq!(proof, &b"the aggregate proof".to_vec());
        // The subsidy at the schedule index after the prove (halving every sealed block: 1000 >> 1),
        // plus the node's bucketed excess — and the envelope opens to exactly that note.
        let amount = 500 + 25;
        let cm = ZkExecutor::new(FriProfile::Test).note_commitment(&payout.pk, &[0; 8], amount, 0, *time, r);
        let (_, opened) = randprotocol_zkvm::address::envelope_from_core(envelope)
            .open_as_receiver(cm, &payee.viewing_key())
            .expect("the payout note opens at the post-prove amount and time");
        assert_eq!(opened.amount, amount);
    }

    /// And a pass whose nonce moved while proving is abandoned: the proof is bound to the old
    /// nonce (AGG-2) and can never verify, so it is not submitted to certain refusal.
    #[tokio::test]
    async fn the_aggregate_pass_abandons_a_proof_whose_nonce_moved() {
        let kp = Keypair::from_seed([9; 32]).unwrap();
        let payout = randprotocol_zkvm::address::address_of(&SpendKey([7; 8]).viewing_key());
        let node = moving_node(kp.address(), payout);
        let err = aggregate_pass(&node, &kp, 7, |_, _, _| {
            node.nonce.set(1);
            Ok(b"the aggregate proof".to_vec())
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("nonce moved from 0 to 1"), "{err}");
    }

    #[test]
    fn the_cli_withdraw_note_is_the_note_the_ledger_derives() {
        use randprotocol_core::confidential::ConfidentialExecutor;
        let payee = SpendKey([7; 8]);
        let payout = randprotocol_zkvm::address::address_of(&payee.viewing_key());
        let base = randprotocol_core::gas::BUNDLE_BASE;
        let amount = 5 * UNITS_PER_RAND;
        let time = 1994;
        let (note, envelope) = sealed_withdraw_note(&payout, amount - base, time, EnvelopeFormat::Legacy).unwrap();

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

    /// Genesis vesting: the note `rand-node vesting claim` seals is the note the ledger derives
    /// for the action it signs (`ledger::vesting`, through `Ledger::derived_commitment`), with
    /// the real executor — and the holder's wallet opens it.
    #[test]
    fn the_cli_vesting_note_is_the_note_the_ledger_derives() {
        use randprotocol_core::ledger::vesting::{Class, VestingConfig, VestingEntryConfig, VestingRegister};
        let holder = SpendKey([9; 8]);
        let to = randprotocol_zkvm::address::address_of(&holder.viewing_key());
        let base = randprotocol_core::gas::BUNDLE_BASE;
        let (amount, time) = (3 * UNITS_PER_RAND, 77);
        let (note, envelope) = sealed_vesting_note(&to, amount - base, time, EnvelopeFormat::Legacy).unwrap();
        let ex = ZkExecutor::new(FriProfile::Test);
        let action = randprotocol_core::Action::ClaimVested {
            entry: [1; 32],
            amount,
            nonce: 0,
            to: to.clone(),
            time,
            r: note.r,
            envelope: envelope.clone(),
            signature: randprotocol_core::crypto::Signature::empty(),
        };
        let mut ledger = pinned_genesis().build(&ex).unwrap().ledger;
        let key = Keypair::from_seed([4; 32]).unwrap();
        ledger.set_vesting(Some(VestingRegister::from_config(&VestingConfig {
            entries: vec![VestingEntryConfig {
                id: [1; 32],
                class: Class::Partner,
                beneficiary: key.public_key().clone(),
                revokers: Vec::new(),
                threshold: None,
                treasury: None,
                amount: 10 * UNITS_PER_RAND,
                start_ms: 0,
                cliff_ms: 0,
                linear_ms: 1,
                step_ms: None,
            }],
        })));
        assert_eq!(ledger.derived_commitment(&action, &ex), Some(note.commitment()), "the CLI's note is the chain's");
        let (_, opened) = randprotocol_zkvm::address::envelope_from_core(&envelope)
            .open_as_receiver(note.commitment(), &holder.viewing_key())
            .expect("the holder's wallet opens its claim");
        assert_eq!(opened.amount, amount - base);
    }

    /// The `--vesting` file format is `docs/vesting.md`'s example, verbatim: a doc that drifts
    /// from what `rand-node genesis --vesting` reads fails here.
    #[test]
    fn the_documented_vesting_file_parses_and_validates() {
        let doc = include_str!("../../../docs/vesting.md");
        let start = doc.find("```json\n{\n  \"entries\"").expect("docs/vesting.md carries the example file");
        let body = &doc[start + "```json\n".len()..];
        let mut json = body[..body.find("```").unwrap()].to_string();
        // The keys and the treasury are `"<…>"` placeholders in the doc: stand a real one in
        // for each (a distinct key per revoker: the section refuses one listed twice).
        let key = Keypair::from_seed([6; 32]).unwrap().public_key().to_hex();
        let treasury = pinned_payee().to_string();
        let mut revokers = 0u8;
        while let Some(a) = json.find("\"<") {
            let b = a + json[a..].find(">\"").unwrap() + 2;
            let k = if json[a..b].contains("revoker") {
                revokers += 1;
                Keypair::from_seed([6 + revokers; 32]).unwrap().public_key().to_hex()
            } else if json[a..b].contains("treasury") {
                treasury.clone()
            } else {
                key.clone()
            };
            json.replace_range(a..b, &format!("\"{k}\""));
        }
        let cfg: randprotocol_core::ledger::vesting::VestingConfig = serde_json::from_str(&json).expect("the example parses");
        assert_eq!(cfg.entries.len(), 2);
        let total = cfg.check().expect("the example is a valid section");
        assert_eq!(total, 23_000_000 * UNITS_PER_RAND, "18 M (the Founding Sale shape) + 5 M (a team grant)");
        let founding = &cfg.entries[0];
        const MONTH: u64 = 30 * 86_400_000;
        assert_eq!((founding.cliff_ms, founding.linear_ms, founding.step_ms), (12 * MONTH, 18 * MONTH, Some(MONTH)));
        let team = &cfg.entries[1];
        assert!(founding.revokers.is_empty() && founding.treasury.is_none(), "investor irrevocable");
        assert_eq!((team.revokers.len(), team.threshold, team.treasury.as_deref()), (3, Some(2), Some(treasury.as_str())), "team revocable, 2 of 3, to the treasury");
        // `rand-node genesis --vesting` reads the file through the same function the test does.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vesting.json");
        std::fs::write(&path, &json).unwrap();
        assert_eq!(read_vesting_config(&path).unwrap(), cfg);
        // A treasury whose ML-KEM key does not decode is an address nobody can seal a revoke's
        // note to: the core crate checks its length, the CLI its key.
        let junk = ShieldedAddress { pk: [1; 8], kem_ek: vec![0xff; randprotocol_core::notes::KEM_EK_BYTES] }.to_string();
        std::fs::write(&path, json.replace(&treasury, &junk)).unwrap();
        let err = format!("{:#}", read_vesting_config(&path).unwrap_err());
        assert!(err.contains("the treasury cannot be sealed to"), "{err}");
    }

    /// Audit v6, STAKE-3: `vesting revoke prepare` → `sign` (per revoker) → `submit` builds the
    /// action the ledger accepts — the treasury's note sealed by the first step, one message
    /// for every signer, the signatures in index order — and the treasury's wallet opens the
    /// note. One signature of a 2-of-3 entry is refused by the chain, as is a revoke paying any
    /// address but the entry's treasury.
    #[test]
    fn a_prepared_revoke_signed_by_a_threshold_is_the_revoke_the_ledger_accepts() {
        use randprotocol_core::ledger::vesting::{Class, VestingConfig, VestingEntryConfig, VestingError, VestingRegister};
        use randprotocol_core::ledger::TxError;
        let ex = ZkExecutor::new(FriProfile::Test);
        let treasury_key = SpendKey([9; 8]);
        let treasury = randprotocol_zkvm::address::address_of(&treasury_key.viewing_key());
        let revokers: Vec<Keypair> = (20..23u8).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect();
        let mut ledger = pinned_genesis().build(&ex).unwrap().ledger;
        ledger.set_vesting(Some(VestingRegister::from_config(&VestingConfig {
            entries: vec![VestingEntryConfig {
                id: [1; 32],
                class: Class::Team,
                beneficiary: Keypair::from_seed([4; 32]).unwrap().public_key().clone(),
                revokers: revokers.iter().map(|k| k.public_key().clone()).collect(),
                threshold: Some(2),
                treasury: Some(treasury.to_string()),
                amount: 10 * UNITS_PER_RAND,
                start_ms: ledger.timestamp_ms(),
                cliff_ms: 0,
                linear_ms: 1_000_000,
                step_ms: None,
            }],
        })));
        let (chain_id, genesis, time) = (ledger.chain_id(), ledger.signing_domain().genesis, ledger.height() as u32);
        let unvested = 9 * UNITS_PER_RAND;
        let prepare = |to: &ShieldedAddress| {
            let mut p = RevokeProposal::new(chain_id, &genesis, &[1; 32], unvested, 0, to, time, EnvelopeFormat::Legacy).unwrap();
            p.revokers = revokers.iter().map(|k| k.address().to_base58()).collect();
            p.threshold = 2;
            // Through the file, as the three steps pass it.
            serde_json::from_str::<RevokeProposal>(&serde_json::to_string_pretty(&p).unwrap()).unwrap()
        };
        let p = prepare(&treasury);
        // Each revoker finds its own position in the file's list; a key outside it is told so.
        let sigs: Vec<String> = revokers.iter().map(|k| p.sign(k, None).unwrap()).collect();
        assert!(sigs[2].starts_with("2:"), "{}", &sigs[2][..8]);
        assert!(p.sign(&Keypair::from_seed([99; 32]).unwrap(), None).unwrap_err().to_string().contains("not among the revokers"));
        let tx = |action| randprotocol_core::Transaction { chain_id, bundle: None, action };
        let verdict = |t: &randprotocol_core::Transaction| match ledger.validate(t, &ex) {
            Err(TxError::Vesting(v)) => Err(v),
            Err(other) => panic!("only a vesting refusal is expected here, got {other:?}"),
            Ok(_) => Ok(()),
        };
        // 2 of 3, given out of order: accepted, the list in index order.
        let revoke = tx(p.action(&[sigs[2].clone(), sigs[0].clone()]).unwrap());
        let randprotocol_core::Action::RevokeVesting { signatures, r, envelope, .. } = &revoke.action else { panic!("a revoke") };
        assert_eq!(signatures.iter().map(|s| s.index).collect::<Vec<_>>(), [0, 2]);
        assert_eq!(verdict(&revoke), Ok(()));
        // The note is the one the treasury's wallet opens.
        let cm = ledger.derived_commitment(&revoke.action, &ex).expect("a revoke creates a note");
        let (_, opened) = randprotocol_zkvm::address::envelope_from_core(envelope)
            .open_as_receiver(cm, &treasury_key.viewing_key())
            .expect("the treasury's wallet opens the revoke's note");
        assert_eq!((opened.amount, opened.r), (unvested - randprotocol_core::gas::BUNDLE_BASE, *r));
        // 1 of 3 is refused by the chain; the same revoker twice, by `submit` itself.
        assert_eq!(verdict(&tx(p.action(&sigs[..1]).unwrap())), Err(VestingError::BelowThreshold { have: 1, need: 2 }));
        assert!(p.action(&[sigs[0].clone(), sigs[0].clone()]).unwrap_err().to_string().contains("given twice"));
        // A key signing under a position that is not its own.
        let misplaced = p.sign(&revokers[0], Some(1)).unwrap();
        assert_eq!(verdict(&tx(p.action(&[sigs[0].clone(), misplaced]).unwrap())), Err(VestingError::BadSignature));
        // Prepared for any other address — every revoker signing it — it is refused.
        let elsewhere = randprotocol_zkvm::address::address_of(&SpendKey([8; 8]).viewing_key());
        let q = prepare(&elsewhere);
        let all: Vec<String> = revokers.iter().map(|k| q.sign(k, None).unwrap()).collect();
        assert_eq!(verdict(&tx(q.action(&all).unwrap())), Err(VestingError::NotTheTreasury));
        // A file edited after it was signed is another message.
        let mut edited = p.clone();
        edited.unvested = (unvested - 1).to_string();
        assert_eq!(verdict(&tx(edited.action(&sigs[..2]).unwrap())), Err(VestingError::BadSignature));
    }

    /// Two allocations of the same amount to the same address are two different notes. A
    /// deterministic commitment would let anyone confirm a guess at a genesis note's owner and
    /// value by recomputing it, which is the property the whole scheme exists to deny.
    #[test]
    fn deposit_notes_are_never_the_same_note_twice() {
        let addr = pinned_payee().to_string();
        let a = deposit_note(&addr, 5, EnvelopeFormat::Legacy).unwrap();
        let b = deposit_note(&addr, 5, EnvelopeFormat::Legacy).unwrap();
        assert_eq!(a.amount, b.amount);
        assert_ne!(a.cm, b.cm, "genesis notes must carry fresh commitment randomness");
        assert_ne!(a.envelope.kem_ct, b.envelope.kem_ct, "a fresh KEM ciphertext per note");
        // Anything that is not a shielded address is refused, with the address in the message.
        let err = deposit_note("not-an-address", 1, EnvelopeFormat::Legacy).unwrap_err().to_string();
        assert!(err.contains("not-an-address"), "{err}");
    }
}

#[cfg(test)]
mod prune_flag_tests {
    use super::*;

    #[test]
    fn the_flag_takes_minutes_hours_and_days() {
        assert_eq!(parse_prune_history("24h").unwrap(), Duration::from_secs(24 * 3600));
        assert_eq!(parse_prune_history("2d").unwrap(), Duration::from_secs(2 * 86_400));
        assert_eq!(parse_prune_history("90m").unwrap(), Duration::from_secs(90 * 60));
    }

    #[test]
    fn the_flag_refuses_under_an_hour_and_bad_syntax() {
        assert_eq!(parse_prune_history("59m").unwrap_err(), "prune-history must be at least 1h");
        assert!(parse_prune_history("24").unwrap_err().contains("<n>m, <n>h or <n>d"));
        assert!(parse_prune_history("h").unwrap_err().contains("<n>m, <n>h or <n>d"));
        assert!(parse_prune_history("0h").unwrap_err().contains("at least 1h"));
        assert!(parse_prune_history("24ｈ").unwrap_err().contains("<n>m, <n>h or <n>d"));
    }

    #[test]
    fn run_defaults_to_the_spec_prices_and_zero_means_no_policy() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["rand-node", "run", "--datadir", "/tmp/x", "--key", "/tmp/k"]).unwrap();
        let Cmd::Run { gas_price, byte_price, .. } = cli.cmd else { panic!("run") };
        assert_eq!((gas_price, byte_price), (100, 800));
        assert_eq!(randprotocol_core::gas::GasPolicy::from_prices(gas_price, byte_price), Some(randprotocol_core::gas::GasPolicy::DEFAULT));
        let cli = Cli::try_parse_from(["rand-node", "run", "--datadir", "/tmp/x", "--key", "/tmp/k", "--gas-price", "0", "--byte-price", "0"]).unwrap();
        let Cmd::Run { gas_price, byte_price, .. } = cli.cmd else { panic!("run") };
        assert_eq!(randprotocol_core::gas::GasPolicy::from_prices(gas_price, byte_price), None);
    }
}
