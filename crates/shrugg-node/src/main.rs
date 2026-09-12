use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use libp2p::Multiaddr;
use shrugg_client::RpcClient;
use shrugg_core::bridge::BridgeConfig;
use shrugg_core::genesis::{EnvelopeHex, Genesis, GenesisNote, GenesisValidator};
use shrugg_core::notes::{word8_to_hex, ShieldedAddress};
use shrugg_core::{format_amount, parse_amount};
use shrugg_core::{Keypair, PublicKey, UNITS_PER_SHRUGG};
use shrugg_node::keyfile::{load_keypair, KeyFile};
use shrugg_node::node::{self, NodeConfig};
use shrugg_node::storage::{Storage, VerifyMode};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::notes::{Note, SpendKey};
use shrugg_zkvm::viewing::TxKey;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// One genesis deposit note: `amount` units owned by the shielded address `addr`.
///
/// The note carries fresh commitment randomness, so writing the same allocation twice produces
/// two different notes with two different genesis hashes. That is the point of a commitment
/// scheme rather than an oversight: a deterministic `r` would let anyone confirm a guess at who
/// a genesis note pays and how much it holds, simply by recomputing the commitment. A genesis
/// file is written once and its hash is fixed from then on.
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
    let envelope = shrugg_zkvm::address::seal_note(&throwaway, to, note, &TxKey::random())
        .map_err(|e| anyhow::anyhow!("sealing a note to {}: {e}", to.to_string()))?;
    Ok(GenesisNote {
        cm: word8_to_hex(&note.commitment()),
        envelope: EnvelopeHex::from_envelope(&envelope),
        amount: note.amount,
    })
}

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
    /// Write a genesis.json: every validator key is staked, and each `--alloc` becomes one
    /// shielded deposit note.
    Genesis {
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
        /// Validator key files (seed) or hex public keys, repeatable.
        #[arg(long = "validator", required = true)]
        validators: Vec<String>,
        #[arg(long, default_value_t = 100_000)]
        stake: u128,
        /// Deposit notes `shrugg1<address>=<amount in SHRUGG>`, repeatable. A redacted chain has
        /// no accounts, so there is no per-validator allocation: value only exists as a note
        /// someone holds the spend key for.
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
        /// Enable the cross-chain bridge from a JSON file:
        /// `{ "emitter": <64 hex>, "guardians": [<40 hex>, ...], "emitters": { "<chain id>": <64 hex> } }`.
        /// Part of the genesis hash.
        #[arg(long)]
        bridge: Option<PathBuf>,
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
        Cmd::Genesis { chain_id, validators, stake, allocs, out, faucet, no_confidential, fri_profile, bridge } => {
            let bridge = match &bridge {
                Some(path) => {
                    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
                    Some(serde_json::from_str::<BridgeConfig>(&text).with_context(|| format!("parsing {}", path.display()))?)
                }
                None => None,
            };
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
                bridge,
            };
            for v in validators {
                let pk = if PathBuf::from(&v).exists() {
                    load_keypair(&PathBuf::from(&v))?.public_key().clone()
                } else {
                    PublicKey::from_hex(&v).with_context(|| format!("{v} is neither a key file nor a hex public key"))?
                };
                gen.validators.push(GenesisValidator { public_key: pk, stake });
            }
            for a in &allocs {
                let (addr, amt) = a.split_once('=').context("--alloc must be shrugg1address=amount")?;
                let amount = parse_amount(amt)?;
                gen.alloc.push(deposit_note(addr, amount)?);
                println!("  alloc {} SHRUGG to {addr}", format_amount(amount));
            }
            let executor = node::executor_for_profile(&gen.fri_profile)?;
            let state = gen.build(executor.as_ref())?;
            std::fs::write(&out, gen.to_json())?;
            println!(
                "wrote {} (genesis hash {}, {} notes, faucet {}, confidential {}, fri {}, hc_bundle {})",
                out.display(),
                state.hash(),
                state.notes.len(),
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
        Cmd::Status { rpc } => {
            let v = RpcClient::new(rpc).status().await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
    }
    let _ = UNITS_PER_SHRUGG;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shrugg_zkvm::machine::FriProfile;

    /// The owner of the pinned genesis's one deposit note.
    fn pinned_payee() -> ShieldedAddress {
        shrugg_zkvm::address::address_of(&SpendKey([7; 8]).viewing_key())
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
        let note = Note { pk: to.pk, from: [0; 8], amount: 5 * UNITS_PER_SHRUGG, asset: 0, time: 0, r: [7; 8] };
        Genesis {
            chain_id: 7,
            timestamp_ms: 1_700_000_000_000,
            validators: vec![
                GenesisValidator { public_key: Keypair::from_seed([1; 32]).unwrap().public_key().clone(), stake: 10 },
                GenesisValidator { public_key: Keypair::from_seed([2; 32]).unwrap().public_key().clone(), stake: 20 },
            ],
            alloc: vec![seal_deposit(&to, &note).unwrap()],
            faucet: true,
            confidential: true,
            fri_profile: "test".into(),
            hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
            bridge: None,
        }
    }

    /// A chain's identity, pinned. This hex changes whenever the bundle guest, the note format,
    /// or the genesis binding changes — all three are consensus-breaking, so a diff here is the
    /// intended alarm, not a nuisance. Regenerate it deliberately (print `state.hash()`), and
    /// only together with a chain restart.
    #[test]
    fn the_genesis_hash_is_pinned() {
        let ex = ZkExecutor::new(FriProfile::Test);
        let state = pinned_genesis().build(&ex).unwrap();
        assert_eq!(state.hash().to_hex(), "700f28e8c40f45085a29441920f36077324dd9ad69c7a77bb1f740ecd87f87ea");
        // The envelope is resealed on every call and must not move the hash: only the
        // commitment and the amount are bound.
        let again = pinned_genesis().build(&ex).unwrap();
        assert_ne!(again.notes[0].1, state.notes[0].1, "a fresh envelope per build");
        assert_eq!(again.hash(), state.hash());
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
