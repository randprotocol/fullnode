use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use libp2p::Multiaddr;
use shrugg_client::wallet::{self, NoteStore, Wallet};
use shrugg_client::RpcClient;
use shrugg_core::genesis::{EnvelopeHex, Genesis, GenesisNote, GenesisValidator};
use shrugg_core::notes::{word8_to_hex, ShieldedAddress};
use shrugg_core::types::actions::{registration_message, unbond_message, withdraw_message, Registration};
use shrugg_core::{format_amount, parse_amount};
use shrugg_core::{Keypair, PublicKey, UNITS_PER_SHRUGG};
use shrugg_node::keyfile::{load_keypair, KeyFile};
use shrugg_node::node::{self, NodeConfig};
use shrugg_node::storage::{Storage, VerifyMode};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::machine::Backend;
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

/// One `--validator key,stake,payout` triple. The three fields travel together because they are
/// one register entry (spec §8): three parallel repeatable flags would silently pair the wrong
/// stake with the wrong key the moment one of them was left out.
fn parse_genesis_validator(spec: &str) -> Result<GenesisValidator> {
    let parts: Vec<&str> = spec.split(',').collect();
    let [key, stake, payout] = parts.as_slice() else {
        anyhow::bail!("--validator takes <key file or hex public key>,<stake in SHRUGG>,<payout shrugg1…>, got {spec}");
    };
    let public_key = if PathBuf::from(key).exists() {
        load_keypair(&PathBuf::from(key))?.public_key().clone()
    } else {
        PublicKey::from_hex(key).with_context(|| format!("{key} is neither a key file nor a hex public key"))?
    };
    let stake = parse_amount(stake).with_context(|| format!("{stake} is not an amount in SHRUGG"))?;
    ShieldedAddress::parse(payout).with_context(|| format!("{payout} is not a shielded address"))?;
    // `Genesis::build` is what refuses a stake below the minimum; saying so here too means the
    // operator hears it before a genesis hash has been printed anywhere.
    anyhow::ensure!(
        stake >= shrugg_core::ledger::staking::MIN_STAKE,
        "stake {} SHRUGG is below the staking minimum of {} SHRUGG",
        format_amount(stake),
        format_amount(shrugg_core::ledger::staking::MIN_STAKE)
    );
    Ok(GenesisValidator { public_key, stake: stake as u128, payout: (*payout).to_string() })
}


/// This validator's row of the register, as `shrugg_getValidators` reports it: the nonce its
/// next signed action must carry, and the payout address a withdraw pays to. A node that is not
/// in the register has nothing to sign yet — it has to be bonded in first.
async fn register_row(rpc: &RpcClient, me: &shrugg_core::Address) -> Result<(u64, ShieldedAddress)> {
    let rows = rpc.validators().await?;
    let want = me.to_base58();
    let row = rows
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["address"].as_str() == Some(want.as_str())))
        .with_context(|| format!("{want} is not in the validator register; bond it in first (`shrugg-node register`)"))?;
    let nonce = row["nonce"].as_u64().context("the node's getValidators reply has no nonce")?;
    let payout = row["payout"].as_str().context("the node's getValidators reply has no payout address")?;
    let payout = ShieldedAddress::parse(payout).map_err(|e| anyhow::anyhow!("register payout address: {e}"))?;
    Ok((nonce, payout))
}

/// Submit a validator-signed action on a bundle the wallet pays for, and report it.
async fn submit_staking(args: &StakingArgs, action: shrugg_core::Action, what: &str) -> Result<()> {
    let rpc = RpcClient::new(args.rpc.clone());
    let chain_id = rpc.chain_id().await?;
    let w = Wallet::load(&args.wallet)?;
    let store_path = wallet::store_path(&args.wallet);
    let mut store = NoteStore::load(&store_path);
    let fee = match &args.fee {
        Some(f) => parse_amount(f)?,
        None => shrugg_core::gas::fee_floor(&action),
    };
    let profile = ZkExecutor::profile_from_str(
        rpc.status().await?["fri_profile"].as_str().unwrap_or("production"),
    )
    .context("node reports an unknown fri profile")?;
    let submission = wallet::submit(
        &rpc,
        &w,
        &mut store,
        None,
        action,
        fee,
        profile,
        Backend::Cpu,
        chain_id,
        !args.no_wait,
    )
    .await?;
    store.save(&store_path)?;
    println!("submitted {what} {}\n  fee {} SHRUGG, anchored at height {}", submission.hash, format_amount(submission.fee), submission.time);
    Ok(())
}

#[derive(Parser)]
#[command(name = "shrugg-node", version, about = "SHRUGG full node: HotStuff BFT consensus, p2p discovery, shielded note ledger")]
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
        /// A validator, as `<key file or hex public key>,<stake in SHRUGG>,<payout shrugg1…>`;
        /// repeatable. The stake must be at least the staking minimum (1000 SHRUGG) or the
        /// validator would be in the register but in no epoch's set. The payout address is where
        /// this validator's rewards and unbonded stake are paid, and it is part of the genesis
        /// hash: it is register state.
        #[arg(long = "validator", required = true, value_name = "KEY,STAKE,PAYOUT")]
        validators: Vec<String>,
        /// Blocks per epoch (spec §8): the validator set for epoch `e` is derived from the
        /// register as of the last block of epoch `e - 1`. Part of the genesis hash.
        #[arg(long, default_value_t = shrugg_core::genesis::EPOCH_BLOCKS_DEFAULT)]
        epoch_blocks: u64,
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
    /// Print this node's `Registration` (hex) for a wallet to attach to the bond that registers
    /// it. The bond itself is a wallet transaction: it burns the stake out of the wallet's own
    /// notes, which a node has none of.
    Register {
        #[arg(long)]
        key: PathBuf,
        /// Where this validator's rewards and unbonded stake are paid (`shrugg1…`).
        #[arg(long)]
        payout: String,
        /// The chain to register on is read from here: a registration is signed over the chain
        /// id, so one written for the wrong chain is simply refused.
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc: String,
    },
    /// Move bonded stake into unbonding. Withdrawable two epochs later.
    Unbond {
        /// Amount in SHRUGG.
        amount: String,
        #[command(flatten)]
        staking: StakingArgs,
    },
    /// Pay released stake and rewards into a note at this validator's payout address.
    Withdraw {
        /// Amount in SHRUGG.
        amount: String,
        #[command(flatten)]
        staking: StakingArgs,
    },
}

/// What `unbond` and `withdraw` both need.
///
/// The action is signed by the *node's* key, but it rides on a bundle like every other
/// transaction (spec §7): something has to pay the fee, and a validator key owns no notes. So
/// these commands take a wallet as well, and the bundle they build is a self-transfer of zero
/// whose only purpose is to carry the action — the same shape `shrugg deploy` and `shrugg call`
/// use. Proving it takes about a minute.
#[derive(clap::Args)]
struct StakingArgs {
    /// The validator key file: the key the register knows, and the key that signs the action.
    #[arg(long)]
    key: PathBuf,
    /// Wallet spend-key file that pays the bundle fee.
    #[arg(long, default_value = "wallet.key.json")]
    wallet: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Fee in SHRUGG; the floor is 0.001.
    #[arg(long)]
    fee: Option<String>,
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
            let id = libp2p::identity::Keypair::ed25519_from_bytes(kp.derive_subkey(b"shrugg-p2p-identity"))?;
            println!("address: {}\npublic_key: {}\npeer_id: {}", kp.address(), kp.public_key().to_hex(), id.public().to_peer_id());
        }
        Cmd::Genesis { chain_id, validators, epoch_blocks, allocs, out, faucet, no_confidential, fri_profile } => {
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
                // `Genesis::build` rejects a bridge section outright until phase S3 puts the
                // bridge back on the shielded chain, so this CLI offers no way to write one.
                bridge: None,
                epoch_blocks,
            };
            for v in &validators {
                gen.validators.push(parse_genesis_validator(v)?);
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
                "wrote {} (genesis hash {}, {} validators, {} notes, {} blocks/epoch, faucet {}, confidential {}, fri {}, hc_bundle {})",
                out.display(),
                state.hash(),
                state.validators.len(),
                state.notes.len(),
                state.epoch_blocks,
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
                hex::encode(bincode::serialize(&registration)?)
            );
        }
        Cmd::Unbond { amount, staking } => {
            let kp = load_keypair(&staking.key)?;
            let amount = parse_amount(&amount)?;
            let (nonce, _) = register_row(&RpcClient::new(staking.rpc.clone()), &kp.address()).await?;
            let chain_id = RpcClient::new(staking.rpc.clone()).chain_id().await?;
            let signature = kp.sign(unbond_message(chain_id, &kp.address(), amount, nonce).as_bytes());
            let action = shrugg_core::Action::Unbond { validator: kp.address(), amount, nonce, signature };
            submit_staking(&staking, action, &format!("unbond of {} SHRUGG", format_amount(amount))).await?;
        }
        Cmd::Withdraw { amount, staking } => {
            let kp = load_keypair(&staking.key)?;
            let amount = parse_amount(&amount)?;
            let rpc = RpcClient::new(staking.rpc.clone());
            let chain_id = rpc.chain_id().await?;
            let (nonce, payout) = register_row(&rpc, &kp.address()).await?;
            // The chain computes the deposit note itself, from the register's payout address,
            // the public amount, the blinding below and **the height of the block that applies
            // the transaction**. The envelope, which only the payee can open, has to be sealed
            // against that same note — so the height is predicted here as the next block, and
            // said out loud, because a transaction that lands later carries an envelope the
            // payee's wallet cannot open. The note itself is still created and still spendable;
            // it is the automatic discovery of it that a wrong guess costs.
            let height = rpc.head().await?["height"].as_u64().context("head has no height")? + 1;
            let note = Note::new(payout.pk, [0; 8], amount, 0, height as u32);
            let throwaway = SpendKey::random().viewing_key();
            let envelope = shrugg_zkvm::address::seal_note(&throwaway, &payout, &note, &TxKey::random())
                .map_err(|e| anyhow::anyhow!("sealing the payout note: {e}"))?;
            let signature =
                kp.sign(withdraw_message(chain_id, &kp.address(), amount, nonce, &note.r, &envelope).as_bytes());
            let action = shrugg_core::Action::Withdraw {
                validator: kp.address(),
                amount,
                nonce,
                r: note.r,
                envelope,
                signature,
            };
            println!(
                "paying {} SHRUGG to {}\n  note blinding r {} at predicted height {height}",
                format_amount(amount),
                payout,
                word8_to_hex(&note.r)
            );
            submit_staking(&staking, action, &format!("withdraw of {} SHRUGG", format_amount(amount))).await?;
        }
    }
    let _ = UNITS_PER_SHRUGG;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use shrugg_core::ledger::staking::MIN_STAKE;
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
            epoch_blocks: shrugg_core::genesis::EPOCH_BLOCKS_DEFAULT,
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
        // S2 Task 1: the register. This moved from 19df87d5… (itself moved from 700f28e8… by
        // the scaffold's `epoch_blocks` binding) for deliberate, consensus-breaking reasons: the
        // genesis binding now covers every validator's payout address, the state root's
        // validator leaf is `shrugg-validator-leaf-2` over the v2 entry (a length-prefixed
        // unbonding queue, the payout address, the nonce), and this genesis's stakes are the
        // staking minimum, which genesis now requires.
        assert_eq!(state.hash().to_hex(), "fb5881c8d5bb5dcf634a1f036caa4cbfb49d0f3407f0d87419fbfa57686ceb4a");
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
