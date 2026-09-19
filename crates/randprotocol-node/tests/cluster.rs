//! End-to-end: several nodes over real TCP on localhost reach consensus, apply shielded bundles,
//! faucet mints and staking actions submitted over RPC, change their validator set at an epoch
//! boundary, and let a late joiner sync the chain.
//!
//! Two kinds of traffic run here, and the split is deliberate. A *faucet mint* is the one
//! transaction a node can build for itself, costs nothing to make, and still exercises the whole
//! plumbing the structural tests care about — a transaction gossips, commits, changes the
//! commitment tree, and every node's state root agrees afterwards. Those tests run on a fast
//! chain (150 ms blocks) because no proof is involved. A *bundle* costs about a minute and a half
//! of proving in the `test` FRI profile, so the tests that need one (a real transfer, a
//! double-spend race, a deploy and a call, a call's input envelope, both staking tests — a bond is
//! a bundle, and a withdrawn note is spent by one — and a bridge deposit and burn) run on a chain
//! whose blocks are slow enough that the 256-block anchor and time windows outlive the proof — see
//! [`PROVING`].
//!
//! What the bundle tests assert is always a *wallet's* view, never a node's: the chain has no
//! balances, so `balance(node, wallet)` scans a fresh note store against that node's RPC and
//! trial-decrypts, exactly as `rand balance` does. A node that served the scan cannot answer
//! the same question itself.

use randprotocol_client::wallet::{self, Burn, NoteStore, Wallet};
use randprotocol_client::RpcClient;
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_core::bridge::{
    Body, BridgeConfig, Payload,
};
use randprotocol_core::genesis::{
    EnvelopeHex, Genesis, GenesisNote, GenesisOpening, GenesisToken, GenesisValidator, TokensConfig,
};
use randprotocol_core::ledger::staking::{MIN_STAKE, UNBONDING_EPOCHS};
use randprotocol_core::notes::{word8_to_hex, Bundle, Envelope, ShieldedAddress};
use randprotocol_core::types::actions::{registration_message, unbond_message, withdraw_message, Registration};
use randprotocol_core::{gas, Action, Address, Hash, Keypair, Transaction, Word8, UNITS_PER_RAND};
use randprotocol_node::node::{self, NodeConfig};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::notes::{Note, SpendKey};
use randprotocol_zkvm::viewing::TxKey;
use randprotocol_zkvm::{call_envelope, hash};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// One proof at a time, for every test in this file and in `randprotocol-client`'s `wallet_flow.rs`.
mod proving_slot;
/// The node harness and the test bridge guardians, shared with `zusd_e2e.rs`.
mod common;
use common::cluster::*;
use proving_slot::proving_slot;

const CHAIN_ID: u64 = 7;

/// What one funded wallet holds at genesis.
const ALLOC: u64 = 1_000 * UNITS_PER_RAND;

// `PROVING` — the block spacing for every test here that proves a bundle — lives in
// `common::cluster` now, shared with `zusd_e2e.rs`. Why it is three seconds:
//
// Block spacing for every test here that proves a bundle. `ANCHOR_WINDOW` and `TIME_WINDOW` are
// 256 *blocks*, so a bundle gets 256 blocks between reading its anchor and being committed under
// it — and its own `time` word gets the same window. Three-second blocks make that nearly thirteen
// minutes, which is the number `wallet_flow.rs` uses for the same reason.
//
// Proving concurrency is what used to make this number load-bearing. `cargo test --workspace`
// schedules every proving test in this file concurrently and they compete for the same cores: a
// tier-14 bundle measures about 98 s alone and 255 s with six other proofs running, and
// `submit_burn` proves *twice* under one anchor (189 s for the pair, alone). At 1 s blocks — where
// this constant started — a 255 s proof put the committed bundle's own `time` outside the window by
// the time the test replayed it, and `two_validators_commit_and_shielded_transfer` failed on
// `bundle time 2 is outside [3, 259]` instead of on the double-spend it is about. A test must fail
// on its property, not on the clock. S2 raised this to 2 s and S3 to 3 s to buy room against that.
//
// That room was a margin rather than a bound, and [`proving_slot`] is the bound. **What the bound
// actually is: a two-way contended proof, not an uncontended one.** The slot serialises *unrelated*
// proofs, and `two_bundles_spending_one_note_only_one_commits` deliberately proves two bundles at
// once under a single hold — that race is its subject — so the worst case any window has to
// outlive is two proofs under one anchor, ~190–255 s, against 3 s × 256 = 768 s. Measured in the
// serialised suite: a single bundle 94.6–97.9 s (~8× headroom), the race's two concurrent bundles
// 114 s each (~7×), and `submit_burn`'s two sequential bundles 190 s together under one anchor —
// the longest exposure any window here has, and still ~4×.
//
// Three seconds stays, and what it buys is that headroom rather than protection from contention:
//
// - the windows are counted in *blocks*, so slowing the chain is the one knob that costs nothing
//   but a test's patience — and every `wait_*` bound here is already sized for it;
// - a queueing test's own cluster keeps making blocks while it waits for the slot, and at 1 s
//   blocks up to seven idle clusters would burn three times the consensus CPU beside the one proof
//   that actually matters — the slot's whole point is to leave that proof alone;
// - the S2 staking tests hold there too — their longest wait is two `EPOCH`-block epochs, 36 s,
//   against a 180 s bound.
//
// **The open knob is the slot's width, not the block interval.** Serialising costs wall time: the
// suite went from 6m28s with proofs overlapping to 19m59s with one at a time (measured
// 2026-09-13). A slot of N = 2 permits would run two proofs at once — which the race test already
// shows costs ~114 s each rather than ~96 s — and roughly halve the serialised time while keeping
// the bound at the two-way figure this comment states, i.e. inside 768 s with room to spare. It is
// the alternative to reach for if the suite's wall time becomes the problem; N = 1 is what is
// implemented, because it is the simplest thing that makes the bound a bound.
//
// The view timeouts scale with the interval (`start_node_at`), and every `wait_*` bound in these
// tests is a wall-clock timeout with room to spare at 3 s blocks (`wallet::COMMIT_TIMEOUT` is
// 180 s, which is 60 blocks).

/// One genesis deposit note, built exactly as `rand-node genesis` builds it (`main.rs`'s
/// `deposit_note`/`seal_deposit`): a note owned by `to` with fresh commitment randomness, sealed
/// to `to` under a throwaway sender key that is dropped here — a genesis has no identity to keep
/// an outgoing-viewing record for.
fn alloc_note(to: &ShieldedAddress, amount: u64) -> GenesisNote {
    let note = Note::new(to.pk, [0; 8], amount, 0, 0);
    let throwaway = SpendKey::random().viewing_key();
    let envelope =
        randprotocol_zkvm::address::seal_note(&throwaway, to, &note, &TxKey::random()).expect("sealing a deposit note");
    GenesisNote {
        cm: word8_to_hex(&note.commitment()),
        envelope: EnvelopeHex::from_envelope(&envelope),
        amount,
        // Core I-2: what the commitment opens to, as `rand-node genesis` now writes it. Required
        // on any chain with a `tokens` section, emitted always.
        opening: Some(GenesisOpening { pk: word8_to_hex(&note.pk), time: note.time, r: word8_to_hex(&note.r) }),
    }
}

/// A chain with no deposit notes: every note in these tests is minted by a validator at runtime.
/// `hc_bundle` must be this build's own guest, or `node::start` refuses to run at all.
fn genesis(validators: &[Keypair]) -> Genesis {
    genesis_funding(validators, &[])
}

/// The staking chain: short epochs, and a deposit note of exactly the amount each funded wallet
/// needs. Both differ from [`genesis_funding`] for a reason — an epoch has to pass inside a test's
/// patience, and a bond has to cover [`MIN_STAKE`] *and* its bundle's fee, which one [`ALLOC`]
/// note does not.
fn genesis_staking(validators: &[Keypair], funded: &[(&Wallet, u64)]) -> Genesis {
    let mut gen = genesis_funding(validators, &[]);
    gen.epoch_blocks = EPOCH;
    gen.alloc = funded.iter().map(|(w, amount)| alloc_note(&w.address, *amount)).collect();
    gen
}

/// The same chain with one [`ALLOC`] deposit note per wallet in `funded`.
fn genesis_funding(validators: &[Keypair], funded: &[&Wallet]) -> Genesis {
    genesis_bridge(validators, funded, None)
}

/// [`genesis_funding`] with an optional `bridge` section. A chain built with `None` has no bridge
/// at all — no registry, no bridge root, and both bridge actions inadmissible.
fn genesis_bridge(validators: &[Keypair], funded: &[&Wallet], bridge: Option<BridgeConfig>) -> Genesis {
    Genesis {
        chain_id: CHAIN_ID,
        timestamp_ms: 0,
        validators: validators
            .iter()
            .enumerate()
            .map(|(i, k)| GenesisValidator {
                public_key: k.public_key().clone(),
                stake: MIN_STAKE as u128,
                // Phase S2 requires a payout address per validator; nothing in this test
                // withdraws, so it only has to parse.
                payout: randprotocol_core::notes::ShieldedAddress {
                    pk: [i as u32 + 1; 8],
                    kem_ek: vec![i as u8 + 1; randprotocol_core::notes::KEM_EK_BYTES],
                }
                .to_string(),
            })
            .collect(),
        alloc: funded.iter().map(|w| alloc_note(&w.address, ALLOC)).collect(),
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
        // A bridge section needs a tokens section (the RPL gate rides the same fork), and a
        // bridged token is *listed* there: an attestation of a token nobody listed is refused, so
        // the chain that is about to be attested lists [`TOKEN`] and it takes index 1. A
        // bridge-less chain (`bridge: None`) still needs no section at all, so a plain
        // `genesis_funding` chain stays exactly what it always was.
        tokens: bridge.is_some().then(|| TokensConfig {
            registration_fee: 1_000_000_000,
            tokens: vec![GenesisToken {
                name: "Tether USD".into(),
                symbol: "zUSDT".into(),
                salt: [0x5a; 32],
                // Eight decimals — the wire's own — so this coin's release unit is 1 and the burn
                // amounts these tests use need no rounding.
                backings: vec![randprotocol_core::genesis::GenesisBacking {
                    chain: TOKEN_CHAIN,
                    token: TOKEN,
                    decimals: 8,
                }],
            }],
            mint_cap_per_day: 100_000 * 100_000_000,
        }),
        bridge,
        aggregation: None,
        epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
        max_program_words: None,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words: None,
    }
}

// ---------------------------------------------------------------- the bridge
//
// A bridged test chain, built the way `docs/bridge.md` describes one: six guardian secrets whose
// addresses are the genesis guardian set, and chain 2 registered as a source emitter. These are
// the same fixed secrets the core bridge tests sign with, built in `common::bridge` out of the
// public API and shared with `zusd_e2e.rs`.

/// The `bridge` section those guardians name, with chain 2 as the one registered source emitter.
/// No asset is registered: a registry starts empty and the first attestation to name a token is
/// what puts it in, under index 1.
fn bridge_config() -> BridgeConfig {
    common::bridge::bridge_config_for([1; 32], &[TOKEN_CHAIN])
}

/// The lowest-five PQ co-signature quorum over `attestation`'s `mu` on this cluster's chain.
fn pq_quorum(attestation: &[u8]) -> Vec<randprotocol_core::bridge::PqSignature> {
    common::bridge::pq_quorum(CHAIN_ID, attestation)
}

/// The bridged token these tests move: chain 2's `0xaa…`, the one coin backing the single token
/// the fixture's genesis lists, which that listing gives asset index 1.
const TOKEN: [u8; 32] = [0xaa; 32];
const TOKEN_CHAIN: u16 = 2;

/// A well-formed EVM burn destination: twelve zero bytes then twenty address bytes (spec 3.5),
/// which is the shape `BridgeState::check_burn` requires for chains 2, 3 and 4.
const EVM_TO: [u8; 32] = {
    let mut t = [0u8; 32];
    let mut i = 12;
    while i < 32 {
        t[i] = 0x22;
        i += 1;
    }
    t
};

/// One inbound transfer attestation: `amount` units of [`TOKEN`] addressed to `to`, emitted by
/// chain 2's registered emitter and signed by five of the six guardians.
///
/// The 32-byte recipient slot carries `to.recipient_hash()`, not an address: a shielded address is
/// 1.2 KB and the wire format has room for a hash, so the source-chain depositor names the hash and
/// the transaction carries the address for the ledger to check against it.
fn attestation(to: &ShieldedAddress, amount: u128) -> Vec<u8> {
    common::bridge::transfer_attestation(TOKEN_CHAIN, TOKEN, to.recipient_hash(), amount, 0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_validators_plus_late_observer_syncs() {
    init_tracing();
    let ks = keys(5);
    let gen = genesis(&ks[..4]);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], 6, Duration::from_secs(60)).await;

    let (hash, cm) = n2.mint(1, 5 * UNITS_PER_RAND).await;
    wait_for("mint committed on n0", Duration::from_secs(30), || n0.handle.storage.tx_location(&hash).unwrap().is_some())
        .await;

    // Late observer (not a validator) joins and must sync the whole chain.
    let obs = start_node(&ks[4], &gen, boot.clone(), false).await;
    assert!(!obs.handle.status.read().unwrap().is_validator);
    let target = n0.height();
    wait_height(&[&obs], target, Duration::from_secs(60)).await;
    assert!(obs.holds(&cm), "the observer replayed the chain without the minted note");
    // Observer's chain is byte-identical to n0's up to the target.
    for h in 0..=target {
        assert_eq!(
            obs.handle.storage.block_by_height(h).unwrap().unwrap().hash(),
            n0.handle.storage.block_by_height(h).unwrap().unwrap().hash(),
            "height {h}"
        );
    }
    // An observer holds no validator key, so it cannot serve the faucet itself.
    let err = obs.rpc.mint_shielded(&payee(2), Some(1)).await.unwrap_err().to_string();
    assert!(err.contains("validators"), "{err}");
    // And it keeps following live consensus afterwards.
    wait_height(&[&obs], target + 3, Duration::from_secs(30)).await;
    let peers = obs.rpc.call("rand_getPeers", serde_json::json!([])).await.unwrap();
    assert!(!peers.as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn validator_restarts_from_disk_and_resumes() {
    init_tracing();
    let ks = keys(2);
    let gen = genesis(&ks);
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let b = start_node(&ks[1], &gen, vec![bootstrap_addr(&a)], true).await;
    wait_height(&[&a, &b], 4, Duration::from_secs(40)).await;

    // Stop B. With two validators the chain must halt: no QC without both signatures.
    let height_at_stop = b.height();
    let dir = stop(b).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let a_height = a.height();
    assert!(a_height <= height_at_stop + 1, "chain advanced without quorum: {a_height} > {height_at_stop}");

    // Restart B from the same directory: it resumes at its persisted head and the chain continues.
    let b = start_in(dir, &ks[1], vec![bootstrap_addr(&a)], true).await;
    let resumed_from = b.handle.storage.head().unwrap().height;
    assert_eq!(resumed_from, height_at_stop);
    wait_height(&[&a, &b], a_height + 4, Duration::from_secs(60)).await;
    let common = a.height().min(b.height());
    assert_eq!(
        a.handle.storage.block_by_height(common).unwrap().unwrap().hash(),
        b.handle.storage.block_by_height(common).unwrap().unwrap().hash()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_cycles_keep_all_nodes_in_sync() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let mut nodes = vec![n0];
    for k in &ks[1..] {
        nodes.push(start_node(k, &gen, boot.clone(), true).await);
    }
    wait_height(&nodes.iter().collect::<Vec<_>>(), 5, Duration::from_secs(60)).await;

    // Restart nodes 1, 2, 3 in turn (never the bootstrap node, so the others keep an address to dial).
    for cycle in 0..2u8 {
        for i in 1..4 {
            let before = nodes[i].handle.storage.head().unwrap().height;
            let stopped = nodes.remove(i);
            let dir = stop(stopped).await;
            // Others advance while it is down.
            let rest: Vec<&TestNode> = nodes.iter().collect();
            let target = rest.iter().map(|n| n.height()).max().unwrap() + 4;
            wait_height(&rest, target, Duration::from_secs(60)).await;
            // Also mint while it is down, so it has state to catch up on.
            let (_, cm) = nodes[0].mint(10 + cycle * 4 + i as u8, UNITS_PER_RAND).await;

            let restarted = start_in(dir, &ks[i], boot.clone(), true).await;
            assert_eq!(restarted.handle.storage.head().unwrap().height, before, "restart lost committed blocks");
            wait_caught_up(&restarted, &nodes.iter().collect::<Vec<_>>(), Duration::from_secs(60)).await;
            wait_for("the missed note arrives", Duration::from_secs(30), || restarted.holds(&cm)).await;
            nodes.insert(i, restarted);
            assert_chains_equal(&nodes.iter().collect::<Vec<_>>());
        }
    }
    // All four keep committing together afterwards.
    let all: Vec<&TestNode> = nodes.iter().collect();
    let h = all.iter().map(|n| n.height()).max().unwrap();
    wait_height(&all, h + 5, Duration::from_secs(60)).await;
    assert_chains_equal(&all);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_of_four_down_halts_and_recovers_without_fork() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], 5, Duration::from_secs(60)).await;

    let d2 = stop(n2).await;
    let d3 = stop(n3).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let h0 = n0.height();
    tokio::time::sleep(Duration::from_secs(6)).await;
    let h1 = n0.height();
    assert!(h1 <= h0 + 1, "chain advanced without quorum: {h0} -> {h1}");
    assert_chains_equal(&[&n0, &n1]);

    let n2 = start_in(d2, &ks[2], boot.clone(), true).await;
    let n3 = start_in(d3, &ks[3], boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], h1 + 6, Duration::from_secs(90)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_behind_by_more_than_one_sync_batch_catches_up() {
    init_tracing();
    // Four validators: with three, stopping one leaves exactly 2/3 stake, which is not a quorum.
    let ks = keys(4);
    let gen = genesis(&ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    wait_height(&[&n0, &n1, &n2, &n3], 3, Duration::from_secs(60)).await;

    let stopped_at = n2.handle.storage.head().unwrap().height;
    let d2 = stop(n2).await;
    // Sync batches are 100 blocks; get the others more than that ahead (empty blocks, ~150ms each).
    // With one validator down every fourth view times out, so ~2 s per 3 blocks; give it room
    // (the suite runs several clusters in parallel on a few threads).
    wait_height(&[&n0, &n1, &n3], stopped_at + 130, Duration::from_secs(400)).await;
    let (_, cm) = n0.mint(30, 2 * UNITS_PER_RAND).await;

    let n2 = start_in(d2, &ks[2], boot.clone(), true).await;
    assert_eq!(n2.handle.storage.head().unwrap().height, stopped_at);
    wait_caught_up(&n2, &[&n0, &n1, &n3], Duration::from_secs(120)).await;
    wait_for("the note minted while it was down", Duration::from_secs(30), || n2.holds(&cm)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3]);
    // and it participates again afterwards
    let h = n0.height();
    wait_height(&[&n0, &n1, &n2, &n3], h + 5, Duration::from_secs(60)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupted_rocksdb_is_detected_truncated_and_resynced() {
    init_tracing();
    let ks = keys(4);
    let gen = genesis(&ks);
    let executor = node::executor_for_profile(&gen.fri_profile).unwrap();
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node(&ks[1], &gen, boot.clone(), true).await;
    let _n3 = start_node(&ks[3], &gen, boot.clone(), true).await;
    let n2 = start_node(&ks[2], &gen, boot.clone(), true).await;
    // A mint early in the chain, so the note must survive the repair.
    let (hash, cm) = n0.mint(40, 3 * UNITS_PER_RAND).await;
    let receipt_height = n0.handle.storage.tx_location(&hash).unwrap().unwrap().0;
    wait_height(&[&n0, &n1, &n2], receipt_height + 8, Duration::from_secs(60)).await;

    let head = n2.handle.storage.head().unwrap().height;
    let dir = stop(n2).await;
    // Damage the middle of n2's chain on disk, after the mint block.
    let bad_height = receipt_height + 3;
    {
        let st = randprotocol_node::storage::Storage::open(dir.path()).unwrap();
        st.overwrite_block_bytes_for_testing(bad_height, b"\xff\x00corrupt").unwrap();
        // and a subtle one: a validator entry with rewards it never earned
        let mut entry = st.validator(&ks[0].address()).unwrap().expect("a genesis validator");
        entry.rewards += 12_345;
        st.overwrite_validator_for_testing(&ks[0].address(), &entry).unwrap();
        let gs_ = gen.build(executor.as_ref()).unwrap();
        let check = st.verify_chain(&gs_, randprotocol_node::storage::VerifyMode::Full, executor.as_ref()).unwrap();
        assert!(!check.is_ok());
        assert_eq!(check.last_good, bad_height - 1);
    }
    // Restart: startup verification must truncate to bad_height-1, then sync catches up.
    let n2 = start_in(dir, &ks[2], boot.clone(), true).await;
    let resumed = n2.handle.storage.head().unwrap().height;
    assert!(resumed >= bad_height - 1 && resumed < head, "expected truncation below {head}, got {resumed}");
    wait_caught_up(&n2, &[&n0, &n1], Duration::from_secs(90)).await;
    assert!(n2.holds(&cm), "the repaired ledger lost the minted note");
    assert_chains_equal(&[&n0, &n1, &n2]);
    // Verified clean again after the resync.
    let gs_ = gen.build(executor.as_ref()).unwrap();
    let check = n2.handle.storage.verify_chain(&gs_, randprotocol_node::storage::VerifyMode::Full, executor.as_ref()).unwrap();
    assert!(check.is_ok(), "{:?}", check.problem);
    let h = n0.height();
    wait_height(&[&n0, &n1, &n2], h + 4, Duration::from_secs(60)).await;
    assert_chains_equal(&[&n0, &n1, &n2]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn faucet_mint_via_rpc_reaches_every_node() {
    init_tracing();
    let ks = keys(3);
    let gen = genesis(&ks[..2]);
    let a = start_node(&ks[0], &gen, vec![], true).await;
    let boot = vec![bootstrap_addr(&a)];
    let b = start_node(&ks[1], &gen, boot.clone(), true).await;
    let obs = start_node(&ks[2], &gen, boot, false).await;
    wait_height(&[&a, &b, &obs], 2, Duration::from_secs(40)).await;
    assert_eq!(a.handle.storage.notes_count().unwrap(), 0, "an alloc-free genesis starts empty");

    // A validator mints the faucet's full 100 RAND to C.
    let c = wallet(3);
    let (h1, cm1) = b.mint(3, 100 * UNITS_PER_RAND).await;
    wait_for("mint visible on A", Duration::from_secs(30), || a.handle.storage.tx_location(&h1).unwrap().is_some()).await;
    assert!(a.holds(&cm1) && b.holds(&cm1));
    // Every node — the observer included — serves the leaf C's viewing key opens, and none of
    // them can say whose it is.
    wait_for("the observer has the note", Duration::from_secs(30), || obs.holds(&cm1)).await;
    for n in [&a, &b, &obs] {
        assert_eq!(balance(n, &c).await, 100 * UNITS_PER_RAND, "C's balance");
        assert_eq!(balance(n, &wallet(4)).await, 0, "a wallet that was never paid sees nothing");
    }

    // A second mint right away: nothing serialises two mints from one node any more, since
    // there is no nonce to advance — the notes simply differ.
    let (_, cm2) = b.mint(2, 5 * UNITS_PER_RAND).await;
    assert_ne!(cm1, cm2);
    wait_for("both notes on A", Duration::from_secs(30), || a.holds(&cm1) && a.holds(&cm2)).await;
    assert_eq!(a.handle.storage.notes_count().unwrap(), 2);

    // An observer holds no validator key, so it cannot serve the faucet itself.
    let err = obs.rpc.mint_shielded(&payee(3), Some(1)).await.unwrap_err().to_string();
    assert!(err.contains("validators"), "{err}");
    // Over the cap is rejected, and so is an address that is not a shielded address.
    assert!(b.rpc.mint_shielded(&payee(3), Some(101 * UNITS_PER_RAND)).await.is_err());
    assert!(b.rpc.mint_shielded("not-an-address", Some(1)).await.is_err());
    assert_chains_equal(&[&a, &b, &obs]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn faucet_is_rejected_when_genesis_disables_it() {
    init_tracing();
    let ks = keys(1);
    let mut gen = genesis(&ks);
    gen.faucet = false;
    let a = start_node(&ks[0], &gen, vec![], true).await;
    wait_height(&[&a], 2, Duration::from_secs(40)).await;
    let err = a.rpc.mint_shielded(&payee(1), None).await.unwrap_err().to_string();
    assert!(err.contains("faucet is disabled"), "{err}");
    assert_eq!(a.handle.storage.notes_count().unwrap(), 0);
}

/// The refused cache end to end: a mint whose signature does not check is a permanent verdict,
/// so the second copy of the same bytes is refused without a second verification — and the
/// count an operator reads says so. No proving: a bad mint signature needs no bundle, which is
/// why this runs on a FAST chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_transaction_is_not_verified_twice() {
    init_tracing();
    // One validator: two in the set with only one running could never form a QC, and this
    // test needs the chain to commit.
    let ks = keys(1);
    let gen = genesis(&ks);
    let n0 = start_node(&ks[0], &gen, vec![], true).await;
    wait_height(&[&n0], 2, Duration::from_secs(20)).await;
    assert_eq!(n0.handle.status.read().unwrap().refused_cache, 0);

    // A mint that names a real validator as its minter and carries a signature over nothing.
    let bad = Transaction {
        chain_id: CHAIN_ID,
        bundle: None,
        action: Action::Mint {
            cm: [9; 8],
            pk: [9; 8],
            time: 0,
            r: [9; 8],
            envelope: Envelope { kem_ct: vec![1; 8], to_receiver: vec![], to_sender: vec![], body: vec![2; 8] },
            amount: 1_000,
            minter: ks[0].public_key().clone(),
            signature: randprotocol_core::Signature::empty(),
        },
    };
    let first = n0.rpc.send_transaction(&bad).await.unwrap_err().to_string();
    assert!(first.contains("mint signature"), "{first}");
    wait_for("the refusal to be cached", Duration::from_secs(5), || {
        n0.handle.status.read().unwrap().refused_cache == 1
    })
    .await;
    // The same bytes again: the same refusal, and the cache did not grow — it answered.
    let again = n0.rpc.send_transaction(&bad).await.unwrap_err().to_string();
    assert!(again.contains("mint signature"), "{again}");
    assert_eq!(n0.handle.status.read().unwrap().refused_cache, 1);
    // A legitimate transaction still goes through, so the cache is not a blanket refusal.
    n0.mint(7, 5 * UNITS_PER_RAND).await;
    stop(n0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_build_whose_bundle_guest_differs_from_genesis_refuses_to_start() {
    init_tracing();
    let ks = keys(1);
    let mut gen = genesis(&ks);
    // What an operator running the wrong commit would have on disk.
    gen.hc_bundle = word8_to_hex(&[0xdead; 8]);
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("genesis.json"), gen.to_json()).unwrap();
    let started = node::start(NodeConfig {
        datadir: dir.path().to_path_buf(),
        seed: *ks[0].seed(),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        enable_mdns: false,
        validator: true,
        block_interval: Duration::from_millis(150),
        base_timeout: Duration::from_millis(1500),
        max_timeout: Duration::from_secs(6),
        verify: randprotocol_node::storage::VerifyMode::Full,
        keep_raw_proofs: false,
    })
    .await;
    // `NodeHandle` is not `Debug`, so unwrap the error by hand rather than via `expect_err`.
    let err = match started {
        Ok(_) => panic!("a mismatched bundle guest must not start"),
        Err(e) => e.to_string(),
    };
    // The message must name both digests: an operator has to know which build to go back to.
    assert!(err.contains("bundle guest"), "{err}");
    assert!(err.contains(&word8_to_hex(&ZkExecutor::hc_bundle())), "{err}");
    assert!(err.contains(&word8_to_hex(&[0xdead; 8])), "{err}");
}

// ---------------------------------------------------------------- shielded bundles
//
// Everything below proves a real 2-in-2-out bundle, so these tests are minutes rather than
// seconds and run on a `PROVING`-paced chain (see the constant). They are also the only tests
// here that look at value at all: a mint proves that a note arrived, a bundle proves that value
// moved from one wallet to another without the chain ever learning either.
//
// Every proof below is taken under the workspace's one proving slot (`proving_slot`), which is
// what makes the anchor window a bound rather than a margin: the slot is held around the whole
// `wallet::` call, so it is taken before the anchor is read and released after the commit.

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_validators_commit_and_shielded_transfer() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    let (a, b) = (wallet(1), wallet(2));
    let gen = genesis_funding(&ks, &[&a]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(60)).await;

    // The genesis deposit note is on both nodes, and only A's viewing key opens it.
    for n in [&n0, &n1] {
        assert_eq!(balance(n, &a).await, ALLOC, "A's genesis note");
        assert_eq!(balance(n, &b).await, 0, "B has nothing yet");
    }

    let fee = gas::BUNDLE_BASE;
    let pay = UNITS_PER_RAND;
    let mut store = NoteStore::default();
    let slot = proving_slot().await;
    let sent = wallet::send(&n0.rpc, &a, &mut store, &b.address, pay, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the bundle is accepted and commits");
    drop(slot);
    eprintln!("transfer: tier {}, proved in {:.1?}, {} proof bytes", sent.tier, sent.proving, sent.proof_bytes);

    // Both validators carry the same transaction, and both answer the same two balances.
    wait_for("the transfer reaches n1", Duration::from_secs(60), || {
        n1.handle.storage.tx_location(&sent.hash).unwrap().is_some()
    })
    .await;
    for n in [&n0, &n1] {
        assert_eq!(balance(n, &b).await, pay, "B was paid 1 RAND");
        assert_eq!(balance(n, &a).await, ALLOC - pay - fee, "A keeps 999 RAND less the fee");
    }
    // The fee left the pool and landed in the proposer's public register entry.
    let rewards: u64 = gen
        .validators
        .iter()
        .map(|v| n0.handle.storage.validator(&v.public_key.address()).unwrap().map(|e| e.rewards).unwrap_or(0))
        .sum();
    assert_eq!(rewards, fee, "the bundle fee is the only reward paid so far");

    // A replay of the very bytes that committed: the nullifiers are in the set now, so the
    // node refuses it before any proof is re-verified.
    let (height, index) = n0.handle.storage.tx_location(&sent.hash).unwrap().unwrap();
    let tx = n0.handle.storage.block_by_height(height).unwrap().unwrap().transactions[index as usize].clone();
    let err = n0.rpc.send_transaction(&tx).await.unwrap_err().to_string();
    assert!(err.contains("spent"), "a replayed bundle must be refused as spent: {err}");

    // The compact-block read against this chain: a wallet that has only ever called
    // getCompactBlocks sees exactly the leaves and nullifiers getCommitments and getNullifiers
    // report, and the rows are grouped by the transaction that produced them. Folded into this
    // test rather than given one of its own because the proving slot serialises the suite — a
    // second copy of this opening is a thirteenth bundle proof and ~95–100 s of wall time, and
    // these assertions need no chain of their own.
    let head = n0.rpc.head().await.unwrap()["height"].as_u64().unwrap();
    wait_height(&[&n1], head, Duration::from_secs(30)).await;
    // Page the range as a wallet must: one call covers at most 128 blocks, so resume from the
    // last returned height + 1 until the range is done. Not ceremony — under the full suite this
    // test's own chain keeps making 3 s blocks while the proof waits for the slot, and the
    // transfer landed at height 181, past the first page, where a single [0, head] call is
    // silently clamped to 128 blocks.
    let mut compact: Vec<Value> = Vec::new();
    let mut from = 0;
    while from <= head {
        let page = n0.rpc.call("rand_getCompactBlocks", json!([from, head])).await.unwrap();
        let page = page.as_array().unwrap();
        assert!(!page.is_empty(), "a page inside [0, {head}] is never empty");
        from = page.last().unwrap()["height"].as_u64().unwrap() + 1;
        compact.extend(page.iter().cloned());
    }

    // Every leaf, in the same order and with the same envelopes, as the paged read. The
    // block-level `commitments` flatten first only because the one block that has any — height
    // 0's genesis deposit — has no transactions; every later block's array is empty, so the
    // flatten is in tree order.
    let flat: Vec<Value> = compact
        .iter()
        .flat_map(|b| {
            b["commitments"].as_array().unwrap().iter().cloned().chain(
                b["transactions"].as_array().unwrap().iter().flat_map(|t| t["commitments"].as_array().unwrap().iter().cloned()),
            )
        })
        .collect();
    let paged = n0.rpc.call("rand_getCommitments", json!([0, 1000])).await.unwrap();
    let paged = paged.as_array().unwrap();
    assert_eq!(flat.len(), paged.len(), "the same leaves");
    for (a, b) in flat.iter().zip(paged) {
        assert_eq!((&a["index"], &a["cm"], &a["envelope"]), (&b["index"], &b["cm"], &b["envelope"]));
    }
    // And every nullifier, attributed to the transaction that spent it.
    let nfs: Vec<&str> = compact
        .iter()
        .flat_map(|b| b["transactions"].as_array().unwrap())
        .flat_map(|t| t["nullifiers"].as_array().unwrap())
        .map(|n| n.as_str().unwrap())
        .collect();
    let paged_nfs = n0.rpc.call("rand_getNullifiers", json!([0, 1000])).await.unwrap();
    assert_eq!(nfs.len(), paged_nfs.as_array().unwrap().len());
    for row in paged_nfs.as_array().unwrap() {
        assert!(nfs.contains(&row["nullifier"].as_str().unwrap()));
    }
    // Every node answers the same way.
    assert_eq!(
        n1.rpc.call("rand_getCompactBlocks", json!([0, head])).await.unwrap(),
        n0.rpc.call("rand_getCompactBlocks", json!([0, head])).await.unwrap()
    );

    assert_chains_equal(&[&n0, &n1]);
    eprintln!("two_validators_commit_and_shielded_transfer in {:.1?}", started.elapsed());
}

/// A node that was down while a real shielded transfer committed must be able to sync past it.
///
/// The chain-8 wall this belongs to is a *size* bug, not a slowness one: a batch carrying a
/// constraint-set-5 proof under 18-validator Dilithium2 QCs came to more than the 10 MiB the
/// libp2p CBOR codec reads before it truncates, so the response was cut mid-message and failed to
/// decode. Node A sat at the height below the chain's first transfer across restarts, asking four
/// peers for the same range and getting `Eof { name: "bytes", .. }` from each — unservable at any
/// size the client asked for, because the server's budget counted only `cb.block.encode()`.
///
/// What this test covers is the end-to-end path: a node that missed a proof-bearing block gets it
/// over sync, replays it, and agrees on the state it produced. It does **not** reproduce the
/// overrun itself — a `FriProfile::Test` proof is ~300 KB against production's ~1.3 MB, and four
/// validators make a QC a twentieth of chain 8's — so the wire arithmetic is pinned where it can be
/// stated exactly: `network::codec::tests` round-trips a real chain-8-shaped batch through the
/// codec, and `node::tests` measures the budget against
/// `MAX_PROOF_BYTES` and 18-validator QCs.
///
/// Four validators, because three leave exactly 2/3 of the stake when one is down, which is not a
/// quorum, and the chain has to keep committing while this node is away.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_node_that_was_down_syncs_past_a_block_carrying_a_real_proof() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(4);
    let (a, b) = (wallet(1), wallet(2));
    let gen = genesis_funding(&ks, &[&a]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node_at(&ks[1], &gen, boot.clone(), true, PROVING).await;
    let n2 = start_node_at(&ks[2], &gen, boot.clone(), true, PROVING).await;
    let n3 = start_node_at(&ks[3], &gen, boot.clone(), true, PROVING).await;
    wait_height(&[&n0, &n1, &n2, &n3], 2, Duration::from_secs(90)).await;

    // n3 goes down before the transfer, so the only way it can learn the proof-bearing block is
    // over sync.
    let stopped_at = n3.handle.storage.head().unwrap().height;
    let d3 = stop(n3).await;

    let fee = gas::BUNDLE_BASE;
    let pay = UNITS_PER_RAND;
    let mut store = NoteStore::default();
    let slot = proving_slot().await;
    let sent = wallet::send(&n0.rpc, &a, &mut store, &b.address, pay, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the bundle is accepted and commits");
    drop(slot);
    eprintln!("transfer: tier {}, proved in {:.1?}, {} proof bytes", sent.tier, sent.proving, sent.proof_bytes);
    // The point of the test: a block carrying a real proof, not a stub. In the `test` profile that
    // is ~300 KB (production's 80-query profile is ~1.3 MB), still two orders of magnitude past an
    // empty block and enough that the block must travel as its own batch.
    assert!(sent.proof_bytes > 200 << 10, "expected a real proof, got {} bytes", sent.proof_bytes);

    let (proof_height, _) = n0.handle.storage.tx_location(&sent.hash).unwrap().unwrap();
    assert!(proof_height > stopped_at, "the transfer must land after n3 went down");
    // And put a few more blocks on top, so catching up means a batch, not a single block.
    wait_height(&[&n0, &n1, &n2], proof_height + 3, Duration::from_secs(180)).await;

    // Back up: it must cross the proof-bearing block and reach the others.
    let n3 = start_in_at(d3, &ks[3], boot.clone(), true, PROVING).await;
    assert_eq!(n3.handle.storage.head().unwrap().height, stopped_at);
    wait_caught_up(&n3, &[&n0, &n1, &n2], Duration::from_secs(180)).await;
    assert!(
        n3.handle.storage.tx_location(&sent.hash).unwrap().is_some(),
        "n3 synced without the proof-bearing transaction"
    );
    // It agrees on the state the proof produced, not merely on the block bytes.
    assert_eq!(balance(&n3, &b).await, pay, "B's note, as n3 sees it");
    assert_eq!(balance(&n3, &a).await, ALLOC - pay - fee);
    assert_chains_equal(&[&n0, &n1, &n2, &n3]);

    // and it keeps up afterwards
    let h = n0.height();
    wait_height(&[&n0, &n1, &n2, &n3], h + 3, Duration::from_secs(120)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3]);
    eprintln!("a_node_that_was_down_syncs_past_a_block_carrying_a_real_proof in {:.1?}", started.elapsed());
}

/// Two bundles spending the same note, proved in parallel and submitted to two different
/// validators. Whichever reaches a block first spends the note; the other can never be admitted
/// again — it is refused at the RPC if the nullifier is already committed, or dropped from the
/// mempool by `prune` if it was accepted before the race resolved. Either way the chain must end
/// with exactly one of them and every node must agree on the result.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn two_bundles_spending_one_note_only_one_commits() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    let (a, b) = (wallet(5), wallet(6));
    let gen = genesis_funding(&ks, &[&a]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(60)).await;
    assert_eq!(balance(&n0, &a).await, ALLOC);

    let fee = gas::BUNDLE_BASE;
    // Different amounts, so the two bundles differ in every public field except the nullifier
    // they collide on — and `--no-wait`, so each returns as soon as its node has answered.
    let race = |rpc: RpcClient, pay: u64| {
        tokio::spawn(async move {
            let (a, b) = (wallet(5), wallet(6));
            let mut store = NoteStore::default();
            let out =
                wallet::send(&rpc, &a, &mut store, &b.address, pay, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, false)
                    .await;
            out.map(|s| (s.hash, s.amount))
        })
    };
    // One slot for the pair, not one each: these two proofs are the *subject* of this test — two
    // bundles built against the same tree, so that one of them has to lose — and taking the slot
    // twice would prove them one after the other, the second scanning a chain where the note it
    // means to spend is already spent. The slot bounds unrelated proofs (`proving_slot`).
    let slot = proving_slot().await;
    let one = race(n0.rpc.clone(), UNITS_PER_RAND);
    let two = race(n1.rpc.clone(), 2 * UNITS_PER_RAND);
    let (one, two) = tokio::join!(one, two);
    drop(slot);

    let mut accepted: Vec<(Hash, u64)> = Vec::new();
    let mut refused: Vec<String> = Vec::new();
    for r in [one.expect("the prover task did not panic"), two.expect("the prover task did not panic")] {
        match r {
            Ok(pair) => accepted.push(pair),
            Err(e) => refused.push(e.to_string()),
        }
    }
    assert!(!accepted.is_empty(), "both bundles were refused outright: {refused:?}");
    eprintln!("accepted {} bundle(s), refused {refused:?}", accepted.len());

    // One of the accepted hashes commits; give the chain a few blocks past it so a loser that was
    // admitted has been pruned rather than merely not-yet-proposed.
    let hashes: Vec<Hash> = accepted.iter().map(|(h, _)| *h).collect();
    let committed_on = |n: &TestNode| -> Vec<Hash> {
        hashes.iter().copied().filter(|h| n.handle.storage.tx_location(h).unwrap().is_some()).collect()
    };
    wait_for("one of the two bundles commits", Duration::from_secs(90), || !committed_on(&n0).is_empty()).await;
    let h = n0.height();
    wait_height(&[&n0, &n1], h + 6, Duration::from_secs(90)).await;

    let winners = committed_on(&n0);
    assert_eq!(winners.len(), 1, "exactly one of two bundles spending the same note may commit");
    assert_eq!(committed_on(&n1), winners, "the two validators disagree about which one won");

    // The winner's amount is what B holds, and A's note paid for it exactly once.
    let paid = accepted.iter().find(|(h, _)| *h == winners[0]).map(|(_, amount)| *amount).unwrap();
    for n in [&n0, &n1] {
        assert_eq!(balance(n, &b).await, paid, "B holds the winning bundle's payment, and only that");
        assert_eq!(balance(n, &a).await, ALLOC - paid - fee);
    }
    assert_chains_equal(&[&n0, &n1]);
    eprintln!("two_bundles_spending_one_note_only_one_commits in {:.1?}", started.elapsed());
}

/// Deploy and call, both paid for by a bundle rather than by an account. The deploy and the call
/// are ordinary shielded transactions whose `Action` happens to carry a program: the wallet pays
/// each one's fee floor out of its notes, and the only thing the chain learns is that *some*
/// note paid.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn confidential_call_rides_on_a_bundle() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    let a = wallet(7);
    let gen = genesis_funding(&ks, &[&a]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(60)).await;

    let program = randprotocol_zkvm::guests::private_payment(1_000);
    let id = randprotocol_core::program::program_id(program.base_pc, &program.words);
    let mut store = NoteStore::default();

    // ---- deploy, paid by a bundle ----
    let action = Action::Deploy { base_pc: program.base_pc, words: program.words.clone(), public: vec![] };
    let deploy_fee = wallet::deploy_fee_default(&action);
    assert_eq!(deploy_fee, gas::BUNDLE_BASE + gas::deploy_fee(program.words.len()));
    let slot = proving_slot().await;
    let deployed =
        wallet::submit(&n0.rpc, &a, &mut store, None, action, deploy_fee, Burn::None, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
            .await
            .expect("the deploy bundle commits");
    drop(slot);
    eprintln!("deploy: {} words, fee {deploy_fee}, proved in {:.1?}", program.words.len(), deployed.proving);
    assert_eq!(deployed.amount, 0, "a deploy pays nobody; it is a self-transfer of zero");
    for n in [&n0, &n1] {
        wait_for("the program reaches every node", Duration::from_secs(60), || {
            n.handle.storage.program(&id).unwrap().is_some()
        })
        .await;
    }

    // ---- call, proved locally, paid by a second bundle ----
    // The call's own proof and the bundle that pays for it are one hold of the slot: a program
    // proof is prover work like any other, and the bundle follows it immediately.
    let slot = proving_slot().await;
    let (proof, outputs, tier) =
        randprotocol_zkvm::executor::prove(FriProfile::Test, &program, &[400, 250, 300, 75], &[], None, Backend::Cpu)
            .expect("the call proves");
    eprintln!("call: tier {tier}, {} proof bytes, outputs {outputs:?}", proof.len());
    let call_fee = wallet::call_fee_default(tier, randprotocol_core::gas::call_bytes(&proof, None));
    let called = wallet::submit(
        &n0.rpc,
        &a,
        &mut store,
        None,
        Action::Call { program: id, proof, input_envelope: None },
        call_fee,
        Burn::None,
        FriProfile::Test,
        Backend::Cpu,
        CHAIN_ID,
        true,
    )
    .await
    .expect("the call bundle commits");
    drop(slot);
    eprintln!("call bundle: fee {call_fee}, proved in {:.1?}", called.proving);

    // The receipt is on every node, with the outputs the prover published.
    for n in [&n0, &n1] {
        wait_for("the receipt reaches every node", Duration::from_secs(60), || {
            n.handle.storage.receipt(&called.hash).unwrap().is_some()
        })
        .await;
        let r = n.handle.storage.receipt(&called.hash).unwrap().unwrap();
        assert_eq!(r.program, id);
        assert_eq!(r.tier, tier);
        assert_eq!(r.outputs, outputs);
    }

    // A paid the two fee floors and not one unit more: the deploy and the call moved no value.
    for n in [&n0, &n1] {
        assert_eq!(balance(n, &a).await, ALLOC - deploy_fee - call_fee, "A paid exactly the two floors");
    }
    assert_chains_equal(&[&n0, &n1]);
    eprintln!("confidential_call_rides_on_a_bundle in {:.1?}", started.elapsed());
}

// ---------------------------------------------------------------- staking (phase S2)
//
// The register with public weights, end to end on a real cluster: a validator registers and bonds
// itself in through a wallet's bundle and starts proposing when its epoch arrives; another unbonds
// itself out and withdraws its stake into a note its payout wallet can spend. Both run on a
// `PROVING`-paced chain — each proves one real bundle — and on [`EPOCH`]-block epochs, because
// what they are about is what happens at an epoch boundary.

/// Blocks per epoch for the staking tests. The chain's default is 1000, which at `PROVING` pace
/// would be over half an hour per boundary; six blocks is twelve seconds and still exercises the
/// one rule that matters here — the set for epoch `e` is derived from the register as of the last
/// block of epoch `e - 1`.
const EPOCH: u64 = 6;

/// One row of the register as `rand_getValidators` reports it, or `None` when the register holds
/// no entry for that address. This is the read `rand-node unbond` and `withdraw` make to find
/// their nonce, so a test that drives them by hand makes it too.
async fn register_row(node: &TestNode, validator: &Address) -> Option<serde_json::Value> {
    let rows = node.rpc.validators().await.expect("getValidators answers");
    let want = validator.to_base58();
    rows.as_array()?.iter().find(|r| r["address"].as_str() == Some(want.as_str())).cloned()
}

/// The supply audit, as `rand_getSupply` reports it (`docs/supply.md`).
async fn supply_of(node: &TestNode) -> serde_json::Value {
    node.rpc.call("rand_getSupply", serde_json::json!([])).await.expect("getSupply answers")
}

/// An amount from an RPC reply. Every amount the register and the supply audit publish is a
/// decimal string, because a JSON number is not an exact integer past 2^53.
fn units(v: &serde_json::Value) -> u64 {
    v.as_str().expect("an amount is a decimal string").parse().expect("an amount parses")
}

/// A validator-signed action rides alone: no bundle to prove, no wallet, and the register's nonce
/// is the whole of its replay protection — exactly the transaction `rand-node unbond` and
/// `rand-node withdraw` build.
fn signed_tx(action: Action) -> Transaction {
    Transaction { chain_id: CHAIN_ID, bundle: None, action }
}

/// Wait until every node reports `active == want` for `validator`'s register row, then assert it by
/// timing out.
///
/// Deliberately not a [`wait_for`]: the row comes from an RPC call, so the condition cannot be a
/// synchronous closure — and it has to be asked of every node rather than read off one, because
/// `active` is *that node's* consensus-side current set. A node one view behind another reports the
/// previous epoch's answer, so asserting the flag straight after another node's has flipped is a
/// race even though the two agree within a block.
async fn wait_active(nodes: &[&TestNode], validator: &Address, want: bool, timeout: Duration) {
    let start = Instant::now();
    loop {
        let mut agreed = true;
        for n in nodes {
            let active = register_row(n, validator).await.and_then(|r| r["active"].as_bool()).unwrap_or(false);
            agreed &= active == want;
        }
        if agreed {
            return;
        }
        assert!(start.elapsed() < timeout, "timed out waiting for every node to report active={want} for {validator}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// A fifth validator joins a running four-validator chain: its operator prints a registration, a
/// wallet bonds the minimum stake with it attached, and from the next epoch on the new key is in
/// the set every node derives — leading views and having its blocks committed by the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_fifth_validator_registers_bonds_and_joins_the_next_epoch() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(5);
    let bonder = wallet(50);
    let payout = wallet(51);
    // One note has to hold the stake and the fee of the bundle that burns it: 1000 RAND of stake,
    // and 1 RAND more to pay the 0.001 fee out of and keep as change.
    let funding = MIN_STAKE + UNITS_PER_RAND;
    let gen = genesis_staking(&ks[..4], &[(&bonder, funding)]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node_at(&ks[1], &gen, boot.clone(), true, PROVING).await;
    let n2 = start_node_at(&ks[2], &gen, boot.clone(), true, PROVING).await;
    let n3 = start_node_at(&ks[3], &gen, boot.clone(), true, PROVING).await;
    // The joiner runs with `--validator` from the start and simply observes: the node's
    // `is_validator` means "a signer is here", and a key in no current epoch's set neither
    // proposes nor votes until an epoch admits it (spec §8) — which is why joining needs no
    // restart.
    let n4 = start_node_at(&ks[4], &gen, boot.clone(), true, PROVING).await;
    let all = [&n0, &n1, &n2, &n3, &n4];
    wait_height(&all, 2, Duration::from_secs(60)).await;
    {
        let s = n4.handle.status.read().unwrap();
        assert!(s.is_validator, "the joiner holds a validator key");
        assert!(!s.active_validator, "which is in no epoch's set yet");
    }
    assert!(register_row(&n0, &ks[4].address()).await.is_none(), "and in no register row yet");

    // ---- the bond: a wallet's bundle burns the stake, with the validator's registration attached
    let registration = Registration {
        public_key: ks[4].public_key().clone(),
        payout: payout.address.clone(),
        signature: ks[4].sign(registration_message(CHAIN_ID, &payout.address).as_bytes()),
    };
    let action = Action::Bond { validator: ks[4].address(), amount: MIN_STAKE, registration: Some(registration) };
    let fee = gas::fee_floor(&action);
    let mut store = NoteStore::default();
    let slot = proving_slot().await;
    let bonded =
        wallet::submit(&n0.rpc, &bonder, &mut store, None, action, fee, Burn::Rand(MIN_STAKE), FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
            .await
            .expect("the bond's bundle is accepted and commits");
    drop(slot);
    eprintln!("bond: tier {}, proved in {:.1?}, {} proof bytes", bonded.tier, bonded.proving, bonded.proof_bytes);
    assert_eq!(bonded.burn, Burn::Rand(MIN_STAKE), "the bundle burns exactly what is bonded, in RAND");
    assert_eq!(bonded.amount, 0, "a bond pays nobody a note");

    // The register has the entry at once, with the payout address the validator itself signed for.
    let row = register_row(&n0, &ks[4].address()).await.expect("the bond registered the fifth validator");
    assert_eq!(units(&row["stake"]), MIN_STAKE);
    assert_eq!(row["payout"].as_str().unwrap(), payout.address.to_string(), "the payout it signed, not the bonder's");
    assert_eq!(row["nonce"].as_u64().unwrap(), 0, "a fresh entry's first signed action carries nonce 0");
    let epoch = n0.rpc.epoch().await.unwrap();
    assert_eq!(epoch["epoch_blocks"].as_u64().unwrap(), EPOCH);
    assert_eq!(epoch["next_set"].as_array().unwrap().len(), 5, "the register derives five for the next epoch");

    // ---- the boundary: from here the key is weight, not just a row
    wait_for("the fifth validator's epoch to arrive", Duration::from_secs(180), || {
        n4.handle.status.read().unwrap().active_validator
    })
    .await;
    let joined_at = n4.height();
    // Every node has to agree it is in, not just the joiner: `active` is each node's own view of the
    // current set, so this waits rather than reads.
    wait_active(&all, &ks[4].address(), true, Duration::from_secs(60)).await;

    // Two whole epochs of the five-validator set. The leader schedule runs over the set, so a
    // member leads about one view in five and the chain cannot advance past its views without it:
    // a block proposed by the newcomer is proof that the other four voted for it.
    let until = joined_at + 2 * EPOCH + 2;
    wait_height(&all, until, Duration::from_secs(240)).await;
    let proposed: Vec<u64> = (joined_at..=until)
        .filter(|h| {
            n0.handle.storage.block_by_height(*h).unwrap().is_some_and(|b| b.proposer() == ks[4].address())
        })
        .collect();
    assert!(!proposed.is_empty(), "the fifth validator led no view in heights {joined_at}..={until}");
    eprintln!("the fifth validator proposed blocks {proposed:?}");

    // The register is hashed into the state root, so a node that had missed the bond would differ
    // here rather than merely disagree about who may propose.
    assert_chains_equal(&all);

    // The stake left the pool as the bundle's burn instead of becoming anyone's note, and the
    // audit accounts for it on the register's side of the boundary (`docs/supply.md`).
    assert_eq!(balance(&n0, &bonder).await, funding - MIN_STAKE - fee, "the wallet paid the stake and the fee");
    let supply = supply_of(&n0).await;
    assert_eq!(units(&supply["burned"]), MIN_STAKE, "a bond is the only thing that burns");
    assert_eq!(units(&supply["genesis_deposited"]), funding);
    assert_eq!(units(&supply["genesis_staked"]), 4 * MIN_STAKE);
    assert_eq!(units(&supply["register_total"]), 5 * MIN_STAKE + fee, "four genesis stakes, the bond, and the fee");
    assert!(supply["invariant_holds"].as_bool().unwrap(), "{supply}");
    eprintln!("a_fifth_validator_registers_bonds_and_joins_the_next_epoch in {:.1?}", started.elapsed());
}

/// The other direction: validator D unbonds its whole stake, so the next epoch's set is derived
/// without it; two epochs later the amount is released and a withdraw pays it into a deposit note
/// at the register's payout address — a note the payout wallet finds by scanning and can spend,
/// which is the only proof that a withdraw really returns value to the pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn unbond_below_min_stake_leaves_the_set_and_withdraw_pays_a_spendable_note() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(4);
    // D's payout wallet starts with nothing at all: every unit it spends at the end arrived as the
    // withdraw's own note, so the spend is what proves the note is real.
    let payout = wallet(52);
    let payee = wallet(53);
    let mut gen = genesis_staking(&ks, &[]);
    gen.validators[3].payout = payout.address.to_string();
    let d = ks[3].address();
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node_at(&ks[1], &gen, boot.clone(), true, PROVING).await;
    let n2 = start_node_at(&ks[2], &gen, boot.clone(), true, PROVING).await;
    let n3 = start_node_at(&ks[3], &gen, boot.clone(), true, PROVING).await;
    let all = [&n0, &n1, &n2, &n3];
    wait_height(&all, 2, Duration::from_secs(60)).await;
    assert!(n3.handle.status.read().unwrap().active_validator, "D starts in the genesis set");
    assert_eq!(balance(&n0, &payout).await, 0, "the payout wallet holds nothing to begin with");

    // ---- unbond the whole stake: free, bundle-less, signed by the validator's own key
    let nonce = register_row(&n0, &d).await.unwrap()["nonce"].as_u64().unwrap();
    let signature = ks[3].sign(unbond_message(CHAIN_ID, &d, MIN_STAKE, nonce).as_bytes());
    let unbond = signed_tx(Action::Unbond { validator: d, amount: MIN_STAKE, nonce, signature });
    let hash = n0.rpc.send_transaction(&unbond).await.expect("the unbond is accepted");
    let unbonded = n0.rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("the unbond commits");
    let row = register_row(&n0, &d).await.unwrap();
    assert_eq!(units(&row["stake"]), 0, "the whole stake moved into unbonding");
    assert_eq!(row["nonce"].as_u64().unwrap(), nonce + 1, "the nonce is the replay protection");
    let pending = row["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1, "one row per release epoch");
    assert_eq!(units(&pending[0]["amount"]), MIN_STAKE);
    let release_epoch = pending[0]["release_epoch"].as_u64().unwrap();
    assert_eq!(release_epoch, unbonded.height / EPOCH + UNBONDING_EPOCHS, "released two epochs on");

    // ---- the next boundary derives the set without it: an entry with no stake is not eligible.
    // (The *amount* waits `UNBONDING_EPOCHS`; the *set* is re-derived at the very next boundary,
    // which is why a validator stops proposing long before it can withdraw.)
    wait_for("D to leave the set", Duration::from_secs(180), || !n3.handle.status.read().unwrap().active_validator).await;
    wait_active(&all, &d, false, Duration::from_secs(60)).await;
    assert_eq!(n0.rpc.epoch().await.unwrap()["next_set"].as_array().unwrap().len(), 3);
    // The other three are a quorum on their own — more than 2/3 of three equal stakes is three of
    // them — so the chain keeps committing through the boundary and D keeps following it. From the
    // *first block of the next epoch* on, D leads no view: the set the leader rotation runs over is
    // the one that epoch's boundary derived, and D is not in it. The epoch it was still in counts
    // for nothing here — the unbond and the boundary are different heights.
    let out_from = (unbonded.height / EPOCH + 1) * EPOCH;
    wait_height(&all, out_from + EPOCH, Duration::from_secs(180)).await;
    let led = (out_from..=n0.height())
        .filter(|h| n0.handle.storage.block_by_height(*h).unwrap().is_some_and(|b| b.proposer() == d))
        .count();
    assert_eq!(led, 0, "a validator the epoch's set excludes leads no view in it");

    // ---- withdraw, once the unbonding epochs have passed
    wait_height(&all, release_epoch * EPOCH, Duration::from_secs(240)).await;
    let nonce = register_row(&n0, &d).await.unwrap()["nonce"].as_u64().unwrap();
    let base = gas::BUNDLE_BASE;
    // Exactly what `rand-node withdraw` builds: the note is worth the amount less the base, at
    // the head height (inside the 256-block window), and its envelope is sealed to the payout
    // address under a throwaway sender key. The chain recomputes the commitment from the register
    // and the action's public fields, so the note it appends is this one or the withdraw is
    // refused.
    let time = n0.height() as u32;
    let note = Note::new(payout.address.pk, [0; 8], MIN_STAKE - base, 0, time);
    let envelope = randprotocol_zkvm::address::seal_note(&SpendKey::random().viewing_key(), &payout.address, &note, &TxKey::random())
        .expect("sealing the payout note");
    let signature = ks[3].sign(withdraw_message(CHAIN_ID, &d, MIN_STAKE, nonce, time, &note.r, &envelope).as_bytes());
    let withdraw = signed_tx(Action::Withdraw {
        validator: d,
        amount: MIN_STAKE,
        nonce,
        time,
        r: note.r,
        envelope,
        signature,
    });
    let hash = n0.rpc.send_transaction(&withdraw).await.expect("the withdraw is accepted");
    let paid_in = n0.rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("the withdraw commits");
    let cm = note.commitment();
    wait_for("the withdraw's note to reach every node", Duration::from_secs(60), || all.iter().all(|n| n.holds(&cm))).await;

    // The register lost the whole amount, and the base it paid is in the register still — as the
    // rewards of the proposer of the block that applied it, exactly where a bundle fee goes.
    // Nothing has paid a fee on this chain yet, so it is the only reward anyone holds.
    let row = register_row(&n0, &d).await.unwrap();
    assert!(row["pending"].as_array().unwrap().is_empty(), "the released amount left the register");
    assert_eq!(units(&row["rewards"]), 0, "and nothing was ever credited to D: no bundle has paid a fee here");
    let proposer = n0.handle.storage.block_by_height(paid_in.height).unwrap().unwrap().proposer();
    assert_eq!(units(&register_row(&n0, &proposer).await.unwrap()["rewards"]), base, "the base went to the proposer");

    // ---- the payout wallet finds the note by scanning, and spends it
    let paid = MIN_STAKE - base;
    for n in all {
        assert_eq!(balance(n, &payout).await, paid, "the note is worth the amount less the base");
    }
    let mut store = NoteStore::default();
    let pay = UNITS_PER_RAND;
    let slot = proving_slot().await;
    let sent =
        wallet::send(&n0.rpc, &payout, &mut store, &payee.address, pay, base, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
            .await
            .expect("the withdrawn note pays a real bundle");
    drop(slot);
    eprintln!("spending the withdrawn note: tier {}, proved in {:.1?}", sent.tier, sent.proving);
    // `wallet::send` waited for the commit on the node it submitted to, which leaves the others up to
    // a block behind: a balance read straight away can scan a tree the payee's note is not in yet.
    wait_for("the spend to reach every node", Duration::from_secs(60), || {
        all.iter().all(|n| n.handle.storage.tx_location(&sent.hash).unwrap().is_some())
    })
    .await;
    for n in all {
        assert_eq!(balance(n, &payee).await, pay, "1 RAND out of a note the chain created itself");
        assert_eq!(balance(n, &payout).await, paid - pay - base, "and the change is spendable too");
    }

    // The audit's two halves still add up: the withdraw moved value from the register into the
    // pool, and only what actually reached the pool — the note, not the base — is counted.
    let supply = supply_of(&n0).await;
    assert_eq!(units(&supply["withdraw_deposited"]), paid);
    assert_eq!(units(&supply["genesis_deposited"]), 0, "nothing was ever deposited at genesis here");
    assert_eq!(units(&supply["fees_paid"]), base, "the transfer's fee; the withdraw's base never left the pool");
    assert_eq!(units(&supply["burned"]), 0);
    assert!(supply["invariant_holds"].as_bool().unwrap(), "{supply}");
    assert_chains_equal(&all);
    eprintln!("unbond_below_min_stake_leaves_the_set_and_withdraw_pays_a_spendable_note in {:.1?}", started.elapsed());
}

// ---------------------------------------------------------------- the bridge, end to end
//
// One inbound deposit and one outbound burn across two validators. This is the only place the two
// bridge actions meet a real chain: a guardian-signed attestation turns into a note the chain
// computes itself, and a burn spends that note through two bundles in one transaction.

/// The relayer's half of `rand bridge-mint`, in the wallet helpers the command itself uses: read
/// the deposit out of the attestation bytes, resolve the index the note will carry against the
/// node's registry, stamp the note with a `time` inside the admission window, seal the recipient's
/// envelope against the commitment the *chain* will compute, and pay for all of it with a bundle of
/// the relayer's own RAND.
///
/// Returns the submission, the asset index and the deposit note's commitment — the last of which is
/// on no wire anywhere: the chain derives it from the amount the guardians signed, which is what
/// stops a relayer minting a note of its own choosing.
///
/// Takes the proving slot around its own bundle, so a caller must not already hold it.
async fn bridge_mint(
    node: &TestNode,
    relayer: &Wallet,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    attestation: Vec<u8>,
) -> (wallet::Submission, u32, Word8) {
    let d = wallet::attested_deposit(&attestation).expect("the attestation decodes to a transfer");
    assert_eq!(d.to_hash, to.recipient_hash(), "the guardians signed this recipient's hash");
    // The asset id from the node, over the two wire fields the guardians signed; a disagreement
    // would mean the two are not talking about the same chain.
    let asset_id = node.rpc.bridge_asset_id(d.token_chain, &d.token).await.expect("the node computes an asset id");
    assert_eq!(asset_id, d.asset.to_hex(), "and computes the same one this wallet did");
    let state = node.rpc.bridge_state().await.expect("bridge state");
    let assets = node.rpc.assets().await.expect("the registry");
    let index = wallet::deposit_index(&state, &assets, &asset_id).expect("the token is listed on this chain");
    let time = u32::try_from(node.rpc.head().await.expect("head")["height"].as_u64().expect("height")).unwrap();
    // The blinding is the attestation digest's (F1), derived inside `deposit_note_for`, so the
    // note this wallet seals against is the one the ledger will append whoever submits it.
    let (note, envelope) =
        wallet::deposit_note_for(relayer, to, &attestation, d.amount, index, time).expect("sealing the deposit");
    let pq_signatures = pq_quorum(&attestation);
    let action = Action::BridgeAttest {
        attestation,
        recipient: to.clone(),
        r: note.r,
        time,
        asset: index,
        envelope,
        pq_signatures,
    };
    let fee = gas::fee_floor(&action);
    let slot = proving_slot().await;
    let s = wallet::submit(&node.rpc, relayer, store, None, action, fee, Burn::None, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the attestation's fee bundle commits");
    drop(slot);
    (s, index, note.commitment())
}

/// A second transaction for the same attestation, as a relayer who has not noticed it was already
/// consumed would build it — except that its bundle carries junk where a proof goes.
///
/// Admission checks the action at step 7 and a bundle proof only at step 9 (spec §7,
/// `docs/shielded.md` §5), so everything before the action passes and the refusal that comes back
/// is the *attestation's*. That is what makes this a probe worth a second of test time rather than
/// a second bundle proof.
/// Widen two note words to a bundle's four slots (the two extra derived from them).
fn pad4(w: [[u32; 8]; 2]) -> [[u32; 8]; 4] {
    let tag = |x: [u32; 8], k: u32| {
        let mut y = x;
        y[7] ^= 0xd0d0_0000 | k;
        y
    };
    [w[0], w[1], tag(w[0], 2), tag(w[1], 3)]
}

async fn replayed_attest(node: &TestNode, to: &ShieldedAddress, attestation: Vec<u8>, asset: u32) -> Transaction {
    let (height, anchor) = node.rpc.anchor(None).await.expect("the head anchor");
    let time = u32::try_from(height).unwrap();
    let empty = Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] };
    let bundle = Bundle {
        anchor,
        nullifiers: pad4([[0x51; 8], [0x52; 8]]),
        commitments: pad4([[0x53; 8], [0x54; 8]]),
        fee: gas::BUNDLE_BASE,
        burn_a: 0,
        burn_r: 0,
        burn_asset: 0,
        time,
        envelopes: [empty.clone(), empty.clone(), empty.clone(), empty.clone()],
        proof: vec![0xff; 32],
    };
    // A full PQ quorum, so the refusal that comes back is the replay, not the co-signature's shape
    // (which `check_attest` checks first).
    let pq_signatures = pq_quorum(&attestation);
    // The derived blinding (F1), so the refusal that comes back is the replay and not the
    // blinding rule, which is checked before the digest's consumed set.
    let r = randprotocol_core::ledger::bridge_notes::deposit_r(&attestation).expect("the digest derives it");
    let action = Action::BridgeAttest {
        attestation,
        recipient: to.clone(),
        r,
        time,
        asset,
        envelope: empty,
        pq_signatures,
    };
    Transaction::shielded(CHAIN_ID, bundle, action)
}

/// Inbound and outbound across a two-validator bridged chain: an attestation deposits a note only
/// its recipient can open, the registry names the token on both nodes, the same attestation
/// resubmitted is refused, and a two-bundle burn spends the note and leaves an outbound message
/// every guardian reads identically.
///
/// Three bundle proofs (one for the attestation's fee bundle, two for the burn), so this is the
/// slowest test in this file; the burn's pair is also what sets [`PROVING`]'s lower bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn bridge_mint_deposits_a_note_and_a_burn_spends_it() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    // The relayer pays the fees and the recipient receives the deposit: two wallets, because a
    // relayer having no claim on what it relays is the property worth showing.
    let (relayer, recipient) = (wallet(60), wallet(61));
    let gen = genesis_bridge(&ks, &[&relayer, &recipient], Some(bridge_config()));
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(90)).await;

    // A bridged genesis names guardians, emitters and the tokens it will accept: the registry
    // holds the listed token at index 1 before any attestation arrives, which is the index the
    // deposit below carries.
    let state = n0.rpc.bridge_state().await.unwrap();
    assert_eq!(state["enabled"], true);
    assert_eq!(state["guardians"].as_array().unwrap().len(), 6);
    assert!(state.get("next_index").is_none(), "nothing left to predict: tokens are listed");
    assert_eq!(n0.rpc.assets().await.unwrap().len(), 1, "the genesis listing");

    // ---- inbound: one attestation, one deposit note ----
    let deposit = 5_000u64;
    let attested = attestation(&recipient.address, deposit as u128);
    let mut relayer_store = NoteStore::default();
    let (minted, index, cm) =
        bridge_mint(&n0, &relayer, &mut relayer_store, &recipient.address, attested.clone()).await;
    assert_eq!(index, 1, "the index the genesis listing gave the token");
    eprintln!("bridge-mint: tier {}, proved in {:.1?}, {} proof bytes", minted.tier, minted.proving, minted.proof_bytes);

    wait_for("the attestation reaches n1", Duration::from_secs(120), || {
        n1.handle.storage.tx_location(&minted.hash).unwrap().is_some()
    })
    .await;
    for n in [&n0, &n1] {
        assert!(n.holds(&cm), "the deposit note the chain computed is a leaf");
        assert_eq!(asset_balance(n, &recipient, index).await, deposit, "the recipient holds the deposit");
        assert_eq!(asset_balance(n, &relayer, index).await, 0, "and the relayer, who paid for it, holds none");
        assert_eq!(balance(n, &relayer).await, ALLOC - gas::BUNDLE_BASE, "the relayer paid one bundle base");
        assert_eq!(balance(n, &recipient).await, ALLOC, "the recipient paid nothing");
        // Both nodes hold the same listed token under the same index, and the deposit is its
        // whole supply.
        let rows = n.rpc.assets().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].index, rows[0].chain, rows[0].token.as_slice()), (index, TOKEN_CHAIN, &TOKEN[..]));
    }
    // The explorer's view of it: the amount and the asset decoded out of the attestation, and the
    // index the action named, which admission held to the registry's answer.
    let rendered = n0.rpc.call("rand_getTransaction", serde_json::json!([minted.hash.to_hex()])).await.unwrap();
    let action = &rendered["tx"]["action"];
    assert_eq!(action["kind"], "bridge_attest");
    // Every u64 amount the RPC serves is a decimal string since chain 14 (node I3).
    assert_eq!(units(&action["amount"]), deposit);
    assert_eq!(action["asset"], index, "the index the action named");
    assert_eq!(action["asset_index"], index, "and the one the registry resolves, which admission held it to");

    // ---- the same attestation again: one digest, one deposit ----
    let replay = replayed_attest(&n0, &recipient.address, attested, index).await;
    let err = n0.rpc.send_transaction(&replay).await.unwrap_err().to_string();
    assert!(err.contains("already consumed"), "a replayed attestation must be refused as consumed: {err}");

    // ---- outbound: the recipient burns part of it, through two bundles in one transaction ----
    let (burn, relayer_fee) = (2_000u64, 100u64);
    let burn_fee = wallet::burn_fee_default();
    // Pinned here rather than taken on trust from the wallet: the floor this transaction has to
    // clear is the bridge's burn fee, which covers the bundle base for each of the two bundles a
    // node verifies (spec §7 item 3). The balance assertion below would hold against a wrong default.
    assert_eq!(burn_fee, gas::BRIDGE_BURN_FEE);
    let mut recipient_store = NoteStore::default();
    // A burn proves twice under one anchor, which is the longest single hold of the slot there is.
    let slot = proving_slot().await;
    let burned = wallet::submit_burn(
        &n0.rpc,
        &recipient,
        &mut recipient_store,
        index,
        burn,
        relayer_fee,
        TOKEN_CHAIN,
        // The coin being redeemed: this chain's one listed token has one backing, and a burn
        // names it (spec §12).
        TOKEN,
        EVM_TO,
        burn_fee,
        FriProfile::Test,
        Backend::Cpu,
        CHAIN_ID,
        true,
    )
    .await
    .expect("both of the burn's bundles commit");
    drop(slot);
    eprintln!("bridge-burn: tier {}, proved in {:.1?}, {} proof bytes", burned.tier, burned.proving, burned.proof_bytes);
    assert_eq!(burned.amount, burn, "what left the pool is exactly what the message sends");
    assert_eq!(burned.change, deposit - burn);
    assert_eq!(burned.asset, index);

    wait_for("the burn reaches n1", Duration::from_secs(120), || {
        n1.handle.storage.tx_location(&burned.hash).unwrap().is_some()
    })
    .await;
    for n in [&n0, &n1] {
        assert_eq!(
            asset_balance(n, &recipient, index).await,
            deposit - burn,
            "the change note is what is left of the deposit"
        );
        assert_eq!(balance(n, &recipient).await, ALLOC - burn_fee, "the fee bundle paid two bundle bases in RAND");
        // The outbound message, which is the whole point of a burn: guardians sign this digest.
        let msg = n.rpc.bridge_burn(0).await.unwrap().expect("the burn emitted a message");
        assert_eq!(msg["sequence"], 0);
        assert_eq!(msg["tx"], burned.hash.to_hex(), "the transaction hash stands in for the absent sender");
        assert_eq!(msg["digest"].as_str().unwrap().len(), 64);
        // What the message sends is exactly what the pool destroyed, with the relayer's cut a
        // portion of it: the far side releases `amount - fee` to `to` and `fee` to the relayer,
        // so a pool that burned `amount + fee` would strand the difference on the source chain.
        let body_bytes = hex::decode(msg["body_hex"].as_str().expect("body_hex is hex")).expect("body_hex decodes");
        let body = Body::decode(&body_bytes).expect("the outbound body decodes");
        let Ok(Payload::Transfer(sent)) = Payload::decode(&body.payload) else { panic!("a transfer payload") };
        assert_eq!(sent.amount_u128(), Some(burn as u128), "the message sends exactly what was burned");
        assert_eq!(sent.fee_u128(), Some(relayer_fee as u128), "and the relayer fee is a portion of it");
        assert_eq!(n.rpc.bridge_burn(1).await.unwrap(), None, "and only the one");
    }
    assert_chains_equal(&[&n0, &n1]);
    eprintln!("bridge_mint_deposits_a_note_and_a_burn_spends_it in {:.1?}", started.elapsed());
}

/// The call-input envelope end to end (spec §6.1). A call's private inputs are published as one
/// sealed transcript, and exactly three keys open it: the caller's outgoing viewing key, the
/// per-call key, and the viewing key of the auditor named when it was sealed. Every node serves the
/// ciphertext to anyone who asks and none of them holds a key to it.
///
/// What the chain guarantees is only the binding: the transcript's AEAD is bound to the `H_IN` the
/// proof published, and a holder who decrypts checks that it hashes back to that `H_IN`. Both
/// halves are asserted here, against the bytes a *node* served rather than the ones sealed locally.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_call_envelope_is_opened_by_the_caller_and_the_auditor_only() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(2);
    let (caller, auditor, stranger) = (wallet(70), wallet(71), wallet(72));
    let gen = genesis_funding(&ks, &[&caller]);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(60)).await;

    let program = randprotocol_zkvm::guests::private_payment(1_000);
    let id = randprotocol_core::program::program_id(program.base_pc, &program.words);
    let mut store = NoteStore::default();
    let deploy = Action::Deploy { base_pc: program.base_pc, words: program.words.clone(), public: vec![] };
    let deploy_fee = wallet::deploy_fee_default(&deploy);
    let slot = proving_slot().await;
    wallet::submit(&n0.rpc, &caller, &mut store, None, deploy, deploy_fee, Burn::None, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the deploy bundle commits");
    drop(slot);

    // `prove_call` is `prove` plus the salt the input commitment was drawn with — the one value
    // that never leaves the prover on its own, and the thing the transcript is sealed around.
    let inputs = [400u32, 250, 300, 75];
    let slot = proving_slot().await;
    let (proof, outputs, tier, salt) =
        randprotocol_zkvm::executor::prove_call(
            FriProfile::Test,
            &program,
            &inputs,
            &[],
            None,
            Backend::Cpu,
            call_envelope::FALLBACK_MAX_CALL_INPUT_WORDS,
        )
        .expect("the call proves");
    let h_in = hash::input_digest(salt, &inputs);
    let (sealed, key) = call_envelope::seal_call_envelope(&caller.vk, Some(&auditor.address), &h_in, salt, &inputs, call_envelope::CallCaps::FALLBACK)
        .expect("sealing the transcript");
    let fee = wallet::call_fee_default(tier, randprotocol_core::gas::call_bytes(&proof, Some(&sealed)));
    let called = wallet::submit(
        &n0.rpc,
        &caller,
        &mut store,
        None,
        Action::Call { program: id, proof, input_envelope: Some(sealed.clone()) },
        fee,
        Burn::None,
        FriProfile::Test,
        Backend::Cpu,
        CHAIN_ID,
        true,
    )
    .await
    .expect("the call bundle commits");
    drop(slot);
    eprintln!("call: tier {tier}, envelope {} bytes, outputs {outputs:?}", sealed.len());

    for n in [&n0, &n1] {
        wait_for("the receipt reaches every node", Duration::from_secs(90), || {
            n.handle.storage.receipt(&called.hash).unwrap().is_some()
        })
        .await;
        let (served_h_in, served) =
            n.rpc.call_envelope(&called.hash).await.unwrap().expect("the node serves the transcript");
        assert_eq!(served_h_in, h_in, "served against the H_IN the proof published");
        assert_eq!(served, sealed, "and verbatim: a node holds no key to any part of it");
        let receipt = n.rpc.receipt(&called.hash).await.unwrap().expect("a receipt");
        assert_eq!(receipt["h_in"].as_str().unwrap(), word8_to_hex(&h_in));
        assert_eq!(receipt["tier"], tier);

        // The caller, through the outgoing viewing key that opens every call this wallet made.
        let (as_caller, salt_back, inputs_back) =
            call_envelope::open_call_as_sender(&served, &served_h_in, &caller.vk).expect("the caller opens it");
        assert_eq!(salt_back, salt);
        assert_eq!(inputs_back, inputs.to_vec(), "the words the guest was fed, off the chain");
        assert_eq!(as_caller, key, "and the very per-call key it was sealed under");
        // The auditor it was addressed to, through a different path entirely: ML-KEM against that
        // address's encapsulation key, not the caller's `ovk`.
        let (as_auditor, _, audited) =
            call_envelope::open_call_as_auditor(&served, &served_h_in, &auditor.vk).expect("the auditor opens it");
        assert_eq!((as_auditor, audited), (key, inputs_back.clone()));
        // A third wallet — neither the caller nor the auditor — is served the same bytes and gets
        // nothing out of either path.
        assert!(call_envelope::open_call_as_sender(&served, &served_h_in, &stranger.vk).is_none());
        assert!(call_envelope::open_call_as_auditor(&served, &served_h_in, &stranger.vk).is_none());
        // Nor do the two named parties open each other's part: the wrapped key is a different
        // ciphertext under different associated data in each.
        assert!(call_envelope::open_call_as_sender(&served, &served_h_in, &auditor.vk).is_none());
        assert!(call_envelope::open_call_as_auditor(&served, &served_h_in, &caller.vk).is_none());
        // The per-call key alone opens this one call — the grain of disclosure that hands over no
        // history.
        assert_eq!(call_envelope::open_call_with_key(&served, &served_h_in, &key), Some((salt, inputs.to_vec())));

        // Faithfulness is the holder's own recomputation, not something the chain checked: the
        // transcript hashes back to the receipt's H_IN, and a transcript with one word changed
        // does not — which is how a caller who published a lie is caught, by whoever decrypts.
        assert!(call_envelope::call_envelope_is_faithful(&served_h_in, salt_back, &inputs_back));
        let mut tampered = inputs_back.clone();
        tampered[0] += 1;
        assert!(!call_envelope::call_envelope_is_faithful(&served_h_in, salt_back, &tampered));
        // And the ciphertext is bound to that H_IN by the AEAD: a flipped byte opens for nobody,
        // and neither does the real envelope read against another call's H_IN.
        let mut bent = served.clone();
        *bent.body.last_mut().unwrap() ^= 1;
        assert!(call_envelope::open_call_as_sender(&bent, &served_h_in, &caller.vk).is_none());
        let other_h_in = hash::input_digest(salt, &tampered);
        assert!(call_envelope::open_call_with_key(&served, &other_h_in, &key).is_none());
    }

    // The transcript is voluntary — a call built with `--no-envelope` publishes none and the node
    // serves `null` for it — which costs a proof to show here and is already pinned against a
    // committed block in `rpc.rs`'s `get_call_envelope_serves_the_sealed_transcript_of_a_call`.
    assert_chains_equal(&[&n0, &n1]);
    eprintln!("a_call_envelope_is_opened_by_the_caller_and_the_auditor_only in {:.1?}", started.elapsed());
}

// ── block aggregation, end to end (spec §7): one rVM verification per sealed window ──────────

/// The sealed-sync capstone (spec §7's acceptance, live): a gated chain registers an
/// aggregator, its bond bundle is covered by a real aggregate (the proving slot's one rVM
/// proof at the test profile), the seal lands, the pruning pass rewrites the record — and a
/// fresh joiner syncs the pruned block in sealed form, reaching the same blocks and the same
/// state root with exactly **one** rVM verification for the whole sealed window (the covering
/// aggregate's), where a raw sync would have re-verified the bundle itself.
///
/// **Ignored since the hidden-asset bundle (node I2).** It sets `gen.aggregation`, and
/// `node::check_build_runs_genesis` bails on any such genesis at `start_node_at` — within
/// seconds, before any proving — until the admitted shapes and the recursion fixtures are
/// re-measured for the new bundle guest. Left red it would take the whole cluster binary with
/// it, hiding a real regression among its other tests. Un-ignore with that work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "aggregation is refused at startup on the hidden-asset bundle until its admitted shape is re-measured (b053a76)"]
async fn a_fresh_node_syncs_pruned_history_with_one_rvm_verify_per_sealed_window() {
    init_tracing();
    let started = Instant::now();
    let ks = keys(4);
    // ks[0]/ks[1] validate, ks[2] aggregates, ks[3] is the fresh observer (its own peer id —
    // reusing a live validator's key would collide its libp2p identity and the join would
    // silently never connect).
    let (a, aggregator) = (wallet(1), &ks[2]);

    // The gated genesis: the test-profile bundle shape admitted — the fleet's own measured
    // classes for a 2-in/2-out bundle, NOT the recursion fixtures' (which over-declare at
    // 13/12/18; asserted live against the committed bundle's header below, since an admitted
    // shape the fleet does not declare is one no aggregate can ever cover) — the bundle
    // guest's digest as the admitted hc, the real aggregate program digest computed up front,
    // and a short window so the prune pass fires inside the test.
    let shape = randprotocol_core::types::DeclaredShape {
        profile: randprotocol_core::types::FriProfile::Test,
        tier: 14,
        program_log_height: 12,
        input_log_height: 10,
        keccak_log_height: 0,
        sha256_log_height: 0,
        public_log_height: 2,
        mem_log_height: 16,
    };
    let hc = Hash(randprotocol_core::notes::word8_to_bytes(&ZkExecutor::hc_bundle()));
    let program_digest = randprotocol_node::agg_executor::AggExecutor::new(FriProfile::Test)
        .aggregate_program_digest(&shape)
        .expect("the shape builds");
    let cfg = randprotocol_core::ledger::aggregation::AggregationConfig {
        bond: 100 * UNITS_PER_RAND,
        max_covers: 3,
        subsidy_base: 100 * UNITS_PER_RAND,
        halving_blocks: 210_000,
        // 32, not 8: the window is a block-validity rule since H1 (the ledger's coverable set),
        // so the aggregate must land inside it. Resuming after the prove takes a view change or
        // two, and 8 blocks (24 s) sealed on the last admissible block once and missed it once;
        // 32 keeps the prune pass (every 16 blocks, gated at sealed_at + window) inside the wait.
        window: 32,
        admitted_shapes: vec![randprotocol_core::ledger::aggregation::AdmittedShape {
            shape,
            hc,
            aggregate_program_digest: program_digest,
        }],
    };
    let mut gen = genesis_funding(&ks[..2], &[&a]);
    gen.aggregation = Some(cfg.clone());

    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let n1 = start_node_at(&ks[1], &gen, vec![bootstrap_addr(&n0)], true, PROVING).await;
    wait_height(&[&n0, &n1], 2, Duration::from_secs(60)).await;

    // The registration, a wallet submission with a bond-burning bundle (excess 7 over the
    // floor, so the aggregate's payment is the subsidy plus a proving share).
    let payout = ShieldedAddress { pk: [7; 8], kem_ek: vec![8; randprotocol_core::notes::KEM_EK_BYTES] };
    let registration = randprotocol_core::types::actions::AggregatorRegistration {
        public_key: aggregator.public_key().clone(),
        payout: payout.clone(),
        signature: aggregator.sign(
            randprotocol_core::types::actions::aggregator_register_message(CHAIN_ID, &payout).as_bytes(),
        ),
    };
    let mut store = NoteStore::default();
    let register = {
        let slot = proving_slot().await;
        let sent = wallet::submit(
            &n0.rpc,
            &a,
            &mut store,
            None,
            Action::RegisterAggregator { registration },
            gas::BUNDLE_BASE + 7,
            wallet::Burn::Rand(cfg.bond),
            FriProfile::Test,
            Backend::Cpu,
            CHAIN_ID,
            true,
        )
        .await
        .expect("the registration is accepted and commits");
        drop(slot);
        sent
    };
    eprintln!("register: proved in {:.1?} ({:.1?} in)", register.proving, started.elapsed());

    // The committed bundle and its proof, read back: its declared heights must be the admitted
    // shape's, or the aggregate's admission refuses at step 6 — check that here, loudly.
    let (h_reg, i_reg) = n0.handle.storage.tx_location(&register.hash).unwrap().unwrap();
    let register_block = n0.handle.storage.block_by_height(h_reg).unwrap().unwrap();
    let register_tx = register_block.transactions[i_reg as usize].clone();
    let proof: randprotocol_zkvm::machine::Proof =
        postcard::from_bytes(&register_tx.bundle.as_ref().unwrap().proof).expect("the stored proof decodes");
    let declared = randprotocol_core::types::DeclaredShape {
        profile: randprotocol_core::types::FriProfile::Test,
        tier: proof.tier.0 as u8,
        program_log_height: proof.program_log_height,
        input_log_height: proof.input_log_height,
        keccak_log_height: proof.keccak_log_height,
        sha256_log_height: proof.sha256_log_height,
        public_log_height: proof.public_log_height,
        mem_log_height: proof.mem_log_height,
    };
    assert_eq!(declared, shape, "the committed bundle's declared shape is the admitted shape");

    // Halt the chain for the prove: with n1 down the window cannot scroll past the covered
    // bundle no matter how long the rVM prove takes.
    let dir1 = stop(n1).await;

    // The aggregate: one rVM proof over the register bundle's proof, through the proving slot.
    let aggregate_proof = {
        let slot = proving_slot().await;
        let shape_inner = randprotocol_rvm::shape::InnerShape::of(
            FriProfile::Test,
            proof.tier,
            proof.program_log_height,
            proof.input_log_height,
            proof.keccak_log_height,
            proof.sha256_log_height,
            proof.public_log_height,
            proof.mem_log_height,
        );
        let key_inner = randprotocol_rvm::shape::InnerKey::of(FriProfile::Test, &shape_inner);
        let vk = randprotocol_rvm::aggregate::InnerVerifierKey { shape: shape_inner, key: key_inner };
        let m = randprotocol_rvm::machine::Machine::new(FriProfile::Test);
        let t0 = Instant::now();
        let a = randprotocol_rvm::aggregate::aggregate(&m, &vk, std::slice::from_ref(&proof), None)
            .expect("one real bundle proof aggregates");
        eprintln!(
            "aggregate: tier {}, {} proof bytes, proved in {:.1?} ({:.1?} in)",
            a.proof.tier.0,
            a.proof.to_bytes().len(),
            t0.elapsed(),
            started.elapsed()
        );
        drop(slot);
        a
    };

    // The chain resumes, and the aggregate is submitted: admitted (its own rVM verification at
    // the node), pooled, selected, committed — the sealing block. Wait for consensus to be
    // alive again first: the prove halted the chain for minutes of wall time, and the replicas'
    // view timeouts had escalated to their cap while it was down — convergence takes a view
    // change or two at that cap, so a bare 120 s commit window right after the restart is not a
    // margin, it is the stall itself.
    let n1 = start_in_at(dir1, &ks[1], vec![bootstrap_addr(&n0)], true, PROVING).await;
    let resumed_at = n0.height();
    wait_height(&[&n0, &n1], resumed_at + 2, Duration::from_secs(600)).await;
    eprintln!("chain resumed at {} ({:.1?} in)", n0.height(), started.elapsed());
    let head = n0.height();
    let aggregate_tx = {
        let r = [9u32; 8];
        let covers = vec![register.hash];
        let proof_bytes = aggregate_proof.proof.to_bytes();
        let time = head as u32 + 1;
        let signature = aggregator.sign(
            randprotocol_core::types::actions::aggregate_signing_hash(CHAIN_ID, 0, time, &r, &covers, &Hash::digest(&proof_bytes))
                .as_bytes(),
        );
        Transaction {
            chain_id: CHAIN_ID,
            bundle: None,
            action: Action::Aggregate {
                covers,
                proof: proof_bytes,
                aggregator: aggregator.public_key().address(),
                nonce: 0,
                time,
                r,
                envelope: Envelope { kem_ct: vec![1; 8], to_receiver: vec![2; 4], to_sender: vec![3; 4], body: vec![4; 16] },
                signature,
            },
        }
    };
    let agg_hash = n0.rpc.send_transaction(&aggregate_tx).await.expect("the aggregate is admitted");
    assert_eq!(agg_hash, aggregate_tx.hash());
    n0.rpc.wait_for_transaction(&agg_hash, Duration::from_secs(300)).await.expect("the aggregate commits");
    let (h_seal, _) = n0.handle.storage.tx_location(&agg_hash).unwrap().unwrap();
    eprintln!("sealed at block {h_seal} ({:.1?} in)", started.elapsed());
    assert_eq!(
        n0.handle.storage.sealed_by(&register.hash).unwrap(),
        Some((agg_hash, h_seal)),
        "the covered bundle carries the seal"
    );

    // The prune pass: it runs every 16 blocks on a gated chain, gated at sealed_at + window.
    wait_for(
        "the covered bundle's record is pruned",
        Duration::from_secs(300),
        || matches!(n0.handle.storage.tx_record(&register.hash).unwrap().unwrap(), randprotocol_node::storage::TxRecord::Pruned { .. }),
    )
    .await;

    // The fresh joiner: syncs the whole chain, the pruned block in sealed form. The
    // verification counter scopes to this sync alone.
    let verifications_before = randprotocol_node::agg_executor::AggExecutor::verification_count();
    let n2 = start_node(&ks[3], &gen, vec![bootstrap_addr(&n0)], false).await;
    let target = n0.height();
    // The sealed sync, with its failure modes printed: a batch rejection shows in
    // `sync_failures`, a raw-form fallback in the log's own line, and a stall in neither.
    let t0 = Instant::now();
    while n2.height() < target {
        let st = n2.handle.status.read().unwrap().clone();
        assert!(
            t0.elapsed() < Duration::from_secs(300),
            "n2 never reached {target}: height {height}, syncing {}, sync_inflight_age_ms {:?}, sync_target {}, connected_peers {}/{}, sync_failures {}",
            st.syncing,
            st.sync_inflight_age_ms,
            st.sync_target,
            st.connected_peers,
            st.peer_count,
            st.sync_failures,
            height = n2.height(),
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let verifications_after = randprotocol_node::agg_executor::AggExecutor::verification_count();

    for h in 0..=target {
        let b2 = n2.handle.storage.block_by_height(h).unwrap().unwrap();
        let b0 = n0.handle.storage.block_by_height(h).unwrap().unwrap();
        assert_eq!(b2.hash(), b0.hash(), "block hash differs at {h}");
        assert_eq!(b2.header.state_root, b0.header.state_root, "state root differs at {h}");
    }
    assert_eq!(
        verifications_after - verifications_before,
        1,
        "one rVM verification for the whole sealed window — the covering aggregate's"
    );
    assert_eq!(
        n2.handle.storage.sealed_by(&register.hash).unwrap(),
        Some((agg_hash, h_seal)),
        "the joiner marked the seal itself"
    );
    let supply = n2.rpc.call("rand_getSupply", json!([])).await.unwrap();
    assert_eq!(supply["invariant_holds"], true, "{supply}");
    assert_eq!(supply["sealed_blocks"], Value::String("1".into()), "{supply}");
    assert_eq!(
        supply["subsidised"],
        Value::String(cfg.subsidy_base.to_string()),
        "one subsidy minted: {supply}"
    );

    eprintln!(
        "sealed-sync capstone done in {:.1?}: register + aggregate prove + seal + prune + resync",
        started.elapsed()
    );
    n2.handle.shutdown().await;
    n0.handle.shutdown().await;
    n1.handle.shutdown().await;
}

/// Audit v3, CON-1a: a peer serving a *certified* chain cannot make a syncing node finalise it.
///
/// Blocks are certified and then abandoned at every view change, so a QC per block — all the sync
/// path used to check — is not evidence of a commit. Here a peer's database is seeded by hand with
/// a chain whose views are 1, 3 and 5: every block carries a real quorum certificate signed by the
/// chain's only validator, and no three of them sit in consecutive views, so the three-chain rule
/// commits none of them. The syncing node must stay at genesis rather than take the peer's word.
///
/// Before the fix it committed all three and served them as final.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_synced_certified_but_uncommitted_chain_is_not_committed() {
    use randprotocol_core::consensus::CommittedBlock;
    use randprotocol_core::{Block, BlockHeader, QuorumCertificate, Vote};
    use randprotocol_node::storage::Storage;

    let v = Keypair::from_seed([61; 32]).unwrap();
    let gen = genesis(std::slice::from_ref(&v));
    let gs = gen.build(&ZkExecutor::new(FriProfile::Test)).expect("genesis builds");

    // The peer's database: genesis, then three certified blocks at views 1, 3 and 5.
    let liar_dir = tempfile::tempdir().unwrap();
    std::fs::write(liar_dir.path().join("genesis.json"), gen.to_json()).unwrap();
    {
        let s = Storage::open(liar_dir.path()).unwrap();
        s.init_genesis(&gs).unwrap();
        let mut ledger = gs.ledger.clone();
        let mut parent = gs.block.clone();
        let mut parent_view = 0u64;
        let mut chain: Vec<CommittedBlock> = Vec::new();
        for view in [1u64, 3, 5] {
            let height = parent.height() + 1;
            ledger.set_height(height);
            ledger.set_timestamp_ms(height);
            ledger.record_anchor(height);
            let header = BlockHeader {
                height,
                view,
                parent: parent.hash(),
                proposer: v.public_key().clone(),
                timestamp_ms: height,
                tx_root: Block::tx_root(&[]),
                state_root: ledger.state_root(),
                justify: QuorumCertificate {
                    view: parent_view,
                    block_hash: parent.hash(),
                    votes: if parent_view == 0 {
                        vec![]
                    } else {
                        vec![Vote::sign(parent_view, parent.hash(), &v)]
                    },
                },
            };
            let block = Block::sign(header, vec![], &v);
            let qc = QuorumCertificate {
                view,
                block_hash: block.hash(),
                votes: vec![Vote::sign(view, block.hash(), &v)],
            };
            parent = block.clone();
            parent_view = view;
            chain.push(CommittedBlock { block, pruned: vec![], qc, receipts: vec![], deposits: vec![] });
        }
        s.commit(&chain, &ledger, &[], &ZkExecutor::new(FriProfile::Test)).unwrap();
        assert_eq!(s.head().unwrap().height, 3, "the peer serves a chain of three certified blocks");
    }

    // The peer is an observer: it serves its stored chain and proposes nothing.
    let liar = start_in(liar_dir, &Keypair::from_seed([62; 32]).unwrap(), vec![], false).await;
    let target = liar.handle.listen_addrs[0]
        .clone()
        .with(libp2p::multiaddr::Protocol::P2p(liar.handle.network.local_peer_id));
    // A fresh node that knows only this peer, and is not a validator, so nothing but the sync can
    // move its committed head.
    let victim = start_node(&Keypair::from_seed([63; 32]).unwrap(), &gen, vec![target], false).await;

    // Long enough for several sync rounds against a peer claiming height 3.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let height = victim.handle.status.read().unwrap().height;
    assert_eq!(height, 0, "a certified but uncommitted chain was committed by sync");

    victim.handle.shutdown().await;
    liar.handle.shutdown().await;
}
