//! The zUSD gate (v0.5): a bridged stablecoin end to end on a real four-validator cluster, with
//! real bundle proofs and test bridge guardians.
//!
//! One test, nine phases, in the order the user stated the goal:
//!
//! 1. the faucet funds a deployer, a relayer and three wallets A, B, C with RAND;
//! 2. zUSD is deployed **by transaction** — `RegisterBridgedToken` (chain 2 USDT, 6 decimals)
//!    under a PQ guardian quorum, then `ListBacking` for chain 2 USDC and chain 5 USDT;
//! 3. guardian-signed deposits of chain 2 USDT to A (its envelope deliberately garbage) and chain 2
//!    USDC to B both mint zUSD; a replay of either is refused;
//! 4. A → B → C zUSD transfers as hidden-asset bundles, balances asserted at every step;
//! 5. C burns zUSD into chain 2 USDC; a redirected copy of that burn (same proof, `to` swapped) is
//!    refused by the bundle proof while the original commits;
//! 6. every refusal: `InsufficientBacking`, `NotReleasable`, `MintCapExceeded`, `MintsPaused`
//!    (while a burn still succeeds), an unpause by the pause key alone, and the PQ-quorum unpause;
//! 7. the supply audit: `total_supply == Σ locked == deposits − burns`, per backing;
//! 8. disclosure: a transaction key opens C's incoming transfer, B's imported viewing key shows its
//!    zUSD notes and their spent state;
//! 9. a validator stopped before phase 5 and restarted after phase 6 rejoins and agrees on every
//!    state root and on `rand_getTokenSupply`.
//!
//! Every proof is taken under the workspace proving slot. Refusals that the ledger decides before
//! any proof (spec §7 step 7, ahead of steps 8–9) are probed with a junk-proof bundle, so they cost
//! an RPC round trip rather than a proof — and each is checked to leave the ledger unchanged.
//!
//! Run it alone, in release: `cargo test --release -p randprotocol-node --test zusd_e2e -- --nocapture`.

use axum::extract::State;
use axum::routing::post;
use randprotocol_client::governance::{self, GovState};
use randprotocol_client::wallet::{self, NoteStore, Submission, Wallet};
use randprotocol_client::RpcClient;
use randprotocol_core::bridge::gov::{list_message, register_message, unpause_message};
use randprotocol_core::bridge::{Body, BridgeError, Payload, PqSignature, CHAIN_RAND};
use randprotocol_core::genesis::{Genesis, GenesisValidator, TokensConfig};
use randprotocol_core::ledger::staking::MIN_STAKE;
use randprotocol_core::ledger::tokens::{bridged_asset_id, TokenError};
use randprotocol_core::ledger::TxError;
use randprotocol_core::notes::{word8_to_hex, Bundle, Envelope, ShieldedAddress};
use randprotocol_core::{gas, Action, Transaction, UNITS_PER_RAND};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::{Backend, FriProfile};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod proving_slot;
use proving_slot::proving_slot;
mod common;
use common::bridge::{bridge_config_for, pause_keypair, pq_quorum, pq_quorum_message, transfer_attestation};
use common::cluster::*;

const CHAIN_ID: u64 = 7;

/// One zUSD: a bridged token has eight decimals on Rand whatever its backings have at home.
const ZUSD: u64 = 100_000_000;

/// The daily mint cap per backing — small enough that a test deposit can pass it.
const MINT_CAP: u64 = 10_000 * ZUSD;

/// What a `RegisterBridgedToken` owes on top of the bundle base.
const REGISTRATION_FEE: u64 = UNITS_PER_RAND;

/// What the faucet gives each wallet: its per-mint cap.
const FAUCET: u64 = 100 * UNITS_PER_RAND;

/// Rand's own outbound emitter, the `bridge.emitter` every burn message must carry.
const RAND_EMITTER: [u8; 32] = [1; 32];

/// The release unit of a six-decimal source coin, in eight-decimal zUSD units.
const UNIT6: u64 = 100;

fn h32(s: &str) -> [u8; 32] {
    randprotocol_client::hex32(s).unwrap()
}
/// Chain 2 (Ethereum) USDT and USDC and chain 5 (Solana) USDT — the mainnet wire addresses.
fn usdt2() -> [u8; 32] {
    h32("000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7")
}
fn usdc2() -> [u8; 32] {
    h32("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
}
fn usdt5() -> [u8; 32] {
    h32("ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264")
}

/// An EVM burn destination: twelve zero bytes then twenty address bytes.
const fn evm_to(b: u8) -> [u8; 32] {
    let mut t = [0u8; 32];
    let mut i = 12;
    while i < 32 {
        t[i] = b;
        i += 1;
    }
    t
}

/// The chain: four validators, a bridge with the test guardians, chains 2 and 5 registered as
/// source emitters, a pause key, a token registry with **no listed token**, the faucet on, no
/// aggregation.
fn zusd_genesis(validators: &[randprotocol_core::Keypair]) -> Genesis {
    Genesis {
        chain_id: CHAIN_ID,
        timestamp_ms: 0,
        validators: validators
            .iter()
            .enumerate()
            .map(|(i, k)| GenesisValidator {
                public_key: k.public_key().clone(),
                stake: MIN_STAKE as u128,
                payout: ShieldedAddress { pk: [i as u32 + 1; 8], kem_ek: vec![i as u8 + 1; randprotocol_core::notes::KEM_EK_BYTES] }
                    .to_string(),
            })
            .collect(),
        alloc: vec![],
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
        bridge: Some(bridge_config_for(RAND_EMITTER, &[2, 5])),
        tokens: Some(TokensConfig { registration_fee: REGISTRATION_FEE, mint_cap_per_day: MINT_CAP, tokens: vec![] }),
        aggregation: None,
        consensus_domain: None,
        epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
        max_program_words: None,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words: None,
        staking: None,
    }
}

// ---------------------------------------------------------------- timing

struct Phases {
    started: Instant,
    rows: Vec<(String, Duration)>,
}

impl Phases {
    fn done(&mut self, name: &str, since: Instant) {
        let d = since.elapsed();
        eprintln!("ZUSD-E2E PHASE {name}: PASS in {d:.1?} (total {:.1?})", self.started.elapsed());
        self.rows.push((name.to_string(), d));
    }
}

// ---------------------------------------------------------------- chain reads

async fn token_supply(n: &TestNode, index: u32) -> Value {
    n.rpc.call("rand_getTokenSupply", json!([index])).await.expect("getTokenSupply answers")
}

/// `locked` of one backing, from `rand_getTokenSupply`.
fn locked_of(supply: &Value, chain: u16, token: &[u8; 32]) -> u64 {
    backing_row(supply, chain, token)["locked"].as_str().unwrap().parse().unwrap()
}

fn backing_row<'a>(supply: &'a Value, chain: u16, token: &[u8; 32]) -> &'a Value {
    supply["backings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["chain"] == chain && b["token"] == hex::encode(token))
        .unwrap_or_else(|| panic!("no backing chain {chain} {} in {supply}", hex::encode(token)))
}

fn total_of(supply: &Value) -> u64 {
    supply["total_supply"].as_str().unwrap().parse().unwrap()
}

/// Everything a refused transaction must leave alone: the token's supply and backings, the whole
/// bridge state, and the RAND supply audit (its `height` aside).
async fn ledger_snapshot(n: &TestNode, index: u32) -> Value {
    let mut supply = supply_of(n).await;
    supply.as_object_mut().unwrap().remove("height");
    json!({ "token": token_supply(n, index).await, "bridge": n.rpc.bridge_state().await.unwrap(), "rand": supply })
}

/// Submit a transaction the ledger must refuse, assert the refusal names `want`, and that the
/// ledger is unchanged a few blocks later and the transaction never committed.
async fn assert_refused(n: &TestNode, index: u32, tx: &Transaction, want: &str) -> String {
    let before = ledger_snapshot(n, index).await;
    let err = n.rpc.send_transaction(tx).await.expect_err("the ledger must refuse this").to_string();
    assert!(err.contains(want), "expected a refusal containing {want:?}, got {err:?}");
    let h = n.height();
    wait_for("two more blocks", Duration::from_secs(60), || n.height() >= h + 2).await;
    assert!(n.handle.storage.tx_location(&tx.hash()).unwrap().is_none(), "a refused transaction never commits");
    assert_eq!(ledger_snapshot(n, index).await, before, "a refused transaction leaves the ledger unchanged");
    err
}

/// Widen two note words to a bundle's four slots.
fn pad4(w: [[u32; 8]; 2]) -> [[u32; 8]; 4] {
    let tag = |x: [u32; 8], k: u32| {
        let mut y = x;
        y[7] ^= 0xd0d0_0000 | k;
        y
    };
    [w[0], w[1], tag(w[0], 2), tag(w[1], 3)]
}

fn empty_envelope() -> Envelope {
    Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] }
}

/// A bundle whose proof is junk, on a live anchor and time: everything before step 8 of admission
/// passes, so the refusal that comes back is the action's.
async fn junk_bundle(n: &TestNode, fee: u64, burn_asset: u32, burn_a: u64, seed: u32) -> (Bundle, u32) {
    let (height, anchor) = n.rpc.anchor(None).await.expect("the head anchor");
    let time = u32::try_from(height).unwrap();
    let e = empty_envelope();
    let bundle = Bundle {
        anchor,
        nullifiers: pad4([[0x5100 + seed; 8], [0x5200 + seed; 8]]),
        commitments: pad4([[0x5300 + seed; 8], [0x5400 + seed; 8]]),
        fee,
        burn_a,
        burn_r: 0,
        burn_asset,
        time,
        envelopes: [e.clone(), e.clone(), e.clone(), e],
        proof: vec![0xff; 32],
    };
    (bundle, time)
}

/// A `BridgeAttest` of `attestation` to `to` on a junk-proof bundle, with a full PQ quorum.
async fn junk_attest(n: &TestNode, to: &ShieldedAddress, attestation: Vec<u8>, asset: u32, seed: u32) -> Transaction {
    let (bundle, time) = junk_bundle(n, gas::BUNDLE_BASE, 0, 0, seed).await;
    let pq_signatures = pq_quorum(CHAIN_ID, &attestation);
    // The blinding the attestation's digest derives (F1): the one the ledger admits, so what this
    // probe is refused for is the rule it is probing and not its `r`.
    let r = randprotocol_core::ledger::bridge_notes::deposit_r(&attestation).expect("the digest derives it");
    let action =
        Action::BridgeAttest { attestation, recipient: to.clone(), r, time, asset, envelope: empty_envelope(), pq_signatures };
    Transaction::shielded(CHAIN_ID, bundle, action)
}

/// A `BridgeBurn` on a junk-proof bundle shaped for it (`burn_asset == asset`, `burn_a == amount`).
async fn junk_burn(n: &TestNode, asset: u32, amount: u64, to_chain: u16, token: [u8; 32], seed: u32) -> Transaction {
    let (bundle, _) = junk_bundle(n, gas::BRIDGE_BURN_FEE, asset, amount, seed).await;
    let action = Action::BridgeBurn { asset, amount, relayer_fee: 0, to_chain, token, to: evm_to(0x22) };
    Transaction::shielded(CHAIN_ID, bundle, action)
}

fn token_refusal(e: TokenError) -> String {
    TxError::Bridge(BridgeError::Token(e)).to_string()
}

// ---------------------------------------------------------------- wallet actions (each one proof)

/// The relayer's `rand bridge-mint`: read the deposit, resolve the index from the registry, seal
/// the recipient's envelope — or, with `garbage`, publish an envelope nobody can open — and pay
/// with the relayer's RAND. Takes the proving slot.
async fn bridge_mint(
    n: &TestNode,
    relayer: &Wallet,
    store: &mut NoteStore,
    to: &ShieldedAddress,
    attestation: Vec<u8>,
    garbage: bool,
) -> (Submission, u32, [u32; 8]) {
    let d = wallet::attested_deposit(&attestation).expect("the attestation decodes to a transfer");
    assert_eq!(d.to_hash, to.recipient_hash());
    let asset_id = n.rpc.bridge_asset_id(d.token_chain, &d.token).await.unwrap();
    let state = n.rpc.bridge_state().await.unwrap();
    let assets = n.rpc.assets().await.unwrap();
    let index = wallet::deposit_index(&state, &assets, &asset_id).expect("the coin is a listed backing");
    let time = u32::try_from(n.rpc.head().await.unwrap()["height"].as_u64().unwrap()).unwrap();
    // The blinding is derived from the attestation digest (F1), inside `deposit_note_for`.
    let (note, mut envelope) = wallet::deposit_note_for(relayer, to, &attestation, d.amount, index, time).unwrap();
    if garbage {
        // A hostile or careless relayer: bytes that decrypt under no key at all.
        envelope = Envelope {
            kem_ct: vec![0xde; 64],
            to_receiver: vec![0xad; 96],
            to_sender: vec![0xbe; 96],
            body: vec![0xef; 128],
        };
    }
    let pq_signatures = pq_quorum(CHAIN_ID, &attestation);
    wallet::check_pq_cosignatures(&state, CHAIN_ID, &attestation, &pq_signatures).expect("the quorum is well formed");
    let action = Action::BridgeAttest { attestation, recipient: to.clone(), r: note.r, time, asset: index, envelope, pq_signatures };
    let fee = gas::fee_floor(&action);
    let slot = proving_slot().await;
    let s = wallet::submit_bridge_action(&n.rpc, relayer, store, action, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the attestation's fee bundle commits");
    drop(slot);
    eprintln!("  bridge-mint {}: tier {}, proved in {:.1?}", s.hash, s.tier, s.proving);
    (s, index, note.commitment())
}

/// `rand send --asset`: one hidden-asset bundle. Takes the proving slot.
async fn send_asset(n: &TestNode, from: &Wallet, store: &mut NoteStore, to: &Wallet, asset: u32, amount: u64) -> Submission {
    let slot = proving_slot().await;
    let s = wallet::send_asset(
        &n.rpc,
        from,
        store,
        &to.address,
        asset,
        amount,
        gas::fee_floor(&Action::None),
        FriProfile::Test,
        Backend::Cpu,
        CHAIN_ID,
        true,
    )
    .await
    .expect("the transfer commits");
    drop(slot);
    eprintln!("  transfer {}: tier {}, proved in {:.1?}", s.hash, s.tier, s.proving);
    s
}

/// A bridge-governance action on the deployer's fee bundle. Takes the proving slot.
async fn submit_gov(n: &TestNode, w: &Wallet, store: &mut NoteStore, action: Action, fee: u64) -> Submission {
    let slot = proving_slot().await;
    let s = wallet::submit_bridge_action(&n.rpc, w, store, action, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the governance action commits");
    drop(slot);
    eprintln!("  governance {}: tier {}, proved in {:.1?}", s.hash, s.tier, s.proving);
    s
}

// ---------------------------------------------------------------- a submission interceptor

/// A JSON-RPC proxy in front of a node that forwards every call but `rand_sendTransaction`, which
/// it keeps and answers with the transaction's hash. The wallet then proves and "submits" exactly
/// as `rand bridge-burn` does, and the test holds the signed-and-proved transaction before any node
/// has seen it — which is what a redirect attack needs to race the original.
struct Interceptor {
    upstream: String,
    http: reqwest::Client,
    captured: Mutex<Option<Transaction>>,
}

async fn intercept(State(s): State<Arc<Interceptor>>, body: axum::body::Bytes) -> axum::Json<Value> {
    let req: Value = serde_json::from_slice(&body).expect("a JSON-RPC request");
    if req["method"] == "rand_sendTransaction" {
        let raw = hex::decode(req["params"][0].as_str().unwrap()).unwrap();
        let tx = Transaction::decode(&raw).expect("the wallet's transaction decodes");
        let hash = tx.hash();
        *s.captured.lock().unwrap() = Some(tx);
        return axum::Json(json!({ "jsonrpc": "2.0", "id": req["id"], "result": hash.to_hex() }));
    }
    let resp = s
        .http
        .post(&s.upstream)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body.to_vec())
        .send()
        .await
        .expect("the node answers")
        .json::<Value>()
        .await
        .expect("a JSON reply");
    axum::Json(resp)
}

async fn start_interceptor(upstream: &TestNode) -> (RpcClient, Arc<Interceptor>) {
    let state = Arc::new(Interceptor {
        upstream: upstream.rpc.url().to_string(),
        http: reqwest::Client::builder().timeout(Duration::from_secs(120)).build().unwrap(),
        captured: Mutex::new(None),
    });
    let app = axum::Router::new().route("/", post(intercept)).with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (RpcClient::new(format!("http://{addr}")), state)
}

/// Every key naming an asset anywhere in `v` must hold 0 (RAND's) — the public face of a
/// hidden-asset transfer names no token.
fn assert_no_asset(v: &Value, path: &str) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k.contains("asset") {
                    assert!(x == &json!(0) || x == &json!("0"), "{path}.{k} = {x} reveals an asset");
                }
                assert_no_asset(x, &format!("{path}.{k}"));
            }
        }
        Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| assert_no_asset(x, &format!("{path}[{i}]"))),
        _ => {}
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn zusd_bridge_in_transfer_bridge_back_and_every_refusal() {
    init_tracing();
    let mut phases = Phases { started: Instant::now(), rows: Vec::new() };
    let ks = keys(4);
    let gen = zusd_genesis(&ks);
    let n0 = start_node_at(&ks[0], &gen, vec![], true, PROVING).await;
    let boot = vec![bootstrap_addr(&n0)];
    let n1 = start_node_at(&ks[1], &gen, boot.clone(), true, PROVING).await;
    let n2 = start_node_at(&ks[2], &gen, boot.clone(), true, PROVING).await;
    let n3 = start_node_at(&ks[3], &gen, boot.clone(), true, PROVING).await;
    wait_height(&[&n0, &n1, &n2, &n3], 2, Duration::from_secs(120)).await;
    let (deployer, relayer, a, b, c) = (wallet(10), wallet(11), wallet(12), wallet(13), wallet(14));
    let mut fees_paid_by_us: u64 = 0;

    // The genesis: a bridge, a registry, nothing listed.
    let state = n0.rpc.bridge_state().await.unwrap();
    assert_eq!(state["enabled"], true);
    assert_eq!(state["emitter"], hex::encode(RAND_EMITTER));
    assert!(state["emitters"].get("2").is_some() && state["emitters"].get("5").is_some());
    assert_eq!(state["list_nonce"], 0);
    assert_eq!(state["mint_paused"], false);
    assert_eq!(state["assets"], json!([]), "no token is listed at genesis");
    let tokens = n0.rpc.call("rand_getTokens", json!([])).await.unwrap();
    assert_eq!(tokens["tokens"], json!([]));
    assert_eq!(tokens["next_index"], 1);

    // ================================================================ 1. faucet → wallets
    let t = Instant::now();
    for (seed, name) in [(10u8, "deployer"), (11, "relayer"), (12, "A"), (13, "B"), (14, "C")] {
        let (hash, _) = n0.mint(seed, FAUCET).await;
        eprintln!("  faucet {name}: {hash}");
    }
    for (w, name) in [(&deployer, "deployer"), (&relayer, "relayer"), (&a, "A"), (&b, "B"), (&c, "C")] {
        assert_eq!(balance(&n0, w).await, FAUCET, "{name} holds the faucet's RAND");
    }
    let rand_supply_0 = supply_of(&n0).await;
    assert_eq!(rand_supply_0["invariant_holds"], true);
    assert_eq!(units(&rand_supply_0["faucet_minted"]), 5 * FAUCET);
    phases.done("1 faucet -> deployer, relayer, A, B, C", t);

    // ================================================================ 2. deploy zUSD by transaction
    let t = Instant::now();
    let mut deployer_store = NoteStore::default();
    let (name, symbol, salt) = ("Shielded USD", "zUSD", [0x27u8; 32]);
    let gov = GovState::from_bridge_state(&n0.rpc.bridge_state().await.unwrap()).unwrap();
    assert_eq!(gov.registration_fee, Some(REGISTRATION_FEE));
    let reg_sigs = pq_quorum_message(&register_message(CHAIN_ID, gov.list_nonce, name, symbol, &salt, 2, &usdt2(), 6).unwrap());
    let action = governance::register_bridged_action(&gov, CHAIN_ID, name, symbol, salt, 2, usdt2(), 6, reg_sigs).unwrap();
    let fee = gas::fee_floor(&action) + REGISTRATION_FEE;
    let deployed = submit_gov(&n0, &deployer, &mut deployer_store, action, fee).await;
    fees_paid_by_us += deployed.fee;
    // The registry, read from the chain: zUSD at index 1, bridge authority, its deploy tx.
    let tokens = n0.rpc.call("rand_getTokens", json!([])).await.unwrap();
    let row = tokens["tokens"].as_array().unwrap().iter().find(|r| r["symbol"] == symbol).expect("zUSD is registered").clone();
    let zusd = u32::try_from(row["index"].as_u64().unwrap()).unwrap();
    assert_eq!(zusd, 1, "the first registered token takes index 1");
    assert_eq!(row["name"], name);
    assert_eq!(row["decimals"], 8);
    assert_eq!(row["authority"]["kind"], "bridge");
    assert_eq!(row["id"], bridged_asset_id(name, symbol, &salt).to_hex());
    let id_text = row["id_text"].as_str().unwrap().to_string();
    assert!(id_text.starts_with("rpl1"));
    let deploy_tx = n0.rpc.call("rand_getTransaction", json!([deployed.hash.to_hex()])).await.unwrap();
    assert_eq!(deploy_tx["tx"]["action"]["kind"], "register_bridged_token");
    assert_eq!(row["registered_at"], deploy_tx["height"], "registered at its deploy transaction's height");
    eprintln!("  zUSD {id_text} registered by {} at height {}", deployed.hash, deploy_tx["height"]);

    // Two more backings, each under its own PQ quorum at the chain's list_nonce (1, then 2).
    let mut list_hashes = Vec::new();
    for (chain, coin, want_nonce) in [(2u16, usdc2(), 1u64), (5u16, usdt5(), 2u64)] {
        let gov = GovState::from_bridge_state(&n0.rpc.bridge_state().await.unwrap()).unwrap();
        assert_eq!(gov.list_nonce, want_nonce, "the list nonce read from the chain");
        let sigs = pq_quorum_message(&list_message(CHAIN_ID, gov.list_nonce, zusd, chain, &coin, 6));
        let action = governance::list_backing_action(&gov, CHAIN_ID, zusd, chain, coin, 6, sigs).unwrap();
        let fee = gas::fee_floor(&action);
        let s = submit_gov(&n0, &deployer, &mut deployer_store, action, fee).await;
        fees_paid_by_us += s.fee;
        list_hashes.push(s.hash);
    }
    assert_eq!(n0.rpc.bridge_state().await.unwrap()["list_nonce"], 3);
    let supply = token_supply(&n0, zusd).await;
    assert_eq!(supply["backings"].as_array().unwrap().len(), 3);
    for (chain, coin) in [(2, usdt2()), (2, usdc2()), (5, usdt5())] {
        let r = backing_row(&supply, chain, &coin);
        assert_eq!((r["decimals"].as_u64(), locked_of(&supply, chain, &coin)), (Some(6), 0));
    }
    assert_eq!(total_of(&supply), 0);
    assert_eq!(wallet::resolve_asset(&n0.rpc, &id_text).await.unwrap(), zusd, "`--asset rpl1…` resolves to index 1");
    eprintln!("  list-backing: {:?}", list_hashes.iter().map(|h| h.to_hex()).collect::<Vec<_>>());
    phases.done("2 deploy zUSD by transaction (register + 2 listings)", t);

    // ================================================================ 3. bridge in
    let t = Instant::now();
    let mut relayer_store = NoteStore::default();
    let (dep_a, dep_b) = (1_000 * ZUSD, 600 * ZUSD);
    let att_a = transfer_attestation(2, usdt2(), a.address.recipient_hash(), dep_a as u128, 1);
    let att_b = transfer_attestation(2, usdc2(), b.address.recipient_hash(), dep_b as u128, 2);
    let (minted_a, idx_a, cm_a) = bridge_mint(&n0, &relayer, &mut relayer_store, &a.address, att_a.clone(), true).await;
    let (minted_b, idx_b, _) = bridge_mint(&n0, &relayer, &mut relayer_store, &b.address, att_b.clone(), false).await;
    fees_paid_by_us += minted_a.fee + minted_b.fee;
    assert_eq!((idx_a, idx_b), (zusd, zusd), "USDT and USDC both mint zUSD");
    assert!(n0.holds(&cm_a), "A's deposit note is a leaf");
    // A's envelope opens to nobody — the wallet finds the note from the public action fields.
    let raw_a = n0.rpc.raw_transaction(&minted_a.hash).await.unwrap().unwrap();
    let Action::BridgeAttest { envelope, .. } = &raw_a.action else { panic!("an attest") };
    assert_eq!(envelope.kem_ct, vec![0xde; 64], "the garbage envelope is what the chain stored");
    assert!(wallet::rebuilt_notes(&a, &raw_a).len() == 1, "A rebuilds its deposit from the public fields");
    assert_eq!(asset_balance(&n0, &a, zusd).await, dep_a, "A holds the USDT deposit as zUSD despite the garbage envelope");
    assert_eq!(asset_balance(&n0, &b, zusd).await, dep_b, "B holds the USDC deposit as zUSD");
    assert_eq!(asset_balance(&n0, &relayer, zusd).await, 0, "the relayer holds none of what it relayed");
    let supply = token_supply(&n0, zusd).await;
    assert_eq!(locked_of(&supply, 2, &usdt2()), dep_a);
    assert_eq!(locked_of(&supply, 2, &usdc2()), dep_b);
    assert_eq!(total_of(&supply), dep_a + dep_b);
    for (i, att) in [att_a, att_b].into_iter().enumerate() {
        let who = if i == 0 { &a.address } else { &b.address };
        let replay = junk_attest(&n0, who, att, zusd, 10 + i as u32).await;
        assert_refused(&n0, zusd, &replay, &TxError::Bridge(BridgeError::Replay).to_string()).await;
    }
    eprintln!("  deposits: A {} (USDT, garbage envelope), B {} (USDC)", minted_a.hash, minted_b.hash);
    phases.done("3 bridge in (USDT->A garbage envelope, USDC->B, replays refused)", t);

    // ================================================================ 4. transfers A -> B -> C
    let t = Instant::now();
    let mut a_store = NoteStore::default();
    let mut b_store = NoteStore::default();
    let (ab, bc) = (250 * ZUSD, 800 * ZUSD);
    let asset = wallet::resolve_asset(&n0.rpc, &id_text).await.unwrap();
    let s_ab = send_asset(&n0, &a, &mut a_store, &b, asset, ab).await;
    fees_paid_by_us += s_ab.fee;
    assert_eq!(asset_balance(&n0, &a, zusd).await, dep_a - ab);
    assert_eq!(asset_balance(&n0, &b, zusd).await, dep_b + ab);
    assert_eq!(asset_balance(&n0, &c, zusd).await, 0);
    assert_eq!(balance(&n0, &a).await, FAUCET - s_ab.fee, "A paid the fee in RAND");
    let s_bc = send_asset(&n0, &b, &mut b_store, &c, asset, bc).await;
    fees_paid_by_us += s_bc.fee;
    assert_eq!(asset_balance(&n0, &a, zusd).await, dep_a - ab);
    assert_eq!(asset_balance(&n0, &b, zusd).await, dep_b + ab - bc);
    assert_eq!(asset_balance(&n0, &c, zusd).await, bc);
    assert_eq!(balance(&n0, &b).await, FAUCET - s_bc.fee);
    for s in [&s_ab, &s_bc] {
        let j = n0.rpc.call("rand_getTransaction", json!([s.hash.to_hex()])).await.unwrap();
        assert_eq!(j["tx"]["action"], json!({ "kind": "none" }), "a plain transfer");
        assert_no_asset(&j["tx"], "tx");
    }
    eprintln!("  transfers: A->B {}, B->C {}", s_ab.hash, s_bc.hash);
    phases.done("4 transfer A -> B -> C (hidden-asset bundles)", t);

    // Phase 9's node goes down here and misses phases 5 and 6.
    let n3_dir = stop(n3).await;
    let t_down = Instant::now();

    // ================================================================ 5. bridge back (and a redirect)
    let t = Instant::now();
    let mut c_store = NoteStore::default();
    let (burn1, relayer_fee) = (100 * ZUSD, ZUSD);
    let usdc_before = locked_of(&token_supply(&n0, zusd).await, 2, &usdc2());
    let (proxy, captured) = start_interceptor(&n0).await;
    let slot = proving_slot().await;
    let burned = wallet::submit_burn(
        &proxy,
        &c,
        &mut c_store,
        zusd,
        burn1,
        relayer_fee,
        2,
        usdc2(),
        evm_to(0x22),
        gas::BRIDGE_BURN_FEE,
        FriProfile::Test,
        Backend::Cpu,
        CHAIN_ID,
        false,
    )
    .await
    .expect("the burn is proved");
    drop(slot);
    eprintln!("  bridge-burn proved: tier {}, {:.1?}", burned.tier, burned.proving);
    let original = captured.captured.lock().unwrap().take().expect("the wallet submitted its burn");
    assert_eq!(original.hash(), burned.hash);
    // The redirect: same bundle, same proof, `to` swapped for the attacker's address.
    let mut redirected = original.clone();
    let Action::BridgeBurn { to, .. } = &mut redirected.action else { panic!("a burn") };
    *to = evm_to(0x66);
    let err = assert_refused(&n0, zusd, &redirected, "invalid bundle proof").await;
    eprintln!("  redirected copy {} refused: {err}", redirected.hash());
    // The original, submitted after its copy was refused, commits.
    let hash = n0.rpc.send_transaction(&original).await.expect("the original burn is accepted");
    n0.rpc.wait_for_transaction(&hash, wallet::COMMIT_TIMEOUT).await.expect("the original burn commits");
    fees_paid_by_us += burned.fee;
    assert_eq!(asset_balance(&n0, &c, zusd).await, bc - burn1);
    assert_eq!(balance(&n0, &c).await, FAUCET - gas::BRIDGE_BURN_FEE);
    let supply = token_supply(&n0, zusd).await;
    assert_eq!(locked_of(&supply, 2, &usdc2()), usdc_before - burn1, "USDC locked drops by exactly the burn");
    assert_eq!(locked_of(&supply, 2, &usdt2()), dep_a, "USDT untouched");
    let msg = n0.rpc.bridge_burn(0).await.unwrap().expect("the burn emitted a message");
    assert_eq!(msg["tx"], hash.to_hex());
    let body = Body::decode(&hex::decode(msg["body_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(body.emitter_chain, CHAIN_RAND);
    assert_eq!(body.emitter_address, RAND_EMITTER, "emitter_address == bridge.emitter");
    let Ok(Payload::Transfer(out)) = Payload::decode(&body.payload) else { panic!("a transfer payload") };
    assert_eq!((out.token_chain, out.token_address, out.to_chain), (2, usdc2(), 2), "chain 2 USDC wire form");
    assert_eq!(out.to, evm_to(0x22), "to the original destination, not the redirect");
    assert_eq!(out.amount_u128(), Some(burn1 as u128));
    assert_eq!(out.fee_u128(), Some(relayer_fee as u128));
    eprintln!("  burn {} -> outbound sequence 0, digest {}", hash, msg["digest"]);
    phases.done("5 bridge back C -> chain 2 USDC (redirected copy refused)", t);

    // ================================================================ 6. refusals
    let t = Instant::now();
    let supply = token_supply(&n0, zusd).await;
    let usdc_locked = locked_of(&supply, 2, &usdc2());
    // (a) more than the backing holds, though the token's supply and C's balance would cover it.
    let too_much = usdc_locked + 100 * ZUSD;
    assert!(too_much <= total_of(&supply) && too_much <= asset_balance(&n0, &c, zusd).await);
    let e = wallet::submit_burn(&n0.rpc, &c, &mut c_store, zusd, too_much, 0, 2, usdc2(), evm_to(0x22), gas::BRIDGE_BURN_FEE, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect_err("the wallet refuses before proving");
    assert!(e.to_string().contains("only"), "{e}");
    let tx = junk_burn(&n0, zusd, too_much, 2, usdc2(), 20).await;
    assert_refused(&n0, zusd, &tx, &token_refusal(TokenError::InsufficientBacking { locked: usdc_locked, amount: too_much })).await;
    eprintln!("  InsufficientBacking refused ({too_much} > {usdc_locked})");
    // (b) not a whole release unit of a six-decimal coin.
    let odd = 10 * ZUSD + 50;
    let tx = junk_burn(&n0, zusd, odd, 2, usdt2(), 21).await;
    assert_refused(&n0, zusd, &tx, &token_refusal(TokenError::NotReleasable { amount: odd, unit: UNIT6 })).await;
    eprintln!("  NotReleasable refused ({odd} % {UNIT6} != 0)");
    // (c) past today's cap on chain 2 USDT.
    let row = backing_row(&token_supply(&n0, zusd).await, 2, &usdt2()).clone();
    let minted_today: u64 = row["minted_today"].as_str().unwrap().parse().unwrap();
    assert_eq!(minted_today, dep_a);
    let over = MINT_CAP - minted_today + UNIT6;
    let att = transfer_attestation(2, usdt2(), c.address.recipient_hash(), over as u128, 3);
    let tx = junk_attest(&n0, &c.address, att, zusd, 22).await;
    assert_refused(&n0, zusd, &tx, &token_refusal(TokenError::MintCapExceeded { cap: MINT_CAP, minted_today, amount: over })).await;
    eprintln!("  MintCapExceeded refused ({minted_today} + {over} > {MINT_CAP})");
    // (d) the pause key pauses; a deposit is refused; a burn still goes through.
    let gov = GovState::from_bridge_state(&n0.rpc.bridge_state().await.unwrap()).unwrap();
    let sig = pause_keypair().sign(&randprotocol_core::bridge::gov::pause_message(CHAIN_ID, gov.pause_nonce));
    let pause = governance::pause_action(&gov, CHAIN_ID, sig).unwrap();
    let paused = governance::submit_bundle_less(&n0.rpc, CHAIN_ID, pause, true).await.expect("the pause commits");
    let st = n0.rpc.bridge_state().await.unwrap();
    assert_eq!((st["mint_paused"].as_bool(), st["pause_nonce"].as_u64()), (Some(true), Some(1)));
    let dep_c5 = 200 * ZUSD;
    let att_c5 = transfer_attestation(5, usdt5(), c.address.recipient_hash(), dep_c5 as u128, 1);
    let tx = junk_attest(&n0, &c.address, att_c5.clone(), zusd, 23).await;
    assert_refused(&n0, zusd, &tx, &TxError::Bridge(BridgeError::MintsPaused).to_string()).await;
    let burn2 = 100 * ZUSD;
    let usdt_before = locked_of(&token_supply(&n0, zusd).await, 2, &usdt2());
    let slot = proving_slot().await;
    let burned2 = wallet::submit_burn(&n0.rpc, &c, &mut c_store, zusd, burn2, 0, 2, usdt2(), evm_to(0x22), gas::BRIDGE_BURN_FEE, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("a burn still goes through while mints are paused");
    drop(slot);
    fees_paid_by_us += burned2.fee;
    assert_eq!(locked_of(&token_supply(&n0, zusd).await, 2, &usdt2()), usdt_before - burn2);
    assert!(n0.rpc.bridge_burn(1).await.unwrap().is_some());
    eprintln!("  paused by {paused}; MintsPaused refused; burn {} committed while paused", burned2.hash);
    // (e) the pause key alone cannot unpause; a PQ quorum can.
    let nonce = n0.rpc.bridge_state().await.unwrap()["pause_nonce"].as_u64().unwrap();
    let key_only = pause_keypair().sign(&unpause_message(CHAIN_ID, nonce)).as_bytes().to_vec();
    let one = Transaction {
        chain_id: CHAIN_ID,
        bundle: None,
        action: Action::UnpauseMints { nonce, pq_signatures: vec![PqSignature { index: 0, signature: key_only.clone() }] },
    };
    assert_refused(&n0, zusd, &one, &TxError::Bridge(BridgeError::PqNoQuorum { have: 1, need: 5, n: 6 }).to_string()).await;
    let five = Transaction {
        chain_id: CHAIN_ID,
        bundle: None,
        action: Action::UnpauseMints {
            nonce,
            pq_signatures: (0..5).map(|i| PqSignature { index: i, signature: key_only.clone() }).collect(),
        },
    };
    assert_refused(&n0, zusd, &five, &TxError::Bridge(BridgeError::PqBadSignature { index: 0 }).to_string()).await;
    let gov = GovState::from_bridge_state(&n0.rpc.bridge_state().await.unwrap()).unwrap();
    let unpause = governance::unpause_action(&gov, CHAIN_ID, pq_quorum_message(&unpause_message(CHAIN_ID, nonce))).unwrap();
    let unpaused = governance::submit_bundle_less(&n0.rpc, CHAIN_ID, unpause, true).await.expect("the PQ unpause commits");
    let st = n0.rpc.bridge_state().await.unwrap();
    assert_eq!((st["mint_paused"].as_bool(), st["pause_nonce"].as_u64()), (Some(false), Some(2)));
    // And the deposit the pause held back is admissible again.
    let (minted_c5, idx_c5, _) = bridge_mint(&n0, &relayer, &mut relayer_store, &c.address, att_c5, false).await;
    fees_paid_by_us += minted_c5.fee;
    assert_eq!(idx_c5, zusd, "chain 5 USDT mints the same zUSD");
    eprintln!("  unpause by key alone refused (1 sig, 5 key sigs); PQ unpause {unpaused}; chain-5 deposit {}", minted_c5.hash);
    phases.done("6 refusals (backing, release unit, cap, pause/unpause, burn while paused)", t);

    // Phase 9's node comes back.
    let n3 = start_in_at(n3_dir, &ks[3], boot.clone(), true, PROVING).await;
    let down_for = t_down.elapsed();

    // ================================================================ 7. supply audit
    let t = Instant::now();
    let supply = token_supply(&n0, zusd).await;
    let deposits = dep_a + dep_b + dep_c5;
    let burns = burn1 + burn2;
    let locked: u64 = supply["backings"].as_array().unwrap().iter().map(|b| b["locked"].as_str().unwrap().parse::<u64>().unwrap()).sum();
    assert_eq!(total_of(&supply), locked, "total_supply == Σ locked");
    assert_eq!(total_of(&supply), deposits - burns, "== deposits − burns");
    assert_eq!(locked_of(&supply, 2, &usdt2()), dep_a - burn2, "chain 2 USDT");
    assert_eq!(locked_of(&supply, 2, &usdc2()), dep_b - burn1, "chain 2 USDC");
    assert_eq!(locked_of(&supply, 5, &usdt5()), dep_c5, "chain 5 USDT");
    let (za, zb, zc) = (asset_balance(&n0, &a, zusd).await, asset_balance(&n0, &b, zusd).await, asset_balance(&n0, &c, zusd).await);
    assert_eq!((za, zb, zc), (dep_a - ab, dep_b + ab - bc, bc - burn1 - burn2 + dep_c5));
    assert_eq!(za + zb + zc, total_of(&supply), "every zUSD unit is in some wallet's notes");
    let rand_supply = supply_of(&n0).await;
    assert_eq!(rand_supply["invariant_holds"], true);
    assert_eq!(rand_supply["total_supply"], rand_supply_0["total_supply"], "RAND total supply unchanged");
    assert_eq!(rand_supply["faucet_minted"], rand_supply_0["faucet_minted"]);
    assert_eq!(rand_supply["burned"], rand_supply_0["burned"], "no RAND burned");
    assert_eq!(
        units(&rand_supply["fees_paid"]) - units(&rand_supply_0["fees_paid"]),
        fees_paid_by_us,
        "RAND moved only as the fees these transactions paid"
    );
    eprintln!("  zUSD total {} = Σ locked; RAND fees {fees_paid_by_us}", total_of(&supply));
    phases.done("7 supply audit", t);

    // ================================================================ 8. disclosure
    let t = Instant::now();
    let raw_bc = n0.rpc.raw_transaction(&s_bc.hash).await.unwrap().unwrap();
    let keys_b = wallet::output_keys(&b, &raw_bc);
    let sent = keys_b.iter().find(|k| k.role == wallet::KeyRole::Sent).expect("B sealed C's output");
    let disclosed = n2.rpc.check_transaction(&s_bc.hash, &hex::encode(sent.key.0)).await.unwrap().expect("committed");
    let rows = disclosed["disclosed"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "the key opens exactly the one output");
    assert_eq!(rows[0]["note"]["asset"], zusd, "the transaction key reveals the asset");
    assert_eq!(rows[0]["note"]["amount"], bc.to_string(), "and the amount");
    assert_eq!(rows[0]["note"]["pk"], word8_to_hex(&c.vk.pk()), "paid to C");
    n1.rpc.import_viewing_key(&b.viewing_key_hex(), None).await.expect("import");
    let mut notes = Vec::new();
    for _ in 0..100 {
        let page = n1.rpc.viewing_notes(&b.viewing_key_hex(), 0, 1000).await.unwrap();
        if page["complete"] == true {
            notes = page["notes"].as_array().unwrap().clone();
            break;
        }
    }
    let received: Vec<&Value> =
        notes.iter().filter(|n| n["role"] == "received" && n["note"]["asset"] == zusd).collect();
    let amt = |n: &Value| n["note"]["amount"].as_str().unwrap().parse::<u64>().unwrap();
    let mut spent: Vec<u64> = received.iter().filter(|n| n["spent"] == true).map(|n| amt(n)).collect();
    spent.sort();
    let unspent: u64 = received.iter().filter(|n| n["spent"] == false).map(|n| amt(n)).sum();
    assert_eq!(spent, vec![ab, dep_b], "B's USDC deposit and A's payment, both spent paying C");
    assert_eq!(unspent, dep_b + ab - bc, "the unspent zUSD is B's change");
    assert!(notes.iter().any(|n| n["role"] == "sent" && n["note"]["asset"] == zusd && amt(n) == bc), "the payment to C as sent");
    phases.done("8 disclosure (tx key, viewing key)", t);

    // ================================================================ 9. restart
    let t = Instant::now();
    wait_caught_up(&n3, &[&n0, &n1, &n2], Duration::from_secs(300)).await;
    let head = n0.height();
    wait_height(&[&n0, &n1, &n2, &n3], head + 2, Duration::from_secs(120)).await;
    assert_chains_equal(&[&n0, &n1, &n2, &n3]);
    let want = token_supply(&n0, zusd).await;
    for n in [&n1, &n2, &n3] {
        assert_eq!(token_supply(n, zusd).await, want, "every node, the restarted one included, agrees on rand_getTokenSupply");
    }
    assert!(n3.handle.storage.tx_location(&burned.hash).unwrap().is_some(), "the restarted node holds the burn it missed");
    eprintln!("  n3 was down {down_for:.1?}; rejoined at height {}", n3.height());
    phases.done("9 restart: rejoin and agree", t);

    eprintln!("ZUSD-E2E SUMMARY");
    for (name, d) in &phases.rows {
        eprintln!("  {name}: {d:.1?}");
    }
    eprintln!("ZUSD-E2E TOTAL {:.1?}", phases.started.elapsed());
    for n in [n0, n1, n2, n3] {
        n.handle.shutdown().await;
    }
}
