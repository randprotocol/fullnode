//! The shielded wallet against a real chain: mint, scan, send, scan both sides, spend the change,
//! bond a validator, then make a confidential call and open its input transcript back.
//!
//! One validator node runs in-process (the same `node::start` the cluster tests use) so the
//! whole loop is exercised end to end — a faucet mint lands a note only wallet A's viewing key
//! opens; A proves a real 2-in-2-out bundle; B finds its payment by trial-decrypting the tree;
//! A's spent note comes back marked spent by the chain's own nullifier set; the change note
//! is spendable, which is the part a wallet gets wrong if it forgets its own second output; the
//! bond is the one bundle whose value does not land in anybody's note (it burns, and the
//! register's stake is where it turns up instead); and a call's private inputs come back off the
//! chain under A's viewing key alone, checked against the `H_IN` its proof published (spec §6.1).
//!
//! Six bundle proofs and one call proof, so this is the slowest test in the workspace by a wide
//! margin — minutes, not seconds. The bridge commands are not here: they need a chain with a
//! guardian set, which the node's cluster tests configure.
//!
//! Two things about the chain this test configures deliberately. The FRI profile is `test` (16
//! queries: a real proof, not a security claim), and blocks are slow — `ANCHOR_WINDOW` and
//! `TIME_WINDOW` are both 256 *blocks*, so a chain making blocks every 150 ms expires an anchor
//! in under forty seconds, which is less than it takes to prove a bundle. Three-second blocks
//! give a bundle nearly thirteen minutes between reading its anchor and being committed under
//! it, against a proof that takes about a minute and a half in this profile — margin enough
//! that a slow machine fails the assertion it is testing rather than the clock.
//!
//! Every proof here is taken under the workspace's one proving slot ([`proving_slot`]), so no other
//! test's proof — in this binary, in `rand-node`'s cluster suite, or in another session's
//! `cargo test` against the same target directory — is ever in flight beside it. The slow blocks
//! are what covers a slow machine; the slot is what covers a busy one.

use randprotocol_client::prover::Prover;
use randprotocol_client::wallet::{self, Burn, NoteStore, Wallet};
use randprotocol_client::RpcClient;
use randprotocol_core::genesis::{Genesis, GenesisValidator};
use randprotocol_core::notes::word8_to_hex;
use randprotocol_core::{format_amount, gas, Action, Keypair, UNITS_PER_RAND};
use randprotocol_node::node::{self, NodeConfig, NodeHandle};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::notes::SpendKey;
use randprotocol_zkvm::{call_envelope, executor, guests, hash};
use std::time::{Duration, Instant};

/// One proof at a time, for every test here and in `rand-node`'s `cluster.rs`.
mod proving_slot;
use proving_slot::proving_slot;

const CHAIN_ID: u64 = 7;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn,randprotocol_node=info".into()))
        .with_test_writer()
        .try_init();
}

fn genesis(validator: &Keypair) -> Genesis {
    Genesis {
        chain_id: CHAIN_ID,
        timestamp_ms: 0,
        validators: vec![GenesisValidator {
            public_key: validator.public_key().clone(),
            stake: randprotocol_core::ledger::staking::MIN_STAKE as u128,
            // Phase S2 requires a payout address per validator; this test never withdraws, so
            // it only has to parse.
            payout: randprotocol_core::notes::ShieldedAddress {
                pk: [1; 8],
                kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES],
            }
            .to_string(),
        }],
        alloc: vec![],
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        // Must be this build's own guest, or `node::start` refuses to run at all.
        hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
        bridge: None,
        aggregation: None,
        epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
    }
}

async fn start(dir: &tempfile::TempDir, key: &Keypair) -> NodeHandle {
    std::fs::write(dir.path().join("genesis.json"), genesis(key).to_json()).unwrap();
    node::start(NodeConfig {
        datadir: dir.path().to_path_buf(),
        seed: *key.seed(),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        enable_mdns: false,
        validator: true,
        // See the module comment: the anchor and time windows are 256 blocks, and a bundle proof
        // takes longer than 256 blocks of a fast chain.
        block_interval: Duration::from_secs(3),
        base_timeout: Duration::from_secs(6),
        max_timeout: Duration::from_secs(30),
        verify: randprotocol_node::storage::VerifyMode::Full,
        keep_raw_proofs: false,
    })
    .await
    .expect("node starts")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wallet_mints_scans_sends_and_spends_its_change() {
    init_tracing();
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([101; 32]).unwrap();
    let handle = start(&dir, &key).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));

    let a = Wallet::from_spend_key(SpendKey([1; 8]));
    let b = Wallet::from_spend_key(SpendKey([2; 8]));
    let mut a_store = NoteStore::default();
    let mut b_store = NoteStore::default();
    assert_ne!(a.address, b.address, "two spend keys, two addresses");

    // ---- mint: a validator pays 100 RAND into a note only A can open ----
    let mint = 100 * UNITS_PER_RAND;
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");

    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(a_store.balance(), mint, "A sees the minted note");
    assert_eq!(a_store.spendable().len(), 1);
    // The same leaf is on the chain for everyone; B's viewing key simply does not open it.
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), 0, "B cannot see A's note");
    assert!(b_store.notes.is_empty());

    // ---- send: A pays B 1 RAND, proving a real bundle ----
    let fee = gas::BUNDLE_BASE;
    let pay = UNITS_PER_RAND;
    // Under the workspace's proving slot, held around the whole call: taken before the anchor is
    // read and released after the commit, so no other test's proof shares these cores (see
    // `proving_slot`).
    let slot = proving_slot().await;
    let first = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, fee, FriProfile::Test, &Prover::Local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect("the bundle is accepted and commits");
    drop(slot);
    eprintln!("first bundle: tier {}, proved in {:.1?}, {} proof bytes", first.tier, first.proving, first.proof_bytes);
    assert_eq!(first.amount, pay);
    assert_eq!(first.change, mint - pay - fee);

    // ---- scan both sides ----
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), pay, "B's payment arrived as {} RAND", format_amount(pay));
    assert_eq!(b_store.spendable().len(), 1);

    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    let change = mint - pay - fee;
    assert_eq!(a_store.balance(), change, "A keeps {} RAND as change", format_amount(change));
    assert_eq!(a_store.spendable().len(), 1, "one change note, and the spent one is gone");
    // The spent note is marked from the chain's nullifier set, not from this wallet's guess:
    // `scan` re-reads `rand_getNullifiers` and matches `H_NF(nk, cm)`.
    let spent: Vec<u64> = a_store.notes.iter().filter(|n| n.spent).map(|n| n.note.amount).collect();
    assert_eq!(spent, vec![mint], "the 100 RAND note is spent");
    // A also records what it sent, opened through its own outgoing viewing key.
    assert!(a_store.sent.iter().any(|s| s.amount == pay && s.to_pk == b.vk.pk()), "A's history names the payment");

    // ---- the change note is spendable ----
    let slot = proving_slot().await;
    let second = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, fee, FriProfile::Test, &Prover::Local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect("the change note pays a second bundle");
    drop(slot);
    eprintln!("second bundle: tier {}, proved in {:.1?}", second.tier, second.proving);
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(b_store.balance(), 2 * pay, "B has been paid twice");
    assert_eq!(a_store.balance(), mint - 2 * pay - 2 * fee);
    assert_eq!(a_store.spendable().len(), 1, "still exactly one change note");

    // ---- bond: A stakes 1 RAND onto the genesis validator, burning it out of the pool ----
    // The genesis validator is already in the register, so this bond carries no registration; the
    // stake leaves the shielded pool as the bundle's `burn` rather than as anybody's note.
    let validator = key.address();
    let staked_before = stake_of(&rpc, &validator.to_base58()).await;
    let balance_before = a_store.balance();
    let bond = UNITS_PER_RAND;
    let action = randprotocol_core::Action::Bond { validator, amount: bond, registration: None };
    let slot = proving_slot().await;
    let bonded =
        wallet::submit(&rpc, &a, &mut a_store, None, action, fee, Burn::Rand(bond), FriProfile::Test, &Prover::Local(Backend::Cpu), CHAIN_ID, true)
            .await
            .expect("the bond's bundle is accepted and commits");
    drop(slot);
    eprintln!("bond bundle: tier {}, proved in {:.1?}", bonded.tier, bonded.proving);
    assert_eq!(bonded.burn, Burn::Rand(bond), "the bundle burns exactly what is bonded, in RAND");
    assert_eq!(bonded.amount, 0, "a bond pays nobody a note");
    assert_eq!(
        stake_of(&rpc, &validator.to_base58()).await,
        staked_before + bond,
        "the register's stake grew by exactly the bonded amount"
    );
    assert_eq!(a_store.balance(), balance_before - bond - fee, "the wallet paid the stake and the fee");

    // ---- a confidential call whose input transcript A can open back (spec §6.1) ----
    // `balance_check` reads four private words and publishes only whether they reach a threshold,
    // so the transcript is the only record of what it was fed — and it is sealed to A alone.
    let prog = guests::balance_check(1_000);
    let pid = randprotocol_core::program::program_id(prog.base_pc, &prog.words);
    let deploy = Action::Deploy { base_pc: prog.base_pc, words: prog.words.clone() };
    let fee = wallet::deploy_fee_default(&deploy);
    let slot = proving_slot().await;
    wallet::submit(&rpc, &a, &mut a_store, None, deploy, fee, Burn::None, FriProfile::Test, &Prover::Local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect("the program deploys");
    drop(slot);

    let inputs = [100u32, 200, 300, 400];
    // `prove_call`, not `prove`: it returns the `H_IN` salt, without which the transcript could not
    // be bound to this proof at all. It and the bundle that pays for it are one hold of the proving
    // slot — a program proof is prover work like any other, and the bundle follows it immediately.
    let slot = proving_slot().await;
    let (proof, outputs, tier, salt) =
        executor::prove_call(FriProfile::Test, &prog, &inputs, None, Backend::Cpu).expect("the call proves");
    let h_in = hash::input_digest(salt, &inputs);
    let (envelope, key) = call_envelope::seal_call_envelope(&a.vk, None, &h_in, salt, &inputs).expect("the transcript seals");
    let action = Action::Call { program: pid, proof, input_envelope: Some(envelope) };
    let call = wallet::submit(
        &rpc,
        &a,
        &mut a_store,
        None,
        action,
        wallet::call_fee_default(tier),
        Burn::None,
        FriProfile::Test,
        &Prover::Local(Backend::Cpu),
        CHAIN_ID,
        true,
    )
    .await
    .expect("the call is accepted and commits");
    drop(slot);
    let receipt = rpc.wait_for_receipt(&call.hash, Duration::from_secs(120)).await.expect("the call has a receipt");
    // The chain publishes the same `H_IN` the wallet sealed against — it comes out of the proof,
    // not out of the transaction, which is what makes it a commitment to the inputs.
    assert_eq!(receipt["h_in"], serde_json::json!(word8_to_hex(&h_in)));
    assert_eq!(receipt["outputs"][0], 1, "the four private balances do reach the threshold");

    // Off the chain and back open, with nothing but A's own viewing key.
    let (served_h_in, e) = rpc.call_envelope(&call.hash).await.unwrap().expect("the call published a transcript");
    assert_eq!(served_h_in, h_in, "the envelope is served with the H_IN it is bound to");
    let (back_key, back_salt, back_inputs) =
        call_envelope::open_call_as_sender(&e, &h_in, &a.vk).expect("A opens the call it made");
    assert_eq!(back_inputs, inputs.to_vec(), "the four private words, as they were fed to the guest");
    assert_eq!((back_salt, back_key), (salt, key));
    // And the transcript is faithful: it hashes to the `H_IN` the proof published, which commits
    // in-circuit to every word the guest read.
    assert!(call_envelope::call_envelope_is_faithful(&h_in, back_salt, &back_inputs));
    assert_eq!(receipt["outputs"], serde_json::json!(outputs));
    // B holds the same bytes as everyone else and no key that opens them.
    assert!(call_envelope::open_call_as_sender(&e, &h_in, &b.vk).is_none(), "a transcript is not public");
    assert!(call_envelope::open_call_as_auditor(&e, &h_in, &b.vk).is_none(), "and this call named no auditor");

    eprintln!("whole flow in {:.1?}", started.elapsed());
    handle.shutdown().await;
}

/// One validator's bonded stake, as `rand_getValidators` reports it: amounts go out as decimal
/// strings, since a stake in units does not fit a JSON number safely.
async fn stake_of(rpc: &RpcClient, address: &str) -> u64 {
    let rows = rpc.validators().await.expect("getValidators answers");
    let row = rows
        .as_array()
        .expect("getValidators returns a list")
        .iter()
        .find(|r| r["address"].as_str() == Some(address))
        .unwrap_or_else(|| panic!("{address} is in the register"));
    row["stake"].as_str().expect("stake is a decimal string").parse().expect("stake parses")
}

/// Coin selection refuses what a 2-in-2-out bundle cannot do, before any proving starts.
#[test]
fn a_wallet_that_cannot_pay_says_so_without_proving() {
    let a = Wallet::from_spend_key(SpendKey([3; 8]));
    let store = NoteStore::default();
    assert_eq!(store.balance(), 0);
    assert_eq!(a.address.pk, a.vk.pk());
    let err = wallet::select_inputs(&store.spendable(), 1).unwrap_err();
    assert_eq!(err, wallet::SelectError::Insufficient { have: 0 });
}

/// Spec §12: the same send, bond-free, through an in-process `rand-prover`; then a prover that
/// answers with a proof of a *different* computation, which the wallet's digest check refuses;
/// then a call through the prover with an input envelope the caller opens back (the §6 salt path).
///
/// Three bundle proofs (the send, the deploy's fee, the call's fee) and one program proof, all
/// made in this process by the service rather than by the wallet — so this test is as slow as the
/// one above and takes the same proving slot around every proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegated_proving_sends_calls_and_refuses_a_tampering_prover() {
    use randprotocol_client::prover::RemoteProver;
    use randprotocol_prover::{serve, Config};
    use randprotocol_zkvm::delegate::ProverKey;

    init_tracing();
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([102; 32]).unwrap();
    let handle = start(&dir, &key).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));

    // ---- the prover: a real `rand-prover` in this process, jobs sealed to its own wallet ----
    let prover_wallet = Wallet::from_spend_key(SpendKey([9; 8]));
    let (prover_addr, _prover) =
        serve("127.0.0.1:0".parse().unwrap(), Config::test(ProverKey::from_viewing_key(&prover_wallet.vk)))
            .await
            .expect("the prover serves");
    let remote = Prover::Remote(RemoteProver::new(format!("http://{prover_addr}"), prover_wallet.address.clone(), None, 600));

    // ---- two wallets, one funded ----
    let a = Wallet::from_spend_key(SpendKey([7; 8]));
    let b = Wallet::from_spend_key(SpendKey([8; 8]));
    let mut a_store = NoteStore::default();
    let mut b_store = NoteStore::default();
    let mint = 100 * UNITS_PER_RAND;
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(a_store.balance(), mint, "A sees the minted note");

    // ---- 1. a delegated send: proved at the prover, submitted by the wallet, found by B ----
    let fee = gas::BUNDLE_BASE;
    let pay = 3 * UNITS_PER_RAND;
    let slot = proving_slot().await;
    let sent = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, fee, FriProfile::Test, &remote, CHAIN_ID, true)
        .await
        .expect("the delegated bundle is accepted and commits");
    drop(slot);
    eprintln!("delegated send: tier {}, proved in {:.1?}, {} proof bytes", sent.tier, sent.proving, sent.proof_bytes);
    assert_eq!(sent.amount, pay);
    assert_eq!(sent.change, mint - pay - fee);
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), pay, "B found the payment a prover made for A");
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(a_store.balance(), mint - pay - fee, "A keeps its change");

    // ---- the call's program proof, made at the prover with the §6 salt ----
    // Taken here rather than after the deploy so its bytes can stand in as the tampering prover's
    // canned proof: a real proof of a *different* computation, which is exactly what a prover that
    // proved something else would be handing back. (`Submission` carries no proof bytes, and the
    // node serves proof lengths rather than proofs, so there is nothing else real to can.)
    let prog = guests::private_payment(1_000);
    let pid = randprotocol_core::program::program_id(prog.base_pc, &prog.words);
    let inputs = [400u32, 250, 300, 75];
    let slot = proving_slot().await;
    let (proof, outputs, tier, salt) =
        remote.prove_program(FriProfile::Test, &prog, &inputs, None, true).await.expect("the call proves at the prover");
    drop(slot);
    let salt = salt.expect("the prover returns the salt this wallet asked for");

    // ---- 2. a tampering prover: the job is opened and the reply sealed properly, and the only
    //         thing wrong is which computation the proof is of ----
    let tamper = tampering_prover(&prover_wallet, proof.clone(), tier).await;
    let bad = Prover::Remote(RemoteProver::new(format!("http://{tamper}"), prover_wallet.address.clone(), None, 600));
    let before = a_store.balance();
    // No proving slot: the stub answers from memory, so this send proves nothing anywhere.
    let err = wallet::send(&rpc, &a, &mut a_store, &b.address, UNITS_PER_RAND, fee, FriProfile::Test, &bad, CHAIN_ID, true)
        .await
        .expect_err("a proof of some other computation is refused");
    assert!(err.to_string().contains("refusing to submit"), "{err}");
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(b_store.balance(), pay, "nothing was submitted, so B was paid once");
    assert_eq!(a_store.balance(), before, "and A paid no fee for a proof it would not submit");

    // ---- 2b. the same stub on a *program* job: a real proof of this very call, handed back with
    //          a salt it was not made with. The transcript the wallet would seal against that salt
    //          is one the proof does not commit to, so the wallet refuses before it publishes it.
    let err = bad
        .prove_program(FriProfile::Test, &prog, &inputs, None, true)
        .await
        .expect_err("a salt the proof was not made with is refused");
    assert!(err.to_string().contains("refusing to submit"), "{err}");

    // ---- 3. a delegated deploy and call, with an input transcript A opens back ----
    let deploy = Action::Deploy { base_pc: prog.base_pc, words: prog.words.clone() };
    let deploy_fee = wallet::deploy_fee_default(&deploy);
    let slot = proving_slot().await;
    wallet::submit(&rpc, &a, &mut a_store, None, deploy, deploy_fee, Burn::None, FriProfile::Test, &remote, CHAIN_ID, true)
        .await
        .expect("the program deploys, its fee bundle proved at the prover");
    drop(slot);

    let h_in = hash::input_digest(salt, &inputs);
    let (envelope, envelope_key) =
        call_envelope::seal_call_envelope(&a.vk, None, &h_in, salt, &inputs).expect("the transcript seals");
    let action = Action::Call { program: pid, proof, input_envelope: Some(envelope) };
    let slot = proving_slot().await;
    let call = wallet::submit(
        &rpc,
        &a,
        &mut a_store,
        None,
        action,
        wallet::call_fee_default(tier),
        Burn::None,
        FriProfile::Test,
        &remote,
        CHAIN_ID,
        true,
    )
    .await
    .expect("the delegated call is accepted and commits");
    drop(slot);
    let receipt = rpc.wait_for_receipt(&call.hash, Duration::from_secs(120)).await.expect("the call has a receipt");
    // The `H_IN` comes out of the proof the *prover* made, and it is the one the wallet sealed its
    // transcript against — the salt survived the round trip, which is the whole of the §6 path.
    assert_eq!(receipt["h_in"], serde_json::json!(word8_to_hex(&h_in)));
    assert_eq!(receipt["outputs"], serde_json::json!(outputs));

    let (served_h_in, e) = rpc.call_envelope(&call.hash).await.unwrap().expect("the call published a transcript");
    assert_eq!(served_h_in, h_in);
    let (back_key, back_salt, back_inputs) =
        call_envelope::open_call_as_sender(&e, &h_in, &a.vk).expect("A opens the call a prover proved for it");
    assert_eq!(back_inputs, inputs.to_vec());
    assert_eq!((back_salt, back_key), (salt, envelope_key));
    assert!(call_envelope::call_envelope_is_faithful(&h_in, back_salt, &back_inputs));

    eprintln!("whole delegated flow in {:.1?}", started.elapsed());
    handle.shutdown().await;
}

/// A prover that ignores the job and answers with `canned`, sealed properly to the job's reply
/// key — so the only thing wrong with it is *which* computation it proved, and the digest it
/// publishes is one no wallet ever built.
///
/// For a bundle job it answers a bundle result whose digest no wallet built. For a program job it
/// answers the *real* proof of this test's call with a salt that proof was never made with, which
/// is the subtler lie: the proof verifies, the wallet would seal an input transcript against the
/// returned salt, and the `H_IN` the chain reads out of the proof would then commit to something
/// else entirely.
async fn tampering_prover(prover_wallet: &Wallet, canned: Vec<u8>, canned_tier: u8) -> std::net::SocketAddr {
    use axum::{
        extract::State,
        routing::{get, post},
        Json, Router,
    };
    use randprotocol_zkvm::delegate::{self, JobKind, JobResult, ProverKey};
    use std::sync::{Arc, Mutex};

    struct S {
        key: ProverKey,
        canned: Vec<u8>,
        canned_tier: u8,
        last: Mutex<Option<Vec<u8>>>,
        address: String,
    }
    let state = Arc::new(S {
        key: ProverKey::from_viewing_key(&prover_wallet.vk),
        canned,
        canned_tier,
        last: Mutex::new(None),
        address: prover_wallet.address.to_string(),
    });
    let app = Router::new()
        .route(
            "/v1/health",
            get(|State(s): State<Arc<S>>| async move { Json(serde_json::json!({ "address": s.address, "backend": "cpu" })) }),
        )
        .route(
            "/v1/jobs",
            post(|State(s): State<Arc<S>>, body: axum::body::Bytes| async move {
                let job = delegate::open_job(&s.key, &delegate::decode(&body).unwrap()).unwrap();
                let result = match &job.kind {
                    JobKind::Bundle { .. } => JobResult::Bundle { proof: s.canned.clone(), digest: [0xdead_beef; 8], tier: 14 },
                    JobKind::Program { .. } => {
                        JobResult::Program { proof: s.canned.clone(), outputs: [0; 8], tier: s.canned_tier, salt: Some([1, 2, 3, 4]) }
                    }
                };
                *s.last.lock().unwrap() = Some(delegate::encode(&delegate::seal_result(&job.reply_ek, &result).unwrap()));
                (axum::http::StatusCode::ACCEPTED, Json(serde_json::json!({ "id": "00".repeat(16), "position": 1 })))
            }),
        )
        .route("/v1/jobs/:id", get(|| async { Json(serde_json::json!({ "state": "done" })) }))
        .route(
            "/v1/jobs/:id/result",
            get(|State(s): State<Arc<S>>| async move { s.last.lock().unwrap().clone().unwrap() }),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}
