//! The shielded wallet against a real chain: mint, scan, send, scan both sides, spend the change,
//! then make a confidential call and open its input transcript back.
//!
//! One validator node runs in-process (the same `node::start` the cluster tests use) so the
//! whole loop is exercised end to end — a faucet mint lands a note only wallet A's viewing key
//! opens; A proves a real 2-in-2-out bundle; B finds its payment by trial-decrypting the tree;
//! A's spent note comes back marked spent by the chain's own nullifier set; the change note
//! is spendable, which is the part a wallet gets wrong if it forgets its own second output; and a
//! call's private inputs come back off the chain under A's viewing key alone, checked against the
//! `H_IN` its proof published (spec §6.1).
//!
//! Four bundle proofs and one call proof, so this is the slowest test in the workspace by a wide
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

use shrugg_client::wallet::{self, NoteStore, Wallet};
use shrugg_client::RpcClient;
use shrugg_core::genesis::{Genesis, GenesisValidator};
use shrugg_core::notes::word8_to_hex;
use shrugg_core::{format_amount, gas, Action, Keypair, UNITS_PER_SHRUGG};
use shrugg_node::node::{self, NodeConfig, NodeHandle};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::machine::{Backend, FriProfile};
use shrugg_zkvm::notes::SpendKey;
use shrugg_zkvm::{call_envelope, executor, guests, hash};
use std::time::{Duration, Instant};

const CHAIN_ID: u64 = 7;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn,shrugg_node=info".into()))
        .with_test_writer()
        .try_init();
}

fn genesis(validator: &Keypair) -> Genesis {
    Genesis {
        chain_id: CHAIN_ID,
        timestamp_ms: 0,
        validators: vec![GenesisValidator { public_key: validator.public_key().clone(), stake: 10, payout: None }],
        alloc: vec![],
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        // Must be this build's own guest, or `node::start` refuses to run at all.
        hc_bundle: word8_to_hex(&ZkExecutor::hc_bundle()),
        bridge: None,
        epoch_blocks: shrugg_core::genesis::EPOCH_BLOCKS_DEFAULT,
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
        verify: shrugg_node::storage::VerifyMode::Full,
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

    // ---- mint: a validator pays 100 SHRUGG into a note only A can open ----
    let mint = 100 * UNITS_PER_SHRUGG;
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");

    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(a_store.balance(), mint, "A sees the minted note");
    assert_eq!(a_store.spendable().len(), 1);
    // The same leaf is on the chain for everyone; B's viewing key simply does not open it.
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), 0, "B cannot see A's note");
    assert!(b_store.notes.is_empty());

    // ---- send: A pays B 1 SHRUGG, proving a real bundle ----
    let fee = gas::BUNDLE_BASE;
    let pay = UNITS_PER_SHRUGG;
    let first = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the bundle is accepted and commits");
    eprintln!("first bundle: tier {}, proved in {:.1?}, {} proof bytes", first.tier, first.proving, first.proof_bytes);
    assert_eq!(first.amount, pay);
    assert_eq!(first.change, mint - pay - fee);

    // ---- scan both sides ----
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), pay, "B's payment arrived as {} SHRUGG", format_amount(pay));
    assert_eq!(b_store.spendable().len(), 1);

    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    let change = mint - pay - fee;
    assert_eq!(a_store.balance(), change, "A keeps {} SHRUGG as change", format_amount(change));
    assert_eq!(a_store.spendable().len(), 1, "one change note, and the spent one is gone");
    // The spent note is marked from the chain's nullifier set, not from this wallet's guess:
    // `scan` re-reads `shrugg_getNullifiers` and matches `H_NF(nk, cm)`.
    let spent: Vec<u64> = a_store.notes.iter().filter(|n| n.spent).map(|n| n.note.amount).collect();
    assert_eq!(spent, vec![mint], "the 100 SHRUGG note is spent");
    // A also records what it sent, opened through its own outgoing viewing key.
    assert!(a_store.sent.iter().any(|s| s.amount == pay && s.to_pk == b.vk.pk()), "A's history names the payment");

    // ---- the change note is spendable ----
    let second = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the change note pays a second bundle");
    eprintln!("second bundle: tier {}, proved in {:.1?}", second.tier, second.proving);
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(b_store.balance(), 2 * pay, "B has been paid twice");
    assert_eq!(a_store.balance(), mint - 2 * pay - 2 * fee);
    assert_eq!(a_store.spendable().len(), 1, "still exactly one change note");

    // ---- a confidential call whose input transcript A can open back (spec §6.1) ----
    // `balance_check` reads four private words and publishes only whether they reach a threshold,
    // so the transcript is the only record of what it was fed — and it is sealed to A alone.
    let prog = guests::balance_check(1_000);
    let pid = shrugg_core::program::program_id(prog.base_pc, &prog.words);
    let deploy = Action::Deploy { base_pc: prog.base_pc, words: prog.words.clone() };
    let fee = wallet::deploy_fee_default(&deploy);
    wallet::submit(&rpc, &a, &mut a_store, None, deploy, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the program deploys");

    let inputs = [100u32, 200, 300, 400];
    // `prove_call`, not `prove`: it returns the `H_IN` salt, without which the transcript could not
    // be bound to this proof at all.
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
        FriProfile::Test,
        Backend::Cpu,
        CHAIN_ID,
        true,
    )
    .await
    .expect("the call is accepted and commits");
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
