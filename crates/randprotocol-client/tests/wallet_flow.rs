//! The shielded wallet against a real chain: mint, scan, send, scan both sides, spend the change,
//! bond a validator, then make a confidential call and open its input transcript back; and, on a
//! chain with an RPL token registry, register a token, send it privately and burn some of it.
//!
//! One validator node runs in-process (the same `node::start` the cluster tests use) so the
//! whole loop is exercised end to end — a faucet mint lands a note only wallet A's viewing key
//! opens; A proves a real four-slot hidden-asset bundle; B finds its payment by trial-decrypting
//! the tree;
//! A's spent note comes back marked spent by the chain's own nullifier set; the change note
//! is spendable, which is the part a wallet gets wrong if it forgets its own second output; the
//! bond is the one bundle whose value does not land in anybody's note (it burns, and the
//! register's stake is where it turns up instead); and a call's private inputs come back off the
//! chain under A's viewing key alone, checked against the `H_IN` its proof published (spec §6.1).
//!
//! Twelve bundle proofs and three call proofs across the five tests, so this is the slowest test
//! binary in the workspace by a wide margin — minutes, not seconds. The two split-authorisation
//! tests (a v3 chain) add two bundle proofs and two auth proofs, one pair proved by a paired
//! prover. The bridge commands are not here: they need a chain with a
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

use randprotocol_client::wallet::{self, Burn, NoteStore, Wallet, Proving};
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
    genesis_with(validator, None, None)
}

/// The same chain, with the two program caps the public-input test sets (the genesis CLI's
/// `--max-program-words` and `--max-program-public-words`).
fn genesis_with(validator: &Keypair, max_program_words: Option<u32>, max_program_public_words: Option<u32>) -> Genesis {
    genesis_full(validator, max_program_words, max_program_public_words, None)
}

fn genesis_full(
    validator: &Keypair,
    max_program_words: Option<u32>,
    max_program_public_words: Option<u32>,
    tokens: Option<randprotocol_core::genesis::TokensConfig>,
) -> Genesis {
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
        tokens,
        aggregation: None,
        consensus_domain: None,
        staking: None,
        epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
        max_program_words,
        max_proof_bytes: None,
        max_block_bytes: None,
        max_call_envelope_bytes: None,
        max_program_public_words,
        envelope_bytes: None,
        vesting: None,
        gas: None,
        testnet: None,
        // BIND-1: this suite runs the genesis-bound form end to end — chain 7 is not one of the
        // chains cut before `binding_domain`, so the wallet signs and proves nothing else there.
        binding_domain: Some(1),
        proof_window_blocks: None,
        program_state: None,
        multisig: None,
        incremental_nullifier_root: None,
        hardening_v6: None,
        hc_auth: None,
        fees: None,
    }
}

/// The same chain on the branch-free hidden guest (`hc_hidden_bundle_v2`), the one chain 16 pins.
/// The wallet learns the guest from `rand_status.hc_bundle`, so nothing else changes.
fn genesis_v2(validator: &Keypair) -> Genesis {
    Genesis { hc_bundle: word8_to_hex(&ZkExecutor::hc_hidden_bundle_v2()), ..genesis(validator) }
}

/// The same chain under split authorisation (delegated proving Phase 2): bundle guest v3 and the
/// auth guest pinned as `hc_auth` — both or neither, or the node refuses to start. Every
/// transaction then carries two proofs, the bundle's (over `nk`) and the auth proof (over the
/// spend key, always made by the wallet).
fn genesis_v3(validator: &Keypair) -> Genesis {
    Genesis {
        hc_bundle: word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()),
        hc_auth: Some(word8_to_hex(&ZkExecutor::hc_auth())),
        // Room for three proofs at the default 2 MiB proof cap (`gas::min_block_bytes`): a
        // split-authorisation genesis at the 4 MiB default is refused.
        max_block_bytes: Some(7 << 20),
        ..genesis(validator)
    }
}

async fn start(dir: &tempfile::TempDir, key: &Keypair) -> NodeHandle {
    start_with(dir, key, genesis(key)).await
}

async fn start_with(dir: &tempfile::TempDir, key: &Keypair, genesis: Genesis) -> NodeHandle {
    std::fs::write(dir.path().join("genesis.json"), genesis.to_json()).unwrap();
    node::start(NodeConfig {
        viewing_open: false,
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
        min_free_disk_bytes: 0,
        verify_workers: None,
        prune_history: None,
        // Final review I2: the node runs the default gas policy (what `rand-node run` carries
        // unless told `--gas-price 0 --byte-price 0`), so every real call proof in these flows is
        // priced by the pool's `admission::call_floor` over its decoded header, and the wallet
        // pays the policy floor it reads from `rand_getLimits`.
        gas_policy: Some(randprotocol_core::gas::GasPolicy::DEFAULT),
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
    let first = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, "", fee, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
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
    let second = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, "", fee, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
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
        wallet::submit(&rpc, &a, &mut a_store, None, action, fee, Burn::Rand(bond), FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
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
    let deploy = Action::Deploy { base_pc: prog.base_pc, words: prog.words.clone(), public: vec![] };
    let fee = wallet::deploy_fee_default(&deploy);
    let slot = proving_slot().await;
    wallet::submit(&rpc, &a, &mut a_store, None, deploy, fee, Burn::None, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect("the program deploys");
    drop(slot);

    let inputs = [100u32, 200, 300, 400];
    // `prove_call`, not `prove`: it returns the `H_IN` salt, without which the transcript could not
    // be bound to this proof at all. It and the bundle that pays for it are one hold of the proving
    // slot — a program proof is prover work like any other, and the bundle follows it immediately.
    let slot = proving_slot().await;
    let (proof, outputs, tier, salt) =
        executor::prove_call(FriProfile::Test, &prog, &inputs, &[], None, Backend::Cpu, call_envelope::FALLBACK_MAX_CALL_INPUT_WORDS, None)
            .expect("the call proves");
    let h_in = hash::input_digest(salt, &inputs);
    let (envelope, key) = call_envelope::seal_call_envelope(&a.vk, None, &h_in, salt, &inputs, call_envelope::CallCaps::FALLBACK)
        .expect("the transcript seals");
    let header = randprotocol_zkvm::executor::decode_canonical(&proof).expect("the call proof decodes");
    // The node's gas policy, as the wallet reads it: the call pays the policy floor of its header.
    let limits = rpc.limits().await.unwrap().expect("this node reports its limits");
    assert_eq!(limits.gas_policy(), Some(randprotocol_core::gas::GasPolicy::DEFAULT), "the node announces its policy");
    let fee = wallet::call_fee_default(
        Some(&limits),
        tier,
        header.keccak_log_height,
        header.sha256_log_height,
        header.public_values[randprotocol_zkvm::tables::cpu::pv::GAS],
        randprotocol_core::gas::call_bytes(&proof, Some(&envelope)),
    ).unwrap();
    let action = Action::Call { program: pid, proof, input_envelope: Some(envelope) };
    let call = wallet::submit(
        &rpc,
        &a,
        &mut a_store,
        None,
        action,
        fee,
        Burn::None,
        FriProfile::Test,
        &Proving::local(Backend::Cpu),
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

/// Task 9 (spec 2026-09-26 §2.3, §2.4): the memo round trip against a real node. Genesis carries
/// `envelope_bytes: Some(1860)`, so every note-creating envelope in the committed bundle is
/// exactly that long; a real bundle proof still passes because the memo lives outside the proof
/// (`viewing.rs`'s sealed body, not the note or the commitment). The memo is readable by exactly
/// the parties spec §2.3 names: the payee's own scan, the sender's own history row, and anyone
/// handed that output's per-transaction key (`rand_checkTransaction`, `rand tx-key`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_memo_is_read_by_the_payee_the_sender_and_a_disclosed_tx_key() {
    init_tracing();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([103; 32]).unwrap();
    let mut g = genesis(&key);
    g.envelope_bytes = Some(1860);
    let handle = start_with(&dir, &key, g).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));

    let a = Wallet::from_spend_key(SpendKey([7; 8]));
    let b = Wallet::from_spend_key(SpendKey([8; 8]));
    let mut a_store = NoteStore::default();
    let mut b_store = NoteStore::default();

    // ---- mint: A gets 10 RAND to send from ----
    let mint = 10 * UNITS_PER_RAND;
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();

    // ---- send: A pays B 1 RAND with a memo, proving a real bundle under the proving slot ----
    let fee = gas::BUNDLE_BASE;
    let pay = UNITS_PER_RAND;
    let memo = "round trip";
    let slot = proving_slot().await;
    let sent = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, memo, fee, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect("the memo bundle is accepted and commits");
    drop(slot);
    eprintln!("memo bundle: tier {}, proved in {:.1?}, {} proof bytes", sent.tier, sent.proving, sent.proof_bytes);

    // ---- the payee's scan shows the memo ----
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.spendable().len(), 1);
    assert_eq!(b_store.notes[0].memo.as_deref(), Some(memo), "the payee's note carries the memo");

    // ---- the sender's own history row shows it too ----
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    let row = a_store.sent.iter().find(|s| s.amount == pay).expect("the payment is in A's own history");
    assert_eq!(row.memo.as_deref(), Some(memo), "A's history names the memo it sent");

    // ---- a disclosed tx key, from the chain alone, shows it a third time ----
    let tx = rpc.raw_transaction(&sent.hash).await.unwrap().expect("the transaction is committed");
    let rows = wallet::output_keys(&a, &tx);
    let payment = rows
        .iter()
        .find(|r| r.role == wallet::KeyRole::Sent && r.note.amount == pay)
        .expect("A's own output key for the payment slot");
    assert_eq!(payment.memo.as_deref(), Some(memo));
    let disclosed = rpc
        .check_transaction(&sent.hash, &hex::encode(payment.key.0))
        .await
        .unwrap()
        .expect("rand_checkTransaction knows this committed transaction");
    let d = disclosed["disclosed"].as_array().expect("a disclosed array");
    let cm_hex = word8_to_hex(&payment.cm);
    let out = d.iter().find(|o| o["cm"] == serde_json::json!(cm_hex)).expect("the payment output is among the disclosed ones");
    assert_eq!(out["note"]["memo"], serde_json::json!(memo), "rand_checkTransaction discloses the same memo");

    // ---- every envelope in the committed bundle is exactly 1860 bytes (spec §2.4) ----
    let bundle = tx.bundle.as_ref().expect("a plain transfer has a bundle");
    for e in &bundle.envelopes {
        assert_eq!(e.len(), 1860, "envelope_bytes: Some(1860) is enforced on every slot, memo or not");
    }

    handle.shutdown().await;
}

/// A program deployed with a public input (spec §5, §6), end to end on a test-profile chain whose
/// genesis admits 64 public words: `--public` on deploy, a call proved over the public input the
/// wallet fetched back, a receipt carrying `h_pub`, and a call proved against any other public
/// input refused — by the wallet before proving, and by the chain if it is proved anyway.
///
/// `public_echo` sums its four public words and adds `public[1]` again, so the output shows the
/// guest really read the deploy-time words.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_program_with_a_public_input_is_deployed_and_called_over_it() {
    use randprotocol_core::program::program_id_with_public;
    use randprotocol_zkvm::call_envelope::CallCaps;

    init_tracing();
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([102; 32]).unwrap();
    let handle = start_with(&dir, &key, genesis_with(&key, Some(4096), Some(64))).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));
    let a = Wallet::from_spend_key(SpendKey([4; 8]));
    let mut store = NoteStore::default();
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(100 * UNITS_PER_RAND)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");

    // ---- the chain's limits, as the wallet reads them ----
    let limits = rpc.limits().await.unwrap().expect("this node reports its limits");
    assert_eq!((limits.max_program_words, limits.max_program_public_words), (4096, 64));
    let caps = wallet::call_caps(Some(&limits));
    assert_eq!(caps, CallCaps { max_input_words: 4295, max_envelope_bytes: 18_432 });

    // ---- deploy with --public ----
    let public_file = dir.path().join("public.txt");
    std::fs::write(&public_file, "1 2 3 4\n").unwrap();
    let public = wallet::public_file_words(&public_file).unwrap();
    assert_eq!(public, vec![1, 2, 3, 4]);
    let prog = guests::public_echo();
    // Over the chain's 64-word cap: refused by the pre-check, before any proof.
    let e = wallet::deploy_precheck(&rpc, prog.words.len(), 65).await.unwrap_err().to_string();
    assert!(e.contains("max_program_public_words"), "{e}");
    let estimate = wallet::deploy_precheck(&rpc, prog.words.len(), public.len()).await.expect("within the caps");
    let deploy = Action::Deploy { base_pc: prog.base_pc, words: prog.words.clone(), public: public.clone() };
    let fee = wallet::deploy_fee_default(&deploy);
    assert_eq!(fee, estimate, "the node prices the public words as the wallet does");
    assert_eq!(fee, gas::BUNDLE_BASE + gas::deploy_fee(prog.words.len() + public.len()));
    let pid = program_id_with_public(prog.base_pc, &prog.words, &public);
    let slot = proving_slot().await;
    wallet::submit(&rpc, &a, &mut store, None, deploy, fee, Burn::None, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect("the program deploys with its public input");
    drop(slot);
    let shown = rpc.program(&pid).await.unwrap().expect("the program is on chain under its public-input id");
    assert_eq!(shown["public_words_len"], 4);
    let digest = word8_to_hex(&hash::public_digest(&public));
    assert_eq!(shown["public_digest"], serde_json::json!(digest));

    // ---- call: the wallet fetches the public input back and proves over it ----
    let (onchain, fetched) = wallet::load_call_program(&rpc, &pid).await.expect("code and public input check out");
    assert_eq!(fetched, public);
    assert_eq!((onchain.base_pc, &onchain.words), (prog.base_pc, &prog.words));
    let inputs = [9u32];
    let slot = proving_slot().await;
    let (proof, outputs, tier, salt) =
        executor::prove_call(FriProfile::Test, &onchain, &inputs, &fetched, None, Backend::Cpu, caps.max_input_words, None)
            .expect("the call proves");
    assert_eq!(outputs[0], 1 + 2 + 3 + 4 + 2, "the guest read the deploy-time words");
    wallet::check_proof_size(proof.len(), wallet::proof_cap(Some(&limits))).expect("inside the proof cap");
    let h_in = hash::input_digest(salt, &inputs);
    let (envelope, _) = call_envelope::seal_call_envelope(&a.vk, None, &h_in, salt, &inputs, caps).expect("seals");
    let header = randprotocol_zkvm::executor::decode_canonical(&proof).expect("the call proof decodes");
    let fee = wallet::call_fee_default(
        Some(&limits),
        tier,
        header.keccak_log_height,
        header.sha256_log_height,
        header.public_values[randprotocol_zkvm::tables::cpu::pv::GAS],
        gas::call_bytes(&proof, Some(&envelope)),
    ).unwrap();
    let action = Action::Call { program: pid, proof, input_envelope: Some(envelope) };
    let call = wallet::submit(&rpc, &a, &mut store, None, action, fee, Burn::None, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect("the call is accepted and commits");
    drop(slot);
    let receipt = rpc.wait_for_receipt(&call.hash, Duration::from_secs(120)).await.expect("the call has a receipt");
    assert_eq!(receipt["h_pub"], serde_json::json!(digest), "the receipt carries the program's H_PUB");
    assert_eq!(receipt["outputs"], serde_json::json!(outputs));

    // ---- a mismatched public input is refused ----
    let other = [1u32, 2, 3, 5];
    // By the wallet, before proving, when the caller says which public input it expects.
    let e = wallet::check_expected_public(&fetched, &other).unwrap_err().to_string();
    assert!(e.contains("word 3"), "{e}");
    // And by the chain, when a proof over it is made anyway: its H_PUB is not the program's.
    let slot = proving_slot().await;
    let (proof, _, _, _) =
        executor::prove_call(FriProfile::Test, &onchain, &inputs, &other, None, Backend::Cpu, caps.max_input_words, None)
            .expect("a proof over another public input still proves");
    let header = randprotocol_zkvm::executor::decode_canonical(&proof).expect("the call proof decodes");
    let fee = wallet::call_fee_default(Some(&limits), tier, header.keccak_log_height, header.sha256_log_height, header.public_values[randprotocol_zkvm::tables::cpu::pv::GAS], gas::call_bytes(&proof, None)).unwrap();
    let action = Action::Call { program: pid, proof, input_envelope: None };
    let refused = wallet::submit(&rpc, &a, &mut store, None, action, fee, Burn::None, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true).await;
    drop(slot);
    let e = refused.expect_err("the chain refuses a call proved over another public input").to_string();
    assert!(e.contains("PublicValues"), "{e}");

    eprintln!("public-input flow in {:.1?}", started.elapsed());
    handle.shutdown().await;
}

/// The RPL token standard's own commands, end to end (T8b): `token create` (`Key` authority, no
/// initial mint) registers A's authority, `token mint` mints A's supply against it, `send
/// --asset rpl1…` (the id resolved through the whole `rand_getTokens` listing, never a per-token
/// lookup) pays part of it to B in a plain bundle, `token burn` destroys part of the rest, and
/// `token info` reads the row back with the supply and nonce both moved. B, holding the token but
/// no RAND, is refused before proving when it tries to pay it on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_token_is_created_minted_sent_privately_burned_and_read_back() {
    use randprotocol_core::genesis::{TokensConfig, MIN_REGISTRATION_FEE};

    init_tracing();
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([103; 32]).unwrap();
    let tokens = TokensConfig { registration_fee: MIN_REGISTRATION_FEE, mint_cap_per_day: 0, max_tokens: None, burn_registration_fee: None, bound_note_value: None, incremental_root: None, tokens: vec![] };
    let handle = start_with(&dir, &key, genesis_full(&key, None, None, Some(tokens))).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));
    let a = Wallet::from_spend_key(SpendKey([5; 8]));
    let b = Wallet::from_spend_key(SpendKey([6; 8]));
    let (mut a_store, mut b_store) = (NoteStore::default(), NoteStore::default());
    let mint = 100 * UNITS_PER_RAND;
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");

    // ---- `token create`: a `Key`-authorised token, registering empty ----
    // `wallet::create_token` is `rand token create`'s own function (T8b review round 1's fix):
    // the fresh authority key goes to `<authority_out>.pending` before the one call that can
    // refuse the registration, and is promoted to `authority_out` only once it is accepted.
    let authority = Keypair::generate();
    let authority_out = dir.path().join("authority.key.json");
    let cpu = Proving::local(Backend::Cpu);
    let created = wallet::create_token(
        &rpc,
        &a,
        &mut a_store,
        "Wallet Flow Dollar",
        "WFD",
        6,
        Some((&authority, authority_out.as_path())),
        None,
        None,
        [7; 32],
        None,
        FriProfile::Test,
        &cpu,
        CHAIN_ID,
        true,
    );
    let slot = proving_slot().await;
    let created = created.await.expect("the registration's bundle commits");
    drop(slot);
    assert_eq!(created.index, 1);
    assert_eq!(created.fee, gas::BUNDLE_BASE + MIN_REGISTRATION_FEE);
    let register_fee = created.fee;
    eprintln!("register bundle: tier {}, proved in {:.1?}", created.submission.tier, created.submission.proving);
    assert_eq!(a_store.balance_of(1), 0, "registering empty mints nothing yet");
    assert_eq!(a_store.balance(), mint - register_fee);
    assert!(authority_out.exists(), "the accepted registration promoted the pending authority key");
    assert!(!wallet::pending_authority_key_path(&authority_out).exists(), "no leftover .pending file");

    // ---- `token mint`: A mints its own supply against the authority key ----
    let supply = 1_000_000u64;
    // The slot before the build, not after: `build_token_mint` stamps the note's `time` with the
    // head height, and a wait for the slot behind other tests' proofs (~230 s each at constraint
    // set 7 on a shared box) outran its window — "time 82 is outside [160, 416]" (v0.6.1 suite).
    let slot = proving_slot().await;
    let row = wallet::find_token_row(&rpc, "1").await.unwrap();
    let domain = wallet::binding_domain(&rpc, &a, &mut a_store, CHAIN_ID).await.expect("the chain binds its genesis");
    assert_eq!(domain, randprotocol_core::BindingDomain::Genesis(rpc.genesis_hash().await.unwrap()), "BIND-1: genesis-bound on chain 7");
    let mint_action = wallet::build_token_mint(&rpc, &a, &domain, CHAIN_ID, 1, &row, &a.address, supply, &authority)
        .await
        .expect("the authority mints against its own token");
    assert!(matches!(&mint_action, Action::TokenMint { asset: 1, amount: 1_000_000, nonce: 0, .. }));
    let minted = wallet::submit_token_mint(&rpc, &a, &mut a_store, mint_action, gas::BUNDLE_BASE, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect("the mint's bundle commits");
    drop(slot);
    eprintln!("mint bundle: tier {}, proved in {:.1?}", minted.tier, minted.proving);
    assert_eq!(a_store.balance_of(1), supply, "the sealed mint note is found by the ordinary scan");
    let after_register_and_mint = mint - register_fee - gas::BUNDLE_BASE;
    assert_eq!(a_store.balance(), after_register_and_mint);

    // ---- `send --asset rpl1…`: the id resolved through the whole listing, never a lookup ----
    let row = wallet::find_token_row(&rpc, "1").await.unwrap();
    let id_text = row["id_text"].as_str().unwrap().to_string();
    assert!(id_text.starts_with("rpl1"));
    let resolved = wallet::resolve_asset(&rpc, &id_text).await.expect("resolved from the whole rand_getTokens listing");
    assert_eq!(resolved, 1);
    let pay = 400_000u64;
    let slot = proving_slot().await;
    let sent =
        wallet::send_asset(&rpc, &a, &mut a_store, &b.address, resolved, pay, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
            .await
            .expect("the token transfer commits");
    drop(slot);
    eprintln!("token bundle: tier {}, proved in {:.1?}, {} proof bytes", sent.tier, sent.proving, sent.proof_bytes);
    assert_eq!((sent.amount, sent.change, sent.asset), (pay, supply - pay, 1));
    // What everyone else sees: a plain transaction whose bundle burns nothing and names no asset.
    let shown = rpc.raw_transaction(&sent.hash).await.unwrap().expect("committed");
    assert_eq!(shown.action, Action::None);
    let bundle = shown.bundle.as_ref().expect("a bundle");
    assert_eq!((bundle.burn_a, bundle.burn_r, bundle.burn_asset), (0, 0, 0));
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance_of(1), pay, "B holds the token");
    assert_eq!(b_store.balance(), 0, "and no RAND");
    assert_eq!(a_store.balance_of(1), supply - pay);
    assert_eq!(a_store.balance(), after_register_and_mint - gas::BUNDLE_BASE);

    // ---- B cannot pay it on without RAND for the fee: refused before any proof ----
    let e = wallet::send_asset(&rpc, &b, &mut b_store, &a.address, 1, 1, "", gas::BUNDLE_BASE, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect_err("no RAND, no transfer")
        .to_string();
    assert!(e.contains("fee in RAND"), "{e}");

    // ---- `token burn`: A burns 100 000, the token's supply drops by exactly that ----
    let burn = 100_000u64;
    let slot = proving_slot().await;
    let burned =
        wallet::submit_token_burn(&rpc, &a, &mut a_store, 1, burn, gas::BUNDLE_BASE, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
            .await
            .expect("the token burn commits");
    drop(slot);
    assert_eq!((burned.amount, burned.burn), (burn, Burn::Asset { index: 1, amount: burn }));
    let shown = rpc.raw_transaction(&burned.hash).await.unwrap().expect("committed");
    assert_eq!(shown.action, Action::TokenBurn { asset: 1, amount: burn });
    let bundle = shown.bundle.as_ref().expect("a bundle");
    assert_eq!((bundle.burn_a, bundle.burn_r, bundle.burn_asset), (burn, 0, 1));
    assert_eq!(a_store.balance_of(1), supply - pay - burn);

    // ---- `token info`: the row reads back the moved supply and the spent mint nonce ----
    let row = wallet::find_token_row(&rpc, &id_text).await.unwrap();
    assert_eq!(row["total_supply"], (supply - burn).to_string());
    assert_eq!(row["mint_nonce"], 1, "one TokenMint spent the authority's nonce once");
    assert_eq!(row["authority"]["kind"], "key");
    assert_eq!(row["authority"]["key"], authority.public_key().to_hex());

    eprintln!("token flow in {:.1?}", started.elapsed());
    handle.shutdown().await;
}

/// One validator's bonded stake, as `rand_getValidators` reports it: amounts go out as decimal
/// strings, since a stake in units does not fit a JSON number safely.
/// VK-4 (audit v6, decision D33) — this was the Phase 1 end to end, a spend-key witness proved by
/// an `own` prover on a chain that pins the v2 guest; that witness path is retired. Against a real
/// node on a v2-guest chain and a real prover service behind its listener, paired with `own=1`: a
/// send through the prover is refused before the prover is sent anything (its queue stays empty)
/// and before anything is proved or submitted — so this test takes no proving slot — and the
/// wallet's RAND is untouched. Proving on this machine on such a chain is every other test here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pre_v3_chain_refuses_a_paired_prover_before_anything_is_sent() {
    init_tracing();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([107; 32]).unwrap();
    let handle = start_with(&dir, &key, genesis_v2(&key)).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));

    // ---- the prover: its own key, one pairing whose link says own=1 ----
    let pkey = randprotocol_prover::key::ProverKey::generate();
    let ek = pkey.kem_ek().to_vec();
    let mut pairings = randprotocol_prover::pairing::Pairings::default();
    let token = pairings.pair("laptop", true).unwrap();
    let cfg = randprotocol_prover::service::Config::new(pkey, pairings);
    let (paddr, svc, _ptask) = randprotocol_prover::http::serve("127.0.0.1:0".parse().unwrap(), cfg).await.expect("the prover listens");
    let link = randprotocol_prover::pairing::PairingLink { kem_ek: ek, url: format!("http://{paddr}"), token, own: true };
    let paired = randprotocol_client::prover::PairedProver::from_link(&link, Some("laptop".into()));
    let remote = std::sync::Arc::new(randprotocol_client::prover::RemoteProver::new(paired));
    let proving = Proving::Remote(remote.clone());

    // ---- fund A, try to send to B through the prover ----
    let a = Wallet::from_spend_key(SpendKey([21; 8]));
    let b = Wallet::from_spend_key(SpendKey([22; 8]));
    let mut a_store = NoteStore::default();
    let mint = 100 * UNITS_PER_RAND;
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(a_store.balance(), mint);

    let e = wallet::send(&rpc, &a, &mut a_store, &b.address, UNITS_PER_RAND, "", gas::BUNDLE_BASE, FriProfile::Test, &proving, CHAIN_ID, true)
        .await
        .expect_err("a paired prover on a v2-guest chain");
    assert_eq!(e.to_string(), randprotocol_client::prover::PRE_V3_REFUSAL);
    assert_eq!(wallet::prover_confirmation(&rpc, &proving).await.unwrap_err().to_string(), randprotocol_client::prover::PRE_V3_REFUSAL, "and before `rand send`'s y/N");
    let info = svc.info();
    assert_eq!((info.queue.depth, info.queue.proving), (0, 0), "the prover was sent no job");
    assert!(!remote.warned_history(), "and the wallet warned of no witness: none was headed anywhere");
    assert_eq!(a_store.balance(), mint, "nothing is held back as pending");
    assert_eq!(info.witness_kinds, vec!["viewing_key"], "the prover takes no spend-key witness either");
    handle.shutdown().await;
}

/// Split authorisation, the wallet's end to end: on a v3 chain `send` draws a fresh salt, builds
/// the v3 witness, proves the bundle and the auth proof against the same binding, and the node
/// admits the pair; the payee finds the note and the payer's change comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_v3_send_proves_both_and_is_admitted() {
    init_tracing();
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([108; 32]).unwrap();
    let handle = start_with(&dir, &key, genesis_v3(&key)).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));

    let a = Wallet::from_spend_key(SpendKey([23; 8]));
    let b = Wallet::from_spend_key(SpendKey([24; 8]));
    let mut a_store = NoteStore::default();
    let mut b_store = NoteStore::default();
    let mint = 100 * UNITS_PER_RAND;
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(a_store.balance(), mint);

    let fee = gas::BUNDLE_BASE;
    let pay = UNITS_PER_RAND;
    let slot = proving_slot().await;
    let sub = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, "", fee, FriProfile::Test, &Proving::local(Backend::Cpu), CHAIN_ID, true)
        .await
        .expect("the v3 transaction is accepted and commits");
    drop(slot);
    let auth = sub.auth_proving.expect("a v3 send makes the auth proof");
    eprintln!("v3 local: bundle tier {} in {:.1?} ({} bytes), auth in {auth:.1?}", sub.tier, sub.proving, sub.proof_bytes);
    eprintln!("{}", sub.summary("transfer"));
    assert!(sub.summary("transfer").contains("(auth)"), "the summary reports both proving times");
    assert_eq!((sub.tier, sub.amount, sub.change), (14, pay, mint - pay - fee));

    let shown = rpc.raw_transaction(&sub.hash).await.unwrap().expect("committed");
    let bundle = shown.bundle.as_ref().expect("a bundle");
    assert_ne!(bundle.auth_commit, [0; 8], "a v3 bundle commits to its salt");
    assert!(!bundle.auth_proof.is_empty(), "and carries its auth proof");

    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), pay, "B received the payment");
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(a_store.balance(), mint - pay - fee, "A keeps its change");
    eprintln!("v3 send end to end in {:.1?}", started.elapsed());
    handle.shutdown().await;
}

/// Split authorisation through a delegated prover — the only delegated proving there is (VK-4):
/// the prover is paired as not the owner's own (`own=0`), and on a v3 chain the wallet sends it the
/// viewing-key witness (`nk`, never the spend key), warns once that it can read this wallet's
/// history, makes the auth proof itself, and the node admits the pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_v3_send_through_a_viewing_key_prover_is_admitted() {
    init_tracing();
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([109; 32]).unwrap();
    let handle = start_with(&dir, &key, genesis_v3(&key)).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));

    // ---- the prover: its own key, one pairing that is NOT the owner's ----
    let pkey = randprotocol_prover::key::ProverKey::generate();
    let ek = pkey.kem_ek().to_vec();
    let mut pairings = randprotocol_prover::pairing::Pairings::default();
    let token = pairings.pair("friend", false).unwrap();
    let cfg = randprotocol_prover::service::Config::new(pkey, pairings);
    let (paddr, _svc, _ptask) = randprotocol_prover::http::serve("127.0.0.1:0".parse().unwrap(), cfg).await.expect("the prover listens");
    let link = randprotocol_prover::pairing::PairingLink { kem_ek: ek, url: format!("http://{paddr}"), token, own: false };
    let paired = randprotocol_client::prover::PairedProver::from_link(&link, Some("friend".into()));
    let remote = std::sync::Arc::new(randprotocol_client::prover::RemoteProver::new(paired));
    let proving = Proving::Remote(remote.clone());

    let a = Wallet::from_spend_key(SpendKey([25; 8]));
    let b = Wallet::from_spend_key(SpendKey([26; 8]));
    let mut a_store = NoteStore::default();
    let mut b_store = NoteStore::default();
    let mint = 100 * UNITS_PER_RAND;
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(a_store.balance(), mint);

    let fee = gas::BUNDLE_BASE;
    let pay = UNITS_PER_RAND;
    let slot = proving_slot().await;
    let sub = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, "", fee, FriProfile::Test, &proving, CHAIN_ID, true)
        .await
        .expect("the delegated v3 transaction is accepted and commits");
    drop(slot);
    let auth = sub.auth_proving.expect("the wallet made the auth proof itself");
    eprintln!("v3 remote: bundle tier {} in {:.1?} ({} bytes, remote), auth in {auth:.1?} (local)", sub.tier, sub.proving, sub.proof_bytes);
    assert!(remote.warned_history(), "the wallet warned: {}", randprotocol_client::prover::VIEWING_KEY_WARNING);
    assert_eq!((sub.tier, sub.amount, sub.change), (14, pay, mint - pay - fee));

    let shown = rpc.raw_transaction(&sub.hash).await.unwrap().expect("committed");
    let bundle = shown.bundle.as_ref().expect("a bundle");
    assert_ne!(bundle.auth_commit, [0; 8]);
    assert!(!bundle.auth_proof.is_empty());

    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), pay, "B received the note the prover's proof carried");
    wallet::scan(&rpc, &a, &mut a_store).await.unwrap();
    assert_eq!(a_store.balance(), mint - pay - fee, "A keeps its change");
    eprintln!("delegated v3 send end to end in {:.1?}", started.elapsed());
    handle.shutdown().await;
}

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

/// Coin selection refuses what a four-slot bundle cannot do, before any proving starts.
#[test]
fn a_wallet_that_cannot_pay_says_so_without_proving() {
    let a = Wallet::from_spend_key(SpendKey([3; 8]));
    let store = NoteStore::default();
    assert_eq!(store.balance(), 0);
    assert_eq!(a.address.pk, a.vk.pk());
    let err = wallet::select_inputs(&store.spendable(), 1).unwrap_err();
    assert_eq!(err, wallet::SelectError::Insufficient { have: 0 });
}

/// The chain RPL-2 runs on: split authorisation (`genesis_v3`), a token registry, a fixed-price
/// `gas` section, the v0.6 rules and the `program_state` section with a 0.01 RAND cell fee —
/// every section the feature stands on (`Genesis::validate` refuses it otherwise).
fn genesis_rpl2(validator: &Keypair) -> Genesis {
    use randprotocol_core::genesis::{TokensConfig, MIN_REGISTRATION_FEE};
    use randprotocol_core::ledger::program_state::ProgramStateConfig;
    Genesis {
        tokens: Some(TokensConfig {
            registration_fee: MIN_REGISTRATION_FEE,
            mint_cap_per_day: 0,
            max_tokens: None,
            burn_registration_fee: None,
            bound_note_value: None, incremental_root: None,
            tokens: vec![],
        }),
        gas: Some(gas::GasConfig {
            gas_price: 100,
            byte_price: 800,
            bundle_gas_limit: gas::bundle_gas_limit_pin(),
            metering: gas::GasMetering::Circuit,
            dynamic: None,
        }),
        hardening_v6: Some(true),
        program_state: Some(ProgramStateConfig { cell_fee: RPL2_CELL_FEE }),
        multisig: None,
        // BIND-1, pinned here rather than inherited: chain 20, the first that can carry RPL-2, is
        // cut with `binding_domain: 1`, so the real-proof invoke is proved and verified in the
        // genesis-bound form.
        binding_domain: Some(1),
        ..genesis_v3(validator)
    }
}

const RPL2_CELL_FEE: u64 = UNITS_PER_RAND / 100;

/// RPL-2 end to end, with real proofs: on the chain above, A deploys the counter guest,
/// registers a fixed-supply token it holds (token 1) and the counter's own program token
/// (token 2), then makes ONE invoke that reads the counter's cell (absent), writes it to 1,
/// deposits 5 RAND and 300 of token 1 into the counter's vault, pays 2 of that RAND to B and
/// mints 40 of token 2 to itself — three proofs, the call's over the transition's context. The
/// cell, the vault, token 2's supply, the receipt's outputs, both wallets' scans (B's payout and
/// A's mint found by the ordinary trial decryption of the commitment feed, the node having
/// served the derived notes) and the supply identity are all checked. Then a second invoke
/// declaring the read the chain has moved past is refused with the stale-read verdict — before
/// any proof of it is looked at, which is the point of the segment being built from the
/// transaction: the read check is the one thing that depends on state, so the second invoke is
/// sent with its proofs empty and the chain still answers `StaleRead`.
///
/// Seven proofs (a bundle and an auth proof each for the deploy and the two registrations, plus
/// the invoke's three), so this is the slowest test in the binary; it sits last for that reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invoke_moves_a_cell_fills_a_vault_pays_out_and_mints_end_to_end() {
    use randprotocol_core::genesis::MIN_REGISTRATION_FEE;
    use randprotocol_core::ledger::program_state::{payout_commitment, Cell, Inflow, PROGRAM_FROM};
    use randprotocol_core::program::program_id;

    init_tracing();
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([109; 32]).unwrap();
    let handle = start_with(&dir, &key, genesis_rpl2(&key)).await;
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));
    let a = Wallet::from_spend_key(SpendKey([31; 8]));
    let b = Wallet::from_spend_key(SpendKey([32; 8]));
    let (mut a_store, mut b_store) = (NoteStore::default(), NoteStore::default());
    let mint = 100 * UNITS_PER_RAND;
    let hash = rpc.mint_shielded(&a.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");
    let limits = rpc.limits().await.unwrap().expect("this node reports its limits");
    let ps = limits.program_state.expect("the chain has the program_state section");
    assert_eq!((ps.cell_fee, ps.max_reads, ps.max_writes, ps.max_payouts), (RPL2_CELL_FEE, 8, 8, 4));
    assert!(limits.hardening_v6 && limits.gas_circuit, "the sections the feature stands on");
    let cpu = Proving::local(Backend::Cpu);

    // ---- deploy the counter ----
    let prog = guests::rpl2_counter();
    let pid = program_id(prog.base_pc, &prog.words);
    let deploy = Action::Deploy { base_pc: prog.base_pc, words: prog.words.clone(), public: vec![] };
    let deploy_fee = wallet::deploy_fee_default(&deploy);
    let slot = proving_slot().await;
    let deployed = wallet::submit(&rpc, &a, &mut a_store, None, deploy, deploy_fee, Burn::None, FriProfile::Test, &cpu, CHAIN_ID, true)
        .await
        .expect("the counter deploys");
    drop(slot);
    eprintln!("deploy: tier {}, proved in {:.1?} + auth {:?}", deployed.tier, deployed.proving, deployed.auth_proving);
    assert!(rpc.program(&pid).await.unwrap().is_some());
    assert_eq!(rpc.program_vault(&pid).await.unwrap(), Some(vec![]), "an empty vault");
    let k = Cell { key: [7, 0, 0, 0, 0, 0, 0, 0], value: [0; 8] };
    assert_eq!(rpc.program_cell(&pid, &k.key).await.unwrap(), Some([0; 8]), "the cell is absent");

    // ---- token 1: a fixed supply A holds; token 2: the counter's own ----
    let supply = 1_000_000u64;
    let slot = proving_slot().await;
    let held = wallet::create_token(&rpc, &a, &mut a_store, "Held Coin", "HLD", 0, None, None, Some((supply, a.address.clone())), [8; 32], None, FriProfile::Test, &cpu, CHAIN_ID, true)
        .await
        .expect("token 1 registers with its supply");
    drop(slot);
    assert_eq!(held.index, 1);
    assert_eq!(a_store.balance_of(1), supply, "A holds the initial mint");
    let slot = proving_slot().await;
    let own = wallet::create_token(&rpc, &a, &mut a_store, "Counter Share", "CTR", 0, None, Some(pid), None, [9; 32], None, FriProfile::Test, &cpu, CHAIN_ID, true)
        .await
        .expect("the program token registers");
    drop(slot);
    assert_eq!(own.index, 2);
    let row = wallet::find_token_row(&rpc, "2").await.unwrap();
    assert_eq!(row["authority"], serde_json::json!({ "kind": "program", "program": pid.to_hex() }));
    assert_eq!(row["total_supply"], "0");
    let fees_so_far = deploy_fee + 2 * (gas::BUNDLE_BASE + MIN_REGISTRATION_FEE);
    assert_eq!(a_store.balance(), mint - fees_so_far);

    // ---- the invoke ----
    let deposit_rand = 5 * UNITS_PER_RAND;
    let deposit_token = 300u64;
    let pay_b = 2 * UNITS_PER_RAND;
    let mint_ctr = 40u64;
    let plan = wallet::InvokePlan {
        program: pid,
        reads: vec![k],
        writes: vec![Cell { key: k.key, value: [1, 0, 0, 0, 0, 0, 0, 0] }],
        inflow: Inflow::Deposit,
        pays: vec![wallet::PayoutRequest { asset: 0, amount: pay_b, to: b.address.clone() }],
        mints: vec![wallet::PayoutRequest { asset: 2, amount: mint_ctr, to: a.address.clone() }],
        burn_r: deposit_rand,
        burn_asset: 1,
        burn_a: deposit_token,
        input_envelope: None,
        created_cells: 1,
    };
    // The dry run over the real context words, eight zeros for the binding: the tier, the gas.
    let probe = randprotocol_core::ledger::program_state::Transition {
        reads: plan.reads.clone(),
        writes: plan.writes.clone(),
        inflow: plan.inflow,
        pays: vec![randprotocol_core::ledger::program_state::Payout { asset: 0, amount: pay_b, recipient: b.address.clone(), r: [0; 8], envelope: randprotocol_core::notes::Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] } }],
        mints: vec![randprotocol_core::ledger::program_state::Payout { asset: 2, amount: mint_ctr, recipient: a.address.clone(), r: [0; 8], envelope: randprotocol_core::notes::Envelope { kem_ct: vec![], to_receiver: vec![], to_sender: vec![], body: vec![] } }],
    }
    .context(deposit_rand, 1, deposit_token);
    let segment = [&[0u32; 8][..], &probe].concat();
    let run = executor::dry_run_call(&prog, &[], &segment).expect("the counter accepts 0 → 1");
    let tier = run.tier;
    let fee = wallet::call_fee_default(Some(&limits), tier, 0, 0, run.gas_max(), wallet::hardened_call_quote_bytes(Some(&limits), 0)).unwrap() + RPL2_CELL_FEE;
    let salt = executor::fresh_call_salt();
    let proved_at = std::sync::Mutex::new(None);
    let prove = |binding: &[u32; 8], context: &[u32]| -> anyhow::Result<Vec<u8>> {
        let t = Instant::now();
        let (proof, outputs, tier) = executor::prove_invoke(FriProfile::Test, &prog, &[], &[], binding, context, salt, Some(tier), None).map_err(|e| anyhow::anyhow!(e))?;
        eprintln!("invoke call proof: tier {tier}, {} bytes, outputs {outputs:?}, proved in {:.1?}", proof.len(), t.elapsed());
        *proved_at.lock().unwrap() = Some((t.elapsed(), proof.len(), tier, outputs));
        Ok(proof)
    };
    let slot = proving_slot().await;
    let (s, transition) = wallet::submit_bound_invoke(&rpc, &a, &mut a_store, &plan, fee, &prove, Some(&limits), FriProfile::Test, &cpu, CHAIN_ID, true)
        .await
        .expect("the invoke is admitted and commits");
    drop(slot);
    eprintln!("invoke bundle: tier {}, proved in {:.1?} ({} bytes), auth {:?}; call {:?}", s.tier, s.proving, s.proof_bytes, s.auth_proving, proved_at.lock().unwrap());
    eprintln!("{}", s.summary("invoke"));
    assert_eq!(s.burn, Burn::Both { rand: deposit_rand, index: 1, amount: deposit_token });
    assert_eq!((s.asset, s.amount, s.change), (1, deposit_token, supply - deposit_token));

    // The cell, the vault, the supply, the receipt.
    assert_eq!(rpc.program_cell(&pid, &k.key).await.unwrap(), Some([1, 0, 0, 0, 0, 0, 0, 0]));
    let (cells, next) = rpc.program_cells(&pid, None, 10).await.unwrap().unwrap();
    assert_eq!((cells, next), (vec![Cell { key: k.key, value: [1, 0, 0, 0, 0, 0, 0, 0] }], None));
    assert_eq!(rpc.program_vault(&pid).await.unwrap(), Some(vec![(0, deposit_rand - pay_b), (1, deposit_token)]));
    let row = wallet::find_token_row(&rpc, "2").await.unwrap();
    assert_eq!(row["total_supply"], mint_ctr.to_string(), "the program minted its token");
    let receipt = rpc.wait_for_receipt(&s.hash, Duration::from_secs(120)).await.expect("an invoke has a call's receipt");
    assert_eq!(receipt["outputs"][0], 1, "the counter's new count");
    assert_eq!(receipt["program"], pid.to_hex());
    let shown = rpc.call("rand_getTransaction", serde_json::json!([s.hash.to_hex()])).await.unwrap();
    assert_eq!(shown["tx"]["action"]["kind"], "invoke");
    assert_eq!(shown["tx"]["action"]["transition"]["inflow"], "deposit");
    assert_eq!(shown["tx"]["bundle"]["burn_r"], deposit_rand.to_string());
    let zk = ZkExecutor::new(FriProfile::Test);
    let time = shown["tx"]["bundle"]["time"].as_u64().unwrap() as u32;
    assert_eq!(time, s.time);
    let pay_cm = payout_commitment(&transition.pays[0], time, &zk);
    let mint_cm = payout_commitment(&transition.mints[0], time, &zk);
    assert_eq!(shown["tx"]["action"]["transition"]["pays"][0]["cm"], word8_to_hex(&pay_cm));
    assert_eq!(shown["tx"]["action"]["transition"]["mints"][0]["cm"], word8_to_hex(&mint_cm));

    // Both recipients find their notes by the ordinary scan: the node served the derived leaves
    // with the payouts' own envelopes in the commitment feed.
    wallet::scan(&rpc, &b, &mut b_store).await.unwrap();
    assert_eq!(b_store.balance(), pay_b, "B was paid out of the vault");
    let paid = b_store.notes.iter().find(|n| n.cm == pay_cm).expect("at the leaf the chain appended");
    assert_eq!((paid.note.from, paid.note.time, paid.note.amount), (PROGRAM_FROM, time, pay_b));
    assert_eq!(a_store.balance_of(2), mint_ctr, "A holds what the program minted");
    assert!(a_store.notes.iter().any(|n| n.cm == mint_cm));
    assert_eq!(a_store.balance_of(1), supply - deposit_token, "300 of token 1 went into the vault");
    assert_eq!(a_store.balance(), mint - fees_so_far - s.fee - deposit_rand, "the fee and the RAND deposit left A");
    let supply_json = rpc.call("rand_getSupply", serde_json::json!([])).await.unwrap();
    assert_eq!(supply_json["program_rand_held"], (deposit_rand - pay_b).to_string());
    assert_eq!(supply_json["program_rand_out"], pay_b.to_string());
    assert_eq!(supply_json["invariant_holds"], true, "{supply_json}");

    // ---- a second invoke against the value the chain has moved past: StaleRead, no proof read ----
    let (head, anchor) = rpc.anchor(None).await.unwrap();
    let stale = randprotocol_core::Transaction::shielded(
        CHAIN_ID,
        randprotocol_core::notes::Bundle {
            anchor,
            nullifiers: [[0xa1; 8], [0xa2; 8], [0xa3; 8], [0xa4; 8]],
            commitments: [[0xb1; 8], [0xb2; 8], [0xb3; 8], [0xb4; 8]],
            fee,
            burn_a: 0,
            burn_r: 0,
            burn_asset: 0,
            time: head as u32,
            envelopes: std::array::from_fn(|_| transition.pays[0].envelope.clone()),
            proof: Vec::new(),
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        },
        Action::Invoke {
            program: pid,
            proof: Vec::new(),
            input_envelope: None,
            transition: randprotocol_core::ledger::program_state::Transition { pays: vec![], mints: vec![], inflow: Inflow::None, ..transition.clone() },
        },
    );
    let e = rpc.send_transaction(&stale).await.expect_err("the read the chain has moved past is refused").to_string();
    assert!(e.contains("is no longer what this transition read"), "{e}");
    eprintln!("rpl2 flow in {:.1?}", started.elapsed());
    handle.shutdown().await;
}
