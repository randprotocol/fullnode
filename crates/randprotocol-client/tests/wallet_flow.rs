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
//! Eleven bundle proofs and three call proofs across the three tests, so this is the slowest test
//! binary in the workspace by a wide margin — minutes, not seconds. The bridge commands are not here: they need a chain with a
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
    let first = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
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
    let second = wallet::send(&rpc, &a, &mut a_store, &b.address, pay, fee, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
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
        wallet::submit(&rpc, &a, &mut a_store, None, action, fee, Burn::Rand(bond), FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
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
    wallet::submit(&rpc, &a, &mut a_store, None, deploy, fee, Burn::None, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect("the program deploys");
    drop(slot);

    let inputs = [100u32, 200, 300, 400];
    // `prove_call`, not `prove`: it returns the `H_IN` salt, without which the transcript could not
    // be bound to this proof at all. It and the bundle that pays for it are one hold of the proving
    // slot — a program proof is prover work like any other, and the bundle follows it immediately.
    let slot = proving_slot().await;
    let (proof, outputs, tier, salt) =
        executor::prove_call(FriProfile::Test, &prog, &inputs, &[], None, Backend::Cpu, call_envelope::FALLBACK_MAX_CALL_INPUT_WORDS)
            .expect("the call proves");
    let h_in = hash::input_digest(salt, &inputs);
    let (envelope, key) = call_envelope::seal_call_envelope(&a.vk, None, &h_in, salt, &inputs, call_envelope::CallCaps::FALLBACK)
        .expect("the transcript seals");
    let fee = wallet::call_fee_default(tier, randprotocol_core::gas::call_bytes(&proof, Some(&envelope)));
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
        Backend::Cpu,
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
    wallet::submit(&rpc, &a, &mut store, None, deploy, fee, Burn::None, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
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
        executor::prove_call(FriProfile::Test, &onchain, &inputs, &fetched, None, Backend::Cpu, caps.max_input_words)
            .expect("the call proves");
    assert_eq!(outputs[0], 1 + 2 + 3 + 4 + 2, "the guest read the deploy-time words");
    wallet::check_proof_size(proof.len(), wallet::proof_cap(Some(&limits))).expect("inside the proof cap");
    let h_in = hash::input_digest(salt, &inputs);
    let (envelope, _) = call_envelope::seal_call_envelope(&a.vk, None, &h_in, salt, &inputs, caps).expect("seals");
    let fee = wallet::call_fee_default(tier, gas::call_bytes(&proof, Some(&envelope)));
    let action = Action::Call { program: pid, proof, input_envelope: Some(envelope) };
    let call = wallet::submit(&rpc, &a, &mut store, None, action, fee, Burn::None, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
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
        executor::prove_call(FriProfile::Test, &onchain, &inputs, &other, None, Backend::Cpu, caps.max_input_words)
            .expect("a proof over another public input still proves");
    let fee = wallet::call_fee_default(tier, gas::call_bytes(&proof, None));
    let action = Action::Call { program: pid, proof, input_envelope: None };
    let refused = wallet::submit(&rpc, &a, &mut store, None, action, fee, Burn::None, FriProfile::Test, Backend::Cpu, CHAIN_ID, true).await;
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
    let tokens = TokensConfig { registration_fee: MIN_REGISTRATION_FEE, mint_cap_per_day: 0, max_tokens: None, tokens: vec![] };
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
    let created = wallet::create_token(
        &rpc,
        &a,
        &mut a_store,
        "Wallet Flow Dollar",
        "WFD",
        6,
        Some((&authority, authority_out.as_path())),
        None,
        [7; 32],
        None,
        FriProfile::Test,
        Backend::Cpu,
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
    let row = wallet::find_token_row(&rpc, "1").await.unwrap();
    let mint_action = wallet::build_token_mint(&rpc, &a, CHAIN_ID, 1, &row, &a.address, supply, &authority)
        .await
        .expect("the authority mints against its own token");
    assert!(matches!(&mint_action, Action::TokenMint { asset: 1, amount: 1_000_000, nonce: 0, .. }));
    let slot = proving_slot().await;
    let minted = wallet::submit_token_mint(&rpc, &a, &mut a_store, mint_action, gas::BUNDLE_BASE, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
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
        wallet::send_asset(&rpc, &a, &mut a_store, &b.address, resolved, pay, gas::BUNDLE_BASE, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
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
    let e = wallet::send_asset(&rpc, &b, &mut b_store, &a.address, 1, 1, gas::BUNDLE_BASE, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
        .await
        .expect_err("no RAND, no transfer")
        .to_string();
    assert!(e.contains("fee in RAND"), "{e}");

    // ---- `token burn`: A burns 100 000, the token's supply drops by exactly that ----
    let burn = 100_000u64;
    let slot = proving_slot().await;
    let burned =
        wallet::submit_token_burn(&rpc, &a, &mut a_store, 1, burn, gas::BUNDLE_BASE, FriProfile::Test, Backend::Cpu, CHAIN_ID, true)
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
