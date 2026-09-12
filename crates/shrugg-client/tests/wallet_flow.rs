//! The shielded wallet against a real chain: mint, scan, send, scan both sides, spend the change.
//!
//! One validator node runs in-process (the same `node::start` the cluster tests use) so the
//! whole loop is exercised end to end — a faucet mint lands a note only wallet A's viewing key
//! opens; A proves a real 2-in-2-out bundle; B finds its payment by trial-decrypting the tree;
//! A's spent note comes back marked spent by the chain's own nullifier set; and the change note
//! is spendable, which is the part a wallet gets wrong if it forgets its own second output.
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
use shrugg_core::{format_amount, gas, Keypair, UNITS_PER_SHRUGG};
use shrugg_node::node::{self, NodeConfig, NodeHandle};
use shrugg_zkvm::executor::ZkExecutor;
use shrugg_zkvm::machine::{Backend, FriProfile};
use shrugg_zkvm::notes::SpendKey;
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
        validators: vec![GenesisValidator {
            public_key: validator.public_key().clone(),
            stake: shrugg_core::ledger::staking::MIN_STAKE as u128,
            // Phase S2 requires a payout address per validator; this test never withdraws, so
            // it only has to parse.
            payout: shrugg_core::notes::ShieldedAddress {
                pk: [1; 8],
                kem_ek: vec![2; shrugg_core::notes::KEM_EK_BYTES],
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
