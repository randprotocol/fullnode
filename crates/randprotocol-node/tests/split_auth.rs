//! Split authorisation end to end on a real node (delegated proving Phase 2, spec
//! `docs/superpowers/specs/2026-09-28-delegated-proving-design.md` §4.1): a one-validator chain
//! whose genesis pins bundle guest v3 and this build's auth guest (`hc_auth`) admits and commits a
//! transaction carrying a real v3 bundle proof over `nk` and a real auth proof over the spend key,
//! and refuses the same transaction with its auth proof swapped — for one made over another
//! transaction's binding, or for one over another salt's commitment.
//!
//! The wallet does not build v3 transactions yet, so this one is built by hand at the zkVM level:
//! a 1-in/1-out self-transfer of the faucet-minted note. One bundle proof (~100 s) and three auth
//! proofs (~7 s each), all under the workspace's proving slot.

mod proving_slot;
use proving_slot::proving_slot;

use randprotocol_client::wallet::{self, NoteStore, Wallet};
use randprotocol_client::RpcClient;
use randprotocol_core::genesis::{Genesis, GenesisValidator};
use randprotocol_core::notes::{word8_to_hex, Bundle, Envelope, Word8, DEPTH};
use randprotocol_core::{gas, Action, Keypair, Transaction, UNITS_PER_RAND};
use randprotocol_node::node::{self, NodeConfig};
use randprotocol_zkvm::address::seal_note;
use randprotocol_zkvm::auth::auth_commit;
use randprotocol_zkvm::executor::{prove_auth, prove_bundle_for, ZkExecutor};
use randprotocol_zkvm::hidden::{self, HiddenDigestInput, HiddenDigestInputV3, HiddenOutput, SLOTS};
use randprotocol_zkvm::machine::{Backend, FriProfile};
use randprotocol_zkvm::notes::{Note, SpendKey};
use randprotocol_zkvm::viewing::TxKey;
use std::time::{Duration, Instant};

const CHAIN_ID: u64 = 17;

/// A one-validator Test-profile chain with the faucet on, pinning bundle guest v3 and the auth
/// guest — what `rand-node genesis --bundle-guest v3 --auth-guest` writes.
fn genesis_v3(validator: &Keypair) -> Genesis {
    Genesis {
        chain_id: CHAIN_ID,
        timestamp_ms: 0,
        validators: vec![GenesisValidator {
            public_key: validator.public_key().clone(),
            stake: randprotocol_core::ledger::staking::MIN_STAKE as u128,
            payout: randprotocol_core::notes::ShieldedAddress { pk: [1; 8], kem_ek: vec![2; randprotocol_core::notes::KEM_EK_BYTES] }
                .to_string(),
        }],
        alloc: vec![],
        faucet: true,
        confidential: true,
        fri_profile: "test".into(),
        hc_bundle: word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()),
        bridge: None,
        tokens: None,
        aggregation: None,
        consensus_domain: None,
        staking: None,
        epoch_blocks: randprotocol_core::genesis::EPOCH_BLOCKS_DEFAULT,
        max_program_words: None,
        max_proof_bytes: None,
        // Room for three proofs at the default 2 MiB proof cap (`gas::min_block_bytes`): a
        // split-authorisation genesis at the 4 MiB default is refused.
        max_block_bytes: Some(7 << 20),
        max_call_envelope_bytes: None,
        max_program_public_words: None,
        envelope_bytes: None,
        vesting: None,
        hardening_v6: None,
        hc_auth: Some(word8_to_hex(&ZkExecutor::hc_auth())),
        gas: None,
    }
}

/// Submit `tx` and expect a refusal naming `want`, whether the node refuses it at the RPC or
/// after its off-loop verification (`rand_getTransactionStatus`'s `rejected`).
async fn expect_refused(rpc: &RpcClient, tx: &Transaction, want: &str) {
    let refused = match rpc.send_transaction(tx).await {
        Err(e) => e.to_string(),
        Ok(hash) => rpc.wait_for_transaction(&hash, Duration::from_secs(120)).await.expect_err("must be refused").to_string(),
    };
    assert!(refused.contains(want), "expected a refusal naming {want:?}: {refused}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_v3_chain_admits_a_real_auth_proof_and_refuses_a_swapped_one() {
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let key = Keypair::from_seed([117; 32]).unwrap();
    std::fs::write(dir.path().join("genesis.json"), genesis_v3(&key).to_json()).unwrap();
    let handle = node::start(NodeConfig {
        viewing_open: false,
        datadir: dir.path().to_path_buf(),
        seed: *key.seed(),
        listen: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap: vec![],
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        enable_mdns: false,
        validator: true,
        // The anchor and time windows are 256 blocks; a bundle proof plus three auth proofs fit
        // with room at 3 s blocks (the wallet flow's reasoning).
        block_interval: Duration::from_secs(3),
        base_timeout: Duration::from_secs(6),
        max_timeout: Duration::from_secs(30),
        verify: randprotocol_node::storage::VerifyMode::Full,
        keep_raw_proofs: false,
        min_free_disk_bytes: 0,
        prune_history: None,
        gas_policy: None,
    })
    .await
    .expect("a v3 + hc_auth genesis starts on this build");
    let rpc = RpcClient::new(format!("http://{}", handle.rpc_addr));
    let status = rpc.status().await.unwrap();
    assert_eq!(status["hc_auth"], word8_to_hex(&ZkExecutor::hc_auth()), "rand_status serves hc_auth");
    assert_eq!(status["hc_bundle"], word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()));

    // ---- mint a note to the wallet, and find it ----
    let w = Wallet::from_spend_key(SpendKey([3; 8]));
    let mint = 10 * UNITS_PER_RAND;
    let hash = rpc.mint_shielded(&w.address.to_string(), Some(mint)).await.expect("mint accepted");
    rpc.wait_for_transaction(&hash, Duration::from_secs(60)).await.expect("mint commits");
    let mut store = NoteStore::default();
    wallet::scan(&rpc, &w, &mut store).await.unwrap();
    let owned = store.spendable().into_iter().next().expect("the minted note").clone();
    assert_eq!(owned.note.amount, mint);

    let slot = proving_slot().await;
    // ---- the v3 transaction, by hand: slot 2 spends the note, slot 3 returns it less the fee ----
    let (anchor, path) = loop {
        let (root, path) = rpc.witness(owned.index).await.unwrap();
        let (_, head_root) = rpc.anchor(None).await.unwrap();
        if root == head_root {
            break (root, path);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let (height, _) = rpc.anchor(None).await.unwrap();
    let time = height as u32;
    let fee = gas::fee_floor(&Action::None);
    let pk_self = w.vk.pk();
    let fresh = || SpendKey::random().0;
    let dummy_in = |k: usize| (Note::new(pk_self, [0; 8], 0, hidden::slot_asset(k, 0), time), [[0u32; 8]; DEPTH], 0u32);
    let inputs = [dummy_in(0), dummy_in(1), (owned.note, path, owned.index as u32), dummy_in(3)];
    let nobodies: Vec<Wallet> = (0..SLOTS).map(|_| Wallet::generate()).collect();
    let mut outs = [HiddenOutput { pk: [0; 8], amount: 0, r: [0; 8] }; SLOTS];
    let mut envelopes: Vec<Envelope> = Vec::new();
    for k in 0..SLOTS {
        let (owner, amount) = if k == 3 { (&w, mint - fee) } else { (&nobodies[k], 0) };
        outs[k] = HiddenOutput { pk: owner.vk.pk(), amount, r: fresh() };
        let note = outs[k].note(k, pk_self, 0, time);
        envelopes.push(seal_note(&owner.vk, &owner.address, &note, &TxKey::random()).unwrap());
    }
    let salt: Word8 = fresh();
    let c = auth_commit(&w.vk.nk, &salt);
    let nullifiers: [Word8; SLOTS] = std::array::from_fn(|k| w.vk.nullifier(&inputs[k].0.commitment()));
    let commitments: [Word8; SLOTS] = std::array::from_fn(|k| outs[k].note(k, pk_self, 0, time).commitment());
    let words = hidden::hidden_bundle_inputs_v3(&w.vk, &salt, &inputs, &outs, anchor, fee, 0, 0, 0, time);
    let bundle = Bundle {
        anchor,
        nullifiers,
        commitments,
        fee,
        burn_a: 0,
        burn_r: 0,
        burn_asset: 0,
        time,
        envelopes: envelopes.try_into().map_err(|_| "four envelopes").unwrap(),
        proof: Vec::new(),
        auth_commit: c,
        auth_proof: Vec::new(),
    };
    let mut tx = Transaction::shielded(CHAIN_ID, bundle, Action::None);
    let binding = tx.binding();

    let hc = ZkExecutor::hc_hidden_bundle_v3();
    let t = Instant::now();
    let (bundle_proof, digest, tier) = prove_bundle_for(&hc, FriProfile::Test, &words, &binding, Backend::Cpu).unwrap();
    eprintln!("v3 bundle proof: tier {tier}, {:.1?}, {} bytes", t.elapsed(), bundle_proof.len());
    let expected = hidden::hidden_bundle_digest_v3(&HiddenDigestInputV3 {
        base: HiddenDigestInput { anchor, nullifiers, commitments, fee, burn_a: 0, burn_r: 0, burn_asset: 0, time },
        auth_commit: c,
    });
    assert_eq!(digest, expected, "the v3 guest published the digest the ledger recomputes (no taint)");
    let t = Instant::now();
    let (auth_proof, published, auth_tier) = prove_auth(FriProfile::Test, &w.sk, &salt, &binding, Backend::Cpu).unwrap();
    eprintln!("auth proof: tier {auth_tier}, {:.1?}, {} bytes", t.elapsed(), auth_proof.len());
    assert_eq!(published, c, "the auth proof publishes c = H(AUTH, nk, salt)");
    // Two swaps: an auth proof over another transaction's binding (same salt, same c), and one
    // over this binding under another salt (another c).
    let mut other_binding = binding;
    other_binding[0] ^= 1;
    let (foreign, _, _) = prove_auth(FriProfile::Test, &w.sk, &salt, &other_binding, Backend::Cpu).unwrap();
    let (resalted, other_c, _) = prove_auth(FriProfile::Test, &w.sk, &fresh(), &binding, Backend::Cpu).unwrap();
    assert_ne!(other_c, c);
    tx.bundle.as_mut().unwrap().proof = bundle_proof;
    assert_eq!(tx.binding(), binding, "the binding blanks both proofs");

    // ---- the swapped ones first (while the note is unspent, so only the auth proof can refuse) ----
    let mut swapped = tx.clone();
    swapped.bundle.as_mut().unwrap().auth_proof = foreign;
    expect_refused(&rpc, &swapped, "auth proof:").await;
    let mut swapped = tx.clone();
    swapped.bundle.as_mut().unwrap().auth_proof = resalted;
    expect_refused(&rpc, &swapped, "different commitment than the bundle's auth_commit").await;

    // ---- the honest one commits ----
    tx.bundle.as_mut().unwrap().auth_proof = auth_proof;
    let hash = rpc.send_transaction(&tx).await.expect("the v3 transaction is accepted");
    let receipt = rpc.wait_for_transaction(&hash, Duration::from_secs(120)).await.expect("the v3 transaction commits");
    drop(slot);
    let shown = rpc.call("rand_getTransaction", serde_json::json!([hash.to_hex()])).await.unwrap();
    assert_eq!(shown["tx"]["bundle"]["auth_commit"], word8_to_hex(&c));
    assert_eq!(shown["tx"]["bundle"]["auth_proof_bytes"], tx.bundle.as_ref().unwrap().auth_proof.len());
    wallet::scan(&rpc, &w, &mut store).await.unwrap();
    assert_eq!(store.balance(), mint - fee, "the self-transfer's output is the wallet's, less the fee");
    eprintln!("split_auth: committed at height {} in {:.1?} total", receipt.height, started.elapsed());
}
