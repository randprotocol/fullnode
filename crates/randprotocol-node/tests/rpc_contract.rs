//! The RPC contract the downstream repos read, as a canary in this repo's fast CI.
//!
//! Six repos consume this node's JSON-RPC: randscan (its indexer), randbridge.org (the status
//! service), randprotocol.org (the sale relay and the balance viewer) and zusd.money (through
//! randscan's REST, which is these same reads), durian.market's perps frontend and its
//! `perp-prover` (the RPL-3 perps methods, [`perps_reads_under_a_perps_section`]), and the wallet
//! clients repo, which reads the node through `clients/ui/engine/rpc.js` and checks every reply's
//! shape in `clients/ui/engine/validate.js` ([`the_wallet_reads_the_scan_and_send_path_exactly`],
//! the `clients` rows of the table). The wallet's own half is `web/wallet/test/node.e2e.test.mjs`,
//! run by `scripts/e2e-node.sh` in that repo's CI job `real-node` against the release binary. Their own integration tests spawn a real
//! `rand-node` (`scripts/dev-chain.sh`, `docs/howto.md` §7, "How do I run the downstream
//! integration tests?"), but those run in their CI, after a release. This file fails here first: a field one of
//! them reads that is renamed, dropped or changes JSON type is a red `check-and-test` in this repo
//! before any of them sees the release.
//!
//! One in-process validator on a chain shaped like the ones they read — faucet on, a `gas`
//! section, a `fees` section, a `bridge` section with one listed token — a faucet mint, then a
//! table of `(method, params, [(field path, JSON type)])`, one row per read, each naming the
//! consumer file. What the test cannot cheaply create (a program, a call, a burn, a spend) is read
//! for its **empty or refusal shape**, which the consumers handle too and which is pinned exactly.
//! Amounts are decimal strings everywhere they appear, and the table says so per field ([`Dec`]).
//!
//! `subsidy_net_of_fees` needs an `aggregation` section, which `node::start` refuses today
//! (`check_build_runs_genesis`), so the live chain runs `burn_base` and `burn_floor`; the all-three
//! `rand_getLimits.fee_rules` and `rand_getSupply.base_fees_burned` are pinned separately over an
//! RPC server with no node behind it ([`fee_rules_under_all_three_flags`]).
//!
//! Adding a row: name the consumer file in the comment, and list only the fields it reads.

mod common;

use randprotocol_core::genesis::{GenesisBacking, GenesisToken, TokensConfig};
use randprotocol_zkvm::notes::SpendKey;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;

use J::*;

/// The JSON type a consumer reads a field as.
#[derive(Clone, Copy, Debug)]
enum J {
    /// A non-negative integer.
    Int,
    /// An amount: a non-empty string of ASCII digits (never a JSON number — a stake or a supply
    /// overflows an f64's integers).
    Dec,
    /// A non-empty, even-length string of lowercase hex.
    Hex,
    /// Exactly 64 lowercase hex characters: a hash, a commitment, a Merkle root, a witness path
    /// level (the wallet's `hexField(.., 64)`, `ui/engine/validate.js`).
    Hex64,
    /// Even-length lowercase hex, possibly empty (an envelope part: `to_sender` is `""` on a
    /// faucet note, and the wallet's `hexBlob` accepts it).
    HexOrEmpty,
    /// Any string.
    Str,
    Bool,
    Arr,
    Obj,
    /// `null`, with the key present.
    Null,
}

impl J {
    fn holds(self, v: &Value) -> bool {
        match self {
            Int => v.as_u64().is_some(),
            Dec => v.as_str().is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
            Hex => v
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            Hex64 => v.as_str().is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            HexOrEmpty => v
                .as_str()
                .is_some_and(|s| s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            Str => v.is_string(),
            Bool => v.is_boolean(),
            Arr => v.is_array(),
            Obj => v.is_object(),
            Null => v.is_null(),
        }
    }
}

/// What a row expects of a method's `result`.
enum Expect {
    /// Every path present with that JSON type. `""` is the result itself; a numeric segment
    /// indexes an array (`"transactions.0.hash"`).
    Fields(&'static [(&'static str, J)]),
    /// Exactly this value: the empty and refusal shapes a consumer branches on.
    Exactly(Value),
}

struct Row {
    method: &'static str,
    params: Value,
    expect: Expect,
    /// Who reads it, and where.
    consumer: &'static str,
}

fn row(method: &'static str, params: Value, consumer: &'static str, fields: &'static [(&'static str, J)]) -> Row {
    Row { method, params, expect: Expect::Fields(fields), consumer }
}

fn exactly(method: &'static str, params: Value, consumer: &'static str, value: Value) -> Row {
    Row { method, params, expect: Expect::Exactly(value), consumer }
}

/// `path` inside `v`, or `None` where a segment is missing. A segment is an object key, or an
/// array index where the value is an array (`emitters.2` is the key `"2"`, `guardians.0` the
/// first element).
fn at<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    if path.is_empty() {
        return Some(v);
    }
    path.split('.').try_fold(v, |v, seg| match (v, seg.parse::<usize>()) {
        (Value::Array(a), Ok(i)) => a.get(i),
        _ => v.get(seg),
    })
}

/// A reply, cut short for a failure message: a bridge state carries six Dilithium2 keys.
fn short(v: &Value) -> String {
    let s = v.to_string();
    match s.char_indices().nth(400) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s,
    }
}

async fn call(addr: SocketAddr, method: &str, params: Value) -> Value {
    reqwest::Client::new()
        .post(format!("http://{addr}/"))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Run every row; collect every broken field across the table rather than stopping at the first,
/// so one red run names the whole damage. Returns how many fields were checked.
async fn check(addr: SocketAddr, rows: &[Row]) -> usize {
    let mut broken = Vec::new();
    let mut checked = 0;
    for r in rows {
        let reply = call(addr, r.method, r.params.clone()).await;
        let Some(result) = reply.get("result") else {
            broken.push(format!("{} {} ({}): an error, not a result: {}", r.method, short(&r.params), r.consumer, short(&reply)));
            continue;
        };
        match &r.expect {
            Expect::Fields(fields) => {
                for (path, ty) in *fields {
                    checked += 1;
                    match at(result, path) {
                        None => broken.push(format!("{}.{path} ({}): missing in {}", r.method, r.consumer, short(result))),
                        Some(v) if !ty.holds(v) => {
                            broken.push(format!("{}.{path} ({}): {} is not {ty:?}", r.method, r.consumer, short(v)))
                        }
                        Some(_) => {}
                    }
                }
            }
            Expect::Exactly(want) => {
                checked += 1;
                if result != want {
                    broken.push(format!("{} {} ({}): {}, pinned {want}", r.method, short(&r.params), r.consumer, short(result)));
                }
            }
        }
    }
    assert!(broken.is_empty(), "the downstream RPC contract is broken:\n  {}", broken.join("\n  "));
    checked
}

/// A real shielded address, for the faucet to mint to.
fn address() -> String {
    randprotocol_zkvm::address::address_of(&SpendKey([7; 8]).viewing_key()).to_string()
}

/// The listed token's backing: chain 2, a fixed token address, eight decimals.
const TOKEN_CHAIN: u16 = 2;
const TOKEN: [u8; 32] = [0x11; 32];

/// The live chain: the harness's one validator with a gas section, `fees { burn_base,
/// burn_floor }`, a bridge from chain 2 and one listed token at index 1, and the testnet marker
/// that lets the faucet sit beside the bridge.
async fn start() -> common::TestNode {
    common::start_one_validator_shaped(|g| {
        g.gas = Some(randprotocol_core::gas::GasConfig {
            gas_price: 100,
            byte_price: randprotocol_core::gas::BYTE_PRICE_DEFAULT,
            bundle_gas_limit: randprotocol_core::gas::bundle_gas_limit_pin(),
            metering: randprotocol_core::gas::GasMetering::Circuit,
            dynamic: None,
        });
        g.fees = Some(randprotocol_core::ledger::fees::FeesConfig {
            burn_base: Some(true),
            subsidy_net_of_fees: None,
            burn_floor: Some(true),
            proposer_share_bps: None,
            prove_base: None,
            usd_subsidy: None,
        });
        g.bridge = Some(common::bridge::bridge_config_for([0xaa; 32], &[TOKEN_CHAIN]));
        g.tokens = Some(TokensConfig {
            registration_fee: 1_000_000_000,
            tokens: vec![GenesisToken {
                name: "Tether USD".into(),
                symbol: "zUSDT".into(),
                salt: [0x5a; 32],
                backings: vec![GenesisBacking { chain: TOKEN_CHAIN, token: TOKEN, decimals: 8, locked: None }],
            }],
            mint_cap_per_day: 100_000 * 100_000_000,
            max_tokens: None,
            burn_registration_fee: None,
            bound_note_value: None,
            incremental_root: None,
        });
        g.testnet = Some(true);
    })
    .await
}

/// The live chain after one faucet mint: every read the four downstream repos make, field by field.
#[tokio::test]
async fn every_field_the_downstream_repos_read_is_served_with_its_type() {
    let node = start().await;
    let addr = node.rpc_addr;

    // The faucet (randprotocol.org's sale relay fills through `rand_sendTransaction`; the
    // downstream tests fund wallets with `rand faucet`, which is this).
    let minted = call(addr, "rand_mint", json!([address()])).await;
    let tx = minted["result"].as_str().unwrap_or_else(|| panic!("rand_mint refused: {minted}")).to_string();
    assert!(Hex64.holds(&minted["result"]), "rand_mint answers a 64-hex hash (the wallet's `checkSubmitted`): {minted}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let height = loop {
        let got = call(addr, "rand_getTransaction", json!([tx])).await;
        if let Some(h) = got["result"]["height"].as_u64() {
            break h;
        }
        assert!(tokio::time::Instant::now() < deadline, "the mint never committed: {got}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    // One more block on top, so the head is past the mint's.
    while call(addr, "rand_getHead", json!([])).await["result"]["height"].as_u64().unwrap_or(0) <= height {
        assert!(tokio::time::Instant::now() < deadline, "the chain stopped after the mint");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let block_hash = call(addr, "rand_getBlockByHeight", json!([height])).await["result"]["hash"].as_str().unwrap().to_string();

    // `rand_sendTransaction`'s success shape (randprotocol.org server/sale/src/rpc.rs relays it;
    // the wallet reads the hash): the cheapest valid transaction is a mint the chain's one
    // validator signs, as `submit.rs` sends it — no proof. The answer is the hash, hex.
    let validator = randprotocol_core::Keypair::from_seed([101; 32]).unwrap();
    let executor = randprotocol_zkvm::executor::ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
    let mint = |tag: u8| {
        let envelope = randprotocol_core::notes::Envelope { kem_ct: vec![tag; 8], to_receiver: vec![tag; 4], to_sender: vec![], body: vec![tag; 16] };
        randprotocol_core::Transaction::mint(7, [tag as u32; 8], 0, [tag as u32; 8], envelope, 1000, &validator, &executor)
    };
    let signed = mint(9);
    let sent = call(addr, "rand_sendTransaction", json!([hex::encode(signed.encode())])).await;
    assert_eq!(sent["result"], json!(signed.hash().to_hex()), "rand_sendTransaction: {}", short(&sent));
    let unknown = "ab".repeat(32);

    // The block fields randscan's `RpcBlock` and randbridge.org's scan read.
    const BLOCK: &[(&str, J)] = &[
        ("hash", Hex), ("height", Int), ("view", Int), ("parent", Hex), ("proposer", Str), ("timestamp_ms", Int),
        ("tx_root", Hex), ("state_root", Hex), ("justify_view", Int), ("tx_count", Int), ("transactions", Arr),
        ("transactions.0.hash", Hex), ("transactions.0.chain_id", Int), ("transactions.0.bundle", Null),
        ("transactions.0.action.kind", Str), ("transactions.0.action.cm", Hex), ("transactions.0.action.amount", Dec),
        ("transactions.0.action.minter", Str),
    ];

    let rows = vec![
        // ---- chain identity ----
        // randscan crates/randscan-indexer/src/rpc.rs `chain_id`; randbridge.org status/src/rand.rs
        // (`RandBridge::read`); randprotocol.org server/sale (relay health), src/scripts/balance.js.
        row("rand_chainId", json!([]), "randscan rpc.rs, randbridge.org status/src/rand.rs, randprotocol.org, clients/ui/engine/wallet.js `chainIdentity`", &[("", Int)]),
        // randscan crates/randscan-indexer/src/rpc.rs `TokenInfo`.
        row("rand_tokenInfo", json!([]), "randscan crates/randscan-indexer/src/rpc.rs", &[("symbol", Str), ("decimals", Int)]),
        // randscan crates/randscan-indexer/src/rpc.rs `RpcVersion`.
        row("rand_getVersion", json!([]), "randscan crates/randscan-indexer/src/rpc.rs", &[("version", Str), ("git_sha", Str), ("fri_profile", Str)]),
        // randscan crates/randscan-indexer/src/rpc.rs `genesis_hash`.
        row("rand_getGenesisHash", json!([]), "randscan crates/randscan-indexer/src/rpc.rs, clients/ui/engine/validate.js `checkGenesisHash`", &[("", Hex64)]),
        // ---- the head and the node ----
        // randscan crates/randscan-indexer/src/rpc.rs `Head`; randbridge.org status/src/rand.rs (`height`).
        row("rand_getHead", json!([]), "randscan rpc.rs `Head`, randbridge.org status/src/rand.rs, clients/ui/engine/validate.js `checkHead`", &[("height", Int), ("hash", Hex), ("view", Int)]),
        // randscan crates/randscan-indexer/src/rpc.rs `NodeStatus` (every field is `serde(default)`
        // there, so a drop would be silent downstream — which is why it is pinned here).
        // clients/ui/engine/wallet.js `proofParamsOf` reads `hc_bundle` (exactly 64 hex), `hc_auth`
        // (`null` or 64 hex) and `fri_profile`; `backend-shared.js` `probe` reads `height`.
        row("rand_status", json!([]), "randscan crates/randscan-indexer/src/rpc.rs `NodeStatus`, clients/ui/engine/wallet.js `proofParamsOf`", &[
            ("height", Int), ("head_hash", Hex), ("view", Int), ("high_qc_view", Int), ("syncing", Bool), ("sync_target", Int),
            ("peer_count", Int), ("mempool_size", Int), ("is_validator", Bool), ("active_validator", Bool), ("faucet", Bool),
            ("confidential", Bool), ("fri_profile", Str), ("programs", Int), ("notes", Int), ("nullifiers", Int),
            ("tree_root", Hex), ("hc_bundle", Hex64), ("hc_auth", Null), ("address", Str), ("peer_id", Str),
            ("gas_prices.gas_price", Dec), ("gas_prices.byte_price", Dec),
        ]),
        // clients/ui/lib/rpc-methods.js lists `rand_syncStatus`; it is `rand_status` under another name.
        row("rand_syncStatus", json!([]), "clients/ui/lib/rpc-methods.js", &[("height", Int), ("syncing", Bool), ("sync_target", Int), ("hc_bundle", Hex64)]),
        // randscan crates/randscan-indexer/src/rpc.rs `RpcPeer` (an empty list on one validator).
        exactly("rand_getPeers", json!([]), "randscan crates/randscan-indexer/src/rpc.rs `RpcPeer`", json!([])),
        // ---- limits and supply ----
        // randscan crates/randscan-core/src/types/stats.rs `ChainLimits`; randprotocol.org (the
        // wallet's fee path through the relay).
        // clients/ui/engine/validate.js `checkLimits` reads `envelope_bytes` (Int or null; `null` on
        // this chain, an Int where genesis fixes it, pinned in [`the_wallet_reads_the_limits_it_derives_caps_from`]),
        // `max_proof_bytes`, `bundle_gas_limit`, `program_state` and `proof_window_blocks`.
        row("rand_getLimits", json!([]), "randscan crates/randscan-core/src/types/stats.rs `ChainLimits`, clients/ui/engine/validate.js `checkLimits`", &[
            ("max_program_words", Int), ("max_proof_bytes", Int), ("max_block_bytes", Int), ("max_call_envelope_bytes", Int),
            ("max_program_public_words", Int), ("envelope_bytes", Null), ("hardening_v6", Bool), ("hc_auth", Null),
            ("gas_price", Dec), ("byte_price", Dec), ("gas_metering", Str), ("bundle_gas_limit", Int),
            ("admission_by_vote", Bool), ("testnet", Bool), ("binding_domain", Int), ("proof_window_blocks", Null),
            ("program_state", Null), ("multisig", Null),
            ("fee_rules.burn_base", Bool), ("fee_rules.subsidy_net_of_fees", Bool), ("fee_rules.burn_floor", Bool),
        ]),
        // randscan crates/randscan-core/src/types/stats.rs `Supply`; randprotocol.org (supply page).
        row("rand_getSupply", json!([]), "randscan crates/randscan-core/src/types/stats.rs `Supply`", &[
            ("height", Int), ("genesis_deposited", Dec), ("genesis_staked", Dec), ("faucet_minted", Dec),
            ("withdraw_deposited", Dec), ("fees_paid", Dec), ("burned", Dec), ("pool_value", Dec), ("register_total", Dec),
            ("total_supply", Dec), ("invariant_holds", Bool), ("vesting_issued", Dec), ("vesting_released", Dec),
            ("vesting_in_register", Dec), ("vesting_locked", Dec), ("program_rand_out", Dec), ("program_rand_held", Dec),
            ("registration_fees_burned", Dec), ("base_fees_burned", Dec),
            ("multisig_issued", Dec), ("multisig_rand_in", Dec), ("multisig_rand_out", Dec), ("multisig_base_out", Dec),
            ("multisig_rand_held", Dec),
        ]),
        // ---- blocks and transactions ----
        // randscan crates/randscan-indexer/src/rpc.rs `RpcBlock`/`RpcTx`/`RpcAction::Mint`;
        // randbridge.org status/src/rand.rs (`transactions[].action.kind`, `transactions[].hash`).
        Row { method: "rand_getBlockByHeight", params: json!([height]), expect: Expect::Fields(BLOCK), consumer: "randscan rpc.rs `RpcBlock`, randbridge.org status/src/rand.rs, clients/ui/engine/validate.js `checkBlockHeader`/`checkBlockActions`" },
        Row { method: "rand_getBlockByHash", params: json!([block_hash]), expect: Expect::Fields(BLOCK), consumer: "randscan crates/randscan-indexer/src/rpc.rs `RpcBlock`" },
        // A height past the head: `null`, which randscan's `block_by_height` reads as "not yet".
        exactly("rand_getBlockByHeight", json!([height + 1_000_000]), "randscan crates/randscan-indexer/src/rpc.rs", Value::Null),
        // randscan crates/randscan-api/tests/real_node.rs (the transaction page).
        row("rand_getTransaction", json!([tx]), "randscan crates/randscan-api, clients/ui/engine/validate.js `checkTransaction`", &[
            ("height", Int), ("index", Int), ("block_hash", Hex), ("tx.hash", Hex), ("tx.action.kind", Str),
        ]),
        exactly("rand_getTransaction", json!([unknown]), "randscan crates/randscan-api", Value::Null),
        // randbridge.org status/src/rand.rs: the attestation's raw bytes, a hex string.
        row("rand_getRawTransaction", json!([tx]), "randbridge.org status/src/rand.rs", &[("", Hex)]),
        exactly("rand_getRawTransaction", json!([unknown]), "randbridge.org status/src/rand.rs", Value::Null),
        // randscan crates/randscan-indexer/src/rpc.rs `RpcReceipt`, `call_envelope`: a mint is no
        // call, so both are `null` — the shape the indexer stores as "no receipt".
        exactly("rand_getReceipt", json!([tx]), "randscan crates/randscan-indexer/src/rpc.rs `RpcReceipt`", Value::Null),
        exactly("rand_getCallEnvelope", json!([tx]), "randscan crates/randscan-indexer/src/rpc.rs `call_envelope`", Value::Null),
        // ---- the shielded pool ----
        // randscan crates/randscan-indexer/src/rpc.rs `RpcCommitment` (the mint's note is leaf 0).
        // clients/ui/engine/validate.js `checkCommitments`: `cm` is 64 hex, `height` an Int, and the
        // four envelope parts are hex (`to_sender` may be empty).
        row("rand_getCommitments", json!([0, 10]), "randscan crates/randscan-indexer/src/rpc.rs `RpcCommitment`, clients/ui/engine/validate.js `checkCommitments`", &[
            ("0.index", Int), ("0.cm", Hex64), ("0.height", Int), ("0.envelope", Obj),
            ("0.envelope.kem_ct", HexOrEmpty), ("0.envelope.to_receiver", HexOrEmpty), ("0.envelope.to_sender", HexOrEmpty),
            ("0.envelope.body", HexOrEmpty),
        ]),
        // randscan crates/randscan-indexer/src/rpc.rs `RpcTreeInfo`.
        row("rand_getTreeInfo", json!([]), "randscan crates/randscan-indexer/src/rpc.rs `RpcTreeInfo`, clients/ui/engine/validate.js `checkTreeInfo`", &[("next_index", Int), ("root", Hex64), ("nullifiers", Int)]),
        // randprotocol.org src/scripts/balance.js `fetchSpent` (rows `{height, nullifier}`; no
        // spend has happened here, so the page is empty and the row shape is `rpc.rs`'s own test's).
        // The wallet pages it the same way (clients/ui/engine/validate.js `checkNullifiers`, rows
        // `{height, nullifier}` with a 64-hex nullifier): [`the_wallet_reads_the_scan_and_send_path_exactly`]
        // pins the empty page past the tip too.
        exactly("rand_getNullifiers", json!([0, 1000]), "randprotocol.org src/scripts/balance.js `fetchSpent`, clients/ui/engine/validate.js `checkNullifiers`", json!([])),
        // ---- validators ----
        // randscan crates/randscan-indexer/src/rpc.rs `RpcValidator`.
        row("rand_getValidators", json!([]), "randscan crates/randscan-indexer/src/rpc.rs `RpcValidator`", &[
            ("0.address", Str), ("0.stake", Dec), ("0.rewards", Dec), ("0.pending", Arr), ("0.payout", Str), ("0.nonce", Int),
            ("0.active", Bool),
        ]),
        // randscan crates/randscan-indexer/src/rpc.rs `RpcEpoch`.
        row("rand_getEpoch", json!([]), "randscan crates/randscan-indexer/src/rpc.rs `RpcEpoch`", &[("epoch", Int), ("epoch_blocks", Int), ("next_set", Arr)]),
        // randscan crates/randscan-core/src/types/validator.rs `AdmittedSet`.
        row("rand_getAdmitted", json!([]), "randscan crates/randscan-core/src/types/validator.rs `AdmittedSet`", &[("admission_by_vote", Bool), ("max", Int), ("admitted", Arr)]),
        // ---- the bridge and the token registry ----
        // randscan crates/randscan-core/src/types/bridge.rs `BridgeState`; randbridge.org
        // status/src/rand.rs (`enabled`, `emitters`, `guardians`, `assets[].{index,chain,token}`,
        // `fees`, `mint_paused`); zusd.money src/components/BalanceSheet.astro (via randscan's
        // `/bridge`).
        row("rand_getBridgeState", json!([]), "randscan types/bridge.rs, randbridge.org status/src/rand.rs, zusd.money BalanceSheet.astro, clients/ui/engine/validate.js `checkBridgeState`", &[
            ("enabled", Bool), ("emitter", Hex), ("emitters", Obj), ("emitters.2", Hex), ("guardian_set_index", Int),
            ("guardians", Arr), ("guardians.0", Hex), ("pq_guardians", Arr), ("mint_paused", Bool), ("pause_nonce", Int),
            ("list_nonce", Int), ("pause_key", Hex), ("burn_sequence", Int), ("fees", Null),
            ("assets", Arr), ("assets.0.index", Int), ("assets.0.chain", Int), ("assets.0.token", Hex), ("assets.0.asset_id", Hex),
            ("assets.0.locked", Dec), ("registration_fee", Dec), ("rotation_nonce", Int),
        ]),
        // randscan crates/randscan-core/src/types/bridge.rs `BridgeAsset` (randprotocol.org's
        // relay forwards it to the wallet); zusd.money src/components/BalanceSheet.astro `Asset`
        // `{index, chain, locked}` via randscan's `/bridge/assets`, whose `symbol` randscan joins
        // from `rand_getTokens`.
        row("rand_getAssets", json!([]), "randscan types/bridge.rs `BridgeAsset`, zusd.money BalanceSheet.astro `Asset`, clients/ui/engine/validate.js `checkAssets`", &[
            ("0.index", Int), ("0.chain", Int), ("0.token", Hex), ("0.asset_id", Hex), ("0.decimals", Int), ("0.locked", Dec),
            ("0.minted_today", Dec), ("0.mint_day", Int), ("0.mint_cap_per_day", Dec),
        ]),
        // randbridge.org status/src/rand.rs `source_of` (`tx` of a burn); no burn has happened.
        exactly("rand_getBridgeBurn", json!([0]), "randbridge.org status/src/rand.rs", Value::Null),
        // randscan crates/randscan-core/src/types/token.rs `TokenList`/`TokenInfo`; randprotocol.org
        // src/scripts/balance.js `fetchRegistry` (`tokens[].index`); zusd.money (via randscan).
        // clients/ui/engine/validate.js `checkTokens`: `decimals` <= 9, `total_supply` a decimal,
        // and `authority.backings[]` `{chain, token (64 hex), decimals, locked}`.
        row("rand_getTokens", json!([0, 1000]), "randscan types/token.rs `TokenList`, randprotocol.org balance.js `fetchRegistry`, clients/ui/engine/validate.js `checkTokens`", &[
            ("enabled", Bool), ("registration_fee", Dec), ("next_index", Int), ("tokens", Arr),
            ("tokens.0.index", Int), ("tokens.0.id", Hex), ("tokens.0.id_text", Str), ("tokens.0.name", Str),
            ("tokens.0.symbol", Str), ("tokens.0.decimals", Int), ("tokens.0.authority", Obj), ("tokens.0.mint_nonce", Int),
            ("tokens.0.total_supply", Dec), ("tokens.0.registered_at", Int),
            ("tokens.0.id", Hex64), ("tokens.0.authority.backings", Arr), ("tokens.0.authority.backings.0.chain", Int),
            ("tokens.0.authority.backings.0.token", Hex64), ("tokens.0.authority.backings.0.decimals", Int),
            ("tokens.0.authority.backings.0.locked", Dec),
        ]),
        // randscan crates/randscan-core/src/types/token.rs `TokenInfo`; randprotocol.org
        // src/scripts/balance.js `getToken`.
        row("rand_getToken", json!([1]), "randscan types/token.rs `TokenInfo`, randprotocol.org balance.js `getToken`, clients/ui/lib/rpc-methods.js", &[
            ("index", Int), ("id", Hex), ("id_text", Str), ("name", Str), ("symbol", Str), ("decimals", Int),
            ("authority", Obj), ("mint_nonce", Int), ("total_supply", Dec), ("registered_at", Int),
        ]),
        exactly("rand_getToken", json!([99]), "randprotocol.org src/scripts/balance.js `getToken` (null: no such token)", Value::Null),
        // randscan crates/randscan-core/src/types/token.rs `TokenSupply`; zusd.money
        // src/components/BalanceSheet.astro `Token.total_supply` (via randscan's `/tokens/:i`).
        row("rand_getTokenSupply", json!([1]), "randscan types/token.rs `TokenSupply`, zusd.money BalanceSheet.astro", &[
            ("total_supply", Dec), ("backings", Arr),
        ]),
        exactly("rand_getTokenSupply", json!([99]), "randscan crates/randscan-indexer/src/rpc.rs `token_supply`", Value::Null),
        // ---- programs (none deployed: the refusal and empty shapes the indexer branches on) ----
        // randscan crates/randscan-indexer/src/rpc.rs `program`: `null` for an unknown id.
        exactly("rand_getProgram", json!([unknown]), "randscan crates/randscan-indexer/src/rpc.rs `program`, clients/ui/lib/rpc-methods.js", Value::Null),
        // clients/ui/engine/validate.js `checkProgramCode` / `checkProgramPublic`: `null` is "no such program".
        exactly("rand_getProgramCode", json!([unknown]), "clients/ui/engine/validate.js `checkProgramCode`", Value::Null),
        exactly("rand_getProgramPublic", json!([unknown]), "clients/ui/engine/validate.js `checkProgramPublic`", Value::Null),
        // `checkProgramCell`: without a `program_state` section `{"enabled": false}`, which the wallet reads as `null`.
        exactly("rand_getProgramCell", json!([unknown, "00".repeat(32)]), "clients/ui/engine/validate.js `checkProgramCell`", json!({ "enabled": false })),
        // `rand_getVesting` without a `vesting` section: `{"enabled": false}`.
        exactly("rand_getVesting", json!([unknown]), "clients/ui/lib/rpc-methods.js `getVesting`", json!({ "enabled": false })),
        // randscan crates/randscan-indexer/src/rpc.rs `program_vault`/`program_cells`: without a
        // `program_state` section both answer `{"enabled": false}`, which the indexer reads as `None`.
        exactly("rand_getProgramVault", json!([unknown]), "randscan crates/randscan-indexer/src/rpc.rs `program_vault`, clients/ui/engine/validate.js `checkProgramVault`", json!({ "enabled": false })),
        // Multisig accounts: without a `multisig` section `{"enabled": false}`, `rand_getVesting`'s
        // and `rand_getProgramVault`'s shape (no consumer yet; the CLI's `multisig status` reads it).
        exactly("rand_getMultisig", json!([unknown]), "rand-node `multisig status`", json!({ "enabled": false })),
        // The voted RAND price on a chain without `fees.usd_subsidy`: `null`, which the aggregate
        // daemon reads as "the RAND schedule".
        exactly("rand_getRandPrice", json!([]), "rand-node `aggregate` (`aggregate_pass`), `price status`", Value::Null),
        exactly(
            "rand_getProgramCells",
            json!([unknown, { "after": null, "limit": 10 }]),
            "randscan crates/randscan-indexer/src/rpc.rs `program_cells`, clients/ui/engine/validate.js `checkProgramCells`",
            json!({ "enabled": false }),
        ),
        // ---- perps (RPL-3; no `perps` section here: the disabled shapes the consumers branch on) ----
        // durian.market web/lib/perps/client.ts `parsePerps` and crates/perp-prover/src/rpc.rs
        // `parse_perps`: `{"enabled": false}` is "perps are off on this chain".
        exactly("rand_getPerps", json!([]), "durian.market web/lib/perps/client.ts `parsePerps`, crates/perp-prover/src/rpc.rs `parse_perps`", json!({ "enabled": false })),
        // durian.market crates/perp-prover/src/rpc.rs `parse_perp_inputs`: `null` is "no record".
        exactly("rand_getPerpInputs", json!([height]), "durian.market crates/perp-prover/src/rpc.rs `parse_perp_inputs`", Value::Null),
        // randprotocol-client src/lib.rs `ChainLimits::perps` (`rand perp`): `null` without the section.
        row("rand_getLimits", json!([]), "randprotocol-client src/lib.rs `ChainLimits::perps`", &[("perps", Null)]),
    ];
    let mut rows = rows;
    // randprotocol.org server/sale/src/rpc.rs (the relay forwards the answer to the wallet).
    // A second, distinct mint: the first one is in the pool, and a resubmission is refused.
    // clients/ui/engine/validate.js `checkSubmitted`: the answer is a 64-hex transaction hash.
    rows.push(row("rand_sendTransaction", json!([hex::encode(mint(10).encode())]), "randprotocol.org server/sale/src/rpc.rs, clients/ui/engine/validate.js `checkSubmitted`", &[("", Hex64)]));
    // The wallet's own reads of the scan and send path (clients/ui/engine/{wallet,validate,backend-shared}.js).
    rows.extend([
        // `checkAnchor`: `height` an Int, `root` 64 hex.
        row("rand_getAnchor", json!([]), "clients/ui/engine/validate.js `checkAnchor`", &[("height", Int), ("root", Hex64)]),
        // `checkWitness`: `root` 64 hex, `path` exactly 32 levels of 64 hex (levels 0 and 31 here;
        // the length is pinned in the wallet test below).
        row("rand_getWitness", json!([0]), "clients/ui/engine/validate.js `checkWitness`", &[
            ("index", Int), ("root", Hex64), ("path", Arr), ("path.0", Hex64), ("path.31", Hex64),
        ]),
        // A leaf past the tree: `null`, which `checkWitness` passes through as "no witness".
        exactly("rand_getWitness", json!([1_000_000_000u64]), "clients/ui/engine/validate.js `checkWitness`", Value::Null),
        // `checkBlockHeaders`: `{height, tx_count}` per header, `height === from + i`.
        row("rand_getBlocks", json!([height, height]), "clients/ui/engine/validate.js `checkBlockHeaders`", &[("0.height", Int), ("0.tx_count", Int)]),
        // `checkFee`: a decimal amount; `backend-shared.js` `bundleFee` falls back to a constant at 0.
        row("rand_estimateFee", json!([{ "kind": "bundle" }]), "clients/ui/engine/validate.js `checkFee`", &[("", Dec)]),
    ]);
    let checked = check(addr, &rows).await;
    assert!(checked > 240, "the table shrank to {checked} checks");

    // The exact values the fee rows above only type-check: this chain's two live rules.
    let limits = call(addr, "rand_getLimits", json!([])).await;
    assert_eq!(limits["result"]["fee_rules"], json!({ "burn_base": true, "subsidy_net_of_fees": false, "burn_floor": true, "proposer_share_bps": null, "prove_base": null, "usd_subsidy": null }));

    node.shutdown().await;
}

/// The error shapes a consumer branches on, by `error.code`: randscan's `call_optional_method`
/// (crates/randscan-indexer/src/rpc.rs) reads `-32601` as "this node predates the method", and
/// randprotocol.org's sale relay (server/sale/src/rpc.rs) and src/scripts/balance.js pass
/// `error.message` to the reader. A bad `rand_sendTransaction` is refused with both.
#[tokio::test]
async fn the_refusal_shapes_the_consumers_branch_on_are_pinned() {
    let node = common::start_one_validator().await;
    let addr = node.rpc_addr;

    let missing = call(addr, "rand_noSuchMethod", json!([])).await;
    assert_eq!(missing["error"]["code"], json!(-32601), "{missing}");
    assert!(missing["error"]["message"].is_string(), "{missing}");

    let bad = call(addr, "rand_sendTransaction", json!(["not hex"])).await;
    assert_eq!(bad["error"]["code"], json!(-32602), "{bad}");
    assert_eq!(bad["error"]["message"], json!("tx must be hex"), "{bad}");

    let undecodable = call(addr, "rand_sendTransaction", json!(["00"])).await;
    assert_eq!(undecodable["error"]["code"], json!(-32602), "{undecodable}");
    assert!(undecodable["error"]["message"].as_str().is_some_and(|m| m.starts_with("tx decode")), "{undecodable}");

    // A chain without a bridge or a token registry: what randscan, randbridge.org and
    // randprotocol.org read on one (`enabled: false`, an empty registry, no assets).
    assert_eq!(call(addr, "rand_getBridgeState", json!([])).await["result"], json!({ "enabled": false }));
    assert_eq!(call(addr, "rand_getTokens", json!([0, 1000])).await["result"], json!({ "enabled": false, "tokens": [] }));
    assert_eq!(call(addr, "rand_getAssets", json!([])).await["result"], json!([]));
    assert_eq!(call(addr, "rand_getToken", json!([1])).await["result"], Value::Null);
    // The pre-account-removal names the wallet deletes from its method table
    // (clients/ui/test/rpc-methods.test.mjs): the node refuses them by name.
    for gone in ["rand_getBalance", "rand_getAccount", "rand_getAssetBalance"] {
        let r = call(addr, gone, json!([])).await;
        assert_eq!(r["error"]["code"], json!(-32601), "{gone}: {r}");
    }
    // A submit with no params at all is a param error, not a panic or a method error.
    let none = call(addr, "rand_sendTransaction", json!([])).await;
    assert_eq!(none["error"]["code"], json!(-32602), "{none}");
    // And no `fees` section: no rules, nothing burned.
    let limits = call(addr, "rand_getLimits", json!([])).await;
    assert_eq!(limits["result"]["fee_rules"], Value::Null, "{limits}");
    let supply = call(addr, "rand_getSupply", json!([])).await;
    assert_eq!(supply["result"]["base_fees_burned"], json!("0"), "{supply}");

    node.shutdown().await;
}

/// The wallet's `RPC_METHOD_RE` (clients/ui/engine/rpc.js): the only method names it will put on
/// the wire, `^(?:rand|bridge)_[A-Za-z][A-Za-z0-9]*$`, written out by hand (no `regex` dependency).
fn wallet_allows(method: &str) -> bool {
    let Some(rest) = method.strip_prefix("rand_").or_else(|| method.strip_prefix("bridge_")) else { return false };
    let mut chars = rest.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.all(|c| c.is_ascii_alphanumeric())
}

/// Every method in the wallet's table (clients/ui/lib/rpc-methods.js `METHODS`, each as `rand_<name>`).
const WALLET_METHODS: &[&str] = &[
    "chainId", "tokenInfo", "status", "getHead", "getEpoch", "getValidators", "getPeers", "getSupply", "getVersion",
    "getGenesisHash", "getHealth", "getLimits", "getMempoolInfo", "getEmission", "getVesting", "getVestingSummary",
    "getVestingSchedule", "getTreeInfo", "getAnchor", "getWitness", "getWitnesses", "getCommitments", "getNullifiers",
    "getCompactBlocks", "importViewingKey", "getViewingNotes", "removeViewingKey", "checkTransaction", "getProgram",
    "getProgramPublic", "getProgramCode", "getProgramCell", "getProgramCells", "getProgramVault", "getTransaction",
    "getTransactionStatus", "getRawTransaction", "getReceipt", "getReceipts", "getCallEnvelope", "getBlockByHeight",
    "getBlockByHash", "getBlocks", "getFinality", "getProposer", "getAdmitted", "getAggregate", "getAggregators",
    "getUnsealed", "getBridgeState", "getBridgeBurn", "bridgeAssetId", "getAssets", "getTokens", "getToken",
    "getTokenSupply", "estimateFee", "sendTransaction", "mint",
];

/// The wallet's scan-and-send path, read the way `clients/ui/engine/wallet.js` reads it, with the
/// exact values (not just the types) the wallet's checks in `validate.js` need: the three roots
/// agree, a witness is 32 levels, the empty pages are empty, the fee is a positive decimal, a
/// refusal carries the code and message it is shown with, and every method it can call exists.
#[tokio::test]
async fn the_wallet_reads_the_scan_and_send_path_exactly() {
    let node = start().await;
    let addr = node.rpc_addr;

    // Every name the wallet may put on the wire passes its own `RPC_METHOD_RE`, and the regex
    // refuses what it should (clients/ui/test/rpc.test.mjs pins the same on its side).
    for m in WALLET_METHODS {
        assert!(wallet_allows(&format!("rand_{m}")), "rand_{m} must match RPC_METHOD_RE");
    }
    for bad in ["eth_getBalance", "rand_", "rand_1x", "rand_get-x", "rand_get x", "getHead", "rand/getHead", "Rand_getHead"] {
        assert!(!wallet_allows(bad), "{bad} must not match RPC_METHOD_RE");
    }

    let minted = call(addr, "rand_mint", json!([address()])).await;
    let tx = minted["result"].as_str().unwrap_or_else(|| panic!("rand_mint refused: {minted}")).to_string();
    assert_eq!(tx.len(), 64, "the mint answers a hash: {minted}");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let height = loop {
        let got = call(addr, "rand_getTransaction", json!([tx])).await;
        if let Some(h) = got["result"]["height"].as_u64() {
            break h;
        }
        assert!(tokio::time::Instant::now() < deadline, "the mint never committed: {got}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    while call(addr, "rand_getHead", json!([])).await["result"]["height"].as_u64().unwrap_or(0) <= height {
        assert!(tokio::time::Instant::now() < deadline, "the chain stopped after the mint");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Every method of the wallet's table is in the node's dispatch table: none answers -32601
    // (a bad-params error is fine and has no effect: the empty params parse nothing).
    for m in WALLET_METHODS {
        let r = call(addr, &format!("rand_{m}"), json!([])).await;
        assert_ne!(r["error"]["code"], json!(-32601), "rand_{m} is not served: {}", short(&r));
    }

    // The tree, the anchor and a witness name one root. The tree moves only when a block carries a
    // note, so read them until one snapshot is quiet (the same root before and after).
    let (root, next_index, anchor_height) = loop {
        let before = call(addr, "rand_getTreeInfo", json!([])).await["result"].clone();
        let anchor = call(addr, "rand_getAnchor", json!([])).await["result"].clone();
        let witness = call(addr, "rand_getWitness", json!([0])).await["result"].clone();
        let after = call(addr, "rand_getTreeInfo", json!([])).await["result"].clone();
        if before["root"] == after["root"] && before["root"] == anchor["root"] && before["root"] == witness["root"] {
            assert_eq!(witness["index"], json!(0), "{}", short(&witness));
            let path = witness["path"].as_array().unwrap_or_else(|| panic!("a witness has a path: {}", short(&witness)));
            assert_eq!(path.len(), 32, "the wallet's checkWitness wants exactly 32 levels");
            assert!(path.iter().all(|l| Hex64.holds(l)), "every level is 64 hex: {}", short(&witness));
            break (before["root"].clone(), before["next_index"].as_u64().unwrap(), anchor["height"].as_u64().unwrap());
        }
        assert!(tokio::time::Instant::now() < deadline, "the root never settled: {} {} {}", short(&before), short(&anchor), short(&witness));
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(Hex64.holds(&root));
    assert_eq!(next_index, 1, "one faucet mint is one leaf");
    // The anchor at an explicit height is the same pair; one past the head is a refusal, not null.
    let at = call(addr, "rand_getAnchor", json!([anchor_height])).await;
    assert_eq!(at["result"]["root"], root, "{at}");
    assert_eq!(at["result"]["height"], json!(anchor_height), "{at}");
    let head = call(addr, "rand_getHead", json!([])).await["result"]["height"].as_u64().unwrap();
    let past = call(addr, "rand_getAnchor", json!([head + 1_000])).await;
    assert_eq!(past["error"]["code"], json!(-32001), "{past}");

    // The scan: the leaf page starts at the index asked for, has no gap, and is empty past the end.
    let leaves = call(addr, "rand_getCommitments", json!([0, 10])).await["result"].clone();
    let leaves = leaves.as_array().unwrap_or_else(|| panic!("an array: {}", short(&leaves)));
    assert_eq!(leaves.len() as u64, next_index);
    assert_eq!(leaves[0]["index"], json!(0));
    assert_eq!(call(addr, "rand_getCommitments", json!([next_index, 10])).await["result"], json!([]));
    // The nullifier page: nothing is spent, so it is empty at the start and past the tip.
    assert_eq!(call(addr, "rand_getNullifiers", json!([0, 1000])).await["result"], json!([]));
    assert_eq!(call(addr, "rand_getNullifiers", json!([head + 1_000, 1000])).await["result"], json!([]));
    // A leaf past the tree has no witness.
    assert_eq!(call(addr, "rand_getWitness", json!([next_index])).await["result"], Value::Null);

    // The block headers the wallet walks: `height === from + i`, one per block, clamped at the head.
    let headers = call(addr, "rand_getBlocks", json!([1, head])).await["result"].clone();
    let headers = headers.as_array().unwrap_or_else(|| panic!("an array: {}", short(&headers)));
    assert!(!headers.is_empty() && headers.len() as u64 <= head);
    for (i, h) in headers.iter().enumerate() {
        assert_eq!(h["height"], json!(1 + i as u64), "{}", short(h));
        assert!(h["tx_count"].is_u64(), "{}", short(h));
    }
    let minted_in = headers.iter().find(|h| h["height"] == json!(height)).expect("the mint's block is in the range");
    assert_eq!(minted_in["tx_count"], json!(1));

    // The fee: a positive decimal for a bundle; an unknown kind is a param error, not a number.
    let fee = call(addr, "rand_estimateFee", json!([{ "kind": "bundle" }])).await["result"].clone();
    assert!(Dec.holds(&fee), "{fee}");
    assert!(fee.as_str().unwrap().parse::<u128>().unwrap() > 0, "the wallet falls back to a constant at 0");
    let bad = call(addr, "rand_estimateFee", json!([{ "kind": "nonsense" }])).await;
    assert_eq!(bad["error"]["code"], json!(-32602), "{bad}");

    node.shutdown().await;
}

/// `rand_mint` on a chain whose genesis has no faucet: a refusal the wallet shows as the node's
/// own sentence (`rand-wallet` surfaces `RpcError.message`; clients/ui/engine/wallet.js
/// `faucet`, backend-shared.js `faucet`) — code -32000 and `faucet is disabled on this chain`.
#[tokio::test]
async fn the_faucet_refusal_the_wallet_shows_is_pinned() {
    let node = common::start_one_validator_shaped(|g| g.faucet = false).await;
    let addr = node.rpc_addr;
    let refused = call(addr, "rand_mint", json!([address()])).await;
    assert_eq!(refused["error"]["code"], json!(-32000), "{refused}");
    assert_eq!(refused["error"]["message"], json!("faucet is disabled on this chain"), "{refused}");
    assert_eq!(call(addr, "rand_status", json!([])).await["result"]["faucet"], json!(false));
    node.shutdown().await;
}

/// The limits the wallet derives its caps from when genesis sets them (clients/ui/engine/validate.js
/// `checkLimits`: `envelope_bytes` an Int, `program_state` `{cell_fee, max_reads, max_writes,
/// max_payouts}`), and the program-state reads it makes on such a chain
/// (`checkProgramCell`/`checkProgramCells`/`checkProgramVault`), served without a node behind it.
#[tokio::test]
async fn the_wallet_reads_the_limits_it_derives_caps_from() {
    let (addr, _served) = common::serve_genesis(|g| {
        g.envelope_bytes = Some(randprotocol_core::notes::MEMO_ENVELOPE_BYTES as u32);
        // `program_state` needs `gas`, `tokens`, `hardening_v6` and an `hc_auth` beside it.
        g.hardening_v6 = Some(true);
        g.hc_auth = Some("11".repeat(32));
        g.max_block_bytes = Some(20 << 20);
        g.gas = Some(randprotocol_core::gas::GasConfig {
            gas_price: 100,
            byte_price: randprotocol_core::gas::BYTE_PRICE_DEFAULT,
            bundle_gas_limit: randprotocol_core::gas::bundle_gas_limit_pin(),
            metering: randprotocol_core::gas::GasMetering::Circuit,
            dynamic: None,
        });
        g.tokens = Some(TokensConfig {
            registration_fee: 1_000_000_000,
            tokens: vec![],
            mint_cap_per_day: 0,
            max_tokens: None,
            burn_registration_fee: None,
            bound_note_value: None,
            incremental_root: None,
        });
        g.program_state = Some(randprotocol_core::ledger::program_state::ProgramStateConfig { cell_fee: 10_000_000 });
    })
    .await;
    let unknown = "ab".repeat(32);
    let limits = call(addr, "rand_getLimits", json!([])).await["result"].clone();
    assert_eq!(limits["envelope_bytes"], json!(randprotocol_core::notes::MEMO_ENVELOPE_BYTES), "{}", short(&limits));
    assert_eq!(limits["program_state"]["cell_fee"], json!("10000000"), "{}", short(&limits));
    for f in ["max_reads", "max_writes", "max_payouts"] {
        assert!(limits["program_state"][f].as_u64().is_some_and(|n| n > 0), "program_state.{f}: {}", short(&limits));
    }
    // An absent cell reads as 64 zeros, under the key asked for.
    let zeros = "00".repeat(32);
    let cell = call(addr, "rand_getProgramCell", json!([unknown, zeros])).await["result"].clone();
    assert_eq!(cell, json!({ "key": zeros, "value": zeros }));
    assert_eq!(
        call(addr, "rand_getProgramCells", json!([unknown, { "limit": 256 }])).await["result"],
        json!({ "cells": [], "next": null })
    );
    assert_eq!(call(addr, "rand_getProgramVault", json!([unknown])).await["result"], json!([]));
}

/// `rand_getLimits.fee_rules` with all three flags `true`, and `rand_getSupply.base_fees_burned`
/// beside it (randscan crates/randscan-core/src/types/stats.rs; the wallet's fee path through
/// randprotocol.org's relay). `subsidy_net_of_fees` needs an aggregation section and
/// `node::start` refuses one today, so this chain is served without a node behind it — both reads
/// are genesis and store state, which is all it needs.
///
/// TODO: this is a serialization check against an RPC server with no node behind it, not the live
/// path. Move it onto the live chain of
/// [`every_field_the_downstream_repos_read_is_served_with_its_type`] (`subsidy_net_of_fees: true`
/// beside an `aggregation` section) once `node::start` admits aggregation
/// (`check_build_runs_genesis`, `docs/aggregation.md` "Before enabling aggregation").
#[tokio::test]
async fn fee_rules_under_all_three_flags() {
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::ledger::aggregation::{AdmittedShape, AggregationConfig};
    use randprotocol_core::types::{DeclaredShape, FriProfile};
    use randprotocol_core::confidential::ConfidentialExecutor;

    let (addr, _served) = common::serve_genesis(|g| {
        let shape = DeclaredShape {
            profile: FriProfile::Test,
            tier: randprotocol_core::types::BUNDLE_PROOF_TIER,
            program_log_height: 12,
            input_log_height: 10,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: randprotocol_core::types::BUNDLE_PUBLIC_LOG_HEIGHT,
            mem_log_height: 16,
        };
        g.aggregation = Some(AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![AdmittedShape {
                shape,
                hc: randprotocol_core::Hash(randprotocol_core::notes::word8_to_bytes(&randprotocol_zkvm::executor::ZkExecutor::hc_bundle())),
                aggregate_program_digest: StubExecutor.aggregate_program_digest(&shape).unwrap(),
            }],
        });
        g.fees = Some(randprotocol_core::ledger::fees::FeesConfig {
            burn_base: Some(true),
            subsidy_net_of_fees: Some(true),
            burn_floor: Some(true),
            proposer_share_bps: None,
            prove_base: None,
            usd_subsidy: None,
        });
    })
    .await;
    let rows = [
        row("rand_getLimits", json!([]), "randscan crates/randscan-core/src/types/stats.rs `ChainLimits`", &[
            ("fee_rules.burn_base", Bool), ("fee_rules.subsidy_net_of_fees", Bool), ("fee_rules.burn_floor", Bool),
        ]),
        row("rand_getSupply", json!([]), "randscan crates/randscan-core/src/types/stats.rs `Supply`", &[
            ("base_fees_burned", Dec), ("burned", Dec), ("subsidised", Dec), ("sealed_blocks", Dec), ("invariant_holds", Bool),
            ("multisig_issued", Dec), ("multisig_rand_in", Dec), ("multisig_rand_out", Dec), ("multisig_base_out", Dec),
            ("multisig_rand_held", Dec),
        ]),
    ];
    check(addr, &rows).await;
    assert_eq!(
        call(addr, "rand_getLimits", json!([])).await["result"]["fee_rules"],
        json!({ "burn_base": true, "subsidy_net_of_fees": true, "burn_floor": true, "proposer_share_bps": null, "prove_base": null, "usd_subsidy": null })
    );
    assert_eq!(call(addr, "rand_getSupply", json!([])).await["result"]["base_fees_burned"], json!("0"));
}

/// Tree aggregation's `rand_status.aggregation.tree` (review m8; `rand-node aggregate --layout
/// tree` reads it): every digest is 64 lowercase hex characters, never a JSON number (a limb past
/// 2^53 would lose bits in a JavaScript reader), and the section reads back exactly. Absent on a
/// chain without the section. Served without a node behind it: the node loop publishes the
/// snapshot, and a node refuses every aggregating genesis today.
#[tokio::test]
async fn the_status_tree_section_serves_its_digests_as_hex() {
    use randprotocol_core::ledger::aggregation::{RvmHeights, TreeConfig, TreeStepPin};
    let (addr, served) = common::serve_genesis(|_| {}).await;
    let plain = call(addr, "rand_status", json!([])).await;
    assert!(plain["result"]["aggregation"].get("tree").is_none(), "absent without a section: {}", short(&plain));
    let h = RvmHeights { tier: 19, reg_log_height: 20, ram_log_height: 20, poseidon2_log_height: 15, reduce_log_height: 16 };
    let tree = TreeConfig {
        shape: randprotocol_core::types::DeclaredShape {
            profile: randprotocol_core::types::FriProfile::Test,
            tier: 14,
            program_log_height: 12,
            input_log_height: 10,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 7,
            mem_log_height: 16,
        },
        leaf_size: 1,
        max_depth: 2,
        leaf: h,
        vk_leaf: [u64::MAX, 1 << 60, 3, 4],
        steps: vec![TreeStepPin { heights: h, program_digest: [0xFFFF_FFFF_0000_0001, 6, 7, 8], key: [9, 10, 11, 12] }],
    };
    served.set_status(|s| s.aggregation.tree = Some(randprotocol_node::rpc::TreeStatus::of(&tree)));
    let rows = [row("rand_status", json!([]), "rand-node aggregate --layout tree (`daemon_tree_of`)", &[
        ("aggregation.tree.leaf_size", Int),
        ("aggregation.tree.max_depth", Int),
        ("aggregation.tree.leaf.tier", Int),
        ("aggregation.tree.vk_leaf", Hex),
        ("aggregation.tree.steps.0.heights.reduce_log_height", Int),
        ("aggregation.tree.steps.0.program_digest", Hex),
        ("aggregation.tree.steps.0.key", Hex),
    ])];
    check(addr, &rows).await;
    let v = call(addr, "rand_status", json!([])).await["result"]["aggregation"]["tree"].clone();
    assert_eq!(v["vk_leaf"], json!("ffffffffffffffff100000000000000000000000000000030000000000000004"));
    let back: randprotocol_node::rpc::TreeStatus = serde_json::from_value(v).unwrap();
    assert_eq!(back.to_config().unwrap(), tree, "the section reads back exactly");
}

/// The proposer/aggregator split (`docs/compute-optimization.md` §6.2–§6.3) on the wire:
/// `fee_rules.prove_base` is a decimal string like every amount, `proposer_share_bps` a number, and
/// `rand_estimateFee`'s bundle floor includes `prove_base`. Served without a node behind it, for
/// the reason `fee_rules_under_all_three_flags` gives (an aggregating genesis).
#[tokio::test]
async fn fee_rules_serve_prove_base_as_a_decimal_string() {
    use randprotocol_core::confidential::{ConfidentialExecutor, StubExecutor};
    use randprotocol_core::ledger::aggregation::{AdmittedShape, AggregationConfig};
    use randprotocol_core::types::{DeclaredShape, FriProfile};

    let (addr, _served) = common::serve_genesis(|g| {
        let shape = DeclaredShape {
            profile: FriProfile::Test,
            tier: randprotocol_core::types::BUNDLE_PROOF_TIER,
            program_log_height: 12,
            input_log_height: 10,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: randprotocol_core::types::BUNDLE_PUBLIC_LOG_HEIGHT,
            mem_log_height: 16,
        };
        g.aggregation = Some(AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![AdmittedShape {
                shape,
                hc: randprotocol_core::Hash(randprotocol_core::notes::word8_to_bytes(&randprotocol_zkvm::executor::ZkExecutor::hc_bundle())),
                aggregate_program_digest: StubExecutor.aggregate_program_digest(&shape).unwrap(),
            }],
        });
        g.fees = Some(randprotocol_core::ledger::fees::FeesConfig {
            proposer_share_bps: Some(4000),
            prove_base: Some(600_000),
            usd_subsidy: None,
            ..Default::default()
        });
    })
    .await;
    let rows = [row("rand_getLimits", json!([]), "randprotocol-client src/lib.rs `fee_rules_of`, `ChainLimits::prove_base`", &[
        ("fee_rules.prove_base", Dec),
    ])];
    check(addr, &rows).await;
    let rules = call(addr, "rand_getLimits", json!([])).await["result"]["fee_rules"].clone();
    assert_eq!(rules["prove_base"], json!("600000"), "an amount: a decimal string");
    assert_eq!(rules["proposer_share_bps"], json!(4000), "a share: a number");
    assert_eq!(call(addr, "rand_estimateFee", json!([{"kind": "bundle"}])).await["result"], json!("1600000"));
}

/// The dollar-indexed subsidy (`docs/fees.md` §1.3) on the wire: `fee_rules.usd_subsidy`'s three
/// numbers (the two amounts decimal strings, the age a number) and `rand_getRandPrice`'s shape,
/// read by the aggregate daemon (`aggregate_pass`) and `rand-node price`; `rand_getEmission`'s
/// `current` is the dollar target at the genesis price, `⌊4 791 · 10⁹ / 150 000⌋`. Served without
/// a node behind it, for the reason `fee_rules_under_all_three_flags` gives (an aggregating
/// genesis).
#[tokio::test]
async fn usd_subsidy_rules_and_the_rand_price_on_the_wire() {
    use randprotocol_core::confidential::{ConfidentialExecutor, StubExecutor};
    use randprotocol_core::ledger::aggregation::{AdmittedShape, AggregationConfig};
    use randprotocol_core::types::{DeclaredShape, FriProfile};

    let (addr, _served) = common::serve_genesis(|g| {
        let shape = DeclaredShape {
            profile: FriProfile::Test,
            tier: randprotocol_core::types::BUNDLE_PROOF_TIER,
            program_log_height: 12,
            input_log_height: 10,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: randprotocol_core::types::BUNDLE_PUBLIC_LOG_HEIGHT,
            mem_log_height: 16,
        };
        g.aggregation = Some(AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![AdmittedShape {
                shape,
                hc: randprotocol_core::Hash(randprotocol_core::notes::word8_to_bytes(&randprotocol_zkvm::executor::ZkExecutor::hc_bundle())),
                aggregate_program_digest: StubExecutor.aggregate_program_digest(&shape).unwrap(),
            }],
        });
        g.fees = Some(randprotocol_core::ledger::fees::FeesConfig {
            usd_subsidy: Some(randprotocol_core::ledger::fees::UsdSubsidy {
                usd_micros_per_sealed_block: 4_791,
                max_subsidy_per_block: 300_000_000,
                price_max_age_blocks: 72_000,
                initial_price_micros: 150_000,
            }),
            ..Default::default()
        });
    })
    .await;
    let rows = [
        row("rand_getLimits", json!([]), "randprotocol-client src/lib.rs `fee_rules_of` (`usd_subsidy_of`)", &[
            ("fee_rules.usd_subsidy.usd_micros_per_sealed_block", Dec),
            ("fee_rules.usd_subsidy.max_subsidy_per_block", Dec),
            ("fee_rules.usd_subsidy.price_max_age_blocks", Int),
        ]),
        row("rand_getRandPrice", json!([]), "rand-node `aggregate` (`aggregate_pass`), `price status`", &[
            ("price_micros_per_rand", Dec),
            ("set_at_height", Int),
            ("nonce", Int),
            ("fresh", Bool),
            ("max_age_blocks", Int),
        ]),
        row("rand_getEmission", json!([]), "randscan emission panel", &[("subsidy.current", Dec)]),
    ];
    check(addr, &rows).await;
    assert_eq!(
        call(addr, "rand_getRandPrice", json!([])).await["result"],
        json!({ "price_micros_per_rand": "150000", "set_at_height": 0, "nonce": 0, "fresh": true, "max_age_blocks": 72_000 })
    );
    assert_eq!(
        call(addr, "rand_getLimits", json!([])).await["result"]["fee_rules"]["usd_subsidy"],
        json!({ "usd_micros_per_sealed_block": "4791", "max_subsidy_per_block": "300000000", "price_max_age_blocks": 72_000 })
    );
    assert_eq!(call(addr, "rand_getEmission", json!([])).await["result"]["subsidy"]["current"], json!("31940000"));
}

/// randprotocol.org's sale relay (server/sale/src/rpc.rs `RPC_ALLOWED`) forwards exactly the
/// node's public listener's set, by name: a method dropped from [`PUBLIC_METHODS`] is a method the
/// relay forwards to a node that refuses it. A copy of the relay's list as of randprotocol.org
/// `e77ec7a` (2026-10-01), so it goes stale when the relay adds a method; the authoritative check
/// is randprotocol.org's own `server/sale/tests/real_node.rs` against a real node.
///
/// [`PUBLIC_METHODS`]: randprotocol_node::rpc::PUBLIC_METHODS
#[test]
fn the_sale_relays_allowlist_is_inside_the_public_listeners_set() {
    const RELAY: &[&str] = &[
        "rand_chainId", "rand_status", "rand_getVersion", "rand_getGenesisHash", "rand_getHealth", "rand_getLimits",
        "rand_getHead", "rand_getFinality", "rand_getProposer", "rand_getMempoolInfo", "rand_tokenInfo",
        "rand_getTreeInfo", "rand_getCommitments", "rand_getNullifiers", "rand_getCompactBlocks", "rand_getAnchor",
        "rand_getWitness", "rand_getWitnesses", "rand_estimateFee",
        "rand_checkTransaction", "rand_sendTransaction", "rand_getTransaction", "rand_getTransactionStatus", "rand_getRawTransaction",
        "rand_getReceipt", "rand_getReceipts", "rand_getCallEnvelope",
        "rand_getProgram", "rand_getProgramCode", "rand_getProgramPublic",
        "rand_getProgramCell", "rand_getProgramCells", "rand_getProgramVault", "rand_getAdmitted", "rand_syncStatus",
        "rand_getAggregate", "rand_getAggregators", "rand_getUnsealed",
        "rand_getVesting", "rand_getVestingSchedule", "rand_getVestingSummary",
        "rand_getBlockByHeight", "rand_getBlockByHash", "rand_getBlocks",
        "rand_getValidators", "rand_getEpoch", "rand_getSupply", "rand_getEmission",
        "rand_getTokens", "rand_getToken", "rand_getTokenSupply",
        "rand_getBridgeState", "rand_getAssets", "rand_getBridgeBurn", "rand_bridgeAssetId",
    ];
    let missing: Vec<_> = RELAY.iter().filter(|m| !randprotocol_node::rpc::PUBLIC_METHODS.contains(m)).collect();
    assert!(missing.is_empty(), "the sale relay forwards methods the public listener refuses: {missing:?}");
}

/// RPL-3: the reads durian.market's perps frontend and its `perp-prover` make on a chain with a
/// `perps` section, field by field (durian.market web/lib/perps/client.ts `parsePerps`,
/// crates/perp-prover/src/rpc.rs `PerpsInfo`/`parse_perp_inputs`), and `rand_getLimits.perps`
/// (randprotocol-client src/lib.rs `PerpsLimits`). Served without a node behind it: these are
/// genesis and store reads, and one block's input row is seeded into the store directly, as a
/// committed block would have written it.
#[tokio::test]
async fn perps_reads_under_a_perps_section() {
    let (addr, _served) = common::serve_genesis_seeded(
        |g| {
            g.tokens = Some(TokensConfig {
                registration_fee: 1_000_000_000,
                tokens: vec![],
                mint_cap_per_day: 100_000 * 100_000_000,
                max_tokens: None,
                burn_registration_fee: None,
                bound_note_value: None,
                incremental_root: None,
            });
            g.gas = Some(randprotocol_core::gas::GasConfig {
                gas_price: 100,
                byte_price: randprotocol_core::gas::BYTE_PRICE_DEFAULT,
                bundle_gas_limit: randprotocol_core::gas::bundle_gas_limit_pin(),
                metering: randprotocol_core::gas::GasMetering::Circuit,
                dynamic: None,
            });
            g.hardening_v6 = Some(true);
            g.hc_auth = Some("11".repeat(32));
            g.max_block_bytes = Some(20 << 20);
            g.perps = Some(randprotocol_core::ledger::perps::PerpsConfig {
                collateral_asset: 0,
                max_tier: 16,
                max_window_blocks: 8,
                max_block_inputs: 8,
                min_deposit: 1_000,
                engine_hc: [31; 8],
                genesis_root: [32; 8],
                markets: vec![randprotocol_core::ledger::perps::MarketSpec {
                    id: 0,
                    symbol: "BTC-PERP".into(),
                    lot: 1_000_000,
                    tick: 1_000,
                    max_leverage: 10,
                    maintenance_bps: 500,
                    taker_fee_bps: 5,
                    maker_fee_bps: 2,
                }],
            });
        },
        |storage| storage.put_perp_inputs(1, &[1, 2, 3]).unwrap(),
    )
    .await;
    let rows = [
        // durian.market web/lib/perps/client.ts `parsePerps` / `decodeMarket`; crates/perp-prover
        // src/rpc.rs `PerpsInfo` / `ChainMarket` / `Median` (each u64 a number or a decimal string).
        row("rand_getPerps", json!([]), "durian.market web/lib/perps/client.ts `parsePerps`, crates/perp-prover/src/rpc.rs `PerpsInfo`", &[
            ("enabled", Bool), ("collateral_asset", Int), ("max_tier", Int), ("max_window_blocks", Int),
            ("engine_hc", Hex), ("genesis_root", Hex), ("markets", Arr),
            ("markets.0.id", Int), ("markets.0.symbol", Str), ("markets.0.lot", Int), ("markets.0.tick", Int),
            ("markets.0.max_leverage", Int), ("markets.0.maintenance_bps", Int), ("markets.0.taker_fee_bps", Int),
            ("markets.0.maker_fee_bps", Int),
            ("proved_root", Hex), ("proved_height", Int), ("head_height", Int), ("pending_heights", Arr),
            ("medians", Arr), ("medians.0.market", Int), ("medians.0.price", Dec),
            ("accounts", Int), ("pending_withdrawals", Int),
        ]),
        // durian.market crates/perp-prover/src/rpc.rs `parse_perp_inputs` (`{height, words}`).
        row("rand_getPerpInputs", json!([1]), "durian.market crates/perp-prover/src/rpc.rs `parse_perp_inputs`", &[
            ("height", Int), ("words", Arr), ("words.0", Int),
        ]),
        exactly("rand_getPerpInputs", json!([2]), "durian.market crates/perp-prover/src/rpc.rs `parse_perp_inputs`", Value::Null),
        // randprotocol-client src/lib.rs `PerpsLimits`.
        row("rand_getLimits", json!([]), "randprotocol-client src/lib.rs `PerpsLimits`", &[
            ("perps.collateral_asset", Int), ("perps.max_tier", Int), ("perps.max_window_blocks", Int), ("perps.max_payouts", Int),
        ]),
    ];
    check(addr, &rows).await;
    // The engine commitments are exactly the section's, as the prover compares them.
    let perps = call(addr, "rand_getPerps", json!([])).await;
    assert_eq!(perps["result"]["enabled"], json!(true));
    assert_eq!(perps["result"]["engine_hc"], json!(randprotocol_core::notes::word8_to_hex(&[31; 8])));
}
