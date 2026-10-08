//! The RPC contract the downstream repos read, as a canary in this repo's fast CI.
//!
//! Four repos consume this node's JSON-RPC: randscan (its indexer), randbridge.org (the status
//! service), randprotocol.org (the sale relay and the balance viewer) and zusd.money (through
//! randscan's REST, which is these same reads). Their own integration tests spawn a real
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
        row("rand_chainId", json!([]), "randscan rpc.rs, randbridge.org status/src/rand.rs, randprotocol.org", &[("", Int)]),
        // randscan crates/randscan-indexer/src/rpc.rs `TokenInfo`.
        row("rand_tokenInfo", json!([]), "randscan crates/randscan-indexer/src/rpc.rs", &[("symbol", Str), ("decimals", Int)]),
        // randscan crates/randscan-indexer/src/rpc.rs `RpcVersion`.
        row("rand_getVersion", json!([]), "randscan crates/randscan-indexer/src/rpc.rs", &[("version", Str), ("git_sha", Str), ("fri_profile", Str)]),
        // randscan crates/randscan-indexer/src/rpc.rs `genesis_hash`.
        row("rand_getGenesisHash", json!([]), "randscan crates/randscan-indexer/src/rpc.rs", &[("", Hex)]),
        // ---- the head and the node ----
        // randscan crates/randscan-indexer/src/rpc.rs `Head`; randbridge.org status/src/rand.rs (`height`).
        row("rand_getHead", json!([]), "randscan rpc.rs `Head`, randbridge.org status/src/rand.rs", &[("height", Int), ("hash", Hex), ("view", Int)]),
        // randscan crates/randscan-indexer/src/rpc.rs `NodeStatus` (every field is `serde(default)`
        // there, so a drop would be silent downstream — which is why it is pinned here).
        row("rand_status", json!([]), "randscan crates/randscan-indexer/src/rpc.rs `NodeStatus`", &[
            ("height", Int), ("head_hash", Hex), ("view", Int), ("high_qc_view", Int), ("syncing", Bool), ("sync_target", Int),
            ("peer_count", Int), ("mempool_size", Int), ("is_validator", Bool), ("active_validator", Bool), ("faucet", Bool),
            ("confidential", Bool), ("fri_profile", Str), ("programs", Int), ("notes", Int), ("nullifiers", Int),
            ("tree_root", Hex), ("hc_bundle", Hex), ("hc_auth", Null), ("address", Str), ("peer_id", Str),
            ("gas_prices.gas_price", Dec), ("gas_prices.byte_price", Dec),
        ]),
        // randscan crates/randscan-indexer/src/rpc.rs `RpcPeer` (an empty list on one validator).
        exactly("rand_getPeers", json!([]), "randscan crates/randscan-indexer/src/rpc.rs `RpcPeer`", json!([])),
        // ---- limits and supply ----
        // randscan crates/randscan-core/src/types/stats.rs `ChainLimits`; randprotocol.org (the
        // wallet's fee path through the relay).
        row("rand_getLimits", json!([]), "randscan crates/randscan-core/src/types/stats.rs `ChainLimits`", &[
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
        Row { method: "rand_getBlockByHeight", params: json!([height]), expect: Expect::Fields(BLOCK), consumer: "randscan rpc.rs `RpcBlock`, randbridge.org status/src/rand.rs" },
        Row { method: "rand_getBlockByHash", params: json!([block_hash]), expect: Expect::Fields(BLOCK), consumer: "randscan crates/randscan-indexer/src/rpc.rs `RpcBlock`" },
        // A height past the head: `null`, which randscan's `block_by_height` reads as "not yet".
        exactly("rand_getBlockByHeight", json!([height + 1_000_000]), "randscan crates/randscan-indexer/src/rpc.rs", Value::Null),
        // randscan crates/randscan-api/tests/real_node.rs (the transaction page).
        row("rand_getTransaction", json!([tx]), "randscan crates/randscan-api", &[
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
        row("rand_getCommitments", json!([0, 10]), "randscan crates/randscan-indexer/src/rpc.rs `RpcCommitment`", &[
            ("0.index", Int), ("0.cm", Hex), ("0.height", Int), ("0.envelope", Obj),
        ]),
        // randscan crates/randscan-indexer/src/rpc.rs `RpcTreeInfo`.
        row("rand_getTreeInfo", json!([]), "randscan crates/randscan-indexer/src/rpc.rs `RpcTreeInfo`", &[("next_index", Int), ("root", Hex), ("nullifiers", Int)]),
        // randprotocol.org src/scripts/balance.js `fetchSpent` (rows `{height, nullifier}`; no
        // spend has happened here, so the page is empty and the row shape is `rpc.rs`'s own test's).
        exactly("rand_getNullifiers", json!([0, 1000]), "randprotocol.org src/scripts/balance.js `fetchSpent`", json!([])),
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
        row("rand_getBridgeState", json!([]), "randscan types/bridge.rs, randbridge.org status/src/rand.rs, zusd.money BalanceSheet.astro", &[
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
        row("rand_getAssets", json!([]), "randscan types/bridge.rs `BridgeAsset`, zusd.money BalanceSheet.astro `Asset`", &[
            ("0.index", Int), ("0.chain", Int), ("0.token", Hex), ("0.asset_id", Hex), ("0.decimals", Int), ("0.locked", Dec),
            ("0.minted_today", Dec), ("0.mint_day", Int), ("0.mint_cap_per_day", Dec),
        ]),
        // randbridge.org status/src/rand.rs `source_of` (`tx` of a burn); no burn has happened.
        exactly("rand_getBridgeBurn", json!([0]), "randbridge.org status/src/rand.rs", Value::Null),
        // randscan crates/randscan-core/src/types/token.rs `TokenList`/`TokenInfo`; randprotocol.org
        // src/scripts/balance.js `fetchRegistry` (`tokens[].index`); zusd.money (via randscan).
        row("rand_getTokens", json!([0, 1000]), "randscan types/token.rs `TokenList`, randprotocol.org balance.js `fetchRegistry`", &[
            ("enabled", Bool), ("registration_fee", Dec), ("next_index", Int), ("tokens", Arr),
            ("tokens.0.index", Int), ("tokens.0.id", Hex), ("tokens.0.id_text", Str), ("tokens.0.name", Str),
            ("tokens.0.symbol", Str), ("tokens.0.decimals", Int), ("tokens.0.authority", Obj), ("tokens.0.mint_nonce", Int),
            ("tokens.0.total_supply", Dec), ("tokens.0.registered_at", Int),
        ]),
        // randscan crates/randscan-core/src/types/token.rs `TokenInfo`; randprotocol.org
        // src/scripts/balance.js `getToken`.
        row("rand_getToken", json!([1]), "randscan types/token.rs `TokenInfo`, randprotocol.org balance.js `getToken`", &[
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
        exactly("rand_getProgram", json!([unknown]), "randscan crates/randscan-indexer/src/rpc.rs `program`", Value::Null),
        // randscan crates/randscan-indexer/src/rpc.rs `program_vault`/`program_cells`: without a
        // `program_state` section both answer `{"enabled": false}`, which the indexer reads as `None`.
        exactly("rand_getProgramVault", json!([unknown]), "randscan crates/randscan-indexer/src/rpc.rs `program_vault`", json!({ "enabled": false })),
        // Multisig accounts: without a `multisig` section `{"enabled": false}`, `rand_getVesting`'s
        // and `rand_getProgramVault`'s shape (no consumer yet; the CLI's `multisig status` reads it).
        exactly("rand_getMultisig", json!([unknown]), "rand-node `multisig status`", json!({ "enabled": false })),
        exactly(
            "rand_getProgramCells",
            json!([unknown, { "after": null, "limit": 10 }]),
            "randscan crates/randscan-indexer/src/rpc.rs `program_cells`",
            json!({ "enabled": false }),
        ),
    ];
    let mut rows = rows;
    // randprotocol.org server/sale/src/rpc.rs (the relay forwards the answer to the wallet).
    // A second, distinct mint: the first one is in the pool, and a resubmission is refused.
    rows.push(row("rand_sendTransaction", json!([hex::encode(mint(10).encode())]), "randprotocol.org server/sale/src/rpc.rs", &[("", Hex)]));
    let checked = check(addr, &rows).await;
    assert!(checked > 150, "the table shrank to {checked} checks");

    // The exact values the fee rows above only type-check: this chain's two live rules.
    let limits = call(addr, "rand_getLimits", json!([])).await;
    assert_eq!(limits["result"]["fee_rules"], json!({ "burn_base": true, "subsidy_net_of_fees": false, "burn_floor": true, "proposer_share_bps": null, "prove_base": null }));

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
    // And no `fees` section: no rules, nothing burned.
    let limits = call(addr, "rand_getLimits", json!([])).await;
    assert_eq!(limits["result"]["fee_rules"], Value::Null, "{limits}");
    let supply = call(addr, "rand_getSupply", json!([])).await;
    assert_eq!(supply["result"]["base_fees_burned"], json!("0"), "{supply}");

    node.shutdown().await;
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
        json!({ "burn_base": true, "subsidy_net_of_fees": true, "burn_floor": true, "proposer_share_bps": null, "prove_base": null })
    );
    assert_eq!(call(addr, "rand_getSupply", json!([])).await["result"]["base_fees_burned"], json!("0"));
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
