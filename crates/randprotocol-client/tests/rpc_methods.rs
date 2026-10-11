//! `RpcClient`'s typed methods against a loopback node: the reply shapes it decodes and the
//! malformed ones it refuses, by name. The in-crate tests cover the transport (retries, caps,
//! timeouts); this covers the decoding of each method's reply.

mod common;

use common::*;
use randprotocol_client::RpcClient;
use randprotocol_core::notes::{word8_to_hex, DEPTH};
use randprotocol_core::Hash;
use serde_json::{json, Value};

fn node(f: impl Fn(&str, &Value) -> Result<Value, (i64, String)> + Send + Sync + 'static) -> RpcClient {
    RpcClient::new(fake(Box::new(f)).url)
}

fn w(n: u32) -> String {
    word8_to_hex(&[n; 8])
}

fn pid() -> randprotocol_core::program::ProgramId {
    Hash::from_hex(&"5a".repeat(32)).unwrap()
}

#[tokio::test]
async fn program_code_and_public_decode_and_distinguish_unknown_from_empty() {
    let rpc = node(|m, p| match (m, p[0].as_str().unwrap()) {
        ("rand_getProgramCode", id) if id == "5a".repeat(32) => Ok(json!({ "base_pc": 4096, "words": [1, 2, 3] })),
        ("rand_getProgramCode", _) => Ok(Value::Null),
        // Words are little-endian hex: 01000000 02000000.
        ("rand_getProgramPublic", id) if id == "5a".repeat(32) => Ok(json!("0100000002000000")),
        ("rand_getProgramPublic", _) => Ok(Value::Null),
        _ => Err((-32601, "nope".into())),
    });
    assert_eq!(rpc.program_code(&pid()).await.unwrap(), Some((4096, vec![1, 2, 3])));
    assert_eq!(rpc.program_code(&Hash::from_hex(&"00".repeat(32)).unwrap()).await.unwrap(), None);
    assert_eq!(rpc.program_public(&pid()).await.unwrap(), Some(vec![1, 2]));
    assert_eq!(rpc.program_public(&Hash::from_hex(&"00".repeat(32)).unwrap()).await.unwrap(), None);
}

#[tokio::test]
async fn program_public_from_a_node_that_predates_the_method_is_empty_not_unknown() {
    let rpc = node(|_, _| Err((-32601, "method not found".into())));
    assert_eq!(rpc.program_public(&pid()).await.unwrap(), Some(vec![]));
    let rpc = node(|_, _| Err((-32000, "boom".into())));
    assert!(rpc.program_public(&pid()).await.is_err(), "any other error is an error");
    let rpc = node(|_, _| Ok(json!(7)));
    assert!(rpc.program_public(&pid()).await.unwrap_err().to_string().contains("did not return a hex string"));
}

#[tokio::test]
async fn program_cell_cells_and_vault_refuse_malformed_replies() {
    let rpc = node(|m, _| match m {
        "rand_getProgramCell" => Ok(json!({ "enabled": true })),
        "rand_getProgramCells" => Ok(json!({ "cells": [{ "key": "zz", "value": w(1) }] })),
        "rand_getProgramVault" => Ok(json!([{ "asset": 1 }])),
        _ => Err((-32601, "nope".into())),
    });
    assert!(rpc.program_cell(&pid(), &[0; 8]).await.unwrap_err().to_string().contains("did not return a value"));
    assert!(rpc.program_cells(&pid(), None, 10).await.unwrap_err().to_string().contains("is not 64 hex"));
    assert!(rpc.program_vault(&pid()).await.unwrap_err().to_string().contains("without its amount"));

    let rpc = node(|m, _| match m {
        "rand_getProgramCell" => Ok(json!({ "enabled": true, "value": "nothex" })),
        "rand_getProgramCells" => Ok(json!({ "cells": [], "next": "nothex" })),
        "rand_getProgramVault" => Ok(json!({ "not": "a list" })),
        _ => Err((-32601, "nope".into())),
    });
    assert!(rpc.program_cell(&pid(), &[0; 8]).await.unwrap_err().to_string().contains("value is not 64 hex"));
    assert!(rpc.program_cells(&pid(), Some(&[1; 8]), 10).await.unwrap_err().to_string().contains("next is not 64 hex"));
    assert!(rpc.program_vault(&pid()).await.unwrap_err().to_string().contains("did not return a list"));

    let rpc = node(|m, p| match m {
        "rand_getProgramCells" => {
            assert_eq!(p[1]["after"], json!(w(1)), "the continuation key is sent");
            assert_eq!(p[1]["limit"], 10);
            Ok(json!({ "cells": [{ "key": w(2), "value": w(3) }], "next": w(2) }))
        }
        _ => Err((-32601, "nope".into())),
    });
    let (cells, next) = rpc.program_cells(&pid(), Some(&[1; 8]), 10).await.unwrap().unwrap();
    assert_eq!((cells.len(), cells[0].key, cells[0].value, next), (1, [2; 8], [3; 8], Some([2; 8])));
}

#[tokio::test]
async fn anchor_witness_and_tree_info_decode() {
    let path: Vec<String> = (0..DEPTH as u32).map(w).collect();
    let rpc = {
        let path = path.clone();
        node(move |m, p| match m {
            "rand_getAnchor" => Ok(json!({ "height": p.as_array().and_then(|a| a.first()).and_then(Value::as_u64).unwrap_or(99), "root": w(7) })),
            "rand_getWitness" if p[0] == 5 => Ok(json!({ "root": w(8), "path": path })),
            "rand_getWitness" if p[0] == 6 => Ok(json!({ "root": w(8), "path": [w(1)] })),
            "rand_getWitness" if p[0] == 7 => Ok(json!({ "root": w(8), "path": vec!["zz"; DEPTH] })),
            "rand_getWitness" => Ok(Value::Null),
            "rand_getTreeInfo" => Ok(json!({ "next_index": 12, "root": w(9), "nullifiers": 3 })),
            _ => Err((-32601, "nope".into())),
        })
    };
    assert_eq!(rpc.anchor(None).await.unwrap(), (99, [7; 8]));
    assert_eq!(rpc.anchor(Some(4)).await.unwrap(), (4, [7; 8]));
    let (root, got) = rpc.witness(5).await.unwrap();
    assert_eq!(root, [8; 8]);
    assert_eq!(got[3], [3; 8]);
    assert!(rpc.witness(6).await.unwrap_err().to_string().contains(&format!("witness path is 1 levels, expected {DEPTH}")));
    assert!(rpc.witness(7).await.unwrap_err().to_string().contains("path level is not 64 hex"));
    assert!(rpc.witness(8).await.unwrap_err().to_string().contains("no leaf at index 8"));
    let t = rpc.tree_info().await.unwrap();
    assert_eq!((t.next_index, t.root, t.nullifiers), (12, [9; 8], 3));
}

#[tokio::test]
async fn commitments_and_nullifiers_decode_rows_and_name_the_missing_field() {
    let row = json!({ "index": 4, "cm": w(1), "height": 9, "envelope": { "kem_ct": "01", "to_receiver": "02", "to_sender": "03", "body": "04" } });
    let rpc = {
        let row = row.clone();
        node(move |m, p| match m {
            "rand_getCommitments" if p[0] == 0 => Ok(json!([row])),
            "rand_getCommitments" if p[0] == 1 => Ok(json!([{ "index": 4, "cm": w(1), "height": 9 }])),
            "rand_getCommitments" => Ok(json!({ "not": "a list" })),
            "rand_getNullifiers" => Ok(json!([{ "height": 3, "nullifier": w(6) }])),
            _ => Err((-32601, "nope".into())),
        })
    };
    let rows = rpc.commitments(0, 10).await.unwrap();
    assert_eq!((rows[0].index, rows[0].cm, rows[0].height), (4, [1; 8], 9));
    assert_eq!((rows[0].envelope.kem_ct.clone(), rows[0].envelope.body.clone()), (vec![1], vec![4]));
    assert!(rpc.commitments(1, 10).await.unwrap_err().to_string().contains("envelope"));
    assert!(rpc.commitments(2, 10).await.unwrap_err().to_string().contains("did not return a list"));
    assert_eq!(rpc.nullifiers(0, 10).await.unwrap(), vec![(3, [6; 8])]);
}

#[tokio::test]
async fn call_envelope_decodes_or_is_none() {
    let rpc = node(|m, p| match (m, p[0].as_str().unwrap()) {
        ("rand_getCallEnvelope", h) if h == "11".repeat(32) => Ok(json!({ "kem_ct": "aa", "to_sender": "bb", "to_auditor": "cc", "body": "dd", "h_in": w(5) })),
        ("rand_getCallEnvelope", h) if h == "22".repeat(32) => Ok(json!({ "kem_ct": "aa" })),
        ("rand_getCallEnvelope", _) => Ok(Value::Null),
        _ => Err((-32601, "nope".into())),
    });
    let (h_in, e) = rpc.call_envelope(&Hash::from_hex(&"11".repeat(32)).unwrap()).await.unwrap().unwrap();
    assert_eq!((h_in, e.kem_ct, e.to_sender, e.to_auditor, e.body), ([5; 8], vec![0xaa], vec![0xbb], vec![0xcc], vec![0xdd]));
    assert!(rpc.call_envelope(&Hash::from_hex(&"22".repeat(32)).unwrap()).await.unwrap_err().to_string().contains("to_sender missing"));
    assert!(rpc.call_envelope(&Hash::from_hex(&"33".repeat(32)).unwrap()).await.unwrap().is_none());
}

#[tokio::test]
async fn viewing_key_and_payment_proof_calls_send_their_parameters() {
    let server = fake(Box::new(|m, p| match m {
        "rand_importViewingKey" => Ok(json!({ "imported": true, "params": p })),
        "rand_getViewingNotes" => Ok(json!({ "notes": [], "complete": true })),
        "rand_checkTransaction" if p[1] == "bad" => Ok(Value::Null),
        "rand_checkTransaction" => Ok(json!({ "disclosed": [] })),
        _ => Err((-32601, "nope".into())),
    }));
    let rpc = RpcClient::new(server.url.clone());
    let nk = "ab".repeat(32);
    assert_eq!(rpc.import_viewing_key(&nk, None).await.unwrap()["params"], json!([nk]));
    assert_eq!(rpc.import_viewing_key(&nk, Some(5)).await.unwrap()["params"], json!([nk, 5]));
    assert_eq!(rpc.viewing_notes(&nk, 3, 50).await.unwrap()["complete"], true);
    assert_eq!(server.params_of("rand_getViewingNotes").unwrap(), json!([nk, 3, 50]));
    let h = Hash::from_hex(&"44".repeat(32)).unwrap();
    assert_eq!(rpc.check_transaction(&h, "good").await.unwrap(), Some(json!({ "disclosed": [] })));
    assert_eq!(rpc.check_transaction(&h, "bad").await.unwrap(), None);
}

#[tokio::test]
async fn simple_reads_pass_the_reply_through() {
    let rpc = node(|m, p| match m {
        "rand_getEpoch" => Ok(json!({ "epoch": 2 })),
        "rand_getBridgeState" => Ok(json!({ "enabled": false })),
        "rand_getBridgeBurn" => Ok(if p[0] == 1 { json!({ "sequence": 1 }) } else { Value::Null }),
        "rand_bridgeAssetId" => Ok(json!(format!("{}-{}", p[0], p[1].as_str().unwrap()))),
        "rand_getPerps" => Ok(json!({ "enabled": false })),
        "rand_getPerpAccount" => Ok(Value::Null),
        "rand_getPerpInputs" => Ok(Value::Null),
        "rand_getGenesisHash" => Ok(json!("zz")),
        "rand_chainId" => Ok(json!("not a number")),
        "rand_getTransaction" => Ok(json!({ "height": 1, "block_hash": "zz" })),
        "rand_getReceipt" => Ok(json!({ "ok": true })),
        "rand_estimateFee" => Ok(json!("oops")),
        "rand_mint" => Ok(json!(5)),
        "rand_sendTransaction" => Ok(json!("short")),
        _ => Err((-32601, "nope".into())),
    });
    assert_eq!(rpc.epoch().await.unwrap()["epoch"], 2);
    assert_eq!(rpc.bridge_state().await.unwrap()["enabled"], false);
    assert!(rpc.bridge_burn(1).await.unwrap().is_some() && rpc.bridge_burn(2).await.unwrap().is_none());
    let tok = [1u8; 32];
    assert_eq!(rpc.bridge_asset_id(2, &tok).await.unwrap(), format!("2-{}", "01".repeat(32)));
    assert_eq!(rpc.get_perps().await.unwrap()["enabled"], false);
    assert!(rpc.get_perp_account(&[0; 8]).await.unwrap().is_none());
    assert!(rpc.get_perp_inputs(3).await.unwrap().is_none());
    assert!(rpc.genesis_hash().await.unwrap_err().to_string().contains("bad genesis hash in reply"));
    assert!(rpc.chain_id().await.is_err());
    assert!(rpc.transaction(&Hash::from_hex(&"00".repeat(32)).unwrap()).await.is_err(), "a block hash that does not parse is an error");
    assert!(rpc.estimate_fee(json!({})).await.unwrap_err().to_string().contains("fee"));
    assert!(rpc.mint_shielded("rand1x", None).await.unwrap_err().to_string().contains("bad hash in reply"));
    let tx = randprotocol_core::Transaction { chain_id: 1, bundle: None, action: randprotocol_core::Action::None };
    assert!(rpc.send_transaction(&tx).await.unwrap_err().to_string().contains("bad hash in reply"));
    let r = rpc.receipt(&Hash::from_hex(&"00".repeat(32)).unwrap()).await.unwrap();
    assert_eq!(r, Some(json!({ "ok": true })));
}

#[tokio::test]
async fn wait_for_receipt_returns_when_stored_and_times_out_otherwise() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let polls = Arc::new(AtomicUsize::new(0));
    let p2 = polls.clone();
    let rpc = node(move |m, _| match m {
        "rand_getReceipt" if p2.fetch_add(1, Ordering::SeqCst) >= 1 => Ok(json!({ "ok": true })),
        "rand_getReceipt" => Ok(Value::Null),
        _ => Err((-32601, "nope".into())),
    });
    let h = Hash::from_hex(&"00".repeat(32)).unwrap();
    let r = rpc.wait_for_receipt(&h, std::time::Duration::from_secs(5)).await.unwrap();
    assert_eq!(r["ok"], true);
    assert!(polls.load(Ordering::SeqCst) >= 2, "the first poll found nothing");

    let never = node(|_, _| Ok(Value::Null));
    let e = never.wait_for_receipt(&h, std::time::Duration::ZERO).await.unwrap_err().to_string();
    assert!(e.contains("no receipt for"), "{e}");
}

#[tokio::test]
async fn wait_for_transaction_falls_back_to_the_legacy_poll_and_times_out() {
    // A node older than v0.3: no rand_getTransactionStatus (-32601) — the wait polls
    // rand_getTransaction instead, and remembers to.
    let rpc = node(|m, _| match m {
        "rand_getTransaction" => Ok(json!({ "height": 4, "index": 2, "block_hash": "aa".repeat(32) })),
        _ => Err((-32601, "method not found".into())),
    });
    let h = Hash::from_hex(&"00".repeat(32)).unwrap();
    let r = rpc.wait_for_transaction(&h, std::time::Duration::from_secs(5)).await.unwrap();
    assert_eq!((r.height, r.index), (4, 2));
    let again = rpc.wait_for_transaction(&h, std::time::Duration::from_secs(5)).await.unwrap();
    assert_eq!(again.height, 4);

    let pending = node(|m, _| match m {
        "rand_getTransactionStatus" => Ok(json!([{ "status": "pending" }])),
        _ => Err((-32601, "nope".into())),
    });
    let e = pending.wait_for_transaction(&h, std::time::Duration::ZERO).await.unwrap_err().to_string();
    assert!(e.contains("not committed within"), "{e}");
    let legacy_pending = node(|_, _| Err((-32601, "method not found".into())));
    assert!(legacy_pending.wait_for_transaction(&h, std::time::Duration::ZERO).await.is_err());
    let status_error = node(|_, _| Err((-32000, "db down".into())));
    assert!(status_error.wait_for_transaction(&h, std::time::Duration::from_secs(1)).await.unwrap_err().to_string().contains("db down"));
}
