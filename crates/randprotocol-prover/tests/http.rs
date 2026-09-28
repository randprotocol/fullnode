use randprotocol_prover::http::{serve, MAX_BODY_BYTES};
use randprotocol_prover::key::ProverKey;
use randprotocol_prover::pairing::Pairings;
use randprotocol_prover::service::{Config, ProveFn};
use randprotocol_prover::wire::*;
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::hidden::hidden_input;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn ok_prover() -> ProveFn { Arc::new(|_, _, inputs, _, _| Ok((vec![0xAA; 64], [inputs[0]; 8], 14))) }

async fn start() -> (SocketAddr, Vec<u8>, [u8; 32], reqwest::Client) {
    let key = ProverKey::from_seed([4; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let token = pairings.pair("laptop", true).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.accept_spend_key = true;
    cfg.prove = ok_prover();
    let (addr, _svc, _task) = serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();
    (addr, ek, token, reqwest::Client::new())
}

async fn rpc(http: &reqwest::Client, addr: SocketAddr, method: &str, params: Value) -> Value {
    http.post(format!("http://{addr}/")).json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).send().await.unwrap().json().await.unwrap()
}

fn job(token: [u8; 32]) -> ProveJob {
    ProveJob { version: WIRE_VERSION, token, witness_kind: WitnessKind::SpendKey, hc_bundle: ZkExecutor::hc_bundle(), profile: "test".into(), binding: [1; 8], inputs: vec![42; hidden_input::COUNT], reply_key: fresh_reply_key() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_submit_status_cancel_over_json_rpc() {
    let (addr, ek, token, http) = start().await;
    let info = rpc(&http, addr, "prover_info", json!([])).await;
    assert_eq!(info["result"]["witness_kinds"], json!(["spend_key"]));
    assert_eq!(info["result"]["queue"]["max"], 8);
    assert!(info["result"]["fee"].is_null());
    let j = job(token);
    let rk = j.reply_key;
    let sealed = hex::encode(seal_job(&ek, &j).unwrap());
    let r = rpc(&http, addr, "prover_submit", json!([sealed])).await;
    let id = r["result"]["job"].as_str().expect(&r.to_string()).to_string();
    let mut last = Value::Null;
    for _ in 0..100 {
        last = rpc(&http, addr, "prover_status", json!([id])).await;
        if last["result"]["state"] == "done" { break; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(last["result"]["state"], "done", "{last}");
    let reply = open_reply(&rk, &hex::decode(last["result"]["reply"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(reply.digest, [42; 8]);
    assert_eq!(rpc(&http, addr, "prover_cancel", json!([id])).await["result"]["cancelled"], false, "done is not cancellable");
    assert_eq!(rpc(&http, addr, "prover_status", json!(["ffff"])).await["error"]["code"], -32001);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusals_map_to_their_codes() {
    let (addr, ek, _token, http) = start().await;
    let sealed = hex::encode(seal_job(&ek, &job([0; 32])).unwrap());
    assert_eq!(rpc(&http, addr, "prover_submit", json!([sealed])).await["error"]["code"], -32003);
    assert_eq!(rpc(&http, addr, "prover_submit", json!(["zz"])).await["error"]["code"], -32602);
    assert_eq!(rpc(&http, addr, "prover_submit", json!([hex::encode([0u8; 200])])).await["error"]["code"], -32000);
    assert_eq!(rpc(&http, addr, "prover_nope", json!([])).await["error"]["code"], -32601);
    let r = http.post(format!("http://{addr}/")).json(&json!([{"jsonrpc":"2.0","id":1,"method":"prover_info","params":[]}])).send().await.unwrap().json::<Value>().await.unwrap();
    assert_eq!(r["error"]["code"], -32600, "no batches: {r}");
    let r = http.post(format!("http://{addr}/")).body("{not json").send().await.unwrap().json::<Value>().await.unwrap();
    assert_eq!(r["error"]["code"], -32700);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_body_is_refused_at_the_limit() {
    let (addr, _ek, _token, http) = start().await;
    let big = "a".repeat(MAX_BODY_BYTES + 1);
    let r = http.post(format!("http://{addr}/")).json(&json!({"jsonrpc":"2.0","id":1,"method":"prover_submit","params":[big]})).send().await.unwrap();
    assert_eq!(r.status(), 413);
}

#[test]
fn required_bytes_is_peak_times_parallel_plus_a_gib() {
    use randprotocol_prover::memory::*;
    assert_eq!(required_bytes(1), PROVER_PEAK_BYTES + HEADROOM_BYTES);
    assert_eq!(required_bytes(2), 2 * PROVER_PEAK_BYTES + HEADROOM_BYTES);
    // check() with an absurd parallelism must refuse on any machine, naming both numbers
    let e = check(1_000_000).unwrap_err();
    assert!(e.contains("GB"), "{e}");
}
