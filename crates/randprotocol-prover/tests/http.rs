use randprotocol_prover::http::{serve, MAX_BODY_BYTES};
use randprotocol_prover::key::ProverKey;
use randprotocol_prover::pairing::Pairings;
use randprotocol_prover::origins::AllowedOrigins;
use randprotocol_prover::service::{Config, ProveFn};
use randprotocol_prover::wire::*;
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::hidden::hidden_input_v3;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

fn ok_prover() -> ProveFn { Arc::new(|_, _, inputs, _, _| Ok((vec![0xAA; 64], [inputs[0]; 8], 14))) }

async fn start() -> (SocketAddr, Vec<u8>, [u8; 32], reqwest::Client) {
    start_with(AllowedOrigins::default()).await
}

async fn start_with(origins: AllowedOrigins) -> (SocketAddr, Vec<u8>, [u8; 32], reqwest::Client) {
    let key = ProverKey::from_seed([4; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let token = pairings.pair("laptop", true).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.prove = ok_prover();
    cfg.allowed_origins = origins;
    let (addr, _svc, _task) = serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();
    (addr, ek, token, reqwest::Client::new())
}

async fn rpc(http: &reqwest::Client, addr: SocketAddr, method: &str, params: Value) -> Value {
    http.post(format!("http://{addr}/")).json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).send().await.unwrap().json().await.unwrap()
}

fn job(token: [u8; 32]) -> ProveJob {
    ProveJob { version: WIRE_VERSION, token, witness_kind: WitnessKind::ViewingKey, hc_bundle: ZkExecutor::hc_hidden_bundle_v3(), profile: "test".into(), binding: [1; 8], inputs: vec![42; hidden_input_v3::COUNT], reply_key: fresh_reply_key() }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_submit_status_cancel_over_json_rpc() {
    let (addr, ek, token, http) = start().await;
    let info = rpc(&http, addr, "prover_info", json!([])).await;
    assert_eq!(info["result"]["witness_kinds"], json!(["viewing_key"]), "the spend-key kind is retired (VK-4)");
    assert_eq!(info["result"]["hc_bundles"], json!([randprotocol_core::notes::word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3())]));
    assert_eq!(info["result"]["queue"]["max"], 8);
    assert!(info["result"]["fee"].is_null());
    let j = job(token);
    let rk = j.reply_key;
    let sealed = hex::encode(seal_job(&ek, &j).unwrap());
    let r = rpc(&http, addr, "prover_submit", json!([sealed])).await;
    let id = r["result"]["job"].as_str().unwrap_or_else(|| panic!("{}", r.to_string())).to_string();
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
    let (addr, ek, token, http) = start().await;
    let sealed = hex::encode(seal_job(&ek, &job([0; 32])).unwrap());
    assert_eq!(rpc(&http, addr, "prover_submit", json!([sealed])).await["error"]["code"], -32003);
    // VK-4: a spend-key job — what a wallet older than the retirement sends on a v1/v2 chain —
    // still decodes, and is answered with the "witness kind not accepted" code and the reason,
    // which that wallet prints; never a decode error.
    for hc in ZkExecutor::known_hc_bundles() {
        let mut old = job(token);
        (old.witness_kind, old.hc_bundle, old.inputs) = (WitnessKind::SpendKey, hc, vec![42; ZkExecutor::bundle_input_words(&hc)]);
        let r = rpc(&http, addr, "prover_submit", json!([hex::encode(seal_job(&ek, &old).unwrap())])).await;
        assert_eq!(r["error"]["code"], -32004, "{r}");
        assert_eq!(r["error"]["data"]["reason"], randprotocol_prover::service::SPEND_KEY_RETIRED, "{r}");
    }
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

async fn preflight(http: &reqwest::Client, addr: SocketAddr, origin: &str) -> reqwest::Response {
    http.request(reqwest::Method::OPTIONS, format!("http://{addr}/"))
        .header("origin", origin)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .send()
        .await
        .unwrap()
}

async fn post_from(http: &reqwest::Client, addr: SocketAddr, origin: Option<&str>, body: Value) -> reqwest::Response {
    let mut r = http.post(format!("http://{addr}/")).json(&body);
    if let Some(o) = origin {
        r = r.header("origin", o);
    }
    r.send().await.unwrap()
}

fn info_req() -> Value { json!({"jsonrpc":"2.0","id":1,"method":"prover_info","params":[]}) }

/// An allowed origin: the preflight is a 204 echoing it, and every POST reply (a success, a
/// JSON-RPC error, the 413) carries the same header.
async fn assert_allowed(http: &reqwest::Client, addr: SocketAddr, origin: &str, echoed: &str) {
    let r = preflight(http, addr, origin).await;
    assert_eq!(r.status(), 204, "{origin}");
    let h = r.headers();
    assert_eq!(h["access-control-allow-origin"], echoed, "{origin}");
    assert_eq!(h["access-control-allow-methods"], "POST, OPTIONS");
    assert_eq!(h["access-control-allow-headers"], "content-type");
    assert_eq!(h["access-control-max-age"], "86400");
    assert_eq!(h["vary"], "Origin");
    let ok = post_from(http, addr, Some(origin), info_req()).await;
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.headers()["access-control-allow-origin"], echoed, "a success");
    assert_eq!(ok.headers()["vary"], "Origin");
    assert!(ok.json::<Value>().await.unwrap()["result"]["kem_ek"].is_string());
    let err = post_from(http, addr, Some(origin), json!({"jsonrpc":"2.0","id":1,"method":"prover_nope","params":[]})).await;
    assert_eq!(err.headers()["access-control-allow-origin"], echoed, "a JSON-RPC error");
    assert_eq!(err.json::<Value>().await.unwrap()["error"]["code"], -32601);
    let big = post_from(http, addr, Some(origin), json!({"jsonrpc":"2.0","id":1,"method":"prover_submit","params":["a".repeat(MAX_BODY_BYTES + 1)]})).await;
    assert_eq!(big.status(), 413);
    assert_eq!(big.headers()["access-control-allow-origin"], echoed, "the 413");
}

/// A refused origin: the preflight is a 403 with no CORS headers, and every method is -32007
/// with no `Access-Control-Allow-Origin` — the page can read neither.
async fn assert_refused(http: &reqwest::Client, addr: SocketAddr, origin: &str) {
    let r = preflight(http, addr, origin).await;
    assert_eq!(r.status(), 403, "{origin}");
    for h in ["access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "access-control-max-age"] {
        assert!(r.headers().get(h).is_none(), "{origin}: {h} on a refused preflight");
    }
    for method in ["prover_info", "prover_status", "prover_nope"] {
        let res = post_from(http, addr, Some(origin), json!({"jsonrpc":"2.0","id":1,"method":method,"params":["ab"]})).await;
        assert!(res.headers().get("access-control-allow-origin").is_none(), "{origin}: {method}");
        let v = res.json::<Value>().await.unwrap();
        assert_eq!(v["error"]["code"], -32007, "{origin}: {method}: {v}");
        assert_eq!(v["error"]["message"], "origin not allowed");
        assert!(v.get("result").is_none(), "{v}");
    }
    // An oversized body too: refused before its size is, and still no CORS headers.
    let big = post_from(http, addr, Some(origin), json!({"jsonrpc":"2.0","id":1,"method":"prover_submit","params":["a".repeat(MAX_BODY_BYTES + 1)]})).await;
    assert!(big.headers().get("access-control-allow-origin").is_none(), "{origin}: the oversized body");
    assert_eq!(big.json::<Value>().await.unwrap()["error"]["code"], -32007, "{origin}: the oversized body");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_page_origin_is_refused_by_default() {
    let (addr, _ek, _token, http) = start().await;
    assert_refused(&http, addr, "https://evil.example").await;
    assert_refused(&http, addr, "http://localhost.evil.example").await;
    assert_refused(&http, addr, "null").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_extension_origin_is_allowed_by_default() {
    let (addr, _ek, _token, http) = start().await;
    let o = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
    assert_allowed(&http, addr, o, o).await;
    let o = "moz-extension://2b0c6f2a-8d6e-4f5b-9c1d-3e4f5a6b7c8d";
    assert_allowed(&http, addr, o, o).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn localhost_any_port_is_allowed() {
    let (addr, _ek, _token, http) = start().await;
    for o in ["http://localhost:5173", "http://127.0.0.1:3000", "http://[::1]:8080"] {
        assert_allowed(&http, addr, o, o).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_origin_header_gets_no_cors_headers_and_is_served() {
    let (addr, _ek, _token, http) = start().await;
    let r = post_from(&http, addr, None, info_req()).await;
    assert_eq!(r.status(), 200);
    for h in ["access-control-allow-origin", "vary"] {
        assert!(r.headers().get(h).is_none(), "{h} without an Origin");
    }
    let v = r.json::<Value>().await.unwrap();
    assert!(v["result"]["kem_ek"].is_string(), "{v}");
    let big = post_from(&http, addr, None, json!({"jsonrpc":"2.0","id":1,"method":"prover_submit","params":["a".repeat(MAX_BODY_BYTES + 1)]})).await;
    assert_eq!(big.status(), 413);
    assert!(big.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_list_replaces_the_default() {
    let (addr, _ek, _token, http) = start_with(AllowedOrigins::List(vec!["https://wallet.example".into()])).await;
    assert_allowed(&http, addr, "https://wallet.example", "https://wallet.example").await;
    assert_refused(&http, addr, "chrome-extension://abcdefghijklmnopabcdefghijklmnop").await;
    assert_refused(&http, addr, "http://localhost:5173").await;
    assert_refused(&http, addr, "https://wallet.example:8443").await;
    let info = rpc(&http, addr, "prover_info", json!([])).await;
    assert_eq!(info["result"]["allowed_origins"], json!(["https://wallet.example"]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn star_allows_everything() {
    let (addr, _ek, _token, http) = start_with(AllowedOrigins::Any).await;
    assert_allowed(&http, addr, "https://wallet.example", "*").await;
    assert_allowed(&http, addr, "https://evil.example", "*").await;
    let info = rpc(&http, addr, "prover_info", json!([])).await;
    assert_eq!(info["result"]["allowed_origins"], json!(["*"]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prover_info_names_the_default_list() {
    let (addr, _ek, _token, http) = start().await;
    let info = rpc(&http, addr, "prover_info", json!([])).await;
    assert_eq!(
        info["result"]["allowed_origins"],
        json!(["chrome-extension://*", "moz-extension://*", "safari-web-extension://*", "http://localhost:*", "http://127.0.0.1:*", "http://[::1]:*"])
    );
}
