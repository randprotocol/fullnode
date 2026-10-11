//! A loopback JSON-RPC fake and a runner for the `rand-node` binary, shared by the CLI suites.
#![allow(dead_code)]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};

pub type Calls = Arc<Mutex<Vec<(String, Value)>>>;
pub type Answer = Box<dyn Fn(&str, &Value) -> Result<Value, (i64, String)> + Send + Sync>;

/// A node whose replies are `answer(method, params)`; every request is recorded.
pub fn fake_with(answer: Answer) -> (String, Calls) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let calls: Calls = Arc::new(Mutex::new(Vec::new()));
    let log = calls.clone();
    let answer = Arc::new(answer);
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { return };
            let (answer, log) = (answer.clone(), log.clone());
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let end = loop {
                    let n = sock.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
                let len: usize = head.split("content-length:").nth(1).and_then(|r| r.split("\r\n").next()).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                while buf.len() - end < len {
                    let n = sock.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let req: Value = serde_json::from_slice(&buf[end..]).unwrap_or(Value::Null);
                let method = req["method"].as_str().unwrap_or_default().to_string();
                log.lock().unwrap().push((method.clone(), req["params"].clone()));
                let body = match answer(&method, &req["params"]) {
                    Ok(v) => json!({ "jsonrpc": "2.0", "id": 1, "result": v }),
                    Err((code, message)) => json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": message } }),
                }
                .to_string();
                let _ = sock.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{body}", body.len()).as_bytes());
            });
        }
    });
    (url, calls)
}

/// The methods every chain-14 test node answers the same way, then `extra`'s.
pub fn chain14(extra: impl Fn(&str, &Value) -> Option<Value> + Send + Sync + 'static) -> (String, Calls) {
    fake_with(Box::new(move |m, p| {
        if let Some(v) = extra(m, p) {
            return Ok(v);
        }
        match m {
            "rand_chainId" => Ok(json!(14)),
            "rand_getGenesisHash" => Ok(json!("cd".repeat(32))),
            "rand_getHead" => Ok(json!({ "height": 40 })),
            "rand_sendTransaction" => Ok(json!("ef".repeat(32))),
            "rand_getTransactionStatus" => Ok(json!([{ "status": "committed" }])),
            "rand_getTransaction" => Ok(json!({ "height": 41, "index": 0, "block_hash": "aa".repeat(32) })),
            _ => Err((-32601, "method not found".into())),
        }
    }))
}

pub struct Out {
    pub ok: bool,
    pub out: String,
    pub err: String,
}

pub fn node(args: &[&str]) -> Out {
    let o = Command::new(env!("CARGO_BIN_EXE_rand-node")).args(args).output().expect("rand-node runs");
    Out { ok: o.status.success(), out: String::from_utf8_lossy(&o.stdout).into(), err: String::from_utf8_lossy(&o.stderr).into() }
}

pub struct Signer {
    pub key: std::path::PathBuf,
    pub public: String,
    pub address: String,
}

pub fn signer(dir: &std::path::Path, name: &str) -> Signer {
    let key = dir.join(format!("{name}.key.json"));
    let k = node(&["keygen", "--out", key.to_str().unwrap()]);
    assert!(k.ok, "{}", k.err);
    let a = node(&["address", "--key", key.to_str().unwrap()]);
    let public = a.out.lines().find_map(|l| l.strip_prefix("public_key: ")).unwrap().to_string();
    let address = a.out.lines().find_map(|l| l.strip_prefix("address: ")).unwrap().to_string();
    Signer { key, public, address }
}

pub fn sent(calls: &Calls) -> Vec<randprotocol_core::Transaction> {
    calls
        .lock()
        .unwrap()
        .iter()
        .filter(|(m, _)| m == "rand_sendTransaction")
        .map(|(_, p)| randprotocol_core::Transaction::decode(&hex::decode(p[0].as_str().unwrap()).unwrap()).unwrap())
        .collect()
}

pub fn recipient() -> String {
    randprotocol_core::notes::ShieldedAddress { pk: [5; 8], kem_ek: vec![9; 1184] }.to_string()
}
