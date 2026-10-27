//! Shared by the CLI suites: a loopback JSON-RPC fake and a runner for the `rand` binary.
#![allow(dead_code)]

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

pub type Answer = Box<dyn Fn(&str, &Value) -> Result<Value, (i64, String)> + Send + Sync>;

pub struct Fake {
    pub url: String,
    pub calls: Arc<Mutex<Vec<(String, Value)>>>,
}

/// A node whose replies are `answer(method, params)`; every request is recorded.
pub fn fake(answer: Answer) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let log = calls.clone();
    let answer = Arc::new(answer);
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { return };
            let (answer, log) = (answer.clone(), log.clone());
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let header_end = loop {
                    let n = sock.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                let len: usize = headers
                    .split("content-length:")
                    .nth(1)
                    .and_then(|r| r.split("\r\n").next())
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                while buf.len() - header_end < len {
                    let n = sock.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let req: Value = serde_json::from_slice(&buf[header_end..]).unwrap_or(Value::Null);
                let method = req["method"].as_str().unwrap_or_default().to_string();
                log.lock()
                    .unwrap()
                    .push((method.clone(), req["params"].clone()));
                let body = match answer(&method, &req["params"]) {
                    Ok(v) => json!({ "jsonrpc": "2.0", "id": 1, "result": v }),
                    Err((code, message)) => json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": code, "message": message } }),
                }
                .to_string();
                let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{body}", body.len());
                let _ = sock.write_all(resp.as_bytes());
            });
        }
    });
    Fake { url, calls }
}

impl Fake {
    pub fn methods(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(m, _)| m.clone())
            .collect()
    }
    pub fn params_of(&self, method: &str) -> Option<Value> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .find(|(m, _)| m == method)
            .map(|(_, p)| p.clone())
    }
}

pub struct Run {
    pub ok: bool,
    /// The exit code (`None` if a signal ended it).
    pub code: Option<i32>,
    pub out: String,
    pub err: String,
}

pub fn rand(rpc: &str, key: &std::path::Path, args: &[&str]) -> Run {
    rand_env(rpc, key, args, &[])
}

/// [`rand`] with extra environment variables.
pub fn rand_env(rpc: &str, key: &std::path::Path, args: &[&str], env: &[(&str, &str)]) -> Run {
    let o = Command::new(env!("CARGO_BIN_EXE_rand"))
        .envs(env.iter().copied())
        .arg("--key")
        .arg(key)
        .args(["--rpc", rpc])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run rand");
    Run {
        ok: o.status.success(),
        code: o.status.code(),
        out: String::from_utf8_lossy(&o.stdout).into(),
        err: String::from_utf8_lossy(&o.stderr).into(),
    }
}

pub const DEAD: &str = "http://127.0.0.1:9";

pub fn keygen(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let key = dir.path().join("w.key.json");
    let r = rand(DEAD, &key, &["keygen"]);
    assert!(r.ok, "{}", r.err);
    key
}

pub fn address_of(key: &std::path::Path) -> String {
    rand(DEAD, key, &["address"]).out.trim().to_string()
}

/// A minimal SOCKS5 proxy (no auth, CONNECT only) for the `--proxy` tests (issue #148): returns
/// its `socks5h://` URL and every `host:port` it was asked to connect to.
pub fn socks5_stub() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("socks5h://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { return };
            let log = log.clone();
            std::thread::spawn(move || -> Option<()> {
                let mut hello = [0u8; 2];
                sock.read_exact(&mut hello).ok()?;
                let mut methods = vec![0u8; hello[1] as usize];
                sock.read_exact(&mut methods).ok()?;
                sock.write_all(&[5, 0]).ok()?;
                let mut req = [0u8; 4];
                sock.read_exact(&mut req).ok()?;
                let host = match req[3] {
                    1 => {
                        let mut ip = [0u8; 4];
                        sock.read_exact(&mut ip).ok()?;
                        std::net::Ipv4Addr::from(ip).to_string()
                    }
                    3 => {
                        let mut len = [0u8; 1];
                        sock.read_exact(&mut len).ok()?;
                        let mut name = vec![0u8; len[0] as usize];
                        sock.read_exact(&mut name).ok()?;
                        String::from_utf8(name).ok()?
                    }
                    _ => return None,
                };
                let mut port = [0u8; 2];
                sock.read_exact(&mut port).ok()?;
                let target = format!("{host}:{}", u16::from_be_bytes(port));
                log.lock().unwrap().push(target.clone());
                let upstream = std::net::TcpStream::connect(&target).ok()?;
                sock.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).ok()?;
                let (mut a, mut b) = (sock.try_clone().ok()?, upstream.try_clone().ok()?);
                let (mut sock, mut upstream) = (sock, upstream);
                let t = std::thread::spawn(move || std::io::copy(&mut a, &mut b));
                let _ = std::io::copy(&mut upstream, &mut sock);
                let _ = sock.shutdown(std::net::Shutdown::Both);
                let _ = t.join();
                Some(())
            });
        }
    });
    (url, seen)
}
