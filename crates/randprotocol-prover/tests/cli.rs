//! `rand-prover` as an operator runs it: keygen, pair, pairings, unpair, and `run` as a real
//! listener on a loopback port that answers `prover_info` and stops on SIGTERM. No proof is made.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};

fn prover(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rand-prover")).arg("--home").arg(home).args(args).stdin(Stdio::null()).output().expect("rand-prover runs")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn keygen_writes_a_key_once_and_prints_its_fingerprint() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join("nested").join("prover");
    let out = prover(&dir, &["keygen"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let fp = text(&out.stdout);
    assert_eq!(fp.trim(), randprotocol_prover::key::ProverKey::load(&dir.join("prover.key.json")).unwrap().fingerprint().to_string());
    assert!(text(&out.stderr).contains("wrote "), "{}", text(&out.stderr));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700, "the home is private");
        assert_eq!(std::fs::metadata(dir.join("prover.key.json")).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let again = prover(&dir, &["keygen"]);
    assert!(!again.status.success());
    assert!(text(&again.stderr).contains("a prover key is never overwritten"), "{}", text(&again.stderr));
    assert_eq!(prover(&dir, &["keygen"]).stdout.len(), 0);
}

#[test]
fn pair_prints_a_link_once_pairings_lists_it_and_unpair_removes_it() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let no_key = prover(h, &["pair", "--name", "laptop"]);
    assert!(!no_key.status.success());
    assert!(text(&no_key.stderr).contains("run `rand-prover keygen` first"), "{}", text(&no_key.stderr));

    let fp = text(&prover(h, &["keygen"]).stdout).trim().to_string();
    let pair = prover(h, &["pair", "--name", "laptop", "--url", "http://127.0.0.1:8600", "--own"]);
    assert!(pair.status.success(), "{}", text(&pair.stderr));
    let link_text = text(&pair.stdout).trim().to_string();
    let err = text(&pair.stderr);
    assert!(err.contains("paired \"laptop\" (own)") && err.contains(&fp), "{err}");
    assert!(err.contains("shown only this once"), "{err}");
    let link = randprotocol_prover::pairing::PairingLink::parse(&link_text).expect("the printed link parses");
    assert!(link.own && link.url == "http://127.0.0.1:8600");
    assert!(!std::fs::read_to_string(h.join("pairings.json")).unwrap().contains(&hex::encode(link.token)), "the token is never stored");

    let dup = prover(h, &["pair", "--name", "laptop"]);
    assert!(!dup.status.success(), "a label is paired once: {}", text(&dup.stderr));

    let other = prover(h, &["pair", "--name", "phone", "--qr"]);
    assert!(other.status.success());
    assert!(text(&other.stdout).lines().count() > 10, "the QR follows the link");
    assert!(text(&other.stderr).contains("paired \"phone\";"), "{}", text(&other.stderr));

    let list = text(&prover(h, &["pairings"]).stdout);
    let rows: Vec<&str> = list.lines().collect();
    assert_eq!(rows.len(), 2, "{list}");
    assert!(rows[0].starts_with("laptop  own  20") && rows[1].starts_with("phone  -  20"), "{list}");

    let un = prover(h, &["unpair", "--name", "laptop"]);
    assert!(un.status.success() && text(&un.stderr).contains("unpaired \"laptop\""), "{}", text(&un.stderr));
    let gone = prover(h, &["unpair", "--name", "laptop"]);
    assert!(!gone.status.success() && text(&gone.stderr).contains("no pairing labelled \"laptop\""), "{}", text(&gone.stderr));
    assert_eq!(text(&prover(h, &["pairings"]).stdout).lines().count(), 1);
}

#[test]
fn pair_refuses_a_url_no_wallet_would_parse_and_mints_nothing() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    assert!(prover(h, &["keygen"]).status.success());
    let bad = prover(h, &["pair", "--name", "x", "--url", "http://exa mple"]);
    assert!(!bad.status.success());
    assert!(text(&bad.stderr).contains("--url:"), "{}", text(&bad.stderr));
    assert_eq!(text(&prover(h, &["pairings"]).stdout), "", "nothing was recorded");
}

#[test]
fn run_refuses_bad_flags_before_listening() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let zero = prover(h, &["run", "--max-parallel", "0"]);
    assert!(!zero.status.success() && text(&zero.stderr).contains("--max-parallel must be at least 1"), "{}", text(&zero.stderr));
    let fee = prover(h, &["run", "--fee", "1", "--fee-address", "not-an-address"]);
    assert!(!fee.status.success(), "{}", text(&fee.stderr));
    let origin = prover(h, &["run", "--allow-origin", "https://wallet.example/path"]);
    assert!(!origin.status.success() && text(&origin.stderr).contains("--allow-origin"), "{}", text(&origin.stderr));
    let both = prover(h, &["run", "--cuda", "--cpu"]);
    assert!(!both.status.success(), "--cuda conflicts with --cpu");
    let nokey = prover(h, &["run", "--skip-memory-check"]);
    assert!(!nokey.status.success() && text(&nokey.stderr).contains("run `rand-prover keygen` first"), "{}", text(&nokey.stderr));
    let cuda = prover(h, &["run", "--cuda", "--skip-memory-check"]);
    assert!(!cuda.status.success(), "a build without CUDA never quietly proves on the CPU: {}", text(&cuda.stderr));
}

fn post(addr: &str, body: &str) -> String {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
    write!(s, "POST / HTTP/1.1\r\nhost: {addr}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[cfg(unix)]
#[test]
fn run_serves_prover_info_with_its_flags_and_stops_cleanly_on_sigterm() {
    let home = tempfile::tempdir().unwrap();
    let h = home.path();
    let fp = text(&prover(h, &["keygen"]).stdout).trim().to_string();
    let rec = randprotocol_core::notes::ShieldedAddress { pk: [3; 8], kem_ek: vec![9; 1184] }.to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rand-prover"))
        .arg("--home")
        .arg(h)
        .args(["run", "--listen", "127.0.0.1:0", "--skip-memory-check", "--max-queue", "3", "--fee", "0.5", "--fee-address", &rec, "--allow-origin", "*", "--threads", "1", "--cpu"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap());
    let mut seen = String::new();
    let mut addr = None;
    for _ in 0..200 {
        let mut line = String::new();
        if lines.read_line(&mut line).unwrap() == 0 {
            break;
        }
        seen.push_str(&line);
        if let Some(rest) = line.split("listening on http://").nth(1) {
            addr = Some(rest.trim().to_string());
            break;
        }
    }
    let addr = addr.unwrap_or_else(|| {
        let _ = child.kill();
        panic!("never listened: {seen}")
    });
    assert!(seen.contains("every website can read this prover's replies"), "the * warning is printed: {seen}");
    assert!(seen.contains("no pairings: every job will be refused"), "{seen}");
    assert!(seen.contains("charging 0.5 RAND per job"), "{seen}");
    assert!(seen.contains(&format!("rand-prover {fp} listening")), "{seen}");

    let reply = post(&addr, r#"{"jsonrpc":"2.0","id":1,"method":"prover_info","params":[]}"#);
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    let body: serde_json::Value = serde_json::from_str(reply.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["result"]["queue"]["max"], 3, "{body}");
    let unknown = post(&addr, r#"{"jsonrpc":"2.0","id":2,"method":"prover_nope","params":[]}"#);
    assert!(unknown.contains("\"error\""), "{unknown}");

    let status = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(status.success());
    let exit = child.wait().unwrap();
    assert!(exit.success(), "a SIGTERM is a clean stop: {exit:?}");
    let mut rest = String::new();
    for l in lines.lines().map_while(Result::ok) {
        rest.push_str(&l);
        rest.push('\n');
    }
    assert!(rest.contains("shutting down: queued jobs dropped"), "{rest}");
}
