//! Spec §3.5: nothing the service logs or returns contains the witness. Three runs: a job refused
//! at admission after it was opened (the refusal path), a job that fails in the prover (the
//! failure path: its `prover_status.error` and its `failed` log line), and one real tier-14
//! hidden-bundle proof at the test profile (the whole path). Every HTTP response body and every
//! log line is scanned for the witness's key as text, and for its raw bytes; the reply is opened
//! with the job's reply key and verified locally against the transaction binding.
//!
//! The witness is bundle guest v3's — the only one a prover admits since the spend-key witness was
//! retired (VK-4, audit v6) — so the key it carries, and the key looked for, is the viewing key's
//! `nk` (with the per-transaction salt). The spend key is in no witness at all; it is looked for
//! anyway.
//!
//! This file installs a GLOBAL tracing subscriber, so it must stay this binary's only tracing test.
mod proving_slot;

use proving_slot::proving_slot;
use randprotocol_prover::{http, key::ProverKey, pairing::Pairings, service::Config, wire};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::hidden::{self, hidden_input_v3 as hi, HiddenDigestInput, HiddenDigestInputV3, HiddenOutput};
use randprotocol_zkvm::ledger::CommitmentTree;
use randprotocol_zkvm::notes::{Note, SpendKey, Word8, DEPTH};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A tracing writer that keeps everything.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture { self.clone() }
}

const BINDING: [u32; 8] = [11; 8];
const TIME: u32 = 5;

/// A 1-in/1-out RAND self-transfer, built as `crates/randprotocol-zkvm/tests/hidden_bundle.rs`'s
/// `Case::new` builds its honest shapes (five unrelated leaves ahead of the spent note, so the path
/// is non-trivial; dummy slots are fresh zero-value notes with a zero path). The shape is that
/// file's `rand_only`: the one real input and the one output in slot 2, a RAND slot, which is
/// where the fee must come from (slots 0–1 balance asset `A` on their own). The real note's `from`
/// words are distinctive, so that slot of the witness is a needle worth looking for.
/// Returns the witness, the digest an honest proof publishes, and the binding.
fn honest_witness(sk: &SpendKey, salt: &Word8) -> (Vec<u32>, Word8, [u32; 8]) {
    let me = sk.viewing_key().pk();
    let mut tree = CommitmentTree::new();
    for _ in 0..5 {
        tree.append(Note::new([9; 8], [0; 8], 1, 0, 1).commitment());
    }
    let from = [0x5d17_c2a8, 0x39e6_04bf, 0x71a0_d35c, 0x2c84_9e17, 0x46fb_1a62, 0x0e39_c7d5, 0x6b52_80f9, 0x1ac7_e43b];
    let real = Note { pk: me, from, amount: 1_000, asset: 0, time: 2, r: [0x3301_77aa, 3, 4, 5, 6, 7, 8, 9] };
    tree.append(real.commitment());
    let anchor = tree.root();
    let (path, index) = tree.path_for(&real.commitment()).unwrap();
    let dummy = || (Note::new(me, [0; 8], 0, 0, TIME), [[0; 8]; DEPTH], 0u32);
    let ins: [(Note, [Word8; DEPTH], u32); 4] = [dummy(), dummy(), (real, path, index), dummy()];
    let fee = 10;
    let outs: [Note; 4] = std::array::from_fn(|k| Note::new(me, me, if k == 2 { 990 } else { 0 }, 0, TIME));
    let hidden_outs = outs.map(|o| HiddenOutput { pk: o.pk, amount: o.amount, r: o.r });
    let vk = sk.viewing_key();
    let inputs = hidden::hidden_bundle_inputs_v3(&vk, salt, &ins, &hidden_outs, anchor, fee, 0, 0, 0, TIME);
    let di = HiddenDigestInput {
        anchor,
        nullifiers: std::array::from_fn(|k| vk.nullifier(&ins[k].0.commitment())),
        commitments: std::array::from_fn(|k| outs[k].commitment()),
        fee,
        burn_a: 0,
        burn_r: 0,
        burn_asset: 0,
        time: TIME,
    };
    let auth_commit = randprotocol_zkvm::auth::auth_commit(&vk.nk, salt);
    (inputs, hidden::hidden_bundle_digest_v3(&HiddenDigestInputV3 { base: di, auth_commit }), BINDING)
}

/// Every text rendering of the witness a log or reply could contain, longest last. A needle under
/// [`LONG`] characters is checked against structured text only (JSON with the sealed reply taken
/// out, log lines); only the long ones are checked against the sealed reply's ~680 K random hex
/// characters, where an 8-character needle would turn up by chance about once in 700 runs.
fn needles(key: &[u32; 8], inputs: &[u32]) -> Vec<String> {
    let bytes = randprotocol_core::notes::word8_to_bytes(key);
    let mut v = Vec::new();
    for w in key {
        v.push(format!("{w}"));
        v.push(format!("{w:08x}"));
        v.push(format!("{w:08X}"));
    }
    // A byte list as `Debug` prints one: the first word's four LE bytes, then all 32.
    v.push(format!("{:?}", &bytes[..4]).trim_end_matches(']').to_string());
    v.push(format!("{:?}", &bytes[..]));
    v.push(hex::encode(bytes));
    v.push(hex::encode_upper(bytes));
    // Witness words as `Debug` would print a slice: the key, then the real input's `from` (the
    // spent note's creator, which only the witness carries; slot 0's is a dummy's zeros).
    let debug = |ws: &[u32]| ws.iter().map(|w| format!("{w}")).collect::<Vec<_>>().join(", ");
    let from = hi::in_slot(2) + hi::S_FROM;
    v.push(debug(key));
    v.push(debug(&inputs[from..from + 8]));
    v
}

/// Needles at least this long are safe to look for in random hex.
const LONG: usize = 16;

/// A key as raw bytes: all 32 LE bytes, and each word's 4.
fn raw_needles(key: &[u32; 8]) -> Vec<Vec<u8>> {
    let mut v = vec![randprotocol_core::notes::word8_to_bytes(key).to_vec()];
    v.extend(key.iter().map(|w| w.to_le_bytes().to_vec()));
    v
}

fn assert_clean(haystack: &[u8], needles: &[String], raw: &[Vec<u8>], what: &str) {
    let text = String::from_utf8_lossy(haystack);
    for n in needles {
        assert!(!text.contains(n.as_str()), "the witness leaked into the {what} as {n:?}");
    }
    for n in raw {
        assert!(!haystack.windows(n.len()).any(|w| w == &n[..]), "the witness leaked (raw bytes) into the {what} as {n:02x?}");
    }
}

async fn rpc(http: &reqwest::Client, addr: std::net::SocketAddr, id: u64, method: &str, params: serde_json::Value) -> (Vec<u8>, serde_json::Value) {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let r = http.post(format!("http://{addr}/")).json(&body).send().await.unwrap().bytes().await.unwrap();
    let v = serde_json::from_slice(&r).unwrap();
    (r.to_vec(), v)
}

/// Polls `id` until it leaves `queued`/`proving`; every body goes into `responses` except a `done`
/// body's sealed reply, which is cut out, replaced by `"<reply>"`, and returned on its own.
async fn poll(http: &reqwest::Client, addr: std::net::SocketAddr, id: &str, responses: &mut Vec<u8>) -> (serde_json::Value, Option<String>) {
    for _ in 0..6000 {
        let (raw, mut v) = rpc(http, addr, 3, "prover_status", serde_json::json!([id])).await;
        match v["result"]["state"].as_str() {
            Some("queued") | Some("proving") => {
                responses.extend_from_slice(&raw);
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Some("done") => {
                let reply = v["result"]["reply"].as_str().expect("a done status carries its reply").to_string();
                v["result"]["reply"] = serde_json::json!("<reply>");
                // The body with the reply cut out, re-rendered: its other fields are scanned as sent.
                let rest = String::from_utf8(raw).unwrap().replacen(&reply, "<reply>", 1);
                assert_eq!(serde_json::from_str::<serde_json::Value>(&rest).unwrap(), v, "only the reply was cut out");
                responses.extend_from_slice(rest.as_bytes());
                return (v, Some(reply));
            }
            _ => {
                responses.extend_from_slice(&raw);
                return (v, None);
            }
        }
    }
    panic!("job {id} still running after 20 minutes");
}

fn service(prove: Option<randprotocol_prover::service::ProveFn>) -> (Config, [u8; 32], Vec<u8>) {
    let key = ProverKey::from_seed([6; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let token = pairings.pair("laptop", true).unwrap();
    let mut cfg = Config::new(key, pairings);
    if let Some(p) = prove {
        cfg.prove = p;
    }
    (cfg, token, ek)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_logged_or_returned_carries_the_witness() {
    // Global, not `set_default`: the listener, the workers and the proving task each run on
    // their own threads, and a thread-local subscriber would see none of them.
    let logs = Capture::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::fmt().with_writer(logs.clone()).with_ansi(false).with_max_level(tracing::Level::TRACE).finish(),
    )
    .expect("the only subscriber in this binary");

    // Spend-key words large and distinct, so their decimal and hex forms are not coincidences.
    let sk = SpendKey([0x7a3c_91e5, 0x1f4b_88d2, 0x6e0d_27a9, 0x53c8_1b76, 0x2b9e_4f13, 0x48d1_6c05, 0x0f72_a3be, 0x67ac_5d94]);
    // The salt a wallet draws fresh per bundle, distinct too: it is witness, and looked for.
    let salt: Word8 = [0x4be1_07c9, 0x1d93_6a2f, 0x62f8_b514, 0x0a5c_e37d, 0x37c4_19a6, 0x58e2_d0b1, 0x2469_fc83, 0x71b0_3e5a];
    let nk = sk.viewing_key().nk;
    let (inputs, expected, binding) = honest_witness(&sk, &salt);
    assert_eq!(inputs.len(), hi::COUNT);
    assert_eq!(&inputs[hi::NK..hi::NK + 8], &nk[..], "the witness carries the viewing key's nk where the needles look");
    assert_eq!(&inputs[hi::SALT..hi::SALT + 8], &salt[..], "and the salt");
    assert!(!inputs.windows(8).any(|w| w == sk.0), "no word run of a v3 witness is the spend key");
    // The witness is honest before a minute and a half goes into proving it.
    let emulated = randprotocol_zkvm::emulator::execute(ZkExecutor::hidden_bundle_v3_program(), &inputs, &binding, 1 << 20).unwrap().outputs;
    assert_eq!(emulated, expected, "the witness is honest");

    let client = reqwest::Client::new();
    let mut responses: Vec<u8> = Vec::new();
    let job_for = |token: [u8; 32], hc_bundle: Word8| wire::ProveJob {
        version: wire::WIRE_VERSION,
        token,
        witness_kind: wire::WitnessKind::ViewingKey,
        hc_bundle,
        profile: "test".into(),
        binding,
        inputs: inputs.clone(),
        reply_key: wire::fresh_reply_key(),
    };

    // 1. The failure path. No witness of the right width makes the hidden guest's emulator fail (it taints
    // `bad` instead: every single-word mutation of this witness to 0, 2^30, 2^31 and 2^32 − 1 was
    // tried, none errs), so the prover here is the real emulator under a 1 000-cycle budget,
    // formatted as `prove_bundle_for` formats a real `ProveError` — a real `ExecError` through the
    // service's `prover_status.error` and its `failed` log line.
    let short: randprotocol_prover::service::ProveFn = Arc::new(|_hc, _profile, inputs, binding, _backend| {
        randprotocol_zkvm::emulator::execute(ZkExecutor::hidden_bundle_v3_program(), inputs, binding, 1_000)
            .map(|_| unreachable!("the guest runs far longer than 1 000 cycles"))
            .map_err(|e| format!("{:?}", randprotocol_zkvm::machine::ProveError::Exec(e)))
    });
    let (cfg, token, ek) = service(Some(short));
    let (failing, _svc, _task) = http::serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();
    let (raw, v) = rpc(&client, failing, 1, "prover_submit", serde_json::json!([hex::encode(wire::seal_job(&ek, &job_for(token, ZkExecutor::hc_hidden_bundle_v3())).unwrap())])).await;
    responses.extend_from_slice(&raw);
    let id = v["result"]["job"].as_str().unwrap_or_else(|| panic!("admitted: {v}")).to_string();
    let (v, _) = poll(&client, failing, &id, &mut responses).await;
    assert_eq!(v["result"]["state"], "failed", "{v}");
    assert!(v["result"]["error"].as_str().unwrap().contains("OutOfCycles"), "the emulator's own error reached the status: {v}");

    // The real service from here on.
    let (cfg, token, ek) = service(None);
    let (addr, _svc, _task) = http::serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();

    // 2. The refusal path: an unknown guest, refused after the job was opened and its pairing checked.
    let (raw, v) = rpc(&client, addr, 1, "prover_submit", serde_json::json!([hex::encode(wire::seal_job(&ek, &job_for(token, [1; 8])).unwrap())])).await;
    responses.extend_from_slice(&raw);
    assert_eq!(v["error"]["code"], http::BAD_JOB, "the unknown guest is refused: {v}");
    // And the retired kind (VK-4): a job opened, found to be a spend-key one, refused — its
    // witness (the same words, standing in for the spend key an old wallet would have sent)
    // appears in neither the refusal nor the log.
    let mut old = job_for(token, ZkExecutor::hc_hidden_bundle_v3());
    old.witness_kind = wire::WitnessKind::SpendKey;
    let (raw, v) = rpc(&client, addr, 1, "prover_submit", serde_json::json!([hex::encode(wire::seal_job(&ek, &old).unwrap())])).await;
    drop(old);
    responses.extend_from_slice(&raw);
    assert_eq!(v["error"]["code"], http::WITNESS_KIND, "a spend-key job is refused: {v}");

    // 3. The whole path: a real proof. The slot is held around the proof only.
    let job = job_for(token, ZkExecutor::hc_hidden_bundle_v3());
    let reply_key = job.reply_key;
    let slot = proving_slot().await;
    let started = Instant::now();
    let (raw, v) = rpc(&client, addr, 2, "prover_submit", serde_json::json!([hex::encode(wire::seal_job(&ek, &job).unwrap())])).await;
    responses.extend_from_slice(&raw);
    drop(job);
    let id = v["result"]["job"].as_str().unwrap_or_else(|| panic!("admitted: {v}")).to_string();
    let (v, reply_hex) = poll(&client, addr, &id, &mut responses).await;
    let secs = started.elapsed().as_secs_f64();
    drop(slot);
    let reply_hex = reply_hex.unwrap_or_else(|| panic!("the proof failed: {v}"));
    let reply = wire::open_reply(&reply_key, &hex::decode(&reply_hex).unwrap()).unwrap();
    println!("proof through the service: {secs:.1} s, {} bytes, tier {}", reply.proof.len(), reply.tier);
    assert_eq!(reply.digest, expected, "the honest digest");
    assert_eq!(reply.tier, 14);
    let exec = ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
    randprotocol_core::confidential::ConfidentialExecutor::verify_bundle(&exec, &ZkExecutor::hc_hidden_bundle_v3(), &reply.proof, &binding)
        .expect("the reply verifies against the binding");

    // 4. Scan everything.
    // `nk` (what the witness carries), the salt, and — though no witness holds it — the spend key.
    let mut n = needles(&nk, &inputs);
    let mut raw = raw_needles(&nk);
    for other in [&salt, &sk.0] {
        n.extend(needles(other, &inputs));
        raw.extend(raw_needles(other));
    }
    assert_clean(&responses, &n, &raw, "HTTP responses");
    let long: Vec<String> = n.iter().filter(|x| x.len() >= LONG).cloned().collect();
    assert!(long.len() >= 15, "per key: the 64-hex key both ways, the 32-byte Debug list and the two Debug joins");
    assert_clean(reply_hex.as_bytes(), &long, &raw, "sealed reply");
    let logged = logs.0.lock().unwrap().clone();
    let text = String::from_utf8_lossy(&logged);
    assert!(text.contains("queued") && text.contains("done"), "the capture saw the real job's log lines");
    assert!(text.contains("failed") && text.contains("OutOfCycles"), "the capture saw the failed job's log line");
    assert_clean(&logged, &n, &raw, "logs");
}
