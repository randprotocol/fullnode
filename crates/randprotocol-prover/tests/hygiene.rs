//! Spec §3.5: nothing the service logs or returns contains the witness. Two runs through one
//! listener: a job refused at admission after it was opened (the error path), and one real tier-14
//! hidden-bundle proof at the test profile (the whole path). Every HTTP response body and every
//! log line of both is scanned for the spend key, as text and as hex; the reply is opened with the
//! job's reply key and verified locally against the transaction binding.

mod proving_slot;

use proving_slot::proving_slot;
use randprotocol_prover::{http, key::ProverKey, pairing::Pairings, service::Config, wire};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::hidden::{self, hidden_input as hi, HiddenDigestInput, HiddenOutput};
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
fn honest_witness(sk: &SpendKey) -> (Vec<u32>, Word8, [u32; 8]) {
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
    let inputs = hidden::hidden_bundle_inputs(sk, &ins, &hidden_outs, anchor, fee, 0, 0, 0, TIME);
    let vk = sk.viewing_key();
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
    (inputs, hidden::hidden_bundle_digest(&di), BINDING)
}

/// Every rendering of the spend key a log or reply could contain.
fn needles(sk: &[u32; 8], inputs: &[u32]) -> Vec<String> {
    let mut v = Vec::new();
    v.push(hex::encode(randprotocol_core::notes::word8_to_bytes(sk)));
    for w in sk {
        v.push(format!("{w}"));
        v.push(format!("{w:08x}"));
    }
    // Witness words as `Debug` would print a slice: the spend key, then the real input's `from`
    // (the spent note's creator, which only the witness carries; slot 0's is a dummy's zeros).
    let debug = |ws: &[u32]| ws.iter().map(|w| format!("{w}")).collect::<Vec<_>>().join(", ");
    let from = hi::in_slot(2) + hi::S_FROM;
    v.push(debug(&inputs[hi::SK..hi::SK + 8]));
    v.push(debug(&inputs[from..from + 8]));
    v
}

fn assert_clean(haystack: &[u8], needles: &[String], what: &str) {
    let text = String::from_utf8_lossy(haystack);
    let lower_hex = hex::encode(haystack);
    for n in needles {
        assert!(!text.contains(n.as_str()), "the witness leaked into the {what} as {n:?}");
        assert!(!lower_hex.contains(&hex::encode(n.as_bytes())), "the witness leaked (binary) into the {what} as {n:?}");
    }
}

async fn rpc(http: &reqwest::Client, addr: std::net::SocketAddr, id: u64, method: &str, params: serde_json::Value, responses: &mut Vec<u8>) -> serde_json::Value {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let r = http.post(format!("http://{addr}/")).json(&body).send().await.unwrap().bytes().await.unwrap();
    responses.extend_from_slice(&r);
    serde_json::from_slice(&r).unwrap()
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
    let (inputs, expected, binding) = honest_witness(&sk);
    assert_eq!(inputs.len(), hi::COUNT);
    assert_eq!(&inputs[hi::SK..hi::SK + 8], &sk.0[..], "the witness carries the spend key where the needles look");
    // The witness is honest before a minute and a half goes into proving it.
    let emulated = randprotocol_zkvm::emulator::execute(ZkExecutor::hidden_bundle_program(), &inputs, &binding, 1 << 20).unwrap().outputs;
    assert_eq!(emulated, expected, "the witness is honest");

    let key = ProverKey::from_seed([6; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let token = pairings.pair("laptop", true).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.accept_spend_key = true;
    let (addr, _svc, _task) = http::serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();
    let client = reqwest::Client::new();
    let mut responses: Vec<u8> = Vec::new();

    // 1. The error path: an unknown guest, refused after the job was opened and its pairing checked.
    let mut job = wire::ProveJob {
        version: wire::WIRE_VERSION,
        token,
        witness_kind: wire::WitnessKind::SpendKey,
        hc_bundle: [1; 8],
        profile: "test".into(),
        binding,
        inputs: inputs.clone(),
        reply_key: wire::fresh_reply_key(),
    };
    let v = rpc(&client, addr, 1, "prover_submit", serde_json::json!([hex::encode(wire::seal_job(&ek, &job).unwrap())]), &mut responses).await;
    assert_eq!(v["error"]["code"], http::BAD_JOB, "the unknown guest is refused: {v}");

    // 2. The whole path: a real proof. The slot is held around the proof only.
    job.hc_bundle = ZkExecutor::hc_bundle();
    let reply_key = job.reply_key;
    let slot = proving_slot().await;
    let started = Instant::now();
    let v = rpc(&client, addr, 2, "prover_submit", serde_json::json!([hex::encode(wire::seal_job(&ek, &job).unwrap())]), &mut responses).await;
    drop(job);
    let id = v["result"]["job"].as_str().unwrap_or_else(|| panic!("admitted: {v}")).to_string();
    let mut reply_hex = None;
    for _ in 0..6000 {
        let v = rpc(&client, addr, 3, "prover_status", serde_json::json!([id]), &mut responses).await;
        match v["result"]["state"].as_str() {
            Some("done") => {
                reply_hex = Some(v["result"]["reply"].as_str().unwrap().to_string());
                break;
            }
            Some("queued") | Some("proving") => tokio::time::sleep(Duration::from_millis(200)).await,
            _ => panic!("the proof failed: {v}"),
        }
    }
    let secs = started.elapsed().as_secs_f64();
    drop(slot);
    let reply = wire::open_reply(&reply_key, &hex::decode(reply_hex.expect("proved within 20 minutes")).unwrap()).unwrap();
    println!("proof through the service: {secs:.1} s, {} bytes, tier {}", reply.proof.len(), reply.tier);
    assert_eq!(reply.digest, expected, "the honest digest");
    assert_eq!(reply.tier, 14);
    let exec = ZkExecutor::new(randprotocol_zkvm::machine::FriProfile::Test);
    randprotocol_core::confidential::ConfidentialExecutor::verify_bundle(&exec, &ZkExecutor::hc_bundle(), &reply.proof, &binding)
        .expect("the reply verifies against the binding");

    // 3. Scan everything.
    let n = needles(&sk.0, &inputs);
    assert_clean(&responses, &n, "HTTP responses");
    let logged = logs.0.lock().unwrap().clone();
    assert!(!logged.is_empty(), "the capture saw the service's logs at all");
    let text = String::from_utf8_lossy(&logged);
    assert!(text.contains("queued") && text.contains("done"), "the capture saw the job's own log lines");
    assert_clean(&logged, &n, "logs");
}
