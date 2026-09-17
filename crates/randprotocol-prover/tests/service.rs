//! An in-process `rand-prover` on the CPU backend and the test profile
//! (`docs/superpowers/specs/2026-09-17-delegated-proving-design.md` §5, §12).

use randprotocol_prover::{serve, Config};
use randprotocol_zkvm::delegate::*;
use randprotocol_zkvm::machine::{FriProfile, Machine};
use randprotocol_zkvm::notes::SpendKey;
use std::net::SocketAddr;
use std::time::Duration;

async fn start(cfg: Config) -> (SocketAddr, reqwest::Client) {
    let (addr, _task) = serve("127.0.0.1:0".parse().unwrap(), cfg).await.unwrap();
    (addr, reqwest::Client::new())
}

fn prover_key() -> (ProverKey, randprotocol_core::notes::ShieldedAddress) {
    let vk = SpendKey::random().viewing_key();
    let key = ProverKey::from_viewing_key(&vk);
    let address = key.address.clone();
    (key, address)
}

fn fib_job(reply_ek: Vec<u8>, deadline_secs: u32) -> JobRequest {
    let (_, prog, inputs) = randprotocol_zkvm::guests::all().into_iter().find(|(n, _, _)| *n == "fib(20)").unwrap();
    JobRequest {
        version: VERSION,
        profile: "test".into(),
        kind: JobKind::Program { base_pc: prog.base_pc, words: prog.words, inputs, tier: None, want_salt: true },
        deadline_secs,
        reply_ek,
    }
}

async fn submit(http: &reqwest::Client, addr: SocketAddr, address: &randprotocol_core::notes::ShieldedAddress, job: &JobRequest, token: Option<&str>) -> reqwest::Response {
    let mut req = http.post(format!("http://{addr}/v1/jobs")).body(encode(&seal_job(address, job).unwrap()));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await.unwrap()
}

async fn wait_done(http: &reqwest::Client, addr: SocketAddr, id: &str) -> serde_json::Value {
    for _ in 0..600 {
        let v: serde_json::Value = http.get(format!("http://{addr}/v1/jobs/{id}")).send().await.unwrap().json().await.unwrap();
        match v["state"].as_str().unwrap() {
            "done" | "failed" | "expired" => return v,
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
    panic!("job never finished");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_program_job_proves_and_the_result_opens_and_verifies() {
    let (key, address) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let reply = ReplyKey::generate();
    let job = fib_job(reply.ek.clone(), 120);
    let r = submit(&http, addr, &address, &job, None).await;
    assert_eq!(r.status(), 202);
    let id = r.json::<serde_json::Value>().await.unwrap()["id"].as_str().unwrap().to_string();
    let status = wait_done(&http, addr, &id).await;
    assert_eq!(status["state"], "done", "{status}");
    let bytes = http.get(format!("http://{addr}/v1/jobs/{id}/result")).send().await.unwrap().bytes().await.unwrap();
    let result = open_result(&reply, &decode(&bytes).unwrap()).unwrap();
    let JobResult::Program { proof, outputs, tier, salt } = result else { panic!("not a program result: {result:?}") };
    assert!(salt.is_some(), "want_salt: true must return the salt");
    assert_eq!(tier, 10);
    let (_, prog, _) = randprotocol_zkvm::guests::all().into_iter().find(|(n, _, _)| *n == "fib(20)").unwrap();
    let proof: randprotocol_zkvm::machine::Proof = postcard::from_bytes(&proof).unwrap();
    Machine::new(FriProfile::Test).verify(&prog.digest(), &proof).unwrap();
    assert_eq!(outputs[0], 6765, "fib(20)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_refuses_with_429_and_an_estimate() {
    let (key, address) = prover_key();
    let mut cfg = Config::test(key);
    cfg.max_queue = 0;
    let (addr, http) = start(cfg).await;
    let first = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(first.status(), 202, "the slot takes the first job");
    let second = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(second.status(), 429);
    let v: serde_json::Value = second.json().await.unwrap();
    assert!(v["retry_after_secs"].as_u64().is_some(), "{v}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_that_cannot_start_before_its_deadline_is_refused() {
    let (key, address) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    // The first job occupies the slot; the second's estimate is one average program proof
    // away, which is more than zero seconds.
    let first = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(first.status(), 202);
    let r = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 0), None).await;
    assert_eq!(r.status(), 429);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_is_400_and_leaves_the_queue_alone() {
    let (key, _) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let r = http.post(format!("http://{addr}/v1/jobs")).body(vec![0xff; 30]).send().await.unwrap();
    assert_eq!(r.status(), 400);
    let h: serde_json::Value = http.get(format!("http://{addr}/v1/health")).send().await.unwrap().json().await.unwrap();
    assert_eq!(h["queue_depth"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_sealed_to_another_prover_is_400() {
    let (key, _) = prover_key();
    let (_, other_address) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let r = submit(&http, addr, &other_address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(r.status(), 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_token_gates_every_route_that_takes_or_gives_a_job() {
    let (key, address) = prover_key();
    let mut cfg = Config::test(key);
    cfg.token = Some("s3cret".into());
    let (addr, http) = start(cfg).await;
    let r = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), None).await;
    assert_eq!(r.status(), 401);
    let r = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), Some("wrong")).await;
    assert_eq!(r.status(), 401);
    let r = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 120), Some("s3cret")).await;
    assert_eq!(r.status(), 202);
    // Health is open: a wallet checks the pin before it has proven it holds the token.
    let h = http.get(format!("http://{addr}/v1/health")).send().await.unwrap();
    assert_eq!(h.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_reports_the_key_files_address_and_the_backend() {
    let (key, address) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let h: serde_json::Value = http.get(format!("http://{addr}/v1/health")).send().await.unwrap().json().await.unwrap();
    assert_eq!(h["address"], address.to_string());
    assert_eq!(h["backend"], "cpu");
    assert_eq!(h["slots"], 1);
}

/// A reply key the prover cannot seal to has to be refused at admission. If it were only
/// discovered after proving, the job would end `failed` with no result and the wallet would
/// poll a 404 forever, having already paid for the proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_whose_reply_key_cannot_be_sealed_to_is_400_and_is_never_queued() {
    let (key, address) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let r = submit(&http, addr, &address, &fib_job(vec![0; 10], 120), None).await;
    assert_eq!(r.status(), 400);
    let h: serde_json::Value = http.get(format!("http://{addr}/v1/health")).send().await.unwrap().json().await.unwrap();
    assert_eq!(h["queue_depth"], 0, "a job we cannot reply to must not reach the queue");
}

/// `slots = 0` spawns no workers, so the job provably stays queued and the deadline — not a
/// race with a proving slot — is what the assertion turns on. The zero program seed makes the
/// estimate zero so that a one-second deadline is still admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_job_past_its_deadline_reports_expired_and_has_no_result() {
    let (key, address) = prover_key();
    let mut cfg = Config::test(key);
    cfg.slots = 0;
    cfg.seed_secs = (100.0, 0.0);
    let (addr, http) = start(cfg).await;
    let r = submit(&http, addr, &address, &fib_job(ReplyKey::generate().ek, 1), None).await;
    assert_eq!(r.status(), 202);
    let id = r.json::<serde_json::Value>().await.unwrap()["id"].as_str().unwrap().to_string();

    let v: serde_json::Value = http.get(format!("http://{addr}/v1/jobs/{id}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["state"], "queued", "inside its deadline it is still queued: {v}");
    assert_eq!(v["position"], 1);

    tokio::time::sleep(Duration::from_millis(1100)).await;
    let v: serde_json::Value = http.get(format!("http://{addr}/v1/jobs/{id}")).send().await.unwrap().json().await.unwrap();
    assert_eq!(v["state"], "expired", "past its deadline it is expired: {v}");
    assert!(v["position"].is_null(), "an expired job holds no queue position: {v}");
    assert_eq!(http.get(format!("http://{addr}/v1/jobs/{id}/result")).send().await.unwrap().status(), 404, "it was never proved");
    let h: serde_json::Value = http.get(format!("http://{addr}/v1/health")).send().await.unwrap().json().await.unwrap();
    assert_eq!(h["queue_depth"], 0, "expiring it drops it from the queue");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_job_is_404_on_both_routes() {
    let (key, _) = prover_key();
    let (addr, http) = start(Config::test(key)).await;
    let id = "00".repeat(16);
    assert_eq!(http.get(format!("http://{addr}/v1/jobs/{id}")).send().await.unwrap().status(), 404);
    assert_eq!(http.get(format!("http://{addr}/v1/jobs/{id}/result")).send().await.unwrap().status(), 404);
}
