use randprotocol_prover::key::ProverKey;
use randprotocol_prover::pairing::Pairings;
use randprotocol_prover::service::*;
use randprotocol_prover::wire::*;
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::hidden::hidden_input;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A stub prover that returns a fixed proof, or blocks until released, or fails.
fn stub(behaviour: Arc<Mutex<Behaviour>>) -> ProveFn {
    Arc::new(move |_hc, _profile, inputs, _binding, _backend| {
        let b = behaviour.lock().unwrap().clone();
        match b {
            Behaviour::Ok => Ok((vec![0xAA; 1000], [inputs[0]; 8], 14)),
            Behaviour::Fail(e) => Err(e),
            Behaviour::Block(ms) => { std::thread::sleep(Duration::from_millis(ms)); Ok((vec![1], [0; 8], 14)) }
        }
    })
}
#[derive(Clone)] enum Behaviour { Ok, Fail(String), Block(u64) }

struct Rig { svc: Shared, ek: Vec<u8>, token: [u8; 32], own_token: [u8; 32] }

fn rig(accept_spend_key: bool, max_queue: usize, max_parallel: usize, behaviour: Behaviour) -> Rig {
    let key = ProverKey::from_seed([2; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let own_token = pairings.pair("laptop", true).unwrap();
    let token = pairings.pair("phone", false).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.accept_spend_key = accept_spend_key;
    cfg.max_queue = max_queue;
    cfg.max_parallel = max_parallel;
    cfg.result_ttl = Duration::from_millis(300);
    cfg.prove = stub(Arc::new(Mutex::new(behaviour)));
    Rig { svc: Service::start(cfg), ek, token, own_token }
}

fn job(token: [u8; 32], kind: WitnessKind) -> ProveJob {
    ProveJob { version: WIRE_VERSION, token, witness_kind: kind, hc_bundle: ZkExecutor::hc_bundle(), profile: "test".into(),
               binding: [5; 8], inputs: vec![77; hidden_input::COUNT], reply_key: fresh_reply_key() }
}

async fn wait_terminal(svc: &Service, id: &str) -> Status {
    for _ in 0..200 {
        let s = svc.status(id).expect("known job");
        if matches!(s.state, State::Done | State::Failed | State::Expired) { return s; }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("never finished");
}

/// Waits until a worker has picked the job up, so a test that needs "one proving, the rest
/// queued" does not race the worker thread.
async fn wait_proving(svc: &Service, id: &str) {
    for _ in 0..200 {
        if svc.status(id).expect("known job").state == State::Proving { return; }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("never started proving");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paired_job_proves_and_the_reply_opens_under_the_reply_key() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let j = job(r.own_token, WitnessKind::SpendKey);
    let reply_key = j.reply_key;
    let id = r.svc.submit(&seal_job(&r.ek, &j).unwrap()).unwrap();
    assert_eq!(id.len(), 32, "128 bits, hex");
    let s = wait_terminal(&r.svc, &id).await;
    assert_eq!(s.state, State::Done);
    let reply = open_reply(&reply_key, s.reply.as_ref().unwrap()).unwrap();
    assert_eq!(reply.tier, 14);
    assert_eq!(reply.digest, [77; 8]);
    assert_eq!(reply.proof.len(), 1000);
    assert!(open_reply(&fresh_reply_key(), s.reply.as_ref().unwrap()).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_token_is_refused_before_queueing() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let j = job([0; 32], WitnessKind::SpendKey);
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Unpaired)));
    assert_eq!(r.svc.info().queue.depth, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spend_key_job_needs_the_flag_and_info_says_so() {
    let r = rig(false, 8, 1, Behaviour::Ok);
    assert!(r.svc.info().witness_kinds.is_empty());
    let j = job(r.own_token, WitnessKind::SpendKey);
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::WitnessKind(_))));
    let r = rig(true, 8, 1, Behaviour::Ok);
    assert_eq!(r.svc.info().witness_kinds, vec!["spend_key"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewing_key_job_is_refused_in_this_build() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let j = job(r.own_token, WitnessKind::ViewingKey);
    let Err(Refusal::WitnessKind(e)) = r.svc.submit(&seal_job(&r.ek, &j).unwrap()) else { panic!() };
    assert!(e.contains("spend key"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_guest_profile_or_witness_length_is_bad() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let mut j = job(r.own_token, WitnessKind::SpendKey);
    j.hc_bundle = [1; 8];
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Bad(_))));
    let mut j = job(r.own_token, WitnessKind::SpendKey);
    j.profile = "fast\u{1b}[2J".into();
    match r.svc.submit(&seal_job(&r.ek, &j).unwrap()) {
        Err(Refusal::Bad(why)) => assert_eq!(why, "unknown fri profile", "the submitter's profile string is never echoed"),
        other => panic!("{other:?}"),
    }
    let mut j = job(r.own_token, WitnessKind::SpendKey);
    j.inputs.truncate(10);
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Bad(_))));
    assert!(matches!(r.svc.submit(&[0u8; 50]), Err(Refusal::Bad(_))));
    assert!(matches!(r.svc.submit(&vec![0u8; MAX_SEALED_JOB_BYTES + 1]), Err(Refusal::Bad(_))));
    assert_eq!(r.svc.info().queue.depth, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_is_busy_with_the_depth_and_a_token_is_capped() {
    let r = rig(true, 1, 1, Behaviour::Block(400));
    let first = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    wait_proving(&r.svc, &first).await;
    let second = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    // per_token is 2: a third from the same token is busy even though the queue (1 proving + 1 queued == max_queue + max_parallel) is also full
    let e = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap_err();
    assert!(matches!(e, Refusal::Busy { depth: 1, max: 1 }), "depth is the queued count");
    let e = r.svc.submit(&seal_job(&r.ek, &job(r.token, WitnessKind::SpendKey)).unwrap()).unwrap_err();
    assert!(matches!(e, Refusal::Busy { .. }), "queue full for another token too");
    assert_eq!(r.svc.status(&second).unwrap().position, Some(1));
    wait_terminal(&r.svc, &first).await;
    wait_terminal(&r.svc, &second).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_proof_reports_its_error_and_never_its_inputs() {
    let r = rig(true, 8, 1, Behaviour::Fail("unknown hc".into()));
    let id = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    let s = wait_terminal(&r.svc, &id).await;
    assert_eq!(s.state, State::Failed);
    assert_eq!(s.error.as_deref(), Some("unknown hc"));
    assert!(s.reply.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_done_reply_expires_after_the_ttl_and_cancel_drops_a_queued_job() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let id = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    let s = wait_terminal(&r.svc, &id).await;
    assert_eq!(s.state, State::Done);
    assert!(r.svc.status(&id).unwrap().reply.is_some(), "served again within the ttl");
    tokio::time::sleep(Duration::from_millis(400)).await;
    let s = r.svc.status(&id).unwrap();
    assert_eq!(s.state, State::Expired);
    assert!(s.reply.is_none());
    let r = rig(true, 8, 1, Behaviour::Block(300));
    let a = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()).unwrap();
    wait_proving(&r.svc, &a).await;
    let b = r.svc.submit(&seal_job(&r.ek, &job(r.token, WitnessKind::SpendKey)).unwrap()).unwrap();
    assert!(r.svc.cancel(&b));
    assert!(r.svc.status(&b).is_none(), "a cancelled queued job is gone");
    assert!(!r.svc.cancel(&b));
    assert!(r.svc.cancel(&a), "a proving job is cancelled: its reply is dropped when it finishes");
    let s = wait_terminal(&r.svc, &a).await;
    assert!(s.reply.is_none());
    assert_eq!(s.state, State::Failed);
    assert_eq!(s.error.as_deref(), Some("cancelled"));
    assert!(r.svc.status("nope").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_names_the_guests_the_profiles_the_backend_and_the_fingerprint() {
    let r = rig(true, 8, 1, Behaviour::Ok);
    let i = r.svc.info();
    // The same hex form `rand_status.hc_bundle` serves, so a wallet compares strings directly.
    let known: Vec<String> = ZkExecutor::known_hc_bundles().iter().map(randprotocol_core::notes::word8_to_hex).collect();
    assert_eq!(i.hc_bundles, known);
    assert!(i.hc_bundles.contains(&randprotocol_core::notes::word8_to_hex(&ZkExecutor::hc_bundle())));
    assert_eq!(i.profiles, vec!["test", "production"]);
    assert_eq!(i.backend, "cpu");
    assert_eq!(i.kem_fingerprint, randprotocol_prover::key::fingerprint_of(&r.ek).to_string());
    assert_eq!(hex::decode(&i.kem_ek).unwrap(), r.ek);
    assert_eq!(i.queue.max, 8);
    assert!(i.fee.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drops_queued_jobs_refuses_new_ones_and_stops_the_workers() {
    let key = ProverKey::from_seed([3; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let own = pairings.pair("laptop", true).unwrap();
    let other = pairings.pair("phone", false).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.accept_spend_key = true;
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let inner = stub(Arc::new(Mutex::new(Behaviour::Block(300))));
    let count = started.clone();
    cfg.prove = Arc::new(move |hc, p, inputs, binding, backend| {
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        inner(hc, p, inputs, binding, backend)
    });
    let svc = Service::start(cfg);
    let proving = svc.submit(&seal_job(&ek, &job(own, WitnessKind::SpendKey)).unwrap()).unwrap();
    wait_proving(&svc, &proving).await;
    let q1 = svc.submit(&seal_job(&ek, &job(own, WitnessKind::SpendKey)).unwrap()).unwrap();
    let q2 = svc.submit(&seal_job(&ek, &job(other, WitnessKind::SpendKey)).unwrap()).unwrap();
    assert_eq!(svc.info().queue.depth, 2);

    svc.shutdown();
    assert!(svc.status(&q1).is_none(), "a queued job is dropped");
    assert!(svc.status(&q2).is_none(), "a queued job is dropped");
    assert_eq!(svc.info().queue.depth, 0);
    match svc.submit(&seal_job(&ek, &job(other, WitnessKind::SpendKey)).unwrap()) {
        Err(Refusal::Bad(why)) => assert_eq!(why, "shutting down"),
        other => panic!("{other:?}"),
    }
    let s = wait_terminal(&svc, &proving).await;
    assert_eq!(s.state, State::Failed);
    assert!(s.reply.is_none(), "the in-flight proof's reply is discarded");
    assert_eq!(s.error.as_deref(), Some("shutting down"));
    // The worker exits: it drops its clone of the service.
    for _ in 0..200 {
        if Arc::strong_count(&svc) == 1 { break; }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(Arc::strong_count(&svc), 1, "the worker task still holds the service");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 1, "no second proof ever starts");
}
