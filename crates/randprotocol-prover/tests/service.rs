use randprotocol_prover::key::ProverKey;
use randprotocol_prover::pairing::Pairings;
use randprotocol_prover::service::*;
use randprotocol_prover::wire::*;
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::hidden::{hidden_input, hidden_input_v3};
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
    assert_eq!(r.svc.info().witness_kinds, vec!["viewing_key"], "viewing-key jobs (v3) are always accepted");
    let j = job(r.own_token, WitnessKind::SpendKey);
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::WitnessKind(_))));
    let r = rig(true, 8, 1, Behaviour::Ok);
    assert_eq!(r.svc.info().witness_kinds, vec!["viewing_key", "spend_key"]);
}

/// A job for bundle guest v3 (split authorisation): `nk` and a salt, 1 212 words.
fn v3_job(token: [u8; 32], kind: WitnessKind) -> ProveJob {
    let mut j = job(token, kind);
    j.hc_bundle = ZkExecutor::hc_hidden_bundle_v3();
    j.inputs = vec![77; hidden_input_v3::COUNT];
    j
}

/// The witness kind follows the guest, whatever the flag: a viewing-key job for v3 is accepted
/// (with or without `--accept-spend-key`), a spend-key job for v3 is refused (v3 takes `nk`), and
/// a viewing-key job for v1/v2 is refused (those take a spend key).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_witness_kind_follows_the_guest() {
    for accept_spend_key in [false, true] {
        let r = rig(accept_spend_key, 8, 1, Behaviour::Ok);
        // v3 + viewing key: accepted, proved, replied.
        let j = v3_job(r.token, WitnessKind::ViewingKey);
        let reply_key = j.reply_key;
        let id = r.svc.submit(&seal_job(&r.ek, &j).unwrap()).unwrap_or_else(|e| panic!("accept_spend_key {accept_spend_key}: {e:?}"));
        let s = wait_terminal(&r.svc, &id).await;
        assert_eq!(s.state, State::Done);
        assert_eq!(open_reply(&reply_key, s.reply.as_ref().unwrap()).unwrap().digest, [77; 8]);
        // v3 witness of the v1/v2 width: bad.
        let mut short = v3_job(r.token, WitnessKind::ViewingKey);
        short.inputs = vec![77; hidden_input::COUNT];
        let Err(Refusal::Bad(e)) = r.svc.submit(&seal_job(&r.ek, &short).unwrap()) else { panic!() };
        assert!(e.contains(&hidden_input_v3::COUNT.to_string()), "{e}");
        // v1 and v2 + viewing key: refused.
        for hc in [ZkExecutor::hc_hidden_bundle(), ZkExecutor::hc_hidden_bundle_v2()] {
            let mut j = job(r.own_token, WitnessKind::ViewingKey);
            j.hc_bundle = hc;
            let Err(Refusal::WitnessKind(e)) = r.svc.submit(&seal_job(&r.ek, &j).unwrap()) else { panic!() };
            assert!(e.contains("v1/v2 guests take a spend key"), "{e}");
        }
    }
    // v3 + spend key: refused even where spend keys are accepted…
    let r = rig(true, 8, 1, Behaviour::Ok);
    let Err(Refusal::WitnessKind(e)) = r.svc.submit(&seal_job(&r.ek, &v3_job(r.own_token, WitnessKind::SpendKey)).unwrap()) else { panic!() };
    assert!(e.contains("a v3 guest takes nk"), "{e}");
    // …and, without the flag, refused as a spend-key job before the guest is looked at.
    let r = rig(false, 8, 1, Behaviour::Ok);
    let Err(Refusal::WitnessKind(e)) = r.svc.submit(&seal_job(&r.ek, &v3_job(r.own_token, WitnessKind::SpendKey)).unwrap()) else { panic!() };
    assert!(e.contains("does not accept spend-key"), "{e}");
    // v1 + spend key without the flag: refused (the flag is the gate).
    let Err(Refusal::WitnessKind(_)) = r.svc.submit(&seal_job(&r.ek, &job(r.own_token, WitnessKind::SpendKey)).unwrap()) else { panic!() };
    assert_eq!(r.svc.info().queue.depth, 0);
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

// ---- The prover fee (spec §5): one RAND output to the prover's address, checked in the witness.

const FEE: u64 = 5_000_000_000; // 5 RAND
const PROVER_PK: [u32; 8] = [0xF00D; 8];

fn prover_address() -> randprotocol_core::notes::ShieldedAddress {
    randprotocol_core::notes::ShieldedAddress { pk: PROVER_PK, kem_ek: vec![9; 1184] }
}

/// A rig whose prover charges `fee` (or nothing), spend keys accepted so a v1 job reaches the fee check.
fn fee_rig(fee: Option<Fee>) -> Rig {
    let key = ProverKey::from_seed([4; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let own_token = pairings.pair("laptop", true).unwrap();
    let token = pairings.pair("phone", false).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.accept_spend_key = true;
    cfg.fee = fee;
    cfg.prove = stub(Arc::new(Mutex::new(Behaviour::Ok)));
    Rig { svc: Service::start(cfg), ek, token, own_token }
}

fn charging() -> Option<Fee> {
    Some(Fee { amount: FEE, address: prover_address() })
}

/// A v3 witness whose four outputs pay nobody in particular (pk 1, amount 0), asset `A` = `asset_a`.
fn v3_witness(token: [u8; 32], asset_a: u32) -> ProveJob {
    let mut j = v3_job(token, WitnessKind::ViewingKey);
    for k in 0..4 {
        let o = hidden_input_v3::out(k);
        j.inputs[o + hidden_input_v3::O_PK..o + hidden_input_v3::O_PK + 8].copy_from_slice(&[1; 8]);
        j.inputs[o + hidden_input_v3::O_AMOUNT_LO] = 0;
        j.inputs[o + hidden_input_v3::O_AMOUNT_HI] = 0;
    }
    j.inputs[hidden_input_v3::ASSET_A] = asset_a;
    j
}

fn pay(j: &mut ProveJob, slot: usize, pk: [u32; 8], amount: u64) {
    let o = hidden_input_v3::out(slot);
    j.inputs[o + hidden_input_v3::O_PK..o + hidden_input_v3::O_PK + 8].copy_from_slice(&pk);
    j.inputs[o + hidden_input_v3::O_AMOUNT_LO] = amount as u32;
    j.inputs[o + hidden_input_v3::O_AMOUNT_HI] = (amount >> 32) as u32;
}

fn submit(r: &Rig, j: &ProveJob) -> Result<String, Refusal> {
    r.svc.submit(&seal_job(&r.ek, j).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fee_paid_in_the_wrong_asset_is_refused() {
    let r = fee_rig(charging());
    // Slots 0–1 carry asset A: a token (A = 1) fee there is not RAND.
    for slot in [0, 1] {
        let mut j = v3_witness(r.token, 1);
        pay(&mut j, slot, PROVER_PK, FEE);
        let Err(Refusal::Fee(why)) = submit(&r, &j) else { panic!("slot {slot} in asset 1 must be refused") };
        assert!(why.contains("RAND"), "{why}");
    }
    // The same slot in a RAND transfer (A = 0) is RAND: accepted.
    let mut j = v3_witness(r.token, 0);
    pay(&mut j, 0, PROVER_PK, FEE);
    submit(&r, &j).expect("slot 0 of a RAND transfer is a RAND slot");
    // Slots 2–3 are RAND whatever A is.
    let mut j = v3_witness(r.own_token, 1);
    pay(&mut j, 2, PROVER_PK, FEE);
    submit(&r, &j).expect("slot 2 is always RAND");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fee_below_the_quote_is_refused() {
    let r = fee_rig(charging());
    let mut j = v3_witness(r.token, 1);
    pay(&mut j, 2, PROVER_PK, FEE - 1);
    let Err(Refusal::Fee(why)) = submit(&r, &j) else { panic!("one unit short must be refused") };
    assert!(why.contains("below"), "{why}");
    // The amount is lo | hi << 32: a fee above 2^32 units is read whole.
    let r = fee_rig(Some(Fee { amount: (1 << 32) + 7, address: prover_address() }));
    let mut j = v3_witness(r.token, 1);
    pay(&mut j, 3, PROVER_PK, 7);
    assert!(matches!(submit(&r, &j), Err(Refusal::Fee(_))), "the low word alone is not the amount");
    let mut j = v3_witness(r.token, 1);
    pay(&mut j, 3, PROVER_PK, (1 << 32) + 7);
    submit(&r, &j).expect("exactly the quote");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fee_output_to_another_pk_is_refused() {
    let r = fee_rig(charging());
    let mut j = v3_witness(r.token, 0);
    pay(&mut j, 2, [0xBEEF; 8], FEE * 10);
    let Err(Refusal::Fee(why)) = submit(&r, &j) else { panic!("paying someone else is no fee") };
    assert!(why.contains("no output pays this prover"), "{why}");
    // A v1/v2 (spend-key) witness cannot carry the fee this prover charges.
    let Err(Refusal::Fee(why)) = submit(&r, &job(r.own_token, WitnessKind::SpendKey)) else { panic!() };
    assert!(why.contains("only a v3 witness can carry"), "{why}");
    assert_eq!(r.svc.info().queue.depth, 0);
    // prover_info quotes it: base units as a decimal string, and the address.
    let fee = r.svc.info().fee.expect("quoted");
    assert_eq!(fee.amount, FEE.to_string());
    assert_eq!(fee.address, prover_address().to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_fee_configured_accepts_any_witness() {
    let r = fee_rig(None);
    assert!(r.svc.info().fee.is_none());
    // The outputs are never read: all-77 words, a token transfer paying nobody, and a v1 job.
    submit(&r, &v3_job(r.token, WitnessKind::ViewingKey)).expect("any v3 witness");
    submit(&r, &v3_witness(r.token, 1)).expect("no output pays anyone we know");
    submit(&r, &job(r.own_token, WitnessKind::SpendKey)).expect("a spend-key job, spend keys accepted");
}

#[test]
fn a_fee_needs_both_flags_parsed_in_display_units() {
    let addr = prover_address().to_string();
    let f = Fee::from_flags("1.5", &addr).unwrap();
    assert_eq!(f.amount, 1_500_000_000);
    assert_eq!(f.address, prover_address());
    assert!(Fee::from_flags("0", &addr).is_err(), "a zero fee is no fee: omit both flags");
    assert!(Fee::from_flags("1.0000000001", &addr).is_err(), "RAND has 9 decimals");
    assert!(Fee::from_flags("1", "rand1nope").is_err());
}
