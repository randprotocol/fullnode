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

fn rig(max_queue: usize, max_parallel: usize, behaviour: Behaviour) -> Rig {
    let key = ProverKey::from_seed([2; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let own_token = pairings.pair("laptop", true).unwrap();
    let token = pairings.pair("phone", false).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.max_queue = max_queue;
    cfg.max_parallel = max_parallel;
    cfg.result_ttl = Duration::from_millis(300);
    cfg.prove = stub(Arc::new(Mutex::new(behaviour)));
    Rig { svc: Service::start(cfg), ek, token, own_token }
}

/// The one job a prover admits: a viewing-key witness for bundle guest v3 (split authorisation) —
/// `nk` and a salt, 1 212 words.
fn job(token: [u8; 32]) -> ProveJob {
    ProveJob { version: WIRE_VERSION, token, witness_kind: WitnessKind::ViewingKey, hc_bundle: ZkExecutor::hc_hidden_bundle_v3(), profile: "test".into(),
               binding: [5; 8], inputs: vec![77; hidden_input_v3::COUNT], reply_key: fresh_reply_key() }
}

/// What a wallet older than VK-4 could still send: a spend-key witness, for the guest `hc`, at
/// that guest's own witness width — so nothing but its kind can be what refuses it.
fn spend_key_job(token: [u8; 32], hc: randprotocol_core::notes::Word8) -> ProveJob {
    let mut j = job(token);
    (j.witness_kind, j.hc_bundle, j.inputs) = (WitnessKind::SpendKey, hc, vec![77; ZkExecutor::bundle_input_words(&hc)]);
    j
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
    let r = rig(8, 1, Behaviour::Ok);
    let j = job(r.own_token);
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
    let r = rig(8, 1, Behaviour::Ok);
    let j = job([0; 32]);
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Unpaired)));
    assert_eq!(r.svc.info().queue.depth, 0);
}

/// VK-4 (audit v6, decision D33): the spend-key witness is retired. No configuration makes this
/// prover take one — for any guest, from any pairing, `own` or not — and `prover_info` says so:
/// `witness_kinds` is `["viewing_key"]` and `hc_bundles` names only the guest a viewing-key
/// witness can prove (v3). The wire still decodes the variant, so an older wallet gets a refusal
/// it can print (`-32004`), not a decode error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spend_key_job_is_refused_whatever_the_pairing_and_info_lists_only_viewing_key() {
    let r = rig(8, 1, Behaviour::Ok);
    let info = r.svc.info();
    assert_eq!(info.witness_kinds, vec!["viewing_key"]);
    assert_eq!(info.hc_bundles, vec![randprotocol_core::notes::word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3())]);
    for token in [r.own_token, r.token] {
        for hc in ZkExecutor::known_hc_bundles() {
            let j = spend_key_job(token, hc);
            match r.svc.submit(&seal_job(&r.ek, &j).unwrap()) {
                Err(Refusal::WitnessKind(why)) => {
                    assert_eq!(why, SPEND_KEY_RETIRED);
                    assert!(why.contains("retired") && why.contains("viewing-key") && why.contains("never leaves the wallet"), "{why}");
                }
                other => panic!("a spend-key job was not refused as a witness kind: {other:?}"),
            }
        }
    }
    assert_eq!(r.svc.info().queue.depth, 0);
}

/// A viewing-key witness is read only by bundle guest v3: a v3 job is accepted, proved and
/// replied to (from a pairing that is not `own` too); a v3 job at the v1/v2 width is a bad job;
/// and a viewing-key job naming v1 or v2 — guests that read a spend key where `nk` would sit — is
/// refused as a witness kind, so nothing is ever proved for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewing_key_job_is_for_guest_v3_only() {
    let r = rig(8, 1, Behaviour::Ok);
    for token in [r.token, r.own_token] {
        let j = job(token);
        let reply_key = j.reply_key;
        let id = r.svc.submit(&seal_job(&r.ek, &j).unwrap()).unwrap();
        let s = wait_terminal(&r.svc, &id).await;
        assert_eq!(s.state, State::Done);
        assert_eq!(open_reply(&reply_key, s.reply.as_ref().unwrap()).unwrap().digest, [77; 8]);
    }
    // v3 witness of the v1/v2 width: bad.
    let mut short = job(r.token);
    short.inputs = vec![77; hidden_input::COUNT];
    let Err(Refusal::Bad(e)) = r.svc.submit(&seal_job(&r.ek, &short).unwrap()) else { panic!() };
    assert!(e.contains(&hidden_input_v3::COUNT.to_string()), "{e}");
    // v1 and v2 + viewing key: refused.
    for hc in [ZkExecutor::hc_hidden_bundle(), ZkExecutor::hc_hidden_bundle_v2()] {
        let mut j = job(r.own_token);
        j.hc_bundle = hc;
        j.inputs = vec![77; hidden_input::COUNT];
        let Err(Refusal::WitnessKind(e)) = r.svc.submit(&seal_job(&r.ek, &j).unwrap()) else { panic!() };
        assert!(e.contains("v1/v2 guests take a spend key"), "{e}");
    }
    assert_eq!(r.svc.info().queue.depth, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_guest_profile_or_witness_length_is_bad() {
    let r = rig(8, 1, Behaviour::Ok);
    let mut j = job(r.own_token);
    j.hc_bundle = [1; 8];
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Bad(_))));
    let mut j = job(r.own_token);
    j.profile = "fast\u{1b}[2J".into();
    match r.svc.submit(&seal_job(&r.ek, &j).unwrap()) {
        Err(Refusal::Bad(why)) => assert_eq!(why, "unknown fri profile", "the submitter's profile string is never echoed"),
        other => panic!("{other:?}"),
    }
    let mut j = job(r.own_token);
    j.inputs.truncate(10);
    assert!(matches!(r.svc.submit(&seal_job(&r.ek, &j).unwrap()), Err(Refusal::Bad(_))));
    assert!(matches!(r.svc.submit(&[0u8; 50]), Err(Refusal::Bad(_))));
    assert!(matches!(r.svc.submit(&vec![0u8; MAX_SEALED_JOB_BYTES + 1]), Err(Refusal::Bad(_))));
    assert_eq!(r.svc.info().queue.depth, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_queue_is_busy_with_the_depth_and_a_token_is_capped() {
    let r = rig(1, 1, Behaviour::Block(400));
    let first = r.svc.submit(&seal_job(&r.ek, &job(r.own_token)).unwrap()).unwrap();
    wait_proving(&r.svc, &first).await;
    let second = r.svc.submit(&seal_job(&r.ek, &job(r.own_token)).unwrap()).unwrap();
    // per_token is 2: a third from the same token is busy even though the queue (1 proving + 1 queued == max_queue + max_parallel) is also full
    let e = r.svc.submit(&seal_job(&r.ek, &job(r.own_token)).unwrap()).unwrap_err();
    assert!(matches!(e, Refusal::Busy { depth: 1, max: 1 }), "depth is the queued count");
    let e = r.svc.submit(&seal_job(&r.ek, &job(r.token)).unwrap()).unwrap_err();
    assert!(matches!(e, Refusal::Busy { .. }), "queue full for another token too");
    assert_eq!(r.svc.status(&second).unwrap().position, Some(1));
    wait_terminal(&r.svc, &first).await;
    wait_terminal(&r.svc, &second).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_proof_reports_its_error_and_never_its_inputs() {
    let r = rig(8, 1, Behaviour::Fail("unknown hc".into()));
    let id = r.svc.submit(&seal_job(&r.ek, &job(r.own_token)).unwrap()).unwrap();
    let s = wait_terminal(&r.svc, &id).await;
    assert_eq!(s.state, State::Failed);
    assert_eq!(s.error.as_deref(), Some("unknown hc"));
    assert!(s.reply.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_done_reply_expires_after_the_ttl_and_cancel_drops_a_queued_job() {
    let r = rig(8, 1, Behaviour::Ok);
    let id = r.svc.submit(&seal_job(&r.ek, &job(r.own_token)).unwrap()).unwrap();
    let s = wait_terminal(&r.svc, &id).await;
    assert_eq!(s.state, State::Done);
    assert!(r.svc.status(&id).unwrap().reply.is_some(), "served again within the ttl");
    tokio::time::sleep(Duration::from_millis(400)).await;
    let s = r.svc.status(&id).unwrap();
    assert_eq!(s.state, State::Expired);
    assert!(s.reply.is_none());
    let r = rig(8, 1, Behaviour::Block(300));
    let a = r.svc.submit(&seal_job(&r.ek, &job(r.own_token)).unwrap()).unwrap();
    wait_proving(&r.svc, &a).await;
    let b = r.svc.submit(&seal_job(&r.ek, &job(r.token)).unwrap()).unwrap();
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
    let r = rig(8, 1, Behaviour::Ok);
    let i = r.svc.info();
    // The same hex form `rand_status.hc_bundle` serves, so a wallet compares strings directly.
    let known: Vec<String> = ZkExecutor::known_hc_bundles().iter().map(randprotocol_core::notes::word8_to_hex).collect();
    // Only the guest a viewing-key witness proves — v3 — of the three this build knows (VK-4).
    assert_eq!(i.hc_bundles, vec![randprotocol_core::notes::word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3())]);
    assert!(known.contains(&i.hc_bundles[0]) && known.len() == 3);
    assert_eq!(i.witness_kinds, vec!["viewing_key"]);
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
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let inner = stub(Arc::new(Mutex::new(Behaviour::Block(300))));
    let count = started.clone();
    cfg.prove = Arc::new(move |hc, p, inputs, binding, backend| {
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        inner(hc, p, inputs, binding, backend)
    });
    let svc = Service::start(cfg);
    let proving = svc.submit(&seal_job(&ek, &job(own)).unwrap()).unwrap();
    wait_proving(&svc, &proving).await;
    let q1 = svc.submit(&seal_job(&ek, &job(own)).unwrap()).unwrap();
    let q2 = svc.submit(&seal_job(&ek, &job(other)).unwrap()).unwrap();
    assert_eq!(svc.info().queue.depth, 2);

    svc.shutdown();
    assert!(svc.status(&q1).is_none(), "a queued job is dropped");
    assert!(svc.status(&q2).is_none(), "a queued job is dropped");
    assert_eq!(svc.info().queue.depth, 0);
    match svc.submit(&seal_job(&ek, &job(other)).unwrap()) {
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

/// A rig whose prover charges `fee` (or nothing).
fn fee_rig(fee: Option<Fee>) -> Rig {
    let key = ProverKey::from_seed([4; 64]);
    let ek = key.kem_ek().to_vec();
    let mut pairings = Pairings::default();
    let own_token = pairings.pair("laptop", true).unwrap();
    let token = pairings.pair("phone", false).unwrap();
    let mut cfg = Config::new(key, pairings);
    cfg.fee = fee;
    cfg.prove = stub(Arc::new(Mutex::new(Behaviour::Ok)));
    Rig { svc: Service::start(cfg), ek, token, own_token }
}

fn charging() -> Option<Fee> {
    Some(Fee { amount: FEE, address: prover_address() })
}

/// A v3 witness whose four outputs pay nobody in particular (pk 1, amount 0), asset `A` = `asset_a`.
fn v3_witness(token: [u8; 32], asset_a: u32) -> ProveJob {
    let mut j = job(token);
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
    // A spend-key job is refused for its kind before any fee is read (VK-4), charging or not.
    let Err(Refusal::WitnessKind(why)) = submit(&r, &spend_key_job(r.own_token, ZkExecutor::hc_hidden_bundle_v2())) else { panic!() };
    assert_eq!(why, SPEND_KEY_RETIRED);
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
    // The outputs are never read: all-77 words, and a token transfer paying nobody.
    submit(&r, &job(r.token)).expect("any v3 witness");
    submit(&r, &v3_witness(r.token, 1)).expect("no output pays anyone we know");
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

/// Review M-3: a fee output at or above 2^63 — which the guest's range check would taint — is
/// refused at admission, before any proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fee_output_of_two_to_the_63_is_refused_before_proving() {
    let r = fee_rig(charging());
    for amount in [1u64 << 63, u64::MAX] {
        let mut j = v3_witness(r.token, 1);
        pay(&mut j, 2, PROVER_PK, amount);
        let Err(Refusal::Fee(why)) = submit(&r, &j) else { panic!("{amount} must be refused") };
        assert!(why.contains("2^63"), "{why}");
    }
    let mut j = v3_witness(r.token, 1);
    pay(&mut j, 2, PROVER_PK, (1 << 63) - 1);
    submit(&r, &j).expect("just below 2^63 pays the quote");
}
