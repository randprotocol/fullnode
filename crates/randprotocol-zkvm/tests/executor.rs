use randprotocol_core::confidential::{ConfidentialError, ConfidentialExecutor};
use randprotocol_core::program::{program_id, ProgramRecord};
use randprotocol_zkvm::executor::{prove, ZkExecutor};
use randprotocol_zkvm::guests;
use randprotocol_zkvm::machine::{Backend, FriProfile};
use std::sync::OnceLock;

fn record(p: &randprotocol_zkvm::isa::Program) -> ProgramRecord {
    let ex = ZkExecutor::new(FriProfile::Test);
    let code_hash = ex.check_program(p.base_pc, &p.words).unwrap();
    ProgramRecord {
        id: program_id(p.base_pc, &p.words),
        base_pc: p.base_pc,
        words: p.words.clone(),
        code_hash,
        deployed_at: 0,
        public_digest: None,
        public_len: 0,
    }
}

/// One proof shared by every test (proving takes ~20 s).
fn shared() -> &'static (Vec<u8>, [u32; 8], u8) {
    static P: OnceLock<(Vec<u8>, [u32; 8], u8)> = OnceLock::new();
    P.get_or_init(|| prove(FriProfile::Test, &guests::private_payment(1000), &[400, 250, 300, 75], &[], None, Backend::Cpu).unwrap())
}

#[test]
fn verifies_a_real_proof_and_reports_outputs() {
    let p = guests::private_payment(1000);
    let (proof, outputs, tier) = shared();
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = record(&p);
    let out = ex.verify_call(&rec, proof).unwrap();
    assert_eq!(out.tier, *tier);
    assert_eq!(out.outputs, *outputs);
    assert_eq!(out.outputs[0], 1, "sum 1025 >= 1000 -> transfer");
    assert_eq!(out.outputs[1], 0);
    assert_eq!(out.outputs[2], 1025 - 1000, "pays the surplus");
    assert_eq!(ex.cached_keys(), 1);
    ex.warm(&rec);
    // `warm` precomputes the keys for tiers 10, 12 and 14 (the tiers real guests land on;
    // warming every tier would build the Poseidon2 chip's 2^22-row preprocessed table on a
    // 2-vCPU validator at deploy time) crossed with two input-height classes (M4.1 ruling,
    // `executor.rs`'s `warm` doc comment): `input::MIN_LOG_HEIGHT` (a 0..3-word call) and
    // `input_log_height(4)` (a 4-word call — what `private_payment` itself reads, matching the
    // proof already verified above at tier 10). 3 tiers * 2 input-height classes = 6 combinations;
    // the (tier 10, input height of a 4-word call) key is already cached from the verify above
    // and is reused, not double-counted, so six cached keys in total.
    assert_eq!(
        ex.cached_keys(),
        6,
        "warm precomputes keys for tiers 10, 12, 14 x 2 input-height classes, reusing the cached one"
    );
    let t = std::time::Instant::now();
    ex.verify_call(&rec, proof).unwrap();
    assert!(t.elapsed().as_millis() < 500, "cached verify took {:?}", t.elapsed());
}

#[test]
fn rejects_wrong_program_tampered_bytes_and_wrong_profile() {
    let p = guests::private_payment(1000);
    let (proof, _, _) = shared();
    let ex = ZkExecutor::new(FriProfile::Test);
    let other = guests::private_payment(1001);
    assert!(matches!(ex.verify_call(&record(&other), proof), Err(ConfidentialError::InvalidProof(_))));
    let mut bad = proof.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 1;
    assert!(ex.verify_call(&record(&p), &bad).is_err());
    assert_eq!(ex.verify_call(&record(&p), b"nope"), Err(ConfidentialError::MalformedProof));
    let prod = ZkExecutor::new(FriProfile::Production);
    assert!(prod.verify_call(&record(&p), proof).is_err(), "a test-profile proof must not pass a production verifier");
}

#[test]
fn check_program_rejects_bad_words() {
    let ex = ZkExecutor::new(FriProfile::Test);
    assert!(matches!(ex.check_program(0, &[0xffff_ffff]), Err(ConfidentialError::BadInstruction { index: 0, .. })));
    assert!(ex.check_program(0, &[0x13]).is_ok());
    assert!(ex.check_program(2, &[0x13]).is_err(), "base_pc must be word aligned");
    assert!(ex.check_program(0, &[]).is_err());
}

/// ZH4 (2026-09-12 zk audit, ours not `research`'s): `base_pc + 4*len` must not wrap the u32 pc
/// space, or `instr_at`/`Program::pc_of` could never address the tail of the program. Two words
/// at `u32::MAX - 3` puts the last word's address one past the wrap; one word lands exactly on
/// it and still fits.
#[test]
fn zh4_rejects_a_program_that_wraps_the_u32_pc_space() {
    let ex = ZkExecutor::new(FriProfile::Test);
    assert!(ex.check_program(u32::MAX - 3, &[0x13, 0x13]).is_err(), "two words wraps");
    assert!(ex.check_program(u32::MAX - 3, &[0x13]).is_ok(), "one word exactly fits");
}

#[test]
fn private_payment_emits_no_transfer_below_threshold() {
    let (_, outputs, _) = prove(FriProfile::Test, &guests::private_payment(2000), &[400, 250, 300, 75], &[], None, Backend::Cpu).unwrap();
    assert_eq!(outputs, [0; 8]);
}

/// `prove` names the backend it runs on; `Backend::Cpu` is the same proof the other tests verify.
#[test]
fn prove_takes_a_backend_and_cpu_is_unchanged() {
    let p = guests::private_payment(1000);
    let (proof, outputs, tier) =
        prove(FriProfile::Test, &p, &[400, 250, 300, 75], &[], None, randprotocol_zkvm::machine::Backend::Cpu).unwrap();
    let ex = ZkExecutor::new(FriProfile::Test);
    let out = ex.verify_call(&record(&p), &proof).unwrap();
    assert_eq!((out.outputs, out.tier), (outputs, tier));
}

/// A program deployed with a public input (the call limits, spec §5): `verify_call` compares the
/// proof's `pv::PUB0..7` with the record's deploy-time digest, never re-hashing any words.
#[test]
fn a_call_is_checked_against_the_records_public_digest() {
    use randprotocol_zkvm::machine::Machine;
    let m = Machine::new(FriProfile::Test);
    let p = guests::public_echo();
    let public = [11u32, 22, 33, 44];
    let ex = ZkExecutor::new(FriProfile::Test);
    assert_eq!(ex.public_digest(&public), randprotocol_zkvm::hash::public_digest(&public));
    let with = ProgramRecord {
        id: randprotocol_core::program::program_id_with_public(p.base_pc, &p.words, &public),
        public_digest: Some(ex.public_digest(&public)),
        public_len: public.len() as u32,
        ..record(&p)
    };
    let (proof, exec) = m.prove(&p, &[], &public, None).unwrap();
    let proof = proof.to_bytes();
    let out = ex.verify_call(&with, &proof).expect("proved with the program's public input");
    assert_eq!(out.outputs, exec.outputs);
    let public_values = |r: Result<_, ConfidentialError>| match r {
        Err(ConfidentialError::InvalidProof(e)) => e == "PublicValues",
        _ => false,
    };
    // Other words, and the empty input, against the same program.
    let (other, _) = m.prove(&p, &[], &[11, 22, 33, 45], None).unwrap();
    assert!(public_values(ex.verify_call(&with, &other.to_bytes())));
    // A record without a digest takes only the empty input: the same proof is refused.
    assert!(public_values(ex.verify_call(&record(&p), &proof)));
    // The empty input against a program deployed with one (a guest that never reads its public
    // segment still commits to it, so the empty-input proof is a different statement).
    let f = guests::fib(10);
    let fib_with = ProgramRecord { public_digest: Some(ex.public_digest(&public)), public_len: public.len() as u32, ..record(&f) };
    let (empty, _) = m.prove(&f, &[], &[], None).unwrap();
    assert!(public_values(ex.verify_call(&fib_with, &empty.to_bytes())));
    let (committed, _) = m.prove(&f, &[], &public, None).unwrap();
    assert!(ex.verify_call(&fib_with, &committed.to_bytes()).is_ok());
}

/// A program deployed without a public input keeps its old id and still verifies `&[]` proofs.
#[test]
fn a_program_without_a_public_input_keeps_its_id_and_its_empty_input_proofs() {
    let p = guests::private_payment(1000);
    let rec = record(&p);
    assert_eq!(rec.id, randprotocol_core::program::program_id_with_public(p.base_pc, &p.words, &[]));
    assert_eq!(rec.public_digest, None);
    let (proof, outputs, _) = shared();
    assert_eq!(ZkExecutor::new(FriProfile::Test).verify_call(&rec, proof).unwrap().outputs, *outputs);
}

/// `warm` precomputes the verifier key a call against a program with a public input needs: the
/// public table's height follows the record's `public_len`, so after warming, a call's verify
/// builds no new key.
#[test]
fn a_program_with_a_public_input_is_warmed() {
    use randprotocol_zkvm::machine::Machine;
    let p = guests::public_echo();
    let public = [11u32, 22, 33, 44, 55, 66, 77, 88, 99];
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = ProgramRecord {
        public_digest: Some(ex.public_digest(&public)),
        public_len: public.len() as u32,
        ..record(&p)
    };
    let (proof, _) = Machine::new(FriProfile::Test).prove(&p, &[], &public, Some(randprotocol_zkvm::machine::Tier(10))).unwrap();
    assert_eq!(proof.public_log_height, randprotocol_zkvm::tables::public::public_log_height(public.len()));
    assert_ne!(proof.public_log_height, randprotocol_zkvm::tables::public::public_log_height(0), "a class of its own");
    ex.warm(&rec);
    let warmed = ex.cached_keys();
    ex.verify_call(&rec, &proof.to_bytes()).unwrap();
    assert_eq!(ex.cached_keys(), warmed, "the call's key was already warm");
}

/// Canonical proof decoding (final review): `postcard::from_bytes` ignores trailing bytes and
/// accepts overlong varints, so the executor re-encodes and compares. An honest proof passes; the
/// same proof with one trailing byte, or with its leading `tier` varint re-encoded overlong,
/// decodes to the same `Proof` and is still refused, as `MalformedProof`.
#[test]
fn a_call_proof_must_be_canonically_encoded() {
    let p = guests::private_payment(1000);
    let (proof, outputs, _) = shared();
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = record(&p);
    assert_eq!(ex.verify_call(&rec, proof).unwrap().outputs, *outputs, "the honest encoding passes");
    assert!(randprotocol_zkvm::executor::decode_canonical(proof).is_ok());

    let mut trailing = proof.clone();
    trailing.push(0);
    assert!(postcard::from_bytes::<randprotocol_zkvm::machine::Proof>(&trailing).is_ok(), "postcard alone accepts it");
    assert_eq!(ex.verify_call(&rec, &trailing), Err(ConfidentialError::MalformedProof));

    // `Proof.tier` is the first field, a `usize` varint; an honest tier is < 128, one byte.
    assert!(proof[0] < 0x80);
    let mut overlong = vec![proof[0] | 0x80, 0x00];
    overlong.extend_from_slice(&proof[1..]);
    let decoded = postcard::from_bytes::<randprotocol_zkvm::machine::Proof>(&overlong).expect("postcard alone accepts it");
    assert_eq!(decoded.to_bytes(), *proof, "the same proof, differently encoded");
    assert_eq!(ex.verify_call(&rec, &overlong), Err(ConfidentialError::MalformedProof));
}

/// The early reject (final review): a call whose declared public-table height is not the one the
/// record's `public_len` implies is refused as `PublicValues` before `Machine::verify`, so it builds
/// no verifier key.
#[test]
fn a_call_with_the_wrong_public_height_is_refused_before_verify() {
    use randprotocol_zkvm::machine::Machine;
    use randprotocol_zkvm::tables::public::public_log_height;
    let public = [11u32, 22, 33, 44];
    let f = guests::fib(10);
    let ex = ZkExecutor::new(FriProfile::Test);
    let with = ProgramRecord { public_digest: Some(ex.public_digest(&public)), public_len: public.len() as u32, ..record(&f) };
    assert_ne!(public_log_height(0), public_log_height(public.len()), "the test needs two height classes");
    let (empty, _) = Machine::new(FriProfile::Test).prove(&f, &[], &[], None).unwrap();
    assert_eq!(empty.public_log_height, public_log_height(0));
    let before = ex.cached_keys();
    assert_eq!(
        ex.verify_call(&with, &empty.to_bytes()),
        Err(ConfidentialError::InvalidProof("PublicValues".into()))
    );
    assert_eq!(ex.cached_keys(), before, "no verifier key was built for the refused call");
}

/// The program-height pin (deep scan 2026-09-24, zkvm): a call proof's `program_log_height` is
/// exactly what the prover derives from the deployed program's word count
/// (`program_log_height(record.words.len())`, `Machine::prove`), so any other declared height
/// is a proof over a different program table — refused before `Machine::verify`, which would
/// otherwise build (and cache, evicting an honest one) a verifier key for the junk height and
/// only then fail on the batch.
#[test]
fn a_call_with_the_wrong_program_height_is_refused_before_verify() {
    use randprotocol_zkvm::machine::Machine;
    use randprotocol_zkvm::tables::program::program_log_height;
    let f = guests::fib(10);
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = record(&f);
    let (mut proof, _) = Machine::new(FriProfile::Test).prove(&f, &[], &[], None).unwrap();
    assert_eq!(proof.program_log_height, program_log_height(rec.words.len()), "the prover's own rule");
    ex.verify_call(&rec, &proof.to_bytes()).expect("the honest header verifies");
    let before = ex.cached_keys();
    // One class up, with `degree_bits` edited to match (the program instance is first in
    // `chips()` order; `+ 1` is the hiding config's `is_zk`, already folded into the entry).
    proof.program_log_height += 1;
    proof.batch.degree_bits[0] += 1;
    let err = ex.verify_call(&rec, &proof.to_bytes()).expect_err("a different program table");
    assert!(matches!(err, ConfidentialError::InvalidProof(_)), "{err}");
    assert_eq!(ex.cached_keys(), before, "no verifier key was built for the refused call ({err})");
}

/// The input-height bound (same scan): a call's private-input width is unknown to the chain,
/// but it is bounded by the tier — every input word costs a quarter of a digest cycle, so at
/// tier `t` the input table never honestly exceeds `2^(t+2)` rows (`executor::
/// max_input_log_height`). A declaration past that is refused before any key is built.
#[test]
fn a_call_with_an_input_height_past_the_tiers_bound_is_refused_before_verify() {
    use randprotocol_zkvm::executor::max_input_log_height;
    use randprotocol_zkvm::machine::{Machine, Tier};
    let f = guests::fib(10);
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = record(&f);
    let (mut proof, _) = Machine::new(FriProfile::Test).prove(&f, &[], &[], Some(Tier(10))).unwrap();
    let bound = max_input_log_height(Tier(10));
    assert!(bound < randprotocol_zkvm::tables::input::MAX_LOG_HEIGHT, "the flat range alone would admit it");
    ex.verify_call(&rec, &proof.to_bytes()).expect("the honest header verifies");
    let before = ex.cached_keys();
    // The input instance is eighth in `chips()` order (program, cpu, memory, alu, range,
    // nibble, poseidon2, input, …).
    let delta = bound + 1 - proof.input_log_height;
    proof.input_log_height = bound + 1;
    proof.batch.degree_bits[7] += delta as usize;
    let err = ex.verify_call(&rec, &proof.to_bytes()).expect_err("past what tier 10 can read");
    assert!(matches!(err, ConfidentialError::InvalidProof(_)), "{err}");
    assert_eq!(ex.cached_keys(), before, "no verifier key was built for the refused call ({err})");
}

/// The tier cap (same scan, the load-bearing half): a legal tier-20 header — every range check
/// satisfiable from public data, `degree_bits` consistent — used to reach `Machine::verify`,
/// which built the tier-20 verifier key (216 s and 6.5 GB at the production profile) before
/// looking at a single byte of STARK data. A call above `MAX_CALL_TIER` is refused as
/// `CallTierTooHigh` before any key is built, in well under a second.
#[test]
fn a_call_declaring_a_tier_above_the_cap_is_refused_before_any_key_is_built() {
    use randprotocol_zkvm::executor::MAX_CALL_TIER;
    use randprotocol_zkvm::machine::{Machine, Tier};
    use randprotocol_zkvm::tables::cpu::pv;
    let f = guests::fib(10);
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = record(&f);
    let m = Machine::new(FriProfile::Test);
    let (mut proof, _) = m.prove(&f, &[], &[], None).unwrap();
    assert!(proof.tier.0 as u8 <= MAX_CALL_TIER, "fib(10) lands under the cap");
    let before = ex.cached_keys();
    // The header an attacker submits: tier 20, everything else honest and self-consistent —
    // the public value the tier check reads, the memory floor the range check demands, and the
    // degree bits `verify` compares.
    proof.tier = Tier(20);
    proof.public_values[pv::TIER] = 20;
    proof.mem_log_height = Tier(20).min_mem_log_height();
    proof.batch.degree_bits = m.log_ext_degrees_pub(
        proof.tier,
        proof.program_log_height,
        proof.input_log_height,
        proof.keccak_log_height,
        proof.sha256_log_height,
        proof.public_log_height,
        proof.mem_log_height,
    );
    let t = std::time::Instant::now();
    let err = ex.verify_call(&rec, &proof.to_bytes()).expect_err("tier 20 is above the cap");
    assert_eq!(err, ConfidentialError::CallTierTooHigh { tier: 20, max: MAX_CALL_TIER });
    assert_eq!(ex.cached_keys(), before, "no verifier key was built for the refused call");
    assert!(t.elapsed().as_secs() < 1, "refused in {:?}, not after a key build", t.elapsed());
}

/// And the honest side of the three pins: a real proof at its own tier, program height and
/// input height still verifies, building exactly its one key.
#[test]
fn an_honest_call_proof_still_verifies_under_the_header_pins() {
    use randprotocol_zkvm::machine::Machine;
    let f = guests::fib(10);
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = record(&f);
    let (proof, exec) = Machine::new(FriProfile::Test).prove(&f, &[], &[], None).unwrap();
    let out = ex.verify_call(&rec, &proof.to_bytes()).expect("honest");
    assert_eq!(out.outputs, exec.outputs);
    assert_eq!(out.tier, proof.tier.0 as u8);
    assert_eq!(ex.cached_keys(), 1, "the honest key, and only it");
}

/// The keccak cap (same scan, second half): the tier cap alone still admitted a tier-14 header
/// declaring `keccak_log_height = 19` (the tier's own honest bound), whose key is 2^19 rows of
/// 99 preprocessed columns — measured with the harness below at 209 s and 10 GB together with
/// the sha256 table's 2^20, worse than the tier-20 header the finding started from. A call's
/// keccak height is capped at `MAX_CALL_KECCAK_LOG_HEIGHT`, refused before any key is built.
#[test]
fn a_call_with_a_keccak_height_past_the_call_cap_is_refused_before_verify() {
    use randprotocol_zkvm::executor::MAX_CALL_KECCAK_LOG_HEIGHT;
    use randprotocol_zkvm::machine::{Machine, Tier};
    let p = guests::keccak_demo(b"hi");
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = record(&p);
    let m = Machine::new(FriProfile::Test);
    // Tier 12, so the tier's own bound (`klh <= t + 5`) admits the height the cap refuses.
    let (mut proof, _) = m.prove(&p, &[], &[], Some(Tier(12))).unwrap();
    assert_eq!(proof.keccak_log_height, 5, "one permutation fits the minimum block");
    let over = MAX_CALL_KECCAK_LOG_HEIGHT + 1;
    assert!(
        over <= Tier(12).max_keccak_log_height().min(randprotocol_zkvm::tables::keccak::MAX_LOG_HEIGHT),
        "the test needs a height only the call cap refuses"
    );
    ex.verify_call(&rec, &proof.to_bytes()).expect("the honest header verifies");
    let before = ex.cached_keys();
    proof.keccak_log_height = over;
    proof.batch.degree_bits = m.log_ext_degrees_pub(
        proof.tier,
        proof.program_log_height,
        proof.input_log_height,
        proof.keccak_log_height,
        proof.sha256_log_height,
        proof.public_log_height,
        proof.mem_log_height,
    );
    let err = ex.verify_call(&rec, &proof.to_bytes()).expect_err("past the call cap");
    assert!(matches!(err, ConfidentialError::InvalidProof(_)), "{err}");
    assert_eq!(ex.cached_keys(), before, "no verifier key was built for the refused call ({err})");
}

/// And the sha256 table's cap, `MAX_CALL_SHA256_LOG_HEIGHT`, on identical terms.
#[test]
fn a_call_with_a_sha256_height_past_the_call_cap_is_refused_before_verify() {
    use randprotocol_zkvm::executor::MAX_CALL_SHA256_LOG_HEIGHT;
    use randprotocol_zkvm::machine::{Machine, Tier};
    let p = guests::sha256_demo();
    let ex = ZkExecutor::new(FriProfile::Test);
    let rec = record(&p);
    let m = Machine::new(FriProfile::Test);
    let (mut proof, _) = m.prove(&p, &[], &[], Some(Tier(12))).unwrap();
    assert_eq!(proof.sha256_log_height, 6, "one compression fills the minimum block");
    let over = MAX_CALL_SHA256_LOG_HEIGHT + 1;
    assert!(over <= Tier(12).max_sha256_log_height(), "the test needs a height only the call cap refuses");
    ex.verify_call(&rec, &proof.to_bytes()).expect("the honest header verifies");
    let before = ex.cached_keys();
    proof.sha256_log_height = over;
    proof.batch.degree_bits = m.log_ext_degrees_pub(
        proof.tier,
        proof.program_log_height,
        proof.input_log_height,
        proof.keccak_log_height,
        proof.sha256_log_height,
        proof.public_log_height,
        proof.mem_log_height,
    );
    let err = ex.verify_call(&rec, &proof.to_bytes()).expect_err("past the call cap");
    assert!(matches!(err, ConfidentialError::InvalidProof(_)), "{err}");
    assert_eq!(ex.cached_keys(), before, "no verifier key was built for the refused call ({err})");
}

/// Measurement, not a check (`#[ignore]`d): builds one call verifier key at the *production*
/// profile and prints its wall time — run under `/usr/bin/time -l` for the peak RSS. The shape
/// comes from `RAND_KEY_SHAPE="tier,plh,ilh,klh,slh,pubh"`, so the worst admissible header under
/// `MAX_CALL_TIER` can be costed without proving anything (the deep scan's tier-20 number,
/// 216 s / 6.5 GB, was measured this way).
#[test]
#[ignore]
fn measure_a_call_verifier_key_build_at_the_production_profile() {
    use randprotocol_zkvm::machine::{Machine, Tier};
    let shapes = std::env::var("RAND_KEY_SHAPE").unwrap_or_else(|_| "14,14,3,0,0,2".into());
    let m = Machine::new(FriProfile::Production);
    // Several shapes separated by `;` are built in order in the one process, so the process's
    // peak RSS then also shows what the key cache *retains* per key, not only a build's peak.
    for shape in shapes.split(';') {
        let v: Vec<u8> = shape.split(',').map(|x| x.trim().parse().unwrap()).collect();
        assert_eq!(v.len(), 6, "tier,plh,ilh,klh,slh,pubh");
        let t = std::time::Instant::now();
        let _ = m.verifier_key(Tier(v[0] as usize), v[1], v[2], v[3], v[4], v[5]);
        println!("verifier key {shape}: {:.1?} ({} cached)", t.elapsed(), m.cached_keys());
    }
}
