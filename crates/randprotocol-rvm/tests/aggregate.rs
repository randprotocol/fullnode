//! The N-generic aggregate program (M5.3): one counted loop over the tape's N, each iteration
//! the per-proof pipeline with a fresh challenger, then the interface digest over
//! `[inner_vk_digest ‖ N ‖ 34·N]`. The differentials: N=1 is the single-proof program plus a
//! pinned loop overhead, and the thirteen segment tampers are refused at the M5.1 table's named
//! steps, verbatim, at `(proof, segment)`.

mod common;

use p3_field::PrimeCharacteristicRing;
use randprotocol_zkvm::machine::{FriProfile, Proof};
use randprotocol_zkvm::tables::cpu::pv;
use randprotocol_rvm::aggregate::{
    aggregate, aggregate_program, verify_aggregate, AggregateError, AggregateProof,
    InnerVerifierKey, VerifyAggregateError,
};
use randprotocol_rvm::dsl::Checkpoints;
use randprotocol_rvm::emulator::{execute, ExecError};
use randprotocol_rvm::isa::F;
use randprotocol_rvm::machine::{Machine as RvmMachine, Tier as RvmTier};
use randprotocol_rvm::programs::{aggregate_program_digest, verify_rv32, verify_rv32n};
use randprotocol_rvm::shape::{InnerKey, InnerShape};
use randprotocol_rvm::witness::{Segment, WitnessTape};

const MAX_CYCLES: usize = 1 << 24;

/// The rows the counted loop and the runtime-length interface sponge cost over the single-proof
/// program at N=1, measured on this tree: the count word and its guard, the sponge state and
/// cursor, the per-proof 34-word staged absorb (with its eight rate-fill permutations), the
/// final partial-block permutation, and the loop scaffolding — against the single-proof phase
/// 8's list build and one-shot `sponge_seeded` it replaces.
const LOOP_OVERHEAD: usize = 139;

/// The N=3 total, measured on this tree. The per-N total is *not* a clean multiple of the
/// per-proof rows: the staged absorb permutes when the rate fills, and the fill phase advances
/// by two lanes per proof (34 mod 4), so an odd-numbered iteration permutes nine times where an
/// even one permutes eight — the per-N rows are `pre + Σ body_j + post` with the parity term,
/// pinned per N rather than modelled.
const N3_ROWS: usize = 1_324_694;

fn shape_and_key(p: &Proof) -> (InnerShape, InnerKey) {
    let shape = InnerShape::of(
        FriProfile::Test,
        p.tier,
        p.program_log_height,
        p.input_log_height,
        p.keccak_log_height,
        p.sha256_log_height,
        p.public_log_height,
        p.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Test, &shape);
    (shape, key)
}

/// The N=1 differential: the looped program over one fixture proof accepts, publishes exactly
/// the single-proof program's interface digest, and costs the single-proof rows plus the pinned
/// loop overhead.
#[test]
fn n1_aggregate_publishes_the_single_proof_digest_at_a_pinned_overhead() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);

    let single_vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let single_tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let single_exec = execute(&single_vp.program, &single_tape.words, MAX_CYCLES).unwrap();

    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape =
        WitnessTape::build_n(FriProfile::Test, &shape, &key, std::slice::from_ref(&p.proof))
            .unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES)
        .expect("the looped program accepts one real proof");

    assert_eq!(
        exec.public, single_exec.public,
        "N=1 publishes exactly the single-proof program's interface digest"
    );
    let words =
        randprotocol_rvm::public_values::interface_words(&shape, &key, &[p.proof.public_values.clone()]);
    assert_eq!(
        exec.public,
        randprotocol_rvm::public_values::public_digest(&words).to_vec(),
        "and that digest is the host's §4.4 construction, exactly"
    );
    assert_eq!(
        exec.cpu_rows(),
        single_exec.cpu_rows() + LOOP_OVERHEAD,
        "the loop costs the single-proof rows plus the pinned overhead"
    );
}

/// Three real proofs, one looped run: accepted, and the published digest is the host's
/// `[vk ‖ 3 ‖ 34·3]` list — the staged absorb's two rate-fill parities both exercised.
#[test]
fn n3_aggregate_publishes_the_host_interface_digest() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 3).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &proofs).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES)
        .expect("the looped program accepts three real proofs");

    let pvs: Vec<Vec<u64>> = proofs.iter().map(|p| p.public_values.clone()).collect();
    let words = randprotocol_rvm::public_values::interface_words(&shape, &key, &pvs);
    assert_eq!(
        exec.public,
        randprotocol_rvm::public_values::public_digest(&words).to_vec(),
        "the looped program's digest is the host's §4.4 list over three proofs"
    );
    assert_eq!(exec.cpu_rows(), N3_ROWS, "the N=3 row count is pinned");
}

/// The loop-invariant test: the replay's `LoopEnd` check — every handle that existed before the
/// loop must end it with the allocation it started with — does not fire for the looped program.
/// Building is the test: a violation panics here, at build time, naming the handle.
#[test]
fn the_looped_program_builds_under_the_replays_loop_invariant() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let _ = verify_rv32n(&shape, &key, Checkpoints::Off);
}

/// What the fullnode registers: one digest per inner shape, deterministic, and not the
/// single-proof program's.
#[test]
fn the_aggregate_program_digest_is_deterministic_and_distinct() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let d1 = aggregate_program_digest(&shape, &key);
    let d2 = aggregate_program_digest(&shape, &key);
    assert_eq!(d1, d2, "rebuilding the program reproduces its digest");
    let single = verify_rv32(&shape, &key, Checkpoints::Off).program.digest();
    assert_ne!(d1, single, "the aggregate program is not the single-proof program");
}

/// A tape whose count word is zero is refused at a named step — the counted loop's `n >= 1`
/// precondition enforced in-program, before any proof is read.
#[test]
fn an_empty_aggregate_is_refused_at_the_count_word() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &[]).unwrap();
    match execute(&vp.program, &tape.words, MAX_CYCLES) {
        Err(ExecError::InverseOfZero { pc }) => assert_eq!(
            vp.program.checkpoint_at(pc),
            Some("aggregate count"),
            "the empty aggregate is refused at the count word's guard"
        ),
        other => panic!("expected the count-word refusal, got {other:?}"),
    }
}

/// A count word that overstates the proofs on the tape runs the loop off the tape's end.
#[test]
fn an_overstated_count_runs_off_the_tape() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let mut tape =
        WitnessTape::build_n(FriProfile::Test, &shape, &key, std::slice::from_ref(&p.proof))
            .unwrap();
    tape.words[0] += F::ONE;
    match execute(&vp.program, &tape.words, MAX_CYCLES) {
        Err(ExecError::HintExhausted { .. }) => {}
        other => panic!("an overstated count must run off the tape, got {other:?}"),
    }
}

// ── the tamper differential ──────────────────────────────────────────────────────────────────
// M5.1's table, verbatim (`tests/exit.rs`'s, with its measured deviations), reused at
// `(proof, segment)`: the looped program must refuse the same word at the same named step.

fn tamper_table() -> Vec<(Segment, &'static str)> {
    vec![
        (Segment::Header, "header word 0"),                 // see expected_step: dynamic suffix
        (Segment::PublicValues, "quotient identity[0]"),
        (Segment::Commitments, "quotient identity[0]"),
        (Segment::LookupTerminals, "lookup terminal sum"),
        (Segment::OpenedValues, "quotient identity[0]"),
        (Segment::RandomOpenings, "sample_bits decomposition"),
        (Segment::FriCommits, "sample_bits decomposition"),
        (Segment::FinalPoly, "sample_bits decomposition"),
        (Segment::QueryPow, "sample_bits decomposition"),
        (Segment::InputOpenings, "input opening root[random]"),
        (Segment::InputPaths, "input opening root[random]"),
        (Segment::CommitPhaseOpenings, "commit phase root[0]"), // see expected_step: dynamic round
        (Segment::CommitPhasePaths, "commit phase root[0]"),
    ]
}

/// The refusal step expected for a tamper of `seg` at segment offset `off`, given the shape —
/// `tests/exit.rs`'s, verbatim.
fn expected_step(seg: Segment, off: usize, shape: &InnerShape) -> String {
    match seg {
        Segment::Header => format!("header word {off}"),
        Segment::CommitPhaseOpenings => {
            let strides: Vec<usize> = shape
                .log_arities
                .iter()
                .map(|&la| ((1usize << la) - 1) * 2 + randprotocol_rvm::witness::SALT_ELEMS)
                .collect();
            let query_stride: usize = strides.iter().sum();
            let mut at = off % query_stride;
            for (r, &s) in strides.iter().enumerate() {
                if at < s {
                    return format!("commit phase root[{r}]");
                }
                at -= s;
            }
            unreachable!("the offset is inside a query's run");
        }
        _ => tamper_table().into_iter().find(|(s, _)| *s == seg).unwrap().1.to_string(),
    }
}

/// One word corrupted in proof `j`'s region of an N-proof tape must be refused at the named
/// step — the loop gives every proof the single-proof program's checks, iteration `j` included.
fn refuse_at(profile: FriProfile, proofs: &[Proof], j: usize, seg: Segment, off_seed: usize) {
    let (shape, key) = shape_and_key(&proofs[0]);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let mut tape = WitnessTape::build_n(profile, &shape, &key, proofs).unwrap();
    let r = *tape
        .segment_refs()
        .iter()
        .find(|r| r.proof == j && r.segment == seg)
        .unwrap_or_else(|| panic!("proof {j} has a {seg:?} segment"));
    assert!(r.len > 0, "{seg:?} is empty");
    let off = off_seed % r.len;
    let want_step = expected_step(seg, off, &shape);
    tape.words[r.start + off] += F::ONE;
    match execute(&vp.program, &tape.words, MAX_CYCLES) {
        Err(ExecError::InverseOfZero { pc }) => assert_eq!(
            vp.program.checkpoint_at(pc),
            Some(want_step.as_str()),
            "proof {j}, tampered {seg:?}: refused at the wrong step"
        ),
        other => panic!("proof {j}, tampered {seg:?}: expected a refusal, got {other:?}"),
    }
}

/// The thirteen segment tampers, each on its own fixture's N=1 tape — `(0, segment)`, the
/// single-proof table exactly.
#[test]
fn thirteen_tampered_proofs_are_refused_at_the_named_steps() {
    let table = tamper_table();
    let proofs: Vec<Proof> = common::bundle_proofs(FriProfile::Test, table.len())
        .into_iter()
        .map(|p| p.proof)
        .collect();
    for (k, (seg, _)) in table.iter().enumerate() {
        refuse_at(FriProfile::Test, std::slice::from_ref(&proofs[k]), 0, *seg, k);
    }
}

/// The same table's killers land in later iterations too: iteration 0 completing first changes
/// nothing about how iteration `j` refuses its own tampered proof.
#[test]
fn tampers_in_later_iterations_are_refused_at_the_named_steps() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 3).into_iter().map(|p| p.proof).collect();
    refuse_at(FriProfile::Test, &proofs, 1, Segment::OpenedValues, 0);
    refuse_at(FriProfile::Test, &proofs, 2, Segment::Commitments, 1);
    refuse_at(FriProfile::Test, &proofs, 2, Segment::Header, 3);
    refuse_at(FriProfile::Test, &proofs, 1, Segment::LookupTerminals, 0);
}

// ── Task 3: the chain-facing API ─────────────────────────────────────────────────────────────

fn inner_vk(shape: &InnerShape, key: &InnerKey) -> InnerVerifierKey {
    InnerVerifierKey { shape: shape.clone(), key: key.clone() }
}

/// (a) an aggregate of one fixture proof round-trips — `aggregate` → `verify_aggregate` → the
/// bundle's `OUT0..7`; (d) one word of the §4.4 list edited fails `verify_aggregate` with
/// `DigestMismatch` even though the proof itself is untouched; (b) the rVM proof's declared tier
/// bumped — bytes otherwise honest — fails at `Machine::verify`, past a digest check that still
/// passes. One prove covers all three.
#[test]
fn a_one_proof_aggregate_round_trips_and_tampered_variants_are_refused() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    let a = aggregate(&m, &vk, std::slice::from_ref(&p.proof), None)
        .expect("one real bundle proof aggregates");
    assert_eq!(a.proof.tier, RvmTier(19), "the test-profile N=1 aggregate lands at tier 19");
    eprintln!("N=1 aggregate proof: {} bytes", a.proof.size());
    let program = aggregate_program(&vk);
    let outs = verify_aggregate(&m, &program, &a).expect("the aggregate verifies");
    let want: [u32; 8] =
        std::array::from_fn(|k| u32::try_from(p.proof.public_values[pv::OUT0 + k]).unwrap());
    assert_eq!(outs, vec![want], "the covered bundle's OUT0..7, in proof order");

    // (`machine::Proof` is serde-only, so the forged handles are postcard round-trips, the
    // fixture cache's own move.)
    let bytes = a.proof.to_bytes();

    // (d): one word of the §4.4 list edited — the proof itself untouched.
    let proof2: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).unwrap();
    let mut forged = AggregateProof { proof: proof2, public: a.public.clone() };
    forged.public[5 + pv::OUT0] += F::ONE;
    match verify_aggregate(&m, &program, &forged) {
        Err(VerifyAggregateError::DigestMismatch) => {}
        other => panic!("a tampered public list must fail the digest check, got {other:?}"),
    }

    // (b): the rVM proof's declared tier bumped — `check_declared_heights`/`degree_bits`'s
    // refusal, exactly the chain's `Machine::verify` rejecting a tampered aggregate.
    let mut proof3: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).unwrap();
    proof3.tier = RvmTier(proof3.tier.0 + 1);
    let forged = AggregateProof { proof: proof3, public: a.public.clone() };
    match verify_aggregate(&m, &program, &forged) {
        Err(VerifyAggregateError::Verify(_)) => {}
        other => panic!("a tampered aggregate must fail Machine::verify, got {other:?}"),
    }
}

/// (b) an empty set is `AggregateError::Empty`, before any work.
#[test]
fn an_empty_set_is_refused_before_any_work() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    assert!(matches!(aggregate(&m, &vk, &[], None), Err(AggregateError::Empty)));
}

/// (c) a wrong-shape proof in the set is `AggregateError::WrongShape { index }`, checked for the
/// whole set before any tape work — here at index 1, so index 0's match is not what stops it.
#[test]
fn a_wrong_shape_proof_in_the_set_is_named_by_index_before_any_tape_work() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 2).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    let mut set = proofs;
    set[1].input_log_height += 1; // no longer the key's shape
    match aggregate(&m, &vk, &set, None) {
        Err(AggregateError::WrongShape { index }) => assert_eq!(index, 1),
        Err(e) => panic!("expected WrongShape at index 1, got {e:?}"),
        Ok(_) => panic!("expected WrongShape at index 1, got an aggregate"),
    }
}

// ── Task 4: the refusal suite, the in-suite aggregate, and the N=3 twin ──────────────────────

/// (a) an inner proof tampered inside the set makes `aggregate` fail — never an aggregate. The
/// tamper is one of the 34 public values of proof 1: `matches` still passes (length and
/// canonicality are all it checks), so the refusal lands in the tape builder's transcript
/// replay, where the native verifier's own checks run.
#[test]
fn a_tampered_inner_proof_never_yields_an_aggregate() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 2).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    let mut set = proofs;
    set[1].public_values[pv::OUT0] += 1; // still 34 canonical words; no longer its transcript
    match aggregate(&m, &vk, &set, None) {
        Err(AggregateError::Tape(_)) => {}
        Err(e) => panic!("a tampered inner proof must fail at the tape replay, got {e:?}"),
        Ok(_) => panic!("a tampered inner proof must never yield an aggregate"),
    }
}

/// (a′) the same M5.1-table tamper, one level down: the tape itself corrupted at
/// `(proof 1, Segment::OpenedValues)` makes the *prove* fail — the program's named refusal
/// escalated to `ProveError::Exec`, which is what `AggregateError::Prove` exists to carry.
#[test]
fn a_tampered_tape_fails_the_prove_at_the_named_step() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 2).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let mut tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &proofs).unwrap();
    let r = *tape
        .segment_refs()
        .iter()
        .find(|r| r.proof == 1 && r.segment == Segment::OpenedValues)
        .unwrap();
    tape.words[r.start] += F::ONE;
    let program = verify_rv32n(&shape, &key, Checkpoints::Off);
    let m = RvmMachine::new(FriProfile::Test);
    match m.prove(&program.program, &tape.words, None) {
        Err(randprotocol_rvm::machine::ProveError::Exec(ExecError::InverseOfZero { pc })) => {
            assert_eq!(
                program.program.checkpoint_at(pc),
                Some("quotient identity[0]"),
                "the prove fails at the tamper's named step"
            );
        }
        Err(e) => panic!("expected ProveError::Exec at quotient identity[0], got {e:?}"),
        Ok(_) => panic!("expected ProveError::Exec at quotient identity[0], got a proof"),
    }
}

/// (e) the in-suite aggregate: two real test-profile bundle proofs prove and verify natively —
/// tier 20 on this fixture shape. `#[ignore]`d after two jetsam deaths on the shared box: the
/// prove peaks above the box's practical line (~33 GB today; 33.7 GB measured before the
/// SIGKILL, twice), so the suite's heaviest *proven* aggregate is the N=1 round-trip at tier 19,
/// and this runs alone, watchdog-guarded, the way the twin does.
#[test]
#[ignore = "the N=2 in-suite aggregate: tier 20, ~34 GB peak observed before jetsam on the \
            shared box (twice); run alone: cargo test --release -p recursion --test aggregate \
            two_test_profile -- --ignored --nocapture"]
fn two_test_profile_bundle_proofs_aggregate_and_verify_natively() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 2).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    let a = aggregate(&m, &vk, &proofs, None).expect("two real bundle proofs aggregate");
    assert_eq!(a.proof.tier, RvmTier(20), "the test-profile N=2 aggregate lands at tier 20");
    eprintln!("N=2 aggregate proof: {} bytes", a.proof.size());
    let outs = verify_aggregate(&m, &aggregate_program(&vk), &a).expect("the aggregate verifies");
    assert_eq!(outs.len(), 2);
    for (j, out) in outs.iter().enumerate() {
        let want: [u32; 8] = std::array::from_fn(|k| {
            u32::try_from(proofs[j].public_values[pv::OUT0 + k]).unwrap()
        });
        assert_eq!(*out, want, "bundle {j}'s OUT0..7");
    }
}

/// The M5.3 exit (spec §7, R4's profile ruling): an aggregate of **3 real test-profile bundle
/// proofs** verifies natively — tier 21, ~38 GB on this tree's prover (the tier-20 prove's
/// measured peak is 33.7 GB). Timed and measured: wall time, proof size, verify time; the RSS
/// watchdog runs outside the process (see the ignore note). On a box that jetsams the largest
/// process at ~33 GB the attempt is expected to die there — the peak it reaches is the
/// measurement, and the plan's fallback records N=1 (tier 19, completed) as the in-scope proof.
#[test]
#[ignore = "the N=3 exit twin: tier 21, ~38 GB, est. ~2-4 h contended; watchdog-guarded; \
            run alone: cargo test --release -p recursion --test aggregate twin -- --ignored --nocapture"]
fn twin_three_test_profile_bundle_proofs_aggregate_and_verify_natively() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 3).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    let t0 = std::time::Instant::now();
    let a = aggregate(&m, &vk, &proofs, None).expect("three real bundle proofs aggregate");
    let prove_s = t0.elapsed().as_secs_f64();
    assert_eq!(a.proof.tier, RvmTier(21), "the test-profile N=3 aggregate lands at tier 21");
    let t1 = std::time::Instant::now();
    let outs = verify_aggregate(&m, &aggregate_program(&vk), &a).expect("the aggregate verifies");
    let verify_s = t1.elapsed().as_secs_f64();
    assert_eq!(outs.len(), 3);
    eprintln!(
        "M5.3 exit twin: N=3 test profile — prove {prove_s:.1} s, verify {verify_s:.2} s, \
         proof {} bytes",
        a.proof.size()
    );
}

// ── Task 6: the fullnode admission stub's test vectors ───────────────────────────────────────

fn hex_words(words: &[F]) -> String {
    use p3_field::PrimeField64;
    words
        .iter()
        .map(|w| format!("{:016x}", w.as_canonical_u64()))
        .collect::<Vec<_>>()
        .join("")
}

/// The pinned vectors for the fullnode-side admission stub (`docs/02-aggregate.md`): for the
/// 3-proof test-profile fixture set, the expected `inner_vk_digest`, the interface list, and
/// the interface digest. The vk digest is a constant of the fixture shape — the bundle program,
/// the input sizes and the tier are data-independent, so a regenerated fixture cache reproduces
/// it — and that half is pinned here; the list and its digest ride on the fixtures' random
/// notes, recomputed from the live cache and printed for the doc's worked example.
#[test]
fn the_admission_stub_vectors() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 3).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vk_digest = randprotocol_rvm::shape::inner_vk_digest(&shape, &key);
    assert_eq!(
        hex_words(&vk_digest),
        "33a94ec690bb7cbe5a3d4564967460996277ac61b539f6525b5fe7f92992a1c8",
        "the inner vk digest is a deterministic constant of the fixture shape"
    );
    let pvs: Vec<Vec<u64>> = proofs.iter().map(|p| p.public_values.clone()).collect();
    let list = randprotocol_rvm::public_values::interface_words(&shape, &key, &pvs);
    assert_eq!(list.len(), 4 + 1 + 34 * 3);
    let digest = randprotocol_rvm::public_values::public_digest(&list);
    eprintln!("inner_vk_digest: {}", hex_words(&vk_digest));
    eprintln!("interface list ({} words), hex: {}", list.len(), hex_words(&list));
    for (i, w) in list.iter().enumerate() {
        eprintln!("  [{i:3}] {w:?}");
    }
    eprintln!("interface digest: {}", hex_words(&digest));
}

// ── Task 5: the per-N cycle budget, pinned ───────────────────────────────────────────────────

/// The per-N budget test: rows = `N × per-proof rows + loop overhead`, pinned per N in
/// `tests/pins.json` — and N=1's pin equals the single-proof rows plus Task 2's recorded loop
/// overhead, measured live here, so the two pins must agree exactly. That agreement is what
/// makes the loop's cost a measured number rather than a guess.
#[test]
fn the_per_n_cycle_budget_is_pinned() {
    let pins = common::aggregate_pins();
    for (i, &want) in pins.cpu_rows.iter().enumerate() {
        let r = common::measure_aggregate(i + 1, FriProfile::Test);
        assert_eq!(r.cpu_rows, want, "N={} cpu rows", i + 1);
        assert_eq!(r.permutations, pins.permutations[i], "N={} permutations", i + 1);
        assert_eq!(r.mem_accesses, pins.mem_accesses[i], "N={} mem accesses", i + 1);
        assert_eq!(r.witness_words, pins.witness_words[i], "N={} witness words", i + 1);
    }
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let single_vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let single_tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let single_rows = execute(&single_vp.program, &single_tape.words, MAX_CYCLES)
        .unwrap()
        .cpu_rows();
    assert_eq!(
        pins.cpu_rows[0],
        single_rows + LOOP_OVERHEAD,
        "the N=1 pin equals the single-proof rows plus Task 2's measured loop overhead"
    );
}

/// The production N=1 aggregate, re-confirmed against the M5.2 single-proof pin: the loop
/// overhead at the production shape (its `log_arities` schedule differs from the test profile's,
/// so the overhead is not assumed equal — it is measured) and the tier-21 landing, recorded in
/// `docs/02-aggregate.md`.
#[test]
#[ignore = "a production-profile fixture proof plus a ~2M-row emulation: the M5.2 budget test's own cost class"]
fn the_production_n1_aggregate_is_the_m52_pin_plus_loop_overhead() {
    let p = common::bundle_proofs(FriProfile::Production, 1).pop().unwrap();
    let shape = InnerShape::of(
        FriProfile::Production,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height,
        p.proof.public_log_height,
        p.proof.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Production, &shape);
    let single_vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let single_tape = WitnessTape::build(FriProfile::Production, &shape, &key, &p.proof).unwrap();
    let single_rows = execute(&single_vp.program, &single_tape.words, MAX_CYCLES)
        .unwrap()
        .cpu_rows();
    assert_eq!(single_rows, common::pins().cpu_rows, "the M5.2 pin still holds");
    let r = common::measure_aggregate(1, FriProfile::Production);
    eprintln!(
        "production N=1 aggregate: {} rows (single {single_rows}, overhead {})",
        r.cpu_rows,
        r.cpu_rows - single_rows
    );
}
