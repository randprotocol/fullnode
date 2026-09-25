//! The self-verifier's emulator differential (M5.4 Task 5): `verify_rv32r` accepts a real rVM
//! proof — the cheating suite's table-covering toy program, proven at the suite's smallest
//! tier — and refuses M5.1's tamper table at the same named steps, verbatim. The fixtures are
//! produced in-test at small tiers; the measured requirement lives in `docs/03`.

mod common;

use p3_field::PrimeCharacteristicRing;
use randprotocol_rvm::dsl::Checkpoints;
use randprotocol_rvm::emulator::{execute, ExecError};
use randprotocol_rvm::isa::{F, Instr, Op, Program};
use randprotocol_rvm::machine::{FriProfile, Machine, Tier};
use randprotocol_rvm::programs::{self_program_digest, verify_rv32, verify_rv32r};
use randprotocol_rvm::shape::{InnerKey, InnerShape, RvmKey, RvmShape, VerifierShape};
use randprotocol_rvm::witness::{Segment, WitnessTape};
use std::sync::Arc;

const MAX_CYCLES: usize = 1 << 24;

fn i(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}
fn ir(op: Op, rd: u8, ra: u8, rb: u8) -> Instr {
    i(op, rd, ra, rb as u64)
}

/// `tests/cheating.rs`'s honest setup, verbatim: one program touching every table.
fn toy_program() -> Program {
    Program {
        instrs: vec![
            i(Op::Faddi, 1, 0, 7),
            i(Op::Faddi, 2, 0, 5),
            ir(Op::Fadd, 3, 1, 2),
            i(Op::Inv, 4, 3, 0),
            i(Op::Faddi, 5, 0, 100),
            i(Op::Store, 2, 5, 3),
            i(Op::Load, 6, 5, 3),
            i(Op::Faddi, 7, 0, 64),
            i(Op::Store, 1, 7, 0),
            i(Op::Store, 2, 7, 1),
            i(Op::Poseidon2, 0, 7, 0),
            i(Op::Load, 8, 7, 0),
            i(Op::Public, 0, 3, 0),
            i(Op::Public, 0, 6, 0),
            i(Op::Public, 0, 8, 0),
            i(Op::Public, 0, 4, 0),
            i(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
    }
}

/// One real rVM proof of the toy program at tier 8, with the shape and key it verifies under.
fn fixture() -> (Arc<Program>, randprotocol_rvm::machine::Proof, RvmShape, RvmKey) {
    let program = Arc::new(toy_program());
    let m = Machine::new(FriProfile::Test);
    let (proof, _exec) = m.prove(&program, &[], None).expect("the toy program proves");
    let shape = RvmShape::of(
        FriProfile::Test,
        &program,
        proof.tier,
        proof.reg_log_height,
        proof.ram_log_height,
        proof.poseidon2_log_height,
        proof.reduce_log_height,
    );
    let key = RvmKey::of(FriProfile::Test, &shape);
    (program, proof, shape, key)
}

/// The acceptance half of the differential: the self-verifier consumes a real rVM proof and
/// publishes exactly the host's interface digest over `[rvm_vk_digest ‖ 1 ‖ B(8) ‖ 4]`.
#[test]
fn the_self_verifier_accepts_a_real_rvm_proof() {
    let (_program, proof, shape, key) = fixture();
    let vp = verify_rv32r(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_for_with_binding(FriProfile::Test, &shape, &key, &proof, &common::TEST_BINDING).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES)
        .expect("the self-verifier accepts a real rVM proof");
    let words = randprotocol_rvm::public_values::interface_words_bound(
        &shape,
        &key,
        &common::TEST_BINDING,
        &[proof.public_values.clone()],
    );
    assert_eq!(
        exec.public,
        randprotocol_rvm::public_values::public_digest(&words).to_vec(),
        "the interface digest over [rvm_vk_digest ‖ 1 ‖ the binding ‖ the proof's four public values], exactly"
    );
}

/// A proof of another shape is refused at the replay's shape check — here, a `ram_log_height`
/// one taller than the fixture's.
#[test]
fn a_wrong_shape_proof_is_refused() {
    let (program, proof, _shape, _key) = fixture();
    let wrong = RvmShape::of(
        FriProfile::Test,
        &program,
        proof.tier,
        proof.reg_log_height,
        proof.ram_log_height + 1,
        proof.poseidon2_log_height,
        proof.reduce_log_height,
    );
    let wrong_key = RvmKey::of(FriProfile::Test, &wrong);
    let err = WitnessTape::build_for(FriProfile::Test, &wrong, &wrong_key, &proof)
        .expect_err("a proof of another shape must be refused");
    assert_eq!(err, randprotocol_rvm::witness::TapeError::Replay(randprotocol_rvm::reference::ReplayError::Shape));
}

/// What a chain registering the self-verifier pins: one digest per rVM shape, deterministic,
/// and not the aggregate program's.
#[test]
fn the_self_program_digest_is_deterministic_and_distinct() {
    let (program, proof, shape, key) = fixture();
    let d1 = self_program_digest(&shape, &key);
    let d2 = self_program_digest(&shape, &key);
    assert_eq!(d1, d2, "rebuilding the self-verifier reproduces its digest");

    // And it is not the single-proof RV32-machine verifier's digest for the same profile: build
    // one bundle-shaped verifier and compare (the fixture is cached, the build is cheap).
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let rv32_shape = InnerShape::of(
        FriProfile::Test,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height,
        p.proof.public_log_height,
        p.proof.mem_log_height,
    );
    let rv32_key = InnerKey::of(FriProfile::Test, &rv32_shape);
    let rv32_digest = verify_rv32(&rv32_shape, &rv32_key, Checkpoints::Off).program.digest();
    assert_ne!(d1, rv32_digest, "the self-verifier is not the RV32-machine verifier");
    let _ = (program, proof);
}

// ── the tamper differential ──────────────────────────────────────────────────────────────────
// M5.1's table, verbatim (`tests/exit.rs`'s, with its measured deviations), reused at
// `(proof 0, segment)`: the self-verifier must refuse the same word at the same named step.

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

/// The refusal step expected for a tamper of `seg` at segment offset `off`, given the rVM
/// shape — `tests/exit.rs`'s, verbatim, over `RvmShape`'s own arity schedule.
fn expected_step(seg: Segment, off: usize, shape: &RvmShape) -> String {
    match seg {
        Segment::Header => format!("header word {off}"),
        Segment::CommitPhaseOpenings => {
            let strides: Vec<usize> = shape
                .log_arities()
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

/// The thirteen segment tampers, each at `(proof 0, segment)` of the one fixture proof's tape —
/// refused at the named step, exactly as the RV32-machine verifier refuses them.
#[test]
fn thirteen_tampered_rvm_proofs_are_refused_at_the_named_steps() {
    let (_program, proof, shape, key) = fixture();
    let vp = verify_rv32r(&shape, &key, Checkpoints::Off);
    for (k, (seg, _)) in tamper_table().iter().enumerate() {
        let mut tape = WitnessTape::build_for_with_binding(FriProfile::Test, &shape, &key, &proof, &common::TEST_BINDING).unwrap();
        let r = *tape
            .segment_refs()
            .iter()
            .find(|r| r.proof == 0 && r.segment == *seg)
            .unwrap_or_else(|| panic!("the tape has a {seg:?} segment"));
        assert!(r.len > 0, "{seg:?} is empty");
        let off = k % r.len;
        let want_step = expected_step(*seg, off, &shape);
        tape.words[r.start + off] += F::ONE;
        match execute(&vp.program, &tape.words, MAX_CYCLES) {
            Err(ExecError::InverseOfZero { pc }) => assert_eq!(
                vp.program.checkpoint_at(pc),
                Some(want_step.as_str()),
                "tampered {seg:?}: refused at the wrong step"
            ),
            other => panic!("tampered {seg:?}: expected a refusal, got {other:?}"),
        }
    }
}

/// The M5.2-exit-shape anchor the measured requirement hangs from: the self-verifier's rows
/// are data-independent, so one fixture's rows are every same-shape proof's rows (the exit
/// test's own straight-line argument).
#[test]
fn the_self_verifier_is_straight_line_in_the_proofs_data() {
    let (_p1, proof1, shape, key) = fixture();
    let (_p2, proof2, shape2, key2) = fixture();
    assert_eq!(shape, shape2, "the fixture is one shape (the toy program's proof is deterministic in size)");
    let vp = verify_rv32r(&shape, &key, Checkpoints::Off);
    let rows: Vec<usize> = [proof1, proof2]
        .iter()
        .map(|proof| {
            let tape = WitnessTape::build_for_with_binding(FriProfile::Test, &shape, &key, proof, &common::TEST_BINDING).unwrap();
            execute(&vp.program, &tape.words, MAX_CYCLES).unwrap().cpu_rows()
        })
        .collect();
    assert_eq!(rows[0], rows[1], "the program is straight-line in the proof's data");
    let _ = key2;
    let _ = Tier(8);
}

// ── Task 6: the measured requirement ─────────────────────────────────────────────────────────

/// A busier program for the scaling's second measured point: ~2^11 stores to distinct cells
/// (a tall RAM table), a stretch of permutations, and the four published words — same chip set,
/// different declared heights than the toy's, at tier 12.
fn busy_program() -> Program {
    let mut instrs = vec![
        i(Op::Faddi, 1, 0, 1),          // r1 = 1 (the stored value)
        i(Op::Faddi, 2, 0, 64),         // r2 = 64 (the cursor)
    ];
    // 2^11 stores: mem[64 + k] = 1, then the cursor += 1.
    for _ in 0..(1 << 11) {
        instrs.push(i(Op::Store, 1, 2, 0));
        instrs.push(i(Op::Faddi, 2, 2, 1));
    }
    // 64 permutations over cells 64..71.
    for _ in 0..64 {
        instrs.push(i(Op::Faddi, 7, 0, 64));
        instrs.push(i(Op::Poseidon2, 0, 7, 0));
    }
    instrs.push(i(Op::Load, 3, 2, 0));
    instrs.push(i(Op::Public, 0, 1, 0));
    instrs.push(i(Op::Public, 0, 1, 0));
    instrs.push(i(Op::Public, 0, 1, 0));
    instrs.push(i(Op::Public, 0, 1, 0));
    instrs.push(i(Op::Halt, 0, 0, 0));
    Program { instrs, checkpoints: vec![] }
}

fn busy_fixture() -> (Arc<Program>, randprotocol_rvm::machine::Proof, RvmShape, RvmKey) {
    let program = Arc::new(busy_program());
    let m = Machine::new(FriProfile::Test);
    let (proof, _exec) = m.prove(&program, &[], None).expect("the busy program proves");
    let shape = RvmShape::of(
        FriProfile::Test,
        &program,
        proof.tier,
        proof.reg_log_height,
        proof.ram_log_height,
        proof.poseidon2_log_height,
        proof.reduce_log_height,
    );
    let key = RvmKey::of(FriProfile::Test, &shape);
    (program, proof, shape, key)
}

/// The self-verifier's cost at two measured points (the toy at tier 8, the busy program at its
/// own small tier), reported as `CycleReport`s: the numbers the production requirement's
/// derivation is anchored to in `docs/03`. Pinned loosely (a build-time statement of the
/// program, not a constant of the box): exact equality is required against the recorded values
/// only because the program is straight-line and deterministic in structure — any code change
/// that moves them is a deliberate re-measurement.
#[test]
fn the_self_verifiers_measured_cost_at_two_fixture_shapes() {
    let (_p, proof, shape, key) = fixture();
    let vp = verify_rv32r(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_for_with_binding(FriProfile::Test, &shape, &key, &proof, &common::TEST_BINDING).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES).unwrap();
    let r = randprotocol_rvm::programs::cycle_report(&vp, &exec);
    eprintln!("TOY_TIER8 {r:?}");
    assert_eq!(exec.hints_read, tape.len(), "the program consumes the whole tape");

    let (_pb, proof_b, shape_b, key_b) = busy_fixture();
    let vp_b = verify_rv32r(&shape_b, &key_b, Checkpoints::Off);
    let tape_b = WitnessTape::build_for_with_binding(FriProfile::Test, &shape_b, &key_b, &proof_b, &common::TEST_BINDING).unwrap();
    let exec_b = execute(&vp_b.program, &tape_b.words, MAX_CYCLES).unwrap();
    let rb = randprotocol_rvm::programs::cycle_report(&vp_b, &exec_b);
    eprintln!("BUSY {rb:?}");
    assert_eq!(exec_b.hints_read, tape_b.len(), "the program consumes the whole tape");

    // The two fixtures, pinned exactly (the program is straight-line and its structure is
    // deterministic — a code change that moves any number is a deliberate re-measurement):
    assert_eq!(
        (r.cpu_rows, r.permutations, r.mem_accesses, r.program_instrs, r.witness_words),
        (275215, 7440, 402909, 277058, 29375),
        "the tier-8 toy fixture's CycleReport, pinned"
    );
    assert_eq!(
        (rb.cpu_rows, rb.permutations, rb.mem_accesses, rb.program_instrs, rb.witness_words),
        (367340, 9090, 478827, 369443, 35207),
        "the busy fixture's CycleReport, pinned"
    );

    // Phase 5 is *not* height-independent: the constraint DAG is per-chip, but the emitted
    // selectors and quotient recomposition square `log(degree_bits)` times per instance
    // (`emit_selectors`' power loop), so the phase grows with the declared heights. Measured:
    // 7 245 rows here, 7 525 there — the derivation in `docs/03` accounts for it explicitly.
    let p5a: usize = vp.phase5.iter().map(|c| c.instrs).sum();
    let p5b: usize = vp_b.phase5.iter().map(|c| c.instrs).sum();
    assert_eq!((p5a, p5b), (7245, 7525), "phase 5 varies with the degree bits, measured");
}
