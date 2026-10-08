//! The N-generic aggregate program (M5.3): one counted loop over the tape's N, each iteration
//! the per-proof pipeline with a fresh challenger, then the interface digest over
//! `[inner_vk_digest ‖ N ‖ B(8) ‖ 35·N]`. The differentials: N=1 is the single-proof program plus a
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
/// cursor, the per-proof 35-word staged absorb (with its rate-fill permutations), the final
/// permutation, and the loop scaffolding — against the single-proof phase 8's list build and
/// one-shot `sponge_seeded` it replaces — plus AGG-2's eight binding words (their hints, stores,
/// and two rate-fill absorbs, the same at every N). Constraint set 7 moved it by one row
/// (219 → 220). Constraint set 8 moved it 220 → 274: the 35th public value and the wider inner
/// shape measure 235 on the eager absorb, and the deferred absorb (`hash::absorb_staged`, which
/// fixed the double final permutation on a list ending at a block boundary — `N = 1` at 35
/// words a proof) costs one cursor reload per staged word (+43 at N=1) and drops the doubled
/// permutation's four rows: 235 + 43 − 4 = 274. Phase 2's row cuts (2026-10-03) leave it at 274:
/// the cuts are inside the per-proof pipeline, the loop scaffolding around it is unchanged
/// (re-measured: N=1 231 224 = 230 950 + 274). Phase 3's Cut D leaves it at 274 for the same reason
/// (re-measured: N=1 202 472 = 202 198 + 274), Cut E1 too (re-measured: N=1 193 256 = 192 982 + 274),
/// Cut E2 (re-measured: N=1 185 480 = 185 206 + 274), and Cut F (re-measured: N=1 169 640 = 169 366 + 274).
const LOOP_OVERHEAD: usize = 274;

/// The N=3 total, measured on this tree. The per-N total is *not* a clean multiple of the
/// per-proof rows: the staged absorb permutes when a block fills, and the fill phase advances
/// by three lanes per proof (35 mod 4), so iterations differ by one permutation depending on
/// where their run of 35 words starts — the per-N rows are `pre + Σ body_j + post` with the
/// phase term, pinned per N rather than modelled. Constraint set 7 with VERIFIER-1: 1 383 100.
/// Constraint set 8 (the 35th public value, the wider inner shape, the deferred absorb):
/// 1 383 100 → 1 385 968 (`tests/pins.json`'s `aggregate_test_n3_cpu_rows`, re-measured; the
/// eager absorb measured 1 385 855 on the same tree — the 113 rows are one cursor reload per
/// staged word, 8 + 3·35). Phase 2's row cuts (height-group hint buffers, `HINTN`, `COMPRESS`;
/// `docs/04-phase2-row-cuts.md`): 1 385 968 → 692 854, re-measured into `tests/pins.json`. Phase 3's
/// Cut D (the reduce layout, one chain per height per query; `docs/06-phase3-fold-reduce.md`):
/// 692 854 → 606 598, re-measured the same way. Cut E1 (the committed row hinted whole, its own
/// slot checked by one register-addressed `LOADE`): 606 598 → 578 950. Cut E2 (`FOLD`, the fold in the
/// reduce chip): 578 950 → 555 622. Cut F (`POW`, the index powers in the reduce chip): 555 622 → 508 102.
const N3_ROWS: usize = 508_102;

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
/// the host's `[vk ‖ 1 ‖ B(8) ‖ 35]` bound-interface digest, and costs the single-proof rows
/// plus the pinned loop overhead. (The aggregate's interface carries the eight binding words, so
/// it is *not* the single-proof program's digest — that equality held before AGG-2.)
#[test]
fn n1_aggregate_publishes_the_bound_interface_digest_at_a_pinned_overhead() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);

    let single_vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let single_tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let single_exec = execute(&single_vp.program, &single_tape.words, MAX_CYCLES).unwrap();

    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape =
        WitnessTape::build_n(FriProfile::Test, &shape, &key, std::slice::from_ref(&p.proof), &common::TEST_BINDING)
            .unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES)
        .expect("the looped program accepts one real proof");

    let words = randprotocol_rvm::public_values::interface_words_bound(
        &shape,
        &key,
        &common::TEST_BINDING,
        &[p.proof.public_values.clone()],
    );
    assert_eq!(
        exec.public,
        randprotocol_rvm::public_values::public_digest(&words).to_vec(),
        "N=1 publishes the host's bound §4.4 construction, exactly"
    );
    assert_ne!(
        exec.public, single_exec.public,
        "the bound interface is not the single-proof program's digest"
    );
    assert_eq!(
        exec.cpu_rows(),
        single_exec.cpu_rows() + LOOP_OVERHEAD,
        "the loop costs the single-proof rows plus the pinned overhead"
    );
}

/// Three real proofs, one looped run: accepted, and the published digest is the host's
/// `[vk ‖ 3 ‖ B(8) ‖ 35·3]` list — the staged absorb over three proofs whose runs start at
/// three different lanes. (N=1 is the block-boundary case: 13 + 35 = 48 words.)
#[test]
fn n3_aggregate_publishes_the_host_interface_digest() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 3).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &proofs, &common::TEST_BINDING).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES)
        .expect("the looped program accepts three real proofs");

    let pvs: Vec<Vec<u64>> = proofs.iter().map(|p| p.public_values.clone()).collect();
    let words = randprotocol_rvm::public_values::interface_words_bound(&shape, &key, &common::TEST_BINDING, &pvs);
    assert_eq!(
        exec.public,
        randprotocol_rvm::public_values::public_digest(&words).to_vec(),
        "the looped program's digest is the host's bound §4.4 list over three proofs"
    );
    assert_eq!(exec.cpu_rows(), N3_ROWS, "the N=3 row count is pinned");
}

/// AGG-2's chain-facing property, at the emulator: the binding words come from the *tape*, so
/// the executed program's digest matches the host's recompute under the tape's own binding and
/// under no other — a proof made under binding A cannot verify against binding B's recompute.
#[test]
fn verify_aggregate_with_another_binding_is_a_digest_mismatch() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape =
        WitnessTape::build_n(FriProfile::Test, &shape, &key, std::slice::from_ref(&p.proof), &common::TEST_BINDING)
            .unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES)
        .expect("the looped program accepts one real proof");
    let pvs = &[p.proof.public_values.clone()];
    let own = randprotocol_rvm::public_values::interface_words_bound(&shape, &key, &common::TEST_BINDING, pvs);
    assert_eq!(
        exec.public,
        randprotocol_rvm::public_values::public_digest(&own).to_vec(),
        "the program absorbed the tape's own binding words"
    );
    let mut other_binding = common::TEST_BINDING;
    other_binding[3] ^= 1;
    let other = randprotocol_rvm::public_values::interface_words_bound(&shape, &key, &other_binding, pvs);
    assert_ne!(
        exec.public,
        randprotocol_rvm::public_values::public_digest(&other).to_vec(),
        "another (chain, aggregator, nonce)'s recompute does not match"
    );
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
    let tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &[], &common::TEST_BINDING).unwrap();
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
        WitnessTape::build_n(FriProfile::Test, &shape, &key, std::slice::from_ref(&p.proof), &common::TEST_BINDING)
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
fn expected_step(seg: Segment, off: usize, shape: &InnerShape, samples: &[u64]) -> String {
    match seg {
        Segment::Header => format!("header word {off}"),
        Segment::CommitPhaseOpenings => {
            // The segment is query-major; within a query's run, round `r` occupies the whole row
            // (`2·arity` words, Cut E1) then its four salts. A tampered word at the query's own
            // slot (`index_in_group`, the index's bits `shift..shift + la`) is refused by the
            // own-slot equality; a sibling or a salt breaks the round's leaf, so its root.
            let strides: Vec<usize> = shape.log_arities
                .iter()
                .map(|&la| (1usize << la) * 2 + randprotocol_rvm::witness::SALT_ELEMS)
                .collect();
            let query_stride: usize = strides.iter().sum();
            let index = samples[off / query_stride] as usize;
            let mut at = off % query_stride;
            let mut shift = 0usize;
            for (r, (&s, &la)) in strides.iter().zip(shape.log_arities.iter()).enumerate() {
                if at < s {
                    let own = (index >> shift) & ((1usize << la) - 1);
                    return if at / 2 == own {
                        format!("commit phase own slot[{r}]")
                    } else {
                        format!("commit phase root[{r}]")
                    };
                }
                at -= s;
                shift += la;
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
    let mut tape = WitnessTape::build_n(profile, &shape, &key, proofs, &common::TEST_BINDING).unwrap();
    let r = *tape
        .segment_refs()
        .iter()
        .find(|r| r.proof == j && r.segment == seg)
        .unwrap_or_else(|| panic!("proof {j} has a {seg:?} segment"));
    assert!(r.len > 0, "{seg:?} is empty");
    let off = off_seed % r.len;
    let samples = randprotocol_rvm::reference::replay(profile, &shape, &key, &proofs[j]).unwrap().index_samples;
    let want_step = expected_step(seg, off, &shape, &samples);
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
/// passes; (e) the same bytes under another binding (a re-signed copy, AGG-2) are
/// `BindingMismatch`, and (f) with the list's binding words rewritten to match, `DigestMismatch`.
/// One prove covers all five.
#[test]
fn a_one_proof_aggregate_round_trips_and_tampered_variants_are_refused() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    let a = aggregate(&m, &vk, std::slice::from_ref(&p.proof), &common::TEST_BINDING, None)
        .expect("one real bundle proof aggregates");
    assert_eq!(a.proof.tier, RvmTier(18), "the test-profile N=1 aggregate lands at tier 18 (169 640 rows since phase 3's Cut F, 185 480 after Cut E2, 193 256 after Cut E1, 202 472 after Cut D, 231 224 before; tier 19 before phase 2's row cuts)");
    eprintln!("N=1 aggregate proof: {} bytes", a.proof.size());
    let program = aggregate_program(&vk);
    let outs = verify_aggregate(&m, &program, &a, &common::TEST_BINDING).expect("the aggregate verifies");
    let want: [u32; 8] =
        std::array::from_fn(|k| u32::try_from(p.proof.public_values[pv::OUT0 + k]).unwrap());
    assert_eq!(outs, vec![want], "the covered bundle's OUT0..7, in proof order");

    // (`machine::Proof` is serde-only, so the forged handles are postcard round-trips, the
    // fixture cache's own move.)
    let bytes = a.proof.to_bytes();

    // (d): one word of the §4.4 list edited — the proof itself untouched.
    let proof2: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).unwrap();
    let mut forged = AggregateProof { proof: proof2, public: a.public.clone() };
    forged.public[5 + 8 + pv::OUT0] += F::ONE;
    match verify_aggregate(&m, &program, &forged, &common::TEST_BINDING) {
        Err(VerifyAggregateError::DigestMismatch) => {}
        other => panic!("a tampered public list must fail the digest check, got {other:?}"),
    }

    // (b): the rVM proof's declared tier bumped — `check_declared_heights`/`degree_bits`'s
    // refusal, exactly the chain's `Machine::verify` rejecting a tampered aggregate.
    let mut proof3: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).unwrap();
    proof3.tier = RvmTier(proof3.tier.0 + 1);
    let forged = AggregateProof { proof: proof3, public: a.public.clone() };
    match verify_aggregate(&m, &program, &forged, &common::TEST_BINDING) {
        Err(VerifyAggregateError::Verify(_)) => {}
        other => panic!("a tampered aggregate must fail Machine::verify, got {other:?}"),
    }

    // (e) AGG-2: the same proof bytes and list re-signed by another aggregator — the chain
    // recomputes *its* binding from the transaction, and the carried words are not it.
    let mut resigned = common::TEST_BINDING;
    resigned[3] ^= 1;
    let proof4: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).unwrap();
    let copy = AggregateProof { proof: proof4, public: a.public.clone() };
    match verify_aggregate(&m, &program, &copy, &resigned) {
        Err(VerifyAggregateError::BindingMismatch) => {}
        other => panic!("a re-signed aggregate must fail the binding check, got {other:?}"),
    }
    // (f) and the list's binding words rewritten to the re-signer's: the binding check passes,
    // the digest — which absorbed the prover's words in-program — does not.
    let proof5: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).unwrap();
    let mut rewritten = AggregateProof { proof: proof5, public: a.public.clone() };
    for (k, w) in resigned.iter().enumerate() {
        rewritten.public[5 + k] = F::from_u64(*w as u64);
    }
    match verify_aggregate(&m, &program, &rewritten, &resigned) {
        Err(VerifyAggregateError::DigestMismatch) => {}
        other => panic!("a rewritten binding must fail the digest check, got {other:?}"),
    }
}

/// (b) an empty set is `AggregateError::Empty`, before any work.
#[test]
fn an_empty_set_is_refused_before_any_work() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    assert!(matches!(aggregate(&m, &vk, &[], &common::TEST_BINDING, None), Err(AggregateError::Empty)));
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
    match aggregate(&m, &vk, &set, &common::TEST_BINDING, None) {
        Err(AggregateError::WrongShape { index }) => assert_eq!(index, 1),
        Err(e) => panic!("expected WrongShape at index 1, got {e:?}"),
        Ok(_) => panic!("expected WrongShape at index 1, got an aggregate"),
    }
}

// ── The final fix wave (the whole-branch review's Important 2 and 3): the reduce height is
// canonical in (program, N), and N has a ceiling ──────────────────────────────────────────────

/// The reduce rows an emulated run sends to the chip: `build_traces`' own count.
fn run_reduce_rows(exec: &randprotocol_rvm::emulator::Execution) -> u64 {
    use randprotocol_rvm::tables::reduce::{fold_events, fold_rows, pow_events, pow_rows, reduce_events, reduce_rows};
    (reduce_rows(&reduce_events(&exec.events)) + fold_rows(&fold_events(&exec.events)) + pow_rows(&pow_events(&exec.events))) as u64
}

/// The static count `program_rows` (what `Machine::verify_n` derives the canonical height from)
/// is exactly what a run sends: the single-proof program's run, and the aggregate's at N = 1 and
/// 2, emulated at the test profile — `N × program_rows`. So the canonical height is the height
/// `build_traces` declares. Pinned: 39 296 rows a proof (`2^16` at N=1, docs/06 §3), and the
/// ceiling at the current `REDUCE_MAX_LOG_HEIGHT = 20`: test N ≤ 26 (26 × 39 296 + 1 ≤ 2^20).
#[test]
fn the_reduce_height_is_canonical_in_the_program_and_n_at_the_test_profile() {
    use randprotocol_rvm::machine::{canonical_reduce_log_height, max_reduce_n, REDUCE_MAX_LOG_HEIGHT};
    use randprotocol_rvm::tables::reduce::{program_rows, provider_rows, reduce_log_height};
    let proofs: Vec<Proof> = common::bundle_proofs(FriProfile::Test, 2).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let single = verify_rv32(&shape, &key, Checkpoints::Off).program;
    let agg = verify_rv32n(&shape, &key, Checkpoints::Off).program;
    let per = program_rows(&agg);
    assert_eq!(per, 39_296, "the test-profile reduce rows per inner proof");
    assert_eq!(program_rows(&single), per, "the loop body is the single-proof pipeline");
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &proofs[0]).unwrap();
    let exec = execute(&single, &tape.words, MAX_CYCLES).unwrap();
    assert_eq!(run_reduce_rows(&exec), per, "the single-proof run sends exactly the static rows");
    for n in 1..=2u64 {
        let tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &proofs[..n as usize], &common::TEST_BINDING).unwrap();
        let exec = execute(&agg, &tape.words, MAX_CYCLES).unwrap();
        let rows = run_reduce_rows(&exec);
        assert_eq!(rows, n * per, "the N={n} aggregate sends N × the static rows");
        assert_eq!(
            canonical_reduce_log_height(&agg, n),
            Some(reduce_log_height(rows as usize, provider_rows(&agg.reduce_layout))),
            "N={n}: the canonical height is the height build_traces declares"
        );
    }
    assert_eq!(REDUCE_MAX_LOG_HEIGHT, 20, "the constant is not raised in phase 3");
    assert_eq!(max_reduce_n(&agg), 26, "the test-profile N ceiling");
    let heights: Vec<Option<u8>> = [1u64, 2, 3, 4, 7, 13, 14, 26, 27].iter().map(|&n| canonical_reduce_log_height(&agg, n)).collect();
    assert_eq!(heights, [Some(16), Some(17), Some(17), Some(18), Some(19), Some(19), Some(20), Some(20), None]);
}

/// The same at the production profile, statically (the emulations are the ignored B3 tests):
/// 196 480 reduce rows a proof (173 120 run + 6 080 fold + 17 280 pow, docs/06 §3), so the
/// canonical heights are `2^18` at N=1, `2^19` at N=2, `2^20` at N=3–5 — three keys — and N ≥ 6 has
/// no verifiable height at `REDUCE_MAX_LOG_HEIGHT = 20` (6 × 196 480 + 1 > 2^20), inside tier 22
/// which holds cpu rows to N=7: the ceiling is the reduce chip's, not the tier's.
#[test]
fn the_production_reduce_heights_and_n_ceiling_are_pinned() {
    use randprotocol_rvm::machine::{canonical_reduce_log_height, max_reduce_n};
    use randprotocol_rvm::tables::reduce::program_rows;
    let p = common::bundle_proofs(FriProfile::Production, 1).pop().unwrap();
    let (shape, key) = production_shape_and_key(&p.proof);
    let agg = verify_rv32n(&shape, &key, Checkpoints::Off).program;
    assert_eq!(program_rows(&agg), 196_480, "the production reduce rows per inner proof");
    assert_eq!(max_reduce_n(&agg), 5, "the production N ceiling");
    let heights: Vec<Option<u8>> = (1..=7u64).map(|n| canonical_reduce_log_height(&agg, n)).collect();
    assert_eq!(heights, [Some(18), Some(19), Some(20), Some(20), Some(20), None, None]);
}

/// `aggregate` refuses an N past the ceiling with a named error before any tape work (and so
/// before any trace or prove): 27 copies of one test fixture proof, one over the test ceiling.
/// At 26 the same set passes the check — shown by the refusal moving on, not by proving.
#[test]
fn an_aggregate_past_the_reduce_ceiling_is_refused_before_any_tape_work() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let vk = inner_vk(&shape, &key);
    let bytes = postcard::to_allocvec(&p.proof).unwrap();
    let set: Vec<Proof> = (0..27).map(|_| postcard::from_bytes(&bytes).unwrap()).collect();
    let m = RvmMachine::new(FriProfile::Test);
    match aggregate(&m, &vk, &set, &common::TEST_BINDING, None) {
        Err(AggregateError::TooManyProofs { n, max }) => assert_eq!((n, max), (27, 26)),
        Err(e) => panic!("expected TooManyProofs, got {e:?}"),
        Ok(_) => panic!("an aggregate past the reduce ceiling was proved"),
    }
}

// ── Task 4: the refusal suite, the in-suite aggregate, and the N=3 twin ──────────────────────

/// (a) an inner proof tampered inside the set makes `aggregate` fail — never an aggregate. The
/// tamper is one of the 35 public values of proof 1: `matches` still passes (length and
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
    set[1].public_values[pv::OUT0] += 1; // still 35 canonical words; no longer its transcript
    match aggregate(&m, &vk, &set, &common::TEST_BINDING, None) {
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
    let mut tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &proofs, &common::TEST_BINDING).unwrap();
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
/// tier 19 on this fixture shape since phase 2's row cuts (tier 20 before; the history below is
/// the tier-20 prove's, and its GB figures are macOS RSS, which excludes compressed and swapped
/// pages — `docs/04-phase2-row-cuts.md` §"The prover's live heap"). `#[ignore]`d after two jetsam deaths on the shared box: the
/// prove peaks above the box's practical line (~33 GB today; 33.7 GB measured before the
/// SIGKILL, twice), so the suite's heaviest *proven* aggregate is the N=1 round-trip — tier 18
/// since phase 2; skipped on the 48 GB box for memory until phase 3, after which it proves here
/// (the tier-18 twin's shape, 26.88 GB live, `docs/06-phase3-fold-reduce.md` §6) — and this runs
/// alone, watchdog-guarded, the way the twin does. Since phase 3 docs/06's cell model put this
/// tier-19 proof at ≈ 52 GB live, past the 48 GB box; at rate ¼ it proves and verifies on this
/// 48 GB box (`docs/07-rvm-rate-quarter.md` §3; ≈ 30 GB projected, heap not printed).
#[test]
#[ignore = "the N=2 in-suite aggregate: tier 19 (tier 20 before phase 2); proves on the 48 GB box at rate 1/4 (docs/07 §3), \
            ~30 GB live projected; heavy, so run alone: cargo test --release -p recursion --test aggregate \
            two_test_profile -- --ignored --nocapture"]
fn two_test_profile_bundle_proofs_aggregate_and_verify_natively() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 2).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    let a = aggregate(&m, &vk, &proofs, &common::TEST_BINDING, None).expect("two real bundle proofs aggregate");
    assert_eq!(a.proof.tier, RvmTier(19), "the test-profile N=2 aggregate lands at tier 19 (338 871 rows since phase 3's Cut F, 370 551 after Cut E2, 386 103 after Cut E1, 404 535 after Cut D, 462 039 before; tier 20 before phase 2's row cuts)");
    eprintln!("N=2 aggregate proof: {} bytes", a.proof.size());
    let outs = verify_aggregate(&m, &aggregate_program(&vk), &a, &common::TEST_BINDING).expect("the aggregate verifies");
    assert_eq!(outs.len(), 2);
    for (j, out) in outs.iter().enumerate() {
        let want: [u32; 8] = std::array::from_fn(|k| {
            u32::try_from(proofs[j].public_values[pv::OUT0 + k]).unwrap()
        });
        assert_eq!(*out, want, "bundle {j}'s OUT0..7");
    }
}

/// The M5.3 exit (spec §7, R4's profile ruling): an aggregate of **3 real test-profile bundle
/// proofs** verifies natively — tier 19 since phase 3 (508 102 rows; tier 20 after phase 2's row
/// cuts, 21 before; the GB figures in this note are the pre-cut macOS RSS readings, not live-heap
/// numbers — `docs/04`). Not proved since its tier moved: docs/06's cell model put it at ≈ 78 GB
/// live at rate ⅛ (`docs/06-phase3-fold-reduce.md` §3, §6); at rate ¼ ≈ 45 GB projected
/// (`docs/07-rvm-rate-quarter.md` §4), at the edge of the 48 GB box — a ≥ 64 GB host. Timed and measured: wall time, proof size, verify time; the RSS
/// watchdog runs outside the process (see the ignore note). On a box that jetsams the largest
/// process at ~33 GB the attempt is expected to die there — the peak it reaches is the
/// measurement, and the plan's fallback records N=1 (tier 19, completed) as the in-scope proof.
#[test]
#[ignore = "the N=3 exit twin: tier 19 since phase 3 (20 after phase 2, 21 before), ~45 GB live projected at rate 1/4 (docs/07 §4), a >= 64 GB host; watchdog-guarded; \
            run alone: cargo test --release -p recursion --test aggregate twin -- --ignored --nocapture"]
fn twin_three_test_profile_bundle_proofs_aggregate_and_verify_natively() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 3).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vk = inner_vk(&shape, &key);
    let m = RvmMachine::new(FriProfile::Test);
    let t0 = std::time::Instant::now();
    let a = aggregate(&m, &vk, &proofs, &common::TEST_BINDING, None).expect("three real bundle proofs aggregate");
    let prove_s = t0.elapsed().as_secs_f64();
    assert_eq!(a.proof.tier, RvmTier(19), "the test-profile N=3 aggregate lands at tier 19 (508 102 rows since phase 3's Cut F; tier 20 at 555 622 after Cut E2, 578 950 after Cut E1, 606 598 after Cut D, 692 854 before; tier 21 before phase 2's row cuts)");
    let t1 = std::time::Instant::now();
    let outs = verify_aggregate(&m, &aggregate_program(&vk), &a, &common::TEST_BINDING).expect("the aggregate verifies");
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
        "346ee1841980e46a3501f5b04cdf40dd3208e5b1c67360285353cf7a0b735fb9",
        "the inner vk digest is a deterministic constant of the fixture shape"
    );
    let pvs: Vec<Vec<u64>> = proofs.iter().map(|p| p.public_values.clone()).collect();
    let list = randprotocol_rvm::public_values::interface_words_bound(&shape, &key, &common::TEST_BINDING, &pvs);
    assert_eq!(list.len(), 4 + 1 + 8 + 35 * 3);
    let digest = randprotocol_rvm::public_values::public_digest(&list);
    eprintln!("binding (8 words), hex: {}", hex_words(&common::TEST_BINDING.map(|x| F::from_u64(x as u64))));
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
/// so the overhead is not assumed equal — it is measured) and the tier landing, recorded in
/// `docs/02-aggregate.md`: tier 21 at constraint set 8, tier 20 since phase 2's row cuts
/// (893 880 rows = 893 606 + 274, `docs/04-phase2-row-cuts.md`), still tier 20 after phase 3
/// (585 960 = 585 686 + 274, `docs/06-phase3-fold-reduce.md`).
///
/// It also pins the N-generic program's digest at the production bundle shape — the number a
/// chain's aggregation section registers and the fullnode re-pins at a chain cut (`docs/02`'s
/// digest table, `docs/04`'s "what moved"). The in-suite digest test
/// (`tests/verifier.rs`'s `the_aggregate_program_digest_is_unchanged_by_rvm_constraint_fixes`)
/// builds the Test shape and sees a different one, so the production value is checked here,
/// beside the production fixture this test already builds. Re-registered for phase 2's row
/// cuts: `1831f036…ddd7` → `c90b3f0a…74d8`. Re-registered for phase 3's Cut D (the reduce
/// layout, `docs/06-phase3-fold-reduce.md`): `c90b3f0a…74d8` → `a183de6e…6637`. Re-registered for
/// phase 3's Cut E1 (the committed row hinted whole): `a183de6e…6637` → `9a619401…e649`.
/// Re-registered for phase 3's Cut E2 (`FOLD`, the fold in the reduce chip): `9a619401…e649` →
/// `b362024c…fc55`. Re-registered for phase 3's Cut F (`POW`, the index powers in the reduce chip):
/// `b362024c…fc55` → `dc350ecf…8ba0`.
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
    assert_eq!(
        randprotocol_rvm::programs::digest_hex(&verify_rv32n(&shape, &key, Checkpoints::Off).program),
        "dc350ecf6b60af74f4bb032bdf607c3fa0fbd6317705f0b1077e71b455e38ba0",
        "the aggregate program's digest at the production bundle shape, as docs/02 and docs/04 state it"
    );
    let r = common::measure_aggregate(1, FriProfile::Production);
    eprintln!(
        "production N=1 aggregate: {} rows (single {single_rows}, overhead {})",
        r.cpu_rows,
        r.cpu_rows - single_rows
    );
}

/// VERIFIER-1, the rVM half, through the shipped N-generic program: a commit-phase PoW word
/// rewritten in *any* proof's region of an N=2 tape is refused at that round's named step, the
/// loop giving every iteration the single-proof program's check. Before the fix the program
/// discarded the word and the aggregate accepted a re-encoded inner proof
/// (`tests/verifier.rs`'s single-proof test has the reasoning and the native refusal).
#[test]
fn a_rewritten_commit_phase_pow_word_in_any_proof_is_refused() {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Test, 2).into_iter().map(|p| p.proof).collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let honest = WitnessTape::build_n(FriProfile::Test, &shape, &key, &proofs, &common::TEST_BINDING).unwrap();
    execute(&vp.program, &honest.words, MAX_CYCLES).expect("the honest N=2 tape is accepted");
    let rounds = shape.log_arities.len();
    for j in 0..proofs.len() {
        let r = *honest
            .segment_refs()
            .iter()
            .find(|r| r.proof == j && r.segment == Segment::FriCommits)
            .unwrap();
        assert_eq!(r.len, rounds * 17);
        for round in [0, rounds - 1] {
            let at = r.start + 17 * round + 16;
            assert_eq!(honest.words[at], F::ZERO);
            let mut t = honest.clone();
            t.words[at] = F::ONE;
            match execute(&vp.program, &t.words, MAX_CYCLES) {
                Err(ExecError::InverseOfZero { pc }) => assert_eq!(
                    vp.program.checkpoint_at(pc),
                    Some(format!("commit pow witness[{round}]").as_str()),
                    "proof {j}, round {round}: refused at the wrong step"
                ),
                other => panic!("proof {j}, round {round}: expected a refusal, got {:?}", other.map(|e| format!("acceptance, {} cpu rows", e.cpu_rows()))),
            }
        }
    }
}

// ── issue #45 A6/B3: the production-profile aggregate proofs and the N>=2 emulator run ─────────
//
// The M5.3 doc's per-N production table was *derived* (the test-profile law applied to the
// production single-proof pin); rows 6-8 of the big-machine runbook (docs/03) were never run.
// These vehicles run them on the big machine: A6 proves the production N=1 (tier 20 since phase
// 2's row cuts; tier 21 before), N=2 (tier 21; 22 before) and N=3 (tier 21 since phase 3; 22
// after phase 2, 23 before) aggregates and measures wall/verify/size/peak; B3 emulates the
// production N>=2 aggregate programs (the #62 review's gap: register pressure from 80 unrolled
// queries, the memory and timestamp bounds at tier 21 for both since phase 3, 21/22 after phase
// 2, 22/23 before) with no proving. The ">=64 GB" sizing these were written against is
// withdrawn (docs/04 §"The prover's live heap").

/// A Production-profile inner shape and key for `n` cached fixtures (the Test-profile
/// `shape_and_key` above, at the production profile).
fn production_shape_and_key(p: &Proof) -> (InnerShape, InnerKey) {
    let shape = InnerShape::of(
        FriProfile::Production,
        p.tier,
        p.program_log_height,
        p.input_log_height,
        p.keccak_log_height,
        p.sha256_log_height,
        p.public_log_height,
        p.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Production, &shape);
    (shape, key)
}

/// Prove and verify a production-profile N-proof aggregate, printing the runbook's numbers.
fn prove_production_aggregate(n: usize, expected_tier: RvmTier) {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Production, n).into_iter().map(|p| p.proof).collect();
    let (shape, key) = production_shape_and_key(&proofs[0]);
    let vk = InnerVerifierKey { shape: shape.clone(), key: key.clone() };
    let m = RvmMachine::new(FriProfile::Production);
    let t0 = std::time::Instant::now();
    let a = aggregate(&m, &vk, &proofs, &common::TEST_BINDING, None)
        .expect("the production aggregate proves");
    let prove_s = t0.elapsed().as_secs_f64();
    assert_eq!(a.proof.tier, expected_tier, "the production N={n} aggregate's tier");
    let t1 = std::time::Instant::now();
    let outs = verify_aggregate(&m, &aggregate_program(&vk), &a, &common::TEST_BINDING)
        .expect("the production aggregate verifies");
    let verify_s = t1.elapsed().as_secs_f64();
    assert_eq!(outs.len(), n);
    for (j, out) in outs.iter().enumerate() {
        let want: [u32; 8] =
            std::array::from_fn(|k| u32::try_from(proofs[j].public_values[pv::OUT0 + k]).unwrap());
        assert_eq!(*out, want, "covered bundle {j}'s OUT0..7");
    }
    println!(
        "issue45 A6: production N={n} aggregate (tier {}) — prove {prove_s:.1} s, verify \
         {verify_s:.2} s, proof {} bytes",
        expected_tier.0,
        a.proof.size()
    );
}

/// A6, runbook row 6: the production N=1 aggregate (tier 20 since phase 2's row cuts; ≈ 190–240 GB
/// projected from docs/04's measured terms then, ≈ 110–130 GB since phase 3's memory tables went
/// to 2^21, docs/06 §3 — the ~48.6 GB oracle / ≥ 64 GB sizing it carried at tier 21 counted one
/// of four terms and is withdrawn; ≈ 64–75 GB projected at rate ¼, docs/07 §4 — a ≥ 96 GB host).
#[test]
#[ignore = "issue45 A6: production N=1 aggregate proof, tier 20, ~64-75 GB projected at rate 1/4 (docs/07 §4), >=96 GB host. Run: \
            cargo test --release -p recursion --test aggregate production_n1_aggregate_proves_and_verifies -- --ignored --nocapture"]
fn production_n1_aggregate_proves_and_verifies() {
    prove_production_aggregate(1, RvmTier(20));
}

/// A6, runbook row 7: the production N=2 aggregate (tier 21 since phase 2's row cuts; ≈ 475 GB
/// derived in docs/04 then, ≈ 210–245 GB projected since phase 3, docs/02 §"Phase 3" and docs/06
/// §3 at rate ⅛; ≈ 122–142 GB projected at rate ¼, docs/07 §4 — a ≥ 192 GB host).
#[test]
#[ignore = "issue45 A6: production N=2 aggregate proof, tier 21, ~122-142 GB projected at rate 1/4 (docs/07 §4), >=192 GB host. Run: \
            cargo test --release -p recursion --test aggregate production_n2_aggregate_proves_and_verifies -- --ignored --nocapture"]
fn production_n2_aggregate_proves_and_verifies() {
    prove_production_aggregate(2, RvmTier(21));
}

/// A6, runbook row 8: the production N=3 aggregate (tier 21 since phase 3 — 1 757 062 rows; tier 22
/// after phase 2's row cuts, 23 before; ≈ 290–340 GB projected at rate ⅛, docs/02 §"Phase 3" and
/// docs/06 §3; ≈ 168–197 GB projected at rate ¼, docs/07 §4 — a ≥ 256 GB host). Only attempt
/// after the rest.
#[test]
#[ignore = "issue45 A6: production N=3 aggregate proof, tier 21, ~168-197 GB projected at rate 1/4 (docs/07 §4), >=256 GB host. Run: \
            cargo test --release -p recursion --test aggregate production_n3_aggregate_proves_and_verifies -- --ignored --nocapture"]
fn production_n3_aggregate_proves_and_verifies() {
    prove_production_aggregate(3, RvmTier(21));
}

/// B3: the production N>=n aggregate program emulated (no proving) — the #62 review's gap. Runs
/// the whole verifier loop over N real production inner proofs and checks the bounds that only an
/// execution can: the tier the row count lands in, every address inside the 2^24 space (register
/// pressure from the 80 unrolled queries' spills does not run the arena past its limit), and every
/// `16·clk + slot` timestamp inside the machine's 2^27 collision-free window (docs/aggregation.md).
fn emulate_production_aggregate(n: usize, expected_tier: RvmTier) {
    let proofs: Vec<Proof> =
        common::bundle_proofs(FriProfile::Production, n).into_iter().map(|p| p.proof).collect();
    let (shape, key) = production_shape_and_key(&proofs[0]);
    let vp = verify_rv32n(&shape, &key, Checkpoints::Off);
    let tape =
        WitnessTape::build_n(FriProfile::Production, &shape, &key, &proofs, &common::TEST_BINDING)
            .unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES)
        .expect("the production aggregate program emulates over N real proofs");

    // The interface digest is exactly the host's bound §4.4 list — the run did the whole job.
    let pvs: Vec<Vec<u64>> = proofs.iter().map(|p| p.public_values.clone()).collect();
    let words =
        randprotocol_rvm::public_values::interface_words_bound(&shape, &key, &common::TEST_BINDING, &pvs);
    assert_eq!(
        exec.public,
        randprotocol_rvm::public_values::public_digest(&words).to_vec(),
        "the emulated production N={n} aggregate publishes the host's interface digest"
    );

    let rows = exec.cpu_rows();
    assert_eq!(
        RvmTier::for_cycles(rows),
        Some(expected_tier),
        "the production N={n} aggregate lands at tier {}",
        expected_tier.0
    );
    assert!(exec.max_addr < (1 << 24), "every address stays inside the 2^24 space (max {})", exec.max_addr);
    // `16·clk + slot`, slot <= 15: the top timestamp is under `16·rows`, and the collision-free
    // window is 2^27 (16·CLK + slot, integral CLK on every real row).
    let max_ts = (rows as u64) * 16 + 15;
    assert!(max_ts < (1 << 27), "the top timestamp {max_ts} is inside the 2^27 window");
    println!(
        "issue45 B3: production N={n} aggregate emulation — {rows} cpu rows (tier {}), \
         {} permutations, {} mem accesses, {} witness words, max addr {}, max ts {max_ts} (< 2^27)",
        expected_tier.0,
        exec.permutations(),
        exec.mem_accesses(),
        tape.words.len(),
        exec.max_addr
    );
}

/// B3: production N=2 aggregate emulation (tier 21: 1 171 511 rows since phase 3, 1 787 351 after
/// phase 2's row cuts; tier 22, ~3.94M rows before).
#[test]
#[ignore = "issue45 B3: production N=2 aggregate emulator run (1 171 511 rows, tier 21, no proving). Run: \
            cargo test --release -p recursion --test aggregate production_n2_aggregate_emulates_within_bounds -- --ignored --nocapture"]
fn production_n2_aggregate_emulates_within_bounds() {
    emulate_production_aggregate(2, RvmTier(21));
}

/// B3: production N=3 aggregate emulation (tier 21: 1 757 062 rows since phase 3; tier 22, 2 680 822
/// rows after phase 2's row cuts; tier 23, ~5.9M rows before — the top rung then).
#[test]
#[ignore = "issue45 B3: production N=3 aggregate emulator run (1 757 062 rows, tier 21, no proving). Run: \
            cargo test --release -p recursion --test aggregate production_n3_aggregate_emulates_within_bounds -- --ignored --nocapture"]
fn production_n3_aggregate_emulates_within_bounds() {
    emulate_production_aggregate(3, RvmTier(21));
}
