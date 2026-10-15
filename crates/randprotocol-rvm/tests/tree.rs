//! Tree aggregation (spec §3, §6): `rv32t` verifies two child rVM proofs of one compile-time
//! shape and publishes `[vk_c ‖ 2 ‖ B ‖ D_1 ‖ D_2]`, with `vk_c` computed in-program over the
//! hinted cap. Task 1a runs the program by emulation over real test-profile leaves (`rv32n` over
//! L = 1 bundle proof each, proved here and cached). Task 1b proves a depth-2 tree, and Task 2
//! verifies it through `verify_tree`.
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_zkvm::machine::{FriProfile, Proof as BundleProof};
use randprotocol_rvm::aggregate::{aggregate, aggregate_program, InnerVerifierKey};
use randprotocol_rvm::dsl::Checkpoints;
use randprotocol_rvm::emulator::{execute, ExecError, Execution};
use randprotocol_rvm::isa::{Op, Program, F};
use randprotocol_rvm::machine::{Machine, Proof, Tier};
use randprotocol_rvm::programs::{rv32t_int, rv32t_leaf, tree_step_program_digest, verify_rv32r, verify_rv32t};
use randprotocol_rvm::public_values::{public_digest, tree_step_words};
use randprotocol_rvm::shape::{inner_vk_digest, InnerKey, InnerShape, RvmKey, RvmShape};
use randprotocol_rvm::witness::{Segment, TapeError, WitnessTape, TREE_TAPE_PREAMBLE};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

const MAX_CYCLES: usize = 1 << 24;
const P: FriProfile = FriProfile::Test;
const B: &[u32; 8] = &common::TEST_BINDING;

/// Set only by the ignored generator (Task 1b): an in-suite run never starts a tier-19 proof
/// on a box that cannot hold it (R7). Leaves are exempt: tier 18, 15.64 GB live at rate ¼ (docs/07 §4).
static ALLOW_STEP_PROVING: AtomicBool = AtomicBool::new(false);

fn tree_file(name: &str) -> std::path::PathBuf {
    common::cache_dir().join("tree").join(format!("{name}.rvmproof"))
}

/// The cached proof `name` if it decodes and verifies at `n`, else `prove()`'s, verified and
/// stored: the bundle-fixture cache's discipline (`common::load_cached`), one level up.
fn load_or_prove(name: &str, program: &Program, n: u64, may_prove: bool, prove: impl FnOnce() -> Proof) -> Proof {
    let m = Machine::new(P);
    if let Some(p) = std::fs::read(tree_file(name)).ok().and_then(|b| postcard::from_bytes::<Proof>(&b).ok()) {
        if m.verify_n(program, &p, n).is_ok() {
            return p;
        }
    }
    assert!(may_prove, "{} is missing or stale: run `cargo test --release --test tree generate_test_tree_fixtures \
        -- --ignored --nocapture` on a host with the docs/08 §5 memory and copy tree/ into $RECURSION_FIXTURES", tree_file(name).display());
    let p = prove();
    m.verify_n(program, &p, n).expect("a freshly proved tree proof verifies");
    let path = tree_file(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, p.to_bytes()).unwrap();
    p
}

/// Four test-profile leaves, `rv32n` over bundle fixture k = 0..3 each (L = 1; 88 486 rows since phase 5, 169 640 before the Merkle spans,
/// tier 18 — `tests/pins.json`'s `aggregate_test_n1_cpu_rows`).
struct Leaves {
    inner: InnerVerifierKey,
    program: Arc<Program>,
    shape: RvmShape,
    key: RvmKey,
    bundles: Vec<BundleProof>,
    proofs: Vec<Proof>,
}

fn leaves() -> &'static Leaves {
    static L: OnceLock<Leaves> = OnceLock::new();
    L.get_or_init(|| {
        let bundles: Vec<BundleProof> = common::bundle_proofs(P, 4).into_iter().map(|b| b.proof).collect();
        let p = &bundles[0];
        let shape = InnerShape::of(P, p.tier, p.program_log_height, p.input_log_height, p.keccak_log_height,
            p.sha256_log_height, p.public_log_height, p.mem_log_height);
        let key = InnerKey::of(P, &shape);
        let inner = InnerVerifierKey { shape, key };
        let program = Arc::new(aggregate_program(&inner));
        let proofs: Vec<Proof> = (0..4)
            .map(|k| {
                load_or_prove(&format!("Test-leaf-{k}"), &program, 1, true, || {
                    aggregate(&Machine::new(P), &inner, std::slice::from_ref(&bundles[k]), B, None)
                        .expect("a test leaf proves")
                        .proof
                })
            })
            .collect();
        let shape = RvmShape::of_proof(P, &program, &proofs[0]);
        assert!(proofs.iter().all(|p| shape.matches(p)), "the four leaves declare one shape (a fixed workload)");
        let key = RvmKey::of(P, &shape);
        Leaves { inner, program, shape, key, bundles, proofs }
    })
}

/// A proof's four public values, the interface digest it publishes.
fn d(p: &Proof) -> [F; 4] {
    std::array::from_fn(|k| F::from_u64(p.public_values[k]))
}

/// The host's step digest over `(a, b)` in that order, as the emulator's public words.
fn host_step(vk: &[F; 4], binding: &[u32; 8], a: &Proof, b: &Proof) -> Vec<F> {
    public_digest(&tree_step_words(vk, binding, &d(a), &d(b))).to_vec()
}

fn emulate_step(child: &RvmShape, program: &Program, a: &Proof, b: &Proof, binding: &[u32; 8]) -> Result<Execution, ExecError> {
    let tape = WitnessTape::build_tree_step(P, child, [a, b], binding).expect("children of the shape build a tape");
    execute(program, &tape.words, MAX_CYCLES)
}

/// The leaf program with one unreachable `HALT` appended (R5's foreign program): the same
/// execution, so the same declared heights and shape words; another digest, so another cap.
fn foreign_leaf_program(p: &Program) -> Program {
    let mut q = p.clone();
    let halt = q.instrs.last().cloned().expect("a program ends");
    assert_eq!(halt.op, Op::Halt, "the builder ends every program with HALT");
    q.instrs.push(halt);
    assert_eq!(randprotocol_rvm::machine::program_log_height(q.instrs.len()), randprotocol_rvm::machine::program_log_height(p.instrs.len()),
        "the extra word must not cross a program-table power of two");
    q
}

// ── Task 1a: the program, by emulation ───────────────────────────────────────────────────────

/// `rv32t`'s pre-loop state (the binding, the cap, the interface sponge and its cursor) lives in
/// absolute cells. Building is the replay's loop-invariant check.
#[test]
fn the_tree_step_builds_under_the_replays_loop_invariant() {
    let l = leaves();
    let a = verify_rv32t(&l.shape, Checkpoints::Off).program;
    let b = verify_rv32t(&l.shape, Checkpoints::Off).program;
    assert_eq!(a.digest(), b.digest(), "the build is deterministic");
    assert_eq!(rv32t_leaf(&l.shape, Checkpoints::Off).program.digest(), a.digest(), "rv32t_leaf is verify_rv32t, named for level 1");
    assert_eq!(rv32t_int(&l.shape, Checkpoints::Off).program.digest(), a.digest(), "rv32t_int is verify_rv32t, named for levels ≥ 2");
    assert_eq!(tree_step_program_digest(&l.shape), a.digest(), "what a chain pins is the checkpoints-off build");
    // Pinned at the test-profile leaf shape (2026-10-09, tree Task 1a): `rv32t_leaf`'s digest,
    // the test chain's `t_leaf_digest` (M4). Re-pinned at the rVM's rate ¼ (2026-10-09, docs/07,
    // tree Task R): the child's Merkle paths are one level shorter (was bf80794d…ff4d5389).
    // Phase 4 (2026-10-09, the Merkle spans) re-recorded it: 2c586636… → d8d558ee….
    // Phase 5 (2026-10-12, S6a/S2b/S4a/S1b) re-recorded it: d8d558ee… → af535052….
    assert_eq!(randprotocol_rvm::programs::digest_hex(&a), "af535052d2df18b5e313a6f0c2e412456d059d5f602d569989ad1b2b69e90cac", "rv32t_leaf's digest at the test leaf shape");
}

/// The program reads the child shape's words and never its committed program: a child program
/// that differs only past its `HALT` builds the identical step.
#[test]
fn the_tree_step_program_reads_the_child_shape_words_only() {
    let l = leaves();
    let foreign = Arc::new(foreign_leaf_program(&l.program));
    let other = RvmShape::of(P, &foreign, Tier(l.shape.tier), l.shape.reg_log_height, l.shape.ram_log_height,
        l.shape.poseidon2_log_height, l.shape.reduce_log_height);
    assert!(other.same_step_words(&l.shape), "one word past HALT moves no shape word");
    assert_ne!(foreign.digest(), l.program.digest());
    assert_ne!(RvmKey::of(P, &other), l.key, "another program is another cap");
    assert_eq!(verify_rv32t(&other, Checkpoints::Off).program.digest(), verify_rv32t(&l.shape, Checkpoints::Off).program.digest());
}

/// Two real leaves, in order: accepted, the whole tape consumed, and exactly the host's
/// `[vk_leaf ‖ 2 ‖ B ‖ D_0 ‖ D_1]` published. Measures C (the k = 1 self-verifier over one leaf,
/// less phase 8) and the step's overhead O = rows − 2C (docs/08 §2's band term).
#[test]
fn the_tree_step_accepts_two_real_leaves_and_publishes_the_host_digest() {
    let l = leaves();
    let vp = rv32t_leaf(&l.shape, Checkpoints::Off);
    let tape = WitnessTape::build_tree_step(P, &l.shape, [&l.proofs[0], &l.proofs[1]], B).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32t_leaf accepts two real leaves");
    assert_eq!(exec.hints_read, tape.len(), "the program consumes the whole tape");
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    assert_eq!(exec.public, host_step(&vk_leaf, B, &l.proofs[0], &l.proofs[1]), "[vk_leaf ‖ 2 ‖ B ‖ D_0 ‖ D_1], exactly");

    let r = verify_rv32r(&l.shape, &l.key, Checkpoints::Off);
    let rt = WitnessTape::build_for_with_binding(P, &l.shape, &l.key, &l.proofs[0], B).unwrap();
    let rexec = execute(&r.program, &rt.words, MAX_CYCLES).expect("rv32r accepts the leaf");
    let phase8: usize = r.phase_rows.iter().filter(|(n, _)| n.starts_with("phase 8")).map(|(_, x)| *x).sum();
    let child = rexec.cpu_rows() - phase8;
    let rows = exec.cpu_rows();
    let overhead = rows as i64 - 2 * child as i64;
    let by_phase = |vp: &randprotocol_rvm::programs::VerifierProgram<RvmShape>, e: &Execution| -> Vec<(&'static str, usize)> {
        let mut at = 0;
        vp.phase_rows.iter().map(|&(name, n)| {
            let x = e.events.iter().filter(|ev| (at..at + n).contains(&(ev.pc as usize))).count();
            at += n;
            (name, x)
        }).collect()
    };
    eprintln!("TREE_TEST phases rv32t {:?}", by_phase(&vp, &exec));
    eprintln!("TREE_TEST phases rv32r {:?}", by_phase(&r, &rexec));
    eprintln!("TREE_TEST child {child} step_leaf {rows} overhead {overhead} tier {:?} program {} instrs",
        Tier::for_cycles(rows), vp.program.instrs.len());
    // Phase 5 (2026-10-12, S6a/S2b/S4a/S1b) re-recorded `child_cpu_rows` 91 034 → 74 605 and `step_leaf_cpu_rows`
    // 182 444 → 149 586 (overhead 376 and tier 18 unchanged; `step_int_*` and the reduce-rows pins are fixture-gated, not re-recorded).
    assert_eq!(child, common::pin("tree_test", "child_cpu_rows"));
    assert_eq!(rows, common::pin("tree_test", "step_leaf_cpu_rows"));
    assert_eq!(overhead, common::pin_i64("tree_test", "step_overhead"));
    assert_eq!(Tier::for_cycles(rows).unwrap().0, common::pin("tree_test", "step_leaf_tier"));
}

/// The counted loop runs one child's static reduce rows twice, so `verify_n(program, proof, 2)`
/// (spec §4) declares exactly the height `build_traces` produces. Extends
/// `tests/aggregate.rs`'s `the_reduce_height_is_canonical_in_the_program_and_n_at_the_test_profile`
/// to the tree step.
#[test]
fn the_reduce_height_is_canonical_in_the_tree_step_at_n2() {
    use randprotocol_rvm::machine::canonical_reduce_log_height;
    use randprotocol_rvm::tables::reduce::{fold_events, fold_rows, pow_events, pow_rows, program_rows, provider_rows, reduce_events, reduce_log_height, reduce_rows};
    let l = leaves();
    let t = rv32t_leaf(&l.shape, Checkpoints::Off).program;
    let r = verify_rv32r(&l.shape, &l.key, Checkpoints::Off).program;
    let per = program_rows(&t);
    assert_eq!(per, program_rows(&r), "the loop body is the self-verifier's pipeline: one child's reduce rows");
    let exec = emulate_step(&l.shape, &t, &l.proofs[0], &l.proofs[1], B).unwrap();
    let rows = (reduce_rows(&reduce_events(&exec.events)) + fold_rows(&fold_events(&exec.events)) + pow_rows(&pow_events(&exec.events))) as u64;
    assert_eq!(rows, 2 * per, "two children run the body's static rows twice");
    assert_eq!(canonical_reduce_log_height(&t, randprotocol_rvm::programs::TREE_ARITY),
        Some(reduce_log_height(rows as usize, provider_rows(&t.reduce_layout))),
        "verify_n(program, proof, 2)'s height is the one build_traces declares");
}

/// Review Focus 3: a tamper in either child's region is refused at `emit_proof`'s own named
/// step, on the loop's first pass (child 0) or its second (child 1). The names are the
/// self-verifier's (`tests/self_verify.rs`'s table) because the body is the same pipeline (R1).
#[test]
fn a_tamper_in_either_child_is_refused_at_the_named_step() {
    let l = leaves();
    let vp = rv32t_leaf(&l.shape, Checkpoints::Off);
    let honest = WitnessTape::build_tree_step(P, &l.shape, [&l.proofs[0], &l.proofs[1]], B).unwrap();
    let table = [
        (Segment::Header, "header word 0"),
        (Segment::PublicValues, "quotient identity[0]"),
        (Segment::Commitments, "quotient identity[0]"),
        (Segment::LookupTerminals, "lookup terminal sum"),
    ];
    for child in 0..2 {
        for (seg, want) in table {
            let r = honest.segment_refs().into_iter().find(|r| r.proof == child && r.segment == seg).expect("the segment exists");
            let mut t = honest.clone();
            t.words[r.start] += F::ONE;
            match execute(&vp.program, &t.words, MAX_CYCLES) {
                Err(ExecError::InverseOfZero { pc }) => {
                    assert_eq!(vp.program.checkpoint_at(pc), Some(want), "child {child}, {seg:?}: refused at the wrong step")
                }
                other => panic!("child {child}, {seg:?}: expected a refusal, got {:?}", other.map(|e| e.cpu_rows())),
            }
        }
    }
}

/// R5, first half: a wrong hinted cap under honest children is refused in-program. The
/// transcript observes the preprocessed cap in phase 2, so every later challenge moves, and the
/// first check that reads one is the quotient identity.
#[test]
fn a_wrong_hinted_cap_with_honest_children_is_refused_in_program() {
    let l = leaves();
    let vp = rv32t_leaf(&l.shape, Checkpoints::Off);
    let honest = WitnessTape::build_tree_step(P, &l.shape, [&l.proofs[0], &l.proofs[1]], B).unwrap();
    for k in [8usize, TREE_TAPE_PREAMBLE - 1] {
        let mut t = honest.clone();
        t.words[k] += F::ONE;
        match execute(&vp.program, &t.words, MAX_CYCLES) {
            Err(ExecError::InverseOfZero { pc }) => assert_eq!(vp.program.checkpoint_at(pc), Some("quotient identity[0]"), "cap word {}", k - 8),
            other => panic!("cap word {}: expected a refusal, got {:?}", k - 8, other.map(|e| e.cpu_rows())),
        }
    }
}

/// ZKQ-5's tie is the chain's recompute. The program accepts a swapped pair and a step made
/// under another binding, and each publishes a digest that the chain's cover-order,
/// chain-binding recompute never produces (Task 2 turns both into `TreeRootDigest`).
#[test]
fn swapped_children_and_another_binding_publish_digests_the_chain_never_computes() {
    let l = leaves();
    let t = rv32t_leaf(&l.shape, Checkpoints::Off).program;
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    let want = host_step(&vk_leaf, B, &l.proofs[0], &l.proofs[1]);
    let swapped = emulate_step(&l.shape, &t, &l.proofs[1], &l.proofs[0], B).expect("both orders are valid in-program");
    assert_eq!(swapped.public, host_step(&vk_leaf, B, &l.proofs[1], &l.proofs[0]), "children are published in tape order");
    assert_ne!(swapped.public, want, "a swapped pair fails the cover-order recompute");
    let rebound = emulate_step(&l.shape, &t, &l.proofs[0], &l.proofs[1], &[7u32; 8]).expect("no in-program B_out == B_in (ZKQ-5)");
    assert_ne!(rebound.public, want, "a step made under another binding fails the recompute");
}

/// A child whose declared shape is not the step's is refused by the tape builder, before any
/// word is written (the self-verifier's `a_wrong_shape_proof_is_refused`, one level up).
#[test]
fn a_child_of_the_wrong_shape_is_refused_by_the_tape_builder() {
    let l = leaves();
    let wrong = RvmShape::of(P, &l.program, Tier(l.shape.tier), l.shape.reg_log_height, l.shape.ram_log_height + 1,
        l.shape.poseidon2_log_height, l.shape.reduce_log_height);
    assert_eq!(
        WitnessTape::build_tree_step(P, &wrong, [&l.proofs[0], &l.proofs[1]], B).err(),
        Some(TapeError::Replay(randprotocol_rvm::reference::ReplayError::Shape))
    );
}

/// The builder's pre-check runs over *both* children before any replay (Task 1a review minor):
/// child 0 matches the shape but is tampered, so its replay alone refuses it with a non-shape
/// error; child 1 declares another shape. Only the pre-check can answer `Shape` for the pair.
#[test]
fn the_tape_builder_shape_checks_both_children_before_replaying_either() {
    let l = leaves();
    let copy = |p: &Proof| postcard::from_bytes::<Proof>(&p.to_bytes()).unwrap();
    let mut tampered = copy(&l.proofs[0]);
    tampered.public_values[0] = (tampered.public_values[0] + 1) % F::ORDER_U64;
    assert!(l.shape.matches(&tampered), "a public-value tamper keeps the declared shape");
    let mut other = copy(&l.proofs[1]);
    other.ram_log_height += 1;
    assert!(!l.shape.matches(&other));
    let alone = WitnessTape::build_tree_step(P, &l.shape, [&tampered, &l.proofs[1]], B).err();
    assert!(matches!(alone, Some(TapeError::Replay(ref e)) if *e != randprotocol_rvm::reference::ReplayError::Shape),
        "the tampered child alone is refused by its replay, not the shape check: {alone:?}");
    assert_eq!(
        WitnessTape::build_tree_step(P, &l.shape, [&tampered, &other], B).err(),
        Some(TapeError::Replay(randprotocol_rvm::reference::ReplayError::Shape)),
        "child 1's shape is refused before child 0 is replayed"
    );
}

// ── Task 1b: the proved test tree ───────────────────────────────────────────────────────────

struct TestTree {
    t_leaf: Arc<Program>,
    steps: Vec<Proof>,
    /// S_T: an `rv32t_leaf` proof's declared shape, carrying `rv32t_leaf`'s program.
    s_step: RvmShape,
    t_int: Arc<Program>,
    root: Proof,
    /// The root's declared shape, carrying `rv32t_int`'s program. R3: its words must equal S_T's.
    s_root: RvmShape,
    foreign: Proof,
    s_foreign: RvmShape,
}

fn test_tree() -> &'static TestTree {
    static T: OnceLock<TestTree> = OnceLock::new();
    T.get_or_init(|| {
        let l = leaves();
        let may = ALLOW_STEP_PROVING.load(Ordering::SeqCst);
        let m = Machine::new(P);
        let prove_step = |child: &RvmShape, program: &Program, a: &Proof, b: &Proof| -> Proof {
            let tape = WitnessTape::build_tree_step(P, child, [a, b], B).unwrap();
            m.prove(program, &tape.words, None).expect("a test tree step proves").0
        };
        let t_leaf = Arc::new(rv32t_leaf(&l.shape, Checkpoints::Off).program);
        let steps: Vec<Proof> = (0..2)
            .map(|k| load_or_prove(&format!("Test-step-{k}"), &t_leaf, 2, may, || {
                prove_step(&l.shape, &t_leaf, &l.proofs[2 * k], &l.proofs[2 * k + 1])
            }))
            .collect();
        let s_step = RvmShape::of_proof(P, &t_leaf, &steps[0]);
        assert!(s_step.matches(&steps[1]), "both level-1 steps declare one shape");
        let t_int = Arc::new(rv32t_int(&s_step, Checkpoints::Off).program);
        let root = load_or_prove("Test-root", &t_int, 2, may, || prove_step(&s_step, &t_int, &steps[0], &steps[1]));
        let s_root = RvmShape::of_proof(P, &t_int, &root);
        let fprog = Arc::new(foreign_leaf_program(&l.program));
        let foreign = load_or_prove("Test-foreign-0", &fprog, 1, true, || {
            let tape = WitnessTape::build_n(P, &l.inner.shape, &l.inner.key, std::slice::from_ref(&l.bundles[0]), B).unwrap();
            m.prove(&fprog, &tape.words, None).expect("the foreign leaf proves").0
        });
        let s_foreign = RvmShape::of_proof(P, &fprog, &foreign);
        TestTree { t_leaf, steps, s_step, t_int, root, s_root, foreign, s_foreign }
    })
}

fn u64s(v: &[F]) -> Vec<u64> {
    v.iter().map(|f| f.as_canonical_u64()).collect()
}

/// The generator (R7): proves whatever `tree/` lacks. Run it once where docs/08 §5 says, then
/// copy `$RECURSION_FIXTURES/tree/` to every box that runs the suite.
#[test]
#[ignore = "tree Task 1b: proves the test tree's steps and root (tier 18 since phase 4, tier 19 before; tests/pins.json tree_test.step_leaf_tier; re-run 2026-10-11 in 1821 s, docs/measurements/2026-10-11-tree-test-fixtures-phase4-laptop.log; at tier 19 34.3 GB max RSS measured for a step, 33.2 GB for the root) — this 48 GB laptop, one proving process at a time"]
fn generate_test_tree_fixtures() {
    ALLOW_STEP_PROVING.store(true, Ordering::SeqCst);
    let t = test_tree();
    let l = leaves();
    for (name, p) in [("leaf-0", &l.proofs[0]), ("step-0", &t.steps[0]), ("step-1", &t.steps[1]), ("root", &t.root), ("foreign-0", &t.foreign)] {
        eprintln!("TREE_TEST_FIXTURE {name}: tier {} reg {} ram {} poseidon2 {} reduce {} bytes {}",
            p.tier.0, p.reg_log_height, p.ram_log_height, p.poseidon2_log_height, p.reduce_log_height, p.size());
    }
}

/// The depth-2 tree, every level: each step and the root publish exactly the host's
/// `[vk_c ‖ 2 ‖ B ‖ D_a ‖ D_b]` in cover order, with level 1's `vk_c = vk_leaf` and level 2's
/// `vk_c = vk_t_leaf` (R2). The child keys are computed here, never read off a
/// `VerifierProgram` (whose `key` is a zero placeholder for `rv32t`). The root's rows, as
/// emulated, are pinned.
#[test]
fn the_test_tree_proves_and_every_level_publishes_the_host_digest() {
    let (l, t) = (leaves(), test_tree());
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    let vk_t_leaf = inner_vk_digest(&t.s_step, &RvmKey::of(P, &t.s_step));
    for k in 0..2 {
        assert_eq!(t.steps[k].public_values, u64s(&host_step(&vk_leaf, B, &l.proofs[2 * k], &l.proofs[2 * k + 1])), "step {k}");
    }
    assert_eq!(t.root.public_values, u64s(&host_step(&vk_t_leaf, B, &t.steps[0], &t.steps[1])), "the root");
    let exec = emulate_step(&t.s_step, &t.t_int, &t.steps[0], &t.steps[1], B).expect("rv32t_int accepts the two steps");
    eprintln!("TREE_TEST_INT rows {} tier {} step_bytes {} {} root_bytes {}", exec.cpu_rows(), t.root.tier.0,
        t.steps[0].size(), t.steps[1].size(), t.root.size());
    assert_eq!(exec.cpu_rows(), common::pin("tree_test", "step_int_cpu_rows"));
    assert_eq!(t.root.tier.0, common::pin("tree_test", "step_int_tier"));
    for p in t.steps.iter().chain(std::iter::once(&t.root)) {
        assert!(p.size() <= common::pin("tree_test", "step_proof_bytes_max"), "a step proof grew: {} bytes", p.size());
    }
}

/// The shape a proof of `program` over this run would declare, without proving: the tier the
/// run's rows need and the heights `build_traces` sizes from the workload (the declared-height
/// rule, which `prove` applies verbatim), read through `RvmShape::of`.
fn emulated_shape(program: &Arc<Program>, exec: &Execution) -> RvmShape {
    let tier = Tier::for_cycles(exec.cpu_rows()).expect("the run fits a tier");
    let tr = randprotocol_rvm::machine::build_traces(program, exec, tier).expect("the run's traces build");
    RvmShape::of(P, program, tier, tr.reg_log_height, tr.ram_log_height, tr.poseidon2_log_height, tr.reduce_log_height)
}

/// R3, as measured: `rv32t_int`, built for S_T, verifies its own output at the test profile.
/// Before phase 4 (docs/08 §5) it did not: its two passes over tier-19 children crossed 2^16 reduce
/// rows while `rv32t_leaf`'s two over tier-18 leaves did not, so the root declared another reduce
/// height and arity schedule. Phase 4 (2026-10-09, the Merkle spans; ruling 10) re-recorded it:
/// both steps are tier 18 and both cross 2^16 (32 912 and 33 328 reduce rows per child), the
/// root declares S_T's words exactly, so `rv32t` at S_root is `rv32t_int`, and the tape builder
/// accepts the root pair as children of S_root — the fixed point is level 2. (Under S_T itself,
/// whose key is `rv32t_leaf`'s, the replay refuses the root: the hinted cap is the child's own.)
/// Both header-word lists and the reduce rows stay pinned (docs/09).
#[test]
fn the_interior_step_verifies_its_own_output_at_the_test_profile() {
    use randprotocol_rvm::tables::reduce::program_rows;
    let t = test_tree();
    let (per_leaf, per_int) = (program_rows(&t.t_leaf), program_rows(&t.t_int));
    eprintln!("TREE_TEST_R3 reduce rows per child: rv32t_leaf {per_leaf} (x2 = {}), rv32t_int {per_int} (x2 = {}); \
        S_T {:?} root {:?}", 2 * per_leaf, 2 * per_int, t.s_step.header_words(), t.s_root.header_words());
    assert_eq!(per_leaf as usize, common::pin("tree_test", "step_leaf_reduce_rows_per_child"));
    assert_eq!(per_int as usize, common::pin("tree_test", "step_int_reduce_rows_per_child"));
    assert!(2 * per_leaf > 1 << 16 && 2 * per_int > 1 << 16, "both steps cross 2^16 reduce rows (rv32t_leaf no longer under it)");
    let words = |s: &RvmShape| u64s(&s.header_words());
    assert_eq!(words(&t.s_step), [18, 19, 20, 15, 17, 17, 16, 1, 1, 1, 2, 3, 3, 1, 3, 2, 3, 1], "S_T");
    assert_eq!(words(&t.s_root), [18, 19, 20, 15, 17, 17, 16, 1, 1, 1, 2, 3, 3, 1, 3, 2, 3, 1], "the root");
    assert!(t.s_root.same_step_words(&t.s_step), "R3, measured: rv32t_int's own proofs declare S_T's words");
    // The step program reads the child shape's words only, so the program for children of S_root
    // is the program for children of S_T: rv32t_int.
    assert_eq!(tree_step_program_digest(&t.s_root), t.t_int.digest(), "rv32t at S_root is rv32t_int");
    // The tape builder takes the root pair as children of S_root (the root's own shape, whose key
    // is rv32t_int's preprocessed commit). Under S_T itself — the same words, but rv32t_leaf's
    // program and so rv32t_leaf's key — the shape check passes and the replay refuses the root
    // (not a proof under that key): the hinted cap must be the child's own.
    assert!(
        WitnessTape::build_tree_step(P, &t.s_root, [&t.root, &t.root], B).is_ok(),
        "rv32t_int takes its own proofs as children"
    );
    assert_eq!(
        WitnessTape::build_tree_step(P, &t.s_step, [&t.root, &t.root], B).err(),
        Some(TapeError::Replay(randprotocol_rvm::reference::ReplayError::Constraints(0))),
        "under S_T's key the root passes the shape check and fails the replay"
    );
}

/// R3, as measured: the fixed point is reached at level 2. The step program built for the root's
/// shape S_root is `rv32t_int` itself (the same digest), emulated over (root, root): accepted,
/// publishing `[vk_int ‖ 2 ‖ B ‖ D ‖ D]`, and its own proofs would declare S_root's words again,
/// so it is the program for every level ≥ 2. Emulation only: the heights are `build_traces`' over
/// the run, the rule `prove` uses; the same method reproduces the proved root's shape from
/// (step-0, step-1). The test profile's lists: 2 step programs, 3 keys (`vk_leaf`, `vk_t_leaf`,
/// `vk_int`). Before phase 4 the fixed point was level 3, a third program `T_FIX_TEST` with its own
/// key `vk_fix` (docs/08 §5); phase 4 (2026-10-09, the Merkle spans; ruling 10) re-recorded it:
/// level 3 → level 2, and `T_FIX_TEST`, `vk_fix` and `step_fix_cpu_rows` are dropped.
#[test]
fn the_step_program_at_the_roots_shape_is_rv32t_int_the_fixed_point() {
    let t = test_tree();
    let int_run = emulate_step(&t.s_step, &t.t_int, &t.steps[0], &t.steps[1], B).expect("rv32t_int accepts the steps");
    assert_eq!(emulated_shape(&t.t_int, &int_run).header_words(), t.s_root.header_words(),
        "the emulated shape method reproduces the proved root's");

    let t_root = Arc::new(verify_rv32t(&t.s_root, Checkpoints::Off).program);
    assert_eq!(t_root.digest(), t.t_int.digest(), "the step program at S_root is rv32t_int itself");
    assert_eq!(randprotocol_rvm::programs::digest_hex(&t_root), T_INT_TEST, "the fixed-point step program at S_root");
    let exec = emulate_step(&t.s_root, &t_root, &t.root, &t.root, B).expect("rv32t_int accepts two roots");
    let vk_int = inner_vk_digest(&t.s_root, &RvmKey::of(P, &t.s_root));
    assert_eq!(exec.public, host_step(&vk_int, B, &t.root, &t.root), "it publishes vk_int, the root's key");
    let s_next = emulated_shape(&t_root, &exec);
    eprintln!("TREE_TEST_FIX rows {} tier {} S_next {:?}", exec.cpu_rows(), s_next.tier, u64s(&s_next.header_words()));
    assert!(s_next.same_step_words(&t.s_root), "level 2 is a fixed point: {:?} vs {:?}", s_next.header_words(), t.s_root.header_words());
    assert_eq!(verify_rv32t(&s_next, Checkpoints::Off).program.digest(), t.t_int.digest(),
        "the program for its own proofs is itself");
    assert_eq!(inner_vk_digest(&s_next, &RvmKey::of(P, &s_next)), pinned_key("vk_int"),
        "the key of the fixed-point program's own proofs is vk_int (children of levels ≥ 3)");
}

/// Review Focus 1 (R5, second half): children of a foreign program with identical shape words,
/// under that program's honest cap, pass every in-program check. The step publishes the key it
/// checked against, and the chain's recompute with the pinned `vk_leaf` refuses it. The children's
/// digests equal the honest leaf's (the same run), so `vk_c` is the only difference.
#[test]
fn a_foreign_program_child_pair_passes_in_program_and_fails_the_root_recompute() {
    let (l, t) = (leaves(), test_tree());
    assert!(t.s_foreign.same_step_words(&l.shape));
    assert_eq!(t.foreign.public_values, l.proofs[0].public_values, "the same run publishes the same digest");
    let step = rv32t_leaf(&l.shape, Checkpoints::Off).program;
    let exec = emulate_step(&t.s_foreign, &step, &t.foreign, &t.foreign, B).expect("accepted in-program");
    let vk_foreign = inner_vk_digest(&t.s_foreign, &RvmKey::of(P, &t.s_foreign));
    let vk_leaf = inner_vk_digest(&l.shape, &l.key);
    assert_ne!(vk_foreign, vk_leaf);
    assert_eq!(exec.public, host_step(&vk_foreign, B, &t.foreign, &t.foreign), "it publishes the key it checked against");
    assert_ne!(exec.public, host_step(&vk_leaf, B, &t.foreign, &t.foreign), "the chain's recompute refuses it (Task 2: TreeRootDigest)");
}

/// The two step programs' digests at the test-profile shapes (M4). History: first pinned by tree
/// Task 1b. Phase 4 (2026-10-09, the Merkle spans) re-recorded `T_LEAF_TEST`: 2c586636… → d8d558ee….
/// Phase 5 (2026-10-12, S6a/S2b/S4a/S1b) re-recorded `T_LEAF_TEST`: d8d558ee… → af535052… (the same
/// digest `the_tree_step_builds_under_the_replays_loop_invariant` pins, measured there without
/// fixtures). `T_INT_TEST` below is NOT re-recorded: it needs the fixture-gated `test_tree()`.
const T_LEAF_TEST: &str = "af535052d2df18b5e313a6f0c2e412456d059d5f602d569989ad1b2b69e90cac";
/// Phase 4 (2026-10-09, the Merkle spans) re-recorded `T_INT_TEST`: 04b16771… → a222637e….
const T_INT_TEST: &str = "a222637e1eb9333b16b820bbacceaac9ea0e5d4cebfc5379d170796a2ac6dc62";

#[test]
fn the_test_tree_program_digests_are_pinned() {
    let t = test_tree();
    let (a, b) = (randprotocol_rvm::programs::digest_hex(&t.t_leaf), randprotocol_rvm::programs::digest_hex(&t.t_int));
    eprintln!("TREE_TEST_DIGESTS t_leaf {a} t_int {b}");
    assert_ne!(a, b, "two programs");
    assert_eq!(a, T_LEAF_TEST, "rv32t_leaf at the test leaf shape");
    assert_eq!(b, T_INT_TEST, "rv32t_int at the test step shape");
}

// ── Task 2: verify_tree, the per-level key list, the prover side's refusals ──────────────────

use randprotocol_rvm::aggregate::{aggregate_tree, tree_root_digest, verify_tree, AggregateError, TreeKeys, TreeShapes, VerifyTreeError};
use randprotocol_rvm::shape::RvmHeights;

/// The first `n` covered bundles' public values, in cover order.
fn covered(n: usize) -> Vec<Vec<u64>> {
    leaves().bundles[..n].iter().map(|b| b.public_values.clone()).collect()
}

/// A key digest pinned in `tests/pins.json`'s `tree_test` block as four canonical u64 limbs
/// (`{name}_0..3`; docs/08 §5 prints the same digests in hex).
fn pinned_key(name: &str) -> [F; 4] {
    std::array::from_fn(|k| F::from_u64(common::pin_u64("tree_test", &format!("{name}_{k}"))))
}

/// The test profile's three keys (R2 amended): `vk_leaf`, then the step list `[vk_t_leaf, vk_int]`,
/// the last repeating, all from `tree_test`'s pins, each computed from the proved shapes and held
/// to its pin. Phase 4 (2026-10-09, the Merkle spans; ruling 10) re-recorded it: four keys → three
/// (`vk_fix` dropped: the fixed point is level 2, so `vk_int` repeats).
fn test_keys() -> TreeKeys {
    let (l, t) = (leaves(), test_tree());
    let keys = TreeKeys { vk_leaf: pinned_key("vk_leaf"), step_keys: vec![pinned_key("vk_t_leaf"), pinned_key("vk_int")] };
    assert_eq!(inner_vk_digest(&l.shape, &l.key), keys.vk_leaf, "vk_leaf, the test leaf's key");
    assert_eq!(inner_vk_digest(&t.s_step, &RvmKey::of(P, &t.s_step)), keys.step_keys[0], "vk_t_leaf, S_T's key");
    assert_eq!(inner_vk_digest(&t.s_root, &RvmKey::of(P, &t.s_root)), keys.step_keys[1], "vk_int, S_root's key");
    keys
}

/// A rVM proof's independent copy (`Proof` has no `Clone`).
fn copy(p: &Proof) -> Proof {
    postcard::from_bytes::<Proof>(&p.to_bytes()).unwrap()
}

/// The proved depth-2 test tree verifies through the chain-facing call, returning the four
/// covered bundles' `OUT0..7` in cover order.
#[test]
fn verify_tree_accepts_the_test_tree() {
    let (l, t) = (leaves(), test_tree());
    let outs = verify_tree(&Machine::new(P), &t.t_int, &t.root, &l.inner, &covered(4), B, 1, 2, &test_keys())
        .expect("the depth-2 test tree verifies");
    assert_eq!(outs.len(), 4);
    for (j, out) in outs.iter().enumerate() {
        let want: [u32; 8] = std::array::from_fn(|k| u32::try_from(l.bundles[j].public_values[randprotocol_zkvm::tables::cpu::pv::OUT0 + k]).unwrap());
        assert_eq!(*out, want, "bundle {j}");
    }
    // A depth-1 tree is a step: step 0 over bundles 0 and 1 under `rv32t_leaf`.
    let outs1 = verify_tree(&Machine::new(P), &t.t_leaf, &t.steps[0], &l.inner, &covered(2), B, 1, 1, &test_keys())
        .expect("a level-1 step is a depth-1 tree");
    assert_eq!(outs1[..], outs[..2]);
}

/// Every refusal by name, each before `verify_n` builds a key except the last: a count that is
/// not L·2^d, depth 0, a level with no pinned key, a malformed covered run, a swapped cover
/// order, another binding, a leaf presented as a depth-1 root (a flat proof as a tree), a level
/// recomputed under another level's key, and the root verified as the wrong program.
#[test]
fn verify_tree_names_every_refusal() {
    let (l, t) = (leaves(), test_tree());
    let m = Machine::new(P);
    let k = test_keys();
    let c4 = covered(4);
    let vt = |prog: &Program, proof: &Proof, cov: &[Vec<u64>], b: &[u32; 8], depth: u32, keys: &TreeKeys| {
        verify_tree(&m, prog, proof, &l.inner, cov, b, 1, depth, keys)
    };
    assert!(matches!(vt(&t.t_int, &t.root, &c4[..3], B, 2, &k), Err(VerifyTreeError::TreeLayout { covers: 3, leaf_size: 1 })));
    assert!(matches!(verify_tree(&m, &t.t_int, &t.root, &l.inner, &c4, B, 0, 2, &k), Err(VerifyTreeError::TreeLayout { covers: 4, leaf_size: 0 })));
    assert!(matches!(vt(&t.t_int, &t.root, &c4[..1], B, 0, &k), Err(VerifyTreeError::TreeDepth { depth: 0 })));
    assert!(matches!(vt(&t.t_int, &t.root, &c4, B, 64, &k), Err(VerifyTreeError::TreeDepth { depth: 64 })));
    let no_steps = TreeKeys { vk_leaf: k.vk_leaf, step_keys: vec![] };
    assert!(matches!(vt(&t.t_int, &t.root, &c4, B, 2, &no_steps), Err(VerifyTreeError::TreeKeyPin { level: 2 })),
        "level 2 publishes a step key and none is pinned");
    let mut short = c4.clone();
    short[2].pop();
    assert!(matches!(vt(&t.t_int, &t.root, &short, B, 2, &k), Err(VerifyTreeError::CoveredPublicValues { index: 2 })));
    let mut aliased = c4.clone();
    aliased[1][0] += F::ORDER_U64; // the same field element, non-canonically
    assert!(matches!(vt(&t.t_int, &t.root, &aliased, B, 2, &k), Err(VerifyTreeError::CoveredPublicValues { index: 1 })),
        "a non-canonical word is refused, not reduced");
    let mut wide_out = c4.clone();
    wide_out[3][randprotocol_zkvm::tables::cpu::pv::OUT0 + 5] = u32::MAX as u64 + 1; // canonical, but not a u32
    assert!(matches!(vt(&t.t_int, &t.root, &wide_out, B, 2, &k), Err(VerifyTreeError::CoveredPublicValues { index: 3 })),
        "an OUT word past u32::MAX is refused, not truncated");
    assert!(matches!(verify_tree(&m, &t.t_int, &t.root, &l.inner, &c4, B, usize::MAX, 1, &k),
        Err(VerifyTreeError::TreeLayout { covers: 4, leaf_size: usize::MAX })), "L·2^d overflows: refused, no panic");
    assert!(matches!(verify_tree(&m, &t.t_int, &t.root, &l.inner, &c4, B, 1 << 40, 63, &k),
        Err(VerifyTreeError::TreeLayout { covers: 4, .. })), "L·2^63 overflows: refused, no panic");
    let wraps_to_4 = (1usize << 62) + 1; // 4·(2^62 + 1) = 2^64 + 4 ≡ 4: an unchecked product would accept the layout
    assert!(matches!(verify_tree(&m, &t.t_int, &t.root, &l.inner, &c4, B, wraps_to_4, 2, &k),
        Err(VerifyTreeError::TreeLayout { covers: 4, .. })), "L·2^d wrapping onto the cover count is refused");
    let swapped = vec![c4[1].clone(), c4[0].clone(), c4[2].clone(), c4[3].clone()];
    assert!(matches!(vt(&t.t_int, &t.root, &swapped, B, 2, &k), Err(VerifyTreeError::TreeRootDigest)));
    let pairs_swapped = vec![c4[2].clone(), c4[3].clone(), c4[0].clone(), c4[1].clone()];
    assert!(matches!(vt(&t.t_int, &t.root, &pairs_swapped, B, 2, &k), Err(VerifyTreeError::TreeRootDigest)));
    assert!(matches!(vt(&t.t_int, &t.root, &c4, &[7; 8], 2, &k), Err(VerifyTreeError::TreeRootDigest)));
    assert!(matches!(vt(&t.t_leaf, &l.proofs[0], &c4[..2], B, 1, &k), Err(VerifyTreeError::TreeRootDigest)),
        "a flat proof (a leaf) is not a depth-1 tree");
    assert!(matches!(vt(&t.t_int, &t.root, &c4, B, 1, &TreeKeys { vk_leaf: k.vk_leaf, step_keys: k.step_keys.clone() }), Err(VerifyTreeError::TreeLayout { covers: 4, leaf_size: 1 })),
        "the root presented at the wrong depth");
    let wrong_level2 = TreeKeys { vk_leaf: k.vk_leaf, step_keys: vec![k.step_keys[1], k.step_keys[1]] };
    assert!(matches!(vt(&t.t_int, &t.root, &c4, B, 2, &wrong_level2), Err(VerifyTreeError::TreeRootDigest)),
        "level 2 recomputed under level 3's key (vk_int, the last entry repeating)");
    let wrong_level1 = TreeKeys { vk_leaf: k.step_keys[0], step_keys: k.step_keys.clone() };
    assert!(matches!(vt(&t.t_int, &t.root, &c4, B, 2, &wrong_level1), Err(VerifyTreeError::TreeRootDigest)),
        "level 1 recomputed under level 2's key");
    assert!(matches!(vt(&t.t_leaf, &t.root, &c4, B, 2, &k), Err(VerifyTreeError::Verify(_))),
        "the root verified as rv32t_leaf's proof");
}

/// Review Focus 4 (R2/R3 amended): level 1 publishes `vk_leaf` and level j ≥ 2 publishes
/// `step_keys[min(j − 2, len − 1)]`, the last entry repeating. A host-only recompute at depth 5
/// over a three-entry list, against a hand-rolled one with distinct dummy keys: levels 4 and 5
/// both take the last entry. Appending a copy of the last entry moves nothing (it is what
/// repeating means); swapping any two of the four keys moves the root.
#[test]
fn verify_tree_selects_the_per_level_key_with_the_last_entry_repeating() {
    let l = leaves();
    let depth = 5u32;
    let n = 1usize << depth;
    let pvs: Vec<Vec<u64>> = (0..n as u64).map(|j| (0..35).map(|k| 1000 * j + k).collect()).collect();
    let dummy = |x: u64| -> [F; 4] { std::array::from_fn(|i| F::from_u64(10 * x + i as u64)) };
    let keys = TreeKeys { vk_leaf: dummy(1), step_keys: vec![dummy(2), dummy(3), dummy(4)] };
    assert_eq!(
        (1..=6).map(|j| keys.at_level(j).unwrap()).collect::<Vec<_>>(),
        vec![dummy(1), dummy(2), dummy(3), dummy(4), dummy(4), dummy(4)],
        "level j's key: vk_leaf, then the list from level 2, the last entry repeating"
    );
    assert_eq!(keys.at_level(0), None, "levels are 1-based");

    let leaf_d: Vec<[F; 4]> = pvs
        .iter()
        .map(|p| public_digest(&randprotocol_rvm::public_values::interface_words_bound(&l.inner.shape, &l.inner.key, B, std::slice::from_ref(p))))
        .collect();
    let step = |vk: [F; 4], a: [F; 4], b: [F; 4]| public_digest(&tree_step_words(&vk, B, &a, &b));
    let fold = |level: &[[F; 4]], vk: [F; 4]| -> Vec<[F; 4]> { level.chunks(2).map(|p| step(vk, p[0], p[1])).collect() };
    let mut level = leaf_d;
    for vk in [dummy(1), dummy(2), dummy(3), dummy(4), dummy(4)] {
        level = fold(&level, vk);
    }
    assert_eq!(level.len(), 1);
    let root = level[0];
    assert_eq!(tree_root_digest(&l.inner, &pvs, B, 1, depth, &keys).unwrap(), root, "the hand-rolled recompute");

    let longer = TreeKeys { vk_leaf: keys.vk_leaf, step_keys: vec![dummy(2), dummy(3), dummy(4), dummy(4)] };
    assert_eq!(tree_root_digest(&l.inner, &pvs, B, 1, depth, &longer).unwrap(), root, "an explicit repeat is the implicit one");
    let shorter = TreeKeys { vk_leaf: keys.vk_leaf, step_keys: vec![dummy(2), dummy(3)] };
    assert_ne!(tree_root_digest(&l.inner, &pvs, B, 1, depth, &shorter).unwrap(), root, "the repeat starts at the right level");

    let all = [dummy(1), dummy(2), dummy(3), dummy(4)];
    for i in 0..4 {
        for j in i + 1..4 {
            let mut s = all;
            s.swap(i, j);
            let swapped = TreeKeys { vk_leaf: s[0], step_keys: s[1..].to_vec() };
            assert_ne!(tree_root_digest(&l.inner, &pvs, B, 1, depth, &swapped).unwrap(), root, "swapping keys {i} and {j}");
        }
    }
    // L = 2 at depth 4 covers the same 32 runs: another layout, another root.
    assert_ne!(tree_root_digest(&l.inner, &pvs, B, 2, 4, &keys).unwrap(), root);
    // An entry no level reads is inert: depth 2 reads vk_leaf and step_keys[0] only.
    let d2 = tree_root_digest(&l.inner, &pvs[..4], B, 1, 2, &keys).unwrap();
    for tail in [vec![dummy(2)], vec![dummy(2), dummy(9)], vec![dummy(2), dummy(3), dummy(9)]] {
        assert_eq!(tree_root_digest(&l.inner, &pvs[..4], B, 1, 2, &TreeKeys { vk_leaf: keys.vk_leaf, step_keys: tail }).unwrap(), d2,
            "an unused trailing key leaves the root unchanged");
    }
}

/// The real test tree's depth-2 root does not read `vk_int`: replacing the unused
/// tail of the pinned list leaves `verify_tree`'s recompute, and its acceptance, unchanged.
#[test]
fn an_unused_trailing_key_leaves_the_test_roots_digest_unchanged() {
    let (l, t) = (leaves(), test_tree());
    let k = test_keys();
    let honest = tree_root_digest(&l.inner, &covered(4), B, 1, 2, &k).unwrap();
    let junk = [F::from_u64(424242); 4];
    for tail in [vec![k.step_keys[0], k.step_keys[1], junk], vec![k.step_keys[0], junk, junk], vec![k.step_keys[0]]] {
        let other = TreeKeys { vk_leaf: k.vk_leaf, step_keys: tail };
        assert_eq!(tree_root_digest(&l.inner, &covered(4), B, 1, 2, &other).unwrap(), honest);
    }
    assert_eq!(u64s(&honest), t.root.public_values, "the recompute is the root's published digest");
}

/// What the node rebuilds from a genesis (`TreeShapes::build` over the pinned heights: the leaf's,
/// then the per-level step list `[S_T, S_root]`) is the test tree's own programs and keys, the
/// second entry the fixed point (`T_INT_TEST`, `vk_int`). Phase 4 (2026-10-09, the Merkle spans;
/// ruling 10) re-recorded it: `[S_T, S_root, S_root]` with `T_FIX_TEST`/`vk_fix` → `[S_T, S_root]`;
/// the list that is not a fixed point is now `[S_T]` alone.
#[test]
fn the_tree_shapes_rebuild_the_test_tree_programs_and_keys() {
    let (l, t) = (leaves(), test_tree());
    let h_leaf = RvmHeights::of_proof(&l.proofs[0]);
    assert_eq!(h_leaf, l.shape.heights());
    assert_eq!(RvmShape::try_of_heights(P, &l.program, h_leaf).unwrap(), l.shape, "the heights round-trip");
    let (h_t, h_root) = (RvmHeights::of_proof(&t.steps[0]), RvmHeights::of_proof(&t.root));
    let s = TreeShapes::build(P, &l.inner, h_leaf, &[h_t, h_root]).unwrap();
    let digests: Vec<String> = s.steps.iter().map(|x| randprotocol_rvm::programs::digest_hex(&x.program)).collect();
    assert_eq!(digests, [T_LEAF_TEST, T_INT_TEST], "the per-level step programs");
    assert_eq!(s.leaf, l.shape);
    assert_eq!(s.steps[0], t.s_step);
    assert_eq!(s.steps[1], t.s_root);
    assert!(s.fixed_point(), "the last entry's program verifies its own proofs");
    assert_eq!(s.keys(), test_keys());
    for (level, want) in [(1, T_LEAF_TEST), (2, T_INT_TEST), (3, T_INT_TEST), (9, T_INT_TEST)] {
        assert_eq!(randprotocol_rvm::programs::digest_hex(s.root_program(level).unwrap()), want, "the root program at depth {level}");
    }
    for (level, want) in [(1, &s.leaf), (2, &s.steps[0]), (3, &s.steps[1]), (4, &s.steps[1]), (9, &s.steps[1])] {
        assert!(std::ptr::eq(s.child_at(level).unwrap(), want), "the child shape at level {level}");
    }
    assert!(s.child_at(0).is_none() && s.step_at(0).is_none() && s.root_program(0).is_none(), "levels are 1-based");
    let one = TreeShapes::build(P, &l.inner, h_leaf, &[h_t]).unwrap();
    assert!(!one.fixed_point(), "rv32t_leaf's proofs are not of the shape it was built for: [S_T] alone is not a fixed point");
    assert!(matches!(TreeShapes::build(P, &l.inner, h_leaf, &[]), Err(randprotocol_rvm::shape::ShapeError::EmptyTreeSteps)));
    // M-3: an empty list put together by hand (the fields are public) answers None, never panics,
    // as `TreeKeys::at_level` does; `aggregate_tree` refuses it before proving.
    let empty = TreeShapes { leaf: s.leaf.clone(), steps: vec![] };
    assert!(std::ptr::eq(empty.child_at(1).unwrap(), &empty.leaf));
    assert!(empty.step_at(1).is_none() && empty.child_at(2).is_none() && empty.root_program(1).is_none());
    assert!(!empty.fixed_point());
    let bundles: Vec<BundleProof> = (0..2).map(|k| postcard::from_bytes(&postcard::to_allocvec(&l.bundles[k]).unwrap()).unwrap()).collect();
    assert!(matches!(aggregate_tree(&Machine::new(P), &l.inner, &empty, &bundles, B, 1), Err(AggregateError::TreeShape { level: 1 })));
}

/// The test tree's genesis section as `rand-node genesis --aggregation-tree` reads it (review
/// m2): the two-level list `[S_T, S_root]` (`max_depth` 2, no fixed point needed) that the node's
/// `agg_executor` tests build, printed as `TreeConfig` JSON by `common::aggregation_tree_json` and
/// held to `tests/tree-test-genesis.json` — the file the node deserializes into its own
/// `TreeConfig` (fullnode `the_printed_tree_section_is_a_tree_config`). A missing file is written
/// (the measurement run, as `pins.json`); every later run is a diff against it.
#[test]
fn the_test_tree_genesis_section_prints_as_the_nodes_tree_config() {
    let (l, t) = (leaves(), test_tree());
    let (h_leaf, h_t, h_root) = (RvmHeights::of_proof(&l.proofs[0]), RvmHeights::of_proof(&t.steps[0]), RvmHeights::of_proof(&t.root));
    let s = TreeShapes::build(P, &l.inner, h_leaf, &[h_t, h_root]).unwrap();
    let k = s.keys();
    let limbs = |d: [F; 4]| d.map(|f| f.as_canonical_u64());
    let steps: Vec<_> = s.steps.iter().enumerate().map(|(i, x)| (x.heights(), limbs(x.program.digest()), limbs(k.step_keys[i]))).collect();
    let json = common::aggregation_tree_json(P, &l.bundles[0], 1, 2, &h_leaf, limbs(k.vk_leaf), &steps);
    println!("{json}");
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/tree-test-genesis.json");
    match std::fs::read_to_string(&path) {
        Ok(pinned) => assert_eq!(json, pinned, "the printed section moved; regenerate {} and re-vendor", path.display()),
        Err(_) => std::fs::write(&path, &json).expect("the pin file is writable"),
    }
    assert_eq!(limbs(k.vk_leaf), limbs(pinned_key("vk_leaf")));
    assert_eq!(steps[1].2, limbs(pinned_key("vk_int")), "level 2's key is vk_int");
}

/// `aggregate_tree`'s refusals that come before any proving: a count that is not L·2^d (d ≥ 1),
/// and a depth past a list whose last entry is not a fixed point (its program would not verify
/// the level below it). Phase 4 (2026-10-09, the Merkle spans; ruling 10) re-recorded the second
/// case: `[S_T, S_root]` is a fixed point since phase 4, so the non-fixed list is `[S_T]` alone,
/// refused at level 2 (was `[S_T, S_root]`, refused at level 3).
#[test]
fn aggregate_tree_refuses_a_bad_layout_and_a_depth_past_a_non_fixed_list_before_proving() {
    let (l, t) = (leaves(), test_tree());
    let m = Machine::new(P);
    let s = TreeShapes::build(P, &l.inner, RvmHeights::of_proof(&l.proofs[0]), &[RvmHeights::of_proof(&t.steps[0])]).unwrap();
    assert!(!s.fixed_point(), "[S_T] alone is not a fixed point");
    let bundle = |k: usize| postcard::from_bytes::<BundleProof>(&postcard::to_allocvec(&l.bundles[k % 4]).unwrap()).unwrap();
    let proofs = |n: usize| -> Vec<BundleProof> { (0..n).map(bundle).collect() };
    for (n, leaf_size) in [(0, 1), (1, 1), (3, 1), (4, 0), (6, 2), (2, 2), (12, 1)] {
        assert!(matches!(aggregate_tree(&m, &l.inner, &s, &proofs(n), B, leaf_size),
            Err(AggregateError::TreeLayout { covers, leaf_size: ls }) if covers == n && ls == leaf_size), "{n} proofs at L = {leaf_size}");
    }
    assert!(matches!(aggregate_tree(&m, &l.inner, &s, &proofs(4), B, 1), Err(AggregateError::TreeShape { level: 2 })),
        "depth 2 over a one-entry list that is not a fixed point");
    assert!(matches!(aggregate_tree(&m, &l.inner, &s, &proofs(8), B, 1), Err(AggregateError::TreeShape { level: 2 })),
        "depth 3 over the same list");
}

/// R5, second half, through the chain-facing call (deferred from Task 1b): a step over two
/// children of the foreign program (identical shape words, its own honest cap) is accepted
/// in-program and publishes `[vk_foreign ‖ 2 ‖ B ‖ D ‖ D]`. Presented as a depth-1 tree over the
/// bundle it covers twice, `verify_tree` with the pinned `vk_leaf` refuses it by name at the root
/// recompute, before any key is built, and the same recompute under `vk_foreign` is exactly what
/// it published (so `vk_c` is the only discriminator). No foreign step is proved (R7: in-suite
/// tests never prove a step): the presented proof is the honest step 0 carrying the foreign
/// step's emulated public values, which `verify_tree` reads before `verify_n`.
#[test]
fn a_foreign_program_child_pair_is_refused_by_verify_tree_at_the_root_digest() {
    let (l, t) = (leaves(), test_tree());
    let exec = emulate_step(&t.s_foreign, &t.t_leaf, &t.foreign, &t.foreign, B).expect("accepted in-program");
    let mut presented = copy(&t.steps[0]);
    presented.public_values = u64s(&exec.public);
    let cov = vec![l.bundles[0].public_values.clone(), l.bundles[0].public_values.clone()];
    let k = test_keys();
    let vk_foreign = inner_vk_digest(&t.s_foreign, &RvmKey::of(P, &t.s_foreign));
    assert_ne!(vk_foreign, k.vk_leaf);
    let under_foreign = TreeKeys { vk_leaf: vk_foreign, step_keys: k.step_keys.clone() };
    assert_eq!(tree_root_digest(&l.inner, &cov, B, 1, 1, &under_foreign).unwrap().to_vec(), exec.public,
        "it published the key it checked against");
    assert_ne!(tree_root_digest(&l.inner, &cov, B, 1, 1, &k).unwrap().to_vec(), exec.public,
        "the honest recompute (the pinned vk_leaf) is not what the foreign step published");
    assert!(matches!(verify_tree(&Machine::new(P), &t.t_leaf, &presented, &l.inner, &cov, B, 1, 1, &k), Err(VerifyTreeError::TreeRootDigest)),
        "the pinned vk_leaf refuses the foreign children");
}
