//! Tree aggregation, Task 0 (spec §5, ruling 5): measure before any program is built. One
//! production leaf (`rv32n` over L = 2 real bundle proofs) is proved on the 256 GB droplet. The
//! existing k = 1 self-verifier `rv32r`, with its cap baked, is then run over that leaf proof on
//! the 503 GB droplet: emulated first (the stop rule), then proved under the heap profiler. Every
//! run is logged under `docs/measurements/`. The numbers land in `tests/pins.json`'s
//! `tree_measure` block and `docs/08-tree-aggregation.md` §1–§2. The proving and real-leaf tests are
//! ignored and run on a droplet, one per process; the laptop's emulated-shape count is ignored too
//! (minutes), and so is Task 1a's production step count (`production_rv32t_rows_at_the_emulated_leaf_shape`).
//! Task 2 adds the production depth-2 tree (leaves 1–3, both `rv32t_leaf` steps, the `rv32t_int`
//! root through `verify_tree`, and the per-level genesis values), all ignored, for the 256 GB droplet.
//! Three tests run in-suite, in seconds: the accepting walk against the emulator, the looped walk
//! (`rv32t`'s) against the emulator, and the pinned band against the pinned emulated child.
mod common;
mod heap;

use heap::{gb, install, report, LIVE};
use randprotocol_zkvm::machine::{FriProfile, Proof};
use randprotocol_rvm::aggregate::{aggregate, aggregate_program, prove_tree_step, verify_aggregate, verify_tree, InnerVerifierKey, TreeShapes};
use randprotocol_rvm::dsl::Checkpoints;
use randprotocol_rvm::emulator::{execute, Execution};
use randprotocol_rvm::isa::Program;
use randprotocol_rvm::machine::{Machine, Tier};
use randprotocol_rvm::programs::{rv32t_leaf, verify_rv32r, verify_rv32t, VerifierProgram, TREE_ARITY};
use randprotocol_rvm::shape::{inner_vk_digest, InnerKey, InnerShape, RvmHeights, RvmKey, RvmShape};
use randprotocol_rvm::witness::WitnessTape;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::Instant;

const MAX_CYCLES: usize = 1 << 24;
/// The production leaf size (spec §2, ruling 6).
const L: usize = 2;
const P: FriProfile = FriProfile::Production;
/// Spec §5's stop rule: one child verification above this, and the k = 2 step exceeds tier 22.
const STOP_CHILD_ROWS: usize = 1_500_000;
/// The interior step's overhead O = step rows − 2C, measured by Task 1a at the test profile
/// (`tree_test.step_overhead`; spec §3 projected +300). It is signed: the step's own fixed rows
/// (its preamble, the loop's absorbs and back edge, the final permutation) are outweighed by what
/// each loop pass does *not* run that `rv32r`'s C counts (the baked cap's constants, the binding
/// read) and by the loop body's different register allocation (docs/08 §2).
fn o_measured() -> i64 {
    common::pin_i64("tree_test", "step_overhead")
}

/// M5's band for the interior step over a child of `child` rows: `(2C + O, floor(0.85·(2C + O)),
/// ceil(1.15·(2C + O)))`, in integers.
fn band(child: usize, o: i64) -> (usize, usize, usize) {
    let step = usize::try_from(2 * child as i64 + o).expect("a step has rows");
    (step, 85 * step / 100, (115 * step).div_ceil(100))
}

/// `$RECURSION_FIXTURES/tree/{name}.rvmproof`: postcard `randprotocol_rvm::machine::Proof` bytes.
fn tree_file(name: &str) -> std::path::PathBuf {
    common::cache_dir().join("tree").join(format!("{name}.rvmproof"))
}

/// Production bundle fixtures `k0..k0 + n` (cached; `common::bundle_proof_at`).
fn bundles(k0: usize, n: usize) -> Vec<Proof> {
    let m = randprotocol_zkvm::machine::Machine::new(P);
    (k0..k0 + n).map(|k| common::bundle_proof_at(&m, P, k).proof).collect()
}

fn inner(p: &Proof) -> InnerVerifierKey {
    let shape = InnerShape::of(P, p.tier, p.program_log_height, p.input_log_height, p.keccak_log_height,
        p.sha256_log_height, p.public_log_height, p.mem_log_height);
    let key = InnerKey::of(P, &shape);
    InnerVerifierKey { shape, key }
}

/// A cached tree proof, re-verified on load at its canonical `n`: a stale file is a loud
/// failure, never a vacuous pass.
fn load(name: &str, program: &Program, n: u64) -> randprotocol_rvm::machine::Proof {
    let path = tree_file(name);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|_| panic!("{} is missing: run the test that writes it (docs/08 §1) and copy the file here", path.display()));
    let p: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).expect("a cached rVM proof decodes");
    Machine::new(P).verify_n(program, &p, n).expect("the cached proof verifies");
    p
}

fn save(name: &str, p: &randprotocol_rvm::machine::Proof) {
    let path = tree_file(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, p.to_bytes()).unwrap();
}

fn heights(what: &str, p: &randprotocol_rvm::machine::Proof) {
    println!("== heights {what}: tier {} reg {} ram {} poseidon2 {} reduce {}", p.tier.0, p.reg_log_height,
        p.ram_log_height, p.poseidon2_log_height, p.reduce_log_height);
}

/// Leaf `k` of the production tree: `rv32n` over fixtures `2k`, `2k + 1`, emulated (M1), proved,
/// verified, saved as `tree/Production-leaf-{k}`. Task 0 runs k = 0; Task 2 runs k = 1, 2, 3.
/// Phase 4 (2026-10-09, the Merkle spans) re-recorded the leaf's tier: 21 → 20 (1 171 511 → 632 175
/// rows, emulated: `tests/aggregate.rs`'s B3 at N = 2).
fn prove_leaf(k: usize) {
    let proofs = bundles(L * k, L);
    let vk = inner(&proofs[0]);
    let program = aggregate_program(&vk);
    let tape = WitnessTape::build_n(P, &vk.shape, &vk.key, &proofs, &common::TEST_BINDING).unwrap();
    let rows = execute(&program, &tape.words, MAX_CYCLES).expect("the leaf emulates").cpu_rows();
    assert_eq!(Tier::for_cycles(rows), Some(Tier(20)), "the production L = 2 leaf is tier 20 since phase 4 ({rows} rows; docs/02 B3: 632 175, 1 171 511 at tier 21 after phase 3)");
    println!("leaf {k}: program built, {rows} rows emulated, live {:.2} GB", gb(LIVE.load(Relaxed)));
    let t0 = install();
    let m = Machine::new(P);
    let t = Instant::now();
    let a = aggregate(&m, &vk, &proofs, &common::TEST_BINDING, None).expect("the production leaf proves");
    let prove_s = t.elapsed().as_secs_f64();
    let tv = Instant::now();
    verify_aggregate(&m, &program, &a, &common::TEST_BINDING).expect("the production leaf verifies");
    println!("verify {:.2} s", tv.elapsed().as_secs_f64());
    save(&format!("Production-leaf-{k}"), &a.proof);
    heights(&format!("leaf {k}"), &a.proof);
    report(&format!("tree leaf {k} L=2 (production)"), t0, rows, a.proof.tier, a.proof.size(), prove_s);
}

/// Task 0, run 1 (the 256 GB droplet).
#[test]
#[ignore = "tree Task 0: the production rv32n leaf at L = 2 (632 175 rows, tier 20 since phase 4; 1 171 511 rows, tier 21 after phase 3, 122-142 GB projected then at rate 1/4, docs/07 §4) — the 256 GB droplet"]
fn production_leaf_l2() {
    prove_leaf(0);
}

/// `rv32r` at the leaf's own declared shape over the cached leaf, emulated. Returns the program,
/// the tape, the rows, and C: the child verification, which is every row except phase 8 (the
/// interface list), i.e. what one iteration of `rv32t`'s loop body costs, give or take the
/// baked-cap stores.
fn rv32r_over_leaf() -> (VerifierProgram<RvmShape>, WitnessTape, usize, usize) {
    let proofs = bundles(0, L);
    let leaf_program = Arc::new(aggregate_program(&inner(&proofs[0])));
    let leaf = load("Production-leaf-0", &leaf_program, L as u64);
    let shape = RvmShape::of_proof(P, &leaf_program, &leaf);
    let key = RvmKey::of(P, &shape);
    let vp = verify_rv32r(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_for_with_binding(P, &shape, &key, &leaf, &common::TEST_BINDING).unwrap();
    let rows = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32r accepts the production leaf").cpu_rows();
    let phase8: usize = vp.phase_rows.iter().filter(|(n, _)| n.starts_with("phase 8")).map(|(_, r)| *r).sum();
    (vp, tape, rows, rows - phase8)
}

/// Task 0, run 2 (the 503 GB droplet, minutes): the stop rule, before anything is proved.
#[test]
#[ignore = "tree Task 0: rv32r over the production leaf, emulated — spec §5's stop rule; needs tree/Production-leaf-0.rvmproof"]
fn production_rv32r_over_the_leaf_emulates() {
    let (vp, _tape, rows, child) = rv32r_over_leaf();
    println!("== rv32r over the production leaf: {rows} rows, tier {:?}, child {child} rows, program {} instrs",
        Tier::for_cycles(rows), vp.program.instrs.len());
    println!("-- phases {:?}", vp.phase_rows);
    assert!(child <= STOP_CHILD_ROWS,
        "STOP (spec §5): one child verification is {child} rows, above {STOP_CHILD_ROWS}: the k = 2 step exceeds tier 22. \
         Record it in docs/08 §2 and stop for a decision (k = 1 chains, a bigger tier, or the memory track first)");
}

/// Task 0, run 3 (the 503 GB droplet, hours): the same program proved, under the heap profiler.
#[test]
#[ignore = "tree Task 0: rv32r over the production leaf, proved (347 673 rows, tier 19 since phase 4; 648 910 rows, tier 20 before, 64-75 GB projected then at rate 1/4, docs/07 §4) — the 256 GB droplet"]
fn production_rv32r_over_the_leaf_proves() {
    let (vp, tape, rows, child) = rv32r_over_leaf();
    assert!(child <= STOP_CHILD_ROWS, "the stop rule holds before anything is proved");
    let t0 = install();
    let m = Machine::new(P);
    let t = Instant::now();
    let (proof, exec) = m.prove(&vp.program, &tape.words, None).expect("rv32r over the leaf proves");
    let prove_s = t.elapsed().as_secs_f64();
    assert_eq!(exec.cpu_rows(), rows, "the proved run is the emulated run");
    let tv = Instant::now();
    m.verify(&vp.program, &proof).expect("rv32r's proof verifies (straight-line: n = 1)");
    println!("verify {:.2} s", tv.elapsed().as_secs_f64());
    heights("rv32r over the leaf", &proof);
    report("tree child: rv32r over the production leaf", t0, rows, proof.tier, proof.size(), prove_s);
}

/// The pins against a fresh emulation (production, minutes; needs the cached leaf).
#[test]
#[ignore = "tree Task 0: the tree_measure pins against a fresh emulation; needs tree/Production-leaf-0.rvmproof"]
fn the_tree_measure_pins_are_the_emulated_rows() {
    let (_vp, _tape, rows, child) = rv32r_over_leaf();
    assert_eq!(rows, common::pin("tree_measure", "rv32r_cpu_rows"));
    assert_eq!(child, common::pin("tree_measure", "child_cpu_rows"));
}

/// The production leaf's declared shape, by emulation alone (no proof): `rv32n` over fixtures 0
/// and 1 executed, and the traces `Machine::prove` would commit built from that execution
/// (`machine::build_traces`, the prover's own height rule), so every declared height is the
/// one an honest leaf proof carries. Returns the leaf program, its rows and the shape.
fn emulated_leaf_shape() -> (Arc<Program>, usize, RvmShape) {
    let proofs = bundles(0, L);
    let vk = inner(&proofs[0]);
    let program = Arc::new(aggregate_program(&vk));
    let tape = WitnessTape::build_n(P, &vk.shape, &vk.key, &proofs, &common::TEST_BINDING).unwrap();
    let exec = execute(&program, &tape.words, MAX_CYCLES).expect("the leaf emulates");
    let rows = exec.cpu_rows();
    let tier = Tier::for_cycles(rows).expect("the leaf has a tier");
    let t = randprotocol_rvm::machine::build_traces(&program, &exec, tier).expect("the leaf's traces build");
    let canonical = randprotocol_rvm::machine::canonical_reduce_log_height(&program, L as u64);
    println!("== emulated leaf: {rows} rows, tier {}, program {} instrs (program table 2^{}), heights reg {} ram {} poseidon2 {} reduce {} (canonical at n = {L}: {canonical:?}); trace heights {:?}, permutations {}",
        tier.0, program.instrs.len(), randprotocol_rvm::machine::program_log_height(program.instrs.len()),
        t.reg_log_height, t.ram_log_height, t.poseidon2_log_height, t.reduce_log_height,
        t.heights(), exec.permutations());
    assert_eq!(canonical, Some(t.reduce_log_height), "an honest leaf declares the canonical reduce height verify_n(_, _, {L}) demands");
    let shape = RvmShape::of(P, &program, tier, t.reg_log_height, t.ram_log_height, t.poseidon2_log_height, t.reduce_log_height);
    (program, rows, shape)
}

/// The rows of `program`'s one accepting run, and of each named phase, by walking its control
/// flow without data. The walk admits exactly one control construct, the DSL's assertion
/// (`Builder::assert_eq`/`assert_zero`): a `JEQ` whose target is `pc + 2`, over a one-row trap
/// (`INV r1, r0`, the inverse of zero). An accepting run takes every such `JEQ` (falling through
/// executes the trap, an error, not a shorter trace), so it visits every instruction except the
/// traps, once each, in order, to its `HALT` — one cpu row per visit (`emulator::execute`).
/// Any other jump (`JMP`, `JNE`: a counted loop or `if_eq`, whose path is data or a counter)
/// panics: the walk claims nothing about a program it cannot see through.
fn accepting_rows(program: &Program, phase_rows: &[(&'static str, usize)]) -> (usize, Vec<(&'static str, usize)>) {
    use p3_field::PrimeField64;
    use randprotocol_rvm::isa::Op;
    let instrs = &program.instrs;
    let mut visited = vec![false; instrs.len()];
    let mut pc = 0usize;
    loop {
        let ins = instrs[pc];
        visited[pc] = true;
        match ins.op {
            Op::Halt => break,
            Op::Jmp | Op::Jne => panic!("pc {pc}: {:?} — not an assertion; the walk does not apply", ins.op),
            Op::Jeq => {
                let target = ins.b.as_canonical_u64() as usize;
                let trap = instrs[pc + 1];
                assert!(target == pc + 2 && trap.op == Op::Inv && trap.rd == 1 && trap.ra == 0,
                    "pc {pc}: a JEQ that is not an assertion over a one-row trap");
                pc = target;
            }
            _ => pc += 1,
        }
    }
    let mut phases = Vec::new();
    let mut at = 0;
    for &(name, n) in phase_rows {
        phases.push((name, visited[at..at + n].iter().filter(|v| **v).count()));
        at += n;
    }
    (visited.iter().filter(|v| **v).count(), phases)
}

/// [`accepting_rows`] through `rv32t`'s two kinds of data-free control flow. Besides the DSL's
/// assertion, the walk admits:
/// - exactly one *backward* `JNE`, the counted loop's back edge (`Builder::counted_loop_mem` with
///   the compile-time count `TREE_ARITY`): taken `trips − 1` times, then fallen through;
/// - *forward* `JNE`s, which in `rv32t` are only `hash::absorb_staged`'s `if_eq(cursor, full)`.
///   The cursor is a function of the absorb schedule alone (it starts at rate lane 1, behind the
///   count word, and each absorb advances it by one), so the `k`-th forward `JNE` executed falls
///   into its body (the deferred permutation) exactly when `(1 + k) mod RATE = 0`, and jumps over
///   it otherwise.
///
/// The count is then the program's alone. Rows are visits, one cpu row each; phases count visits.
/// `the_looped_walk_counts_what_rv32t_executes` holds the walk, schedule included, to the
/// emulator. `JMP` or a second loop panics.
fn accepting_rows_looped(program: &Program, phase_rows: &[(&'static str, usize)], trips: usize) -> (usize, Vec<(&'static str, usize)>) {
    use p3_field::PrimeField64;
    use randprotocol_rvm::dsl::hash::RATE;
    use randprotocol_rvm::isa::Op;
    assert!(trips >= 1, "a counted loop runs at least once");
    let instrs = &program.instrs;
    let mut visits = vec![0usize; instrs.len()];
    let mut back_edge: Option<usize> = None;
    let mut taken = 0usize;
    let mut absorbs = 0usize;
    let mut pc = 0usize;
    loop {
        let ins = instrs[pc];
        visits[pc] += 1;
        match ins.op {
            Op::Halt => break,
            Op::Jmp => panic!("pc {pc}: JMP — not an assertion, an absorb or a counted loop's back edge"),
            Op::Jne => {
                let target = ins.b.as_canonical_u64() as usize;
                if target > pc {
                    // `absorb_staged`'s branch over the deferred permutation.
                    let full = (1 + absorbs) % RATE == 0;
                    absorbs += 1;
                    pc = if full { pc + 1 } else { target };
                    continue;
                }
                assert!(back_edge.is_none_or(|e| e == pc), "pc {pc}: a second loop — the walk admits one");
                back_edge = Some(pc);
                if taken + 1 < trips {
                    taken += 1;
                    pc = target;
                } else {
                    pc += 1;
                }
            }
            Op::Jeq => {
                let target = ins.b.as_canonical_u64() as usize;
                let trap = instrs[pc + 1];
                assert!(target == pc + 2 && trap.op == Op::Inv && trap.rd == 1 && trap.ra == 0,
                    "pc {pc}: a JEQ that is not an assertion over a one-row trap");
                pc = target;
            }
            _ => pc += 1,
        }
    }
    assert_eq!(taken + 1, trips, "the loop ran {trips} times");
    assert_eq!(absorbs, 8 + 4 * trips, "the interface schedule: the eight binding words, then four public words per child");
    let mut phases = Vec::new();
    let mut at = 0;
    for &(name, n) in phase_rows {
        phases.push((name, visits[at..at + n].iter().sum()));
        at += n;
    }
    (visits.iter().sum(), phases)
}

/// `tests/self_verify.rs`'s toy program: a real tier-8 rVM proof in a second.
fn toy_program() -> Arc<Program> {
    use randprotocol_rvm::isa::{Instr, Op, F};
    use p3_field::PrimeCharacteristicRing;
    let i = |op, rd, ra, b: u64| Instr { op, rd, ra, b: F::from_u64(b) };
    Arc::new(Program {
        instrs: vec![
            i(Op::Faddi, 1, 0, 7), i(Op::Faddi, 2, 0, 5), i(Op::Fadd, 3, 1, 2), i(Op::Inv, 4, 3, 0),
            i(Op::Faddi, 5, 0, 100), i(Op::Store, 2, 5, 3), i(Op::Load, 6, 5, 3), i(Op::Faddi, 7, 0, 64),
            i(Op::Store, 1, 7, 0), i(Op::Store, 2, 7, 1), i(Op::Poseidon2, 0, 7, 0), i(Op::Load, 8, 7, 0),
            i(Op::Public, 0, 3, 0), i(Op::Public, 0, 6, 0), i(Op::Public, 0, 8, 0), i(Op::Public, 0, 4, 0),
            i(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    })
}

/// The walk against the emulator, in-suite (seconds): `rv32r` over a real test-profile rVM proof
/// (`tests/self_verify.rs`'s toy program at tier 8) executes exactly the rows the walk counts,
/// in total and in every phase. This is what lets the laptop's production count (walked, not
/// executed) stand for an execution's count.
#[test]
fn the_accepting_walk_counts_what_rv32r_executes() {
    let program = toy_program();
    let t = FriProfile::Test;
    let (proof, _) = Machine::new(t).prove(&program, &[], None).expect("the toy proves");
    let shape = RvmShape::of_proof(t, &program, &proof);
    let key = RvmKey::of(t, &shape);
    let vp = verify_rv32r(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build_for_with_binding(t, &shape, &key, &proof, &common::TEST_BINDING).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32r accepts the toy proof");
    let (rows, phases) = accepting_rows(&vp.program, &vp.phase_rows);
    assert_eq!(rows, exec.cpu_rows(), "the walk is the executed run");
    let pcs: Vec<usize> = exec.events.iter().map(|e| e.pc as usize).collect();
    let mut at = 0;
    for (k, &(name, n)) in vp.phase_rows.iter().enumerate() {
        let executed = pcs.iter().filter(|&&pc| (at..at + n).contains(&pc)).count();
        assert_eq!(phases[k], (name, executed), "the walk is the executed run in {name}");
        at += n;
    }
    assert!(rows < vp.program.instrs.len(), "the traps are not rows");
}

/// The looped walk against the emulator, in-suite (seconds): `rv32t` over two real tier-8 toy
/// proofs executes exactly the rows [`accepting_rows_looped`] counts at `TREE_ARITY` trips, in
/// total and in every phase. What lets the laptop's production step count (walked over the
/// emulated leaf shape; no production leaf proof exists here) stand for an execution's.
#[test]
fn the_looped_walk_counts_what_rv32t_executes() {
    let program = toy_program();
    let t = FriProfile::Test;
    let m = Machine::new(t);
    let (a, _) = m.prove(&program, &[], None).expect("the toy proves");
    let (b, _) = m.prove(&program, &[], None).expect("the toy proves");
    let shape = RvmShape::of_proof(t, &program, &a);
    assert!(shape.matches(&b), "one fixed workload, one shape");
    let vp = verify_rv32t(&shape, Checkpoints::Off);
    let tape = WitnessTape::build_tree_step(t, &shape, [&a, &b], &common::TEST_BINDING).unwrap();
    let exec = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32t accepts two toy proofs");
    let (rows, phases) = accepting_rows_looped(&vp.program, &vp.phase_rows, TREE_ARITY as usize);
    assert_eq!(rows, exec.cpu_rows(), "the looped walk is the executed run");
    let pcs: Vec<usize> = exec.events.iter().map(|e| e.pc as usize).collect();
    let mut at = 0;
    for (k, &(name, n)) in vp.phase_rows.iter().enumerate() {
        let executed = pcs.iter().filter(|&&pc| (at..at + n).contains(&pc)).count();
        assert_eq!(phases[k], (name, executed), "the looped walk is the executed run in {name}");
        at += n;
    }
}

/// Task 1a on the laptop: the production interior step's rows by the looped walk over
/// `rv32t_leaf` built at the emulated production leaf shape (nothing proved; the step reads only
/// the child's shape words, so no leaf key is needed). Checked against the band, which is now
/// M5's formula over the emulated C and the O measured at the test profile (`tree_test`).
#[test]
#[ignore = "tree Task 1a on the laptop: the production leaf emulated (no proof) and rv32t_leaf's accepting path counted at its shape — ~2 min, 8 GB"]
fn production_rv32t_rows_at_the_emulated_leaf_shape() {
    let (_program, _leaf_rows, shape) = emulated_leaf_shape();
    let vp = rv32t_leaf(&shape, Checkpoints::Off);
    let (rows, phases) = accepting_rows_looped(&vp.program, &vp.phase_rows, TREE_ARITY as usize);
    let child = common::pin("tree_measure", "child_cpu_rows_emulated");
    let o = rows as i64 - 2 * child as i64;
    let (lo, hi) = (common::pin("tree_measure", "step_band_lo"), common::pin("tree_measure", "step_band_hi"));
    let reduce = randprotocol_rvm::machine::canonical_reduce_log_height(&vp.program, TREE_ARITY);
    println!("== rv32t_leaf at the production leaf shape (looped walk): {rows} rows, tier {:?}, 2C + {o} (C = {child}), program {} instrs, canonical reduce height at n = {TREE_ARITY}: {reduce:?}; band [{lo}, {hi}]",
        Tier::for_cycles(rows), vp.program.instrs.len());
    println!("-- phases {phases:?}");
    assert!((lo..=hi).contains(&rows), "the production step ({rows} rows) leaves the band [{lo}, {hi}]");
    assert_eq!(rows, common::pin("tree_measure", "step_cpu_rows_emulated"), "the pinned emulated step rows");
    assert_eq!(Tier::for_cycles(rows).unwrap().0, common::pin("tree_measure", "step_tier_emulated"), "the pinned emulated step tier");
}

/// Task 0's stop rule checked on the laptop, before any droplet (48 GB: nothing is proved).
/// The leaf's shape comes from emulation ([`emulated_leaf_shape`]); `rv32r` is built for it with
/// the key a real leaf would verify under (`RvmKey::of`: the preprocessed commit of the program,
/// range and reduce-layout tables). Its rows are then the accepting walk's ([`accepting_rows`]):
/// `rv32r`'s only branches are assertions, so every honest leaf proof of this shape runs exactly
/// these rows, and `the_accepting_walk_counts_what_rv32r_executes` holds the walk to the emulator.
/// The droplet's `production_rv32r_over_the_leaf_emulates` re-derives the number by execution
/// over the real leaf; its `child_cpu_rows` must equal `child_cpu_rows_emulated`.
#[test]
#[ignore = "tree Task 0 on the laptop: the production leaf emulated (no proof) and rv32r's accepting path counted at its shape — ~2 min, 8 GB"]
fn production_rv32r_rows_at_the_emulated_leaf_shape() {
    let (_program, leaf_rows, shape) = emulated_leaf_shape();
    assert_eq!(Tier::for_cycles(leaf_rows), Some(Tier(20)), "the production L = 2 leaf is tier 20 since phase 4 ({leaf_rows} rows; tier 21 after phase 3)");
    let t = Instant::now();
    let key = RvmKey::of(P, &shape);
    println!("leaf key built in {:.1} s, live {:.2} GB, peak {:.2} GB", t.elapsed().as_secs_f64(), gb(LIVE.load(Relaxed)), gb(heap::PEAK.load(Relaxed)));
    let vp = verify_rv32r(&shape, &key, Checkpoints::Off);
    let (rows, phases) = accepting_rows(&vp.program, &vp.phase_rows);
    let phase8: usize = phases.iter().filter(|(n, _)| n.starts_with("phase 8")).map(|(_, r)| *r).sum();
    let static8: usize = vp.phase_rows.iter().filter(|(n, _)| n.starts_with("phase 8")).map(|(_, r)| *r).sum();
    assert_eq!(phase8, static8, "phase 8 has no assertion: the droplet's static phase-8 count is the executed one");
    let child = rows - phase8;
    let rv32r_reduce = randprotocol_rvm::machine::canonical_reduce_log_height(&vp.program, 1);
    println!("== rv32r at the production leaf shape (accepting walk): {rows} rows, tier {:?}, child {child} rows, phase 8 {phase8} rows, program {} instrs ({} traps), reduce height {rv32r_reduce:?}, peak live {:.2} GB",
        Tier::for_cycles(rows), vp.program.instrs.len(), vp.program.instrs.len() - rows, gb(heap::PEAK.load(Relaxed)));
    println!("-- phases {phases:?}");
    let o = o_measured();
    let (step, lo, hi) = band(child, o);
    println!("== band: 2C + ({o}) = {step} rows (tier {:?}), [{lo} (tier {:?}), {hi} (tier {:?})]",
        Tier::for_cycles(step), Tier::for_cycles(lo), Tier::for_cycles(hi));
    assert!(child <= STOP_CHILD_ROWS,
        "STOP (spec §5): one child verification is {child} rows, above {STOP_CHILD_ROWS}: the k = 2 step exceeds tier 22");
    assert_eq!(rows, common::pin("tree_measure", "rv32r_cpu_rows_emulated"), "the pinned emulated rv32r rows");
    assert_eq!(child, common::pin("tree_measure", "child_cpu_rows_emulated"), "the pinned emulated child");
    assert_eq!(leaf_rows, common::pin("tree_measure", "leaf_cpu_rows_emulated"), "the pinned emulated leaf rows");
}

/// The pinned band cannot drift from the pinned emulated child (in-suite, instant): `step_band_lo`
/// and `step_band_hi` are M5's formula over `child_cpu_rows_emulated` and the measured O. At the
/// rVM's rate ¼ (92 queries) the whole band is tier 21; at rate ⅛ (80 queries) its low end was
/// tier 20. The measured step (Task 2), not the band, still decides the pinned step tier (R6).
/// Phase 4 (2026-10-09, the Merkle spans) re-recorded it: tier 21 end to end → tier 20 end to end
/// (band [1 102 455, 1 491 559] → [590 828, 799 356]; C 648 518 → 347 358, O −29 → +376).
#[test]
fn the_pinned_band_is_the_emulated_childs() {
    let child = common::pin("tree_measure", "child_cpu_rows_emulated");
    let (step, lo, hi) = band(child, o_measured());
    assert_eq!(lo, common::pin("tree_measure", "step_band_lo"), "step_band_lo is floor(0.85·(2C + O))");
    assert_eq!(hi, common::pin("tree_measure", "step_band_hi"), "step_band_hi is ceil(1.15·(2C + O))");
    assert_eq!(
        (Tier::for_cycles(lo), Tier::for_cycles(step), Tier::for_cycles(hi)),
        (Some(Tier(20)), Some(Tier(20)), Some(Tier(20))),
        "the band is tier 20 end to end"
    );
}

// ── Task 2: the production depth-2 tree (4 leaves of L = 2; 2 rv32t_leaf; 1 rv32t_int) ──────────
//
// Host class (tree Task 2 rulings): at the rVM's rate ¼ docs/07 §4 projects a tier-21 proof at
// ≈ 122–197 GB (production N = 2 / N = 3 rows), so the leaves, the steps and the root all run on
// the 256 GB droplet, one proving process at a time. The steps' emulated rows (1 294 577, tier 21)
// and band [1 102 455, 1 491 559] are Task R's pins (`tree_measure`). Phase 4 (2026-10-09, the
// Merkle spans) re-recorded them: 1 294 577 → 695 097 rows (tier 21 → 20), band → [590 828, 799 356];
// the GB projections here are the tier-21 ones, not re-taken.

fn env_index(var: &str, max: usize) -> usize {
    let k: usize = std::env::var(var).unwrap_or_else(|_| panic!("set {var}")).parse().expect("an index");
    assert!(k <= max, "{var} ≤ {max}");
    k
}

/// Leaves 1–3 (one per process): `TREE_LEAF=k`. Leaf 0 is Task 0's `production_leaf_l2`.
#[test]
#[ignore = "tree Task 2: production rv32n leaf k (TREE_LEAF=1..3), 632 175 rows tier 20 since phase 4 (1 171 511 rows tier 21 after phase 3, 122-142 GB projected then at rate 1/4, docs/07 §4) — the 256 GB droplet"]
fn production_tree_leaf() {
    let k = env_index("TREE_LEAF", 3);
    assert!(k >= 1, "leaf 0 is Task 0's production_leaf_l2");
    prove_leaf(k);
}

/// The production leaf's inner key, program and declared shape, read off cached leaf 0.
fn production_leaf_shape() -> (InnerVerifierKey, Arc<Program>, RvmShape) {
    let proofs = bundles(0, L);
    let vk = inner(&proofs[0]);
    let program = Arc::new(aggregate_program(&vk));
    let leaf = load("Production-leaf-0", &program, L as u64);
    let shape = RvmShape::of_proof(P, &program, &leaf);
    (vk, program, shape)
}

/// The shape a proof of `program` over `exec` would declare, without proving: `build_traces`'
/// heights (the rule `prove` applies) at the tier the rows need (tree Task 1b's method).
fn emulated_shape(program: &Arc<Program>, exec: &Execution) -> RvmShape {
    let tier = Tier::for_cycles(exec.cpu_rows()).expect("the run fits a tier");
    let t = randprotocol_rvm::machine::build_traces(program, exec, tier).expect("the run's traces build");
    RvmShape::of(P, program, tier, t.reg_log_height, t.ram_log_height, t.poseidon2_log_height, t.reduce_log_height)
}

/// The production per-level step heights (spec §4.1 R3/R4), from the proved step S_1 and root
/// S_2, and whether the list's last entry is a fixed point: `[S_1, S_2]` when `rv32t_int`'s own
/// proofs declare S_1's words (it is the fixed point); otherwise level 3's program, `rv32t` at
/// S_2, is emulated over (root, root) as Task 1b's fixed-point test
/// (`the_step_program_at_the_roots_shape_is_rv32t_int_the_fixed_point`) does, and the list is
/// `[S_1, S_2, S_3]`, a fixed point when S_3 repeats S_2. When it does not, the three-entry list
/// is still a valid genesis for `max_depth ≤ 3` (its last entry is read only at level ≥ 4).
/// Prints the verdict and the list length.
fn production_step_list(s_step: &RvmShape, s_root: &RvmShape, root: &randprotocol_rvm::machine::Proof) -> (Vec<RvmHeights>, bool) {
    if s_root.same_step_words(s_step) {
        println!("== fixed point (R3): HOLDS at level 2 — rv32t_int verifies its own proofs; production list length 2");
        return (vec![s_step.heights(), s_root.heights()], true);
    }
    let t3 = Arc::new(verify_rv32t(s_root, Checkpoints::Off).program);
    let tape = WitnessTape::build_tree_step(P, s_root, [root, root], &common::TEST_BINDING).unwrap();
    let exec = execute(&t3, &tape.words, MAX_CYCLES).expect("rv32t at the root's shape accepts two roots");
    let s3 = emulated_shape(&t3, &exec);
    println!("== level 3 emulated: {} rows, tier {}, header {:?} (root {:?})", exec.cpu_rows(), s3.tier,
        s3.header_words(), s_root.header_words());
    let fixed = s3.same_step_words(s_root);
    if fixed {
        println!("== fixed point (R3): FAILS at level 2, HOLDS at level 3 (emulated) — production list length 3");
    } else {
        println!("== fixed point (R3): FAILS at levels 2 and 3 — the three-entry list below is valid for max_depth ≤ 3 only; \
            a longer list needs a proved level-3 step");
    }
    (vec![s_step.heights(), s_root.heights(), s3.heights()], fixed)
}

/// Step `TREE_STEP=k` ∈ {0, 1}: `rv32t_leaf` over leaves (2k, 2k + 1). Emulated first, against
/// docs/08 §2's band (M5), then proved under the heap profiler.
#[test]
#[ignore = "tree Task 2: production rv32t_leaf step k (TREE_STEP=0|1), 695 097 rows emulated, tier 20 since phase 4 (1 294 577, tier 21 before; 122-197 GB projected then at rate 1/4, docs/07 §4) — the 256 GB droplet"]
fn production_tree_step() {
    let k = env_index("TREE_STEP", 1);
    let (_vk, program, shape) = production_leaf_shape();
    let a = load(&format!("Production-leaf-{}", 2 * k), &program, L as u64);
    let b = load(&format!("Production-leaf-{}", 2 * k + 1), &program, L as u64);
    let vp = verify_rv32t(&shape, Checkpoints::Off);
    let tape = WitnessTape::build_tree_step(P, &shape, [&a, &b], &common::TEST_BINDING).unwrap();
    let rows = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32t_leaf accepts two production leaves").cpu_rows();
    let (lo, hi) = (common::pin("tree_measure", "step_band_lo"), common::pin("tree_measure", "step_band_hi"));
    println!("== step {k} emulated: {rows} rows, tier {:?}, band [{lo}, {hi}] {} (emulated pin {})", Tier::for_cycles(rows),
        if (lo..=hi).contains(&rows) { "IN" } else { "OUT: write the correction into docs/08 §2 (M5)" },
        common::pin("tree_measure", "step_cpu_rows_emulated"));
    let t0 = install();
    let m = Machine::new(P);
    let t = Instant::now();
    let proof = prove_tree_step(&m, &shape, [&a, &b], &common::TEST_BINDING, None).expect("the step proves");
    let prove_s = t.elapsed().as_secs_f64();
    let tv = Instant::now();
    m.verify_n(&vp.program, &proof, TREE_ARITY).expect("the step verifies at n = 2");
    println!("verify {:.2} s", tv.elapsed().as_secs_f64());
    save(&format!("Production-step-{k}"), &proof);
    heights(&format!("step {k}"), &proof);
    report(&format!("tree step {k}: rv32t_leaf (production)"), t0, rows, proof.tier, proof.size(), prove_s);
}

/// The root: `rv32t_int` over steps 0 and 1, proved, then verified through `verify_tree` with the
/// shapes and keys the node rebuilds from the heights (`TreeShapes::build`), and the production
/// list length read off the next level, emulated at the root's shape (R3).
#[test]
#[ignore = "tree Task 2: production rv32t_int root over the two steps (tier 21 expected before phase 4, not re-derived; 122-197 GB projected then at rate 1/4, docs/07 §4), then verify_tree — the 256 GB droplet"]
fn production_tree_root() {
    let (vk, _program, leaf_shape) = production_leaf_shape();
    let t_leaf = Arc::new(verify_rv32t(&leaf_shape, Checkpoints::Off).program);
    let s0 = load("Production-step-0", &t_leaf, TREE_ARITY);
    let s1 = load("Production-step-1", &t_leaf, TREE_ARITY);
    let s_step = RvmShape::of_proof(P, &t_leaf, &s0);
    assert!(s_step.matches(&s1), "both level-1 steps declare one shape");
    let vp = verify_rv32t(&s_step, Checkpoints::Off);
    let tape = WitnessTape::build_tree_step(P, &s_step, [&s0, &s1], &common::TEST_BINDING).unwrap();
    let rows = execute(&vp.program, &tape.words, MAX_CYCLES).expect("rv32t_int accepts the two steps").cpu_rows();
    println!("== root emulated: {rows} rows, tier {:?}", Tier::for_cycles(rows));
    let t0 = install();
    let m = Machine::new(P);
    let t = Instant::now();
    let root = prove_tree_step(&m, &s_step, [&s0, &s1], &common::TEST_BINDING, None).expect("the root proves");
    let prove_s = t.elapsed().as_secs_f64();
    save("Production-root", &root);
    heights("root", &root);
    report("tree root: rv32t_int (production)", t0, rows, root.tier, root.size(), prove_s);

    let t_int = Arc::new(vp.program.clone());
    let s_root = RvmShape::of_proof(P, &t_int, &root);
    let shapes = TreeShapes::build(P, &vk, leaf_shape.heights(), &[s_step.heights(), s_root.heights()]).unwrap();
    assert_eq!(shapes.root_program(2).unwrap().digest(), t_int.digest(), "the rebuilt level-2 program is the proved root's");
    let keys = shapes.keys();
    let covered: Vec<Vec<u64>> = bundles(0, 4 * L).iter().map(|p| p.public_values.clone()).collect();
    let tv = Instant::now();
    verify_tree(&m, shapes.root_program(2).unwrap(), &root, &vk, &covered, &common::TEST_BINDING, L, 2, &keys).expect("the production tree verifies");
    println!("verify_tree {:.2} s", tv.elapsed().as_secs_f64());
    let _ = production_step_list(&s_step, &s_root, &root);
}

/// The chain's `aggregation_tree` genesis values (docs/08 §4; Task 3a), from the cached leaf, step
/// and root, printed as the exact `TreeConfig` JSON `rand-node genesis --aggregation-tree TREE.JSON`
/// reads (`common::aggregation_tree_json`; review m2): the bundle shape, L, `max_depth` (the list
/// length — deeper only by the fixed point and a genesis decision), the leaf heights and
/// `vk_leaf`, and per listed level its heights (`step_tiers` is `heights.tier`), step program digest
/// (`step_digests`) and key (`step_keys`), the last entry repeating. Every digest is four canonical
/// u64 limbs. Save the block between the `== aggregation_tree` markers as TREE.JSON.
#[test]
#[ignore = "tree Task 2: prints the production aggregation_tree genesis values from the cached tree (keys at tier 21: the 256 GB droplet)"]
fn production_tree_genesis_values() {
    let (vk, program, leaf_shape) = production_leaf_shape();
    let t_leaf = Arc::new(verify_rv32t(&leaf_shape, Checkpoints::Off).program);
    let s0 = load("Production-step-0", &t_leaf, TREE_ARITY);
    let s_step = RvmShape::of_proof(P, &t_leaf, &s0);
    let t_int = Arc::new(verify_rv32t(&s_step, Checkpoints::Off).program);
    let root = load("Production-root", &t_int, TREE_ARITY);
    let s_root = RvmShape::of_proof(P, &t_int, &root);
    let (list, fixed) = production_step_list(&s_step, &s_root, &root);
    let shapes = TreeShapes::build(P, &vk, leaf_shape.heights(), &list).unwrap();
    assert_eq!(shapes.fixed_point(), fixed, "the rebuilt list agrees with the emulated verdict");
    assert_eq!(shapes.steps[0], s_step);
    assert_eq!(shapes.steps[1], s_root);
    let limbs = |d: [randprotocol_rvm::isa::F; 4]| d.map(|f| p3_field::PrimeField64::as_canonical_u64(&f));
    let keys = shapes.keys();
    println!("== aggregate_program_digest {:?} (admitted_shapes[].aggregate_program_digest)", limbs(program.digest()));
    assert_eq!(keys.vk_leaf, inner_vk_digest(&leaf_shape, &RvmKey::of(P, &leaf_shape)));
    let steps: Vec<_> = shapes.steps.iter().enumerate().map(|(k, s)| (s.heights(), limbs(s.program.digest()), limbs(keys.step_keys[k]))).collect();
    let json = common::aggregation_tree_json(P, &bundles(0, 1)[0], L, list.len(), &leaf_shape.heights(), limbs(keys.vk_leaf), &steps);
    println!("== aggregation_tree (TREE.JSON for `rand-node genesis --aggregation-tree`)\n{json}== end aggregation_tree");
    println!("== list length {}, fixed point {}: {}", list.len(), if fixed { "HOLDS" } else { "FAILS" },
        if fixed { "max_depth unbounded by R3" } else { "valid genesis for max_depth ≤ 3 only" });
    assert!(fixed, "no fixed point within three levels: the values above serve max_depth ≤ 3; record them in docs/08 §4 and halt for a decision");
}
