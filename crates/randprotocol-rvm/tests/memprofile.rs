//! A live-heap profile of one rVM proof: what the prover actually holds, phase by phase.
//!
//! The 2026-09-30 measurements on the 503 GB box (`docs/02-aggregate.md`, "Constraint set 8,
//! proved") recorded peak RSS 4–8× the committed-oracle model — 94 GB at tier 19, 377 GB at
//! tier 21. This harness counts the bytes that are *live*, phase by phase, and its tier-19 run
//! (2026-10-03, this 48 GB box, `docs/measurements/2026-10-03-tier19-memprofile.log`) settled
//! the question: **78.7 GB live when the kernel killed it**, 20 s into the quotient commit —
//! the Linux peaks are the working set, not allocator retention. The committed main trace is
//! one of four terms (main LDE + tree 17.6 GB, permutation 11.3 GB, the quotient LDEs 29.7 GB,
//! the quotient tree and FRI the rest); the record and the model are
//! `docs/04-phase2-row-cuts.md` §"The prover's live heap". macOS's RSS for the same run read
//! 7–17 GB (19.8 GB maximum) because it excludes compressed and swapped pages: **macOS RSS is
//! not a memory number**, and the September "completes on 48 GB" was ~50 GB of compressed
//! swap. Two instruments, no new dependencies beyond `tracing` (already in the tree through
//! Plonky3):
//!
//! 1. a counting global allocator — live bytes and the high-water mark, every allocation;
//! 2. a minimal `tracing` subscriber that prints live/peak at every Plonky3 span boundary
//!    (`prove_batch`, `compute quotient`, the PCS commit and open spans), so each step of the
//!    prover is attributed its own delta; a sampler thread adds RSS every 10 s (kept to show
//!    how far RSS is from the live count, not as a measurement).
//!
//! Run (the exit twin's shape — tier 19 at constraint set 8, tier 18 since phase 2's row cuts;
//! since the quotient-layout fork it proves on a 48 GB box: 33.27 GB peak live at 230 950 rows,
//! 2026-10-05, `docs/05-quotient-layout.md`; 24.86 GB after phase 3's Cut D and 26.88 GB at
//! 169 366 rows after Cut F, `docs/06-phase3-fold-reduce.md` §3; add `--features parallel` and
//! `RAYON_NUM_THREADS=16` for threads):
//! `cargo test --release -p recursion --test memprofile tier19 -- --ignored --nocapture`
//! The toy (`tier8`) is the harness's own smoke test.
mod common;
mod heap;

use heap::*;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

// ── the runs ────────────────────────────────────────────────────────────────────────────────

/// The harness's smoke test: `tests/backend.rs`'s table-covering toy at the smallest tier.
#[test]
#[ignore = "the memory profile harness's smoke run (seconds); prints the span log"]
fn tier8_toy() {
    use randprotocol_rvm::isa::{Instr, Op, Program, F};
    use p3_field::PrimeCharacteristicRing;
    let i = |op, rd, ra, b: u64| Instr { op, rd, ra, b: F::from_u64(b) };
    let p = Program {
        instrs: vec![
            i(Op::Faddi, 1, 0, 7),
            i(Op::Faddi, 2, 0, 5),
            i(Op::Fadd, 3, 1, 2),
            i(Op::Inv, 4, 3, 0),
            i(Op::Faddi, 7, 0, 64),
            i(Op::Store, 1, 7, 0),
            i(Op::Store, 2, 7, 1),
            i(Op::Poseidon2, 0, 7, 0),
            i(Op::Load, 8, 7, 0),
            i(Op::Public, 0, 3, 0),
            i(Op::Public, 0, 4, 0),
            i(Op::Public, 0, 8, 0),
            i(Op::Public, 0, 1, 0),
            i(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    };
    let t0 = install();
    let m = randprotocol_rvm::machine::Machine::new(randprotocol_zkvm::machine::FriProfile::Test);
    let t = Instant::now();
    let (proof, exec) = m.prove(&p, &[], None).unwrap();
    let prove_s = t.elapsed().as_secs_f64();
    m.verify(&p, &proof).unwrap();
    report("tier8 toy", t0, exec.cpu_rows(), proof.tier, proof.size(), prove_s);
}

/// Threads (Task 6): a synthetic tier-16 program — 1 250 rounds of 16 hinted words stored and
/// sponged (5 000 `SPONGE` absorbs; 60 012 rows, tier 16) — proved once and verified; prints the
/// prove wall time and the peak live heap. Run it three ways (`docs/04-phase2-row-cuts.md`
/// §"Threads"): without the feature (the baseline), then
/// `RAYON_NUM_THREADS=1` and `=16 cargo test --release --features parallel --test memprofile
/// tier16 -- --ignored --nocapture`. 2 000 rounds is 102 012 rows, past tier 16 (no tier 17 rung):
/// the program is emulated and its tier asserted before anything is proved, so a row drift fails
/// in seconds instead of starting a tier-18 proof. Measured 2026-10-04 on the 48 GB box: off
/// 170.6 s, `RAYON_NUM_THREADS=1` 171.1 s, `=16` 36.4 s; peak live 9.09 GB all three. Phase 4
/// (2026-10-09, the Merkle spans) re-recorded it: 63 762 → 60 012 rows, still tier 16 (B′'s
/// immediate `SPONGE` source and re-homing; `docs/09-phase4-spans.md` §4).
#[test]
#[ignore = "the thread benchmark: ~1-3 min; RAYON_NUM_THREADS=1 then 16, --features parallel"]
fn tier16_synthetic_threads() {
    use randprotocol_rvm::dsl::{hash, Builder, Checkpoints, Digest, Liveness};
    use randprotocol_rvm::programs::Precompiles;
    use p3_field::PrimeCharacteristicRing;
    let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, Precompiles::On);
    let mut tape: Vec<randprotocol_rvm::isa::F> = vec![];
    let src = b.alloc(16);
    let out = Digest(b.alloc(4));
    for round in 0..1_250u64 {
        for k in 0..16i64 {
            let v = b.hint();
            tape.push(randprotocol_rvm::isa::F::from_u64(round * 16 + k as u64 + 1));
            b.store(src, k, v);
        }
        hash::sponge(&mut b, src, 16, out);
    }
    for k in 0..4 { let v = b.load(out.0, k); b.public(v); }
    let p = b.finish();
    let rows = randprotocol_rvm::emulator::execute(&p, &tape, 1 << 20).unwrap().cpu_rows();
    assert_eq!(
        randprotocol_rvm::machine::Tier::for_cycles(rows),
        Some(randprotocol_rvm::machine::Tier(16)),
        "the benchmark is a tier-16 program ({rows} rows): a drift must not start a larger proof"
    );
    let t0 = install();
    let m = randprotocol_rvm::machine::Machine::new(randprotocol_zkvm::machine::FriProfile::Test);
    let t = Instant::now();
    let (proof, exec) = m.prove(&p, &tape, None).unwrap();
    let prove_s = t.elapsed().as_secs_f64();
    m.verify(&p, &proof).unwrap();
    report("tier16 synthetic", t0, exec.cpu_rows(), proof.tier, proof.size(), prove_s);
}

/// The exit twin's shape (`tests/exit.rs`): the verifier program over one real test-profile
/// bundle proof — tier 19 at constraint set 8, the shape the 503 GB box measured at 94.2 GB RSS
/// and this harness at 78.7 GB live when killed (2026-10-03, `docs/04-phase2-row-cuts.md`).
/// Since phase 2's row cuts the same proof is tier 18 (230 950 rows then; ≈ 47–50 GB projected by
/// the measured terms). Since the quotient-layout fork it proves on this 48 GB box: 33.27 GB peak
/// live, prove 185.4 s on 16 threads, verify 5.46 s, 268 417 B (2026-10-05,
/// `docs/05-quotient-layout.md`, `docs/measurements/2026-10-05-tier18-twin-memprofile.log`).
/// Phase 3 (`docs/06-phase3-fold-reduce.md` §3): 24.86 GB after Cut D (202 198 rows; the register
/// table 2^20 → 2^19), and **26.88 GB at the phase's end** (169 366 rows, prove 141.3 s, verify
/// 6.67 s, 268 168 B; 2026-10-06, `docs/measurements/2026-10-06-tier18-twin-memprofile-phase3.log`)
/// — fewer cpu rows, but the reduce chip is 81 columns wide (was 30) and carries the fold and pow
/// runs. The name is kept for the record it produced. Phase 4 (2026-10-09, the Merkle spans)
/// re-recorded it: 169 366 → 104 150 rows, still tier 18 (`TIERS` has no 17 rung; not re-profiled).
/// MODQ chip (2026-10-11, private multisig phase 3): the inner cpu gained SYS_MODQ: 104 150 → 104 229 rows (emulated by `tests/profile.rs`), still tier 18.
#[test]
#[ignore = "one exit-twin rVM proof under the heap profiler (tier 18 since phase 2; 88 160 rows since phase 5, 104 229 since the MODQ chip, 104 150 after phase 4): proved on this 48 GB box at 26.88 GB live, 2026-10-06, at phase 3's end (33.27 GB at the quotient-layout fork, 2026-10-05; 78.7 GB live when killed at tier 19 before it); ~2.5 min on 16 threads with --features parallel"]
fn tier19_exit_twin() {
    use randprotocol_zkvm::machine::FriProfile;
    use randprotocol_rvm::dsl::Checkpoints;
    use randprotocol_rvm::programs::verify_rv32;
    use randprotocol_rvm::shape::{InnerKey, InnerShape};
    use randprotocol_rvm::witness::WitnessTape;
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let shape = InnerShape::of(FriProfile::Test, p.proof.tier, p.proof.program_log_height,
        p.proof.input_log_height, p.proof.keccak_log_height, p.proof.sha256_log_height, p.proof.public_log_height,
        p.proof.mem_log_height);
    let key = InnerKey::of(FriProfile::Test, &shape);
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    println!("fixture loaded, program built: live {:.2} GB", gb(LIVE.load(Relaxed)));
    let t0 = install();
    let m = randprotocol_rvm::machine::Machine::new(FriProfile::Test);
    let t = Instant::now();
    let (proof, exec) = m.prove(&vp.program, &tape.words, None).unwrap();
    let prove_s = t.elapsed().as_secs_f64();
    println!("prove done: live {:.2} GB peak {:.2} GB rss {:.2} GB", gb(LIVE.load(Relaxed)), gb(PEAK.load(Relaxed)), rss_gb());
    let tv = Instant::now();
    m.verify(&vp.program, &proof).unwrap();
    println!("verify {:.2} s", tv.elapsed().as_secs_f64());
    report("exit twin (tier 18)", t0, exec.cpu_rows(), proof.tier, proof.size(), prove_s);
}
