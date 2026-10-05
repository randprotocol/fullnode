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
//! since the quotient-layout fork it proves on a 48 GB box at 33.27 GB peak live, 2026-10-05,
//! `docs/05-quotient-layout.md`; add `--features parallel` and `RAYON_NUM_THREADS=16` for threads):
//! `cargo test --release -p recursion --test memprofile tier19 -- --ignored --nocapture`
//! The toy (`tier8`) is the harness's own smoke test.
mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::Instant;

// ── the counting allocator ──────────────────────────────────────────────────────────────────

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn bump(n: usize) {
    let v = LIVE.fetch_add(n, Relaxed) + n;
    let mut p = PEAK.load(Relaxed);
    while v > p {
        match PEAK.compare_exchange_weak(p, v, Relaxed, Relaxed) {
            Ok(_) => break,
            Err(x) => p = x,
        }
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            bump(l.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(l) };
        if !p.is_null() {
            bump(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            LIVE.fetch_sub(l.size(), Relaxed);
            bump(new);
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn gb(b: usize) -> f64 {
    b as f64 / 1e9
}

fn rss_gb() -> f64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok();
    out.and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<f64>().ok())
        .map(|kb| kb * 1024.0 / 1e9)
        .unwrap_or(f64::NAN)
}

// ── the span logger ─────────────────────────────────────────────────────────────────────────

struct Spans {
    t0: Instant,
    names: Mutex<HashMap<u64, (&'static str, Instant, usize)>>,
    next: AtomicU64,
    depth: AtomicUsize,
}

impl Spans {
    fn line(&self, mark: &str, depth: usize, name: &str, extra: &str) {
        let t = self.t0.elapsed().as_secs_f64();
        println!(
            "[{t:9.1}s] {:indent$}{mark} {name:<42} live {:7.2} GB  peak {:7.2} GB{extra}",
            "",
            gb(LIVE.load(Relaxed)),
            gb(PEAK.load(Relaxed)),
            indent = 2 * depth,
        );
    }
}

impl tracing::Subscriber for Spans {
    fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
        m.is_span() && *m.level() <= tracing::Level::DEBUG
    }
    fn new_span(&self, a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let id = self.next.fetch_add(1, Relaxed) + 1;
        self.names.lock().unwrap().insert(id, (a.metadata().name(), Instant::now(), LIVE.load(Relaxed)));
        tracing::span::Id::from_u64(id)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, id: &tracing::span::Id) {
        let depth = self.depth.fetch_add(1, Relaxed);
        if let Some(e) = self.names.lock().unwrap().get_mut(&id.into_u64()) {
            e.1 = Instant::now();
            e.2 = LIVE.load(Relaxed);
            if depth <= 1 {
                self.line("+", depth, e.0, "");
            }
        }
    }
    fn exit(&self, id: &tracing::span::Id) {
        let depth = self.depth.fetch_sub(1, Relaxed) - 1;
        if let Some(&(name, start, live_at_enter)) = self.names.lock().unwrap().get(&id.into_u64()) {
            let dt = start.elapsed().as_secs_f64();
            // Top-level spans always; nested ones only when they took a second or more, so the
            // per-column helpers (`batch_multiplicative_inverse` runs in the thousands) stay out.
            if depth <= 1 || dt >= 1.0 {
                let delta = gb(LIVE.load(Relaxed)) - gb(live_at_enter);
                self.line("-", depth, name, &format!("  Δlive {delta:+7.2} GB  {dt:8.1} s"));
            }
        }
    }
    fn try_close(&self, id: tracing::span::Id) -> bool {
        self.names.lock().unwrap().remove(&id.into_u64());
        true
    }
}

fn install() -> Instant {
    let t0 = Instant::now();
    let s = Spans { t0, names: Mutex::new(HashMap::new()), next: AtomicU64::new(0), depth: AtomicUsize::new(0) };
    tracing::subscriber::set_global_default(s).expect("one subscriber per process");
    // The RSS sampler: every 10 s, so allocator retention (RSS − live) is visible over time.
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
        println!(
            "[{:9.1}s] # sample  live {:7.2} GB  peak {:7.2} GB  rss {:7.2} GB",
            t0.elapsed().as_secs_f64(),
            gb(LIVE.load(Relaxed)),
            gb(PEAK.load(Relaxed)),
            rss_gb()
        );
    });
    t0
}

fn report(what: &str, t0: Instant, rows: usize, tier: randprotocol_rvm::machine::Tier, proof_bytes: usize, prove_s: f64) {
    println!(
        "== {what}: {rows} rows, tier {}, proof {proof_bytes} B, prove {prove_s:.1} s; peak live heap {:.2} GB, live now {:.2} GB, rss now {:.2} GB, wall {:.1} s",
        tier.0,
        gb(PEAK.load(Relaxed)),
        gb(LIVE.load(Relaxed)),
        rss_gb(),
        t0.elapsed().as_secs_f64()
    );
}

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
/// sponged (5 000 `SPONGE` absorbs; 63 762 rows, tier 16) — proved once and verified; prints the
/// prove wall time and the peak live heap. Run it three ways (`docs/04-phase2-row-cuts.md`
/// §"Threads"): without the feature (the baseline), then
/// `RAYON_NUM_THREADS=1` and `=16 cargo test --release --features parallel --test memprofile
/// tier16 -- --ignored --nocapture`. 2 000 rounds is 102 012 rows, past tier 16 (no tier 17 rung):
/// the program is emulated and its tier asserted before anything is proved, so a row drift fails
/// in seconds instead of starting a tier-18 proof. Measured 2026-10-04 on the 48 GB box: off
/// 170.6 s, `RAYON_NUM_THREADS=1` 171.1 s, `=16` 36.4 s; peak live 9.09 GB all three.
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
/// Since phase 2's row cuts the same proof is 230 950 rows, tier 18 (≈ 47–50 GB projected by the
/// measured terms). Since the quotient-layout fork it proves on this 48 GB box: 33.27 GB peak
/// live, prove 185.4 s on 16 threads, verify 5.46 s, 268 417 B (2026-10-05,
/// `docs/05-quotient-layout.md`, `docs/measurements/2026-10-05-tier18-twin-memprofile.log`). The
/// name is kept for the record it produced.
#[test]
#[ignore = "one exit-twin rVM proof under the heap profiler (tier 18 since phase 2): proved on this 48 GB box at 33.27 GB live, 2026-10-05, since the quotient-layout fork (78.7 GB live when killed at tier 19 before it); ~3 min on 16 threads with --features parallel"]
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
