//! ZKVM-110: what a prove costs the first time and the second time — wall time and peak live heap.
//!
//! A counting global allocator (live bytes and their high-water mark; `recursion/tests/memprofile.rs`
//! is the pattern, and its header says why macOS RSS is not a memory number) around three things,
//! at one tier per test:
//!
//! 1. the preprocessed build alone (`Machine::verifier_key` on a fresh machine — the same
//!    `ProverData::from_airs_and_degrees` call a prove makes);
//! 2. two proves of the same program and shape on one machine — the first and a repeat;
//! 3. the two verifies (the first builds the verifier key, the second takes it from the cache).
//!
//! It also prints the trace set's own size (the `Traces` matrices, before the blind columns), which
//! is what a second copy of every trace costs.
//!
//! `fib(650)` runs 3 910 cycles, so tier 12 is its natural tier; tier 14 is the same program at a
//! forced tier — padded tables, the same proving work per row — and tier 10 is `fib(150)`. Run one
//! at a time:
//!
//! `cargo test --release --features parallel --test memprofile tier12 -- --ignored --nocapture`
//!
//! (and `tier10`, `tier14`; drop `--features parallel` for the serial prover). Under the feature the
//! counter itself costs time — every worker bumps the same word — so read the heap figures from that
//! run and the times from a second one with `MEMPROFILE_TIME_ONLY=1` set, which turns the counter off. Tier 14 peaks near
//! 3 GB live; nothing here is for tier 16 and above on a 48 GB machine without checking first.
use randprotocol_zkvm::guests;
use randprotocol_zkvm::machine::{build_traces_salted, FriProfile, Machine, Tier};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Off under `MEMPROFILE_TIME_ONLY=1`: sixteen rayon workers bumping one counter roughly double a
/// prove's wall time, so the times are taken in a run of their own with the counter off.
static COUNT: AtomicBool = AtomicBool::new(true);

fn add(n: usize) {
    if !COUNT.load(Relaxed) { return; }
    let live = LIVE.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(live, Relaxed);
}

fn sub(n: usize) {
    if COUNT.load(Relaxed) { LIVE.fetch_sub(n, Relaxed); }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() { add(l.size()); }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(l) };
        if !p.is_null() { add(l.size()); }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        sub(l.size());
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            if new >= l.size() { add(new - l.size()); } else { sub(l.size() - new); }
        }
        q
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const MB: f64 = 1024.0 * 1024.0;

/// Runs `f` and returns its result, its wall time in seconds, the live heap it started from and the
/// highest the live heap went above that start while it ran — both in MiB.
fn measured<T>(f: impl FnOnce() -> T) -> (T, f64, f64, f64) {
    let start = LIVE.load(Relaxed);
    PEAK.store(start, Relaxed);
    let t = Instant::now();
    let out = f();
    let s = t.elapsed().as_secs_f64();
    (out, s, start as f64 / MB, PEAK.load(Relaxed).saturating_sub(start) as f64 / MB)
}

fn run(tier: Tier, n: u32) {
    // Set before anything is allocated on the heap that a counted `dealloc` could later subtract.
    if std::env::var_os("MEMPROFILE_TIME_ONLY").is_some() {
        COUNT.store(false, Relaxed);
        println!("tier {}: MEMPROFILE_TIME_ONLY — the heap counter is off, read the times only", tier.0);
    }
    let p = guests::fib(n);
    let hc = p.digest();

    // The trace set: what one more copy of every trace is.
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], tier.max_cycles()).unwrap();
    let traces = build_traces_salted(&p, &[], &[], [1, 2, 3, 4], &exec, tier, randprotocol_zkvm::gas::gas_max(tier, 0, 0)).unwrap();
    let trace_bytes: usize = traces.as_slice().iter().map(|m| m.values.len() * 8).sum();
    let (plh, ilh, publh) = (traces.program_log_height, traces.input_log_height, traces.public_log_height);
    drop(traces);
    println!("tier {}: fib({n}), {} cycles; trace set {:.1} MiB", tier.0, exec.cycles(), trace_bytes as f64 / MB);

    // The preprocessed build alone.
    let (_, s, _, peak) = measured(|| Machine::new(FriProfile::Test).verifier_key(tier, plh, ilh, 0, 0, publh));
    println!("tier {}: preprocessed build alone   {s:8.3} s   peak +{peak:9.1} MiB", tier.0);

    let m = Machine::new(FriProfile::Test);
    // `MEMPROFILE_BUDGET=<bytes>` sets the prover cache's budget (0 is off: the prover before
    // ZKVM-110, a build per prove), and `MEMPROFILE_PROVES=<n>` adds repeats — a tier-12 prove's
    // run-to-run noise is about the size of the build it saves, so compare means over several.
    if let Some(b) = std::env::var("MEMPROFILE_BUDGET").ok().and_then(|v| v.parse().ok()) {
        m.set_prover_key_budget(b);
        println!("tier {}: prover cache budget set to {b} bytes", tier.0);
    }
    let extra: usize = std::env::var("MEMPROFILE_PROVES").ok().and_then(|v| v.parse().ok()).unwrap_or(3usize).saturating_sub(3);
    let mut proofs = vec![];
    let mut repeats = vec![];
    for label in ["first prove ", "repeat prove", "third prove "].into_iter().chain(std::iter::repeat_n("later prove ", extra)) {
        let ((proof, _), s, start, peak) = measured(|| m.prove(&p, &[], &[], Some(tier)).unwrap());
        println!(
            "tier {}: {label}                {s:8.3} s   peak +{peak:9.1} MiB over {start:8.1} MiB held = {:9.1} MiB   (preprocessed builds so far {}, cache holds {:.1} MiB by its own count)",
            tier.0, start + peak, m.prover_key_builds(), m.prover_key_bytes() as f64 / MB,
        );
        if !proofs.is_empty() { repeats.push(s); }
        proofs.push(proof);
    }
    println!("tier {}: mean of the {} proves after the first {:8.3} s (min {:.3}, max {:.3})", tier.0, repeats.len(), repeats.iter().sum::<f64>() / repeats.len() as f64, repeats.iter().cloned().fold(f64::MAX, f64::min), repeats.iter().cloned().fold(0.0, f64::max));
    for (label, proof) in ["first verify ", "repeat verify", "third verify "].iter().zip(&proofs) {
        let (r, s, _, peak) = measured(|| m.verify(&hc, proof));
        r.unwrap();
        println!("tier {}: {label}               {s:8.3} s   peak +{peak:9.1} MiB", tier.0);
    }
    // What the prover cache really holds, by the allocator: the live heap before and after emptying it.
    let before = LIVE.load(Relaxed);
    let counted = m.prover_key_bytes();
    m.set_prover_key_budget(0);
    println!(
        "tier {}: held after the run {:.1} MiB (proofs included); emptying the prover cache freed {:.1} MiB, which it had counted as {:.1} MiB",
        tier.0, before as f64 / MB, before.saturating_sub(LIVE.load(Relaxed)) as f64 / MB, counted as f64 / MB,
    );
}

#[test]
#[ignore = "a measurement (seconds); prints prove/verify time and peak live heap at tier 10"]
fn tier10() { run(Tier(10), 150); }

#[test]
#[ignore = "a measurement (about half a minute with --features parallel); tier 12"]
fn tier12() { run(Tier(12), 650); }

#[test]
#[ignore = "a measurement (minutes; about 3 GB live); tier 14"]
fn tier14() { run(Tier(14), 650); }
