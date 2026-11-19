//! Peak live heap of one RV32 proof under each quotient layout (monorepo issue 64, ZKVM-111), at
//! the live `FriProfile::Production` (rate 1/4 since constraint set 11; `PerInstance` is the live
//! layout, `PerChunk` the one it replaced).
//! A counting global allocator, so its own test binary; every test is `#[ignore]`d and meant to
//! be run one per process:
//!
//! ```sh
//! for l in per_chunk per_instance; do for t in 12 14; do
//!   cargo test --release --test quotient_layout_heap tier${t}_${l} -- --ignored --nocapture --exact
//! done; done
//! ```
//!
//! The figure is the high-water mark of live bytes during `prove_traces_with_layout` (the
//! traces are built before the mark is reset, and stay live). Single-threaded unless the crate
//! is built with a parallel prover. Tier 18 is not run here: at the tier-16 figure times four
//! it is past what this harness may use on a shared 48 GB machine.
use p3_batch_stark::QuotientLayout::{self, PerChunk, PerInstance};
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::guests;
use randprotocol_zkvm::machine::{build_traces, FriProfile, Machine, Tier};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn bump(n: usize) {
    let v = LIVE.fetch_add(n, Relaxed) + n;
    PEAK.fetch_max(v, Relaxed);
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

fn measure(tier: Tier, layout: QuotientLayout) {
    let profile = FriProfile::Production;
    // A production-size profile: the query count does not size the LDEs, but it does size the
    // openings, so the proof bytes printed are the production ones.
    let m = Machine::new(profile);
    let p = guests::fib(10);
    let exec = execute(&p, &[], &[], tier.max_cycles()).unwrap();
    let traces = build_traces(&p, &[], &[], &exec, tier).unwrap();
    let before = LIVE.load(Relaxed);
    PEAK.store(before, Relaxed);
    let t0 = std::time::Instant::now();
    let proof = m.prove_traces_with_layout(&traces, tier, layout);
    let prove = t0.elapsed();
    let peak = PEAK.load(Relaxed);
    let bytes = postcard::to_allocvec(&proof).unwrap().len();
    let t1 = std::time::Instant::now();
    m.verify_with_layout(&p.digest(), &proof, layout).unwrap();
    eprintln!(
        "MEASURE {profile:?} tier {} {:?}: peak live heap {:.3} GB ({:.3} GB live before the prove), prove {:.1} s, verify {:.2} s, proof {bytes} bytes",
        tier.0,
        layout,
        peak as f64 / 1e9,
        before as f64 / 1e9,
        prove.as_secs_f64(),
        t1.elapsed().as_secs_f64()
    );
}

#[test]
#[ignore = "measurement, one per process"]
fn tier12_per_chunk() { measure(Tier(12), PerChunk) }
#[test]
#[ignore = "measurement, one per process"]
fn tier12_per_instance() { measure(Tier(12), PerInstance) }
#[test]
#[ignore = "measurement, one per process (about 1 GB)"]
fn tier14_per_chunk() { measure(Tier(14), PerChunk) }
#[test]
#[ignore = "measurement, one per process (about 1 GB)"]
fn tier14_per_instance() { measure(Tier(14), PerInstance) }
#[test]
#[ignore = "measurement, one per process (several GB)"]
fn tier16_per_instance() { measure(Tier(16), PerInstance) }
/// The issue's acceptance run (ZKVM-111 item 6): a tier-18 proof at the live profile and layout.
/// Projected at about 38 GB of live heap from the tier-14 and tier-16 figures
/// (`docs/05-roadmap.md`); not run from an agent session.
#[test]
#[ignore = "measurement, one per process; tier 18, tens of GB — run from a plain terminal on a big host"]
fn tier18_per_instance() { measure(Tier(18), PerInstance) }
