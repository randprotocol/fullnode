//! The live-heap harness shared by `tests/memprofile.rs` and `tests/tree_measure.rs`: a counting
//! global allocator (live bytes and the high-water mark) and a `tracing` subscriber printing
//! live/peak at every Plonky3 span boundary. Moved verbatim from `memprofile.rs` (2026-10-08).
#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::Instant;

// ── the counting allocator ──────────────────────────────────────────────────────────────────

struct Counting;
pub static LIVE: AtomicUsize = AtomicUsize::new(0);
pub static PEAK: AtomicUsize = AtomicUsize::new(0);

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

pub fn gb(b: usize) -> f64 {
    b as f64 / 1e9
}

pub fn rss_gb() -> f64 {
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

pub fn install() -> Instant {
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

pub fn report(what: &str, t0: Instant, rows: usize, tier: randprotocol_rvm::machine::Tier, proof_bytes: usize, prove_s: f64) {
    println!(
        "== {what}: {rows} rows, tier {}, proof {proof_bytes} B, prove {prove_s:.1} s; peak live heap {:.2} GB, live now {:.2} GB, rss now {:.2} GB, wall {:.1} s",
        tier.0,
        gb(PEAK.load(Relaxed)),
        gb(LIVE.load(Relaxed)),
        rss_gb(),
        t0.elapsed().as_secs_f64()
    );
}
