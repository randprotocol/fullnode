//! Regression tests for the two latent register-allocator miscompilations of issue #63
//! (randprotocol/fullnode#63, R62-DSL-1 and R62-DSL-2): control-flow shapes where the replay's
//! straight-line view of the buffer disagreed with what the emitted program executes. Each test
//! accepts exactly two outcomes — the program computes what its DSL source says, or the build is
//! refused with the allocator's own message. What it must never do is compile to a program that
//! computes something else.
use std::panic::{catch_unwind, AssertUnwindSafe};

use p3_field::PrimeCharacteristicRing;
use randprotocol_rvm::dsl::{Builder, Checkpoints};
use randprotocol_rvm::emulator::execute;
use randprotocol_rvm::isa::{Program, F};

/// Build with `f`; `Some(program)` if the builder accepts it, `None` if it refuses the shape with
/// a panic naming `refusal` (any other panic is a test failure).
fn built_or_refused(refusal: &str, f: impl FnOnce() -> Program) -> Option<Program> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(p) => Some(p),
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            assert!(msg.contains(refusal), "the build panicked, but not with the allocator's refusal: {msg}");
            None
        }
    }
}

fn publics(p: &Program) -> Vec<F> {
    execute(p, &[], 100_000).unwrap().public
}

/// R62-DSL-1: a pre-loop handle read in the body had its last use clamped to the `LoopEnd`
/// marker and its register freed there — but `counted_loop_mem`'s back edge (the counter's
/// reload and decrement) is emitted after that marker and claimed the freed register, so from
/// the second iteration the body read the counter instead of the value. Was `[7, 3, 2]`.
#[test]
fn a_loop_mem_back_edge_never_clobbers_a_pre_loop_handle_the_body_reads() {
    let mut b = Builder::new(Checkpoints::Off);
    let x = b.constant(F::from_u64(7));
    let cell = b.alloc_absolute(1);
    let n = b.constant(F::from_u64(3));
    b.counted_loop_mem(cell, n, |b| {
        b.public(x);
    });
    let got = publics(&b.finish());
    assert_eq!(got, vec![F::from_u64(7); 3], "the loop body read a clobbered pre-loop handle");
}

/// R62-DSL-1, the eviction variant: with every allocatable register holding a handle that is
/// live after the loop, the back edge's reload must evict one. Its spill `STORE` sat inside the
/// loop, so the second iteration re-ran it from a register that by then held the counter, and
/// the handle came back from its cell as the counter. The loop invariant ran at `LoopEnd`,
/// before the back edge, and saw nothing.
#[test]
fn a_loop_mem_back_edge_eviction_is_refused_or_correct() {
    let want: Vec<F> = (1..=25u64).map(|k| F::from_u64(100 + k)).collect();
    let p = built_or_refused("counted_loop: the body moved handle", || {
        let mut b = Builder::new(Checkpoints::Off);
        let vals: Vec<_> = (1..=25u64).map(|k| b.constant(F::from_u64(100 + k))).collect();
        let cell = b.alloc_absolute(1);
        let n = b.constant(F::from_u64(3));
        b.counted_loop_mem(cell, n, |_| {});
        for v in &vals {
            b.public(*v);
        }
        b.finish()
    });
    if let Some(p) = p {
        assert_eq!(publics(&p), want, "a spill in the loop's back edge re-ran from a reused register");
    }
}

/// R62-DSL-2: a fresh handle inside an `if_eq` body evicted a live handle — a spill `STORE`
/// inside the body — and the code after the body reloads it from that cell. When the branch is
/// not taken the `STORE` never runs and the reload reads a stale cell. Was `… 125, 0`.
#[test]
fn an_if_eq_body_spill_is_refused_or_correct_on_the_not_taken_path() {
    let mut want: Vec<F> = (1..=25u64).map(|k| F::from_u64(100 + k)).collect();
    want.push(F::from_u64(2));
    let p = built_or_refused("if_eq: the body moved handle", || {
        let mut b = Builder::new(Checkpoints::Off);
        // 25 live handles fill every allocatable register.
        let vals: Vec<_> = (1..=25u64).map(|k| b.constant(F::from_u64(100 + k))).collect();
        let zero = b.zero();
        let two = b.constant(F::from_u64(2));
        b.if_eq(zero, two, |b| {
            let c = b.constant(F::from_u64(999));
            b.public(c);
        });
        for v in &vals {
            b.public(*v);
        }
        b.public(two);
        b.finish()
    });
    if let Some(p) = p {
        assert_eq!(publics(&p), want, "a skipped if_eq body left a stale spill cell");
    }
}

/// The shapes `if_eq` does support still compile and run on both paths: a body that reads
/// pre-branch handles, uses its own temporaries, and writes its result through memory.
#[test]
fn an_if_eq_body_without_spills_runs_on_both_paths() {
    for (a, taken) in [(5u64, true), (6, false)] {
        let mut b = Builder::new(Checkpoints::Off);
        let x = b.constant(F::from_u64(a));
        let five = b.constant(F::from_u64(5));
        let out = b.alloc_absolute(1);
        let init = b.constant(F::from_u64(11));
        b.store(out, 0, init);
        b.if_eq(x, five, |b| {
            let t = b.add(x, five);
            b.store(out, 0, t);
        });
        let r = b.load(out, 0);
        b.public(r);
        b.public(x);
        let want = if taken { 10 } else { 11 };
        assert_eq!(publics(&b.finish()), vec![F::from_u64(want), F::from_u64(a)]);
    }
}
