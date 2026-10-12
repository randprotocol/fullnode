//! Regression tests for the two latent register-allocator miscompilations of issue #63
//! (randprotocol/fullnode#63, R62-DSL-1 and R62-DSL-2): control-flow shapes where the replay's
//! straight-line view of the buffer disagreed with what the emitted program executes. Each test
//! accepts exactly two outcomes — the program computes what its DSL source says, or the build is
//! refused with the allocator's own message. What it must never do is compile to a program that
//! computes something else.
use std::panic::{catch_unwind, AssertUnwindSafe};

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_rvm::dsl::{Builder, Checkpoints};
use randprotocol_rvm::emulator::execute;
use randprotocol_rvm::isa::{Op, Program, F};

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

/// 40 constants (more than the 25 allocatable registers), then every one read three times, far
/// apart: without re-homing every read after the first spill is a reload; with it, a reload
/// whose next use is near takes a real register and the later reads hit it.
fn pressure_program(b: &mut Builder) -> F {
    let vals: Vec<_> = (1..=40u64).map(|k| b.constant(F::from_u64(k))).collect();
    let mut acc = b.zero();
    for _round in 0..3 {
        for v in &vals {
            let t = b.mul(*v, *v);
            acc = b.add(acc, t);
        }
    }
    b.public(acc);
    F::from_u64(3 * (1..=40u64).map(|k| k * k).sum::<u64>())
}

#[test]
fn a_reload_rehomes_into_a_real_register_and_the_result_is_unchanged() {
    let mut b = Builder::new(Checkpoints::Off);
    let want = pressure_program(&mut b);
    let (p, stats) = b.finish_stats();
    assert!(stats.rehomes > 0, "the pressure program must re-home: {stats:?}");
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, vec![want]);
}

/// Rule 4(b): an instruction whose two operands are both spilled — the re-home claim for one must
/// not evict the register the other was just loaded into. A wrong eviction changes the sum.
#[test]
fn a_rehome_never_evicts_an_operand_of_the_instruction_it_feeds() {
    let mut b = Builder::new(Checkpoints::Off);
    let vals: Vec<_> = (1..=60u64).map(|k| b.constant(F::from_u64(k))).collect();
    let mut acc = b.zero();
    for w in vals.windows(2).rev() {
        let t = b.mul(w[0], w[1]);
        acc = b.add(acc, t);
    }
    for w in vals.windows(2) {
        let t = b.sub(w[1], w[0]);
        acc = b.add(acc, t);
    }
    b.public(acc);
    let want: u64 = (1..60u64).map(|k| k * (k + 1)).sum::<u64>() + 59;
    let (p, stats) = b.finish_stats();
    assert!(stats.rehomes > 0, "{stats:?}");
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, vec![F::from_u64(want)]);
}

/// Rule 2: inside an `if_eq` body every reload goes to scratch (r26..r31). A re-home there would
/// move a register on one path only, which the replay refuses (or worse).
#[test]
fn no_reload_inside_an_if_eq_body_lands_in_an_allocatable_register() {
    let mut b = Builder::new(Checkpoints::Off);
    let vals: Vec<_> = (1..=40u64).map(|k| b.constant(F::from_u64(k))).collect();
    let cell = b.alloc(1);
    let z = b.zero();
    b.store(cell, 0, z);
    let x = b.hint();
    let one = b.constant(F::ONE);
    b.if_eq(x, one, |b| {
        let mut acc = b.zero();
        for v in vals.iter().chain(vals.iter()) {
            acc = b.add(acc, *v);
        }
        b.store(cell, 0, acc);
    });
    let out = b.load(cell, 0);
    b.public(out);
    for v in &vals { b.public(*v); }
    let p = b.finish();
    // The body is the pc range between the JNE and its target.
    let jne = p.instrs.iter().position(|i| i.op == Op::Jne).unwrap();
    let end = p.instrs[jne].b.as_canonical_u64() as usize;
    for (pc, ins) in p.instrs[jne + 1..end].iter().enumerate() {
        if ins.op == Op::Load && ins.ra == 0 {
            assert!(ins.rd >= 26, "pc {}: a reload inside the if_eq body went to r{}", jne + 1 + pc, ins.rd);
        }
    }
    let taken = execute(&p, &[F::ONE], 1_000_000).unwrap().public;
    let skipped = execute(&p, &[F::ZERO], 1_000_000).unwrap().public;
    assert_eq!(taken[0], F::from_u64(2 * 820));
    assert_eq!(skipped[0], F::ZERO);
    assert_eq!(taken[1..], skipped[1..]);
}

/// Rule 3 and 4(c): a loop body under pressure that reloads body-defined values (which may
/// re-home) while pre-loop handles stay resident across it — the build must not trip the
/// replay's loop invariant, and every iteration computes the same thing.
#[test]
fn a_loop_body_rehomes_only_its_own_values_and_never_moves_a_pre_loop_handle() {
    let mut b = Builder::new(Checkpoints::Off);
    let outer: Vec<_> = (1..=10u64).map(|k| b.constant(F::from_u64(k))).collect();
    let cell = b.alloc_absolute(1);
    let acc_cell = b.alloc(1);
    let z = b.zero();
    b.store(acc_cell, 0, z);
    let n = b.constant(F::from_u64(3));
    b.counted_loop_mem(cell, n, |b| {
        let inner: Vec<_> = (1..=30u64).map(|k| b.constant(F::from_u64(k))).collect();
        let mut acc = b.load(acc_cell, 0);
        for _ in 0..2 {
            for v in &inner {
                acc = b.add(acc, *v);
            }
        }
        for v in &outer {
            acc = b.add(acc, *v);
        }
        b.store(acc_cell, 0, acc);
    });
    let out = b.load(acc_cell, 0);
    b.public(out);
    let (p, stats) = b.finish_stats();
    assert!(stats.rehomes > 0, "the loop body must re-home its own values (rule 4(c) exercised): {stats:?}");
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, vec![F::from_u64(3 * (2 * 465 + 55))]);
}

/// Rule 3, the main case: pre-loop handles spilled before `LoopTop` and read in the body reload
/// into scratch (r26..r31) on every read — never re-homed into an allocatable register, even with
/// vacant registers at the top (the ten temporaries die just before it). A re-home there would
/// move a pre-loop handle inside the body, which the loop invariant refuses. The body defines
/// nothing, so every `LOAD r, r0, addr` in it is a pre-loop handle's reload.
#[test]
fn a_pre_loop_handle_spilled_at_loop_top_reloads_in_the_body_without_rehoming() {
    let mut b = Builder::new(Checkpoints::Off);
    let vals: Vec<_> = (1..=30u64).map(|k| b.constant(F::from_u64(100 + k))).collect();
    for k in 1..=10u64 {
        let t = b.constant(F::from_u64(900 + k));
        b.public(t);
    }
    let n = b.constant(F::from_u64(2));
    b.counted_loop(n, |b, _| {
        for v in &vals {
            b.public(*v);
        }
    });
    for v in &vals {
        b.public(*v);
    }
    let p = b.finish();
    let jne = p.instrs.iter().rposition(|i| i.op == Op::Jne).unwrap();
    let top = p.instrs[jne].b.as_canonical_u64() as usize;
    assert!(top < jne, "the loop's back edge jumps backward");
    let body_reloads: Vec<_> = (top..jne).filter(|&pc| p.instrs[pc].op == Op::Load && p.instrs[pc].ra == 0).collect();
    assert!(!body_reloads.is_empty(), "the body must reload a spilled pre-loop handle, or this test exercises nothing");
    for pc in body_reloads {
        assert!(p.instrs[pc].rd >= 26, "pc {pc}: a pre-loop handle was re-homed into r{} inside the loop", p.instrs[pc].rd);
    }
    let mut want: Vec<F> = (1..=10u64).map(|k| F::from_u64(900 + k)).collect();
    for _ in 0..3 {
        want.extend((1..=30u64).map(|k| F::from_u64(100 + k)));
    }
    assert_eq!(publics(&p), want);
}

/// A functional smoke test for rule 1's subject: a `counted_loop` whose counter is decremented
/// in place (`FADDI ctr, ctr, −1`) computes the right sum. The counter never spills here, so this
/// test does NOT guard rule 3 or the `mutable` guard (rule 1: a handle written in place is never
/// re-homed, since its cell would go stale) — removing either leaves it green. Today rule 3 and
/// the loop invariant already keep the counter from being re-homed: it is defined just before its
/// own `LoopTop`, it is never spilled outside the loop, and evicting it in the body is the
/// `LoopEnd` refusal; the `mutable` guard is defence in depth with no failing-first test.
#[test]
fn the_counted_loop_counter_is_never_rehomed() {
    let mut b = Builder::new(Checkpoints::Off);
    let cell = b.alloc(1);
    let z = b.zero();
    b.store(cell, 0, z);
    let n = b.constant(F::from_u64(5));
    b.counted_loop(n, |b, i| {
        let mut acc = b.load(cell, 0);
        acc = b.add(acc, i);
        b.store(cell, 0, acc);
    });
    let out = b.load(cell, 0);
    b.public(out);
    let p = b.finish();
    assert_eq!(execute(&p, &[], 1_000_000).unwrap().public, vec![F::from_u64(5 + 4 + 3 + 2 + 1)]);
}

/// Review Focus 3: a re-homed value keeps its spill cell and gives it back when it dies, so a long
/// run of re-home/die cycles does not grow the spill arena past the run without them.
#[test]
fn rehomed_values_return_their_cells_when_they_die() {
    let mut b = Builder::new(Checkpoints::Off);
    let mut acc = b.zero();
    for block in 0..50u64 {
        let vals: Vec<_> = (1..=30u64).map(|k| b.constant(F::from_u64(block * 100 + k))).collect();
        for _ in 0..2 {
            for v in &vals {
                acc = b.add(acc, *v);
            }
        }
    }
    b.public(acc);
    let (_p, stats) = b.finish_stats();
    assert!(stats.rehomes > 0, "{stats:?}");
    assert!(stats.cells < 200, "the arena grew with the number of blocks: {} cells", stats.cells);
}
