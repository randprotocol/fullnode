//! The tree step (tree aggregation, spec §3): the rVM verifying **two** rVM proofs of one
//! compile-time child shape and publishing `[vk_c ‖ 2 ‖ B(8) ‖ D_1 ‖ D_2]` — 21 words, sponged
//! under `RVM_PUB_DOMAIN` with the count in the capacity lane, the digest's four lanes public.
//!
//! The child's *shape* is compile-time; its *key* is not. The cap is hinted (tape words 8..24),
//! `vk_c = H(RVM_VK_DOMAIN ‖ shape_words ‖ cap)` is computed in-program over it, and both children
//! are checked against that same cap. A wrong cap therefore either fails in-program (honest
//! children of another key) or publishes another `vk_c` (children of the program the cap
//! belongs to), which the chain's bottom-up recompute refuses (spec §4; ruling 2). That is what
//! breaks the circular key: `rv32t_int` verifies proofs of itself without embedding its own
//! commitment.
//!
//! The body is `rv32n`'s counted loop with the constant count `TREE_ARITY` (R1): one emission of
//! the per-proof pipeline, run twice with a fresh challenger each time, so the program's static
//! reduce rows are one child's and `Machine::verify_n(program, proof, 2)` is the canonical
//! height. The interface list is never materialised: `hash::absorb_staged` over a dedicated
//! eight-cell state, `rv32n`'s schedule word for word (block zero `vk_c`, then `N`, the eight
//! binding words, and each child's four public words as its iteration accepts them). No
//! `B_out == B_in` in-program (ZKQ-5, `docs/02-aggregate.md`): the chain recomputes every level.

use crate::dsl::hash;
use crate::dsl::{Builder, Checkpoints, Digest, DIGEST_ELEMS};
use crate::isa::F;
use crate::public_values::RVM_PUB_DOMAIN;
use crate::shape::{RvmKey, RvmShape, VerifierShape};
use p3_field::PrimeCharacteristicRing;

use super::rv32::{emit_proof_with, vk_digest_over_cap, CAP_WORDS};
use super::VerifierProgram;

/// The permutation width, in cells: the interface sponge's state size.
const WIDTH: usize = hash::WIDTH;

/// The children one step verifies (spec ruling 4: fan-out 2), and the `n` of its
/// `Machine::verify_n`.
pub const TREE_ARITY: u64 = 2;

/// Builds the tree step for children of `child`'s shape. Only the shape words are read (see
/// `RvmShape::same_step_words`); the child key is a tape value.
pub fn verify_rv32t(child: &RvmShape, cp: Checkpoints) -> VerifierProgram<RvmShape> {
    let mut b = Builder::with_opts(cp, crate::dsl::Liveness::On, super::Precompiles::On);
    let npv = child.num_public_values()[child.pv_instance()];
    assert_eq!(npv, DIGEST_ELEMS, "an rVM proof publishes exactly its four-word interface digest");

    let (st, cursor, n) = b.span("tree preamble", |b| {
        // ── B (audit v3, AGG-2), hinted. Absolute: the loop never reads it, but nothing pre-loop
        // may claim a register the replay's loop invariant could see moved.
        let bind = b.alloc_absolute(8);
        for k in 0..8i64 {
            let w = b.hint();
            b.store(bind, k, w);
        }
        // ── the child cap, hinted: sixteen words, two rows each. Absolute, because both loop
        // iterations read it, as their preprocessed commitment.
        let cap = b.alloc_absolute(CAP_WORDS as u64);
        for k in 0..CAP_WORDS as i64 {
            let w = b.hint();
            b.store(cap, k, w);
        }
        // ── the interface state: zero lanes, the domain and the fixed length 4 + 1 + 8 + 4·2 = 21
        // in the capacity lanes, then vk_c (computed over the hinted cap) as block zero, then N.
        let st = b.alloc_absolute(WIDTH as u64);
        b.zero_cells(st, 0, WIDTH);
        let dom = b.constant(F::from_u64(RVM_PUB_DOMAIN));
        b.store(st, 4, dom);
        let len = b.constant(F::from_u64((DIGEST_ELEMS + 1 + 8 + TREE_ARITY as usize * npv) as u64));
        b.store(st, 5, len);
        let vk = vk_digest_over_cap(b, child, cap);
        // `rv32n`'s rule: the vk sponge's hash scratch is pre-loop state the body would see moved.
        b.release_hash_scratch();
        b.copy_cells(st, 0, vk.0, 0, DIGEST_ELEMS);
        b.poseidon2(st);
        let n = b.constant(F::from_u64(TREE_ARITY));
        b.store(st, 0, n);
        let cursor = b.alloc_absolute(1);
        let first = b.constant(F::from_u64(b.addr_of(st) + 1));
        b.store(cursor, 0, first);
        for k in 0..8i64 {
            let v = b.load(bind, k);
            hash::absorb_staged(b, st, cursor, v);
        }
        ((st, cap), cursor, n)
    });
    let (st, cap) = st;
    b.note_phase("tree preamble: the binding, the child cap, vk_c, the interface state");

    // ── the two children: the fresh-challenger pipeline against the hinted cap, then the child's
    // four public words absorbed. Everything the body needs is created inside it or is absolute.
    let counter = b.alloc_absolute(1);
    let mut phase5 = Vec::new();
    b.counted_loop_mem(counter, n, |b| {
        let (pvs, cost) = b.span("tree child", |b| {
            emit_proof_with(b, child, |b| std::array::from_fn(|i| Digest(b.offset(cap, (i * DIGEST_ELEMS) as i64))))
        });
        phase5 = cost;
        for k in 0..npv {
            let v = b.get(pvs, k);
            hash::absorb_staged(b, st, cursor, v);
        }
    });
    b.note_phase("the two-child loop");

    // ── a block is always pending (`absorb_staged` defers each permutation), so exactly one
    // final permutation; its four lanes are the program's only public values.
    b.poseidon2(st);
    for lane in 0..DIGEST_ELEMS as i64 {
        let v = b.load(st, lane);
        b.public(v);
    }
    b.note_phase("post-loop: the final permutation");

    let checkpoint_names = b.checkpoint_names().to_vec();
    let (program, mut stats) = b.finish_stats();
    let phase_rows = std::mem::take(&mut stats.phase_rows);
    VerifierProgram {
        program,
        shape: child.clone(),
        // No key is baked: the cap is a tape value, published as `vk_c`. Nothing reads this field
        // (`cycle_report` reads the program and the run).
        key: RvmKey { cap: [[F::ZERO; 4]; 4] },
        checkpoints: cp,
        stats,
        phase5,
        phase_rows,
        checkpoint_names,
    }
}

/// Level 1: children are leaves, `rv32n` proofs over L bundle proofs, at the leaf's declared
/// shape (`RvmShape::of_proof(profile, aggregate_program, leaf)`).
pub fn rv32t_leaf(leaf: &RvmShape, cp: Checkpoints) -> VerifierProgram<RvmShape> {
    verify_rv32t(leaf, cp)
}

/// Levels ≥ 2: children are steps at the step shape, the declared shape of an `rv32t_leaf`
/// proof. It is also `rv32t_int`'s own output shape when the fixed point holds (R3,
/// `the_interior_step_verifies_its_own_output`).
pub fn rv32t_int(step: &RvmShape, cp: Checkpoints) -> VerifierProgram<RvmShape> {
    verify_rv32t(step, cp)
}

/// What a chain pins (spec §4, `t_leaf_digest`/`t_int_digest`): the step's program digest at a
/// child shape, checkpoints off.
pub fn tree_step_program_digest(child: &RvmShape) -> [F; 4] {
    verify_rv32t(child, Checkpoints::Off).program.digest()
}
