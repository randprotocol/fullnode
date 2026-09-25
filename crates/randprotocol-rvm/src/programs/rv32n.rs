//! The N-generic aggregate program (M5.3, ruling R1): one counted loop over the tape's `N`,
//! each iteration the per-proof pipeline of `rv32.rs` over that proof's region with a fresh
//! challenger (R2), then the interface digest over `[inner_vk_digest ‖ N ‖ B(8) ‖ 34·N]` (R5;
//! B = the chain's aggregate binding, audit v3's AGG-2).
//!
//! Shape-specialised per `InnerShape`, exactly as the single-proof program is: one program —
//! and one [`Program::digest`] for the fullnode to register — covers every `N` the tape holds,
//! because the loop count is a *tape value*, not a build-time constant. That is what makes the
//! interface digest's length runtime too, and the runtime length is what the one genuinely new
//! piece here answers: the interface list is never materialised. Its words are absorbed into a
//! running padding-free sponge as they exist — the vk digest as block zero, `N` as the next
//! word, the eight binding words after it, and each proof's thirty-four public values as its
//! iteration accepts them — through a cursor cell tracking the next rate lane's absolute
//! address (`dsl::hash::absorb_staged`). The state lives in eight *dedicated* cells: the
//! pipeline hashes through the shared `Builder::hash_scratch` tens of thousands of times per
//! iteration, and the interface sponge must survive that untouched.
//!
//! The absorb schedule is the host's (`public_values::public_digest`), word for word: a full
//! block permutes when its fourth word lands, and the trailing partial block overwrites only its
//! own lanes and permutes once. With the stream `[vk(4) ‖ N ‖ B(8) ‖ 34·N]`, the position after
//! the last word is `(9 + 34N) mod 4 = (1 + 34N) mod 4 ∈ {1, 3}` for `N ≥ 1` — the eight
//! binding words are exactly two rate fills, so they leave the schedule where the count word
//! alone left it — never a block boundary, so the final permutation is unconditional, one row,
//! no branch.

use crate::dsl::hash;
use crate::dsl::{Builder, Checkpoints, DIGEST_ELEMS};
use crate::isa::F;
use crate::public_values::RVM_PUB_DOMAIN;
use crate::shape::{InnerKey, InnerShape, PV_INSTANCE};
use p3_field::PrimeCharacteristicRing;

use super::rv32::{emit_proof, vk_digest_in_program};
use super::VerifierProgram;

/// The permutation width, in cells: the interface sponge's state size.
const WIDTH: usize = hash::WIDTH;

/// Builds the N-generic aggregate program for one inner shape.
pub fn verify_rv32n(shape: &InnerShape, key: &InnerKey, cp: Checkpoints) -> VerifierProgram {
    let mut b = Builder::with_opts(cp, crate::dsl::Liveness::On, super::Precompiles::On);
    let npv = shape.num_public_values[PV_INSTANCE];

    // ── the count word, and the counted loop's `n >= 1` precondition enforced in-program: an
    // empty aggregate is refused here, before any proof is read. Then the eight
    // aggregate-binding words (audit v3, AGG-2): the chain's
    // `H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖ nonce)`, hinted straight after the
    // count and absorbed into the interface sponge between `N` and the public values, so the
    // proof binds the one `(chain, aggregator, nonce)` it was made under and a re-signed copy
    // of the same proof bytes no longer verifies.
    let n = b.hint();
    b.assert_nonzero(n, "aggregate count");
    let bind = b.alloc_absolute(8);
    for k in 0..8i64 {
        let w = b.hint();
        b.store(bind, k, w);
    }

    // ── the interface sponge's preamble. The state: zero lanes, the domain tag and the word
    // count `4 + 1 + 8 + 34·N` in the capacity lanes — the count computed from the tape's `N`, so
    // two different lengths are different digests by construction. Then the vk digest as block
    // zero, and `N` opening block one. The state and the cursor are addressed absolutely: they
    // live across the loop, and an absolute pointer claims no register the replay's loop
    // invariant could see moved under the body's pressure.
    let st = b.alloc_absolute(WIDTH as u64);
    b.zero_cells(st, 0, WIDTH);
    let dom = b.constant(F::from_u64(RVM_PUB_DOMAIN));
    b.store(st, 4, dom);
    let per_proof = b.constant(F::from_u64(npv as u64));
    let len = b.mul(n, per_proof);
    let len = b.add_const(len, F::from_u64((DIGEST_ELEMS + 1 + 8) as u64));
    b.store(st, 5, len);
    let vk = vk_digest_in_program(&mut b, shape, key);
    // The vk sponge's hash scratch is a pre-loop allocation whose next use would be the body's
    // first hash — loop-invariant state the body's register pressure evicts, and the replay's
    // loop invariant then names. Forget it: the body allocates its own scratch on first use,
    // inside the loop, where the invariant does not look.
    b.release_hash_scratch();
    b.copy_cells(st, 0, vk.0, 0, DIGEST_ELEMS);
    b.poseidon2(st);
    b.store(st, 0, n);
    // The cursor: the absolute address of the next rate lane to write, advanced by every
    // absorbed word and rewound by every rate-fill permutation.
    let cursor = b.alloc_absolute(1);
    let first = b.constant(F::from_u64(b.addr_of(st) + 1));
    b.store(cursor, 0, first);
    // The binding words absorb next, from lane 1: eight words are exactly two rate fills, so
    // the cursor re-enters the loop's absorb schedule at the same lane the count word alone
    // used to leave it in — the trailing partial-block analysis is the pre-binding one,
    // unchanged.
    for k in 0..8i64 {
        let v = b.load(bind, k);
        hash::absorb_staged(&mut b, st, cursor, v);
    }
    b.note_phase("preamble: the count word, the binding words, the interface state, the vk digest");

    // ── the counted loop: N proofs, each the fresh-challenger pipeline, then its public values
    // absorbed into the running sponge as the iteration accepts them. Everything the iteration
    // needs is created inside the body or passed through memory cells — the replay's loop
    // invariant leaves every pre-loop allocation unmoved, checked at build time. The counter is
    // a memory cell too: a register counter's only use is the post-body decrement, and the
    // body's register pressure evicts exactly such a handle.
    let counter = b.alloc_absolute(1);
    let mut phase5 = Vec::new();
    b.counted_loop_mem(counter, n, |b| {
        let (pvs, cost) = emit_proof(b, shape, key);
        phase5 = cost;
        for k in 0..npv {
            let v = b.get(pvs, k);
            hash::absorb_staged(b, st, cursor, v);
        }
    });
    b.note_phase("the N-proof loop");

    // ── the trailing partial block always exists ((1 + 34N) mod 4 ∈ {1, 3}), so exactly one
    // final permutation — then the digest's four lanes are the program's only public values,
    // exactly as the single-proof program publishes them.
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
        shape: shape.clone(),
        key: key.clone(),
        checkpoints: cp,
        stats,
        phase5,
        phase_rows,
        checkpoint_names,
    }
}

/// What the fullnode registers (R6): the N-generic program's digest, built deterministically
/// from `(shape, key)` — the shipped build, checkpoints off. One per inner shape, covering every
/// `N`; a test rebuilds it twice and compares.
pub fn aggregate_program_digest(shape: &InnerShape, key: &InnerKey) -> [F; 4] {
    verify_rv32n(shape, key, Checkpoints::Off).program.digest()
}
