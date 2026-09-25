//! The self-verifier (M5.4 Task 5, spec §4.5): the rVM verifying an rVM proof — one
//! `machine::Proof` of the committed program, verified in-circuit by [`verify_rv32r`].
//!
//! The program is `rv32.rs`'s phases 0–7 over the rVM's own shape — the shared
//! [`emit_proof`], with `machine::chips`' AIRs driven through the same `Emit` (the constraint
//! emitter walks any AIR's `SymbolicExpression` DAG) — and then `rv32.rs`'s phase 8, with the
//! interface list being the rVM's own: `[rvm_vk_digest ‖ N = 1 ‖ B(8) ‖ the proof's
//! `NUM_PUBLIC_VALUES` words]`, where B is the outer transaction's aggregate binding (audit
//! v3, AGG-2). A tree of aggregates is this program over a tape of rVM
//! proofs (M5.3's counted loop, unchanged); M5.4 ships the single-proof form and its measured
//! requirement.

use crate::dsl::hash;
use crate::dsl::{Builder, Checkpoints, Digest, DIGEST_ELEMS};
use crate::isa::F;
use crate::public_values::RVM_PUB_DOMAIN;
use crate::shape::{RvmKey, RvmShape, VerifierShape};
use p3_field::PrimeCharacteristicRing;

use super::rv32::{emit_proof, vk_digest_in_program};
use super::VerifierProgram;

/// Builds the self-verifier program for one rVM shape: the shared per-proof pipeline with a
/// fresh challenger, then the interface digest over `[rvm_vk_digest ‖ 1 ‖ B(8) ‖ 4]`.
pub fn verify_rv32r(shape: &RvmShape, key: &RvmKey, cp: Checkpoints) -> VerifierProgram<RvmShape> {
    let mut b = Builder::with_opts(cp, crate::dsl::Liveness::On, super::Precompiles::On);
    // The rVM's batch public values are exactly four: the inner proof's interface digest.
    let npv = shape.num_public_values()[shape.pv_instance()];

    // ── the outer transaction's aggregate binding (audit v3, AGG-2), hinted ahead of the
    // proof's region — the tape is `WitnessTape::build_for_with_binding`'s `[B(8) ‖ region]` —
    // and absorbed into the interface between the count and the public values, exactly as the
    // N-generic program absorbs it after `N`. A tree of aggregates is this program over a tape
    // of rVM proofs, whose root aggregate's `(chain, aggregator, nonce)` these words bind.
    let bind = b.alloc(8);
    for k in 0..8i64 {
        let w = b.hint();
        b.store(bind, k, w);
    }

    let (pvs, phase5) = emit_proof(&mut b, shape, key);

    // ── phase 8: acceptance and the interface digest ────────────────────────────────────────
    // `rvm_vk_digest` recomputed in-program from the compile-time shape words and the key's cap
    // (bound by the program digest twice over), then the list `[vk(4) ‖ N = 1 ‖ B(8) ‖ the
    // proof's four public values]`, sponged with the capacity header, the digest's four lanes
    // published — `rv32.rs`'s phase 8 construction, word for word.
    let vk = vk_digest_in_program(&mut b, shape, key);
    let n_list = DIGEST_ELEMS + 1 + 8 + npv;
    let list = b.alloc(n_list as u64);
    for lane in 0..DIGEST_ELEMS as i64 {
        let v = b.load(vk.0, lane);
        b.store(list, lane, v);
    }
    let one = b.constant(F::ONE);
    b.store(list, DIGEST_ELEMS as i64, one);
    for k in 0..8i64 {
        let v = b.load(bind, k);
        b.store(list, (DIGEST_ELEMS + 1) as i64 + k, v);
    }
    for k in 0..npv {
        let v = b.get(pvs, k);
        b.store(list, (DIGEST_ELEMS + 1 + 8 + k) as i64, v);
    }
    let interface = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::sponge_seeded(&mut b, RVM_PUB_DOMAIN, list, n_list, interface);
    for lane in 0..DIGEST_ELEMS as i64 {
        let v = b.load(interface.0, lane);
        b.public(v);
    }
    b.note_phase("phase 8: the interface digest");

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

/// The self-verifier program's digest, built deterministically from `(shape, key)` — one per
/// rVM shape, exactly as `aggregate_program_digest` is one per inner shape.
pub fn self_program_digest(shape: &RvmShape, key: &RvmKey) -> [F; 4] {
    verify_rv32r(shape, key, Checkpoints::Off).program.digest()
}
