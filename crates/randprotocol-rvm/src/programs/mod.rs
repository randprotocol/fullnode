//! The rVM programs. In M5.1 there is one: [`verify_rv32`], a port of `verify_batch` →
//! `HidingFriPcs::verify` → `verify_fri` → `verify_multi_batch`, step for step, in the order those
//! functions run.
//!
//! A program is built for one [`InnerShape`] and one [`InnerKey`] and is identified by its
//! [`crate::isa::Program::digest`], so "which inner verifier ran" is a value the fullnode registers
//! rather than a convention. Two builds exist per shape: `Checkpoints::Off` is the shipped program,
//! whose `PUBLIC` layout is spec §4.4 exactly, and `Checkpoints::On` additionally publishes every
//! intermediate the differential tests compare against. Both record the same checkpoint *names*, in
//! the same order, which is what lets [`checkpoint_values`] read the `On` build's public values back
//! as a name-keyed map.

pub mod constraints;
mod rv32;
mod rv32n;
mod rv32r;

pub use rv32::{cycle_report, digest_hex, reduce_compiled, run_reduce_sequence, verify_rv32, verify_rv32_with, CycleReport, Precompiles};
pub use rv32n::{aggregate_program_digest, verify_rv32n};
pub use rv32r::{self_program_digest, verify_rv32r};

use crate::dsl::{Checkpoints, Stats};
use constraints::Phase5Cost;
use crate::emulator::Execution;
use crate::isa::{Program, EF, F};
use crate::shape::{InnerShape, VerifierShape};
use p3_field::BasedVectorSpace;
use std::collections::BTreeMap;

/// A built program, together with everything needed to feed and interpret it. Generic over
/// [`VerifierShape`] (M5.4, T5) with the RV32 machine's shape as the default, so every existing
/// use means `VerifierProgram<InnerShape>`.
#[derive(Clone, Debug)]
pub struct VerifierProgram<S: VerifierShape = InnerShape> {
    pub program: Program,
    pub shape: S,
    pub key: S::Key,
    pub checkpoints: Checkpoints,
    pub stats: Stats,
    /// Per instance, what its phase-5 constraint block cost — the DAG-sharing statistics and the
    /// instruction count spec §4.3's generated evaluation comes to. Recorded here because the
    /// milestone's exit is a *measured* number: it is a byproduct of building the program, not an
    /// estimate made about it.
    pub phase5: Vec<Phase5Cost>,
    /// The program's instruction count split by phase, in emission order — phases 0–4 (header,
    /// transcript, commitments, challenges), 5 (constraint evaluation), the phase-6 preamble
    /// (claimed-evaluation observation, betas, final poly, arity schedule, the query PoW and the
    /// index sampling), the four query-major segment reads, the unrolled query loop, and phase 8
    /// (the §4.4 public values). The program is straight-line apart from its assertion traps, so
    /// for an accepting run these are also the cpu rows per phase.
    pub phase_rows: Vec<(&'static str, usize)>,
    /// The checkpoint names in emission order — the same list under `Off` and `On`, which is what
    /// makes the two builds comparable. Needed because `Builder::checkpoint_names` does not survive
    /// `Builder::finish`, and [`checkpoint_values`] is nothing without it.
    pub checkpoint_names: Vec<String>,
}

/// The `Checkpoints::On` build's intermediates, keyed by name.
///
/// Under `On`, every checkpoint is two `PUBLIC` rows (`c0` then `c1`) and they are the *first*
/// public values the program emits — spec §4.4's own list comes at the very end of the program, in
/// phase 8 — so the `i`-th name pairs with `public[2i..2i+2]`. Panics if the two do not line up,
/// which they cannot unless a checkpoint was added without a name or the program did not run to
/// completion.
pub fn checkpoint_values<S: VerifierShape>(vp: &VerifierProgram<S>, exec: &Execution) -> BTreeMap<String, EF> {
    assert_eq!(
        vp.checkpoints,
        Checkpoints::On,
        "checkpoint_values reads the Checkpoints::On build's public values; the Off build emits none"
    );
    let want = 2 * vp.checkpoint_names.len();
    assert!(
        exec.public.len() >= want,
        "{} checkpoints need {want} public words, the run emitted {}",
        vp.checkpoint_names.len(),
        exec.public.len()
    );
    vp.checkpoint_names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let pair: [F; 2] = [exec.public[2 * i], exec.public[2 * i + 1]];
            let v = EF::from_basis_coefficients_slice(&pair)
                .expect("an extension element is two coefficients");
            (name.clone(), v)
        })
        .collect()
}
