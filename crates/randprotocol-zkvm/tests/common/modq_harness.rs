//! MODQ (private multisig phase 3): the chip standalone — the modq table, a `MODQ` asker in place
//! of the cpu, a permissive `MEMORY` twin in place of the memory table (it receives whatever it is
//! given, with no order or read-after-write rule) and the range table. Task 3's harness, moved
//! here and generalised so `tests/cheating.rs` can switch one `Defence` off
//! (`ModqAirWithout(off)`) through `modq_run::run_raw_on`; `tests/modq.rs` uses `modq_run::run_raw` (real `ModqAir`). Compiled only with `cheating`.
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder};
use p3_field::Field;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use randprotocol_zkvm::machine::VerifyError;
use randprotocol_zkvm::tables::modq::{range_counts_without, Defence, Forged, ModqAirWithout};
use randprotocol_zkvm::tables::range::RangeCounts;
use randprotocol_zkvm::tables::F;

#[allow(unused_imports)]
pub use super::modq_run::{events, twin_of, Asker, MemoryTwin};
use super::modq_run::{run_raw_on, ModqSide};

impl ModqSide for ModqAirWithout {
    fn main_width(&self) -> usize { <ModqAirWithout as BaseAir<F>>::width(self) }
    fn pre_width(&self) -> usize { <ModqAirWithout as BaseAir<F>>::preprocessed_width(self) }
    fn eval_on<AB: AirBuilder + PermutationAirBuilder + InteractionBuilder>(&self, b: &mut AB) where AB::F: Field { self.eval(b) }
}

/// Prove and verify the four-table batch: the modq `trace` under `ModqAirWithout(off)`, an asker
/// row per `(clk, base, a1)` in `asks`, the memory `twin` and the range table of `range`.
pub fn run_raw(trace: &RowMajorMatrix<F>, range: &RangeCounts, asks: &[(u32, u32, u32)], twin: &RowMajorMatrix<F>, off: Option<Defence>) -> Result<(), VerifyError> {
    run_raw_on(ModqAirWithout(off), trace, range, asks, twin)
}

/// A forged block standalone with `off` switched off: the cpu asks what the forgery's story says
/// (`Forged::asks` — one ask per event block, as the cpu would, doubled only where a lie doubles the
/// table's own claim), the twin holds exactly the story's accesses, and the range table holds the
/// limbs rule 8 looks up under `off` (`range_counts_without`).
pub fn run(forged: &Forged, off: Option<Defence>) -> Result<(), VerifyError> {
    run_raw(&forged.trace, &range_counts_without(&forged.trace, off), &forged.asks, &twin_of(&forged.accesses), off)
}
