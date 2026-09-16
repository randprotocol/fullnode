//! The permutation-per-row Poseidon2 chip (plan Task 5): the trace-level equality contract, the
//! constants draw, the width/degree pins, and the padding discipline.
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use rand::SeedableRng;
use randprotocol_rvm::emulator::PermEvent;
use randprotocol_rvm::isa::F;
use randprotocol_rvm::tables::poseidon2::{col, poseidon2_log_height, poseidon2_trace, ROUNDS_F, ROUNDS_P};

fn event(ptr: u64, input: [F; 8]) -> PermEvent {
    PermEvent { ptr, input, output: randprotocol_zkvm::hash::permute_state(input), src: None }
}

fn random_state(rng: &mut impl rand::Rng) -> [F; 8] {
    core::array::from_fn(|_| common::random_felt(rng))
}

#[test]
fn the_chips_output_equals_the_reference_on_one_thousand_random_states() {
    // The trace-level half of spec §7's equality contract: every row's OUT columns carry exactly
    // `permute_state(IN)`, and the input lands on the bus columns. (The in-proof half — the AIR
    // accepts exactly this trace, and the machine proves a program asserting it — is Task 6's
    // `tests/cpu.rs`; `check_constraints` is `pub(crate)` in p3-batch-stark, so no standalone
    // unit check exists between these two levels.)
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    let events: Vec<(u32, PermEvent)> = (0..1000)
        .map(|i| (i as u32, event(64 + 8 * i as u64, random_state(&mut rng))))
        .collect();
    let height = 1024;
    let t = poseidon2_trace(&events, height);
    for (i, &(clk, ev)) in events.iter().enumerate() {
        let input: [F; 8] = core::array::from_fn(|k| t.get(i, col::IN0 + k).unwrap());
        let output: [F; 8] = core::array::from_fn(|k| t.get(i, col::OUT0 + k).unwrap());
        assert_eq!(input, ev.input, "row {i} input");
        assert_eq!(output, randprotocol_zkvm::tables::poseidon2::permute_scalar(ev.input),
                   "row {i}: the chip's permutation must equal the reference");
        assert_eq!(t.get(i, col::IS_REAL).unwrap(), F::ONE);
        assert_eq!(t.get(i, col::MULT).unwrap(), F::ONE, "MULT = IS_REAL on a real row");
        assert_eq!(t.get(i, col::IS_PERM).unwrap(), F::ONE);
        assert_eq!(t.get(i, col::IS_SPONGE).unwrap(), F::ZERO);
        assert_eq!(t.get(i, col::CLK).unwrap().as_canonical_u64(), clk as u64);
        assert_eq!(t.get(i, col::PTR).unwrap().as_canonical_u64(), ev.ptr);
    }
    // Padding rows carry a genuine all-zero permutation trace (the M3.1 padding lesson: the
    // round constraints run on every row) with IS_REAL = MULT = 0.
    let last = height - 1;
    let out: [F; 8] = core::array::from_fn(|k| t.get(last, col::OUT0 + k).unwrap());
    assert_eq!(out, randprotocol_zkvm::tables::poseidon2::permute_scalar([F::ZERO; 8]));
    assert_eq!(t.get(last, col::IS_REAL).unwrap(), F::ZERO);
    assert_eq!(t.get(last, col::MULT).unwrap(), F::ZERO);
}

#[test]
fn the_round_constants_are_the_machines_own_draw() {
    // The AIR bakes the constants into its expressions (R9); the draw it uses must be the
    // machine's own (`machine::PERM_SEED`-seeded, reproduced by research's `round_constants()`).
    // This is pinned structurally: the chip's `ROUNDS_F`/`ROUNDS_P` and the reference helpers it
    // shares all come from `randprotocol_zkvm::tables::poseidon2`.
    let rc = randprotocol_zkvm::tables::poseidon2::round_constants();
    assert_eq!(rc.initial.len(), ROUNDS_F / 2);
    assert_eq!(rc.internal.len(), ROUNDS_P);
    assert_eq!(rc.terminal.len(), ROUNDS_F / 2);
    // And the scalar replay over those constants is the machine's permutation (research's own
    // anchor, restated here because the chip's correctness *is* this equality).
    let mut rng = rand::rngs::StdRng::seed_from_u64(3);
    for _ in 0..20 {
        let s = random_state(&mut rng);
        assert_eq!(
            randprotocol_zkvm::tables::poseidon2::permute_scalar(s),
            randprotocol_zkvm::hash::permute_state(s),
            "the constants draw reproduces machine::permutation"
        );
    }
}

#[test]
fn the_width_and_height_rules_are_pinned() {
    assert_eq!(col::WIDTH, 341, "the plan's designed width, pinned");
    assert_eq!(col::OUT0 + 8 + 86, col::WIDTH);
    assert_eq!(poseidon2_log_height(0), 4, "the floor");
    assert_eq!(poseidon2_log_height(51_595), 16, "the measured production count fits 2^16");
    assert_eq!(poseidon2_log_height(51_606), 16);
    assert_eq!(poseidon2_log_height(65_536), 17, "one past the capacity climbs a rung");
}
