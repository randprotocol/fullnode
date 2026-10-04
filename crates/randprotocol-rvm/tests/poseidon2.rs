//! The permutation-per-row Poseidon2 chip (plan Task 5): the trace-level equality contract, the
//! constants draw, the width/degree pins, and the padding discipline.
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use rand::SeedableRng;
use randprotocol_rvm::emulator::{PermEvent, PermKind};
use randprotocol_rvm::isa::F;
use randprotocol_rvm::tables::poseidon2::{col, poseidon2_log_height, poseidon2_trace, ROUNDS_F, ROUNDS_P};

fn event(ptr: u64, input: [F; 8]) -> PermEvent {
    PermEvent { ptr, input, output: randprotocol_zkvm::hash::permute_state(input), kind: PermKind::Perm }
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
    // machine's own (research's committed `poseidon2_constants` table, via `round_constants()`).
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
    assert_eq!(col::WIDTH, 343, "the plan's designed width + Cut C's IS_COMPRESS and BIT, pinned");
    assert_eq!(col::OUT0 + 8 + 86 + 2, col::WIDTH);
    assert_eq!(poseidon2_log_height(0), 4, "the floor");
    assert_eq!(poseidon2_log_height(51_595), 16, "the measured production count fits 2^16");
    assert_eq!(poseidon2_log_height(51_606), 16);
    assert_eq!(poseidon2_log_height(65_536), 17, "one past the capacity climbs a rung");
}

/// ZKQ-6 (the 2026-09-27 zk scan, hardening): a known answer for the permutation, pinned as
/// numbers. `research`'s `poseidon2_constants::permutation()` builds a *different type* per target
/// — `p3_goldilocks`'s fused NEON implementation on aarch64, the generic `Poseidon2` elsewhere — so
/// the host hash (`hash::permute_state`, every program digest and every emulated `POSEIDON2`) runs
/// different code on an ARM laptop than on an x86 CI runner or validator. Both must compute the
/// one permutation the chip's AIR constrains (`tables::poseidon2::permute_scalar`, the constants
/// table walked round by round). The other tests here compare the two on the machine they run
/// on; this pins the output itself, so an architecture whose fast path diverged would fail here
/// rather than disagree silently with another machine. Recorded on aarch64 (NEON), where the
/// scalar reference agreed.
#[test]
fn the_permutation_matches_its_known_answers() {
    let inputs: [[u64; 8]; 3] = [
        [0; 8],
        [0, 1, 2, 3, 4, 5, 6, 7],
        [F::ORDER_U64 - 1, 1 << 63, 0xC0FF_EE00_0000_0001, 42, 7, 1 << 32, (1 << 32) - 1, 0xDEAD_BEEF],
    ];
    let want: [[u64; 8]; 3] = [
        [
            2182887505462051504, 3439344203595588314, 11257167888106482493, 4107398993123293806,
            14643323442960772459, 11192306518859915094, 364998372190244659, 17999480207850065192,
        ],
        [
            7506498085745773920, 3890631433287662404, 17345641480708064142, 16023537662855063796,
            14956148158829802274, 4100699954794509621, 17694435955024199899, 7588218540016218618,
        ],
        [
            13177204086891333497, 5926417715648558762, 14857286310666800248, 15753195083841397473,
            10135933228134719423, 4405257592837931310, 3073845396149882880, 12581549497245156936,
        ],
    ];
    for (k, input) in inputs.iter().enumerate() {
        let input: [F; 8] = input.map(F::from_u64);
        let host: Vec<u64> = randprotocol_zkvm::hash::permute_state(input).iter().map(|x| x.as_canonical_u64()).collect();
        let scalar: Vec<u64> = randprotocol_zkvm::tables::poseidon2::permute_scalar(input).iter().map(|x| x.as_canonical_u64()).collect();
        assert_eq!(host, scalar, "input {k}: the host permutation and the AIR's scalar reference disagree on this machine");
        assert_eq!(host, want[k].to_vec(), "input {k}: the permutation's known answer");
    }
}

/// Cut C: a `COMPRESS` row (bit set, so the children swap) is the chip's third row kind — the
/// cpu's dispatch on `COMPRESS`, the chip's 4 + 4 reads and 4 writes on `RAM`, all balanced in a
/// real proof.
#[test]
fn a_compress_row_proves_and_verifies() {
    use randprotocol_rvm::machine::{build_traces, FriProfile, Machine, Tier};
    let p = common::compress_program(1);
    let exec = randprotocol_rvm::emulator::execute(&p, &[], 1000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    let m = Machine::new(FriProfile::Test);
    let proof = m.prove_traces(&p, &t, Tier(8));
    m.verify(&p, &proof).unwrap();
}
