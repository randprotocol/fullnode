//! The quotient-layout fork (`docs/05-quotient-layout.md`): the rVM commits each instance's
//! quotient chunks as one matrix. What this file pins: the machine's layout constant, the proof's
//! quotient-round structure, the proof's survival of serialisation, and the refusals — a flipped
//! chunk value, a flipped random hint, and a proof of either layout checked under the other —
//! each refused by the hiding PCS's matrix-count check, by name — plus the structure at a
//! reduce-carrying shape.
mod common;

use p3_batch_stark::QuotientLayout;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use randprotocol_rvm::isa::{Instr, Op, Program, F};
use randprotocol_rvm::machine::{build_traces, Machine, Tier, VerifyError, QUOTIENT_LAYOUT};
use randprotocol_zkvm::machine::FriProfile;

fn instr(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}

/// `tests/machine.rs`'s toy with the four-word interface digest.
fn toy_program() -> Program {
    Program {
        instrs: vec![
            instr(Op::Faddi, 1, 0, 7),
            instr(Op::Faddi, 2, 0, 5),
            instr(Op::Fadd, 3, 1, 2),
            instr(Op::Public, 0, 3, 0),
            instr(Op::Public, 0, 1, 0),
            instr(Op::Public, 0, 2, 0),
            instr(Op::Public, 0, 3, 0),
            instr(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    }
}

/// The quotient round's index in `opening_proof`: `random` (0), `main` (1), `quotient_chunks` (2),
/// then `preprocessed` and `permutation` (`p3-batch-stark/src/prover.rs`, "Round 2").
const QUOTIENT_ROUND: usize = 2;
const NUM_RANDOM_CODEWORDS: usize = 4;
const DIMENSION: usize = <randprotocol_rvm::machine::Challenge as BasedVectorSpace<randprotocol_rvm::machine::Val>>::DIMENSION;

#[test]
fn the_machine_pins_the_per_instance_layout() {
    assert_eq!(QUOTIENT_LAYOUT, QuotientLayout::PerInstance, "the rVM's own proofs take the fork's layout");
}

#[test]
fn a_per_instance_proof_has_one_quotient_matrix_per_instance_and_verifies() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();

    let n = proof.batch.degree_bits.len();
    let (rand_openings, fri) = &proof.batch.opening_proof;
    // The hiding PCS's hidden halves: one set of four per instance, not one per chunk.
    assert_eq!(rand_openings[QUOTIENT_ROUND].len(), n, "one quotient matrix per instance");
    for mat in &rand_openings[QUOTIENT_ROUND] {
        assert_eq!(mat.len(), 1, "opened at zeta only");
        assert_eq!(mat[0].len(), NUM_RANDOM_CODEWORDS);
    }
    // The committed rows: `chunks · DIMENSION + 4` base columns, chunks as the proof's per-chunk
    // opened values count them (16 for the cpu table, 2 for the program table).
    for q in 0..fri.input_openings[QUOTIENT_ROUND].opened_values.len() {
        let rows = &fri.input_openings[QUOTIENT_ROUND].opened_values[q];
        assert_eq!(rows.len(), n);
        for (i, row) in rows.iter().enumerate() {
            let chunks = proof.batch.opened_values.instances[i].base_opened_values.quotient_chunks.len();
            assert!(chunks >= 2, "ZK doubles every chunk count");
            assert_eq!(row.len(), chunks * DIMENSION + NUM_RANDOM_CODEWORDS, "instance {i}");
        }
    }
    // The per-chunk opened values keep upstream's shape, so recomposition is untouched.
    for inst in &proof.batch.opened_values.instances {
        for chunk in &inst.base_opened_values.quotient_chunks {
            assert_eq!(chunk.len(), DIMENSION);
        }
    }
}

#[test]
fn a_per_instance_proof_survives_postcard() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    let bytes = proof.to_bytes();
    let back: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).unwrap();
    m.verify(&p, &back).unwrap();
}

#[test]
fn a_flipped_quotient_chunk_value_is_refused() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    // Instance 1 is the cpu table (16 chunks); flip one lane of chunk 3 inside the wide row.
    let v = &mut proof.batch.opened_values.instances[1].base_opened_values.quotient_chunks[3][0];
    *v += randprotocol_rvm::machine::Challenge::ONE;
    match m.verify(&p, &proof) {
        Err(VerifyError::Batch(_)) => {}
        other => panic!("a flipped quotient value must be refused by the batch verifier, got {other:?}"),
    }
}

#[test]
fn a_flipped_quotient_random_hint_is_refused() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    // The wide row's four hidden values are the instance's one salt set now; flip one.
    let v = &mut proof.batch.opening_proof.0[QUOTIENT_ROUND][1][0][0];
    *v += randprotocol_rvm::machine::Challenge::ONE;
    match m.verify(&p, &proof) {
        Err(VerifyError::Batch(_)) => {}
        other => panic!("a flipped random hint must fail the Merkle row, got {other:?}"),
    }
}

#[test]
fn a_proof_made_under_upstreams_layout_is_refused_not_panicked() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let exec = randprotocol_rvm::emulator::execute(&p, &[], Tier(8).max_cycles()).unwrap();
    let tier = Tier::for_cycles(exec.cpu_rows()).unwrap();
    let traces = randprotocol_rvm::machine::build_traces(&p, &exec, tier).unwrap();
    let honest = m.prove_traces_with_layout(&p, &traces, tier, QUOTIENT_LAYOUT);
    m.verify(&p, &honest).unwrap();
    let per_chunk = m.prove_traces_with_layout(&p, &traces, tier, QuotientLayout::PerChunk);
    match m.verify(&p, &per_chunk) {
        Err(VerifyError::Batch(msg)) => {
            // The quotient round (2): the verifier lists 7 matrices (one per instance), the proof
            // carries 52 random-opening sets (one per chunk).
            assert!(
                msg.contains("HidingRandomOpeningMatrixCountMismatch { round: 2, expected: 7, got: 52 }"),
                "the refusal names the layout disagreement: {msg}"
            );
        }
        other => panic!("a PerChunk proof must be refused by a PerInstance verifier, got {other:?}"),
    }
}

#[test]
fn a_per_instance_proof_is_refused_by_a_per_chunk_verifier_by_name() {
    let p = toy_program();
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    m.verify_with_layout(&p, &proof, QUOTIENT_LAYOUT).unwrap();
    match m.verify_with_layout(&p, &proof, QuotientLayout::PerChunk) {
        Err(VerifyError::Batch(msg)) => {
            // The reverse: the per-chunk verifier lists 52 matrices, the proof carries 7.
            assert!(
                msg.contains("HidingRandomOpeningMatrixCountMismatch { round: 2, expected: 52, got: 7 }"),
                "the refusal names the layout disagreement: {msg}"
            );
        }
        other => panic!("a PerInstance proof must be refused by a PerChunk verifier, got {other:?}"),
    }
}

/// `tests/cheating.rs::reduce_setup`'s batch (one four-column `REDUCE` run, eight instances):
/// the reduce instance's chunks share one wide matrix like every other instance's.
#[test]
fn a_reduce_carrying_proof_has_one_quotient_matrix_per_instance() {
    use randprotocol_rvm::dsl::{Builder, Checkpoints};
    use randprotocol_rvm::isa::EF;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(31);
    let vals: Vec<EF> = (0..4).map(|_| common::random_ext(&mut rng)).collect();
    let row: Vec<F> = (0..4).map(|_| common::random_felt(&mut rng)).collect();
    let inv = common::random_ext(&mut rng);
    let alpha = common::random_ext(&mut rng);
    let mut b = Builder::new(Checkpoints::Off);
    let mut tape: Vec<F> = vec![];
    let vals_a = b.hint_ext_array(4);
    vals.iter().for_each(|v| tape.extend_from_slice(v.as_basis_coefficients_slice()));
    let row_a = b.hint_array(4);
    tape.extend_from_slice(&row);
    // Cut D: the key and alpha live at compile-time addresses the layout names.
    let keys = b.alloc(4);
    let res = b.alloc(2);
    let (alpha_h, inv_h) = (b.ext_constant(alpha), b.ext_constant(inv));
    b.store_ext(keys, 0, alpha_h);
    b.store_ext(keys, 2, inv_h);
    let key = b.offset(keys, 2);
    b.reduce(&[randprotocol_rvm::dsl::ReduceRun { vals: vals_a, row: row_a, key }], keys, res);
    let ro = b.load_ext(res, 0);
    b.public_ext(ro);
    b.public_ext(ro);
    let p = b.finish();
    let m = Machine::new(FriProfile::Test);
    let t = build_traces(&p, &randprotocol_rvm::emulator::execute(&p, &tape, 10_000).unwrap(), Tier(8)).unwrap();
    assert!(t.reduce.is_some(), "the batch carries the reduce table");
    let proof = m.prove_traces(&p, &t, Tier(8));
    m.verify(&p, &proof).unwrap();
    let n = proof.batch.degree_bits.len();
    assert_eq!(n, 8, "the reduce table is the eighth instance");
    assert_eq!(proof.batch.opening_proof.0[QUOTIENT_ROUND].len(), n, "one quotient matrix per instance");
    let reduce = n - 1;
    let chunks = proof.batch.opened_values.instances[reduce].base_opened_values.quotient_chunks.len();
    assert_eq!(chunks, 16, "the reduce chip's chunk count under ZK");
    for opened in &proof.batch.opening_proof.1.input_openings[QUOTIENT_ROUND].opened_values {
        assert_eq!(opened[reduce].len(), chunks * DIMENSION + NUM_RANDOM_CODEWORDS);
    }
}
