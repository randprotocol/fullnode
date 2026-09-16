//! The precompile tasks' differential tests (the M5.1 Task-7 pattern): every precompile must
//! agree with the compiled sequence it replaces — which stays in the tree as the reference — and
//! refuse its malformed inputs at a named point.
mod common;

use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use rand::SeedableRng;
use randprotocol_rvm::dsl::{Array, Builder, Checkpoints, Ext, Felt};
use randprotocol_rvm::emulator::{execute, ExecError};
use randprotocol_rvm::isa::{EF, F};
use randprotocol_rvm::programs::{reduce_compiled, run_reduce_sequence};

fn ef(c: [F; 2]) -> EF {
    EF::from_basis_coefficients_slice(&c).unwrap()
}

/// One `REDUCE` run through the DSL precompile, over hint-supplied arrays.
fn reduce_via_precompile(vals: &[EF], row: &[F], inv: EF, acc: EF, apow: EF, alpha: EF) -> (EF, EF) {
    let mut b = Builder::new(Checkpoints::Off);
    let mut tape: Vec<F> = vec![];
    let vals_a = b.hint_ext_array(vals.len());
    for v in vals {
        tape.extend_from_slice(v.as_basis_coefficients_slice());
    }
    let row_a = b.hint_array(row.len());
    tape.extend_from_slice(row);
    let inv = b.ext_constant(inv);
    let acc = b.ext_constant(acc);
    let apow = b.ext_constant(apow);
    let alpha = b.ext_constant(alpha);
    let (ro, ap) = b.reduce(vals_a, row_a, inv, acc, apow, alpha);
    b.public_ext(ro);
    b.public_ext(ap);
    let (p, _) = b.finish_stats();
    let got = execute(&p, &tape, 1_000_000).unwrap().public;
    (ef([got[0], got[1]]), ef([got[2], got[3]]))
}

/// The same run through the kept compiled loop (the differential reference).
fn reduce_via_compiled(vals: &[EF], row: &[F], inv: EF, acc: EF, apow: EF, alpha: EF) -> (EF, EF) {
    let mut b = Builder::new(Checkpoints::Off);
    let mut tape: Vec<F> = vec![];
    let vals_a = b.hint_ext_array(vals.len());
    for v in vals {
        tape.extend_from_slice(v.as_basis_coefficients_slice());
    }
    let row_a = b.hint_array(row.len());
    tape.extend_from_slice(row);
    let inv = b.ext_constant(inv);
    let acc = b.ext_constant(acc);
    let apow = b.ext_constant(apow);
    let alpha = b.ext_constant(alpha);
    let (ro, ap) = reduce_compiled(&mut b, vals_a, row_a, inv, acc, apow, alpha);
    b.public_ext(ro);
    b.public_ext(ap);
    let (p, _) = b.finish_stats();
    let got = execute(&p, &tape, 1_000_000).unwrap().public;
    (ef([got[0], got[1]]), ef([got[2], got[3]]))
}

#[test]
fn reduce_matches_the_compiled_sequence() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    // Run lengths from one column to a wide committed row's worth, all point/height mixes the
    // cs6 shape opens being structurally identical (`run.len` is the only run-to-run variable).
    for len in [1usize, 2, 3, 7, 40, 121] {
        for _ in 0..10 {
            let vals: Vec<EF> = (0..len).map(|_| common::random_ext(&mut rng)).collect();
            let row: Vec<F> = (0..len).map(|_| common::random_felt(&mut rng)).collect();
            let inv = common::random_ext(&mut rng);
            let acc = common::random_ext(&mut rng);
            let apow = common::random_ext(&mut rng);
            let alpha = common::random_ext(&mut rng);
            let want = run_reduce_sequence(&vals, &row, inv, acc, apow, alpha);
            assert_eq!(reduce_via_compiled(&vals, &row, inv, acc, apow, alpha), want,
                       "the compiled loop must match the native reference (len {len})");
            assert_eq!(reduce_via_precompile(&vals, &row, inv, acc, apow, alpha), want,
                       "the REDUCE precompile must match the native reference (len {len})");
        }
    }
}

#[test]
fn reduce_refuses_a_zero_length_run() {
    let mut b = Builder::new(Checkpoints::Off);
    // Two zero-length arrays: the descriptor's `len` is 0, which is an emulator error, not a
    // proof — the instruction-level twin of the named-checkpoint traps.
    let vals_a = b.hint_ext_array(0);
    let row_a = b.hint_array(0);
    let one = b.ext_constant(EF::ONE);
    let (ro, ap) = b.reduce(vals_a, row_a, one, one, one, one);
    b.public_ext(ro);
    b.public_ext(ap);
    let (p, _) = b.finish_stats();
    assert!(matches!(
        execute(&p, &[], 1_000_000),
        Err(ExecError::ReduceZeroLength { .. })
    ));
}

// ── Task 8: the REDUCE precompile in proofs, and the keccak-pattern instance rule ─────────────
use randprotocol_rvm::machine::{FriProfile, Machine};

/// A small program with two chained `REDUCE` runs: the second's accumulator starts where the
/// first's stopped (the descriptor write-back and the program's own chaining agree).
fn two_run_program(vals1: &[EF], row1: &[F], vals2: &[EF], row2: &[F], inv: EF, alpha: EF) -> (randprotocol_rvm::isa::Program, Vec<F>) {
    let mut b = Builder::new(Checkpoints::Off);
    let mut tape: Vec<F> = vec![];
    let vals1_a = b.hint_ext_array(vals1.len());
    for v in vals1 {
        tape.extend_from_slice(v.as_basis_coefficients_slice());
    }
    let row1_a = b.hint_array(row1.len());
    tape.extend_from_slice(row1);
    let vals2_a = b.hint_ext_array(vals2.len());
    for v in vals2 {
        tape.extend_from_slice(v.as_basis_coefficients_slice());
    }
    let row2_a = b.hint_array(row2.len());
    tape.extend_from_slice(row2);
    let inv = b.ext_constant(inv);
    let zero = b.ext_constant(EF::ZERO);
    let one = b.ext_constant(EF::ONE);
    let alpha = b.ext_constant(alpha);
    let (ro, ap) = b.reduce(vals1_a, row1_a, inv, zero, one, alpha);
    let (ro, _ap) = b.reduce(vals2_a, row2_a, inv, ro, ap, alpha);
    b.public_ext(ro);
    b.public_ext(ro);
    (b.finish(), tape)
}

#[test]
fn a_program_using_reduce_proves_and_verifies_with_the_chip_present() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(13);
    let vals1: Vec<EF> = (0..7).map(|_| common::random_ext(&mut rng)).collect();
    let row1: Vec<F> = (0..7).map(|_| common::random_felt(&mut rng)).collect();
    let vals2: Vec<EF> = (0..3).map(|_| common::random_ext(&mut rng)).collect();
    let row2: Vec<F> = (0..3).map(|_| common::random_felt(&mut rng)).collect();
    let inv = common::random_ext(&mut rng);
    let alpha = common::random_ext(&mut rng);
    let (p, tape) = two_run_program(&vals1, &row1, &vals2, &row2, inv, alpha);

    let m = Machine::new(FriProfile::Test);
    let (proof, exec) = m.prove(&p, &tape, None).unwrap();
    assert!(proof.reduce_log_height > 0, "the reduce table is in this batch");
    m.verify(&p, &proof).unwrap();

    // And the value is the chained reduction, as the compiled sequence computes it.
    let (want_ro, _) = {
        let (ro, ap) = run_reduce_sequence(&vals1, &row1, inv, EF::ZERO, EF::ONE, alpha);
        run_reduce_sequence(&vals2, &row2, inv, ro, ap, alpha)
    };
    assert_eq!(exec.public[..2].to_vec(), want_ro.as_basis_coefficients_slice().to_vec());
}

#[test]
fn a_program_without_reduce_has_no_reduce_instance() {
    // The keccak pattern: no `REDUCE` row, no reduce instance in the batch — and the declared
    // `reduce_log_height = 0` is what says so.
    let p = {
        let mut b = Builder::new(Checkpoints::Off);
        let x = b.constant(F::from_u64(7));
        let y = b.constant(F::from_u64(5));
        let z = b.mul(x, y);
        for v in [z, z, z, z] {
            b.public(v);
        }
        b.finish()
    };
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    assert_eq!(proof.reduce_log_height, 0, "no REDUCE row, no reduce instance");
    m.verify(&p, &proof).unwrap();
}

// ── Task 9: the SPONGE precompile as a poseidon2 row kind ─────────────────────────────────────
use p3_symmetric::CryptographicHasher;
use randprotocol_rvm::dsl::Liveness;

/// The transcript.rs leaf-sponge differential, rerun with the precompile on: the SPONGE-instruction
/// absorb loop and the compiled tail must produce exactly `PaddingFreeSponge`'s digest.
#[test]
fn sponge_via_the_precompile_matches_padding_free_sponge() {
    use randprotocol_rvm::programs::Precompiles;
    let perm = randprotocol_zkvm::machine::permutation();
    let sponge = p3_symmetric::PaddingFreeSponge::<randprotocol_zkvm::machine::Perm, 8, 4, 4>::new(perm);
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(3);
    for n in [1usize, 3, 4, 5, 8, 9, 37, 121] {
        let msg: Vec<F> = (0..n).map(|_| common::random_felt(&mut rng)).collect();
        let want: [F; 4] = sponge.hash_iter(msg.iter().copied());

        let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, Precompiles::On);
        let src = b.alloc(n as u64);
        for (k, v) in msg.iter().enumerate() {
            let hv = b.constant(*v);
            b.store(src, k as i64, hv);
        }
        let out = randprotocol_rvm::dsl::Digest(b.alloc(4));
        randprotocol_rvm::dsl::hash::sponge(&mut b, src, n, out);
        for k in 0..4 {
            let v = b.load(out.0, k);
            b.public(v);
        }
        let got = execute(&b.finish(), &[], 1_000_000).unwrap().public;
        assert_eq!(got, want.to_vec(), "n = {n}");
    }
}

/// The sponge contract in a proof (joining Task 5's 1 000-state contract): a program absorbs
/// 100 random buffers through the precompile and asserts each digest against the host's
/// `PaddingFreeSponge`, proved and verified. (100, not 1 000, so the in-suite proof stays at
/// tier 12; the chip-level 1 000-state equality contract is Task 5's `tests/poseidon2.rs`.)
#[test]
fn the_sponge_contract_holds_in_a_proof_over_one_hundred_random_buffers() {
    use randprotocol_rvm::programs::Precompiles;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(23);
    let perm = randprotocol_zkvm::machine::permutation();
    let sponge = p3_symmetric::PaddingFreeSponge::<randprotocol_zkvm::machine::Perm, 8, 4, 4>::new(perm);

    let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, Precompiles::On);
    let mut tape: Vec<F> = vec![];
    let n = 12usize;
    let src = b.alloc(n as u64);
    let out = randprotocol_rvm::dsl::Digest(b.alloc(4));
    for _ in 0..100 {
        let msg: Vec<F> = (0..n).map(|_| common::random_felt(&mut rng)).collect();
        let want: [F; 4] = sponge.hash_iter(msg.iter().copied());
        for (k, v) in msg.iter().enumerate() {
            let hv = b.hint();
            tape.push(*v);
            b.store(src, k as i64, hv);
        }
        randprotocol_rvm::dsl::hash::sponge(&mut b, src, n, out);
        for k in 0..4 {
            let v = b.load(out.0, k);
            let w = b.constant(want[k as usize]);
            b.assert_eq(v, w, "sponge digest must equal the reference");
        }
    }
    for _ in 0..4 {
        let z = b.zero();
        b.public(z);
    }
    let p = b.finish();
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&p, &tape, None).unwrap();
    m.verify(&p, &proof).unwrap();
}
