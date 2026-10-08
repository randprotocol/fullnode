//! The precompile tasks' differential tests (the M5.1 Task-7 pattern): every precompile must
//! agree with the compiled sequence it replaces — which stays in the tree as the reference — and
//! refuse its malformed inputs at a named point.
mod common;

use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use rand::SeedableRng;
use randprotocol_rvm::dsl::{Builder, Checkpoints};
use randprotocol_rvm::emulator::{execute, ExecError};
use randprotocol_rvm::isa::{EF, F};
use randprotocol_rvm::programs::{reduce_compiled, run_reduce_sequence};

fn ef(c: [F; 2]) -> EF {
    EF::from_basis_coefficients_slice(&c).unwrap()
}

use randprotocol_rvm::machine::{FriProfile, Machine};
use randprotocol_rvm::dsl::ReduceRun;

/// A chain of runs through `Builder::reduce` (`On`) or the kept compiled loop (`Off`): the same
/// hinted arrays, keys and alpha; the result published.
fn reduce_chain(on: bool, runs: &[(Vec<EF>, Vec<F>, EF)], alpha: EF) -> (EF, randprotocol_rvm::isa::Program, Vec<F>) {
    use randprotocol_rvm::dsl::Liveness;
    use randprotocol_rvm::programs::Precompiles;
    let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, if on { Precompiles::On } else { Precompiles::Off });
    let mut tape: Vec<F> = vec![];
    let keys = b.alloc(2 + 2 * runs.len() as u64);
    let res = b.alloc(2);
    let a = b.ext_constant(alpha);
    b.store_ext(keys, 0, a);
    let mut arrays = vec![];
    for (j, (vals, row, inv)) in runs.iter().enumerate() {
        let va = b.hint_ext_array(vals.len());
        for v in vals {
            tape.extend_from_slice(v.as_basis_coefficients_slice());
        }
        let ra = b.hint_array(row.len());
        tape.extend_from_slice(row);
        let k = b.ext_constant(*inv);
        b.store_ext(keys, 2 + 2 * j as i64, k);
        arrays.push((va, ra));
    }
    if on {
        let chain: Vec<ReduceRun> = arrays.iter().enumerate().map(|(j, &(vals, row))| ReduceRun { vals, row, key: b.offset(keys, 2 + 2 * j as i64) }).collect();
        b.reduce(&chain, keys, res);
    } else {
        let (mut acc, mut apow) = (b.ext_constant(EF::ZERO), b.ext_constant(EF::ONE));
        for (j, &(vals, row)) in arrays.iter().enumerate() {
            let inv = b.load_ext(keys, 2 + 2 * j as i64);
            (acc, apow) = reduce_compiled(&mut b, vals, row, inv, acc, apow, a);
        }
        let _ = apow;
        b.store_ext(res, 0, acc);
    }
    let out = b.load_ext(res, 0);
    b.public_ext(out);
    b.public_ext(out);
    let p = b.finish();
    let got = execute(&p, &tape, 1_000_000).unwrap().public;
    (ef([got[0], got[1]]), p, tape)
}

#[test]
fn reduce_matches_the_compiled_sequence() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for lens in [vec![1usize], vec![3], vec![2, 1], vec![7, 40, 121], vec![1, 1, 1, 1]] {
        for _ in 0..5 {
            let runs: Vec<(Vec<EF>, Vec<F>, EF)> = lens
                .iter()
                .map(|&len| ((0..len).map(|_| common::random_ext(&mut rng)).collect(), (0..len).map(|_| common::random_felt(&mut rng)).collect(), common::random_ext(&mut rng)))
                .collect();
            let alpha = common::random_ext(&mut rng);
            let (mut want, mut apow) = (EF::ZERO, EF::ONE);
            for (vals, row, inv) in &runs {
                (want, apow) = run_reduce_sequence(vals, row, *inv, want, apow, alpha);
            }
            assert_eq!(reduce_chain(false, &runs, alpha).0, want, "compiled, lens {lens:?}");
            assert_eq!(reduce_chain(true, &runs, alpha).0, want, "the chain, lens {lens:?}");
        }
    }
}

#[test]
fn a_zero_length_layout_entry_is_an_emulator_error_and_illegal_at_registration() {
    let mut p = common::reduce_chain_program(false);
    p.reduce_layout[0].len = 0;
    assert!(matches!(execute(&p, &[], 1_000), Err(ExecError::ReduceZeroLength { .. })));
    assert_eq!(Machine::check_program(&p), Err(randprotocol_rvm::isa::DecodeError::Layout { entry: 0 }));
}

#[test]
fn a_program_using_reduce_proves_and_verifies_with_the_chip_present() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(13);
    let runs: Vec<(Vec<EF>, Vec<F>, EF)> = [7usize, 3]
        .iter()
        .map(|&len| ((0..len).map(|_| common::random_ext(&mut rng)).collect(), (0..len).map(|_| common::random_felt(&mut rng)).collect(), common::random_ext(&mut rng)))
        .collect();
    let alpha = common::random_ext(&mut rng);
    let (want, p, tape) = reduce_chain(true, &runs, alpha);
    let m = Machine::new(FriProfile::Test);
    let (proof, exec) = m.prove(&p, &tape, None).unwrap();
    assert!(proof.reduce_log_height > 0, "the reduce table is in this batch");
    m.verify(&p, &proof).unwrap();
    assert_eq!(exec.public[..2].to_vec(), want.as_basis_coefficients_slice().to_vec());
}

/// Review Focus 3: one-column entries opening and closing a chain, and a lone one-column chain.
#[test]
fn one_column_entries_at_chain_start_and_end_prove_and_verify() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(14);
    let m = Machine::new(FriProfile::Test);
    for lens in [vec![1usize], vec![1, 4], vec![4, 1], vec![1, 1]] {
        let runs: Vec<(Vec<EF>, Vec<F>, EF)> = lens
            .iter()
            .map(|&len| ((0..len).map(|_| common::random_ext(&mut rng)).collect(), (0..len).map(|_| common::random_felt(&mut rng)).collect(), common::random_ext(&mut rng)))
            .collect();
        let (_, p, tape) = reduce_chain(true, &runs, common::random_ext(&mut rng));
        let (proof, _) = m.prove(&p, &tape, None).unwrap();
        m.verify(&p, &proof).unwrap_or_else(|e| panic!("lens {lens:?}: {e:?}"));
    }
}

/// Review Focus 2: a two-entry chain inside the aggregate's loop shape (`counted_loop_mem`, a tape
/// count), run twice — every layout row's MULT is 2 and no carry crosses an iteration.
#[test]
fn a_reduce_chain_inside_a_counted_loop_proves_with_mult_n() {
    use randprotocol_rvm::tables::reduce::col::MULT;
    let mut b = Builder::new(Checkpoints::Off);
    let n = b.hint();
    let counter = b.alloc_absolute(1);
    let keys = b.alloc_absolute(4);
    let res = b.alloc_absolute(2);
    let vals = b.alloc_absolute(6);
    let row = b.alloc_absolute(3);
    let acc_out = b.alloc_absolute(2);
    b.counted_loop_mem(counter, n, |b| {
        for k in 0..4 { let w = b.hint(); b.store(keys, k, w); }
        for k in 0..6 { let w = b.hint(); b.store(vals, k, w); }
        for k in 0..3 { let w = b.hint(); b.store(row, k, w); }
        let va = randprotocol_rvm::dsl::Array::new(vals, 2, 2);
        let ra = randprotocol_rvm::dsl::Array::new(row, 2, 1);
        let vb = randprotocol_rvm::dsl::Array::new(b.offset(vals, 4), 1, 2);
        let rb = randprotocol_rvm::dsl::Array::new(b.offset(row, 2), 1, 1);
        let key = b.offset(keys, 2);
        b.reduce(&[ReduceRun { vals: va, row: ra, key }, ReduceRun { vals: vb, row: rb, key }], keys, res);
        let r = b.load_ext(res, 0);
        let prev = b.load_ext(acc_out, 0);
        let s = b.ext_add(prev, r);
        b.store_ext(acc_out, 0, s);
    });
    let s = b.load_ext(acc_out, 0);
    b.public_ext(s);
    b.public_ext(s);
    let p = b.finish();
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(15);
    let mut tape = vec![F::from_u64(2)];
    for _ in 0..2 {
        tape.extend((0..13).map(|_| common::random_felt(&mut rng)));
    }
    let m = Machine::new(FriProfile::Test);
    let (proof, exec) = m.prove(&p, &tape, None).unwrap();
    m.verify(&p, &proof).unwrap();
    let t = randprotocol_rvm::machine::build_traces(&p, &exec, proof.tier).unwrap();
    let red = t.reduce.unwrap();
    let w = randprotocol_rvm::tables::reduce::col::WIDTH;
    assert_eq!(p.reduce_layout.len(), 2);
    assert_eq!((red.values[MULT], red.values[w + MULT]), (F::TWO, F::TWO), "each entry ran once per iteration");
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

/// Cut B: `hint_array(n)` under `Precompiles::On` (HINTN blocks + a compiled tail) reads exactly
/// `n` words into the same cells the compiled form does, for every tail length.
#[test]
fn hint_array_via_hintn_matches_the_compiled_pairs() {
    use randprotocol_rvm::dsl::{Builder, Checkpoints, Liveness};
    use randprotocol_rvm::programs::Precompiles;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(26);
    for n in [1usize, 7, 8, 9, 16, 17, 121] {
        let tape: Vec<F> = (0..n + 3).map(|_| common::random_felt(&mut rng)).collect(); // 3 spare words
        let run = |pc: Precompiles| {
            let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, pc);
            let arr = b.hint_array(n);
            for k in 0..n {
                let v = b.get(arr, k);
                b.public(v);
            }
            let p = b.finish();
            let exec = execute(&p, &tape, 1_000_000).unwrap();
            let rows = exec.cpu_rows();
            (exec.public, exec.hints_read, rows)
        };
        let (off, off_read, off_rows) = run(Precompiles::Off);
        let (on, on_read, on_rows) = run(Precompiles::On);
        assert_eq!(on, off, "n = {n}");
        assert_eq!(on, tape[..n].to_vec(), "n = {n}: the first n words, in order");
        assert_eq!((off_read, on_read), (n, n), "exactly n words consumed either way");
        assert_eq!(on_rows, off_rows - (n / 8) * 16 + (n / 8), "n = {n}: 16 rows per full block become 1");
    }
}

/// Cut C: the walk with injections under `Precompiles::On` (one COMPRESS per level) computes the
/// compiled walk's digest, for random leaves, siblings and index bits, 1..=12 levels, with and
/// without an injection — and dispatches one `COMPRESS` per level and per injection. (A level's cpu
/// cost is two rows, not one: `compress_step` also emits the `FADDI` that folds the sibling
/// `Ptr`'s offset into a register; `merkle_walk`'s doc has the measured `2·levels + 15`.)
#[test]
fn merkle_walk_via_compress_matches_the_compiled_walk() {
    use randprotocol_rvm::dsl::{hash, Builder, Checkpoints, Digest, Liveness};
    use randprotocol_rvm::isa::Op;
    use randprotocol_rvm::programs::Precompiles;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(27);
    for levels in 1..=12usize {
        for with_injection in [false, true] {
            let leaf: Vec<F> = (0..4).map(|_| common::random_felt(&mut rng)).collect();
            let sibs: Vec<F> = (0..4 * levels).map(|_| common::random_felt(&mut rng)).collect();
            let bits: Vec<bool> = (0..levels).map(|_| rand::RngExt::random(&mut rng)).collect();
            let inj: Vec<F> = (0..9).map(|_| common::random_felt(&mut rng)).collect();
            let run = |pc: Precompiles| {
                let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, pc);
                let leaf_p = b.alloc(4);
                for (k, v) in leaf.iter().enumerate() { let c = b.constant(*v); b.store(leaf_p, k as i64, c); }
                let sib_p = b.alloc(4 * levels as u64);
                for (k, v) in sibs.iter().enumerate() { let c = b.constant(*v); b.store(sib_p, k as i64, c); }
                let bit_f: Vec<_> = bits.iter().map(|&t| b.constant(F::from_bool(t))).collect();
                let inj_p = b.alloc(9);
                for (k, v) in inj.iter().enumerate() { let c = b.constant(*v); b.store(inj_p, k as i64, c); }
                let injections = if with_injection && levels >= 2 {
                    vec![hash::Injection { after_level: levels / 2, rows: inj_p, n_cells: 9 }]
                } else { vec![] };
                let out = Digest(b.alloc(4));
                hash::merkle_walk_with_injections(&mut b, Digest(leaf_p), &bit_f, sib_p, levels, &injections, out);
                for k in 0..4 { let v = b.load(out.0, k); b.public(v); }
                let exec = execute(&b.finish(), &[], 1_000_000).unwrap();
                let compress_rows = exec.histogram()[Op::Compress as usize];
                (exec.public, compress_rows)
            };
            let (off, _) = run(Precompiles::Off);
            let (on, compress_rows) = run(Precompiles::On);
            assert_eq!(on, off, "levels {levels}, injection {with_injection}");
            let expected_compress = levels + usize::from(with_injection && levels >= 2);
            assert_eq!(compress_rows, expected_compress, "one COMPRESS per level and per injection");
        }
    }
}

/// Cut E1 (Review Focus 4): the own-slot check agrees On and Off at every slot of every arity,
/// accepting the honest value and refusing any other at the same named step.
#[test]
fn the_own_slot_check_agrees_on_and_off_at_every_slot() {
    use randprotocol_rvm::dsl::Liveness;
    use randprotocol_rvm::dsl::Felt;
    use randprotocol_rvm::programs::{own_slot_check, Precompiles};
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(28);
    for la in 1..=3usize {
        let a = 1usize << la;
        let row: Vec<EF> = (0..a).map(|_| common::random_ext(&mut rng)).collect();
        // The cases (Task 5 sweep: lane 1 and a right value in the wrong slot, beside lane 0):
        // honest; the folded value off in its low lane; off in its high lane; and exactly the value
        // of another slot of the same row — a check that read the wrong offset would accept it.
        let lane1 = EF::from_basis_coefficients_slice(&[F::ZERO, F::ONE]).unwrap();
        for idx in 0..a {
            let other = row[(idx + 1) % a];
            assert_ne!(other, row[idx], "the random row's slots are distinct");
            for (case, folded) in [("honest", row[idx]), ("lane 0", row[idx] + EF::ONE), ("lane 1", row[idx] + lane1), ("other slot", other)] {
                let honest = case == "honest";
                let run = |pc: Precompiles| -> Result<(), String> {
                    let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, pc);
                    let msg = b.alloc(2 * a as u64);
                    for (j, v) in row.iter().enumerate() {
                        let c = b.ext_constant(*v);
                        b.store_ext(msg, 2 * j as i64, c);
                    }
                    let own: Vec<Felt> = (0..la).map(|k| b.constant(F::from_u64(((idx >> k) & 1) as u64))).collect();
                    let f = b.ext_constant(folded);
                    own_slot_check(&mut b, msg, &own, f, "own slot");
                    for _ in 0..4 {
                        let z = b.zero();
                        b.public(z);
                    }
                    let p = b.finish();
                    match execute(&p, &[], 100_000) {
                        Ok(_) => Ok(()),
                        Err(ExecError::InverseOfZero { pc }) => Err(p.checkpoint_at(pc).unwrap_or("?").to_string()),
                        Err(e) => Err(format!("{e:?}")),
                    }
                };
                let (on, off) = (run(Precompiles::On), run(Precompiles::Off));
                assert_eq!(on, off, "la {la}, idx {idx}, {case}");
                assert_eq!(on, if honest { Ok(()) } else { Err("own slot".to_string()) }, "la {la}, idx {idx}, {case}");
            }
        }
    }
}

/// Cut E2 (Review Focus 5): fold runs of every arity back to back in one table, and a run at
/// u = 0, prove and verify — the K counter, the phase switch and the coefficient lookups across
/// run boundaries.
#[test]
fn fold_runs_of_every_arity_back_to_back_prove_and_verify() {
    use p3_field::Field;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(29);
    let mut runs = vec![];
    for la in [1usize, 2, 3, 3, 1] {
        runs.push((la, (0..1usize << la).map(|_| common::random_ext(&mut rng)).collect::<Vec<EF>>(), common::random_ext(&mut rng)));
    }
    runs[3].2 = EF::ZERO;
    let (p, want) = common::fold_program(&runs);
    let m = Machine::new(FriProfile::Test);
    let (proof, exec) = m.prove(&p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();
    assert_eq!(exec.public[..2].to_vec(), want[0].as_basis_coefficients_slice().to_vec());
    let b0 = runs[3].1.iter().fold(EF::ZERO, |acc, y| acc + *y) * F::from_u64(8).inverse();
    assert_eq!(want[3], b0, "at u = 0 the fold is B_0, the row's mean");
}

/// Cut E2: the chip fold equals the compiled barycentric fold and `fold_row`, at every arity.
#[test]
fn fold_via_the_chip_matches_the_compiled_fold() {
    use randprotocol_rvm::dsl::Liveness;
    use randprotocol_rvm::programs::{fold_eval, Precompiles};
    use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
    let folding: TwoAdicFriFolding<(), ()> = TwoAdicFriFolding(std::marker::PhantomData);
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(30);
    for la in 1..=3usize {
        for _ in 0..8 {
            let log_folded = 6usize;
            let index: usize = rand::RngExt::random_range(&mut rng, 0..1usize << log_folded);
            let beta = common::random_ext(&mut rng);
            let row: Vec<EF> = (0..1usize << la).map(|_| common::random_ext(&mut rng)).collect();
            let want = <TwoAdicFriFolding<(), ()> as FriFoldingStrategy<F, EF>>::fold_row(&folding, index, log_folded, la, beta, row.iter().copied());
            let run = |pc: Precompiles| {
                let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, pc);
                let msg = b.alloc(2 * (1 << la) + 6);
                for (j, v) in row.iter().enumerate() {
                    let c = b.ext_constant(*v);
                    b.store_ext(msg, 2 * j as i64, c);
                }
                let bits: Vec<randprotocol_rvm::dsl::Felt> = (0..log_folded).map(|k| b.constant(F::from_u64(((index >> k) & 1) as u64))).collect();
                let be = b.ext_constant(beta);
                let out = fold_eval(&mut b, log_folded, la, &bits, be, msg, None);
                b.public_ext(out);
                b.public_ext(out);
                let got = execute(&b.finish(), &[], 1_000_000).unwrap().public;
                ef([got[0], got[1]])
            };
            assert_eq!(run(Precompiles::Off), want, "compiled, la {la}");
            assert_eq!(run(Precompiles::On), want, "the chip, la {la}");
            // Cut F: the same fold with `s` a POW run over the index's cells (at offset 3 of a
            // 65-cell buffer, as `emit_query` places a round's group bits after earlier rounds').
            let mut b = Builder::with_opts(Checkpoints::Off, Liveness::On, Precompiles::On);
            let msg = b.alloc(2 * (1 << la) + 6);
            for (j, v) in row.iter().enumerate() {
                let c = b.ext_constant(*v);
                b.store_ext(msg, 2 * j as i64, c);
            }
            let buf = b.alloc(65);
            let bits: Vec<randprotocol_rvm::dsl::Felt> = (0..log_folded)
                .map(|k| {
                    let c = b.constant(F::from_u64(((index >> k) & 1) as u64));
                    b.store(buf, 3 + k as i64, c);
                    c
                })
                .collect();
            let be = b.ext_constant(beta);
            let out = fold_eval(&mut b, log_folded, la, &bits, be, msg, Some((buf, 3)));
            b.public_ext(out);
            b.public_ext(out);
            let p = b.finish();
            assert!(p.instrs.iter().any(|i| i.op == randprotocol_rvm::isa::Op::Pow), "the cells path dispatches POW");
            let got = execute(&p, &[], 1_000_000).unwrap().public;
            assert_eq!(ef([got[0], got[1]]), want, "the chip with POW, la {la}");
        }
    }
}

/// Cut F: POW equals the closed form `base·Π_k g^{2^{L−1−k}·bit_{off+k}}` for random bits,
/// offsets and lengths. (Renamed in the Task 5 sweep: this checks the formula, not the compiled
/// `bit_selected_power`. The On/Off differential against that ladder is
/// `fold_via_the_chip_matches_the_compiled_fold`'s `cells = Some` case, where `On` takes `s` from a
/// `POW` and `Off` from `bit_selected_power`, and the fixture acceptance and tamper tables, which
/// run both builds over real proofs.)
#[test]
fn pow_matches_the_closed_form_index_power() {
    use p3_field::TwoAdicField;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(31);
    let m = Machine::new(FriProfile::Test);
    for (off, len) in [(0u64, 1u64), (0, 20), (5, 11), (44, 20), (63, 1)] {
        let bits: Vec<u64> = (0..64).map(|_| rand::RngExt::random::<bool>(&mut rng) as u64).collect();
        let g = F::two_adic_generator(len as usize + 3);
        let mut want = F::GENERATOR;
        for k in 0..len {
            if bits[(off + k) as usize] == 1 {
                want *= g.exp_u64(1 << (len - 1 - k));
            }
        }
        let p = common::pow_program(&bits, off, len, g, F::GENERATOR);
        let (proof, exec) = m.prove(&p, &[], None).unwrap();
        m.verify(&p, &proof).unwrap();
        assert_eq!(exec.public[0], want, "off {off}, len {len}");
    }
}

/// Cut F: a POW immediate whose run leaves the 64 bits (or is empty) is refused at registration,
/// as the emulator refuses it at run time — the chip range-checks the two bytes, not their sum.
#[test]
fn a_pow_immediate_leaving_the_buffer_is_refused_at_registration() {
    use randprotocol_rvm::isa::DecodeError;
    for (off, len) in [(60u64, 8u64), (0, 0), (64, 1), (0, 65)] {
        let p = common::pow_program(&[0; 64], off, len, F::TWO, F::ONE);
        assert_eq!(Machine::check_program(&p), Err(DecodeError::PowShape { imm: off + 256 * len }), "off {off}, len {len}");
        assert!(matches!(execute(&p, &[], 10_000), Err(ExecError::PowShape { .. })), "off {off}, len {len}");
    }
    let p = common::pow_program(&[0; 64], 44, 20, F::TWO, F::ONE);
    assert_eq!(Machine::check_program(&p), Ok(()));
}
