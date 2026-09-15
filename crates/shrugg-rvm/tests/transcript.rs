//! The transcript and the hashes, differentially against the very Plonky3 code the native verifier
//! calls: `p3-challenger`'s `DuplexChallenger`, `p3-symmetric`'s `PaddingFreeSponge` and
//! `TruncatedPermutation`, and `p3-merkle-tree`'s own authentication paths.
//!
//! Every expectation here is computed by the real crate on random input. Nothing is compared against
//! a constant, and nothing is compared against a second hand-rolled implementation of the same idea
//! — bit-exactness with the code the verifier runs is the whole point of the DSL's hash layer, and a
//! reimplementation would agree with itself while both were wrong.
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation};
use rand::{RngExt, SeedableRng};
use shrugg_rvm::dsl::{hash, transcript::DslChallenger, Builder, Checkpoints};
use shrugg_rvm::emulator::execute;
use shrugg_rvm::isa::{EF, F};

type Perm = shrugg_zkvm::machine::Perm;
type Chal = shrugg_zkvm::machine::Challenger;
fn perm() -> Perm {
    shrugg_zkvm::machine::permutation()
}
fn native() -> Chal {
    Chal::new(perm())
}

fn run(b: Builder, w: &[F]) -> Vec<F> {
    execute(&b.finish(), w, 5_000_000).unwrap().public
}

#[test]
fn the_dsl_challenger_matches_p3_challenger_on_random_observations() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    for trial in 0..20 {
        let n: usize = rng.random_range(0..23);
        let obs: Vec<F> = (0..n).map(|_| F::from_u64(rng.random::<u64>() % F::ORDER_U64)).collect();

        let mut nat = native();
        nat.observe_slice(&obs);
        let want: Vec<F> = (0..5).map(|_| nat.sample()).collect();

        let mut b = Builder::new(Checkpoints::Off);
        let mut ch = DslChallenger::new(&mut b);
        let handles: Vec<_> = obs.iter().map(|v| b.constant(*v)).collect();
        ch.observe_slice(&mut b, &handles);
        for _ in 0..5 {
            let s = ch.sample(&mut b);
            b.public(s);
        }
        assert_eq!(run(b, &[]), want, "trial {trial}, n = {n}");
    }
}

#[test]
fn sample_ext_matches_p3_challengers_two_coefficient_draw() {
    let mut nat = native();
    nat.observe(F::from_u64(42));
    let want: EF = nat.sample_algebra_element();
    let want2: EF = nat.sample_algebra_element();

    let mut b = Builder::new(Checkpoints::Off);
    let mut ch = DslChallenger::new(&mut b);
    let v = b.constant(F::from_u64(42));
    ch.observe(&mut b, v);
    let a = ch.sample_ext(&mut b);
    let c = ch.sample_ext(&mut b);
    b.public_ext(a);
    b.public_ext(c);
    let mut expect = want.as_basis_coefficients_slice().to_vec();
    expect.extend_from_slice(want2.as_basis_coefficients_slice());
    assert_eq!(run(b, &[]), expect);
}

#[test]
fn observe_usize_and_observe_ext_match_the_batch_transcripts_helpers() {
    // `BatchTranscript::observe_usize` is observe_base_as_algebra_element::<Challenge>, i.e. two absorbs.
    let mut nat = native();
    nat.observe_base_as_algebra_element::<EF>(F::from_u64(9));
    nat.observe_algebra_element(EF::from_basis_coefficients_slice(&[F::ONE, F::TWO]).unwrap());
    let want: Vec<F> = (0..4).map(|_| nat.sample()).collect();

    let mut b = Builder::new(Checkpoints::Off);
    let mut ch = DslChallenger::new(&mut b);
    ch.observe_usize(&mut b, 9);
    let e = b.ext_constant(EF::from_basis_coefficients_slice(&[F::ONE, F::TWO]).unwrap());
    ch.observe_ext(&mut b, e);
    for _ in 0..4 {
        let s = ch.sample(&mut b);
        b.public(s);
    }
    assert_eq!(run(b, &[]), want);
}

#[test]
fn an_observe_after_a_sample_discards_the_squeezed_output_p3_has_not_handed_out() {
    // sample, observe, sample — the shape every phase of the real verifier has (draw alpha, observe
    // the next commitment, draw beta). `CanObserve::observe` clears the output buffer, so the
    // observe forces a fresh permutation instead of handing out the two elements left over from the
    // previous squeeze (`p3-challenger-0.7.0/src/duplex_challenger.rs:168`). A challenger that kept
    // them agrees with the reference on every transcript that never interleaves the two, which is
    // every other test in this file.
    let mut rng = rand::rngs::StdRng::seed_from_u64(8);
    let obs: Vec<F> = (0..3).map(|_| F::from_u64(rng.random::<u64>() % F::ORDER_U64)).collect();
    let mut nat = native();
    nat.observe(obs[0]);
    let mut want: Vec<F> = vec![nat.sample(), nat.sample()];
    nat.observe(obs[1]);
    want.push(nat.sample());
    nat.observe(obs[2]);
    for _ in 0..5 {
        want.push(nat.sample());
    }

    let mut b = Builder::new(Checkpoints::Off);
    let mut ch = DslChallenger::new(&mut b);
    let h: Vec<_> = obs.iter().map(|v| b.constant(*v)).collect();
    ch.observe(&mut b, h[0]);
    for _ in 0..2 {
        let s = ch.sample(&mut b);
        b.public(s);
    }
    ch.observe(&mut b, h[1]);
    let s = ch.sample(&mut b);
    b.public(s);
    ch.observe(&mut b, h[2]);
    for _ in 0..5 {
        let s = ch.sample(&mut b);
        b.public(s);
    }
    assert_eq!(run(b, &[]), want);
}

#[test]
fn sample_bits_matches_the_low_bits_of_the_canonical_representative() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);
    for bits in [1usize, 8, 20, 21, 27] {
        let seed = F::from_u64(rng.random::<u64>() % F::ORDER_U64);
        let mut nat = native();
        nat.observe(seed);
        let want = nat.sample_bits(bits);

        let mut b = Builder::new(Checkpoints::Off);
        let mut ch = DslChallenger::new(&mut b);
        let s = b.constant(seed);
        ch.observe(&mut b, s);
        // The program reads the 64 bit hints from the witness tape; the host supplies them.
        let idx_bits = ch.sample_bits(&mut b, bits);
        for bit in &idx_bits {
            b.public(*bit);
        }
        let p = b.finish();

        // The witness: the 64 bits of the sampled element, little-endian, plus the
        // nonzero-inverse hint the canonicality check needs.
        let mut nat2 = native();
        nat2.observe(seed);
        let x: F = nat2.sample();
        let v = x.as_canonical_u64();
        let mut w: Vec<F> = (0..64).map(|k| F::from_u64((v >> k) & 1)).collect();
        w.push(shrugg_rvm::dsl::transcript::canonicality_hint(v));
        let got = execute(&p, &w, 5_000_000).unwrap().public;
        let want_bits: Vec<F> = (0..bits).map(|k| F::from_u64(((want as u64) >> k) & 1)).collect();
        assert_eq!(got, want_bits, "bits = {bits}");
    }
}

#[test]
fn sample_bits_rejects_a_non_canonical_decomposition() {
    // 2^64 - 2^32 + 2 ≡ 1 (mod p) has a 64-bit decomposition that is not the canonical one — high
    // half all ones, low half 2 — so the canonicality check must trap on it whatever hint the prover
    // supplies. The two hints exercise the two halves of that check, which trap in different places:
    //
    // - `t = 1` is not `lo⁻¹`, so the hint-validity assert (`lo·t·lo = lo`, here 4 ≠ 2) fires;
    // - `t = lo⁻¹` satisfies it, so execution reaches the rejection assert proper
    //   (`all_hi · lo · t = 1 ≠ 0`) — the constraint that actually forbids the forgery `v = x + p`
    //   with an honest hint, and the one nothing else in this file reaches in a violating state.
    //
    // Both carry the same checkpoint name, because either firing means the same thing: the hinted
    // bits are not the canonical representative of the sampled element.
    let build = || {
        let mut b = Builder::new(Checkpoints::Off);
        let mut ch = DslChallenger::new(&mut b);
        let s = b.constant(F::ONE);
        ch.observe(&mut b, s);
        let _ = ch.sample_bits(&mut b, 20);
        b.finish()
    };
    let v: u64 = u64::MAX - (1 << 32) + 3; // 2^64 - 2^32 + 2 ≡ 1 mod p, 64 bits wide
    let bits: Vec<F> = (0..64).map(|k| F::from_u64((v >> k) & 1)).collect();
    for (hint, which) in [
        (F::ONE, "a hint that is not lo's inverse"),
        (shrugg_rvm::dsl::transcript::canonicality_hint(v), "lo's real inverse"),
    ] {
        let mut w = bits.clone();
        w.push(hint);
        let p = build();
        match execute(&p, &w, 5_000_000) {
            Err(shrugg_rvm::emulator::ExecError::InverseOfZero { pc }) => {
                assert_eq!(p.checkpoint_at(pc), Some("sample_bits canonicality"), "{which}");
            }
            other => panic!("{which}: a non-canonical decomposition must trap, got {other:?}"),
        }
    }
}

#[test]
fn sample_bits_rejects_a_forged_decomposition_of_the_sampled_element() {
    // The two ways a prover would forge a query index if `sample_bits` only checked the sum, both
    // named by the checkpoint they must trap at.
    //
    // 1. A non-boolean "bit": put the whole sampled element in bit 0 and zero the rest. The sum is
    //    right, the high bits are zero so the canonicality product is zero, and bit 0 comes back as
    //    an arbitrary field element the caller would use as an index bit.
    // 2. A non-canonical decomposition with a *zero* hint: `all_hi · lo · t` is zero for t = 0
    //    whatever `lo` is, so the hint has to be pinned to `lo`'s inverse (`lo·t·lo = lo`) or the
    //    canonicality check is vacuous.
    let build = || {
        let mut b = Builder::new(Checkpoints::Off);
        let mut ch = DslChallenger::new(&mut b);
        let s = b.constant(F::from_u64(11));
        ch.observe(&mut b, s);
        let _ = ch.sample_bits(&mut b, 20);
        b.finish()
    };
    let mut nat = native();
    nat.observe(F::from_u64(11));
    let x: F = nat.sample();

    let mut forged: Vec<F> = vec![F::ZERO; 64];
    forged[0] = x;
    let mut with_bit_hint = forged.clone();
    with_bit_hint.push(shrugg_rvm::dsl::transcript::canonicality_hint(x.as_canonical_u64()));

    let v: u128 = (1u128 << 64) - (1u128 << 32) + 2;
    let mut zero_hint: Vec<F> = (0..64).map(|k| F::from_u64(((v >> k) & 1) as u64)).collect();
    zero_hint.push(F::ZERO);

    for (tape, want) in
        [(with_bit_hint, "sample_bits bit 0"), (zero_hint, "sample_bits canonicality")]
    {
        let p = build();
        match execute(&p, &tape, 5_000_000) {
            Err(shrugg_rvm::emulator::ExecError::InverseOfZero { pc }) => {
                assert_eq!(p.checkpoint_at(pc), Some(want));
            }
            other => panic!("{want}: a forged decomposition must trap, got {other:?}"),
        }
    }
}

#[test]
fn check_witness_accepts_only_a_grinding_witness_p3_accepts() {
    const BITS: usize = 8;
    let mut nat = native();
    nat.observe(F::from_u64(5));
    let mut grinder = nat.clone();
    let witness = grinder.grind(BITS);
    assert!(nat.clone().check_witness(BITS, witness));
    assert!(!nat.clone().check_witness(BITS, witness + F::ONE));

    for (w_val, ok) in [(witness, true), (witness + F::ONE, false)] {
        let mut b = Builder::new(Checkpoints::Off);
        let mut ch = DslChallenger::new(&mut b);
        let s = b.constant(F::from_u64(5));
        ch.observe(&mut b, s);
        let wh = b.constant(w_val);
        ch.check_witness(&mut b, BITS, wh, "pow");
        let p = b.finish();
        let mut nat2 = native();
        nat2.observe(F::from_u64(5));
        nat2.observe(w_val);
        let x: F = nat2.sample();
        let v = x.as_canonical_u64();
        let mut tape: Vec<F> = (0..64).map(|k| F::from_u64((v >> k) & 1)).collect();
        tape.push(shrugg_rvm::dsl::transcript::canonicality_hint(v));
        assert_eq!(execute(&p, &tape, 5_000_000).is_ok(), ok, "witness {w_val:?}");
    }
}

#[test]
fn observe_digest_and_observe_cap_match_p3_challengers_digest_and_cap_absorbs() {
    // `CanObserve<[F; 4]>` and `CanObserve<&MerkleCap<F, [F; 4]>>` are what the batch verifier uses
    // for a commitment; four and sixteen base absorbs respectively, and the cap's digest order is
    // `roots()` order.
    let mut rng = rand::rngs::StdRng::seed_from_u64(6);
    let d: [F; 4] = core::array::from_fn(|_| F::from_u64(rng.random::<u64>() % F::ORDER_U64));
    let cap_digests: Vec<[F; 4]> = (0..4)
        .map(|_| core::array::from_fn(|_| F::from_u64(rng.random::<u64>() % F::ORDER_U64)))
        .collect();
    let cap = p3_symmetric::MerkleCap::<F, [F; 4]>::new(cap_digests.clone());

    let mut nat = native();
    nat.observe(d);
    nat.observe(&cap);
    let want: Vec<F> = (0..6).map(|_| nat.sample()).collect();

    let mut b = Builder::new(Checkpoints::Off);
    let mut ch = DslChallenger::new(&mut b);
    let dp = shrugg_rvm::dsl::Digest(b.alloc(4));
    for (k, v) in d.iter().enumerate() {
        let h = b.constant(*v);
        b.store(dp.0, k as i64, h);
    }
    ch.observe_digest(&mut b, dp);
    let capp: [shrugg_rvm::dsl::Digest; 4] = core::array::from_fn(|j| {
        let p = shrugg_rvm::dsl::Digest(b.alloc(4));
        for (k, v) in cap_digests[j].iter().enumerate() {
            let h = b.constant(*v);
            b.store(p.0, k as i64, h);
        }
        p
    });
    ch.observe_cap(&mut b, &capp);
    for _ in 0..6 {
        let s = ch.sample(&mut b);
        b.public(s);
    }
    assert_eq!(run(b, &[]), want);
}

#[test]
fn the_dsl_leaf_sponge_matches_padding_free_sponge_8_4_4() {
    let sponge = PaddingFreeSponge::<Perm, 8, 4, 4>::new(perm());
    let mut rng = rand::rngs::StdRng::seed_from_u64(3);
    for n in [1usize, 3, 4, 5, 8, 9, 37, 121] {
        let msg: Vec<F> = (0..n).map(|_| F::from_u64(rng.random::<u64>() % F::ORDER_U64)).collect();
        let want: [F; 4] = sponge.hash_iter(msg.iter().copied());

        let mut b = Builder::new(Checkpoints::Off);
        let src = b.alloc(n as u64);
        for (k, v) in msg.iter().enumerate() {
            let h = b.constant(*v);
            b.store(src, k as i64, h);
        }
        let out = shrugg_rvm::dsl::Digest(b.alloc(4));
        hash::sponge(&mut b, src, n, out);
        for k in 0..4 {
            let v = b.load(out.0, k);
            b.public(v);
        }
        assert_eq!(run(b, &[]), want.to_vec(), "n = {n}");
    }
}

#[test]
fn the_dsl_compression_matches_truncated_permutation_2_4_8() {
    let c = TruncatedPermutation::<Perm, 2, 4, 8>::new(perm());
    let mut rng = rand::rngs::StdRng::seed_from_u64(4);
    for _ in 0..20 {
        let l: [F; 4] = core::array::from_fn(|_| F::from_u64(rng.random::<u64>() % F::ORDER_U64));
        let r: [F; 4] = core::array::from_fn(|_| F::from_u64(rng.random::<u64>() % F::ORDER_U64));
        let want = c.compress([l, r]);

        let mut b = Builder::new(Checkpoints::Off);
        let (lp, rp, op) = (b.alloc(4), b.alloc(4), b.alloc(4));
        for k in 0..4 {
            let a = b.constant(l[k]);
            b.store(lp, k as i64, a);
            let d = b.constant(r[k]);
            b.store(rp, k as i64, d);
        }
        hash::compress(
            &mut b,
            shrugg_rvm::dsl::Digest(lp),
            shrugg_rvm::dsl::Digest(rp),
            shrugg_rvm::dsl::Digest(op),
        );
        for k in 0..4 {
            let v = b.load(op, k);
            b.public(v);
        }
        assert_eq!(run(b, &[]), want.to_vec());
    }
}

#[test]
fn a_restored_merkle_path_verifies_in_the_dsl_exactly_where_p3_verifies_it() {
    use p3_commit::Mmcs;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Dimensions;
    let mmcs = shrugg_zkvm::machine::val_mmcs_for_tests(); // the crate's own ValMmcs, seeded
    let mut rng = rand::rngs::StdRng::seed_from_u64(5);
    let (h, w) = (64usize, 5usize);
    let mat = RowMajorMatrix::new(
        (0..h * w).map(|_| F::from_u64(rng.random::<u64>() % F::ORDER_U64)).collect(),
        w,
    );
    let (commit, data) = mmcs.commit(vec![mat.clone()]);
    let indices = [0usize, 1, 17, 63];
    let (opened, multi) = mmcs.open_multi_batch(&indices, &data);
    let dims = [Dimensions { width: w, height: h }];
    mmcs.verify_multi_batch(&commit, &dims, &indices, &opened, &multi).unwrap();
    let paths = shrugg_zkvm::machine::restore_paths_for_tests(&mmcs, &dims, &indices, &opened, &multi);

    for (q, idx) in indices.iter().enumerate() {
        let mut b = Builder::new(Checkpoints::Off);
        // leaf = sponge(row ‖ salts): the hiding MMCS widens the row by SALT_ELEMS = 4.
        let row: Vec<F> = opened[q][0].iter().copied().chain(multi.0[q][0].iter().copied()).collect();
        let src = b.alloc(row.len() as u64);
        for (k, v) in row.iter().enumerate() {
            let hv = b.constant(*v);
            b.store(src, k as i64, hv);
        }
        let leaf = shrugg_rvm::dsl::Digest(b.alloc(4));
        hash::sponge(&mut b, src, row.len(), leaf);

        let sib = b.alloc((paths[q].siblings.len() * 4) as u64);
        for (l, s) in paths[q].siblings.iter().enumerate() {
            for (k, hw) in s.iter().enumerate() {
                let hv = b.constant(*hw);
                b.store(sib, (l * 4 + k) as i64, hv);
            }
        }
        let levels = paths[q].siblings.len();
        let bits: Vec<_> =
            (0..levels).map(|k| b.constant(F::from_u64(((*idx as u64) >> k) & 1))).collect();
        let root = shrugg_rvm::dsl::Digest(b.alloc(4));
        hash::merkle_walk(&mut b, leaf, &bits, sib, levels, root);
        for k in 0..4 {
            let v = b.load(root.0, k);
            b.public(v);
        }

        // `cap_height = 2`, so the walk stops two levels below the root and the surviving digest
        // is compared with `commit[index >> levels]` (`mmcs/batch.rs:267`).
        assert_eq!(levels, 6 - 2, "log2(64) - cap_height");
        assert_eq!(run(b, &[]), commit.roots()[*idx >> levels].to_vec(), "query {q}");
    }
}

#[test]
#[should_panic(expected = "two injections after level 1")]
fn two_injections_at_one_level_are_refused_at_build_time() {
    // The reference hashes every matrix at one height into a single digest and compresses once, so
    // two injections at one level would compress twice and reach a different root. There is no tape
    // that makes that visible — it is a wrong program, not a rejected proof — so the builder refuses
    // it (`p3-merkle-tree-0.7.0/src/mmcs/batch.rs:245-262`).
    let mut b = Builder::new(Checkpoints::Off);
    let leaf = shrugg_rvm::dsl::Digest(b.alloc(4));
    let sib = b.alloc(16);
    let rows = b.alloc(9);
    let out = shrugg_rvm::dsl::Digest(b.alloc(4));
    let bits: Vec<_> = (0..4).map(|_| b.constant(F::ONE)).collect();
    let inj = [
        hash::Injection { after_level: 1, rows, n_cells: 5 },
        hash::Injection { after_level: 1, rows, n_cells: 4 },
    ];
    hash::merkle_walk_with_injections(&mut b, leaf, &bits, sib, 4, &inj, out);
}

#[test]
fn an_injected_shorter_matrix_group_verifies_in_the_dsl_exactly_where_p3_verifies_it() {
    // Two matrices of different heights, which is what every round of the real batch looks like:
    // the tall one is hashed into the leaf, the short one is *injected* after the level whose height
    // it matches (`p3-merkle-tree-0.7.0/src/mmcs/mod.rs:777-834`, the same code as `verify_batch`'s
    // `mmcs/batch.rs:240-262`). Heights 64 and 16, so the injection lands after level 1.
    use p3_commit::Mmcs;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::Dimensions;
    let mmcs = shrugg_zkvm::machine::val_mmcs_for_tests();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let mut mat = |h: usize, w: usize| {
        RowMajorMatrix::new(
            (0..h * w).map(|_| F::from_u64(rng.random::<u64>() % F::ORDER_U64)).collect::<Vec<F>>(),
            w,
        )
    };
    let (tall, short) = (mat(64, 5), mat(16, 3));
    let (commit, data) = mmcs.commit(vec![tall, short]);
    let indices = [0usize, 5, 33, 63];
    let (opened, multi) = mmcs.open_multi_batch(&indices, &data);
    let dims = [Dimensions { width: 5, height: 64 }, Dimensions { width: 3, height: 16 }];
    mmcs.verify_multi_batch(&commit, &dims, &indices, &opened, &multi).unwrap();
    let paths = shrugg_zkvm::machine::restore_paths_for_tests(&mmcs, &dims, &indices, &opened, &multi);

    for (q, idx) in indices.iter().enumerate() {
        // The injected rows are not siblings: they are the shorter matrix's own opened row, salted
        // and sponged, then compressed into the running digest.
        let leaf_row: Vec<F> =
            opened[q][0].iter().copied().chain(multi.0[q][0].iter().copied()).collect();
        let inj_row: Vec<F> =
            opened[q][1].iter().copied().chain(multi.0[q][1].iter().copied()).collect();

        let mut b = Builder::new(Checkpoints::Off);
        let src = b.alloc(leaf_row.len() as u64);
        for (k, v) in leaf_row.iter().enumerate() {
            let hv = b.constant(*v);
            b.store(src, k as i64, hv);
        }
        let leaf = shrugg_rvm::dsl::Digest(b.alloc(4));
        hash::sponge(&mut b, src, leaf_row.len(), leaf);

        let rows = b.alloc(inj_row.len() as u64);
        for (k, v) in inj_row.iter().enumerate() {
            let hv = b.constant(*v);
            b.store(rows, k as i64, hv);
        }

        let levels = paths[q].siblings.len();
        assert_eq!(levels, 4, "log2(64) - cap_height");
        let sib = b.alloc((levels * 4) as u64);
        for (l, s) in paths[q].siblings.iter().enumerate() {
            for (k, hw) in s.iter().enumerate() {
                let hv = b.constant(*hw);
                b.store(sib, (l * 4 + k) as i64, hv);
            }
        }
        let bits: Vec<_> =
            (0..levels).map(|k| b.constant(F::from_u64(((*idx as u64) >> k) & 1))).collect();
        let root = shrugg_rvm::dsl::Digest(b.alloc(4));
        let inj = [hash::Injection { after_level: 1, rows, n_cells: inj_row.len() }];
        hash::merkle_walk_with_injections(&mut b, leaf, &bits, sib, levels, &inj, root);
        for k in 0..4 {
            let v = b.load(root.0, k);
            b.public(v);
        }
        assert_eq!(run(b, &[]), commit.roots()[*idx >> levels].to_vec(), "query {q}");
    }
}
