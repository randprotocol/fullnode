//! The verifier program, against a real `randprotocol_zkvm` bundle proof.
//!
//! Every expectation here comes from the *same* Plonky3 code `Machine::verify` runs:
//! `reference::replay` is a host-side replay of the transcript built out of `p3-challenger`,
//! `p3_batch_stark::verifier::commitments_with_opening_points`, `p3_uni_stark`'s own
//! `recompose_quotient_from_chunks` and folder, and `p3_fri::verifier`'s `open_inputs`/`fold_query`
//! — not a second implementation of any of them. The program is then compared against that replay
//! value by value, so "the rVM reproduces the transcript" is a checked claim about bit-exactness
//! rather than about acceptance.
mod common;

use p3_field::PrimeCharacteristicRing;
use randprotocol_zkvm::machine::{FriProfile, Machine};
use randprotocol_rvm::dsl::Checkpoints;
use randprotocol_rvm::emulator::{execute, ExecError};
use randprotocol_rvm::isa::F;
use randprotocol_rvm::programs::verify_rv32;
use randprotocol_rvm::reference::replay;
use randprotocol_rvm::shape::{InnerKey, InnerShape};
use randprotocol_rvm::witness::WitnessTape;

fn one_test_proof() -> (common::BundleProof, InnerShape, InnerKey) {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let shape = InnerShape::of(
        FriProfile::Test,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height, p.proof.public_log_height,
        p.proof.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Test, &shape);
    (p, shape, key)
}

#[test]
fn the_witness_tape_layout_is_pinned() {
    let (p, shape, key) = one_test_proof();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let names: Vec<_> = tape.segments.iter().map(|(s, _, _)| *s).collect();
    use randprotocol_rvm::witness::Segment::*;
    assert_eq!(
        names,
        vec![
            Header,
            PublicValues,
            Commitments,
            LookupTerminals,
            OpenedValues,
            RandomOpenings,
            FriCommits,
            FinalPoly,
            QueryPow,
            QueryBits,
            InputOpenings,
            InputPaths,
            CommitPhaseOpenings,
            CommitPhasePaths
        ]
    );
    // Segments tile the tape exactly, in order, with no gap and no overlap.
    let mut at = 0usize;
    for (_, start, len) in &tape.segments {
        assert_eq!(*start, at);
        at += len;
    }
    assert_eq!(at, tape.words.len());
    assert_eq!(at, tape.len());
    // The header is the proof's own declared shape, so a shape mismatch is visible immediately.
    assert_eq!(tape.words[0], F::from_usize(p.proof.tier.0));
    assert!(shape.matches(&p.proof));
    println!("{}", tape.describe());
}

#[test]
fn the_host_transcript_replay_reproduces_machine_verifys_acceptance() {
    let (p, shape, key) = one_test_proof();
    let m = Machine::new(FriProfile::Test);
    m.verify(&p.hc, &p.proof).expect("the fixture proof verifies natively");
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).expect("the replay accepts it too");
    assert_eq!(r.indices.len(), shape.num_queries);
    assert_eq!(r.betas.len(), shape.log_arities.len());
    assert_eq!(
        r.log_global_max_height,
        shape.log_arities.iter().sum::<usize>() + randprotocol_rvm::shape::LOG_BLOWUP
    );
    // The replay is the transcript, so its zeta must also satisfy the quotient identity the
    // native verifier checked: accumulator * inv_vanishing == quotient, per instance.
    assert_eq!(r.accumulators.len(), r.quotients.len());
    for i in 0..r.quotients.len() {
        assert_eq!(
            r.accumulators[i] * r.selectors[i].inv_vanishing, r.quotients[i],
            "instance {i}'s quotient identity"
        );
    }
}

#[test]
fn the_program_reproduces_the_lookup_challenges_alpha_and_zeta() {
    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let vp = verify_rv32(&shape, &key, Checkpoints::On);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, 100_000_000).expect("the program accepts");
    let cp = randprotocol_rvm::programs::checkpoint_values(&vp, &exec);
    assert_eq!(cp["lookup_alpha"], r.lookup_alpha);
    assert_eq!(cp["lookup_beta"], r.lookup_beta);
    assert_eq!(cp["alpha"], r.alpha);
    assert_eq!(cp["zeta"], r.zeta);
    assert_eq!(cp["fri_alpha"], r.fri_alpha);
    for (i, beta) in r.betas.iter().enumerate() {
        assert_eq!(cp[&format!("beta[{i}]")], *beta, "beta[{i}]");
    }
    // The finished program consumes the *whole* tape — which is the invariant that makes the
    // tape's segment boundaries real rather than decorative. (At Task 4's boundary this asserted
    // the first five segments; Task 6's finished program reads all fourteen.)
    assert_eq!(exec.hints_read, tape.len(), "the program reads every segment, no more");
}

/// The one assertion phases 0–4 make beyond the declared shape: `LogUpGadget::verify_terminal_sum`.
/// Without this test, deleting it goes unnoticed — the transcript tests only compare challenges.
#[test]
fn a_tampered_lookup_terminal_is_refused_at_the_terminal_sum_checkpoint() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let (_, start, len) = *tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == randprotocol_rvm::witness::Segment::LookupTerminals)
        .unwrap();
    assert!(len > 0, "this machine's batch has lookups");
    for k in [0usize, 1, len - 1] {
        let mut t = tape.clone();
        t.words[start + k] += F::ONE;
        match execute(&vp.program, &t.words, 100_000_000) {
            Err(ExecError::InverseOfZero { pc }) => assert_eq!(
                vp.program.checkpoint_at(pc),
                Some("lookup terminal sum"),
                "terminal word {k}"
            ),
            other => panic!("terminal word {k}: expected a refusal, got {other:?}"),
        }
    }
    // And the untampered tape still runs, so the refusal is about the tamper.
    execute(&vp.program, &tape.words, 100_000_000).expect("the honest tape is accepted");
}

/// `OpenedValues` and `RandomOpenings` are the two biggest segments phases 0–4 do not read, and
/// Tasks 5 and 6 will size their reads from the [`InnerShape`] alone. So the pin is exactly that:
/// the segment lengths derived from the shape, with no reference to the proof's own nesting — which
/// is what makes the amendment to the brief's table (the permutation openings belong in segment 5,
/// because `OpenedValuesWithLookups` has two fields beyond `OpenedValues` and the constraint check
/// needs both) a checked claim rather than a comment.
#[test]
fn the_opened_value_segments_are_sized_by_the_shape_alone() {
    let (p, shape, key) = one_test_proof();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let seg = |s: randprotocol_rvm::witness::Segment| {
        tape.segments.iter().find(|(x, _, _)| *x == s).unwrap().2
    };
    let n = shape.instances();
    // Per instance: trace_local, trace_next?, preprocessed_local, preprocessed_next?, one chunk per
    // committed quotient chunk (each `Challenge::DIMENSION = 2` elements wide), random (2), and the
    // permutation openings at both points (`aux_width = num_lookups + 1`, 2 elements each).
    let mut opened = 0usize;
    let mut random = 0usize;
    for i in 0..n {
        let w = shape.widths[i];
        let pre = shape.preprocessed_widths[i];
        let chunks = (1usize << shape.log_num_quotient_chunks[i]) << 1;
        let aux = if shape.num_lookups[i] > 0 { shape.num_lookups[i] + 1 } else { 0 };
        opened += w
            + if shape.main_next[i] { w } else { 0 }
            + pre
            + if shape.pre_next[i] { pre } else { 0 }
            + chunks * 2
            + 2
            + 2 * aux * 2;
        // The hiding wrapper's four hidden values per opened point, for every round but the
        // preprocessed one: `random` (one point), `main` (one or two), each quotient chunk (one),
        // and `permutation` (two, only where there are lookups).
        random += 1 + (1 + shape.main_next[i] as usize) + chunks + if aux > 0 { 2 } else { 0 };
    }
    assert_eq!(seg(randprotocol_rvm::witness::Segment::OpenedValues), 2 * opened);
    assert_eq!(seg(randprotocol_rvm::witness::Segment::RandomOpenings), 2 * 4 * random);
}

/// `QueryBits` is 65 words per sampled element and nothing in phases 0–4 reads it, so without this
/// its bit order, its group order and its canonicality hint would go unchecked until Task 6 — and a
/// mistake in any of them is a tape the finished program cannot consume.
///
/// The claims are the ones the program's `sample_bits` makes: each group's sixty-four little-endian
/// bits are a decomposition of a canonical Goldilocks element, the hint is that element's low half
/// inverted, the low `log_global_max_height` bits are the query index the Merkle proofs were checked
/// against, and the PoW group comes first and grinds.
#[test]
fn the_query_bit_segment_decodes_to_the_sampled_query_indices() {
    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let (_, start, len) = *tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == randprotocol_rvm::witness::Segment::QueryBits)
        .unwrap();
    // One group per query, plus one for the query proof-of-work check (4 bits at this profile).
    assert_eq!(shape.query_pow_bits, 4);
    assert_eq!(len, 65 * (shape.num_queries + 1));

    let group = |g: usize| -> (u64, F) {
        let at = start + 65 * g;
        let mut v = 0u64;
        for k in (0..64).rev() {
            let bit = tape.words[at + k];
            assert!(bit == F::ZERO || bit == F::ONE, "group {g} bit {k} is not boolean");
            v = (v << 1) | (bit == F::ONE) as u64;
        }
        (v, tape.words[at + 64])
    };
    let canonical = |v: u64| {
        // `p = 2^64 - 2^32 + 1`: the elements with a second 64-bit decomposition are exactly those
        // with the high half all ones and a non-zero low half.
        !(v >> 32 == 0xFFFF_FFFF && v & 0xFFFF_FFFF != 0)
    };

    let (pow, hint) = group(0);
    assert!(canonical(pow));
    assert_eq!(hint, randprotocol_rvm::dsl::transcript::canonicality_hint(pow));
    assert_eq!(pow & ((1 << shape.query_pow_bits) - 1), 0, "the query PoW witness must grind");

    for q in 0..shape.num_queries {
        let (v, hint) = group(q + 1);
        assert!(canonical(v), "query {q}");
        assert_eq!(hint, randprotocol_rvm::dsl::transcript::canonicality_hint(v), "query {q}");
        let mask = (1u64 << r.log_global_max_height) - 1;
        assert_eq!(
            (v & mask) as usize, r.indices[q],
            "query {q}'s low bits are the index its Merkle proof was checked against"
        );
    }
}

/// The four query-major segments carry exactly the words the round geometry implies: per query, per
/// round, per matrix a full opened row plus four salts, and four words per Merkle level. Nothing in
/// phases 0–4 reads them either, and an off-by-one here is a tape Task 6's program walks off the end
/// of — so the lengths are pinned against the geometry the *replay* derived from `open_inputs`' own
/// rule.
#[test]
fn the_query_segments_are_sized_by_the_round_geometry() {
    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let seg = |s: randprotocol_rvm::witness::Segment| {
        tape.segments.iter().find(|(x, _, _)| *x == s).unwrap().2
    };
    use randprotocol_rvm::dsl::DIGEST_ELEMS;
    use randprotocol_rvm::witness::{open_stride, path_stride, per_query_levels, per_query_rows, Segment};

    // `coms_to_verify`' five rounds: random, main, quotient_chunks, preprocessed, permutation.
    assert_eq!(r.input_rounds.len(), 5);
    let rows = per_query_rows(&r.input_rounds);
    let levels = per_query_levels(&r.input_rounds);
    assert_eq!(seg(Segment::InputOpenings), shape.num_queries * rows);
    assert_eq!(seg(Segment::InputPaths), shape.num_queries * levels * DIGEST_ELEMS);

    // The commit phase: `arity − 1` extension siblings (two words each) plus the four salts of the
    // query's own row, and one path per round.
    assert_eq!(
        seg(Segment::CommitPhaseOpenings),
        shape.num_queries * open_stride(&r.log_arities)
    );
    assert_eq!(
        seg(Segment::CommitPhasePaths),
        shape.num_queries * path_stride(r.log_global_max_height, &r.log_arities)
    );
}

/// The strongest claim about the tape this task can make: the `CommitPhaseOpenings` and
/// `CommitPhasePaths` words really are a *single-path-per-query* witness for the round's
/// commitment — hash the leaf the tape describes, walk the path the tape carries, and the digest
/// reached is the cap entry the proof committed to.
///
/// This is what the plan's ruling on `restore_and_recompute_paths` asserts and nothing else here
/// checks: the two size tests would pass just as happily with the rounds and the queries nested the
/// other way round, or with the salts in the wrong place. The commit phase is the case to do it on
/// because each round commits exactly *one* matrix, so there are no shorter-height groups to inject
/// and the walk is `merkle_walk`'s plain form.
///
/// The gadgets are `crate::dsl::hash`'s, already differential against `p3-symmetric` and
/// `p3-merkle-tree` in `tests/transcript.rs`; what is under test is the tape's layout.
#[test]
fn a_commit_phase_leaf_and_its_restored_path_recompute_the_rounds_commitment() {
    use p3_field::BasedVectorSpace;
    use randprotocol_rvm::dsl::{hash, Builder, Digest, Felt};
    use randprotocol_rvm::isa::EF;

    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let at = |s: randprotocol_rvm::witness::Segment| {
        tape.segments.iter().find(|(x, _, _)| *x == s).unwrap().1
    };
    let opens = at(randprotocol_rvm::witness::Segment::CommitPhaseOpenings);
    let paths = at(randprotocol_rvm::witness::Segment::CommitPhasePaths);
    let fri = &p.proof.batch.opening_proof.1;

    // Round 0: the tallest commit-phase tree, and the first round of every query's stride.
    let log_arity = r.log_arities[0];
    let arity = 1usize << log_arity;
    let levels = (r.log_global_max_height - log_arity) - randprotocol_rvm::shape::CAP_HEIGHT;
    let open_stride = randprotocol_rvm::witness::open_stride(&r.log_arities);
    let path_stride = randprotocol_rvm::witness::path_stride(r.log_global_max_height, &r.log_arities);

    let mut b = Builder::new(Checkpoints::Off);
    let mut want: Vec<F> = Vec::new();
    for q in 0..shape.num_queries {
        // The leaf: `ExtensionMmcs` flattens the arity-wide row to base, then the hiding MMCS
        // appends the four salts the tape carries right after this round's siblings.
        let row: Vec<EF> = r.commit_rows[0][q][0].clone();
        assert_eq!(row.len(), arity);
        let mut msg: Vec<F> = <EF as BasedVectorSpace<F>>::flatten_to_base(row);
        let salt_at = opens + q * open_stride + (arity - 1) * <EF as BasedVectorSpace<F>>::DIMENSION;
        msg.extend_from_slice(&tape.words[salt_at..salt_at + randprotocol_rvm::witness::SALT_ELEMS]);

        let src = b.alloc(msg.len() as u64);
        for (i, v) in msg.iter().enumerate() {
            let c = b.constant(*v);
            b.store(src, i as i64, c);
        }
        let leaf = Digest(b.alloc(4));
        hash::sponge(&mut b, src, msg.len(), leaf);

        let sib_at = paths + q * path_stride;
        let sibs = b.alloc(4 * levels as u64);
        for i in 0..4 * levels {
            let c = b.constant(tape.words[sib_at + i]);
            b.store(sibs, i as i64, c);
        }
        let index = r.commit_group_indices[0][q];
        let bits: Vec<Felt> = (0..levels)
            .map(|k| b.constant(F::from_u64(((index >> k) & 1) as u64)))
            .collect();
        let root = Digest(b.alloc(4));
        hash::merkle_walk(&mut b, leaf, &bits, sibs, levels, root);
        for i in 0..4 {
            let v = b.load(root.0, i);
            b.public(v);
        }
        want.extend_from_slice(&fri.commit_phase_commits[0].roots()[index >> levels]);
    }
    let exec = execute(&b.finish(), &[], 100_000_000).expect("the walk runs");
    assert_eq!(exec.public, want, "round 0's restored paths must reach its committed cap");
}

/// The same claim for an *input* round, which is where it is hardest: an input round commits
/// matrices of several heights, so the walk carries a shorter-height group injected partway up
/// (`p3-merkle-tree-0.7.0/src/mmcs/batch.rs:240-262`).
///
/// The preprocessed round is the one to do it on: three matrices, two heights, exactly one
/// injection — and its commitment is the [`InnerKey`] the program carries as a constant, so this
/// also checks that the key really is the cap the proof was built against.
#[test]
fn an_input_rounds_leaf_group_and_restored_path_recompute_the_preprocessed_cap() {
    use randprotocol_rvm::dsl::{hash, Builder, Digest, Felt};
    use randprotocol_rvm::witness::levels_for;

    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let opens = tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == randprotocol_rvm::witness::Segment::InputOpenings)
        .unwrap()
        .1;
    let paths = tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == randprotocol_rvm::witness::Segment::InputPaths)
        .unwrap()
        .1;

    // `coms_to_verify`' round order: random, main, quotient_chunks, preprocessed, permutation.
    const PRE: usize = 3;
    let dims = &r.input_rounds[PRE].dims;
    assert_eq!(dims.len(), shape.preprocessed_matrix_to_instance.len());
    let levels = levels_for(dims);

    // Group the matrices the way the leaf hash does: tallest first, everything whose padded height
    // equals the tallest's in the leaf, the rest injected at the level the walk reaches their height
    // at. `sorted_by_key(Reverse(height))` is stable, so matrices of equal height keep dims order —
    // which is the order their rows sit in on the tape.
    let tallest = dims.iter().map(|d| d.height).max().unwrap();
    let words_of = |m: usize| dims[m].width + randprotocol_rvm::witness::SALT_ELEMS;
    let offset_in_round = |m: usize| (0..m).map(words_of).sum::<usize>();
    let leaf_group: Vec<usize> = (0..dims.len()).filter(|&m| dims[m].height == tallest).collect();
    let short: Vec<usize> = (0..dims.len()).filter(|&m| dims[m].height != tallest).collect();
    assert_eq!(leaf_group.len(), 1, "the preprocessed round's tallest matrix is the poseidon2 table");
    assert_eq!(short.len(), 2, "range and nibble share the shorter height");
    let short_height = dims[short[0]].height;
    assert!(short.iter().all(|&m| dims[m].height == short_height));
    // `curr` is the layer width; after level `k` it is `tallest >> (k + 1)`.
    let after_level = (tallest.trailing_zeros() - short_height.trailing_zeros() - 1) as usize;
    // The two short matrices are adjacent in dims order, so their rows are one contiguous run.
    assert_eq!(short, vec![0, 1]);
    let short_cells: usize = short.iter().map(|&m| words_of(m)).sum();

    use randprotocol_rvm::dsl::DIGEST_ELEMS;
    use randprotocol_rvm::witness::{per_query_levels, per_query_rows};
    let round_at =
        |q: usize| opens + q * per_query_rows(&r.input_rounds) + per_query_rows(&r.input_rounds[..PRE]);
    let path_at = |q: usize| {
        paths
            + (q * per_query_levels(&r.input_rounds) + per_query_levels(&r.input_rounds[..PRE]))
                * DIGEST_ELEMS
    };

    let mut b = Builder::new(Checkpoints::Off);
    let mut want: Vec<F> = Vec::new();
    for q in 0..shape.num_queries {
        let base = round_at(q);
        let tall = base + offset_in_round(leaf_group[0]);
        let leaf_words = words_of(leaf_group[0]);
        let src = b.alloc(leaf_words as u64);
        for i in 0..leaf_words {
            let c = b.constant(tape.words[tall + i]);
            b.store(src, i as i64, c);
        }
        let leaf = Digest(b.alloc(4));
        hash::sponge(&mut b, src, leaf_words, leaf);

        let rows = b.alloc(short_cells as u64);
        for i in 0..short_cells {
            let c = b.constant(tape.words[base + i]);
            b.store(rows, i as i64, c);
        }
        let sibs = b.alloc(4 * levels as u64);
        for i in 0..4 * levels {
            let c = b.constant(tape.words[path_at(q) + i]);
            b.store(sibs, i as i64, c);
        }
        let index = r.input_rounds[PRE].indices[q];
        let bits: Vec<Felt> = (0..levels)
            .map(|k| b.constant(F::from_u64(((index >> k) & 1) as u64)))
            .collect();
        let root = Digest(b.alloc(4));
        hash::merkle_walk_with_injections(
            &mut b,
            leaf,
            &bits,
            sibs,
            levels,
            &[hash::Injection { after_level, rows, n_cells: short_cells }],
            root,
        );
        for i in 0..4 {
            let v = b.load(root.0, i);
            b.public(v);
        }
        want.extend_from_slice(&key.cap[index >> levels]);
    }
    let exec = execute(&b.finish(), &[], 100_000_000).expect("the walk runs");
    assert_eq!(exec.public, want, "the preprocessed round's paths must reach the key's cap");
}

/// A proof of a *different* shape is refused at the header word that differs, before anything is
/// sized from it. Every word of the header is pinned, so the test walks all of them.
#[test]
fn a_header_word_that_disagrees_with_the_programs_shape_is_refused_at_that_word() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let (_, start, len) = *tape.segments.iter().find(|(s, _, _)| *s == randprotocol_rvm::witness::Segment::Header).unwrap();
    assert_eq!(len, shape.header_words().len());
    for k in 0..len {
        let mut t = tape.clone();
        t.words[start + k] += F::ONE;
        match execute(&vp.program, &t.words, 100_000_000) {
            Err(ExecError::InverseOfZero { pc }) => assert_eq!(
                vp.program.checkpoint_at(pc),
                Some(format!("header word {k}").as_str()),
                "header word {k}"
            ),
            other => panic!("header word {k}: expected a refusal, got {other:?}"),
        }
    }
}

#[test]
fn a_tampered_main_commitment_diverges_at_the_zeta_checkpoint() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::On);
    let mut tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let (_, start, _) = *tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == randprotocol_rvm::witness::Segment::Commitments)
        .unwrap();
    tape.words[start] += F::ONE; // one lane of the main cap
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, 100_000_000);
    match exec {
        Ok(e) => {
            // The transcript is bound: a tampered commitment must move every challenge drawn
            // after it, `zeta` included.
            let cp = randprotocol_rvm::programs::checkpoint_values(&vp, &e);
            assert_ne!(cp["zeta"], r.zeta, "a tampered commitment must move zeta");
            assert_ne!(cp["alpha"], r.alpha);
            assert_ne!(cp["lookup_alpha"], r.lookup_alpha);
            // It must also *fail an assertion* — but nothing this task builds depends on zeta
            // yet: phases 0–4 assert only the declared shape and the cross-AIR terminal sum,
            // neither of which a commitment word touches. The refusal is asserted where the
            // step that does the work lives, in Task 6's `tests/exit.rs` tamper table
            // (`Segment::Commitments` -> `"input opening root[main]"`).
        }
        Err(ExecError::InverseOfZero { pc }) => {
            let name = vp.program.checkpoint_at(pc).expect("every trap is named");
            println!("refused at {name}");
        }
        Err(other) => panic!("unexpected failure {other:?}"),
    }
}


/// Phase 5, against the very folder `p3-batch-stark` runs: the emitted DAG must fold to the *same*
/// accumulator, not merely to something that satisfies the same identity.
///
/// This is the strongest form the claim has. Comparing only acceptance would pass with the
/// constraints folded in the wrong order, with a shared sub-expression emitted twice with different
/// operands, or with `alpha` applied one step out of phase — every one of which is a program that
/// accepts this proof and rejects the next. So the checkpoints are the accumulator itself, the
/// recomposed quotient, and all four Lagrange selectors, per instance.
#[test]
fn the_emitted_constraint_evaluation_equals_the_native_folded_accumulator_on_every_instance() {
    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let vp = verify_rv32(&shape, &key, Checkpoints::On);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, 200_000_000).unwrap();
    let cp = randprotocol_rvm::programs::checkpoint_values(&vp, &exec);
    for i in 0..shape.degree_bits.len() {
        assert_eq!(
            cp[&format!("accumulator[{i}]")], r.accumulators[i],
            "instance {i}: the emitted DAG must fold exactly as p3-batch-stark folds"
        );
        assert_eq!(cp[&format!("quotient[{i}]")], r.quotients[i], "instance {i}: quotient(zeta)");
        assert_eq!(
            cp[&format!("selectors[{i}].is_first_row")], r.selectors[i].is_first_row,
            "instance {i}: is_first_row"
        );
        assert_eq!(
            cp[&format!("selectors[{i}].is_last_row")], r.selectors[i].is_last_row,
            "instance {i}: is_last_row"
        );
        assert_eq!(
            cp[&format!("selectors[{i}].is_transition")], r.selectors[i].is_transition,
            "instance {i}: is_transition"
        );
        assert_eq!(
            cp[&format!("selectors[{i}].inv_vanishing")], r.selectors[i].inv_vanishing,
            "instance {i}: 1/Z_H(zeta)"
        );
    }
}

/// The per-lookup challenge pairs the program derives from the two sampled elements must be
/// `BatchTranscript::sample_perm_challenges`' own layout — `[prefix[bus_0], beta, prefix[bus_1],
/// beta, …]` per instance, with the bus ids assigned as that function assigns them.
///
/// The emitter has to reproduce the bus assignment host-side, because `sample_perm_challenges`
/// returns the challenge *values* and not the map. That makes it the one place in this file where a
/// second implementation of p3 logic exists — so it is compared against the real function's output,
/// element for element, rather than against a restatement of the rule.
#[test]
fn the_emitted_lookup_challenges_are_sample_perm_challenges_own_layout() {
    let (p, shape, key) = one_test_proof();
    let r = replay(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let vp = verify_rv32(&shape, &key, Checkpoints::On);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, 200_000_000).unwrap();
    let cp = randprotocol_rvm::programs::checkpoint_values(&vp, &exec);
    assert!(
        r.challenges.iter().any(|c| !c.is_empty()),
        "p3 squeezes the lookup pair only when some instance has lookups"
    );
    for (i, want) in r.challenges.iter().enumerate() {
        assert_eq!(want.len(), 2 * shape.num_lookups[i], "instance {i}: one pair per lookup");
        for (k, w) in want.iter().enumerate() {
            assert_eq!(cp[&format!("challenges[{i}][{k}]")], *w, "instance {i} challenge {k}");
        }
    }
}

/// The identity itself, in the shipped (`Checkpoints::Off`) build: reaching `HALT` on a real proof
/// *is* the claim, because every instance's `accumulator · inv_vanishing == quotient` is asserted
/// along the way and a failure is a trap.
#[test]
fn the_quotient_identity_holds_in_the_program_for_a_real_proof() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, 200_000_000).expect("accepts a real proof");
    // R5: exactly the four-element interface digest (the §4.4 list, hashed in-circuit — the
    // in-circuit seeded sponge and the host's `public_digest` are pinned to each other here).
    let words = randprotocol_rvm::public_values::interface_words(&shape, &key, &[p.proof.public_values.clone()]);
    assert_eq!(exec.public, randprotocol_rvm::public_values::public_digest(&words).to_vec(),
               "the interface digest, exactly");
    // And it got there by reading the *whole* tape, not by stopping short of it: without that this
    // test would pass on a program with no query phase at all.
    assert_eq!(exec.hints_read, tape.len());
}

/// One word of one opened value moved, and the quotient identity of *that instance* fails — at the
/// checkpoint named for it, not somewhere downstream.
#[test]
fn a_tampered_opened_value_fails_the_quotient_identity_at_the_named_checkpoint() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let mut tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let (_, start, _) = *tape
        .segments
        .iter()
        .find(|(s, _, _)| *s == randprotocol_rvm::witness::Segment::OpenedValues)
        .unwrap();
    tape.words[start] += F::ONE; // instance 0's first opened trace value
    match execute(&vp.program, &tape.words, 200_000_000) {
        Err(ExecError::InverseOfZero { pc }) => {
            assert_eq!(vp.program.checkpoint_at(pc), Some("quotient identity[0]"));
        }
        other => panic!("expected the quotient identity to fail, got {other:?}"),
    }
}

/// The milestone's exit is a *measured* number, so phase 5's cost is pinned rather than described:
/// the per-instance instruction counts the build reports, and the whole program's cpu rows and
/// Poseidon2 permutations from the emulator's own event log.
///
/// The bound is the one the plan's decision point is written against — `2^19 = 524 288` cpu rows for
/// the *whole* inner proof, phases 6–8 included — so phase 5 crossing a fifth of it would be the
/// signal that Task 7's precompiles are needed. It is asserted, not merely printed, because a
/// constraint-set change that doubles the cpu table's DAG has to show up as a red test and not as a
/// number nobody read.
#[test]
fn phase_5_costs_the_measured_number_of_rows_per_inner_proof() {
    let (p, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let exec = execute(&vp.program, &tape.words, 200_000_000).expect("the program accepts");

    let mut table = String::from(
        "phase 5, per instance: width  lookups  base+ext constraints  nodes(+hits)  \
         leaves(+hits)  instrs\n",
    );
    for (i, c) in vp.phase5.iter().enumerate() {
        table += &format!(
            "  [{i}] w={:<4} l={:<3} {:>5}+{:<4} {:>6}(+{:<6}) {:>5}(+{:<6}) {:>7}\n",
            shape.widths[i],
            shape.num_lookups[i],
            c.base_constraints,
            c.ext_constraints,
            c.nodes,
            c.node_hits,
            c.leaves,
            c.leaf_hits,
            c.instrs
        );
    }
    let sum = |f: fn(&randprotocol_rvm::programs::constraints::Phase5Cost) -> usize| -> usize {
        vp.phase5.iter().map(f).sum()
    };
    let phase5_instrs = sum(|c| c.instrs);
    table += &format!(
        "  total: {} constraints, {} nodes (+{} shared), {} leaves (+{} shared), {} instrs\n",
        sum(|c| c.base_constraints) + sum(|c| c.ext_constraints),
        sum(|c| c.nodes),
        sum(|c| c.node_hits),
        sum(|c| c.leaves),
        sum(|c| c.leaf_hits),
        phase5_instrs,
    );
    table += &format!(
        "  program: {} instrs, {} cpu rows, {} permutations, {} memory accesses, {} tape words read\n",
        vp.stats.instrs,
        exec.cpu_rows(),
        exec.permutations(),
        exec.mem_accesses(),
        exec.hints_read,
    );
    println!("{table}");

    // The program is straight-line — nothing in phases 0–5 is a `counted_loop` — so every
    // instruction runs at most once, and the ones that do not are exactly the assertion traps their
    // own `JEQ` jumped over.
    assert!(
        exec.cpu_rows() <= vp.stats.instrs,
        "a straight-line program cannot run more rows than it has instructions"
    );
    assert!(
        phase5_instrs < 100_000,
        "phase 5 costs {phase5_instrs} rows per inner proof, past the 100 000 the milestone's \
         budget allots it out of 2^19"
    );
    // Hashing: phases 0–4 cost the challenger's 51 duplexes and phase 5 hashes nothing; the rest
    // is the query phase — the FRI transcript's duplexes, the five input rounds' leaf sponges,
    // walks and injections, and the commit-phase rows and walks — plus phase 8's interface
    // digest (R5): a 39-word seeded sponge, `ceil(39/4)` = 10 permutations. Pinned at the
    // measured Test-profile number (constraint set 6's shape); the production one lives in
    // `docs/00-recursion-vm.md` and `pins.json`.
    assert_eq!(exec.permutations(), 11_205, "51 transcript duplexes in phases 0–4, the rest is the query phase and phase 8's digest");
}

/// Every assertion phase 5 makes is a *named* checkpoint, and the names are the interface Task 6's
/// tamper table indexes by — so they are pinned here rather than left to whatever the code happens to
/// spell.
///
/// The `OodPointInDomain` check (`Z_H(zeta) != 0`) is the reason this test exists at all. It cannot
/// be reached by tampering — `zeta` comes out of the transcript, and no tape word puts it inside a
/// trace domain — so nothing else in this file would notice if its name were dropped and the check
/// became an anonymous `EINV`. Dropping the quotient identity's own assertions fails here too.
#[test]
fn phase_5s_assertions_are_all_named() {
    let (_, shape, key) = one_test_proof();
    let vp = verify_rv32(&shape, &key, Checkpoints::Off);
    let names: std::collections::BTreeSet<&str> =
        vp.program.checkpoints.iter().map(|(_, n)| n.as_str()).collect();
    for i in 0..shape.instances() {
        assert!(
            names.contains(format!("quotient identity[{i}]").as_str()),
            "instance {i}'s quotient identity is unnamed"
        );
        assert!(
            names.contains(format!("zeta is inside instance {i}'s trace domain").as_str()),
            "instance {i}'s OodPointInDomain check is unnamed"
        );
    }
    // The `Off` build records the same checkpoint *names* as the `On` build, which is what makes the
    // two comparable — and what `checkpoint_values` reads the `On` build's public values back with.
    let on = verify_rv32(&shape, &key, Checkpoints::On);
    assert_eq!(vp.checkpoint_names, on.checkpoint_names);
    assert!(vp.checkpoint_names.contains(&format!("accumulator[{}]", shape.instances() - 1)));
    // And the trap table stays pc-sorted, which is what `checkpoint_at`'s binary search needs.
    assert!(vp.program.checkpoints.windows(2).all(|w| w[0].0 < w[1].0));
}

/// Task 7's two allocator policies: the `Off` replay reproduces the pre-liveness program byte
/// for byte, and the two builds accept the same proofs with the same public values. The
/// hardcoded digest is the production shape's pre-Task-7 program digest (the value committed
/// before the liveness rework — after this task re-records, `src/programs/verify_rv32.digest`
/// carries the On build's own, different, digest).
#[test]
fn the_off_replay_reproduces_the_pre_liveness_program_byte_for_byte() {
    use randprotocol_rvm::dsl::Liveness;
    use randprotocol_rvm::programs::verify_rv32_with;

    let p = common::bundle_proofs(FriProfile::Production, 1).pop().unwrap();
    let shape = InnerShape::of(
        FriProfile::Production,
        p.proof.tier, p.proof.program_log_height, p.proof.input_log_height, p.proof.keccak_log_height,
        p.proof.sha256_log_height, p.proof.public_log_height, p.proof.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Production, &shape);
    let off = verify_rv32_with(&shape, &key, Checkpoints::Off, Liveness::Off, randprotocol_rvm::programs::Precompiles::Off);
    assert_eq!(
        randprotocol_rvm::programs::digest_hex(&off.program),
        "c1c04ac3a9faf266eb8980260dae6c7f12fe9ee4cf3dfa40de8440182258d731",
        "the Off replay must reproduce the pre-Task-7 stream byte for byte"
    );

    let on = verify_rv32_with(&shape, &key, Checkpoints::Off, Liveness::On, randprotocol_rvm::programs::Precompiles::On);
    assert_ne!(off.program.digest(), on.program.digest(), "liveness changes the schedule");

    // The acceptance differential: both builds accept a real proof with identical public values.
    let tape = WitnessTape::build(FriProfile::Production, &shape, &key, &p.proof).unwrap();
    let got_off = execute(&off.program, &tape.words, 200_000_000).unwrap().public;
    let got_on = execute(&on.program, &tape.words, 200_000_000).unwrap().public;
    assert_eq!(got_off, got_on);
    assert_eq!(got_on.len(), 4, "the interface digest, from both builds");
}
