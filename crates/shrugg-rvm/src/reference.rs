//! The host-side replay of the transcript the verifier program reproduces, with every intermediate
//! exposed.
//!
//! **Nothing here is a second implementation of anything.** Every step runs the very code
//! `shrugg_zkvm::machine::verify` runs: `p3_batch_stark::BatchTranscript` for the eight observe/sample
//! steps, `p3_batch_stark::verifier::commitments_with_opening_points` for the opening argument,
//! `p3_uni_stark::recompose_quotient_from_chunks` and `p3_uni_stark`'s own
//! `VerifierConstraintFolder` (through `p3_lookup`'s `eval_air_and_lookups`) for the per-instance
//! accumulator, and `p3_fri::verifier::{open_inputs, fold_query}` plus the MMCS's own
//! `verify_multi_batch` for the query phase. The three things it *does* spell out —
//! `HidingFriPcs::verify`'s re-merge of the hidden halves, `TwoAdicFriPcs::verify`'s observation of
//! the claimed evaluations, and `verify_fri`'s own transcript sequence — are spelled out only because
//! they are unreachable through the public `Pcs::verify` (which exposes no intermediates), and each
//! is a transcription of the lines cited above it.
//!
//! A replay that accepts is therefore evidence in both directions: `tests/verifier.rs` asserts that
//! `Machine::verify` accepts the same proof, and that the accumulator/quotient identity it reports
//! is the one the native verifier checked.

use crate::isa::EF;
use crate::shape::{
    ProofBatch, ShapeKey, VerifierShape, CAP_HEIGHT, LOG_BLOWUP, LOG_FINAL_POLY_LEN, MAX_LOG_ARITY,
};
use p3_air::BaseAir;
use p3_batch_stark::BatchTranscript;
use p3_batch_stark::verifier::commitments_with_opening_points;
use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger};
use p3_commit::{ExtensionMmcs, LagrangeSelectors, Mmcs, PolynomialSpace};
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, HornerIter, PrimeCharacteristicRing, PrimeField64,
    TwoAdicField,
};
use p3_fri::verifier::{fold_query, open_inputs};
use p3_fri::{FriParameters, TwoAdicFriFolding};
use p3_lookup::logup::LogUpGadget;
use p3_lookup::LookupProtocol;
use p3_matrix::dense::RowMajorMatrixView;
use p3_matrix::stack::VerticalPair;
use p3_matrix::Dimensions;
use p3_uni_stark::{recompose_quotient_from_chunks, StarkGenericConfig, VerifierConstraintFolder};
use p3_util::{log2_strict_usize, reverse_bits_len};
use shrugg_zkvm::machine::{Challenge, Config, FriProfile, Val, ValMmcs};
use std::marker::PhantomData;

/// The commit-phase MMCS: `research`'s `ChallengeMmcs`, which is private there and therefore
/// re-spelled here from its two public halves.
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
/// The FRI folding strategy `TwoAdicFriPcs::verify` instantiates.
type Folding = TwoAdicFriFolding<
    Vec<p3_fri::BatchMultiOpening<Val, ValMmcs>>,
    <ValMmcs as Mmcs<Val>>::Error,
>;

/// A committed input round's geometry, as `open_inputs` and the hiding MMCS see it: the *unsalted*
/// dimensions (the hiding wrapper widens each by four) and, per query, the index already shifted
/// down by `log_global_max_height − log_height`.
///
/// Not part of the transcript; it is what [`crate::witness`] needs in order to expand each round's
/// pruned multiproof into one full authentication path per query.
#[derive(Clone, Debug)]
pub struct InputRound {
    pub dims: Vec<Dimensions>,
    pub indices: Vec<usize>,
}

/// Every value the program's phases are checked against.
///
/// No `Clone`: `p3_commit::LagrangeSelectors` derives only `Debug`, and a replay is cheap enough to
/// recompute that wrapping it would buy nothing.
#[derive(Debug)]
pub struct Replay {
    pub lookup_alpha: EF,
    pub lookup_beta: EF,
    /// Per instance, `BatchTranscript::sample_perm_challenges`' own layout: one
    /// `(bus_prefix, beta)` pair per declared lookup, flattened. Reported because the program has to
    /// re-derive the bus assignment from the shape's lookup contexts — `sample_perm_challenges`
    /// returns the values and not the map — and that derivation is checked against *these*.
    pub challenges: Vec<Vec<EF>>,
    pub alpha: EF,
    pub zeta: EF,
    pub fri_alpha: EF,
    pub betas: Vec<EF>,
    pub indices: Vec<usize>,
    pub log_global_max_height: usize,
    pub log_arities: Vec<usize>,
    /// Per instance, `quotient(zeta)` recomposed from the chunks.
    pub quotients: Vec<EF>,
    /// Per instance, the folded constraint accumulator — `alpha`-folded in
    /// `get_symbolic_constraints`' order, base constraints before extension ones.
    pub accumulators: Vec<EF>,
    /// Per instance, from `PolynomialSpace::selectors_at_point(zeta)`.
    pub selectors: Vec<LagrangeSelectors<EF>>,
    /// Per query, after the last fold.
    pub folded_evals: Vec<EF>,
    /// The canonical `u64` of the element `sample_bits` drew for each query index, in sampling
    /// order — not the masked index, the whole element. [`crate::witness`] needs all sixty-four
    /// bits of it, because the program's `sample_bits` is a full decomposition with a canonicality
    /// check (the plan's ruling: a `lo + 2^bits·hi` split with only `lo` range-checked would let a
    /// prover choose its own query indices).
    pub index_samples: Vec<u64>,
    /// The same, for the query proof-of-work check — `None` when `query_pow_bits == 0`, because
    /// `check_witness` then neither observes the witness nor samples anything
    /// (`grinding_challenger.rs:44-49`).
    pub pow_sample: Option<u64>,
    /// Per input round, the geometry [`crate::witness`] restores paths with.
    pub input_rounds: Vec<InputRound>,
    /// Per commit-phase round, per query: the group index the fold lands on.
    pub commit_group_indices: Vec<Vec<usize>>,
    /// Per commit-phase round, per query, per matrix (there is exactly one): the reconstructed
    /// arity-wide evaluation row, which is the leaf the round's tree commits to.
    pub commit_rows: Vec<Vec<Vec<Vec<EF>>>>,
}

/// Why the replay refused a proof. Every variant means `Machine::verify` refuses it too.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ReplayError {
    /// The proof's declared shape is not the one this program was built for.
    Shape,
    /// The machine's preprocessed cap at this shape is not the key that was handed in.
    Key,
    /// One of the ZK commitments the config requires is absent.
    Randomization,
    /// `commitments_with_opening_points` refused the opening argument's shape.
    OpeningArgument(String),
    /// `accumulator · inv_vanishing != quotient` for this instance.
    Constraints(usize),
    /// `zeta` landed inside a trace domain, where `inv_vanishing` does not exist.
    OodPointInDomain(usize),
    /// A proof-supplied `log_arity` is outside `1..=max_log_arity`.
    LogArity(usize),
    /// The two derivations of `log_global_max_height` disagree.
    GlobalMaxHeight { expected: usize, got: usize },
    /// A grinding witness does not grind.
    PowWitness(&'static str),
    /// The final polynomial is not `final_poly_len()` coefficients long.
    FinalPolyLength,
    /// `open_inputs` refused an input round (a Merkle check, or a claimed-evaluation shape).
    InputOpenings(String),
    /// `fold_query` refused a query's fold chain.
    Fold(String),
    /// `final_poly(x) != folded_eval` for this query.
    FinalPoly(usize),
    /// A commit-phase round's reconstructed rows do not match its commitment.
    CommitPhase(usize),
}

/// The one thing `commitments_with_opening_points` still needs a live AIR for: whether the
/// instance's constraints read the next row of the main / preprocessed trace, plus the widths and
/// public-value count its shape checks compare against.
///
/// The same stand-in the spike used. It exists because the real `Chip` AIRs would work too but would
/// tie the replay to `chips()`' order twice over; everything here comes off the [`InnerShape`],
/// which is the thing the program is specialised to.
struct ShapeAir {
    width: usize,
    main_next: bool,
    pre_next: bool,
    npv: usize,
}

impl BaseAir<Val> for ShapeAir {
    fn width(&self) -> usize {
        self.width
    }
    fn num_public_values(&self) -> usize {
        self.npv
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        if self.main_next {
            vec![0]
        } else {
            Vec::new()
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        if self.pre_next {
            vec![0]
        } else {
            Vec::new()
        }
    }
}

/// `research`'s `FriParameters`, rebuilt: the `Config`'s PCS owns the only copy and keeps it private.
fn fri_params<S: VerifierShape>(shape: &S, val_mmcs: &ValMmcs) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY,
        num_queries: shape.num_queries(),
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: shape.query_pow_bits(),
        mmcs: ChallengeMmcs::new(val_mmcs.clone()),
    }
}

/// Replays `verify_batch` on `proof`, reporting every intermediate the program is compared against.
///
/// Generic over [`VerifierShape`] (M5.4, T5): the RV32 machine's shape and the rVM's own
/// [`crate::shape::RvmShape`] replay through the same code — the machines share the field, the
/// challenger and the batch machinery (`crate::shape::machine`'s `Config` is the same type on
/// both), and everything machine-specific comes in through the trait.
pub fn replay<S: VerifierShape>(
    profile: FriProfile,
    shape: &S,
    key: &S::Key,
    proof: &S::Proof,
) -> Result<Replay, ReplayError>
where
    S::Air: BaseAir<Val> + for<'a> p3_air::Air<p3_lookup::folder::VerifierConstraintFolderWithLookups<'a, Config>>,
{
    if !shape.matches(proof) {
        return Err(ReplayError::Shape);
    }
    let machine = crate::shape::machine(profile);
    let cfg = &machine.config;
    let is_zk = cfg.is_zk();
    let common = shape.common_data();
    let global = common.preprocessed.as_ref().ok_or(ReplayError::Key)?;
    if global.commitment.roots() != key.cap().as_slice() {
        return Err(ReplayError::Key);
    }

    let batch = proof.batch();
    let commitments = &batch.commitments;
    if commitments.permutation.is_none() || commitments.random.is_none() {
        return Err(ReplayError::Randomization);
    }

    let n = shape.instances();
    let airs: Vec<ShapeAir> = (0..n)
        .map(|i| ShapeAir {
            width: shape.widths()[i],
            main_next: shape.main_next()[i],
            pre_next: shape.pre_next()[i],
            npv: shape.num_public_values()[i],
        })
        .collect();
    let pv_vals: Vec<Val> = proof.public_values_u64().iter().map(|x| Val::from_u64(*x)).collect();
    let pvs: Vec<Vec<Val>> = (0..n)
        .map(|i| if i == shape.pv_instance() { pv_vals.clone() } else { Vec::new() })
        .collect();

    // ── the eight transcript steps, `verify_batch`'s own helpers ────────────────────────────────
    let gadget = LogUpGadget::new();
    let mut transcript = BatchTranscript::<Config>::new(cfg.initialise_challenger());
    transcript.observe_instance_count(n);
    for i in 0..n {
        let ext_db = shape.degree_bits()[i];
        transcript.observe_instance_binding(
            ext_db,
            ext_db - is_zk,
            shape.widths()[i],
            (1usize << shape.log_num_quotient_chunks()[i]) << is_zk,
        );
    }
    transcript.observe_main(&commitments.main, &pvs);
    transcript.observe_preprocessed(&shape.preprocessed_widths(), Some(global));

    // `sample_perm_challenges` draws exactly the one `(alpha, beta)` pair and nothing else — every
    // bus offset it returns is arithmetic on that pair (`p3-batch-stark-0.7.0/src/transcript.rs`).
    // A clone taken here therefore reads the pair itself without touching the real transcript, and
    // the two end in identical states; the alternative would be to re-derive the bus assignment,
    // i.e. to reimplement the function this replay exists to *use*.
    let mut peek = transcript.challenger.clone();
    let lookup_alpha: EF = peek.sample_algebra_element();
    let lookup_beta: EF = peek.sample_algebra_element();
    let challenges_per_instance = transcript.sample_perm_challenges(&common.lookups, &gadget);

    let alpha =
        transcript.observe_perm_and_sample_alpha(commitments.permutation.as_ref(), &batch.lookup_terminals);
    transcript.observe_quotient_commitment(&commitments.quotient_chunks);
    transcript.observe_random_commitment(commitments.random.as_ref().unwrap());
    let zeta = transcript.sample_zeta();

    // ── the opening argument ────────────────────────────────────────────────────────────────────
    let (mut rounds, quotient_domains) = commitments_with_opening_points::<Config, ShapeAir>(
        cfg,
        &airs,
        zeta,
        commitments,
        &batch.opened_values,
        &common,
        &batch.degree_bits,
        shape.preprocessed_widths(),
        shape.log_num_quotient_chunks(),
    )
    .map_err(|e| ReplayError::OpeningArgument(format!("{e:?}")))?;

    // ── the per-instance constraint identity ────────────────────────────────────────────────────
    let mut quotients = Vec::with_capacity(n);
    let mut accumulators = Vec::with_capacity(n);
    let mut selectors = Vec::with_capacity(n);
    let real_airs = shape.constraint_chips();
    for i in 0..n {
        let trace_domain =
            crate::shape::natural_domain(cfg, 1usize << (shape.degree_bits()[i] - is_zk));
        if trace_domain.vanishing_poly_at_point(zeta).is_zero() {
            return Err(ReplayError::OodPointInDomain(i));
        }
        let inst = &batch.opened_values.instances[i];
        let base = &inst.base_opened_values;
        let quotient =
            recompose_quotient_from_chunks::<Config>(&quotient_domains[i], &base.quotient_chunks, zeta);
        let sels = trace_domain.selectors_at_point(zeta);

        // `VerifierData::verify_constraints_with_lookups`'s folder, field for field: its own struct
        // is `pub(crate)` in `p3-batch-stark`, so the folder it builds is built here instead — and
        // the constraints are then evaluated by `p3_lookup`'s own `eval_air_and_lookups` against
        // the shape's own `Chip` AIRs, not against anything restated.
        let trace_next_zeros;
        let trace_next: &[EF] = match &base.trace_next {
            Some(v) => v,
            None => {
                trace_next_zeros = EF::zero_vec(shape.widths()[i]);
                &trace_next_zeros
            }
        };
        let pre_next_zeros;
        let pre_next: &[EF] = match &base.preprocessed_next {
            Some(v) => v,
            None => {
                pre_next_zeros = EF::zero_vec(shape.preprocessed_widths()[i]);
                &pre_next_zeros
            }
        };
        let perm_local = recompose_ext(&inst.permutation_local, shape.num_lookups()[i]);
        let perm_next = recompose_ext(&inst.permutation_next, shape.num_lookups()[i]);
        let perm_vals: Vec<EF> = batch.lookup_terminals[i].iter().map(|t| t.0).collect();
        let periodic_columns = BaseAir::<Val>::periodic_columns(&real_airs[i]);
        let periodic_values: Vec<EF> =
            trace_domain.evaluate_periodic_columns_at(&periodic_columns, zeta);

        let main = VerticalPair::new(
            RowMajorMatrixView::new_row(&base.trace_local),
            RowMajorMatrixView::new_row(trace_next),
        );
        let preprocessed = VerticalPair::new(
            RowMajorMatrixView::new_row(base.preprocessed_local.as_deref().unwrap_or(&[])),
            RowMajorMatrixView::new_row(pre_next),
        );
        let preprocessed_window =
            p3_air::RowWindow::from_two_rows(preprocessed.top.values, preprocessed.bottom.values);
        let inner = VerifierConstraintFolder::<Config> {
            main,
            preprocessed,
            preprocessed_window,
            periodic_values: &periodic_values,
            public_values: &pvs[i],
            is_first_row: sels.is_first_row,
            is_last_row: sels.is_last_row,
            is_transition: sels.is_transition,
            alpha,
            accumulator: EF::ZERO,
        };
        let mut folder = p3_lookup::folder::VerifierConstraintFolderWithLookups::<Config> {
            inner,
            permutation: VerticalPair::new(
                RowMajorMatrixView::new_row(&perm_local),
                RowMajorMatrixView::new_row(&perm_next),
            ),
            permutation_challenges: &challenges_per_instance[i],
            permutation_values: &perm_vals,
        };
        gadget.eval_air_and_lookups(&real_airs[i], &mut folder, &common.lookups[i]);
        let accumulator = folder.inner.accumulator;
        if accumulator * sels.inv_vanishing != quotient {
            return Err(ReplayError::Constraints(i));
        }
        quotients.push(quotient);
        accumulators.push(accumulator);
        selectors.push(sels);
    }

    // ── `HidingFriPcs::verify`: re-join the hidden halves onto the public ones ───────────────────
    // `hiding_pcs.rs:365-441`. The shape checks it performs are the three length comparisons below.
    let (rand_openings, fri) = &batch.opening_proof;
    if rand_openings.len() != rounds.len() {
        return Err(ReplayError::OpeningArgument("hiding round count".into()));
    }
    for (round, rand_round) in rounds.iter_mut().zip(rand_openings.iter()) {
        if rand_round.len() != round.1.len() {
            return Err(ReplayError::OpeningArgument("hiding matrix count".into()));
        }
        for (mat, rand_mat) in round.1.iter_mut().zip(rand_round.iter()) {
            if rand_mat.len() != mat.1.len() {
                return Err(ReplayError::OpeningArgument("hiding point count".into()));
            }
            for (point, rand_point) in mat.1.iter_mut().zip(rand_mat.iter()) {
                point.1.extend(rand_point);
            }
        }
    }

    // ── `TwoAdicFriPcs::verify`: observe every claimed evaluation, then `verify_fri` ─────────────
    // `two_adic_pcs.rs:684-703`.
    let ch = &mut transcript.challenger;
    for (_, round) in &rounds {
        for (_, mat) in round {
            for (_, point) in mat {
                ch.observe_algebra_slice(point);
            }
        }
    }

    let val_mmcs = crate::shape::val_mmcs();
    let params = fri_params(shape, val_mmcs);

    // `verify_fri`, `p3-fri-0.7.0/src/verifier.rs:207-426`.
    let fri_alpha: EF = ch.sample_algebra_element();
    let log_arities: Vec<usize> = fri
        .commit_phase_openings
        .iter()
        .enumerate()
        .map(|(round, o)| o.checked_log_arity(MAX_LOG_ARITY).ok_or(ReplayError::LogArity(round)))
        .collect::<Result<_, _>>()?;
    let log_global_max_height =
        log_arities.iter().sum::<usize>() + LOG_BLOWUP + LOG_FINAL_POLY_LEN;
    let expected = rounds
        .iter()
        .flat_map(|(_, mats)| {
            mats.iter().map(|(domain, _)| log2_strict_usize(domain.size()) + LOG_BLOWUP)
        })
        .max()
        .expect("the batch opens at least one matrix");
    if log_global_max_height != expected {
        return Err(ReplayError::GlobalMaxHeight { expected, got: log_global_max_height });
    }

    let mut betas: Vec<EF> = Vec::with_capacity(log_arities.len());
    for (comm, witness) in fri.commit_phase_commits.iter().zip(&fri.commit_pow_witnesses) {
        ch.observe(comm.clone());
        // `commit_proof_of_work_bits == 0`, so `check_witness` returns `true` *without observing*
        // the witness (`grinding_challenger.rs:44-49`). The call is made anyway, because that
        // branch is the reference's and not an assumption about this config.
        if !ch.check_witness(params.commit_proof_of_work_bits, *witness) {
            return Err(ReplayError::PowWitness("commit phase"));
        }
        betas.push(ch.sample_algebra_element());
    }
    if fri.final_poly.len() != params.final_poly_len() {
        return Err(ReplayError::FinalPolyLength);
    }
    ch.observe_algebra_slice(&fri.final_poly);
    // A *single* base absorb per round, not an `observe_usize`: `verifier.rs:335`.
    for &log_arity in &log_arities {
        ch.observe(Val::from_usize(log_arity));
    }
    // `GrindingChallenger::check_witness` and `CanSampleBits::sample_bits`, inlined — the only two
    // places in this file that spell out a reference body instead of calling it, and only because
    // the *whole sampled element* has to come back out: the program decomposes all sixty-four bits
    // of it and the tape has to carry them. `check_witness(bits, w)` is
    // `if bits == 0 { true } else { observe(w); sample_bits(bits) == 0 }`
    // (`grinding_challenger.rs:44-49`) and `sample_bits(bits)` is
    // `sample::<Val>().as_canonical_u64() as usize & ((1 << bits) - 1)`
    // (`duplex_challenger.rs:285-290`). Both are checked against the real thing in
    // `tests/transcript.rs`, which drives the DSL's own versions against `p3-challenger`'s.
    let mask = |v: u64, bits: usize| v as usize & ((1usize << bits) - 1);
    let pow_sample = if params.query_proof_of_work_bits == 0 {
        None
    } else {
        ch.observe(fri.query_pow_witness);
        let v: Val = ch.sample();
        if mask(v.as_canonical_u64(), params.query_proof_of_work_bits) != 0 {
            return Err(ReplayError::PowWitness("query"));
        }
        Some(v.as_canonical_u64())
    };
    // `TwoAdicFriFolding::extra_query_index_bits() == 0`.
    let index_samples: Vec<u64> = (0..params.num_queries)
        .map(|_| {
            let v: Val = ch.sample();
            v.as_canonical_u64()
        })
        .collect();
    let indices: Vec<usize> =
        index_samples.iter().map(|&v| mask(v, log_global_max_height)).collect();

    // The per-round geometry `open_inputs` derives internally, derived here by the same rule
    // (`verifier.rs:733-770`) because `crate::witness` needs it to restore the pruned paths.
    let input_rounds: Vec<InputRound> = rounds
        .iter()
        .map(|(_, mats)| {
            let dims: Vec<Dimensions> = mats
                .iter()
                .map(|(domain, points)| Dimensions {
                    // The claimed-evaluation count, never the proof's row length.
                    width: points[0].1.len(),
                    height: domain.size() << LOG_BLOWUP,
                })
                .collect();
            let bits_reduced = log_global_max_height
                - log2_strict_usize(dims.iter().map(|d| d.height).max().unwrap());
            InputRound {
                dims,
                indices: indices.iter().map(|&i| i >> bits_reduced).collect(),
            }
        })
        .collect();

    let reduced_openings = open_inputs::<Val, EF, ValMmcs, ChallengeMmcs>(
        &params,
        log_global_max_height,
        &indices,
        &fri.input_openings,
        fri_alpha,
        val_mmcs,
        &rounds,
    )
    .map_err(|e| ReplayError::InputOpenings(format!("{e:?}")))?;

    let num_rounds = fri.commit_phase_commits.len();
    let mut commit_group_indices: Vec<Vec<usize>> = vec![Vec::new(); num_rounds];
    let mut commit_rows: Vec<Vec<Vec<Vec<EF>>>> = vec![Vec::new(); num_rounds];
    let log_final_height = LOG_BLOWUP + LOG_FINAL_POLY_LEN;
    let folding: Folding = TwoAdicFriFolding(PhantomData);
    let mut folded_evals = Vec::with_capacity(indices.len());
    for (query, (&index, ro)) in indices.iter().zip(reduced_openings).enumerate() {
        let mut domain_index = index;
        let folded_eval = fold_query::<Folding, Val, EF, ChallengeMmcs>(
            &folding,
            query,
            &mut domain_index,
            &betas,
            &log_arities,
            &fri.commit_phase_openings,
            ro,
            log_global_max_height,
            log_final_height,
            &mut commit_group_indices,
            &mut commit_rows,
        )
        .map_err(|e| ReplayError::Fold(format!("{e:?}")))?;
        let x = Val::two_adic_generator(log_global_max_height)
            .exp_u64(reverse_bits_len(domain_index, log_global_max_height) as u64);
        let eval: EF = fri.final_poly.iter().copied().horner(x);
        if eval != folded_eval {
            return Err(ReplayError::FinalPoly(query));
        }
        folded_evals.push(folded_eval);
    }

    // The per-round amortised authentication of the reconstructed rows (`verifier.rs:405-426`).
    let mut log_current_height = log_global_max_height;
    for (round, ((commit, opening), &log_arity)) in fri
        .commit_phase_commits
        .iter()
        .zip(&fri.commit_phase_openings)
        .zip(&log_arities)
        .enumerate()
    {
        let log_folded_height = log_current_height - log_arity;
        let dims = [Dimensions { width: 1 << log_arity, height: 1 << log_folded_height }];
        params
            .mmcs
            .verify_multi_batch(
                commit,
                &dims,
                &commit_group_indices[round],
                &commit_rows[round],
                &opening.opening_proof,
            )
            .map_err(|_| ReplayError::CommitPhase(round))?;
        log_current_height = log_folded_height;
    }

    debug_assert_eq!(CAP_HEIGHT, 2, "a commitment is a four-digest cap");

    Ok(Replay {
        lookup_alpha,
        lookup_beta,
        challenges: challenges_per_instance,
        alpha,
        zeta,
        fri_alpha,
        betas,
        indices,
        log_global_max_height,
        log_arities,
        quotients,
        accumulators,
        selectors,
        folded_evals,
        index_samples,
        pow_sample,
        input_rounds,
        commit_group_indices,
        commit_rows,
    })
}

/// `verify_batch`'s own `recompose`: the base-flattened permutation openings back into `aux_width`
/// extension columns, where `aux_width = num_lookups + 1` (or 0 with no lookups).
fn recompose_ext(flat: &[EF], num_lookups: usize) -> Vec<EF> {
    if num_lookups == 0 {
        return Vec::new();
    }
    let d = <EF as BasedVectorSpace<Val>>::DIMENSION;
    flat.chunks_exact(d)
        .map(|c| <EF as ExtensionField<Val>>::from_ext_basis_coefficients(c).expect("DIMENSION-sized chunk"))
        .collect()
}
