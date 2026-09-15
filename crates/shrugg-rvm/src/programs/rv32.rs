//! The RV32-machine verifier, as an rVM program.
//!
//! Phases 0–8 — the declared shape, the batch transcript's eight observe/sample steps, the cross-AIR
//! lookup terminal sum, the per-instance constraint evaluation at `zeta` with its quotient identity,
//! the FRI query phase (commit-phase challenges, the query proof-of-work, the per-query Merkle
//! walks, the batch-opening reduction and the fold chain), and the acceptance with spec §4.4's
//! public values.
//!
//! **The transcript order is `verify_batch`'s, the *read* order is the tape's, and the two are not
//! the same thing.** `p3-batch-stark`'s transcript observes the main cap before the public values,
//! while the tape (`crate::witness::Segment`) carries the public values first and all four caps in
//! one run — because the four caps are consumed across three different phases and a segment table
//! with a run per cap would be a table of sixteen-word segments for no benefit. So the program reads
//! each segment once, in tape order, and observes what it has read in the transcript's order. Every
//! `HINT` below is therefore positioned by `crate::witness`, and every `observe`/`sample` by
//! `p3-batch-stark-0.7.0/src/verifier/mod.rs:459-606` (phases 0–4) and
//! `p3-fri-0.7.0/src/verifier.rs:207-426` (phase 6).

use crate::dsl::hash;
use crate::dsl::transcript::DslChallenger;
use crate::dsl::{Array, Builder, Checkpoints, Digest, Ext, Felt, Ptr, DIGEST_ELEMS};
use crate::emulator::Execution;
use crate::isa::{Program, EF, F};
use crate::public_values::RVM_PUB_DOMAIN;
use crate::shape::{
    natural_domain, InnerKey, InnerShape, ShapeKey, VerifierShape, CAP_HEIGHT, LOG_BLOWUP,
    NUM_RANDOM_CODEWORDS, RVM_VK_DOMAIN,
};
use p3_air::{Air, BaseAir};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_lookup::InteractionSymbolicBuilder;
use p3_util::reverse_bits_len;
use std::collections::BTreeMap;

use super::constraints::{
    aux_width, committed_chunks, emit_instance, emit_lookup_challenges, read_openings, Batch,
    Openings, Phase5Cost,
};
use super::VerifierProgram;

/// The cap size, in words: four digests of four elements (`cap_height = 2`).
const CAP_WORDS: usize = (1 << crate::shape::CAP_HEIGHT) * DIGEST_ELEMS;

/// Reads sixteen witness words into four `Digest`s: one `MerkleCap` of `cap_height = 2`.
///
/// Through [`Builder::hint_array`], so the sixteen words cost two rows each and create no handles —
/// a cap is hashed out of memory, never out of registers.
fn read_cap(b: &mut Builder) -> [Digest; 4] {
    let a = b.hint_array(CAP_WORDS);
    std::array::from_fn(|i| Digest(b.offset(a.base, (i * DIGEST_ELEMS) as i64)))
}

/// The same shape from compile-time constants: the inner preprocessed cap is a machine constant, so
/// the program carries it as sixteen immediates instead of reading it off the tape. Nothing a prover
/// supplies can move it.
fn constant_cap(b: &mut Builder, cap: &[[crate::isa::F; 4]; 4]) -> [Digest; 4] {
    let p = b.alloc(CAP_WORDS as u64);
    for (i, v) in cap.iter().flatten().enumerate() {
        let c = b.constant(*v);
        b.store(p, i as i64, c);
    }
    std::array::from_fn(|i| Digest(b.offset(p, (i * DIGEST_ELEMS) as i64)))
}

/// Builds the verifier program for one inner shape.
pub use crate::dsl::Precompiles;
pub fn verify_rv32(shape: &InnerShape, key: &InnerKey, cp: Checkpoints) -> VerifierProgram {
    verify_rv32_with(shape, key, cp, crate::dsl::Liveness::On, Precompiles::On)
}

/// Phases 0–7 for one proof, read off the tape at its current position with a fresh challenger:
/// the declared-shape header pin, the batch transcript, the terminal sum, the constraint
/// evaluation at `zeta`, and the FRI query phase. Returns the proof's public-values array — the
/// interface list's per-proof run — and the per-instance phase-5 costs.
///
/// [`verify_rv32_with`] emits it once, straight-line; the aggregate program
/// (`super::rv32n::verify_rv32n`, M5.3) emits it as the counted loop's body, where every run
/// re-executes it against the next proof's tape region.
pub(super) fn emit_proof<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    key: &S::Key,
) -> (Array<Felt>, Vec<Phase5Cost>)
where
    S::Air: BaseAir<F> + Air<InteractionSymbolicBuilder<F, EF>>,
{
    let n = shape.instances();
    let mark = |b: &mut Builder, name: &'static str| b.note_phase(name);

    // ── phase 0: the header. Read the proof's declared shape and pin it to this program's own, so
    // a proof of another shape is refused here instead of being read with the wrong field widths.
    for (k, want) in shape.header_words().iter().enumerate() {
        let got = b.hint();
        let w = b.constant(*want);
        b.assert_eq(got, w, &format!("header word {k}"));
    }

    // ── the tape's next four segments, read in tape order and observed below in transcript order.
    // `PublicValues`: instance 1 (the cpu table) owns all of them.
    let pvs = b.hint_array(shape.num_public_values()[shape.pv_instance()]);
    // `Commitments`: main, permutation, quotient_chunks, random — `BatchCommitments`' field order,
    // which is also the order the transcript observes them in.
    let main_cap = read_cap(b);
    let perm_cap = read_cap(b);
    let q_cap = read_cap(b);
    let r_cap = read_cap(b);
    // `LookupTerminals`: one extension element per instance that declares lookups, in instance
    // order — `lookup_terminals.iter().flatten()`.
    let terminals: Vec<_> = (0..n)
        .filter(|&i| shape.num_lookups()[i] > 0)
        .map(|_| b.hint_ext())
        .collect();

    // ── phase 1: the challenger, the instance count and the per-instance binding.
    let mut ch = DslChallenger::new(b);
    ch.observe_usize(b, n);
    for i in 0..n {
        let ext_db = shape.degree_bits()[i];
        ch.observe_usize(b, ext_db);
        // `base_db = ext_db - is_zk`, and `is_zk() == true for this machine's config.
        ch.observe_usize(b, ext_db - 1);
        ch.observe_usize(b, shape.widths()[i]);
        // The *committed* chunk count: `(1 << log_num_quotient_chunks) << is_zk`.
        ch.observe_usize(b, (1 << shape.log_num_quotient_chunks()[i]) << 1);
    }

    // ── phase 2: the main commitment, the public values, the preprocessed widths and cap.
    ch.observe_cap(b, &main_cap);
    for k in 0..shape.num_public_values()[shape.pv_instance()] {
        let v = b.get(pvs, k);
        ch.observe(b, v);
    }
    for i in 0..n {
        ch.observe_usize(b, shape.preprocessed_widths()[i]);
    }
    let pre_cap = constant_cap(b, key.cap());
    ch.observe_cap(b, &pre_cap);

    // ── phase 3: the lookup challenges, the permutation commitment, the terminals, alpha.
    // `sample_perm_challenges` draws exactly this pair; every bus offset it derives is arithmetic on
    // it, which is phase 5's job (`emit_lookup_challenges`).
    let lookup_alpha = ch.sample_ext(b);
    b.checkpoint("lookup_alpha", lookup_alpha);
    let lookup_beta = ch.sample_ext(b);
    b.checkpoint("lookup_beta", lookup_beta);
    ch.observe_cap(b, &perm_cap);
    for t in &terminals {
        ch.observe_ext(b, *t);
    }
    let alpha = ch.sample_ext(b);
    b.checkpoint("alpha", alpha);

    // ── phase 4: the quotient and random commitments, then zeta.
    ch.observe_cap(b, &q_cap);
    ch.observe_cap(b, &r_cap);
    let zeta = ch.sample_ext(b);
    b.checkpoint("zeta", zeta);

    // ── the cross-AIR terminal sum (`LogUpGadget::verify_terminal_sum`): the sum over instances must
    // be zero. Checked here because the terminals are already in hand; the native verifier checks it
    // last, and the order does not matter — nothing downstream reads the sum.
    let mut sum = b.ext_constant(EF::ZERO);
    for t in &terminals {
        sum = b.ext_add(sum, *t);
    }
    // Both coefficients under *one* name, rather than `assert_eq_ext`'s `"… (c0)"`/`"… (c1)"` pair:
    // either failing means the same thing — the batch's lookups do not balance — and the tamper
    // tests name the step, not the coefficient. (`DslChallenger::sample_bits`' two canonicality
    // assertions share a name for the same reason.)
    let (c0, c1) = b.ext_parts(sum);
    let zero = b.zero();
    b.assert_eq(c0, zero, "lookup terminal sum");
    b.assert_eq(c1, zero, "lookup terminal sum");
    mark(b, "phases 0-4: header, transcript, commitments, terminal sum");

    // ── phase 5: the generated constraint evaluation at `zeta` (spec §4.3).
    //
    // The per-lookup challenge pairs come first, because they are the `ExtEntry::Challenge` leaves of
    // every lookup constraint below — `sample_perm_challenges` derives the whole layout from the pair
    // drawn in phase 3, and so does this.
    let challenges = emit_lookup_challenges(b, shape, lookup_alpha, lookup_beta);
    // `Segment::OpenedValues`, read once in tape order. The query phase re-observes every one of
    // these as a claimed evaluation, which is why `openings` keeps the raw runs too.
    let openings = read_openings(b, shape, pvs, &terminals, &challenges, zeta);
    let airs = shape.constraint_chips();
    let common = shape.common_data();
    let lookups: Vec<&[_]> = common.lookups.iter().map(|l| l.as_ref()).collect();
    let batch = Batch { shape, airs: &airs, lookups: &lookups, alpha, zeta };
    let mut phase5 = Vec::with_capacity(n);
    for i in 0..n {
        let before = b.emitted();
        let mut cost = Phase5Cost::default();
        emit_instance(b, &batch, &openings, i, &mut cost);
        cost.instrs = b.emitted() - before;
        phase5.push(cost);
    }
    mark(b, "phase 5: constraint evaluation at zeta");

    // ── phase 6: the FRI query phase (`p3-fri-0.7.0/src/verifier.rs:207-426`, in that order) ──
    //
    // First the observation `TwoAdicFriPcs::verify` makes of every claimed evaluation
    // (`two_adic_pcs.rs:684-703`) — the public runs phase 5 read, then the hiding wrapper's hidden
    // halves, which is `Segment::RandomOpenings`. The merged runs are what the reduction consumes.
    let log_global = shape.log_global_max_height();
    let cfg = &crate::shape::machine(shape.profile()).config;
    let zeta_nexts: Vec<Ext> = (0..n)
        .map(|i| {
            let dom = natural_domain(cfg, 1usize << (shape.degree_bits()[i] - 1));
            let g = b.constant(dom.subgroup_generator());
            b.ext_mul_base(zeta, g)
        })
        .collect();
    let round_caps = RoundCaps { random: r_cap, main: main_cap, quotient: q_cap,
                                 preprocessed: pre_cap, permutation: perm_cap };
    let (opened, metas) = observe_claimed(b, &mut ch, shape, zeta, &zeta_nexts, &openings,
                                          &round_caps);

    // 1. `fri_alpha` — one extension draw.
    let fri_alpha = ch.sample_ext(b);
    b.checkpoint("fri_alpha", fri_alpha);

    // 2. The commit phase — per round: the cap, the discarded PoW witness, one `beta` draw.
    let mut fri_caps = Vec::with_capacity(shape.log_arities().len());
    let mut betas = Vec::with_capacity(shape.log_arities().len());
    for r in 0..shape.log_arities().len() {
        let cap = read_cap(b);
        ch.observe_cap(b, &cap);
        // `commit_proof_of_work_bits == 0` on this machine, and `check_witness(0, w)` observes
        // nothing — it returns `true` without touching the transcript
        // (`grinding_challenger.rs:44-49`). The witness element is therefore read off the tape
        // and discarded, exactly as the native verifier discards it.
        let _discarded = b.hint();
        let beta = ch.sample_ext(b);
        b.checkpoint(&format!("beta[{r}]"), beta);
        fri_caps.push(cap);
        betas.push(beta);
    }

    // 3. `final_poly` — `log_final_poly_len == 0`, so exactly one extension coefficient.
    let final_poly = b.hint_ext();
    ch.observe_ext(b, final_poly);

    // 4. The arity schedule — one *single* base absorb per round (`verifier.rs:335`), from the
    // program's compile-time schedule. Not `observe_usize`: that would be two absorbs.
    for &la in shape.log_arities() {
        let h = b.constant(F::from_usize(la));
        ch.observe(b, h);
    }

    // 5. The query proof-of-work.
    let pow = b.hint();
    ch.check_witness(b, shape.query_pow_bits(), pow, "query pow");

    // 6. The query indices — little-endian bit handles, `sample_bits(log_global_max_height)` each
    // (`TwoAdicFriFolding::extra_query_index_bits() == 0`).
    let index_bits: Vec<Vec<Felt>> = (0..shape.num_queries())
        .map(|_| ch.sample_bits(b, log_global))
        .collect();
    mark(b, "phase 6 preamble: claimed evals, betas, final poly, pow, indices");

    // 7. Per query, unrolled: the count is a compile-time constant of the shape, and a counted
    // loop would force every intermediate through memory for no benefit. The four query-major
    // segments are read first, in tape order — each segment holds *every* query's run, so a
    // per-query read would land on the next query's rows, not this query's paths.
    let mut all_rows = Vec::with_capacity(shape.num_queries());
    let mut all_paths = Vec::with_capacity(shape.num_queries());
    let mut all_commit_openings = Vec::with_capacity(shape.num_queries());
    let mut all_commit_paths = Vec::with_capacity(shape.num_queries());
    for _ in 0..shape.num_queries() {
        all_rows.push(read_input_openings(b, &opened));
    }
    for _ in 0..shape.num_queries() {
        all_paths.push(read_input_paths(b, &opened));
    }
    for _ in 0..shape.num_queries() {
        all_commit_openings.push(read_commit_openings(b, shape));
    }
    for _ in 0..shape.num_queries() {
        all_commit_paths.push(read_commit_paths(b, shape));
    }
    mark(b, "query segments: tape reads");
    b.unrolled(shape.num_queries(), |b, q| {
        emit_query(b, shape, &opened, &metas, &fri_caps, &betas, fri_alpha, final_poly,
                   &index_bits[q], &all_rows[q], &all_paths[q], &all_commit_openings[q],
                   &all_commit_paths[q]);
    });
    mark(b, "queries: merkle walks, reduction, folds");

    (pvs, phase5)
}

/// The inner verifier-key digest, computed in-program from the compile-time shape words and the
/// key's cap: the `RVM_VK_DOMAIN` header in the capacity lanes, one padding-free sponge
/// (`shape::inner_vk_digest`'s host twin pins it). Recomputed in-program so it is bound by the
/// program digest twice over — nothing a prover supplies can move it. Phase 8 (and the aggregate
/// program's preamble) absorbs it into the interface list.
pub(super) fn vk_digest_in_program<S: VerifierShape>(b: &mut Builder, shape: &S, key: &S::Key) -> Digest {
    let words = shape.shape_words();
    let mut msg = Vec::with_capacity(1 + words.len() + CAP_WORDS);
    msg.push(F::from_u64(RVM_VK_DOMAIN));
    msg.extend(words);
    msg.extend(key.flatten());
    let src = b.alloc(msg.len() as u64);
    for (k, v) in msg.iter().enumerate() {
        let c = b.constant(*v);
        b.store(src, k as i64, c);
    }
    let vk = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::sponge(b, src, msg.len(), vk);
    vk
}

/// [`verify_rv32`] with the allocator's liveness policy and the precompiles chosen: `Off`
/// reproduces the pre-Task-7 program byte for byte (the differential reference), `On` is what
/// ships.
pub fn verify_rv32_with(
    shape: &InnerShape,
    key: &InnerKey,
    cp: Checkpoints,
    liveness: crate::dsl::Liveness,
    pc: Precompiles,
) -> VerifierProgram {
    let mut b = Builder::with_opts(cp, liveness, pc);
    let (pvs, phase5) = emit_proof(&mut b, shape, key);

    // ── phase 8: acceptance and the interface digest (R5) ────────────────────────────────────
    //
    // `inner_vk_digest`, recomputed in-program from the compile-time shape words and the key's
    // cap (so it is bound by the program digest twice over), then the §4.4 list — the vk digest,
    // `N = 1`, the 34 inner public values — stored, sponged with the capacity header, and the
    // digest's four lanes published. The batch public values are always exactly those four (R5):
    // the node recomputes the list from the covered bundles' public fields and compares digests
    // (the cs6 `H_PUB` pattern). What used to be thirty-nine `PUBLIC` rows is the digest's four.
    let vk = vk_digest_in_program(&mut b, shape, key);
    let n_list = DIGEST_ELEMS + 1 + shape.num_public_values()[shape.pv_instance()];
    let list = b.alloc(n_list as u64);
    for lane in 0..DIGEST_ELEMS as i64 {
        let v = b.load(vk.0, lane);
        b.store(list, lane, v);
    }
    let one = b.constant(F::ONE);
    b.store(list, DIGEST_ELEMS as i64, one);
    for k in 0..shape.num_public_values()[shape.pv_instance()] {
        let v = b.get(pvs, k);
        b.store(list, (DIGEST_ELEMS + 1 + k) as i64, v);
    }
    let interface = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::sponge_seeded(&mut b, RVM_PUB_DOMAIN, list, n_list, interface);
    for lane in 0..DIGEST_ELEMS as i64 {
        let v = b.load(interface.0, lane);
        b.public(v);
    }
    b.note_phase("phase 8: the interface digest (R5)");

    let checkpoint_names = b.checkpoint_names().to_vec();
    let (program, mut stats) = b.finish_stats();
    let phase_rows = std::mem::take(&mut stats.phase_rows);
    VerifierProgram {
        program,
        shape: shape.clone(),
        key: key.clone(),
        checkpoints: cp,
        stats,
        phase5,
        phase_rows,
        checkpoint_names,
    }
}


// ───────────────────────────────────────────────────────────── phases 6–8

/// The salt elements the hiding MMCS appends to every committed row — every leaf message this
/// file hashes ends with four of them (`hiding_mmcs.rs:232-275`).
const SALT_ELEMS: usize = hash::SALT_ELEMS;

/// One committed matrix of the opening argument, already merged with the hiding wrapper's hidden
/// halves: its log-height (`degree_bits[i] + LOG_BLOWUP`), and per opening point the point itself
/// (`zeta`, or the instance's `zeta_next`) and the claimed values at it — the public prefix, then
/// the four hidden values (none for the preprocessed round) — the order `open_inputs`'
/// accumulation consumes them in.
pub struct MatrixOpening {
    pub log_height: usize,
    pub points: Vec<(Ext, Array<Ext>)>,
}

/// The batch's five rounds in `coms_to_verify` order — `random`, `main`, `quotient_chunks`,
/// `preprocessed`, `permutation` (`p3-batch-stark-0.7.0/src/verifier/mod.rs:137-332`) — with the
/// claimed evaluations merged and the transcript already fed.
pub struct QueryOpenings {
    pub rounds: Vec<Vec<MatrixOpening>>,
}

/// What a round is beyond its matrices: the name its refusal checkpoints take, and the
/// commitment its Merkle walks are checked against — a tape cap, or the constant preprocessed
/// cap the program carries.
struct RoundMeta {
    name: &'static str,
    cap: [Digest; 4],
}

/// The five commitments the input rounds are checked against, in `coms_to_verify` order.
struct RoundCaps {
    random: [Digest; 4],
    main: [Digest; 4],
    quotient: [Digest; 4],
    preprocessed: [Digest; 4],
    permutation: [Digest; 4],
}

/// `TwoAdicFriPcs::verify`'s observation of every claimed evaluation
/// (`two_adic_pcs.rs:684-703`), reading `Segment::RandomOpenings` in the same nesting — and
/// building the [`QueryOpenings`] the query phase consumes.
///
/// Each point's merged `[public ‖ hidden]` run is copied into one fresh array: the reduction
/// indexes it per column, and keeping the two halves in different arrays would make that indexing
/// two code paths for no saving.
fn observe_claimed<S: VerifierShape>(
    b: &mut Builder,
    ch: &mut DslChallenger,
    shape: &S,
    zeta: Ext,
    zeta_nexts: &[Ext],
    o: &Openings,
    caps: &RoundCaps,
) -> (QueryOpenings, Vec<RoundMeta>) {
    let nil = b.alloc(0);
    // One (point, values) pair: the hidden run read off the tape, the public run observed, then
    // the hidden run observed, everything merged into one array. The tape reads land in
    // `Segment::RandomOpenings`' (round, matrix, point) nesting order, which is also the
    // transcript's observation order.
    let point = |b: &mut Builder,
                 ch: &mut DslChallenger,
                 z: Ext,
                 public: Array<Ext>,
                 n_hidden: usize|
     -> (Ext, Array<Ext>) {
        let hidden =
            if n_hidden == 0 { Array::new(nil, 0, 2) } else { b.hint_ext_array(n_hidden) };
        let out = b.alloc((2 * (public.len + n_hidden)) as u64);
        for k in 0..public.len {
            let v = b.get_ext(public, k);
            ch.observe_ext(b, v);
            b.store_ext(out, (2 * k) as i64, v);
        }
        for k in 0..n_hidden {
            let v = b.get_ext(hidden, k);
            ch.observe_ext(b, v);
            b.store_ext(out, (2 * (public.len + k)) as i64, v);
        }
        (z, Array::new(out, public.len + n_hidden, 2))
    };

    let h_of = |i: usize| shape.degree_bits()[i] + LOG_BLOWUP;
    let n = shape.instances();
    let mut rounds = Vec::with_capacity(5);
    let mut metas = Vec::with_capacity(5);

    // `random`: one width-`DIMENSION` matrix per instance, one point (`p3-batch-stark-0.7.0/src/
    // verifier/mod.rs:141-152`). Its two public values are the ZK random trace's opened values.
    let mut mats = Vec::with_capacity(n);
    for i in 0..n {
        let pts = vec![point(b, ch, zeta, o.raw[i].random, NUM_RANDOM_CODEWORDS)];
        mats.push(MatrixOpening { log_height: h_of(i), points: pts });
    }
    rounds.push(mats);
    metas.push(RoundMeta { name: "random", cap: caps.random });

    // `main`: one matrix per instance, `zeta_next` too when the chip reads the next row.
    let mut mats = Vec::with_capacity(n);
    for i in 0..n {
        let mut pts = vec![point(b, ch, zeta, o.raw[i].trace_local, NUM_RANDOM_CODEWORDS)];
        if shape.main_next()[i] {
            pts.push(point(b, ch, zeta_nexts[i], o.raw[i].trace_next, NUM_RANDOM_CODEWORDS));
        }
        mats.push(MatrixOpening { log_height: h_of(i), points: pts });
    }
    rounds.push(mats);
    metas.push(RoundMeta { name: "main", cap: caps.main });

    // `quotient_chunks`: one matrix per committed chunk, instance-major (`verifier/mod.rs:203-212`).
    let mut mats = Vec::new();
    for i in 0..n {
        for c in 0..committed_chunks(shape, i) {
            let pts =
                vec![point(b, ch, zeta, o.raw[i].quotient_chunks[c], NUM_RANDOM_CODEWORDS)];
            mats.push(MatrixOpening { log_height: h_of(i), points: pts });
        }
    }
    rounds.push(mats);
    metas.push(RoundMeta { name: "quotient", cap: caps.quotient });

    // `preprocessed`: one matrix per instance with preprocessed columns, in the global
    // commitment's matrix order. `commit_preprocessing` does not widen, so there are no hidden
    // values (`hiding_pcs.rs:138-158`) — and `Segment::RandomOpenings` carries none for it.
    let mut mats = Vec::new();
    for &inst in shape.preprocessed_matrix_to_instance() {
        let mut pts = vec![point(b, ch, zeta, o.raw[inst].pre_local, 0)];
        if shape.pre_next()[inst] {
            pts.push(point(b, ch, zeta_nexts[inst], o.raw[inst].pre_next, 0));
        }
        mats.push(MatrixOpening { log_height: h_of(inst), points: pts });
    }
    rounds.push(mats);
    metas.push(RoundMeta { name: "preprocessed", cap: caps.preprocessed });

    // `permutation`: one matrix per instance with lookups, always both points
    // (`verifier/mod.rs:314-332`).
    let mut mats = Vec::new();
    for i in 0..n {
        if aux_width(shape, i) > 0 {
            let pts = vec![
                point(b, ch, zeta, o.raw[i].perm_local, NUM_RANDOM_CODEWORDS),
                point(b, ch, zeta_nexts[i], o.raw[i].perm_next, NUM_RANDOM_CODEWORDS),
            ];
            mats.push(MatrixOpening { log_height: h_of(i), points: pts });
        }
    }
    rounds.push(mats);
    metas.push(RoundMeta { name: "permutation", cap: caps.permutation });

    (QueryOpenings { rounds }, metas)
}

/// The Merkle levels one input round walks: its tallest tree's log-height minus the cap's
/// (`mmcs/batch.rs`'s `log2(padded max height) − cap_height`).
fn levels_of(mats: &[MatrixOpening]) -> usize {
    mats.iter().map(|m| m.log_height).max().expect("a committed round has matrices") - CAP_HEIGHT
}

/// One query's run of `Segment::InputOpenings`: per round, per matrix, the opened row and its
/// four salts.
fn read_input_openings(b: &mut Builder, opened: &QueryOpenings) -> Vec<Vec<Array<Felt>>> {
    opened
        .rounds
        .iter()
        .map(|mats| {
            mats.iter().map(|m| b.hint_array(m.points[0].1.len + SALT_ELEMS)).collect()
        })
        .collect()
}

/// One query's run of `Segment::InputPaths`: per round, the restored path's siblings.
fn read_input_paths(b: &mut Builder, opened: &QueryOpenings) -> Vec<Array<Felt>> {
    opened
        .rounds
        .iter()
        .map(|mats| b.hint_array(DIGEST_ELEMS * levels_of(mats)))
        .collect()
}

/// One query's run of `Segment::CommitPhaseOpenings`: per round, the `arity − 1` sibling values
/// and the row's four salts.
fn read_commit_openings<S: VerifierShape>(b: &mut Builder, shape: &S) -> Vec<Array<Felt>> {
    shape
        .log_arities()
        .iter()
        .map(|&la| b.hint_array(((1usize << la) - 1) * 2 + SALT_ELEMS))
        .collect()
}

/// One query's run of `Segment::CommitPhasePaths`: per round, the restored path's siblings.
fn read_commit_paths<S: VerifierShape>(b: &mut Builder, shape: &S) -> Vec<Array<Felt>> {
    let mut log_folded = shape.log_global_max_height();
    shape
        .log_arities()
        .iter()
        .map(|&la| {
            log_folded -= la;
            b.hint_array(DIGEST_ELEMS * (log_folded - CAP_HEIGHT))
        })
        .collect()
}

/// One query, already-tape-read to final check: the five input rounds' Merkle walks, the
/// batch-opening reduction, the fold chain with each round's reconstructed row authenticated
/// against its commitment, and the final-polynomial check.
#[allow(clippy::too_many_arguments)]
fn emit_query<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    opened: &QueryOpenings,
    metas: &[RoundMeta],
    fri_caps: &[[Digest; 4]],
    betas: &[Ext],
    fri_alpha: Ext,
    final_poly: Ext,
    index_bits: &[Felt],
    rows: &[Vec<Array<Felt>>],
    paths: &[Array<Felt>],
    commit_openings: &[Array<Felt>],
    commit_paths: &[Array<Felt>],
) {
    let log_global = shape.log_global_max_height();

    // ── every input round, Merkle-verified against its commitment before any arithmetic reads the
    // openings (`open_inputs` authenticates first, for the same reason).
    for (ri, mats) in opened.rounds.iter().enumerate() {
        emit_input_round_root(b, log_global, mats, &rows[ri], paths[ri], index_bits, &metas[ri]);
    }

    // ── the batch-opening reduction.
    let ros = emit_reduced_openings(b, shape, index_bits, fri_alpha, opened, &rows);

    // ── the fold chain (`fold_query`, verifier.rs:523-671).
    let mut ros: BTreeMap<usize, Ext> = ros.into_iter().collect();
    let mut folded = ros
        .remove(&log_global)
        .expect("open_inputs' first reduced opening is at the global max height");
    let mut shift = 0usize;
    for (r, &la) in shape.log_arities().iter().enumerate() {
        let arity = 1usize << la;
        let log_folded = log_global - shift - la;
        // `index_in_group = index % arity`: the low `log_arity` bits of the current index.
        let own = &index_bits[shift..shift + la];

        // Reconstruct the committed row: the query's own value at `index_in_group`, the
        // `arity − 1` siblings filling the rest in order — selected arithmetically from the low
        // bits, so no branching (`fold_query`'s loop, verifier.rs:583-591). The sibling that
        // lands at position `j` is `siblings[j − (j > index_in_group)]`; the indicators are
        // one-hot, so `[index_in_group < j]` is a prefix sum.
        let sibs = commit_openings[r];
        let ind: Vec<Felt> = (0..arity).map(|v| bit_indicator(b, own, v)).collect();
        let mut evals = Vec::with_capacity(arity);
        for j in 0..arity {
            // `[index_in_group < j]`; empty prefix sums to zero.
            let mut gt: Option<Felt> = None;
            for &i in &ind[..j] {
                gt = Some(match gt {
                    None => i,
                    Some(g) => b.add(g, i),
                });
            }
            let gt = gt.unwrap_or_else(|| b.zero());
            // The two candidates: `siblings[j]` when `j <= index_in_group`, `siblings[j − 1]`
            // when `j > index_in_group`. For `j == arity − 1 == index_in_group` the first
            // candidate does not exist — the value read in its place is masked to zero below.
            let sj = b.load_ext(sibs.base, (2 * j.min(arity - 2)) as i64);
            let sj1 = if j == 0 { sj } else { b.load_ext(sibs.base, (2 * (j - 1)) as i64) };
            // `B = sj + gt·(sj1 − sj)`, then `eval = B + ind_j·(folded − B)`.
            let d = b.ext_sub(sj1, sj);
            let t = b.ext_mul_base(d, gt);
            let candidate = b.ext_add(sj, t);
            let d = b.ext_sub(folded, candidate);
            let t = b.ext_mul_base(d, ind[j]);
            evals.push(b.ext_add(candidate, t));
        }

        // The parent node's index bits, then the fold itself.
        shift += la;
        let group_bits = &index_bits[shift..shift + log_folded];
        folded = emit_fold_round(b, log_folded, la, group_bits, betas[r], &evals);

        // Authenticate the reconstructed row against the round's commitment.
        emit_commit_root(b, &evals, sibs, commit_paths[r], &index_bits[shift..], fri_caps[r],
                         &format!("commit phase root[{r}]"));

        // Roll in a reduced opening landing at the folded height: `beta^(2^log_arity) · ro`
        // (`verifier.rs:620-626`). The arity schedule is derived to land on every distinct input
        // height exactly once, which is what makes the map empty at the end.
        if let Some(ro) = ros.remove(&log_folded) {
            let mut beta_pow = betas[r];
            for _ in 0..la {
                beta_pow = b.ext_mul(beta_pow, beta_pow);
            }
            let t = b.ext_mul(beta_pow, ro);
            folded = b.ext_add(folded, t);
        }
    }
    debug_assert!(ros.is_empty(), "the arity schedule rolls every input height in");

    // ── the final check: `final_poly.horner(x_final) == folded_eval` with
    // `x_final = g_{log_global}^{reverse_bits_len(domain_index, log_global)}` (`verifier.rs:413-423`).
    // `log_final_poly_len == 0`, so the Horner is the single coefficient itself.
    let (f0, f1) = b.ext_parts(final_poly);
    let (g0, g1) = b.ext_parts(folded);
    b.assert_eq(f0, g0, "final polynomial");
    b.assert_eq(f1, g1, "final polynomial");
}

/// One input round's Merkle authentication, `verify_batch`'s loop with the pruned multiproof
/// expanded into one full path per query: the leaf sponge over the tallest group's concatenated
/// `row ‖ salt` runs, the walk, the shorter-height groups injected at their levels, and the
/// surviving digest compared against the round's cap entry (`mmcs/batch.rs:203-267`).
fn emit_input_round_root(
    b: &mut Builder,
    log_global: usize,
    mats: &[MatrixOpening],
    rows: &[Array<Felt>],
    path: Array<Felt>,
    index_bits: &[Felt],
    meta: &RoundMeta,
) {
    let max_h = mats.iter().map(|m| m.log_height).max().expect("a round has matrices");
    let levels = max_h - CAP_HEIGHT;
    let bits_reduced = log_global - max_h;
    // Distinct heights, tallest first; matrices of one height keep their committed order (the
    // reference's `sorted_by_key(Reverse(height))` is stable).
    let mut heights: Vec<usize> = mats.iter().map(|m| m.log_height).collect();
    heights.sort_unstable_by(|a, bb| bb.cmp(a));
    heights.dedup();
    let group = |h: usize| -> Vec<usize> {
        mats.iter().enumerate().filter(|(_, m)| m.log_height == h).map(|(i, _)| i).collect()
    };
    // Concatenate a group's `row ‖ salt` runs into one fresh buffer, in group order.
    let concat = |b: &mut Builder, members: &[usize]| -> (Ptr, usize) {
        let total: usize = members.iter().map(|&m| rows[m].len).sum();
        let buf = b.alloc(total as u64);
        let mut off = 0i64;
        for &m in members {
            b.copy_cells(buf, off, rows[m].base, 0, rows[m].len);
            off += rows[m].len as i64;
        }
        (buf, total)
    };
    let (leaf_msg, n) = concat(b, &group(heights[0]));
    let leaf = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::sponge(b, leaf_msg, n, leaf);
    let mut injections = Vec::new();
    for &h in &heights[1..] {
        let (buf, n) = concat(b, &group(h));
        injections.push(hash::Injection { after_level: max_h - h - 1, rows: buf, n_cells: n });
    }
    let out = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::merkle_walk_with_injections(
        b,
        leaf,
        &index_bits[bits_reduced..bits_reduced + levels],
        path.base,
        levels,
        &injections,
        out,
    );
    assert_cap_eq(
        b,
        out,
        &meta.cap,
        &index_bits[bits_reduced + levels..bits_reduced + levels + CAP_HEIGHT],
        &format!("input opening root[{}]", meta.name),
    );
}

/// The reconstructed commit-phase row, Merkle-verified against the round's cap: the leaf is the
/// sponge over `flatten_to_base(row) ‖ salt(4)` — the commit-phase tree is over `Challenge`,
/// flattened to base coefficients by `ExtensionMmcs`, and it is a hiding MMCS, so the row carries
/// four salts exactly as an input round's does.
fn emit_commit_root(
    b: &mut Builder,
    evals: &[Ext],
    openings: Array<Felt>,
    path: Array<Felt>,
    index_bits: &[Felt],
    cap: [Digest; 4],
    name: &str,
) {
    let arity = evals.len();
    let msg = b.alloc((2 * arity + SALT_ELEMS) as u64);
    for (j, e) in evals.iter().enumerate() {
        b.store_ext(msg, (2 * j) as i64, *e);
    }
    // The salts sit right after the round's `arity − 1` siblings on the tape.
    b.copy_cells(msg, (2 * arity) as i64, openings.base, (2 * (arity - 1)) as i64, SALT_ELEMS);
    let leaf = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::sponge(b, msg, 2 * arity + SALT_ELEMS, leaf);
    let levels = path.len / DIGEST_ELEMS;
    let out = Digest(b.alloc(DIGEST_ELEMS as u64));
    hash::merkle_walk(b, leaf, &index_bits[..levels], path.base, levels, out);
    assert_cap_eq(b, out, &cap, &index_bits[levels..levels + CAP_HEIGHT], name);
}

/// The digest a Merkle walk reached, compared against the commitment's entry at the remaining
/// index: the two bits the walk did not consume (`cap_height = 2`) select the entry
/// arithmetically, `cap_index = bit₀ + 2·bit₁`. All four lanes are asserted under one name —
/// either failing means the same thing: this opening is not in the committed tree.
fn assert_cap_eq(b: &mut Builder, got: Digest, cap: &[Digest; 4], bits: &[Felt], name: &str) {
    debug_assert_eq!(bits.len(), CAP_HEIGHT);
    let one = b.constant(F::ONE);
    let nb0 = b.sub(one, bits[0]);
    let nb1 = b.sub(one, bits[1]);
    let ind = [b.mul(nb0, nb1), b.mul(bits[0], nb1), b.mul(nb0, bits[1]), b.mul(bits[0], bits[1])];
    for lane in 0..DIGEST_ELEMS as i64 {
        let mut acc: Option<Felt> = None;
        for (j, &i) in ind.iter().enumerate() {
            let c = b.load(cap[j].0, lane);
            let term = b.mul(c, i);
            acc = Some(match acc {
                None => term,
                Some(a) => b.add(a, term),
            });
        }
        let g = b.load(got.0, lane);
        b.assert_eq(g, acc.expect("four cap digests"), name);
    }
}

/// The indicator of `bits == v` for a compile-time `v`, as a product of the bits and their
/// negations: `Π_k (v_k ? b_k : 1 − b_k)`.
fn bit_indicator(b: &mut Builder, bits: &[Felt], v: usize) -> Felt {
    let one = b.constant(F::ONE);
    let mut acc: Option<Felt> = None;
    for (k, &bit) in bits.iter().enumerate() {
        let term = if (v >> k) & 1 == 1 { bit } else { b.sub(one, bit) };
        acc = Some(match acc {
            None => term,
            Some(a) => b.mul(a, term),
        });
    }
    acc.expect("an indicator over at least one bit")
}

/// One query's batch-opening reduction: `Σ alpha^k (p_at_z − p_at_x) (z − x)⁻¹`, accumulated per
/// log-height in (round, matrix, point, column) order with one running alpha power per height —
/// exactly `p3_fri::verifier::open_inputs`' loop (`verifier.rs:795-870`). Returns the per-height
/// reduced openings sorted by height descending, which is the order `fold_query` consumes them in.
///
/// `x = GENERATOR · g_{log_height}^{reverse_bits_len(index >> bits_reduced, log_height)}` is
/// emitted by [`emit_query_point`] as a product of bit-selected compile-time constants, and
/// `(z − x)⁻¹` is one checked `EINV` per (height, point kind): two matrices at one height share
/// their opening points (an instance's trace domain is fixed by its degree bits, so equal-height
/// instances have equal `zeta_next`s), and the reference's per-(batch, matrix, point) inverses
/// are then the same elements — its `batch_multiplicative_inverse` is an optimisation, not
/// semantics.
fn emit_reduced_openings<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    index_bits: &[Felt],
    fri_alpha: Ext,
    opened: &QueryOpenings,
    rows: &[Vec<Array<Felt>>],
) -> Vec<(usize, Ext)> {
    let log_global = shape.log_global_max_height();
    let mut xs: BTreeMap<usize, Felt> = BTreeMap::new();
    let mut invs: BTreeMap<(usize, bool), Ext> = BTreeMap::new();
    let mut acc: BTreeMap<usize, (Ext, Ext)> = BTreeMap::new();
    for (ri, mats) in opened.rounds.iter().enumerate() {
        for (mi, m) in mats.iter().enumerate() {
            let h = m.log_height;
            if !xs.contains_key(&h) {
                let x = emit_query_point(b, h, &index_bits[log_global - h..], true);
                xs.insert(h, x);
            }
            let x = xs[&h];
            for (pi, (z, vals)) in m.points.iter().enumerate() {
                // Points are pushed `zeta` first, `zeta_next` second.
                let key = (h, pi == 1);
                if !invs.contains_key(&key) {
                    let (z0, z1) = b.ext_parts(*z);
                    let d0 = b.sub(z0, x);
                    let diff = b.ext_from_parts(d0, z1);
                    let inv = b.ext_inv_checked(diff, "opening point matches the query point");
                    invs.insert(key, inv);
                }
                let inv = invs[&key];
                let (mut alpha_pow, mut ro) = acc
                    .get(&h)
                    .copied()
                    .unwrap_or_else(|| (b.ext_constant(EF::ONE), b.ext_constant(EF::ZERO)));
                let row = rows[ri][mi];
                (ro, alpha_pow) = match b.precompiles() {
                    // The compiled loop, kept as the precompile's differential reference.
                    Precompiles::Off => reduce_compiled(b, *vals, row, inv, ro, alpha_pow, fri_alpha),
                    // Task 8: one `REDUCE` instruction for the whole run.
                    Precompiles::On => b.reduce(*vals, row, inv, ro, alpha_pow, fri_alpha),
                };
                acc.insert(h, (alpha_pow, ro));
            }
        }
    }
    // The blowup-height entry exists only for a constant (height-1) trace; its reduced opening
    // must then be zero (`FinalPolyMismatch`, `verifier.rs:858-864`). No RV32 instance has
    // `degree_bits == 0`, so this never fires for this machine's shapes.
    if let Some(&(_, ro)) = acc.get(&LOG_BLOWUP) {
        let (c0, c1) = b.ext_parts(ro);
        let zero = b.zero();
        b.assert_eq(c0, zero, "reduced opening at the blowup height");
        b.assert_eq(c1, zero, "reduced opening at the blowup height");
    }
    acc.into_iter().rev().map(|(h, (_, ro))| (h, ro)).collect()
}

/// One run of the batch-opening reduction, as a compiled DSL loop: `acc += Σ_k
/// alpha_pow·(vals_k − row_k)·inv`, `alpha_pow ·= alpha` over `vals.len == row.len` columns —
/// the sequence the `REDUCE` precompile replaces (Task 8), kept in the tree as its differential
/// reference and used by the `Precompiles::Off` build.
pub fn reduce_compiled(
    b: &mut Builder,
    vals: Array<Ext>,
    row: Array<Felt>,
    inv: Ext,
    mut acc: Ext,
    mut alpha_pow: Ext,
    alpha: Ext,
) -> (Ext, Ext) {
    assert!(
        vals.len <= row.len,
        "a reduction run covers `vals.len` columns of the opened row (the rest are salts and the          hiding wrapper's hidden values, hashed by the leaf sponge, not reduced)"
    );
    for k in 0..vals.len {
        let pz = b.get_ext(vals, k);
        let px = b.load(row.base, k as i64);
        let px_e = b.ext_lift(px);
        let diff = b.ext_sub(pz, px_e);
        let t = b.ext_mul(alpha_pow, diff);
        let t = b.ext_mul(t, inv);
        acc = b.ext_add(acc, t);
        alpha_pow = b.ext_mul(alpha_pow, alpha);
    }
    (acc, alpha_pow)
}

/// [`reduce_compiled`] computed natively — the host-side anchor of the precompile's differential
/// (`tests/precompiles.rs::reduce_matches_the_compiled_sequence`): the compiled loop and the
/// `REDUCE` instruction must both land on this value.
pub fn run_reduce_sequence(vals: &[EF], row: &[F], inv: EF, acc: EF, alpha_pow: EF, alpha: EF) -> (EF, EF) {
    assert_eq!(vals.len(), row.len());
    let (mut acc, mut apow) = (acc, alpha_pow);
    for (k, pz) in vals.iter().enumerate() {
        let px = EF::from_basis_coefficients_slice(&[row[k], F::ZERO]).unwrap();
        let diff = *pz - px;
        let t = apow * diff;
        let t = t * inv;
        acc = acc + t;
        apow = apow * alpha;
    }
    (acc, apow)
}

/// `TwoAdicFriFolding::fold_row`: barycentric Lagrange interpolation at `beta` over the arity's
/// coset (`two_adic_pcs.rs:99-124, 208-249`). `index_bits` are the `log_height` low bits of the
/// folded (post-shift) index.
///
/// The reference's early return of `y_i` when `z == x_i` is **not** emitted: the plan's ruling is
/// the compiled sequence of `arity` checked `EINV`s, which computes the barycentric value
/// unconditionally. `beta` is an extension challenge squeezed after the round's commitment was
/// observed, so `beta == x_i ∈ F` is a ~2⁻⁶⁴ event for any proof the transcript binds; a prover
/// that somehow lands it is refused at the named trap where the reference would have answered.
fn emit_fold_round(
    b: &mut Builder,
    log_height: usize,
    log_arity: usize,
    index_bits: &[Felt],
    beta: Ext,
    evals: &[Ext],
) -> Ext {
    let arity = 1usize << log_arity;
    assert_eq!(evals.len(), arity);
    assert_eq!(index_bits.len(), log_height);
    // `subgroup_start = g_{log_height+log_arity}^{reverse_bits_len(index, log_height)}`.
    let s = bit_selected_power(
        b,
        F::two_adic_generator(log_height + log_arity),
        log_height,
        index_bits,
        F::ONE,
    );
    // `xs` is the bit-reversed shifted powers of `g_{log_arity}`: `xs[k] = c_k · subgroup_start`
    // with `c_k` compile-time.
    let g = F::two_adic_generator(log_arity);
    let xs: Vec<Felt> = (0..arity)
        .map(|k| b.mul_const(s, g.exp_u64(reverse_bits_len(k, log_arity) as u64)))
        .collect();
    // `weight_scale = (arity · xs[0]^arity)⁻¹`.
    let mut sa = xs[0];
    for _ in 0..log_arity {
        sa = b.mul(sa, sa);
    }
    let ws = b.mul_const(sa, F::from_usize(arity));
    let ws = b.inv(ws);

    let (b0, b1) = b.ext_parts(beta);
    let mut l_z: Option<Ext> = None;
    let mut sum: Option<Ext> = None;
    for k in 0..arity {
        // `diff_k = beta − x_k`, an extension-minus-base.
        let d0 = b.sub(b0, xs[k]);
        let diff = b.ext_from_parts(d0, b1);
        l_z = Some(match l_z {
            None => diff,
            Some(l) => b.ext_mul(l, diff),
        });
        let di = b.ext_inv_checked(diff, "beta coincides with a fold point");
        // `result += y_k · (x_k · weight_scale) · diff_k⁻¹`.
        let w = b.mul(xs[k], ws);
        let t = b.ext_mul(evals[k], di);
        let t = b.ext_mul_base(t, w);
        sum = Some(match sum {
            None => t,
            Some(s) => b.ext_add(s, t),
        });
    }
    b.ext_mul(l_z.expect("arity >= 1"), sum.expect("arity >= 1"))
}

/// `x = GENERATOR · g_{log_height}^{reverse_bits_len(index, log_height)}` when `shifted`, or
/// without the `GENERATOR` factor otherwise — from the index's little-endian bit handles, as a
/// product of `log_height` compile-time constants selected by the bits
/// (`x *= 1 + bit·(g^{2^k} − 1)`).
fn emit_query_point(b: &mut Builder, log_height: usize, index_bits: &[Felt], shifted: bool) -> Felt {
    bit_selected_power(
        b,
        F::two_adic_generator(log_height),
        log_height,
        index_bits,
        if shifted { F::GENERATOR } else { F::ONE },
    )
}

/// `base · g^{reverse_bits_len(index, log_rev)}` from the low `index_bits.len()` bits of `index`:
/// bit `k` selects the compile-time constant `g^{2^{log_rev−1−k}}`.
fn bit_selected_power(
    b: &mut Builder,
    g: F,
    log_rev: usize,
    index_bits: &[Felt],
    base: F,
) -> Felt {
    let mut x = b.constant(base);
    for (k, &bit) in index_bits.iter().enumerate() {
        let c = g.exp_u64(1u64 << (log_rev - 1 - k));
        let cm1 = b.constant(c - F::ONE);
        let t = b.mul(bit, cm1);
        let sel = b.add_const(t, F::ONE);
        x = b.mul(x, sel);
    }
    x
}

// ───────────────────────────────────────────────────────────── the measurement

/// What one verified inner proof costs, from the emulator's own counters. `permutations` counts
/// `POSEIDON2` rows only; M5.2 adds the program digest's one-per-instruction permutations on top
/// of it (`Program::digest_rows`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CycleReport {
    /// One per executed instruction.
    pub cpu_rows: usize,
    /// `POSEIDON2` rows.
    pub permutations: usize,
    /// What sizes the `memory` table.
    pub mem_accesses: usize,
    /// What sizes the `program` table.
    pub program_instrs: usize,
    /// The tape words actually consumed.
    pub witness_words: usize,
}

/// The [`CycleReport`] of one run of a built program.
pub fn cycle_report<S: VerifierShape>(vp: &VerifierProgram<S>, exec: &Execution) -> CycleReport {
    CycleReport {
        cpu_rows: exec.cpu_rows(),
        permutations: exec.permutations(),
        mem_accesses: exec.mem_accesses(),
        program_instrs: vp.program.instrs.len(),
        witness_words: exec.hints_read,
    }
}

/// `[F; 4]` as 32 big-endian hex bytes — the spelling `shrugg_zkvm::isa::Program::code_hash` uses.
pub fn digest_hex(p: &Program) -> String {
    p.digest().iter().map(|w| format!("{:016x}", w.as_canonical_u64())).collect()
}
