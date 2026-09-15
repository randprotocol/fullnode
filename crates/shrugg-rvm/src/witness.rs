//! One `Proof`, flattened into the tape the program reads with `HINT` — in **consumption order**,
//! not `Proof::to_bytes`' postcard order, with a segment table a test pins.
//!
//! The plan's ruling: the two orders genuinely differ. `verify_fri` needs each round's `log_arity`
//! before it can derive `log_global_max_height` (and that lives postcard-late, inside
//! `commit_phase_openings`), and it needs the query indices before the input openings they index. A
//! one-pass tape in postcard order is therefore not expressible, so the whole mapping lives here,
//! in one host builder, with [`WitnessTape::build`]'s segment order pinned by
//! `tests/verifier.rs::the_witness_tape_layout_is_pinned`.
//!
//! Three segments are more than a flattening:
//!
//! - `QueryBits` needs the *sampled elements*, not the query indices — the program's `sample_bits`
//!   decomposes all sixty-four bits of the canonical representative and checks the decomposition is
//!   canonical, so the tape carries the bits and the inverse-or-zero hint. It therefore runs the
//!   same [`crate::reference::replay`] the tests compare against.
//! - `InputPaths` and `CommitPhasePaths` expand each round's *pruned* multiproof into one full
//!   authentication path per query, through `MerkleTreeMmcs::restore_and_recompute_paths` — which
//!   exists in Plonky3 0.7 for exactly this caller (`p3-merkle-tree-0.7.0/src/mmcs/mod.rs:899-913`)
//!   and does the same walk, so it costs the host no extra hashing.

use crate::isa::{EF, F};
use crate::reference::{replay, InputRound, ReplayError};
use crate::shape::{InnerKey, InnerShape, ProofBatch, ShapeKey, VerifierShape, CAP_HEIGHT};
use p3_air::BaseAir;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_matrix::Dimensions;
use p3_util::log2_ceil_usize;
use shrugg_zkvm::machine::{Config, FriProfile, Proof, Val};

/// The salt elements the hiding MMCS appends to every committed row. `crate::dsl::hash::SALT_ELEMS`
/// is the same constant seen from the program's side.
pub const SALT_ELEMS: usize = 4;

/// The fourteen runs of the tape, in the order the program consumes them.
///
/// The names are the ones the tamper tests index by, so they are interface: a test naming
/// `Segment::CommitPhasePaths` is naming the words whose corruption must be refused at
/// `"commit phase root[i]"`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Segment {
    /// `tier`, the six declared log-heights (program, input, keccak, sha256, **public**, mem —
    /// constraint set 6's mandatory public table sits between the two optional hash heights and
    /// memory, matching the machine's argument order), `num_queries`, then one word per FRI
    /// round's `log_arity`. Read off the *proof* and pinned against the program's own shape word
    /// by word, so a proof of another shape is refused here rather than misparsed later.
    Header,
    /// The 34 inner public values (constraint set 6: `PC_ENTRY`, `TIER`, `OUT0..7`, `HC0..7`,
    /// `IN0..7`, then `PUB0..7` — the unsalted `H_PUB`, which for the empty public segment these
    /// fixtures prove is a prover-computed constant of the shape, carried as ordinary public
    /// values; no public-segment words enter the tape).
    PublicValues,
    /// The `main`, `permutation`, `quotient_chunks` and `random` caps: four times sixteen elements.
    Commitments,
    /// One extension element per instance that declares lookups.
    LookupTerminals,
    /// Per instance, `OpenedValuesWithLookups`' own field order with `base_opened_values` expanded
    /// in place: `trace_local`, `trace_next`, `preprocessed_local`, `preprocessed_next`,
    /// `quotient_chunks`, `random`, `permutation_local`, `permutation_next`.
    OpenedValues,
    /// The hiding wrapper's hidden halves, per round / matrix / point.
    RandomOpenings,
    /// Per FRI round: the commit cap (16) and the commit-phase PoW witness (1).
    FriCommits,
    /// `final_poly_len() = 1` extension element.
    FinalPoly,
    /// `query_pow_witness`.
    QueryPow,
    /// The bit decompositions `sample_bits` consumes: 64 bit words plus one canonicality hint per
    /// sampled element, in **sampling** order — the query proof-of-work check's element first (it
    /// is sampled before any query index), then one per query.
    QueryBits,
    /// Per query, per input round, per matrix: the opened row and its four salts.
    InputOpenings,
    /// Per query, per input round: the restored authentication path's siblings, four words a level.
    InputPaths,
    /// Per query, per commit-phase round: `arity − 1` sibling values, then the row's four salts —
    /// the commit-phase tree is a hiding MMCS too, so its leaf is `flatten_to_base(row) ‖ salt(4)`.
    CommitPhaseOpenings,
    /// Per query, per commit-phase round: the restored path's siblings.
    CommitPhasePaths,
}

/// The whole tape, plus where each segment starts and how long it is. The segments tile the tape
/// exactly, in order.
#[derive(Clone, Debug)]
pub struct WitnessTape {
    pub words: Vec<F>,
    pub segments: Vec<(Segment, usize, usize)>,
}

/// Why a proof could not be flattened. Every variant means the proof is not one this program
/// verifies, so `Machine::verify` would refuse it too.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TapeError {
    /// The transcript replay refused it, so there is no tape to build.
    Replay(ReplayError),
    /// A `ValMmcs` multiproof did not restore into per-query paths.
    Paths(String),
}

impl From<ReplayError> for TapeError {
    fn from(e: ReplayError) -> Self {
        TapeError::Replay(e)
    }
}

/// The tape under construction: words plus the segment table, so a segment cannot be closed without
/// its length being the number of words actually pushed.
struct Writer {
    words: Vec<F>,
    segments: Vec<(Segment, usize, usize)>,
    open: Option<(Segment, usize)>,
}

impl Writer {
    fn new() -> Self {
        Writer { words: Vec::new(), segments: Vec::new(), open: None }
    }
    fn begin(&mut self, s: Segment) {
        assert!(self.open.is_none(), "{s:?} opened while another segment is open");
        self.open = Some((s, self.words.len()));
    }
    fn end(&mut self) {
        let (s, start) = self.open.take().expect("no segment is open");
        self.segments.push((s, start, self.words.len() - start));
    }
    fn f(&mut self, v: F) {
        self.words.push(v);
    }
    fn usize(&mut self, v: usize) {
        self.words.push(F::from_usize(v));
    }
    fn base(&mut self, vs: &[Val]) {
        self.words.extend_from_slice(vs);
    }
    /// `c0` then `c1`, the order `BasedVectorSpace` reads an extension element in and the order
    /// `HINTE` writes its pair.
    fn ext(&mut self, v: EF) {
        self.words.extend_from_slice(v.as_basis_coefficients_slice());
    }
    fn exts(&mut self, vs: &[EF]) {
        for v in vs {
            self.ext(*v);
        }
    }
    /// A `MerkleCap` of four digests: sixteen elements in `roots()` order, which is the order the
    /// challenger absorbs them in.
    fn cap(&mut self, cap: &[[Val; 4]]) {
        assert_eq!(cap.len(), 1 << CAP_HEIGHT);
        for d in cap {
            self.base(d);
        }
    }
    /// The sixty-four little-endian bits of `v`'s canonical representative, then the inverse-or-zero
    /// hint the canonicality check needs — exactly what `DslChallenger::sample_bits` reads.
    fn sampled_bits(&mut self, v: u64) {
        for k in 0..64 {
            self.usize(((v >> k) & 1) as usize);
        }
        self.f(crate::dsl::transcript::canonicality_hint(v));
    }
}

/// The fourteen segments one proof contributes to a tape — the count [`SegmentRef`] grouping
/// relies on, and the number [`Writer`] always produces per proof because `write_proof` writes
/// exactly one of each [`Segment`].
pub const SEGMENTS_PER_PROOF: usize = 14;

/// One segment of one proof's region of a tape: which proof (in
/// [`WitnessTape::build_n`]'s argument order), which segment, where its words start, and how
/// many there are. The tamper tests index a word to corrupt by one of these.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SegmentRef {
    pub proof: usize,
    pub segment: Segment,
    pub start: usize,
    pub len: usize,
}

impl WitnessTape {
    /// Flattens one `Proof` in the order the program consumes it.
    pub fn build(
        profile: FriProfile,
        shape: &InnerShape,
        key: &InnerKey,
        proof: &Proof,
    ) -> Result<Self, TapeError> {
        Self::build_for(profile, shape, key, proof)
    }

    /// The tape of N proofs of one shape: one count word — the aggregate program's loop trip
    /// count — then each proof's fourteen segments in [`build`](WitnessTape::build)'s pinned
    /// order, consumed sequentially by the looped program (M5.3 ruling R2). A region is
    /// byte-identical to that proof's single-proof tape, so an N=1 tape is `[1] ‖ build(proof)`.
    ///
    /// Every proof must match the shape: the shape checks run over the whole set up front —
    /// cheapest refusal first, mirroring `InnerShape::matches`'s own order — so a wrong-shape
    /// proof is a `TapeError`, never a misparse or a half-built tape.
    pub fn build_n(
        profile: FriProfile,
        shape: &InnerShape,
        key: &InnerKey,
        proofs: &[Proof],
    ) -> Result<Self, TapeError> {
        Self::build_n_for(profile, shape, key, proofs)
    }

    /// [`WitnessTape::build`], generic over [`VerifierShape`] (M5.4, T5): the same fourteen
    /// segments for the rVM's own shape (`RvmShape`/`RvmKey`, an rVM `machine::Proof`) as for
    /// the RV32 machine's — the self-verifier's input tape.
    pub fn build_for<S: VerifierShape>(
        profile: FriProfile,
        shape: &S,
        key: &S::Key,
        proof: &S::Proof,
    ) -> Result<Self, TapeError>
    where
        S::Air: BaseAir<Val> + for<'a> p3_air::Air<p3_lookup::folder::VerifierConstraintFolderWithLookups<'a, Config>>,
    {
        let mut w = Writer::new();
        write_proof(&mut w, profile, shape, key, proof)?;
        Ok(WitnessTape { words: w.words, segments: w.segments })
    }

    /// [`WitnessTape::build_n`], generic over [`VerifierShape`]: the count word, then each
    /// proof's region in the pinned order.
    pub fn build_n_for<S: VerifierShape>(
        profile: FriProfile,
        shape: &S,
        key: &S::Key,
        proofs: &[S::Proof],
    ) -> Result<Self, TapeError>
    where
        S::Air: BaseAir<Val> + for<'a> p3_air::Air<p3_lookup::folder::VerifierConstraintFolderWithLookups<'a, Config>>,
    {
        for proof in proofs {
            if !shape.matches(proof) {
                return Err(ReplayError::Shape.into());
            }
        }
        let mut w = Writer::new();
        w.usize(proofs.len());
        for proof in proofs {
            write_proof(&mut w, profile, shape, key, proof)?;
        }
        Ok(WitnessTape { words: w.words, segments: w.segments })
    }

    /// The flat segment table as `(proof, segment, start, len)` per proof in order — every
    /// word of the tape past the count word covered exactly once. A single-proof tape is proof
    /// 0's fourteen; `segments` keeps its per-proof layout, so the single-proof call sites that
    /// `find` a segment by name are untouched.
    pub fn segment_refs(&self) -> Vec<SegmentRef> {
        self.segments
            .iter()
            .enumerate()
            .map(|(i, &(segment, start, len))| SegmentRef {
                proof: i / SEGMENTS_PER_PROOF,
                segment,
                start,
                len,
            })
            .collect()
    }
}

/// One proof's fourteen segments, appended to `w` in the program's consumption order — the
/// constructors' shared writer, generic over [`VerifierShape`] (M5.4, T5).
fn write_proof<S: VerifierShape>(
    w: &mut Writer,
    profile: FriProfile,
    shape: &S,
    key: &S::Key,
    proof: &S::Proof,
) -> Result<(), TapeError>
where
    S::Air: BaseAir<Val> + for<'a> p3_air::Air<p3_lookup::folder::VerifierConstraintFolderWithLookups<'a, Config>>,
{
        let r = replay(profile, shape, key, proof)?;
        let batch = proof.batch();
        let (rand_openings, fri) = &batch.opening_proof;
        let n = shape.instances();

        // 1 ── the proof's own declared shape, read off the proof (so a wrong-shape proof is
        // refused here, pinned against the program's own constants), then the profile's query
        // count and the replay's arity schedule.
        w.begin(Segment::Header);
        for &h in proof.tape_header().iter().chain(shape.header_shape_constants().iter()) {
            w.usize(h as usize);
        }
        w.usize(shape.num_queries());
        for &la in &r.log_arities {
            w.usize(la);
        }
        w.end();

        // 2 ── the inner public values.
        w.begin(Segment::PublicValues);
        for v in proof.public_values_u64() {
            w.f(Val::from_u64(*v));
        }
        w.end();

        // 3 ── the four caps, in the order the transcript observes them.
        w.begin(Segment::Commitments);
        let c = &batch.commitments;
        w.cap(c.main.roots());
        w.cap(c.permutation.as_ref().expect("this machine always has lookups").roots());
        w.cap(c.quotient_chunks.roots());
        w.cap(c.random.as_ref().expect("is_zk() == true").roots());
        w.end();

        // 4 ── one terminal per instance with lookups, in instance order.
        w.begin(Segment::LookupTerminals);
        for t in batch.lookup_terminals.iter().flatten() {
            w.ext(t.0);
        }
        w.end();

        // 5 ── the opened values.
        w.begin(Segment::OpenedValues);
        for i in 0..n {
            let inst = &batch.opened_values.instances[i];
            let b = &inst.base_opened_values;
            w.exts(&b.trace_local);
            w.exts(b.trace_next.as_deref().unwrap_or(&[]));
            w.exts(b.preprocessed_local.as_deref().unwrap_or(&[]));
            w.exts(b.preprocessed_next.as_deref().unwrap_or(&[]));
            for chunk in &b.quotient_chunks {
                w.exts(chunk);
            }
            w.exts(b.random.as_deref().unwrap_or(&[]));
            w.exts(&inst.permutation_local);
            w.exts(&inst.permutation_next);
        }
        w.end();

        // 6 ── the hiding wrapper's hidden halves, nested exactly as it re-joins them.
        w.begin(Segment::RandomOpenings);
        for round in rand_openings {
            for mat in round {
                for point in mat {
                    w.exts(point);
                }
            }
        }
        w.end();

        // 7 ── per FRI round, the commit cap and its PoW witness. `commit_proof_of_work_bits == 0`,
        // so the witness is *never observed* (`grinding_challenger.rs:44-49`); the program reads it
        // and discards it, which is why it is on the tape at all.
        w.begin(Segment::FriCommits);
        for (comm, witness) in fri.commit_phase_commits.iter().zip(&fri.commit_pow_witnesses) {
            w.cap(comm.roots());
            w.f(*witness);
        }
        w.end();

        // 8 ── the final polynomial: one coefficient, `log_final_poly_len == 0`.
        w.begin(Segment::FinalPoly);
        w.exts(&fri.final_poly);
        w.end();

        // 9 ── the query grinding witness.
        w.begin(Segment::QueryPow);
        w.f(fri.query_pow_witness);
        w.end();

        // 10 ── every decomposition `sample_bits` consumes, in sampling order: the PoW check's
        // element (sampled first, and only when the bit count is non-zero) then the query indices'.
        w.begin(Segment::QueryBits);
        if let Some(v) = r.pow_sample {
            w.sampled_bits(v);
        }
        for &v in &r.index_samples {
            w.sampled_bits(v);
        }
        w.end();

        // The pruned multiproofs, expanded into one full path per query — for the input rounds and
        // for the commit-phase rounds. Both are needed before segments 11–14 can be written, and
        // both are query-major on the tape, because the program walks one query to completion
        // before it reads the next.
        let val_mmcs = crate::shape::val_mmcs();
        let mut input_paths = Vec::with_capacity(r.input_rounds.len());
        for (round, geom) in r.input_rounds.iter().enumerate() {
            let opening = &fri.input_openings[round];
            let paths = shrugg_zkvm::machine::restore_paths_for_tests(
                val_mmcs,
                &geom.dims,
                &geom.indices,
                &opening.opened_values,
                &opening.opening_proof,
            );
            input_paths.push(paths);
        }
        let mut commit_paths = Vec::with_capacity(r.log_arities.len());
        let mut log_current = r.log_global_max_height;
        for (round, &log_arity) in r.log_arities.iter().enumerate() {
            let log_folded = log_current - log_arity;
            // The commit-phase tree is over `Challenge`, and `ExtensionMmcs` flattens each row into
            // its base coefficients before handing it to the inner (hiding) tree
            // (`p3-commit-0.7.0/src/adapters/extension_mmcs.rs`), so both the dimensions and the
            // opened rows are the base-field ones here.
            let dims = [Dimensions {
                width: (1 << log_arity) * <EF as BasedVectorSpace<Val>>::DIMENSION,
                height: 1 << log_folded,
            }];
            let opened: Vec<Vec<Vec<Val>>> = r.commit_rows[round]
                .iter()
                .map(|rows| {
                    rows.iter()
                        .map(|row| <EF as BasedVectorSpace<Val>>::flatten_to_base(row.clone()))
                        .collect()
                })
                .collect();
            commit_paths.push(shrugg_zkvm::machine::restore_paths_for_tests(
                val_mmcs,
                &dims,
                &r.commit_group_indices[round],
                &opened,
                &fri.commit_phase_openings[round].opening_proof,
            ));
            log_current = log_folded;
        }

        // 11 ── per query, per input round, per matrix: the opened row then its four salts, which is
        // the leaf message the hiding MMCS hashes (`hiding_mmcs.rs:232-275`).
        w.begin(Segment::InputOpenings);
        for q in 0..shape.num_queries() {
            for round in 0..r.input_rounds.len() {
                let opening = &fri.input_openings[round];
                let salts = &opening.opening_proof.0[q];
                for (m, row) in opening.opened_values[q].iter().enumerate() {
                    assert_eq!(salts[m].len(), SALT_ELEMS);
                    w.base(row);
                    w.base(&salts[m]);
                }
            }
        }
        w.end();

        // 12 ── the same rounds' restored paths, level 0 first.
        w.begin(Segment::InputPaths);
        for q in 0..shape.num_queries() {
            for paths in &input_paths {
                for sib in &paths[q].siblings {
                    w.base(sib);
                }
            }
        }
        w.end();

        // 13 ── per query, per commit-phase round: the `arity − 1` siblings that complete the row,
        // then the row's four salts.
        //
        // The salts are here because the commit-phase tree is a *hiding* MMCS too — `ChallengeMmcs`
        // is `ExtensionMmcs<Val, Challenge, ValMmcs>` and `ValMmcs` is the
        // `MerkleTreeHidingMmcs`, so its leaf message is `flatten_to_base(row) ‖ salt(4)` exactly as
        // an input round's is (`hiding_mmcs.rs:232-275`). Without them the program could not
        // recompute a commit-phase leaf at all.
        w.begin(Segment::CommitPhaseOpenings);
        for q in 0..shape.num_queries() {
            for step in &fri.commit_phase_openings {
                w.exts(&step.sibling_values[q]);
                // One matrix per commit-phase round, so one salt set per query.
                assert_eq!(step.opening_proof.0[q].len(), 1);
                assert_eq!(step.opening_proof.0[q][0].len(), SALT_ELEMS);
                w.base(&step.opening_proof.0[q][0]);
            }
        }
        w.end();

        // 14 ── and their restored paths.
        w.begin(Segment::CommitPhasePaths);
        for q in 0..shape.num_queries() {
            for paths in &commit_paths {
                for sib in &paths[q].siblings {
                    w.base(sib);
                }
            }
        }
        w.end();

        Ok(())
}

impl WitnessTape {
    pub fn len(&self) -> usize {
        self.words.len()
    }

    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// One line per segment: name, start, length. Printed by the layout test, and the first thing to
    /// look at when the program stops consuming the tape where it should.
    pub fn describe(&self) -> String {
        let mut s = format!("witness tape: {} words in {} segments\n", self.len(), self.segments.len());
        for (seg, start, len) in &self.segments {
            s += &format!("  {start:>8}  +{len:<8}  {seg:?}\n");
        }
        s
    }
}

/// How many Merkle levels a round of this geometry walks: `log2(padded max height) − cap_height`,
/// the loop count in `MerkleTreeMmcs::verify_batch` (`p3-merkle-tree-0.7.0/src/mmcs/batch.rs`).
///
/// Not used by the tape (a restored path's siblings are self-describing), but the program's query
/// phase needs it and it belongs next to the geometry it describes.
///
/// Both bounds are asserted rather than clamped. A round with no matrices, or one whose tallest tree
/// is shorter than the cap, is not a round this machine's PCS can produce (`cap_height = 2` and
/// every committed matrix is at least `2^(LOG_BLOWUP + 1)` rows tall) — and silently clamping to
/// zero levels would turn that into a walk that checks nothing.
pub fn levels_for(dims: &[Dimensions]) -> usize {
    let max_height =
        dims.iter().map(|d| d.height).max().expect("a committed round has at least one matrix");
    let log_max = log2_ceil_usize(max_height);
    assert!(
        log_max >= CAP_HEIGHT,
        "a round whose tallest tree is 2^{log_max} rows is shorter than the {CAP_HEIGHT}-level cap"
    );
    log_max - CAP_HEIGHT
}

/// The words one query occupies in [`Segment::InputOpenings`]: per round, per matrix, the opened row
/// and its four salts. The rounds are `coms_to_verify`' own order, so `&rounds[..k]` gives the offset
/// of round `k` inside a query's run.
pub fn per_query_rows(rounds: &[InputRound]) -> usize {
    rounds.iter().flat_map(|g| g.dims.iter()).map(|d| d.width + SALT_ELEMS).sum()
}

/// The Merkle levels one query walks across `rounds` — so `4 · per_query_levels(..)` is the words it
/// occupies in [`Segment::InputPaths`], and `&rounds[..k]` again gives round `k`'s offset.
pub fn per_query_levels(rounds: &[InputRound]) -> usize {
    rounds.iter().map(|g| levels_for(&g.dims)).sum()
}

/// The words one query occupies in [`Segment::CommitPhaseOpenings`]: per round, the `arity − 1`
/// sibling *extension* values (two words each) and then the query row's four salts.
pub fn open_stride(log_arities: &[usize]) -> usize {
    log_arities
        .iter()
        .map(|&a| ((1usize << a) - 1) * <EF as BasedVectorSpace<Val>>::DIMENSION + SALT_ELEMS)
        .sum()
}

/// The words one query occupies in [`Segment::CommitPhasePaths`]: four per Merkle level, over every
/// commit-phase round's own folded height.
pub fn path_stride(log_global_max_height: usize, log_arities: &[usize]) -> usize {
    let mut log_current = log_global_max_height;
    let mut words = 0usize;
    for &a in log_arities {
        log_current -= a;
        assert!(
            log_current >= CAP_HEIGHT,
            "a commit-phase round folded to 2^{log_current} rows, inside the {CAP_HEIGHT}-level cap"
        );
        words += (log_current - CAP_HEIGHT) * crate::dsl::DIGEST_ELEMS;
    }
    words
}
