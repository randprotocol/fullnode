//! The inner proof's *shape* and *key*: everything the verifier program is specialised to at build
//! time, and nothing that comes out of a proof.
//!
//! The plan's ruling: the verifier program is shape-specialised. The transcript needs every
//! instance's degree bits, trace width and quotient-chunk count *before* it reads anything, and
//! recomputing the inner preprocessed commitment in-circuit costs 3.1 M Poseidon2 permutations (the
//! spike's single most important finding), so both are compile-time constants of the program. One
//! program — and one program digest — per shape the chain aggregates.
//!
//! Nothing here is read off a `Proof`. [`InnerShape::of`] takes the declared heights (which the
//! *node* knows, from its own chain config and the bundle it is admitting) and derives the rest from
//! the machine: `chips`, `Machine::log_ext_degrees`, `get_log_num_quotient_chunks` and
//! `Machine::verifier_key` are all pure functions of the tier and those heights.
//! [`InnerShape::matches`] is the other direction — it says whether a given proof is one this
//! program was built for — and the program itself re-checks the same thing word by word off its
//! witness tape (`Segment::Header`), so a proof of the wrong shape is refused rather than
//! misparsed.

use crate::isa::F;
use p3_air::symbolic::AirLayout;
use p3_air::BaseAir;
use p3_commit::Pcs;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::LogUpGadget;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use p3_uni_stark::StarkGenericConfig;
use shrugg_zkvm::machine::{
    chips, Challenge, Chip, Config, FriProfile, Machine, Perm, Proof, Tier, Val,
};

/// `log_blowup`, from `research`'s `generic_config` (`research/src/machine.rs`). A literal there and
/// a literal here; `InnerShape::of` cannot read it back off a `FriParameters` because the `Config`'s
/// PCS keeps them private.
pub const LOG_BLOWUP: usize = 3;
/// `log_final_poly_len`, same source: the final polynomial is a single coefficient.
pub const LOG_FINAL_POLY_LEN: usize = 0;
/// `max_log_arity`, same source: FRI folds by at most 8 per round.
pub const MAX_LOG_ARITY: usize = 3;
/// `num_random_codewords`, same source: every committed matrix but the preprocessed one carries four
/// extra hiding columns, and every opened point four extra hidden values.
pub const NUM_RANDOM_CODEWORDS: usize = 4;
/// `cap_height`: a commitment is a [`p3_symmetric::MerkleCap`] of `1 << CAP_HEIGHT` digests, and a
/// Merkle walk stops that many levels below the root.
pub const CAP_HEIGHT: usize = 2;
/// The public-values slot: `chips()[1]` is the cpu table and it owns all of them.
pub const PV_INSTANCE: usize = 1;

/// The hash-domain tag of [`inner_vk_digest`]. `shrugg_zkvm::notes::domain` is occupied through 14 and
/// `crate::isa::RVM_PROGRAM_DOMAIN` is 15, so 16 is the next free tag; all three share one
/// permutation, so a collision would let one construction's digest stand in for another's.
pub const RVM_VK_DOMAIN: u64 = 16;

/// The shape of one inner proof: the declared heights, plus everything the batch transcript and the
/// opening argument need that follows from them.
///
/// `PartialEq` is the load-bearing derive: the exit test asserts every fixture proof shares one
/// shape, which is what makes one program's measurement a statement about all of them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InnerShape {
    pub tier: usize,
    pub program_log_height: u8,
    pub input_log_height: u8,
    pub keccak_log_height: u8,
    pub sha256_log_height: u8,
    /// Constraint set 6: the mandatory public table's declared height. No `0` "no such table"
    /// value exists — the public instance is in every batch, last in `chips()` order.
    pub public_log_height: u8,
    pub mem_log_height: u8,
    pub num_queries: usize,
    pub query_pow_bits: usize,
    /// Per instance, `log2(|extended trace domain|)` — `Machine::log_ext_degrees`.
    pub degree_bits: Vec<usize>,
    /// Per instance, the main trace width (`BaseAir::width`), *without* the hiding wrapper's four
    /// random codewords.
    pub widths: Vec<usize>,
    /// Per instance, the preprocessed width; `0` when the chip declares none.
    pub preprocessed_widths: Vec<usize>,
    /// Per instance, before ZK doubling: the committed chunk count is `(1 << x) << 1`.
    pub log_num_quotient_chunks: Vec<usize>,
    /// Per instance, `= aux_width - 1`: the permutation trace is one accumulator column plus one
    /// fraction column per lookup, and is `0` wide when the chip declares no lookups.
    pub num_lookups: Vec<usize>,
    pub num_public_values: Vec<usize>,
    /// Per instance, whether the constraints read the next row of the main / preprocessed trace —
    /// which is what decides whether that round opens one point or two.
    pub main_next: Vec<bool>,
    pub pre_next: Vec<bool>,
    /// The global preprocessed commitment's matrix order: `matrix_to_instance[m]` is the instance
    /// whose preprocessed trace is matrix `m`.
    pub preprocessed_matrix_to_instance: Vec<usize>,
    /// The FRI arity schedule this program is built for, one entry per commit-phase round.
    ///
    /// It is **derived, not read off a proof**: `p3_fri::compute_log_arity_for_round` is a pure
    /// function of the current height, the next input height, the final height and
    /// `max_log_arity`, and every matrix in the opening argument has log-height
    /// `degree_bits[i] + LOG_BLOWUP` (the quotient-chunk domains split down to `ext_db - is_zk`
    /// and the ZK doubling puts them back, and the preprocessed matrices carry the instance's own
    /// `degree_bits`). So the schedule is a function of the distinct degree bits alone — which is
    /// what makes it part of the shape rather than of the witness.
    pub log_arities: Vec<usize>,
}

/// The inner preprocessed commitment: a `MerkleCap` of four digests, a constant of the machine at
/// this shape. Sixteen field elements the program carries as immediates.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct InnerKey {
    pub cap: [[F; 4]; 4],
}

/// Why a shape could not be built for these heights.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ShapeError {
    /// `check_declared_heights` refused them, so no proof of this shape can exist.
    DeclaredHeights(String),
    /// The machine's preprocessed commitment is not a four-digest cap, so this crate's
    /// `CAP_HEIGHT` no longer matches `research`'s.
    CapShape(usize),
    /// The derived FRI schedule does not roll in every distinct input height, so it is not the
    /// schedule `p3_fri::prover::commit_phase` would build for these degree bits — and a program
    /// built from it would read a commit-phase round the proof does not have. A shape error rather
    /// than an assertion because [`InnerShape::try_of`] is the fallible entry a node calls with
    /// numbers it did not choose.
    FriSchedule { rolled_in: usize, heights: usize },
}

impl InnerShape {
    /// The shape of any proof at `(profile, tier, the six declared heights)`.
    ///
    /// Panics when the heights are ones `Machine::verify` would refuse outright
    /// (`check_declared_heights`), because a verifier program for a shape no proof can have is a
    /// build-time mistake, not a runtime condition. Use [`InnerShape::try_of`] for the fallible
    /// form.
    pub fn of(
        profile: FriProfile,
        tier: Tier,
        program_log_height: u8,
        input_log_height: u8,
        keccak_log_height: u8,
        sha256_log_height: u8,
        public_log_height: u8,
        mem_log_height: u8,
    ) -> Self {
        Self::try_of(
            profile,
            tier,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
            mem_log_height,
        )
        .expect("a verifier program is built for a shape a proof can actually have")
    }

    /// [`InnerShape::of`], reporting rather than panicking.
    pub fn try_of(
        profile: FriProfile,
        tier: Tier,
        program_log_height: u8,
        input_log_height: u8,
        keccak_log_height: u8,
        sha256_log_height: u8,
        public_log_height: u8,
        mem_log_height: u8,
    ) -> Result<Self, ShapeError> {
        shrugg_zkvm::machine::check_declared_heights(
            tier,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
            mem_log_height,
        )
        .map_err(|e| ShapeError::DeclaredHeights(format!("{e:?}")))?;

        let machine = machine(profile);
        let is_zk = machine.config.is_zk();
        let airs = chips(tier, keccak_log_height, sha256_log_height);
        let degree_bits = machine.log_ext_degrees(
            tier,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
            mem_log_height,
        );
        let common = machine.verifier_key(
            tier,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
        );

        let widths: Vec<usize> = airs.iter().map(BaseAir::<Val>::width).collect();
        let num_public_values: Vec<usize> =
            airs.iter().map(BaseAir::<Val>::num_public_values).collect();
        let main_next: Vec<bool> = airs
            .iter()
            .map(|a| !BaseAir::<Val>::main_next_row_columns(a).is_empty())
            .collect();
        let pre_next: Vec<bool> = airs
            .iter()
            .map(|a| !BaseAir::<Val>::preprocessed_next_row_columns(a).is_empty())
            .collect();
        let num_lookups: Vec<usize> = common.lookups.iter().map(|l| l.len()).collect();

        // The preprocessed widths and matrix order come from `CommonData`, exactly as
        // `verify_batch`'s own precompute loop takes them (`BaseAir::preprocessed_width` would
        // agree, but the transcript observes *these*, and a disagreement is a proof-shape error
        // rather than something the program should paper over).
        let (preprocessed_widths, preprocessed_matrix_to_instance, cap_roots) =
            match &common.preprocessed {
                Some(global) => (
                    global
                        .instances
                        .iter()
                        .map(|m| m.as_ref().map_or(0, |m| m.width))
                        .collect::<Vec<_>>(),
                    global.matrix_to_instance.clone(),
                    global.commitment.num_roots(),
                ),
                None => (vec![0; airs.len()], Vec::new(), 1 << CAP_HEIGHT),
            };
        if cap_roots != 1 << CAP_HEIGHT {
            return Err(ShapeError::CapShape(cap_roots));
        }

        let lookup_gadget = LogUpGadget::new();
        let log_arities = fri_schedule(&degree_bits)?;

        let mut shape = InnerShape {
            tier: tier.0,
            program_log_height,
            input_log_height,
            keccak_log_height,
            sha256_log_height,
            public_log_height,
            mem_log_height,
            num_queries: profile.num_queries(),
            query_pow_bits: profile.pow_bits(),
            degree_bits,
            widths,
            preprocessed_widths,
            num_lookups,
            num_public_values,
            main_next,
            pre_next,
            preprocessed_matrix_to_instance,
            log_arities,
            // Filled in immediately below. `air_layout` reads three of the fields above, so the
            // shape has to exist before the layouts can be built from it — and building them from
            // the locals instead would be a second copy of `air_layout`'s body, which is exactly
            // what that method exists to prevent.
            log_num_quotient_chunks: Vec::new(),
        };
        shape.log_num_quotient_chunks = airs
            .iter()
            .enumerate()
            .map(|(i, air)| {
                p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, Challenge, _, _>(
                    air,
                    shape.air_layout(i, air),
                    1usize << (shape.degree_bits[i] - is_zk),
                    &common.lookups[i],
                    is_zk,
                    &lookup_gadget,
                )
            })
            .collect();
        Ok(shape)
    }

    /// The number of batch instances.
    pub fn instances(&self) -> usize {
        self.degree_bits.len()
    }

    /// The FRI profile this shape was built for.
    ///
    /// Recovered from `(num_queries, query_pow_bits)` rather than stored, because those two numbers
    /// *are* the profile — `FriProfile` has exactly two variants and they agree on neither. The only
    /// constructor is [`InnerShape::try_of`], which sets both from a profile, so the lookup is total
    /// for every shape that exists.
    ///
    /// It is needed because a `Machine` is the only way to reach `CommonData` (below), and the
    /// program builder is handed a shape, not a profile.
    pub fn profile(&self) -> FriProfile {
        [FriProfile::Test, FriProfile::Production]
            .into_iter()
            .find(|p| p.num_queries() == self.num_queries && p.pow_bits() == self.query_pow_bits)
            .expect("a shape's query count and PoW bits come from one of the two profiles")
    }

    /// The `AirLayout` `verify_batch`'s precompute loop builds for instance `i`: the widths the
    /// symbolic builder lays its variables out from.
    ///
    /// The permutation fields are deliberately left at `Default`: `get_symbolic_constraints` and
    /// `get_log_num_quotient_chunks` both overwrite them from the instance's own lookup contexts, so
    /// filling them here would be a second, divergeable source for the same three numbers.
    pub fn air_layout(&self, i: usize, air: &Chip) -> AirLayout {
        AirLayout {
            preprocessed_width: self.preprocessed_widths[i],
            main_width: self.widths[i],
            num_public_values: self.num_public_values[i],
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(air),
            ..Default::default()
        }
    }

    /// The batch's `CommonData`: the preprocessed commitment and, the reason the constraint emitter
    /// wants it, every instance's lookup contexts.
    ///
    /// A pure function of the tier, the declared heights and the profile — `Machine::verifier_key`
    /// is seeded from a fixed constant precisely so that it is — and cached inside the shared
    /// [`machine`], so calling it per instance costs one hash-map lookup.
    /// `#[doc(hidden)]` — the lookup contexts and preprocessed commitment, nameable by tests
    /// that exercise the constraint emitter directly (the house test-hook pattern, like
    /// `shrugg_zkvm::machine::val_mmcs_for_tests`).
    #[doc(hidden)]
    pub fn common_data(&self) -> std::sync::Arc<p3_batch_stark::CommonData<Config>> {
        machine(self.profile()).verifier_key(
            Tier(self.tier),
            self.program_log_height,
            self.input_log_height,
            self.keccak_log_height,
            self.sha256_log_height,
            self.public_log_height,
        )
    }

    /// `max(degree_bits) + LOG_BLOWUP`, the height every query index is sampled from — and, by the
    /// cross-check `verify_fri` performs, also `Σ log_arities + LOG_BLOWUP + LOG_FINAL_POLY_LEN`.
    pub fn log_global_max_height(&self) -> usize {
        self.degree_bits.iter().copied().max().expect("a batch has instances") + LOG_BLOWUP
    }

    /// The canonical flattening hashed into the vk digest. Every number the program is specialised
    /// to appears here exactly once, so two different shapes cannot share a digest.
    pub fn shape_words(&self) -> Vec<F> {
        let mut w = vec![
            self.tier,
            self.program_log_height as usize,
            self.input_log_height as usize,
            self.keccak_log_height as usize,
            self.sha256_log_height as usize,
            self.public_log_height as usize,
            self.mem_log_height as usize,
            self.num_queries,
            self.query_pow_bits,
            self.instances(),
        ];
        for i in 0..self.instances() {
            w.push(self.degree_bits[i]);
            w.push(self.widths[i]);
            w.push(self.preprocessed_widths[i]);
            w.push(self.log_num_quotient_chunks[i]);
            w.push(self.num_lookups[i]);
            w.push(self.num_public_values[i]);
            w.push(self.main_next[i] as usize);
            w.push(self.pre_next[i] as usize);
        }
        w.extend(self.log_arities.iter().copied());
        w.into_iter().map(F::from_usize).collect()
    }

    /// The `Header` segment's contents, which the program reads and pins word by word:
    /// `[tier, program_log_height, input_log_height, keccak_log_height, sha256_log_height,
    ///   public_log_height, mem_log_height, num_queries, log_arities…]`.
    ///
    /// These are exactly the words a *proof* carries (or, for `num_queries`, that the profile
    /// fixes and the schedule that the proof's `commit_phase_openings` declare), so the program's
    /// first act is to compare the proof's own declared shape against its own — which is why a
    /// proof of another shape is refused at `"header word k"` rather than silently misparsed.
    pub fn header_words(&self) -> Vec<F> {
        let mut w = vec![
            self.tier,
            self.program_log_height as usize,
            self.input_log_height as usize,
            self.keccak_log_height as usize,
            self.sha256_log_height as usize,
            self.public_log_height as usize,
            self.mem_log_height as usize,
            self.num_queries,
        ];
        w.extend(self.log_arities.iter().copied());
        w.into_iter().map(F::from_usize).collect()
    }

    /// Whether `proof` is one a program of this shape verifies: the declared heights, the instance
    /// count, the degree bits and the arity schedule.
    ///
    /// This is the host's pre-flight check. The program does not rely on it — it re-derives the same
    /// comparison from its witness tape — but a node that runs it first can refuse a
    /// wrong-shape proof without building a tape.
    pub fn matches(&self, proof: &Proof) -> bool {
        proof.tier.0 == self.tier
            && proof.program_log_height == self.program_log_height
            && proof.input_log_height == self.input_log_height
            && proof.keccak_log_height == self.keccak_log_height
            && proof.sha256_log_height == self.sha256_log_height
            && proof.public_log_height == self.public_log_height
            && proof.mem_log_height == self.mem_log_height
            && proof.batch.degree_bits == self.degree_bits
            && proof.public_values.len() == self.num_public_values[PV_INSTANCE]
            // `Machine::verify` insists on the canonical representative, so a proof it refuses is
            // one this crate refuses too. The rVM cannot make the check itself — its tape carries
            // field elements, and `x` and `x + p` are the same one — so it belongs here, on the host
            // that deserialised the bytes.
            && proof.public_values.iter().all(|x| *x < <Val as p3_field::PrimeField64>::ORDER_U64)
            && proof_log_arities(proof) == self.log_arities
    }
}

/// The arity schedule of a proof, as `verify_fri` extracts it (bounds unchecked here; the tape
/// builder and the program both compare it against the shape's own).
pub(crate) fn proof_log_arities(proof: &Proof) -> Vec<usize> {
    proof
        .batch
        .opening_proof
        .1
        .commit_phase_openings
        .iter()
        .map(|o| o.log_arity as usize)
        .collect()
}

/// The commit-phase arity schedule implied by a set of extended degree bits.
///
/// `p3_fri::prover::commit_phase`'s loop, with the heights it folds over: the reduced openings live
/// at the distinct input log-heights `degree_bits[i] + LOG_BLOWUP`, descending, and each round folds
/// by `compute_log_arity_for_round(current, next_input, final, max)` — the very function the prover
/// calls, so this is the reference schedule and not a second guess at it.
fn fri_schedule(degree_bits: &[usize]) -> Result<Vec<usize>, ShapeError> {
    let mut heights: Vec<usize> = degree_bits.iter().map(|d| d + LOG_BLOWUP).collect();
    heights.sort_unstable_by(|a, b| b.cmp(a));
    heights.dedup();

    let log_final_height = LOG_BLOWUP + LOG_FINAL_POLY_LEN;
    let mut log_current = heights[0];
    let mut next = 1usize; // the next *unconsumed* input height
    let mut out = Vec::new();
    while log_current > log_final_height {
        let log_arity = p3_fri::compute_log_arity_for_round(
            log_current,
            heights.get(next).copied(),
            log_final_height,
            MAX_LOG_ARITY,
        );
        out.push(log_arity);
        log_current -= log_arity;
        if heights.get(next) == Some(&log_current) {
            next += 1;
        }
    }
    if next != heights.len() {
        return Err(ShapeError::FriSchedule { rolled_in: next, heights: heights.len() });
    }
    Ok(out)
}

impl InnerKey {
    /// The machine's preprocessed `MerkleCap` at this shape: sixteen field elements, recomputable by
    /// anyone who knows the tier and the declared heights and nothing else (`Machine::verifier_key`
    /// is seeded from a fixed constant precisely so that it is).
    pub fn of(profile: FriProfile, shape: &InnerShape) -> Self {
        let machine = machine(profile);
        let common = machine.verifier_key(
            Tier(shape.tier),
            shape.program_log_height,
            shape.input_log_height,
            shape.keccak_log_height,
            shape.sha256_log_height,
            shape.public_log_height,
        );
        let roots = common
            .preprocessed
            .as_ref()
            .expect("this machine's batch always has preprocessed columns")
            .commitment
            .roots();
        assert_eq!(roots.len(), 1 << CAP_HEIGHT, "cap_height is 2");
        InnerKey { cap: std::array::from_fn(|i| roots[i]) }
    }

    /// The cap's sixteen elements in `roots()` order — the order the challenger absorbs them in and
    /// the order [`inner_vk_digest`] hashes them in.
    pub fn flatten(&self) -> Vec<F> {
        self.cap.iter().flatten().copied().collect()
    }
}

/// The published identity of an inner verifier: `PaddingFreeSponge<Perm, 8, 4, 4>` over
/// `[RVM_VK_DOMAIN] ‖ shape_words ‖ cap(16)`, four field elements.
///
/// Spec §4.4 calls this an "inner verifier key digest (8 elements)"; a digest on this machine is
/// four (spec §12 erratum 1), and a verifier key here is a sixteen-element cap plus a shape rather
/// than a digest at all — so both halves are hashed into one value the node and the program compute
/// with the same function. The program recomputes it from its own compile-time constants and
/// `PUBLIC`s it, so the aggregate says which inner verifier it ran.
///
/// Generic over [`VerifierShape`] (M5.4, T5): the RV32 machine's shape and the rVM's own
/// [`RvmShape`] hash through the same call.
pub fn inner_vk_digest<S: VerifierShape>(shape: &S, key: &S::Key) -> [F; 4] {
    let sponge = PaddingFreeSponge::<Perm, 8, 4, 4>::new(shrugg_zkvm::machine::permutation());
    let mut msg = vec![F::from_u64(RVM_VK_DOMAIN)];
    msg.extend(shape.shape_words());
    msg.extend(key.flatten());
    sponge.hash_iter(msg)
}

/// The one `Machine` this crate verifies against, per profile, built once.
///
/// Amortising it is not a micro-optimisation: `Machine::verifier_key` recomputes the whole
/// preprocessed commitment (the range, nibble and Poseidon2 round-constant tables' Merkle trees) on
/// a cache miss, and its cache lives *in the machine*. A fresh `Machine` per [`InnerShape::of`],
/// [`InnerKey::of`] and [`crate::reference::replay`] call would pay that three times over for every
/// proof, which at Task 6's fifty is the difference between seconds and minutes.
///
/// It is a *verifier's* machine: the only entropy `Machine::new` draws is for the proving side of the
/// config, which nothing here touches. Anything that proves builds its own.
pub(crate) fn machine(profile: FriProfile) -> &'static Machine {
    static TEST: std::sync::OnceLock<Machine> = std::sync::OnceLock::new();
    static PRODUCTION: std::sync::OnceLock<Machine> = std::sync::OnceLock::new();
    let cell = match profile {
        FriProfile::Test => &TEST,
        FriProfile::Production => &PRODUCTION,
    };
    cell.get_or_init(|| Machine::new(profile))
}

/// The value MMCS the input and commit-phase Merkle checks run through, built once.
///
/// `val_mmcs_for_tests` constructs a fresh Poseidon2 permutation (128 rounds of constants drawn from
/// an RNG) on every call, and this crate needs it in the replay and twice more in the tape builder.
pub(crate) fn val_mmcs() -> &'static shrugg_zkvm::machine::ValMmcs {
    static MMCS: std::sync::OnceLock<shrugg_zkvm::machine::ValMmcs> = std::sync::OnceLock::new();
    MMCS.get_or_init(shrugg_zkvm::machine::val_mmcs_for_tests)
}

/// `natural_domain_for_degree`, which is all of the PCS the shape layer needs.
pub(crate) fn natural_domain(
    cfg: &Config,
    size: usize,
) -> p3_field::coset::TwoAdicMultiplicativeCoset<Val> {
    <shrugg_zkvm::machine::Pcs as Pcs<Challenge, shrugg_zkvm::machine::Challenger>>::natural_domain_for_degree(
        cfg.pcs(),
        size,
    )
}

// ─────────────────────────────────────────────────────────────── the shape trait (M5.4, T5)

use p3_batch_stark::BatchProof;

/// One proof's carrier across the two machines' `Proof` types: the batch and the public values
/// every shape's replay and tape builder read, and the declared-shape words the tape's `Header`
/// segment opens with, in the shape's own order. Implemented for `shrugg_zkvm::machine::Proof`
/// (the RV32 machine's) and `crate::machine::Proof` (the rVM's own).
pub trait ProofBatch {
    fn batch(&self) -> &BatchProof<Config>;
    fn public_values_u64(&self) -> &[u64];
    /// The declared-shape words, in the shape's own order, read off the proof (so a wrong-shape
    /// proof is refused at the header the program pins against its own constants).
    fn tape_header(&self) -> Vec<u64>;
}

impl ProofBatch for Proof {
    fn batch(&self) -> &BatchProof<Config> {
        &self.batch
    }
    fn public_values_u64(&self) -> &[u64] {
        &self.public_values
    }
    fn tape_header(&self) -> Vec<u64> {
        vec![
            self.tier.0 as u64,
            self.program_log_height as u64,
            self.input_log_height as u64,
            self.keccak_log_height as u64,
            self.sha256_log_height as u64,
            self.public_log_height as u64,
            self.mem_log_height as u64,
        ]
    }
}

impl ProofBatch for crate::machine::Proof {
    fn batch(&self) -> &BatchProof<Config> {
        &self.batch
    }
    fn public_values_u64(&self) -> &[u64] {
        &self.public_values
    }
    fn tape_header(&self) -> Vec<u64> {
        vec![
            self.tier.0 as u64,
            self.reg_log_height as u64,
            self.ram_log_height as u64,
            self.poseidon2_log_height as u64,
            self.reduce_log_height as u64,
        ]
    }
}

/// A shape's preprocessed-commitment key: the sixteen field elements the program carries as
/// immediates, and the `flatten` the vk digest hashes.
pub trait ShapeKey: Clone + PartialEq + Eq + std::fmt::Debug {
    fn cap(&self) -> &[[F; 4]; 4];
    fn flatten(&self) -> Vec<F>;
}

impl ShapeKey for InnerKey {
    fn cap(&self) -> &[[F; 4]; 4] {
        &self.cap
    }
    fn flatten(&self) -> Vec<F> {
        self.cap.iter().flatten().copied().collect()
    }
}

/// A shape a verifier program is specialised to, across the two machines (M5.4, T5): the
/// per-instance numbers the batch transcript needs, the FRI schedule, the declared-shape pin
/// the tape's header carries, and the program-log height of the committed program.
/// [`InnerShape`] (the RV32 machine's proofs) and [`RvmShape`] (the rVM's own) implement it;
/// the program (`programs::verify_rv32_with`), the replay (`reference::replay`) and the tape
/// (`witness::WitnessTape`) are generic over it.
pub trait VerifierShape: Clone + PartialEq + Eq + std::fmt::Debug {
    type Proof: ProofBatch;
    type Air;
    type Key: ShapeKey;

    fn instances(&self) -> usize;
    fn profile(&self) -> FriProfile;
    fn widths(&self) -> &[usize];
    fn num_public_values(&self) -> &[usize];
    fn preprocessed_widths(&self) -> &[usize];
    fn main_next(&self) -> &[bool];
    fn pre_next(&self) -> &[bool];
    /// The global preprocessed commitment's matrix order: `matrix_to_instance[m]` is the
    /// instance whose preprocessed trace is matrix `m`.
    fn preprocessed_matrix_to_instance(&self) -> &[usize];
    fn degree_bits(&self) -> &[usize];
    fn log_num_quotient_chunks(&self) -> &[usize];
    fn num_lookups(&self) -> &[usize];
    fn num_queries(&self) -> usize;
    fn query_pow_bits(&self) -> usize;
    fn log_arities(&self) -> &[usize];
    fn log_global_max_height(&self) -> usize;
    /// The instance that owns the batch's public values (`PV_INSTANCE` on the RV32 machine,
    /// `machine::PUBLIC_VALUES_INDEX` on the rVM).
    fn pv_instance(&self) -> usize;
    fn program_log_height(&self) -> u8;
    fn air_layout(&self, i: usize, air: &Self::Air) -> AirLayout;
    fn common_data(&self) -> std::sync::Arc<p3_batch_stark::CommonData<Config>>;
    /// The real chip set the constraint evaluation runs against (`chips()`'s order — instance
    /// order).
    fn constraint_chips(&self) -> Vec<Self::Air>;
    fn shape_words(&self) -> Vec<F>;
    fn header_words(&self) -> Vec<F>;
    fn matches(&self, proof: &Self::Proof) -> bool;
    /// The header words that come from the shape rather than the proof, spliced into the tape's
    /// `Header` segment after the proof's own [`ProofBatch::tape_header`] words and before
    /// `num_queries`. The rVM's `program_log_height` (a constant of the committed program — its
    /// proofs do not declare it); empty on the RV32 machine, whose proofs declare every word.
    fn header_shape_constants(&self) -> Vec<u64>;
}

impl VerifierShape for InnerShape {
    type Proof = Proof;
    type Air = Chip;
    type Key = InnerKey;

    fn instances(&self) -> usize {
        self.instances()
    }
    fn profile(&self) -> FriProfile {
        self.profile()
    }
    fn widths(&self) -> &[usize] {
        &self.widths
    }
    fn num_public_values(&self) -> &[usize] {
        &self.num_public_values
    }
    fn preprocessed_widths(&self) -> &[usize] {
        &self.preprocessed_widths
    }
    fn main_next(&self) -> &[bool] {
        &self.main_next
    }
    fn pre_next(&self) -> &[bool] {
        &self.pre_next
    }
    fn preprocessed_matrix_to_instance(&self) -> &[usize] {
        &self.preprocessed_matrix_to_instance
    }
    fn degree_bits(&self) -> &[usize] {
        &self.degree_bits
    }
    fn log_num_quotient_chunks(&self) -> &[usize] {
        &self.log_num_quotient_chunks
    }
    fn num_lookups(&self) -> &[usize] {
        &self.num_lookups
    }
    fn num_queries(&self) -> usize {
        self.num_queries
    }
    fn query_pow_bits(&self) -> usize {
        self.query_pow_bits
    }
    fn log_arities(&self) -> &[usize] {
        &self.log_arities
    }
    fn log_global_max_height(&self) -> usize {
        self.log_global_max_height()
    }
    fn pv_instance(&self) -> usize {
        PV_INSTANCE
    }
    fn program_log_height(&self) -> u8 {
        self.program_log_height
    }
    fn air_layout(&self, i: usize, air: &Chip) -> AirLayout {
        self.air_layout(i, air)
    }
    fn common_data(&self) -> std::sync::Arc<p3_batch_stark::CommonData<Config>> {
        self.common_data()
    }
    fn constraint_chips(&self) -> Vec<Chip> {
        chips(Tier(self.tier), self.keccak_log_height, self.sha256_log_height)
    }
    fn shape_words(&self) -> Vec<F> {
        self.shape_words()
    }
    fn header_words(&self) -> Vec<F> {
        self.header_words()
    }
    fn matches(&self, proof: &Proof) -> bool {
        self.matches(proof)
    }
    fn header_shape_constants(&self) -> Vec<u64> {
        Vec::new()
    }
}

/// The arity schedule of a proof, as `verify_fri` extracts it (bounds unchecked here; the tape
/// builder and the program both compare it against the shape's own) — [`proof_log_arities`]
/// generic over the proof carrier, which both machines' `Proof` types are.
pub(crate) fn proof_log_arities_generic<P: ProofBatch>(proof: &P) -> Vec<usize> {
    proof
        .batch()
        .opening_proof
        .1
        .commit_phase_openings
        .iter()
        .map(|o| o.log_arity as usize)
        .collect()
}

// ─────────────────────────────────────────────────────────────── the rVM's own shape (M5.4, T5)

/// The shape of one **rVM proof**: its declared heights, the committed program, and everything
/// the batch transcript and the opening argument derive from them — [`InnerShape`]'s sibling
/// for the self-verifier (M5.4's R7: a sibling, not a generalisation; the program, replay and
/// tape are shared through [`VerifierShape`], which is where the sharing lives).
///
/// The header a proof of this shape declares is
/// `[tier, reg_log_height, ram_log_height, poseidon2_log_height, reduce_log_height,
///   program_log_height, num_queries, log_arities…]`
/// — the rVM proof's own fields first, then the committed program's height (a constant of the
/// shape, since the program table is preprocessed), then the profile's query count and the
/// schedule. `PartialEq` is load-bearing exactly as [`InnerShape`]'s is — implemented by hand
/// because `isa::Program` has none: two shapes are equal when every scalar and every vector
/// agrees, and the committed programs have the same digest (the program's identity *is* its
/// digest — the preprocessed table commits to it).
#[derive(Clone, Debug)]
pub struct RvmShape {
    pub profile: FriProfile,
    pub tier: usize,
    pub reg_log_height: u8,
    pub ram_log_height: u8,
    pub poseidon2_log_height: u8,
    pub reduce_log_height: u8,
    /// The committed program — the self-verifier's inner verifier is a *specific* program, so
    /// the shape carries it (the program table is preprocessed; its commitment is the key's cap).
    pub program: std::sync::Arc<crate::isa::Program>,
    pub program_log_height: u8,
    pub num_queries: usize,
    pub query_pow_bits: usize,
    /// Per instance, `log2(|extended trace domain|)` — `machine::log_ext_degrees`.
    pub degree_bits: Vec<usize>,
    pub widths: Vec<usize>,
    pub preprocessed_widths: Vec<usize>,
    pub log_num_quotient_chunks: Vec<usize>,
    pub num_lookups: Vec<usize>,
    pub num_public_values: Vec<usize>,
    pub main_next: Vec<bool>,
    pub pre_next: Vec<bool>,
    pub preprocessed_matrix_to_instance: Vec<usize>,
    /// The FRI arity schedule, derived from the distinct degree bits exactly as
    /// [`InnerShape`]'s is.
    pub log_arities: Vec<usize>,
}

impl PartialEq for RvmShape {
    fn eq(&self, other: &Self) -> bool {
        self.profile == other.profile
            && self.tier == other.tier
            && self.reg_log_height == other.reg_log_height
            && self.ram_log_height == other.ram_log_height
            && self.poseidon2_log_height == other.poseidon2_log_height
            && self.reduce_log_height == other.reduce_log_height
            && self.program.digest() == other.program.digest()
            && self.program_log_height == other.program_log_height
            && self.num_queries == other.num_queries
            && self.query_pow_bits == other.query_pow_bits
            && self.degree_bits == other.degree_bits
            && self.widths == other.widths
            && self.preprocessed_widths == other.preprocessed_widths
            && self.log_num_quotient_chunks == other.log_num_quotient_chunks
            && self.num_lookups == other.num_lookups
            && self.num_public_values == other.num_public_values
            && self.main_next == other.main_next
            && self.pre_next == other.pre_next
            && self.preprocessed_matrix_to_instance == other.preprocessed_matrix_to_instance
            && self.log_arities == other.log_arities
    }
}
impl Eq for RvmShape {}

/// The rVM preprocessed commitment for `(program, tier, reduce)`: sixteen field elements,
/// recomputable by anyone through `machine::Machine::verifier_key` (seeded from the fixed
/// `KEY_SEED` precisely so that it is).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RvmKey {
    pub cap: [[F; 4]; 4],
}

impl RvmShape {
    /// The shape of any rVM proof at `(profile, program, tier, the four declared heights)`.
    ///
    /// Panics when the heights are ones `machine::Machine::verify` would refuse outright
    /// (`check_declared_heights`) — a verifier program for a shape no proof can have is a
    /// build-time mistake. [`RvmShape::try_of`] is the fallible form.
    pub fn of(
        profile: FriProfile,
        program: &std::sync::Arc<crate::isa::Program>,
        tier: crate::machine::Tier,
        reg_log_height: u8,
        ram_log_height: u8,
        poseidon2_log_height: u8,
        reduce_log_height: u8,
    ) -> Self {
        Self::try_of(profile, program, tier, reg_log_height, ram_log_height, poseidon2_log_height, reduce_log_height)
            .expect("a verifier program is built for a shape a proof can actually have")
    }

    /// [`RvmShape::of`], reporting rather than panicking — [`InnerShape::try_of`]'s exact
    /// construction over the rVM's own `chips`, `log_ext_degrees` and `verifier_key`.
    pub fn try_of(
        profile: FriProfile,
        program: &std::sync::Arc<crate::isa::Program>,
        tier: crate::machine::Tier,
        reg_log_height: u8,
        ram_log_height: u8,
        poseidon2_log_height: u8,
        reduce_log_height: u8,
    ) -> Result<Self, ShapeError> {
        crate::machine::check_declared_heights(
            tier,
            reg_log_height,
            ram_log_height,
            poseidon2_log_height,
            reduce_log_height,
        )
        .map_err(|e| ShapeError::DeclaredHeights(format!("{e:?}")))?;

        let m = rvm_machine(profile);
        let is_zk = m.config.is_zk() as usize;
        let airs = crate::machine::chips(program, tier, reduce_log_height);
        let degree_bits = crate::machine::log_ext_degrees(
            program,
            tier,
            reg_log_height,
            ram_log_height,
            poseidon2_log_height,
            reduce_log_height,
        );
        let common = m.verifier_key(program, tier, reduce_log_height != 0);

        let widths: Vec<usize> = airs.iter().map(BaseAir::<Val>::width).collect();
        let num_public_values: Vec<usize> =
            airs.iter().map(BaseAir::<Val>::num_public_values).collect();
        let main_next: Vec<bool> = airs
            .iter()
            .map(|a| !BaseAir::<Val>::main_next_row_columns(a).is_empty())
            .collect();
        let pre_next: Vec<bool> = airs
            .iter()
            .map(|a| !BaseAir::<Val>::preprocessed_next_row_columns(a).is_empty())
            .collect();
        let num_lookups: Vec<usize> = common.lookups.iter().map(|l| l.len()).collect();

        // The preprocessed widths and matrix order come from `CommonData`, exactly as
        // `verify_batch`'s own precompute loop takes them (`InnerShape::try_of`'s rule,
        // verbatim).
        let (preprocessed_widths, preprocessed_matrix_to_instance, cap_roots) =
            match &common.preprocessed {
                Some(global) => (
                    global
                        .instances
                        .iter()
                        .map(|m| m.as_ref().map_or(0, |m| m.width))
                        .collect::<Vec<_>>(),
                    global.matrix_to_instance.clone(),
                    global.commitment.num_roots(),
                ),
                None => (vec![0; airs.len()], Vec::new(), 1 << CAP_HEIGHT),
            };
        if cap_roots != 1 << CAP_HEIGHT {
            return Err(ShapeError::CapShape(cap_roots));
        }

        let lookup_gadget = LogUpGadget::new();
        let log_arities = fri_schedule(&degree_bits)?;

        let mut shape = RvmShape {
            profile,
            tier: tier.0,
            reg_log_height,
            ram_log_height,
            poseidon2_log_height,
            reduce_log_height,
            program: program.clone(),
            program_log_height: crate::machine::program_log_height(program.instrs.len()),
            num_queries: profile.num_queries(),
            query_pow_bits: profile.pow_bits(),
            degree_bits,
            widths,
            preprocessed_widths,
            log_num_quotient_chunks: Vec::new(),
            num_lookups,
            num_public_values,
            main_next,
            pre_next,
            preprocessed_matrix_to_instance,
            log_arities,
        };
        shape.log_num_quotient_chunks = airs
            .iter()
            .enumerate()
            .map(|(i, air)| {
                p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, Challenge, _, _>(
                    air,
                    shape.air_layout(i, air),
                    1usize << (shape.degree_bits[i] - is_zk),
                    &common.lookups[i],
                    m.config.is_zk(),
                    &lookup_gadget,
                )
            })
            .collect();
        Ok(shape)
    }

    /// The `AirLayout` `verify_batch`'s precompute loop builds for instance `i` —
    /// [`InnerShape::air_layout`], verbatim.
    pub fn air_layout(&self, i: usize, air: &crate::machine::Chip) -> AirLayout {
        AirLayout {
            preprocessed_width: self.preprocessed_widths[i],
            main_width: self.widths[i],
            num_public_values: self.num_public_values[i],
            num_periodic_columns: BaseAir::<Val>::num_periodic_columns(air),
            ..Default::default()
        }
    }

    /// The batch's `CommonData` (the lookup contexts and the preprocessed commitment), a pure
    /// function of `(program, tier, reduce)` — `InnerShape::common_data`'s role.
    #[doc(hidden)]
    pub fn common_data(&self) -> std::sync::Arc<p3_batch_stark::CommonData<Config>> {
        rvm_machine(self.profile).verifier_key(
            &self.program,
            crate::machine::Tier(self.tier),
            self.reduce_log_height != 0,
        )
    }

    /// `max(degree_bits) + LOG_BLOWUP`.
    pub fn log_global_max_height(&self) -> usize {
        self.degree_bits.iter().copied().max().expect("a batch has instances") + LOG_BLOWUP
    }

    /// The canonical flattening hashed into the vk digest: the rVM prefix
    /// `[tier, program, reg, ram, poseidon2, reduce, num_queries, query_pow_bits, instances]`,
    /// then the per-instance eight-tuple, then the arity schedule — [`InnerShape::shape_words`]'s
    /// layout, minus the two RV32-only heights (input, keccak, sha256, public, mem → the rVM's
    /// reg, ram, poseidon2, reduce).
    pub fn shape_words(&self) -> Vec<F> {
        let mut w = vec![
            self.tier,
            self.program_log_height as usize,
            self.reg_log_height as usize,
            self.ram_log_height as usize,
            self.poseidon2_log_height as usize,
            self.reduce_log_height as usize,
            self.num_queries,
            self.query_pow_bits,
            self.degree_bits.len(),
        ];
        for i in 0..self.degree_bits.len() {
            w.push(self.degree_bits[i]);
            w.push(self.widths[i]);
            w.push(self.preprocessed_widths[i]);
            w.push(self.log_num_quotient_chunks[i]);
            w.push(self.num_lookups[i]);
            w.push(self.num_public_values[i]);
            w.push(self.main_next[i] as usize);
            w.push(self.pre_next[i] as usize);
        }
        w.extend(self.log_arities.iter().copied());
        w.into_iter().map(F::from_usize).collect()
    }

    /// The `Header` segment's contents, which the self-verifier program reads and pins word by
    /// word: `[tier, reg, ram, poseidon2, reduce, program_log_height, num_queries,
    /// log_arities…]`. The program's first act is to compare the proof's declared shape against
    /// its own — a proof of another shape is refused at `"header word k"`.
    pub fn header_words(&self) -> Vec<F> {
        let mut w = vec![
            self.tier,
            self.reg_log_height as usize,
            self.ram_log_height as usize,
            self.poseidon2_log_height as usize,
            self.reduce_log_height as usize,
            self.program_log_height as usize,
            self.num_queries,
        ];
        w.extend(self.log_arities.iter().copied());
        w.into_iter().map(F::from_usize).collect()
    }

    /// Whether `proof` is one a program of this shape verifies: the declared heights, the
    /// instance count (degree bits), the canonical public values and the arity schedule —
    /// [`InnerShape::matches`]'s rule, over the rVM proof's own fields.
    pub fn matches(&self, proof: &crate::machine::Proof) -> bool {
        proof.tier.0 == self.tier
            && proof.reg_log_height == self.reg_log_height
            && proof.ram_log_height == self.ram_log_height
            && proof.poseidon2_log_height == self.poseidon2_log_height
            && proof.reduce_log_height == self.reduce_log_height
            && proof.batch.degree_bits == self.degree_bits
            && proof.public_values.len() == self.num_public_values[crate::machine::PUBLIC_VALUES_INDEX]
            && proof.public_values.iter().all(|x| *x < <Val as p3_field::PrimeField64>::ORDER_U64)
            && proof_log_arities_generic(proof) == self.log_arities
    }
}

impl RvmKey {
    /// The rVM's preprocessed `MerkleCap` at `(program, tier, reduce)` — [`InnerKey::of`]'s
    /// construction over `machine::Machine::verifier_key`.
    pub fn of(_profile: FriProfile, shape: &RvmShape) -> Self {
        let common = shape.common_data();
        let roots = common
            .preprocessed
            .as_ref()
            .expect("this machine's batch always has preprocessed columns")
            .commitment
            .roots();
        assert_eq!(roots.len(), 1 << CAP_HEIGHT, "cap_height is 2");
        RvmKey { cap: std::array::from_fn(|i| roots[i]) }
    }
}

impl ShapeKey for RvmKey {
    fn cap(&self) -> &[[F; 4]; 4] {
        &self.cap
    }
    fn flatten(&self) -> Vec<F> {
        self.cap.iter().flatten().copied().collect()
    }
}

impl VerifierShape for RvmShape {
    type Proof = crate::machine::Proof;
    type Air = crate::machine::Chip;
    type Key = RvmKey;

    fn instances(&self) -> usize {
        self.degree_bits.len()
    }
    fn profile(&self) -> FriProfile {
        self.profile
    }
    fn widths(&self) -> &[usize] {
        &self.widths
    }
    fn num_public_values(&self) -> &[usize] {
        &self.num_public_values
    }
    fn preprocessed_widths(&self) -> &[usize] {
        &self.preprocessed_widths
    }
    fn main_next(&self) -> &[bool] {
        &self.main_next
    }
    fn pre_next(&self) -> &[bool] {
        &self.pre_next
    }
    fn preprocessed_matrix_to_instance(&self) -> &[usize] {
        &self.preprocessed_matrix_to_instance
    }
    fn degree_bits(&self) -> &[usize] {
        &self.degree_bits
    }
    fn log_num_quotient_chunks(&self) -> &[usize] {
        &self.log_num_quotient_chunks
    }
    fn num_lookups(&self) -> &[usize] {
        &self.num_lookups
    }
    fn num_queries(&self) -> usize {
        self.num_queries
    }
    fn query_pow_bits(&self) -> usize {
        self.query_pow_bits
    }
    fn log_arities(&self) -> &[usize] {
        &self.log_arities
    }
    fn log_global_max_height(&self) -> usize {
        self.log_global_max_height()
    }
    fn pv_instance(&self) -> usize {
        crate::machine::PUBLIC_VALUES_INDEX
    }
    fn program_log_height(&self) -> u8 {
        self.program_log_height
    }
    fn air_layout(&self, i: usize, air: &crate::machine::Chip) -> AirLayout {
        self.air_layout(i, air)
    }
    fn common_data(&self) -> std::sync::Arc<p3_batch_stark::CommonData<Config>> {
        self.common_data()
    }
    fn constraint_chips(&self) -> Vec<crate::machine::Chip> {
        crate::machine::chips(&self.program, crate::machine::Tier(self.tier), self.reduce_log_height)
    }
    fn shape_words(&self) -> Vec<F> {
        self.shape_words()
    }
    fn header_words(&self) -> Vec<F> {
        self.header_words()
    }
    fn matches(&self, proof: &crate::machine::Proof) -> bool {
        self.matches(proof)
    }
    fn header_shape_constants(&self) -> Vec<u64> {
        vec![self.program_log_height as u64]
    }
}

/// The one rVM `machine::Machine` this crate's self-verifier shapes are built against, per
/// profile, built once — [`machine`]'s twin (`verifier_key`'s preprocessed recomputation is a
/// cache-miss cost, amortised in the machine's own cache).
pub(crate) fn rvm_machine(profile: FriProfile) -> &'static crate::machine::Machine {
    static TEST: std::sync::OnceLock<crate::machine::Machine> = std::sync::OnceLock::new();
    static PRODUCTION: std::sync::OnceLock<crate::machine::Machine> = std::sync::OnceLock::new();
    let cell = match profile {
        FriProfile::Test => &TEST,
        FriProfile::Production => &PRODUCTION,
    };
    cell.get_or_init(|| crate::machine::Machine::new(profile))
}
