//! The node's aggregating executor: every `ConfidentialExecutor` method the zkVM already
//! implements, delegated to [`ZkExecutor`], plus the block-aggregation surface (spec §4 steps
//! 7–8) backed by the vendored rVM (`randprotocol-rvm`).
//!
//! This type exists because of the crate graph, not preference: `randprotocol-rvm` depends on
//! `randprotocol-zkvm` (an rVM verifier program is specialised to the zkVM's own proof format), so
//! the real aggregate methods cannot live on `ZkExecutor` without a crate cycle. `ZkExecutor`'s
//! own aggregate arms therefore return `ConfidentialError::AggregationUnsupported`, and the
//! node builds this wrapper instead — `node::executor_for_profile` never hands out a bare
//! `ZkExecutor`.

use randprotocol_core::confidential::{ConfidentialError, ConfidentialExecutor};
use randprotocol_core::ledger::aggregation::{AggregationError, TreeConfig, TreeDigests};
use randprotocol_core::notes::{BundleDigestInput, Word8};
use randprotocol_core::program::{CallOutcome, ProgramRecord};
use randprotocol_core::types::{CoveredBundle, DeclaredShape};
use randprotocol_rvm::aggregate::{aggregate_program, AggregateProof, InnerVerifierKey};
use randprotocol_rvm::shape::{InnerKey, InnerShape};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::FriProfile;

/// The counter behind [`AggExecutor::verification_count`] — see its doc comment.
static AGGREGATE_VERIFICATIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One admitted shape's aggregate program, built once (the interface review's INTERFACE-5): the
/// inner verifier key, the program, its digest (step 7b's genesis-pin compare), and the rVM's
/// N ceiling for it (`machine::max_reduce_n`: the most inner proofs whose reduce-chip rows fit
/// `REDUCE_MAX_LOG_HEIGHT` — circuits `recursion/docs/06-phase3-fold-reduce.md` §3; 5 at the
/// production bundle shape, 26 at the test fixture shape).
struct BuiltProgram {
    vk: InnerVerifierKey,
    program: randprotocol_rvm::isa::Program,
    digest: [u64; 4],
    max_n: u64,
}

/// A declared shape as a map key — `DeclaredShape` itself is not `Hash`, and is core's type.
type ShapeKey = (u8, u8, u8, u8, u8, u8, u8, u8);

fn shape_key(s: &DeclaredShape) -> ShapeKey {
    let profile = match s.profile {
        randprotocol_core::types::FriProfile::Test => 0,
        randprotocol_core::types::FriProfile::Production => 1,
    };
    (
        profile,
        s.tier,
        s.program_log_height,
        s.input_log_height,
        s.keccak_log_height,
        s.sha256_log_height,
        s.public_log_height,
        s.mem_log_height,
    )
}

/// How many shapes' programs the memo keeps. A chain admits one shape at activation (spec
/// §2.3), and admission reaches the executor only with a shape step 6 matched against the
/// genesis list, so this bound is never met in practice; it exists so no caller can grow the
/// map without limit — past it a shape is built and used, not kept.
const MAX_BUILT_PROGRAMS: usize = 8;

/// One `aggregation_tree` section's rebuild (tree aggregation, circuits docs/08 §4–§5): the
/// inner key, the leaf and per-level step shapes (each carrying its program), the key list the
/// recompute publishes level by level, the digests 7b and the startup check compare with the
/// genesis pins, and whether the last listed level is a fixed point — what lets a tree deeper
/// than the list reuse it (R3). A pure function of a genesis constant, so built once.
struct BuiltTree {
    inner: InnerVerifierKey,
    shapes: randprotocol_rvm::aggregate::TreeShapes,
    keys: randprotocol_rvm::aggregate::TreeKeys,
    digests: TreeDigests,
    /// `None` when `max_depth` is within the list (no level repeats the last entry, so whether
    /// it is a fixed point is never asked); otherwise the rVM's verdict.
    fixed_point: Option<bool>,
}

/// How many tree sections the memo keeps — a chain has one; the bound is [`MAX_BUILT_PROGRAMS`]'s.
const MAX_BUILT_TREES: usize = 4;

/// The rVM's mirror of core's `RvmHeights` (core never names the rVM; the tier is a `Tier`).
pub fn rvm_heights(h: randprotocol_core::ledger::aggregation::RvmHeights) -> randprotocol_rvm::shape::RvmHeights {
    randprotocol_rvm::shape::RvmHeights {
        tier: randprotocol_rvm::machine::Tier(h.tier as usize),
        reg_log_height: h.reg_log_height,
        ram_log_height: h.ram_log_height,
        poseidon2_log_height: h.poseidon2_log_height,
        reduce_log_height: h.reduce_log_height,
    }
}

/// The executor the node runs: `ZkExecutor` inside, one rVM `Machine` beside it (its 64-entry
/// verifier-key FIFO is what `warm_aggregation` fills and every `verify_aggregate` then reuses),
/// and the admitted shapes' aggregate programs, built once each.
pub struct AggExecutor {
    inner: ZkExecutor,
    rvm: randprotocol_rvm::machine::Machine,
    programs: std::sync::Mutex<std::collections::HashMap<ShapeKey, std::sync::Arc<BuiltProgram>>>,
    /// Program builds this executor has run — the memo's instrument for its test.
    program_builds: std::sync::atomic::AtomicUsize,
    /// The `aggregation_tree` sections' rebuilds, keyed by a digest over the whole section (its
    /// shape, sizes, heights and pins), so two sections differing anywhere never share one.
    trees: std::sync::Mutex<std::collections::HashMap<[u8; 32], std::sync::Arc<BuiltTree>>>,
    /// Tree rebuilds this executor has run (the tree memo's instrument).
    tree_builds: std::sync::atomic::AtomicUsize,
}

impl AggExecutor {
    pub fn new(profile: FriProfile) -> AggExecutor {
        AggExecutor {
            inner: ZkExecutor::new(profile),
            rvm: randprotocol_rvm::machine::Machine::new(profile),
            programs: std::sync::Mutex::new(std::collections::HashMap::new()),
            program_builds: std::sync::atomic::AtomicUsize::new(0),
            trees: std::sync::Mutex::new(std::collections::HashMap::new()),
            tree_builds: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// How many tree sections this executor has rebuilt.
    pub fn tree_builds(&self) -> usize {
        self.tree_builds.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The section's rebuild, memoised: `TreeShapes::build` over the pinned leaf and per-level
    /// heights (the leaf program is the memoised flat program of the shape), the key list, and
    /// the digests. Refused as `BadDeclaredShape`, before any key is compared, when the rVM could
    /// never serve the section: an empty step list; a leaf size past the rVM's N ceiling for the
    /// shape (3a's deferred M6 — production N ≤ 5, `machine::max_reduce_n`); a pinned reduce height
    /// that is not canonical for its program (the leaf at N = L, every step at N = 2, as
    /// `verify_n` insists, so no honest proof could declare it); or a `max_depth` past the listed
    /// levels whose last entry is not a fixed point (R3: deeper levels repeat it, and a step that
    /// does not verify its own proofs makes those depths unprovable). Built outside the lock,
    /// as `built_program` is. Production: minutes (three programs and their keys).
    fn built_tree(&self, tree: &TreeConfig) -> Result<std::sync::Arc<BuiltTree>, ConfidentialError> {
        use p3_field::PrimeField64;
        let memo_key = *blake3::hash(&bincode::serialize(tree).expect("a TreeConfig serializes")).as_bytes();
        if let Some(hit) = self.trees.lock().expect("the tree memo").get(&memo_key) {
            return Ok(hit.clone());
        }
        let unservable = |m: String| ConfidentialError::BadDeclaredShape(format!("aggregation_tree: {m}"));
        let leaf_program = self.built_program(&tree.shape)?;
        if tree.leaf_size == 0 || tree.leaf_size as u64 > leaf_program.max_n {
            return Err(unservable(format!(
                "leaf_size {} is outside 1..={}, the rVM's N ceiling for this shape (the reduce chip's REDUCE_MAX_LOG_HEIGHT)",
                tree.leaf_size, leaf_program.max_n
            )));
        }
        let inner = leaf_program.vk.clone();
        let steps: Vec<randprotocol_rvm::shape::RvmHeights> = tree.steps.iter().map(|s| rvm_heights(s.heights)).collect();
        let shapes = randprotocol_rvm::aggregate::TreeShapes::build(zkvm_profile(tree.shape.profile), &inner, rvm_heights(tree.leaf), &steps)
            .map_err(|e| unservable(format!("{e:?}")))?;
        let canonical = |what: String, program: &randprotocol_rvm::isa::Program, n: u64, pinned: u8| {
            match randprotocol_rvm::machine::canonical_reduce_log_height(program, n) {
                Some(h) if h == pinned => Ok(()),
                h => Err(unservable(format!("{what} pins reduce height {pinned}; the canonical one at N = {n} is {h:?}"))),
            }
        };
        canonical("the leaf".into(), &shapes.leaf.program, tree.leaf_size as u64, tree.leaf.reduce_log_height)?;
        for (k, s) in shapes.steps.iter().enumerate() {
            canonical(format!("level {}", k + 1), &s.program, randprotocol_rvm::programs::TREE_ARITY, tree.steps[k].heights.reduce_log_height)?;
        }
        let fixed_point = (tree.max_depth as usize > tree.steps.len()).then(|| shapes.fixed_point());
        if fixed_point == Some(false) {
            return Err(unservable(format!(
                "max_depth {} is past the {} listed levels and the last is not a fixed point (R3): depths beyond the list are unprovable",
                tree.max_depth,
                tree.steps.len()
            )));
        }
        let keys = shapes.keys();
        let u = |d: [randprotocol_rvm::isa::F; 4]| d.map(|f| f.as_canonical_u64());
        let digests = TreeDigests {
            vk_leaf: u(keys.vk_leaf),
            steps: shapes.steps.iter().zip(&keys.step_keys).map(|(s, k)| (u(s.program.digest()), u(*k))).collect(),
        };
        self.tree_builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let built = std::sync::Arc::new(BuiltTree { inner, shapes, keys, digests, fixed_point });
        let mut memo = self.trees.lock().expect("the tree memo");
        if memo.len() < MAX_BUILT_TREES {
            memo.entry(memo_key).or_insert_with(|| built.clone());
        }
        Ok(built)
    }

    /// The tree root's header (step 7a's executor half): the decode, the canonical encoding, then
    /// the exact tier pinned for the root's level — `aggregate_header`'s discipline with the
    /// pinned tier in place of `admitted_tiers`, so a root at any other tier builds nothing — and
    /// then the level's other four pinned heights (review m4): an honest root of level `d`
    /// declares exactly `step_at(d).heights`, so any other declaration is refused off the header,
    /// before any key work.
    fn aggregate_header_tree(
        &self,
        proof: &[u8],
        pinned: randprotocol_core::ledger::aggregation::RvmHeights,
    ) -> Result<randprotocol_rvm::machine::Proof, ConfidentialError> {
        let p: randprotocol_rvm::machine::Proof = postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        if p.to_bytes() != proof {
            return Err(ConfidentialError::MalformedProof);
        }
        if p.tier.0 != pinned.tier as usize {
            return Err(ConfidentialError::InvalidAggregateProof(format!(
                "tree root at tier {}; its level is pinned at tier {}",
                p.tier.0, pinned.tier
            )));
        }
        let declared = (p.reg_log_height, p.ram_log_height, p.poseidon2_log_height, p.reduce_log_height);
        let want = (pinned.reg_log_height, pinned.ram_log_height, pinned.poseidon2_log_height, pinned.reduce_log_height);
        if declared != want {
            return Err(ConfidentialError::InvalidAggregateProof(format!(
                "tree root declares heights reg/ram/poseidon2/reduce {declared:?}; its level is pinned at {want:?}"
            )));
        }
        Ok(p)
    }

    /// The shape's aggregate program, memoised (INTERFACE-5). Step 7b's digest compare and step
    /// 8's verify each rebuilt the inner key and the program — seconds of DSL emission, twice
    /// per aggregate, on the admission worker and again at every block apply — for a value that
    /// is a pure function of a genesis constant. Built outside the lock: two first callers may
    /// both build, and the second's insert is a no-op; nobody waits on a build under a lock.
    fn built_program(&self, shape: &DeclaredShape) -> Result<std::sync::Arc<BuiltProgram>, ConfidentialError> {
        use p3_field::PrimeField64;
        let key = shape_key(shape);
        if let Some(hit) = self.programs.lock().expect("the program memo").get(&key) {
            return Ok(hit.clone());
        }
        let vk = Self::inner_key(shape)?;
        let program = aggregate_program(&vk);
        self.program_builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let digest = program.digest().map(|f| f.as_canonical_u64());
        // The ceiling is the rVM's own function of the program (phase 3's reduce chip runs a fixed
        // row count per inner proof), not a constant re-derived here.
        let max_n = randprotocol_rvm::machine::max_reduce_n(&program);
        let built = std::sync::Arc::new(BuiltProgram { vk, program, digest, max_n });
        let mut memo = self.programs.lock().expect("the program memo");
        if memo.len() < MAX_BUILT_PROGRAMS {
            memo.entry(key).or_insert_with(|| built.clone());
        }
        Ok(built)
    }

    /// How many aggregate programs this executor has built (INTERFACE-5's instrument).
    pub fn program_builds(&self) -> usize {
        self.program_builds.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The header half of the aggregate checks (INTERFACE-5): the decode, the canonical
    /// encoding and the admitted tier — everything that needs no program — shared by
    /// `check_aggregate_header` (admission, before step 7b) and `verify_aggregate` itself.
    fn aggregate_header(&self, proof: &[u8]) -> Result<randprotocol_rvm::machine::Proof, ConfidentialError> {
        let rvm_proof: randprotocol_rvm::machine::Proof =
            postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        // Canonical encoding only, as `randprotocol_zkvm::executor::decode_canonical` insists for
        // every bundle and call proof: postcard ignores trailing bytes and accepts overlong
        // varints, so a padded or re-encoded aggregate would otherwise verify under another txid.
        if rvm_proof.to_bytes() != proof {
            return Err(ConfidentialError::MalformedProof);
        }
        // The tier, before any key work (audit v3, AGG-3). Everything after it — the program
        // build, `verify_aggregate`'s `verifier_key` — is seconds to a minute of work that an
        // *invalid* proof could otherwise buy at an unwarmed tier, on the consensus loop at block
        // apply. The admitted set is the spec's, per profile.
        // Read as what it is (the rescan's ZKQ-2): the tier is a `usize` off the wire, and `as u8`
        // wrapped 277 into 21 — an admitted test tier. A tier no `u8` holds is no admitted tier.
        let tier = u8::try_from(rvm_proof.tier.0).map_err(|_| {
            ConfidentialError::InvalidAggregateProof(format!(
                "aggregate proof at tier {}; this chain admits {:?}",
                rvm_proof.tier.0,
                admitted_tiers(self.rvm.profile)
            ))
        })?;
        check_tier(self.rvm.profile, tier)?;
        Ok(rvm_proof)
    }

    /// Process-wide count of real rVM aggregate verifications this process has run — the
    /// sealed-sync cluster test's instrument for "one rVM verification per sealed window" (it
    /// reads the delta across a fresh node's sync, in the same process). Incremented only on
    /// this real path, never by the stub executor.
    pub fn verification_count() -> usize {
        AGGREGATE_VERIFICATIONS.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The rVM's own shape types for a registered declared shape: the fallible
    /// `InnerShape::try_of` (a genesis file's heights are numbers this node did not choose —
    /// exactly what `try_of` is for) and the startup-derived preprocessed cap.
    fn inner_key(shape: &DeclaredShape) -> Result<InnerVerifierKey, ConfidentialError> {
        let s = inner_shape(shape)?;
        Ok(InnerVerifierKey { key: InnerKey::of(zkvm_profile(shape.profile), &s), shape: s })
    }
}

/// The refusal every aggregate/tree path gives an inner proof that declares a modq table
/// (constraint set 9, circuits Task 9b): the vendored recursion verifier (`recursion/src`, the
/// aggregate program) does not know the MODQ chip, so it can verify only chip-free inner proofs.
pub const INNER_MODQ_REFUSAL: &str = "an inner proof declares a modq table; the aggregation verifier is chip-free";

/// Whether a zkVM proof may be an aggregate's or a tree's inner proof: `modq_log_height == 0`
/// (`NO_MODQ`), else [`INNER_MODQ_REFUSAL`] as `InvalidAggregateProof`, before anything reaches
/// the rVM. Every place an inner proof's header is decoded runs it — [`covered_bundle_of`] (the
/// covered records `verify_aggregate` and `verify_tree`, its bottom-up recompute included, are
/// handed: `Storage::covered_record`, the pruning pass) and the aggregator's own cover assembly
/// (`rand-node aggregate`'s `decode_inner_proofs`). `DeclaredShape` has no modq field, so a
/// covered record cannot carry the declaration past this point. Auth proofs (msauth included)
/// are never aggregated, so a multisig spend never meets it; and a bundle declaring a modq table
/// is refused at admission by the zkVM's exact pin, so on an honest chain no stored bundle can.
pub fn check_inner_chip_free(proof: &randprotocol_zkvm::machine::Proof) -> Result<(), ConfidentialError> {
    if proof.modq_log_height != 0 {
        return Err(ConfidentialError::InvalidAggregateProof(INNER_MODQ_REFUSAL.into()));
    }
    Ok(())
}

/// The covered-bundle record of an inner proof (spec §6.2): its `pv::NUM` public values and its
/// declared shape, read off the header — after [`check_inner_chip_free`]. `MalformedProof` for a
/// public-value vector of another length.
pub fn covered_bundle_of(
    proof: &randprotocol_zkvm::machine::Proof,
    profile: randprotocol_core::types::FriProfile,
) -> Result<CoveredBundle, ConfidentialError> {
    check_inner_chip_free(proof)?;
    let public_values: [u64; randprotocol_core::types::pv::NUM] =
        proof.public_values.clone().try_into().map_err(|_| ConfidentialError::MalformedProof)?;
    Ok(CoveredBundle {
        public_values,
        shape: DeclaredShape {
            profile,
            tier: proof.tier.0 as u8,
            program_log_height: proof.program_log_height,
            input_log_height: proof.input_log_height,
            keccak_log_height: proof.keccak_log_height,
            sha256_log_height: proof.sha256_log_height,
            public_log_height: proof.public_log_height,
            mem_log_height: proof.mem_log_height,
        },
    })
}

/// The rVM's `InnerShape` for a declared shape, through the fallible `try_of`.
fn inner_shape(shape: &DeclaredShape) -> Result<InnerShape, ConfidentialError> {
    InnerShape::try_of(
        zkvm_profile(shape.profile),
        randprotocol_zkvm::machine::Tier(shape.tier as usize),
        shape.program_log_height,
        shape.input_log_height,
        shape.keccak_log_height,
        shape.sha256_log_height,
        shape.public_log_height,
        shape.mem_log_height,
    )
    .map_err(|e| ConfidentialError::BadDeclaredShape(format!("{e:?}")))
}

/// Whether the rVM can build an inner verifier key for an admitted shape — the half of the
/// genesis check core cannot run (the interface review's IFACE-9: core's `check_aggregation`
/// pins the bundle header, but only the node can name `InnerShape::try_of`). `rand-node
/// genesis` runs it on every `--admitted-shape` before a hash is printed; a shape that fails it
/// could never be verified against, so no aggregate could ever be admitted on the chain.
pub fn check_admitted_shape(shape: &DeclaredShape) -> Result<(), ConfidentialError> {
    inner_shape(shape).map(|_| ())
}

/// `randprotocol-core`'s ledger-side mirror enum to the machine's own (R6: the ledger never names a
/// zkvm type; the two have exactly the same variants).
fn zkvm_profile(profile: randprotocol_core::types::FriProfile) -> FriProfile {
    match profile {
        randprotocol_core::types::FriProfile::Test => FriProfile::Test,
        randprotocol_core::types::FriProfile::Production => FriProfile::Production,
    }
}

/// The rVM tiers an aggregate proof may land at, per FRI profile (spec §3.3: "the register
/// admits the rVM tiers {21, 22, 23} for the one registered inner shape; a proof at any other
/// tier is invalid" — the constraint-set-8 rungs). The phase-2 row cuts (circuits `75b7893`,
/// `recursion/docs/04-phase2-row-cuts.md`) moved every rung one tier down: production N=1 lands
/// at tier 20 (893 880 rows), N=2 at 21, N=3 and N=4 at 22; the test profile's N=1/2/3 at
/// 18/19/20. Phase 3 (circuits `recursion/docs/06-phase3-fold-reduce.md`, docs/02 "The
/// N-economics at the phase-3 tiers") keeps the sets: production N=1 at 20 (585 960 rows), N=2–3
/// at 21, N=4–5 at 22 — and stops there, at the reduce chip's N ceiling (production N ≤ 5,
/// `check_n_ceiling`; (at phase 3) tier 22 would have held N ≤ 7 by cpu rows); test N=1 at 18, N=2–3 at 19, N=4–6 at
/// 20 (by the row model; not measured). The rate-¼ profile (docs/07) moves no tier.
///
/// rVM phase 4 (Merkle spans, circuits `recursion/docs/09-phase4-spans.md` §5, re-pinned with the
/// MODQ chip at circuits `57fb9dc`) moved production one tier down again: one inner verification
/// is 315 391 rows, so N=1 lands at **tier 19**, N=2–3 at 20 (632 175 / 948 071 rows emulated
/// before the MODQ re-pin) and N=4–5 at 21; the reduce chip's N ≤ 5 ceiling did not move, so tier
/// 22 admits nothing a valid production aggregate can be and is refused. Production was therefore
/// {19, 20, 21} (docs/09 §5's recommendation). Test: N=1 and N=2 at 18, N=3 at 19, so {18, 19, 20}
/// still covers it.
///
/// rVM phase 5 (circuits `b3e21d9`, `recursion/docs/10-phase5-n2-tier19.md` §5–§6: four program
/// cuts, no ISA or AIR change, the rVM keys unchanged) brings one inner verification to 235 418
/// rows, so production N=1 lands at **tier 18** (235 744 rows), N=2 at 19 (471 105), N=3 at 20
/// (706 466; N=4 projected 20) and N=5 at 21; the N ≤ 5 ceiling did not move, so tier 22 still
/// admits nothing. Production is therefore **{18, 19, 20, 21}** — four rungs, tier 18 now one of
/// them. Test aggregates are 88 486 / 176 589 / 264 692 rows (tiers 18 / 18 / 19), so {18, 19, 20}
/// is unchanged. The sets below are those rungs.
///
/// Nothing enforced this before (audit v3, AGG-3). `Machine::verify` accepts any tier on the
/// ladder and builds the verifier key for whatever the proof declares *before* verifying it — so
/// a proposer could put an invalid aggregate at an unwarmed tier in a block and every replica
/// would pay a 30–70 s key build, on the consensus loop at block apply, before refusing it.
///
/// Production is the spec's three, two tiers down (phase 2, then phase 4), plus tier 18 since
/// phase 5 (N=1 moved down a rung and N=5 stays at 21, so the set grew rather than slid); test is
/// the one the fixtures and the warm path use, plus its two neighbours for the same N=2/N=3 reason.
pub fn admitted_tiers(profile: FriProfile) -> &'static [u8] {
    match profile {
        FriProfile::Test => &[18, 19, 20],
        FriProfile::Production => &[18, 19, 20, 21],
    }
}

/// The gate itself, split out so it can be tested without a proof: building one costs a fixture
/// cache and minutes of proving, and what matters here is the rule and where it runs.
pub fn check_tier(profile: FriProfile, tier: u8) -> Result<(), ConfidentialError> {
    if admitted_tiers(profile).contains(&tier) {
        return Ok(());
    }
    Err(ConfidentialError::InvalidAggregateProof(format!(
        "aggregate proof at tier {tier}; this chain admits {:?}",
        admitted_tiers(profile)
    )))
}

/// The rVM's N ceiling at admission (circuits docs/06 §3): an aggregate over `n` inner proofs is
/// refused by name when `n` exceeds `max_n` (`machine::max_reduce_n` of the registered program).
pub fn check_n_ceiling(n: usize, max_n: u64) -> Result<(), ConfidentialError> {
    if n as u64 > max_n {
        return Err(ConfidentialError::InvalidAggregateProof(format!(
            "an aggregate over {n} bundles is past the rVM's N ceiling {max_n} for this shape (the reduce chip's \
             REDUCE_MAX_LOG_HEIGHT; no verifiable proof exists)"
        )));
    }
    Ok(())
}

/// The distinct canonical reduce heights for N = 1..=min(max_covers, ceiling), ascending — the
/// heights `warm_aggregation` builds keys at. `canonical_reduce_log_height` is the rVM's own rule.
fn warm_reduce_heights(program: &randprotocol_rvm::isa::Program, max_covers: u32) -> Vec<u8> {
    let top = (max_covers as u64).min(randprotocol_rvm::machine::max_reduce_n(program));
    let mut heights: Vec<u8> =
        (1..=top).filter_map(|n| randprotocol_rvm::machine::canonical_reduce_log_height(program, n)).collect();
    heights.dedup();
    heights
}

/// The genesis half of the N ceiling: an `aggregation` section whose `max_covers` exceeds the
/// rVM's ceiling for an admitted shape would let the ledger admit cover sets no aggregator can
/// prove (production: N ≤ 5, circuits docs/06 §3). `rand-node genesis` runs it beside
/// [`check_admitted_shape`]. Builds the aggregate program (seconds of DSL emission).
pub fn check_admitted_covers(shape: &DeclaredShape, max_covers: u32) -> Result<(), ConfidentialError> {
    let program = aggregate_program(&AggExecutor::inner_key(shape)?);
    let max_n = randprotocol_rvm::machine::max_reduce_n(&program);
    if max_covers as u64 > max_n {
        return Err(ConfidentialError::BadDeclaredShape(format!(
            "max_covers {max_covers} is past the rVM's N ceiling {max_n} for this shape (the reduce chip's REDUCE_MAX_LOG_HEIGHT)"
        )));
    }
    Ok(())
}

/// Why a node refuses to start on its `aggregation_tree` section ([`check_tree_pins`]).
#[derive(Debug)]
pub enum TreePinError {
    /// The rVM cannot serve the section at all (`AggExecutor`'s rebuild refused it): no tree
    /// aggregate could ever be proved or verified on the chain.
    Unbuildable(ConfidentialError),
    /// A pin this build does not rebuild: `TreeKeyPin { level }` (circuits' `at_level`
    /// numbering) or `AggregateProgramMismatch` for a level's step program.
    Pin(AggregationError),
}

impl std::fmt::Display for TreePinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreePinError::Unbuildable(e) => write!(f, "the rVM cannot serve the section: {e}"),
            TreePinError::Pin(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TreePinError {}

/// The startup check (circuits spec §4: the node "refuses to start on a mismatch"): rebuild the
/// section and compare **every** pin — each listed level's step program digest, `vk_leaf`, and
/// each listed level's key — whatever depth a tree may later take. Stricter than admission's
/// 7b, which reads only what a depth-`d` recompute uses, so a pin only a deep tree would touch
/// cannot sit wrong until the first deep aggregate. The node runs it beside
/// `check_build_runs_genesis`, before the warm thread.
pub fn check_tree_pins(ex: &dyn ConfidentialExecutor, tree: &TreeConfig) -> Result<(), TreePinError> {
    let built = ex.tree_digests(tree).map_err(TreePinError::Unbuildable)?;
    for (k, pin) in tree.steps.iter().enumerate() {
        let program = built.steps.get(k).map_or([0; 4], |(p, _)| *p);
        if program != pin.program_digest {
            return Err(TreePinError::Pin(AggregationError::AggregateProgramMismatch { pinned: pin.program_digest, built: program }));
        }
    }
    if built.vk_leaf != tree.vk_leaf {
        return Err(TreePinError::Pin(AggregationError::TreeKeyPin { level: 1 }));
    }
    for (k, pin) in tree.steps.iter().enumerate() {
        // `steps[k].key` is the key of level k+1's proofs, which level k+2 consumes.
        if built.steps.get(k).map(|(_, key)| *key) != Some(pin.key) {
            return Err(TreePinError::Pin(AggregationError::TreeKeyPin { level: u8::try_from(k + 2).unwrap_or(u8::MAX) }));
        }
    }
    Ok(())
}

impl ConfidentialExecutor for AggExecutor {
    fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
        self.inner.check_program(base_pc, words)
    }

    /// Forwarded, never left at the trait's `None` default: this wrapper is the executor every
    /// node runs (`node::executor_for_profile`), so a default here would switch CPU-1's rule off
    /// under `hardening_v6` on the very nodes that are meant to enforce it. The same holds for
    /// every defaulted method the v0.6 rules add.
    fn max_callable_program_words(&self, public_segment_words: usize) -> Option<usize> {
        self.inner.max_callable_program_words(public_segment_words)
    }

    fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        self.inner.verify_call(program, proof)
    }

    /// Admission pricing only (`call_pricing`, which reads a call's header before paying for a
    /// verify) — the ledger never decodes a proof (spec 2026-10-12 verified fold). Mirrors
    /// `ZkExecutor::verify_call`'s pre-`Machine::verify` half exactly, out of the vendored
    /// crate's public API (the executor's own `decode_and_check` is private): the canonical
    /// decode, the declared-height ranges, the public-table height against the record, the
    /// public-value count and `u32` ranges, and the `PUB0..7` compare. Absent are the
    /// degree-bits check and the STARK verification itself — admission's verify that follows
    /// runs both. Re-mirror against `verify_call` at every re-vendor.
    fn decode_call(&self, record: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
        use randprotocol_zkvm::tables::cpu::pv;
        let proof = randprotocol_zkvm::executor::decode_canonical(proof)?;
        // Constraint set 9: `check_decoded`'s call refusal, mirrored — a modq table is the
        // multisig auth guest's alone, and no deployed program issues `SYS_MODQ`.
        if proof.modq_log_height != 0 {
            return Err(ConfidentialError::InvalidProof("a call proof declares no modq table".into()));
        }
        randprotocol_zkvm::machine::check_declared_heights(
            proof.tier,
            proof.program_log_height,
            proof.input_log_height,
            proof.keccak_log_height,
            proof.sha256_log_height,
            proof.public_log_height,
            proof.mem_log_height,
        )
        .map_err(|e| ConfidentialError::InvalidProof(format!("declared shape: {e:?}")))?;
        if proof.public_log_height != randprotocol_zkvm::tables::public::public_log_height(record.public_len as usize) {
            return Err(ConfidentialError::InvalidProof(format!("{:?}", randprotocol_zkvm::machine::VerifyError::PublicValues)));
        }
        if proof.public_values.len() != pv::NUM {
            return Err(ConfidentialError::MalformedProof);
        }
        if proof.public_values[pv::OUT0..pv::OUT0 + 8].iter().any(|v| *v > u32::MAX as u64) {
            return Err(ConfidentialError::InvalidProof("output not a u32".into()));
        }
        if proof.public_values[pv::IN0..pv::IN0 + 8].iter().any(|v| *v > u32::MAX as u64) {
            return Err(ConfidentialError::InvalidProof("H_IN word not a u32".into()));
        }
        let want = record.public_digest.unwrap_or_else(|| randprotocol_zkvm::hash::public_digest(&[]));
        if (0..8).any(|i| proof.public_values[pv::PUB0 + i] != want[i] as u64) {
            return Err(ConfidentialError::InvalidProof(format!("{:?}", randprotocol_zkvm::machine::VerifyError::PublicValues)));
        }
        let outputs = std::array::from_fn(|i| proof.public_values[pv::OUT0 + i] as u32);
        let h_in = std::array::from_fn(|i| proof.public_values[pv::IN0 + i] as u32);
        Ok(CallOutcome {
            tier: proof.tier.0 as u8,
            outputs,
            h_in,
            keccak_log_height: proof.keccak_log_height,
            sha256_log_height: proof.sha256_log_height,
            // Constraint set 8: the declared limit, `pv::GAS`. `Machine::verify` holds the run's
            // gas to it and it to `gas_max` of the header (`VerifyError::GasLimit`).
            gas_limit: proof.public_values[pv::GAS],
        })
    }

    fn warm(&self, program: &ProgramRecord) {
        self.inner.warm(program)
    }

    /// The v0.6 call rules (INT-4), forwarded — the trait's default refuses every call, and this
    /// wrapper is what every node runs.
    fn verify_call_hardened(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.inner.verify_call_hardened(program, proof, segment)
    }

    fn decode_call_hardened(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.inner.decode_call_hardened(program, proof, segment)
    }

    /// RPL-2's invoke rules, forwarded for the same reason: the trait's default refuses every
    /// `Invoke`, and this wrapper is what every node runs.
    fn verify_invoke(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.inner.verify_invoke(program, proof, segment)
    }

    fn decode_invoke(
        &self,
        program: &ProgramRecord,
        proof: &[u8],
        segment: &[u32],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.inner.decode_invoke(program, proof, segment)
    }

    /// RPL-3's state-proof rules, forwarded for the same reason as the invoke rules: the trait's
    /// default refuses every `PerpStateProof` ("does not implement the RPL-3 state-proof
    /// rules"), and this wrapper is what every node runs. No metering or caching sits around
    /// the invoke path here, so none is added: a straight forward.
    fn verify_perp(
        &self,
        engine_hc: &Word8,
        max_tier: u8,
        segment: &[u32],
        proof: &[u8],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.inner.verify_perp(engine_hc, max_tier, segment, proof)
    }

    fn decode_perp(
        &self,
        engine_hc: &Word8,
        max_tier: u8,
        segment: &[u32],
        proof: &[u8],
    ) -> Result<CallOutcome, ConfidentialError> {
        self.inner.decode_perp(engine_hc, max_tier, segment, proof)
    }

    fn perp_proof_shape(&self, proof: &[u8]) -> Option<randprotocol_core::confidential::ProofShape> {
        self.inner.perp_proof_shape(proof)
    }

    fn perp_key_ready(&self, shape: &randprotocol_core::confidential::ProofShape) -> bool {
        self.inner.perp_key_ready(shape)
    }

    fn keep_perp_key(&self, shape: &randprotocol_core::confidential::ProofShape) {
        self.inner.keep_perp_key(shape)
    }

    fn warm_perp(&self, shape: &randprotocol_core::confidential::ProofShape) {
        self.inner.warm_perp(shape)
    }

    fn perp_proof_admissible(
        &self,
        proof: &[u8],
        engine_hc: &Word8,
        max_tier: u8,
        segment: &[u32],
        engine_program_log_height: u8,
    ) -> bool {
        self.inner.perp_proof_admissible(proof, engine_hc, max_tier, segment, engine_program_log_height)
    }

    fn perp_shape_canonical(&self, shape: &randprotocol_core::confidential::ProofShape) -> bool {
        self.inner.perp_shape_canonical(shape)
    }

    fn set_perp_config(&self, max_tier: u8, engine_program_log_height: u8) {
        self.inner.set_perp_config(max_tier, engine_program_log_height)
    }

    /// The keys an `Invoke` verifies under are these too: its segment sits in the hardened
    /// call's public table (`program_state::segment_fits`), so it declares no shape a call to
    /// the same program does not.
    fn warm_hardened(&self, program: &ProgramRecord) {
        self.inner.warm_hardened(program)
    }

    fn public_digest(&self, words: &[u32]) -> Word8 {
        self.inner.public_digest(words)
    }

    fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
        self.inner.node_hash(left, right)
    }

    fn hash_domain(&self, domain: u32, msg: &[u32]) -> Word8 {
        self.inner.hash_domain(domain, msg)
    }

    fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
        self.inner.note_commitment(pk, from, amount, asset, time, r)
    }

    fn bundle_digest(&self, input: &BundleDigestInput) -> Word8 {
        self.inner.bundle_digest(input)
    }

    fn bundle_digest_v3(&self, input: &BundleDigestInput) -> Word8 {
        self.inner.bundle_digest_v3(input)
    }

    fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.inner.bundle_proof_digest(hc_bundle, proof)
    }

    fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
        self.inner.auth_proof_digest(proof)
    }

    fn verify_auth(
        &self,
        hc_auth: &Word8,
        proof: &[u8],
        binding: &[u32; randprotocol_core::types::TX_BINDING_WORDS],
    ) -> Result<Word8, ConfidentialError> {
        self.inner.verify_auth(hc_auth, proof, binding)
    }

    fn bundle_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
        self.inner.bundle_gas_limit(proof)
    }

    fn auth_gas_limit(&self, proof: &[u8]) -> Result<Option<u64>, ConfidentialError> {
        self.inner.auth_gas_limit(proof)
    }

    fn verify_bundle(
        &self,
        hc_bundle: &Word8,
        proof: &[u8],
        binding: &[u32; randprotocol_core::types::TX_BINDING_WORDS],
    ) -> Result<(), ConfidentialError> {
        self.inner.verify_bundle(hc_bundle, proof, binding)
    }

    fn warm_bundle(&self) {
        self.inner.warm_bundle()
    }

    fn warm_auth(&self) {
        self.inner.warm_auth()
    }

    /// Forwarded (Task 2b): the default would refuse every blob and fail a multisig chain's startup.
    fn install_msauth_vk(&self, blob: &[u8]) -> Result<(), String> {
        ConfidentialExecutor::install_msauth_vk(&self.inner, blob)
    }

    fn build_msauth_key(&self) -> Result<(), String> {
        ConfidentialExecutor::build_msauth_key(&self.inner)
    }

    /// Forwarded (Task 3): the default would leave the inner executor's msauth path shut and
    /// refuse every multisig auth proof on a chain that names `hc_auth_multisig`.
    fn enable_auth_multisig(&self) {
        ConfidentialExecutor::enable_auth_multisig(&self.inner)
    }

    fn auth_header(&self, proof: &[u8]) -> Result<(randprotocol_core::confidential::AuthShape, Word8, Option<u64>), ConfidentialError> {
        self.inner.auth_header(proof)
    }

    fn warm_auth_multisig(&self) {
        ConfidentialExecutor::warm_auth_multisig(&self.inner)
    }

    fn auth_multisig_key_ready(&self) -> bool {
        ConfidentialExecutor::auth_multisig_key_ready(&self.inner)
    }

    /// Forwarded, like `max_callable_program_words` (a default would switch the rule off).
    fn non_canonical_proof(&self, proof: &[u8]) -> Option<String> {
        self.inner.non_canonical_proof(proof)
    }

    /// spec §2.3's registered artifact: the N-generic aggregate program's digest for the shape,
    /// rebuilt deterministically from `(shape, key)` — seconds of DSL emission, never a proof.
    fn aggregate_program_digest(&self, shape: &DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
        // `aggregate_program(vk).digest()` is `programs::aggregate_program_digest(shape, key)` —
        // one function the other calls — so the memoised program's digest is the pinned one.
        Ok(self.built_program(shape)?.digest)
    }

    fn check_aggregate_header(&self, proof: &[u8]) -> Result<(), ConfidentialError> {
        self.aggregate_header(proof).map(|_| ())
    }

/// spec §4 steps 7–8: the §4.4 interface list is recomputed from the covered bundles' public
    /// values (auxiliary data, the `verify_public` pattern — the proof carries only its digest),
    /// then the rVM's own `verify_aggregate` does the digest compare and the `Machine::verify`.
    /// Cheap refusals come first: the empty set and the undecodable proof never reach a program
    /// build.
    fn verify_aggregate(
        &self,
        shape: &DeclaredShape,
        covered: &[CoveredBundle],
        proof: &[u8],
        binding: &[u32; 8],
    ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
        if covered.is_empty() {
            return Err(ConfidentialError::InvalidAggregateProof(
                "an aggregate covers at least one bundle".into(),
            ));
        }
        let rvm_proof = self.aggregate_header(proof)?;
        let built = self.built_program(shape)?;
        // The rVM's N ceiling (circuits docs/06 §3, phase 3's final fix wave), by name, before any
        // key work: an aggregate over more inner proofs than the reduce chip holds has no
        // verifiable reduce height — `prove` and `aggregate` refuse to make one — so no valid
        // proof exists for it. The ledger's `max_covers` is the chain's own cap; this is the
        // machine's, and a genesis whose `max_covers` exceeds it would admit Ns nobody can prove
        // (`rand-node genesis` refuses that, `check_admitted_covers`). Production: N ≤ 5.
        check_n_ceiling(covered.len(), built.max_n)?;
        let pvs: Vec<Vec<u64>> = covered.iter().map(|c| c.public_values.to_vec()).collect();
        // The list carries the transaction's own binding (audit v3, AGG-2), recomputed by the
        // ledger from `(chain, aggregator, nonce)`: a proof made under another triple digests
        // differently and is refused.
        let public = randprotocol_rvm::public_values::interface_words_bound(&built.vk.shape, &built.vk.key, binding, &pvs);
        // The reduce height (the interface review's INTERFACE-4, AGG-3). The rVM keys its
        // verifier-key cache by `(tier, program, reduce_log_height)`, and a proof declaring a
        // height of its choosing used to buy a fresh key build (13 s test, 30–70 s production)
        // and a slot in the 64-entry FIFO before its batch was looked at; the node refused the
        // one case it could see (the reduce flag). Since phase 3 the rVM settles it itself:
        // `verify_aggregate` passes the list's N (digest-bound, = `covered.len()` here) to
        // `Machine::verify_n`, which refuses any height but
        // `canonical_reduce_log_height(program, N)` as `ReduceHeightNotCanonical`, before any
        // key work (circuits docs/06 §5). So a `(program, tier, N)` admits exactly one key, and
        // `warm_aggregation` warms exactly those.
        let out = randprotocol_rvm::aggregate::verify_aggregate(
            &self.rvm,
            &built.program,
            &AggregateProof { proof: rvm_proof, public },
            binding,
        )
                .map_err(|e| ConfidentialError::InvalidAggregateProof(format!("{e:?}")))?;
        AGGREGATE_VERIFICATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(out)
    }

    /// Step 7a for a tree: the root's tier off its header alone — the decode and the canonical
    /// encoding (`aggregate_header`'s), no tier set and nothing built; the ledger compares it with
    /// the pinned tier of the root's level.
    fn aggregate_proof_tier(&self, proof: &[u8]) -> Result<u8, ConfidentialError> {
        let p: randprotocol_rvm::machine::Proof = postcard::from_bytes(proof).map_err(|_| ConfidentialError::MalformedProof)?;
        if p.to_bytes() != proof {
            return Err(ConfidentialError::MalformedProof);
        }
        u8::try_from(p.tier.0).map_err(|_| ConfidentialError::InvalidAggregateProof(format!("tree root at tier {}", p.tier.0)))
    }

    /// Step 7b for a tree: the rebuilt `vk_leaf` and each listed level's `(program, key)`, in the
    /// list's order (memoised; see `built_tree` for what refuses a section outright).
    fn tree_digests(&self, tree: &TreeConfig) -> Result<TreeDigests, ConfidentialError> {
        Ok(self.built_tree(tree)?.digests.clone())
    }

    /// Step 8 for a tree (circuits `aggregate::verify_tree`): the root's header at its level's
    /// pinned tier, then the rVM's bottom-up recompute under the rebuilt key list and
    /// `verify_n(root program, root, 2)`. The ledger has checked the layout, the depth, the tier
    /// and the pins; this re-reads the tier (the header is this executor's to decode) and refuses
    /// a depth past the list without a fixed point, which `built_tree` lets through only when
    /// `max_depth` is within the list. Named verdicts keep their names (`TreeRootDigest`,
    /// `TreeKeyPin`, `CoveredPublicValues`); every other refusal is `InvalidAggregateProof`.
    fn verify_tree(
        &self,
        tree: &TreeConfig,
        covered: &[CoveredBundle],
        proof: &[u8],
        binding: &[u32; 8],
        depth: u32,
    ) -> Result<Vec<[u32; 8]>, ConfidentialError> {
        use randprotocol_rvm::aggregate::VerifyTreeError;
        if tree.steps.is_empty() {
            return Err(ConfidentialError::InvalidAggregateProof("aggregation_tree lists no step".into()));
        }
        let root = self.aggregate_header_tree(proof, tree.step_at(depth).heights)?;
        let built = self.built_tree(tree)?;
        if depth as usize > tree.steps.len() && built.fixed_point != Some(true) {
            return Err(ConfidentialError::InvalidAggregateProof(format!(
                "a depth-{depth} tree repeats level {}'s step, which is not a fixed point",
                tree.steps.len()
            )));
        }
        let program = built
            .shapes
            .root_program(depth)
            .ok_or_else(|| ConfidentialError::InvalidAggregateProof(format!("no step program for depth {depth}")))?;
        let pvs: Vec<Vec<u64>> = covered.iter().map(|c| c.public_values.to_vec()).collect();
        let out = randprotocol_rvm::aggregate::verify_tree(
            &self.rvm,
            program,
            &root,
            &built.inner,
            &pvs,
            binding,
            tree.leaf_size as usize,
            depth,
            &built.keys,
        )
        .map_err(|e| match e {
            VerifyTreeError::TreeRootDigest => ConfidentialError::TreeRootDigest,
            VerifyTreeError::TreeKeyPin { level } => ConfidentialError::TreeKeyPin { level: u8::try_from(level).unwrap_or(u8::MAX) },
            VerifyTreeError::CoveredPublicValues { index } => ConfidentialError::CoveredPublicValues { index },
            e => ConfidentialError::InvalidAggregateProof(format!("{e:?}")),
        })?;
        AGGREGATE_VERIFICATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(out)
    }

    /// The tree's startup key-build: for each listed level, the rVM key a root of that depth
    /// verifies under — the level's step program, its pinned tier, its canonical reduce height at
    /// N = 2 (which `built_tree` holds the pin to). A section the rVM refuses is logged, not
    /// panicked on: the startup pin check is where that refusal belongs.
    fn warm_tree(&self, tree: &TreeConfig) {
        let t0 = std::time::Instant::now();
        let built = match self.built_tree(tree) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("aggregation_tree: cannot rebuild the section ({e}); skipping the warm");
                return;
            }
        };
        for (s, pin) in built.shapes.steps.iter().zip(&tree.steps) {
            let _ = self.rvm.verifier_key(&s.program, randprotocol_rvm::machine::Tier(pin.heights.tier as usize), pin.heights.reduce_log_height);
        }
        tracing::info!("aggregation_tree: {} root keys warmed ({:.1?})", tree.steps.len(), t0.elapsed());
    }

    /// The startup key-build (spec §2.3, `circuits/recursion/docs/02-aggregate.md` "Startup: the
    /// key-build story"): build the N-generic program (seconds) and warm one rVM verifier key per
    /// admitted tier and per canonical reduce height for N = 1..=min(max_covers, the rVM's N
    /// ceiling) — `machine::canonical_reduce_log_height(program, N)`, circuits docs/06 §5's
    /// instruction (production: `2^18` / `2^19` / `2^20` at N = 1 / 2 / 3–5; test: `2^16` /
    /// `2^17` at N = 1 / 2–3) — so no aggregate an honest prover can make pays the ~30–70 s
    /// (production) build inside admission. A shape the rVM refuses to build is logged and
    /// skipped, not panicked on: genesis validation is where that refusal belongs.
    fn warm_aggregation(&self, shape: &DeclaredShape, max_covers: u32) {
        let t0 = std::time::Instant::now();
        // The memoised program (INTERFACE-5): the warm builds it once, and admission's step 7b
        // and step 8 reuse it.
        let built = match self.built_program(shape) {
            Ok(built) => built,
            Err(e) => {
                tracing::warn!("aggregation: admitted shape cannot build an inner key ({e}); skipping the warm");
                return;
            }
        };
        let program = &built.program;
        let heights = warm_reduce_heights(program, max_covers);
        // *Every* admitted tier, not just the N=1 landing tier (audit v3, AGG-3): an aggregate
        // covering two or three bundles lands higher, and paying its key build inside admission —
        // on the consensus loop — is what this warm exists to avoid. The tiers above N=1 are rarer,
        // not cheaper. The full admitted tier × canonical height cross product is warmed because the
        // verifier admits any such pair, including ones no valid proof can have (production tier 20
        // at height 2^19): an unwarmed pair is a key build an attacker could make every replica pay
        // on the consensus path.
        for tier in admitted_tiers(self.rvm.profile) {
            for h in &heights {
                let _ = self.rvm.verifier_key(program, randprotocol_rvm::machine::Tier(*tier as usize), *h);
            }
        }
        tracing::info!(
            "aggregation: aggregate program built and the verifier keys for tiers {:?} × reduce heights {:?} (N ≤ {}) warmed ({:.1?})",
            admitted_tiers(self.rvm.profile),
            heights,
            (max_covers as u64).min(built.max_n),
            t0.elapsed()
        );
    }
}

/// A recursion fixture proof (`<dir>/Test-{k}.proof`: a 32-byte `hc` then the postcard
/// `randprotocol_zkvm::machine::Proof`), `<dir>` being `$RECURSION_FIXTURES` or, by default, the
/// in-repo set `fixtures/recursion` (Test-0..2, issue #131). The conformance discipline needs the
/// *doc's* fixtures — the 118-word interface list rides on their random notes, so the
/// pinned-vectors test passes on those exact bytes and on no freshly proved set — and a missing
/// file is a loud failure, not a skip. `scripts/recursion-fixtures.sh --check` checks a
/// directory against the pinned bytes. `pub(crate)` so `node`'s covered-assembly tests can store
/// a bundle carrying a real proof.
#[cfg(test)]
pub(crate) fn fixture_proof(k: usize) -> randprotocol_zkvm::machine::Proof {
    let dir = std::env::var_os("RECURSION_FIXTURES")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/recursion"));
    let path = dir.join(format!("Test-{k}.proof"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} — the aggregation tests read the pinned recursion fixtures Test-0, Test-1 and \
             Test-2, committed in crates/randprotocol-node/fixtures/recursion (the default; \
             RECURSION_FIXTURES overrides it). Check a directory with \
             scripts/recursion-fixtures.sh --check <dir> (docs/aggregation.md)",
            path.display()
        )
    });
    postcard::from_bytes(&bytes[32..]).expect("a fixture proof decodes")
}

/// A tier-10 Test-profile zkVM proof carrying one modq block (`modq_log_height = 10`): the
/// zkVM's `executor::fixtures::one_modq_ntt_program`, proved once per process (~8 s). The
/// aggregate-path refusal tests feed it where an inner proof's header is decoded.
#[cfg(test)]
pub(crate) fn modq_fixture_proof_bytes() -> &'static [u8] {
    static BYTES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    BYTES.get_or_init(|| {
        use randprotocol_zkvm::machine::{Machine, ProveOptions, Tier};
        let program = randprotocol_zkvm::executor::fixtures::one_modq_ntt_program();
        let (proof, _) = Machine::new(FriProfile::Test)
            .prove_with_options(&program, &[], &[], Some(Tier(10)), ProveOptions::default())
            .expect("the one-NTT fixture proves at tier 10");
        assert_eq!(proof.modq_log_height, 10, "one modq block");
        proof.to_bytes()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::confidential::StubExecutor;
    use randprotocol_core::types::FriProfile as CoreProfile;

    /// All three phase-4 methods are forwarded, never left at a default: the wrapper answers exactly
    /// what the bare executor answers.
    #[test]
    fn the_phase_4_auth_methods_are_forwarded() {
        use randprotocol_core::confidential::AuthShape;
        use randprotocol_zkvm::machine::Backend;
        let ex = AggExecutor::new(FriProfile::Test);
        let bare = ZkExecutor::new(FriProfile::Test);
        assert_eq!(ex.auth_header(b"junk"), ConfidentialExecutor::auth_header(&bare, b"junk"));
        let (single, c, _) = randprotocol_zkvm::executor::prove_auth(FriProfile::Test, &randprotocol_zkvm::notes::SpendKey([7; 8]), &[6; 8], &[0; 8], Backend::Cpu).unwrap();
        assert_eq!(ex.auth_header(&single), ConfidentialExecutor::auth_header(&bare, &single));
        assert_eq!(ex.auth_header(&single).unwrap().0, AuthShape::SingleKey);
        assert_eq!(ex.auth_header(&single).unwrap().1, c);
        assert!(!ex.auth_multisig_key_ready(), "nothing warmed yet, as the bare executor says");
        assert_eq!(ex.auth_multisig_key_ready(), ConfidentialExecutor::auth_multisig_key_ready(&bare));
    }

    /// The covered-bundle record admission would assemble for fixture `k`: its declared shape
    /// read off the proof's stored header, and its `pv::NUM` public values.
    fn covered(k: usize) -> (DeclaredShape, CoveredBundle) {
        let p = fixture_proof(k);
        let shape = DeclaredShape {
            profile: CoreProfile::Test,
            tier: p.tier.0 as u8,
            program_log_height: p.program_log_height,
            input_log_height: p.input_log_height,
            keccak_log_height: p.keccak_log_height,
            sha256_log_height: p.sha256_log_height,
            public_log_height: p.public_log_height,
            mem_log_height: p.mem_log_height,
        };
        let public_values: [u64; randprotocol_core::types::pv::NUM] = p.public_values.clone().try_into().expect("cs8 proofs carry pv::NUM public values");
        (shape, CoveredBundle { public_values, shape })
    }

    /// A shape the rVM builds without any recursion fixture: the fixtures' own classes (public
    /// height 7, constraint set 7's floor on every table — the empty segment's 2 before it).
    fn fixture_free_shape() -> DeclaredShape {
        DeclaredShape {
            profile: CoreProfile::Test,
            tier: 14,
            program_log_height: 13,
            input_log_height: 12,
            keccak_log_height: 0,
            sha256_log_height: 0,
            public_log_height: 7,
            mem_log_height: 18,
        }
    }

    /// A decodable, canonical rVM proof that gets exactly as far as the checks under test: the
    /// header fields as given, the interface digest `covered` and `binding` make (so the rVM's
    /// digest compare passes), the degree bits `log_ext_degrees` wants for them (so
    /// `Machine::verify`'s shape checks pass), and an all-zero batch — which could never verify,
    /// but everything that would reject it runs after the verifier-key build. No prove, no
    /// fixture: postcard decodes zero bytes as empty vectors and zero field elements.
    fn crafted_proof(
        shape: &DeclaredShape,
        covered: &[CoveredBundle],
        binding: &[u32; 8],
        tier: usize,
        reduce_log_height: u8,
    ) -> Vec<u8> {
        use p3_field::PrimeField64;
        let vk = AggExecutor::inner_key(shape).unwrap();
        let program = aggregate_program(&vk);
        let pvs: Vec<Vec<u64>> = covered.iter().map(|c| c.public_values.to_vec()).collect();
        let public = randprotocol_rvm::public_values::interface_words_bound(&vk.shape, &vk.key, binding, &pvs);
        let digest: Vec<u64> = randprotocol_rvm::public_values::public_digest(&public).iter().map(|f| f.as_canonical_u64()).collect();
        let h = randprotocol_rvm::machine::MIN_LOG_HEIGHT;
        let mut bytes = postcard::to_allocvec(&(tier, h, h, h, reduce_log_height, digest)).unwrap();
        bytes.extend_from_slice(&[0u8; 4096]);
        let mut proof: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).expect("zeros decode as an empty batch");
        proof.batch.degree_bits =
            randprotocol_rvm::machine::log_ext_degrees(&program, randprotocol_rvm::machine::Tier(tier), h, h, h, reduce_log_height);
        proof.to_bytes()
    }

    /// The canonical reduce height for the shape's aggregate program over `n` proofs.
    fn canonical_height(shape: &DeclaredShape, n: u64) -> u8 {
        let program = aggregate_program(&AggExecutor::inner_key(shape).unwrap());
        randprotocol_rvm::machine::canonical_reduce_log_height(&program, n).expect("n is under the ceiling")
    }

    /// The interface review's INTERFACE-4 (and AGG-3): the rVM keys its verifier-key cache by
    /// `(tier, program, reduce_log_height)` and reads the height off the proof. A proof declaring
    /// any height but the canonical one for its N — the old flipped flag, or any other rung — is
    /// invalid by construction, and must not buy a 13 s (test) to 70 s (production) key build or
    /// evict a warm key from the 64-entry FIFO. Since phase 3 the rVM's `verify_n` (through
    /// `verify_aggregate`, with the list's N) refuses it before any key work; this pins that the
    /// node's path reaches that refusal, for every non-canonical height a proof could name.
    #[test]
    fn a_proof_whose_reduce_height_is_not_canonical_is_refused_before_any_key_build() {
        let ex = AggExecutor::new(FriProfile::Test);
        let shape = fixture_free_shape();
        let covered = vec![CoveredBundle { public_values: [7; randprotocol_core::types::pv::NUM], shape }];
        let binding = [3u32; 8];
        let canonical = canonical_height(&shape, 1);
        for declared in [0, canonical - 1, canonical + 1, randprotocol_rvm::machine::REDUCE_MAX_LOG_HEIGHT] {
            let proof = crafted_proof(&shape, &covered, &binding, admitted_tiers(FriProfile::Test)[0] as usize, declared);
            let before = ex.rvm.cached_keys();
            let err = ex.verify_aggregate(&shape, &covered, &proof, &binding).unwrap_err();
            assert_eq!(ex.rvm.cached_keys(), before, "no verifier key was built for reduce height {declared}: {err}");
            assert!(format!("{err}").contains("ReduceHeightNotCanonical"), "refused by name: {err}");
        }
    }

    /// The rVM's N ceiling at admission (circuits docs/06 §3): one inner proof past
    /// `max_reduce_n` is refused by name, before any key build — whatever height the proof
    /// declares. The test fixture shape's ceiling is 26 (production's is 5).
    #[test]
    fn an_aggregate_past_the_rvms_n_ceiling_is_refused_by_name_before_any_key_build() {
        let ex = AggExecutor::new(FriProfile::Test);
        let shape = fixture_free_shape();
        let program = aggregate_program(&AggExecutor::inner_key(&shape).unwrap());
        let max_n = randprotocol_rvm::machine::max_reduce_n(&program);
        assert!(max_n < 64, "the shape has a finite N ceiling ({max_n})");
        let over = vec![CoveredBundle { public_values: [7; randprotocol_core::types::pv::NUM], shape }; max_n as usize + 1];
        let binding = [3u32; 8];
        let proof = crafted_proof(&shape, &over, &binding, admitted_tiers(FriProfile::Test)[0] as usize, randprotocol_rvm::machine::REDUCE_MAX_LOG_HEIGHT);
        let before = ex.rvm.cached_keys();
        match ex.verify_aggregate(&shape, &over, &proof, &binding) {
            Err(ConfidentialError::InvalidAggregateProof(m)) => assert!(m.contains("N ceiling") && m.contains(&max_n.to_string()), "{m}"),
            other => panic!("N = {} must be refused at the ceiling, got {other:?}", max_n + 1),
        }
        assert_eq!(ex.rvm.cached_keys(), before, "no verifier key was built past the ceiling");
        // At the ceiling the gate passes (the proof is then refused later, as garbage).
        assert!(check_n_ceiling(max_n as usize, max_n).is_ok());
        // And the genesis half: a `max_covers` past the ceiling is refused, at it accepted.
        assert!(check_admitted_covers(&shape, max_n as u32).is_ok());
        assert!(matches!(check_admitted_covers(&shape, max_n as u32 + 1), Err(ConfidentialError::BadDeclaredShape(m)) if m.contains("N ceiling")));
    }

    /// The interface review's INTERFACE-5: step 7b's digest and step 8's verify each rebuilt the
    /// inner key and the aggregate program (seconds of DSL emission) per aggregate, at admission
    /// and again at every block apply. The program is a pure function of a genesis constant, so
    /// it is built once per shape: a second digest, a second verify and the warm reuse it. And
    /// the header gate admission runs before step 7b refuses an unadmitted tier with no build.
    #[test]
    fn the_aggregate_program_is_built_once_per_shape_and_never_for_a_refused_header() {
        let ex = AggExecutor::new(FriProfile::Test);
        let shape = fixture_free_shape();
        let covered = vec![CoveredBundle { public_values: [7; randprotocol_core::types::pv::NUM], shape }];
        let binding = [3u32; 8];
        // A header at a tier the chain never admits: refused before anything is built.
        let unadmitted = crafted_proof(&shape, &covered, &binding, 22, 0);
        assert!(matches!(ex.check_aggregate_header(&unadmitted), Err(ConfidentialError::InvalidAggregateProof(m)) if m.contains("tier 22")));
        assert_eq!(ex.program_builds(), 0, "a refused header builds nothing");

        let first = ex.aggregate_program_digest(&shape).unwrap();
        assert_eq!(ex.aggregate_program_digest(&shape).unwrap(), first, "one program, one digest");
        let vk = AggExecutor::inner_key(&shape).unwrap();
        assert_eq!(
            first,
            randprotocol_rvm::programs::aggregate_program_digest(&vk.shape, &vk.key).map(|f| p3_field::PrimeField64::as_canonical_u64(&f)),
            "the memoised digest is the rVM's own"
        );
        // A verify at the same shape (refused at the reduce-height check, after the program is in hand).
        let off_canonical = canonical_height(&shape, 1) + 1;
        let proof = crafted_proof(&shape, &covered, &binding, admitted_tiers(FriProfile::Test)[0] as usize, off_canonical);
        assert!(ex.verify_aggregate(&shape, &covered, &proof, &binding).is_err());
        assert_eq!(ex.program_builds(), 1, "two digests and a verify: one build");
    }

    /// IFACE-9's node half: the core mirrors of the bundle header (and ZKQ-4's field order) are
    /// the zkVM's own numbers, and
    /// `check_admitted_shape` is `InnerShape::try_of` — the pinned header builds, a declared
    /// height the zkVM refuses does not.
    #[test]
    fn the_bundle_header_mirrors_are_the_zkvms_and_an_unbuildable_shape_is_refused() {
        assert_eq!(
            randprotocol_core::types::BUNDLE_PUBLIC_LOG_HEIGHT,
            randprotocol_zkvm::tables::public::public_log_height(randprotocol_core::types::TX_BINDING_WORDS),
            "the transaction binding's public height"
        );
        assert_eq!(
            randprotocol_core::types::pv::GOLDILOCKS_ORDER,
            <randprotocol_zkvm::machine::Val as p3_field::PrimeField64>::ORDER_U64,
            "the public values' field (ZKQ-4's canonical bound)"
        );
        let honest = DeclaredShape {
            tier: randprotocol_core::types::BUNDLE_PROOF_TIER,
            public_log_height: randprotocol_core::types::BUNDLE_PUBLIC_LOG_HEIGHT,
            ..fixture_free_shape()
        };
        check_admitted_shape(&honest).expect("the pinned bundle header is buildable");
        match check_admitted_shape(&DeclaredShape { mem_log_height: 60, ..honest }) {
            Err(ConfidentialError::BadDeclaredShape(_)) => {}
            other => panic!("an absurd mem height must not build, got {other:?}"),
        }
    }

    /// The rescan's ZKQ-2: the tier gate read the proof's `usize` tier `as u8`, which wraps — a
    /// header declaring tier 276 is gated as 20, an admitted test tier (and 532 as 20, …; at
    /// constraint set 8 the case was 277 as 21). The rVM's own `check_declared_heights` refuses
    /// such a tier later, but the gate is the one admission runs first and it must say what the
    /// proof says.
    #[test]
    fn a_tier_past_u8_is_refused_not_wrapped_into_an_admitted_one() {
        let ex = AggExecutor::new(FriProfile::Test);
        let shape = fixture_free_shape();
        let covered = vec![CoveredBundle { public_values: [7; randprotocol_core::types::pv::NUM], shape }];
        let binding = [3u32; 8];
        assert!(admitted_tiers(FriProfile::Test).contains(&((276usize) as u8)), "276 wraps to an admitted tier");
        let proof = crafted_proof(&shape, &covered, &binding, 276, 0);
        match ex.check_aggregate_header(&proof) {
            Err(ConfidentialError::InvalidAggregateProof(m)) => assert!(m.contains("276"), "{m}"),
            other => panic!("tier 276 must be refused as itself, got {other:?}"),
        }
        assert_eq!(ex.program_builds(), 0);
    }

    /// Why the wrapper exists: the bare zkVM executor names its own refusal, so a miswired node
    /// (or a test that forgot the wrapper) gets `AggregationUnsupported`, never a wrong digest.
    #[test]
    fn the_bare_zkvm_executor_refuses_the_aggregate_surface_by_name() {
        let (shape, cov) = covered(0);
        let zk = ZkExecutor::new(FriProfile::Test);
        assert_eq!(
            zk.aggregate_program_digest(&shape),
            Err(ConfidentialError::AggregationUnsupported)
        );
        assert_eq!(
            zk.verify_aggregate(&shape, &[cov], b"proof", &[0; 8]),
            Err(ConfidentialError::AggregationUnsupported)
        );
    }

    /// Delegation is real: the hash surface answers exactly what the bare executor answers.
    #[test]
    fn the_wrapper_delegates_the_zkvm_surface() {
        let w = AggExecutor::new(FriProfile::Test);
        let zk = ZkExecutor::new(FriProfile::Test);
        let (a, b) = ([1u32; 8], [2u32; 8]);
        assert_eq!(w.node_hash(&a, &b), zk.node_hash(&a, &b));
        assert_eq!(w.note_commitment(&a, &b, 5, 0, 9, &a), zk.note_commitment(&a, &b, 5, 0, 9, &a));
        // The v0.6 rules' defaulted methods too (a default here would switch a rule off).
        assert_eq!(w.max_callable_program_words(0), zk.max_callable_program_words(0));
        assert_eq!(w.max_callable_program_words(0), Some(8184));
        // INT-4's hardened call path: the trait default refuses every call by name, the zkVM's
        // answers the bytes (these do not decode).
        let record = ProgramRecord { id: randprotocol_core::Hash::digest(b"p"), base_pc: 0, words: vec![0x13; 4], code_hash: vec![0; 32], deployed_at: 0, public_digest: None, public_len: 0 };
        assert_eq!(w.verify_call_hardened(&record, b"junk", &[0; 8]), zk.verify_call_hardened(&record, b"junk", &[0; 8]));
        assert_eq!(w.decode_call_hardened(&record, b"junk", &[0; 8]), Err(ConfidentialError::MalformedProof));
        // RPL-2's invoke rules: the trait default refuses every invoke with `InvalidProof`
        // ("this executor does not implement …"), which would make the feature dead on every
        // node — the zkVM decodes the bytes.
        assert_eq!(w.verify_invoke(&record, b"junk", &[0; 19]), zk.verify_invoke(&record, b"junk", &[0; 19]));
        assert_eq!(w.verify_invoke(&record, b"junk", &[0; 19]), Err(ConfidentialError::MalformedProof), "not the trait default");
        assert_eq!(w.decode_invoke(&record, b"junk", &[0; 19]), Err(ConfidentialError::MalformedProof));
        // RPL-3's state-proof rules: the trait default refuses every `PerpStateProof` with an
        // `InvalidProof("… does not implement …")`; the zkVM decodes the bytes (junk: malformed).
        let (hc, seg) = ([3u32; 8], [0u32; 40]);
        let junk = b"junk".as_slice();
        let v = w.verify_perp(&hc, 20, &seg, junk);
        let d = w.decode_perp(&hc, 20, &seg, junk);
        assert_eq!(v, zk.verify_perp(&hc, 20, &seg, junk));
        assert_eq!(v, Err(ConfidentialError::MalformedProof), "not the trait default");
        assert_eq!(d, Err(ConfidentialError::MalformedProof), "not the trait default");
        // A stub-built proof is not a valid STARK: the refusal must be the zkVM's, never the
        // trait default's "does not implement" message.
        let stub = StubExecutor::make_perp_proof(&hc, 16, [1; 8], &seg);
        let v = w.verify_perp(&hc, 20, &seg, &stub);
        let d = w.decode_perp(&hc, 20, &seg, &stub);
        assert_eq!(v, zk.verify_perp(&hc, 20, &seg, &stub));
        assert_eq!(d, zk.decode_perp(&hc, 20, &seg, &stub));
        assert!(!format!("{v:?}{d:?}").contains("does not implement"));
        // Constraint set 8's decodes: the trait defaults answer `Ok(None)` ("no limit"), which
        // under a gas section refuses every honest proof — the zkVM decodes the bytes.
        assert_eq!(w.bundle_gas_limit(b"junk"), zk.bundle_gas_limit(b"junk"));
        assert_eq!(w.auth_gas_limit(b"junk"), zk.auth_gas_limit(b"junk"));
        assert!(w.auth_gas_limit(b"junk").is_err(), "not the trait default");
    }

    /// Constraint set 9: the `decode_call` mirror refuses what `check_decoded` refuses for a call,
    /// by the same message, on an honest tier-10 one-modq-block proof — and builds nothing.
    #[test]
    fn decode_call_refuses_a_modq_bearing_call_proof_like_verify_call() {
        let w = AggExecutor::new(FriProfile::Test);
        let zk = ZkExecutor::new(FriProfile::Test);
        let bytes = modq_fixture_proof_bytes();
        let program = randprotocol_zkvm::executor::fixtures::one_modq_ntt_program();
        let code_hash = program.digest().iter().flat_map(|w| w.to_le_bytes()).collect();
        let record = ProgramRecord { id: randprotocol_core::Hash::digest(b"modq"), base_pc: 0, words: program.words.clone(), code_hash, deployed_at: 0, public_digest: None, public_len: 0 };
        let want = ConfidentialError::InvalidProof("a call proof declares no modq table".into());
        assert_eq!(w.decode_call(&record, bytes).unwrap_err(), want);
        assert_eq!(zk.verify_call(&record, bytes).unwrap_err(), want, "the zkVM's own verdict, by the same words");
        assert_eq!(zk.cached_keys(), 0, "refused before any key");
        assert_eq!(w.program_builds() + w.tree_builds(), 0);
    }

    /// Constraint set 9 / circuits Task 9b: an inner proof declaring a modq table never becomes a
    /// covered record, so it never reaches `verify_aggregate`, `verify_tree` or the tree's
    /// bottom-up recompute (each takes `CoveredBundle`s, whose `DeclaredShape` has no modq field:
    /// the refusal is where the header is read). A chip-free fixture still assembles, field for
    /// field what `storage::raw_proof_facts` always read.
    #[test]
    fn an_inner_proof_declaring_a_modq_table_never_becomes_a_covered_record() {
        let ex = AggExecutor::new(FriProfile::Test);
        let p = randprotocol_zkvm::executor::decode_canonical(modq_fixture_proof_bytes()).unwrap();
        let refusal = ConfidentialError::InvalidAggregateProof(INNER_MODQ_REFUSAL.into());
        assert_eq!(check_inner_chip_free(&p), Err(refusal.clone()));
        assert_eq!(covered_bundle_of(&p, CoreProfile::Test).unwrap_err(), refusal);
        let honest = fixture_proof(0);
        assert_eq!(check_inner_chip_free(&honest), Ok(()));
        assert_eq!(covered_bundle_of(&honest, CoreProfile::Test), Ok(covered(0).1));
        assert_eq!(ex.program_builds() + ex.tree_builds(), 0, "nothing reached the rVM");
    }

    /// Every remaining forwarder answers exactly what the bare zkVM executor answers on the same
    /// inputs — hashes, digests, program checks, the plain (non-hardened) call path, and the
    /// bundle/auth verifications. A wrapper method left at the trait default would differ here
    /// (the defaults answer `None`/"unsupported"), and `decode_call`, which re-implements the
    /// zkVM's pre-verify half, is held to the same answers on junk and on a real (bundle) proof
    /// whose header is not a call's.
    #[test]
    fn the_remaining_forwarders_and_decode_call_agree_with_the_bare_zkvm_executor() {
        let w = AggExecutor::new(FriProfile::Test);
        let zk = ZkExecutor::new(FriProfile::Test);
        // Program admission.
        assert_eq!(w.check_program(0, &[0x13; 4]), zk.check_program(0, &[0x13; 4]));
        assert_eq!(w.check_program(2, &[0x13; 4]), zk.check_program(2, &[0x13; 4]));
        assert!(w.check_program(2, &[0x13; 4]).is_err(), "an unaligned base is refused through the wrapper");
        // Hashes.
        assert_eq!(w.public_digest(&[1, 2, 3]), zk.public_digest(&[1, 2, 3]));
        assert_eq!(w.hash_domain(7, &[1, 2, 3]), zk.hash_domain(7, &[1, 2, 3]));
        assert_ne!(w.hash_domain(7, &[1, 2, 3]), w.hash_domain(8, &[1, 2, 3]), "the domain separates");
        let input = randprotocol_core::notes::BundleDigestInput {
            anchor: [1; 8],
            nullifiers: [[2; 8], [3; 8], [4; 8], [5; 8]],
            commitments: [[6; 8], [7; 8], [8; 8], [9; 8]],
            fee: 11,
            burn_a: 12,
            burn_r: 13,
            burn_asset: 14,
            time: 15,
            auth_commit: [16; 8],
        };
        assert_eq!(w.bundle_digest(&input), zk.bundle_digest(&input));
        assert_eq!(w.bundle_digest_v3(&input), zk.bundle_digest_v3(&input));
        assert_ne!(w.bundle_digest(&input), w.bundle_digest_v3(&input), "v3 binds the auth commitment");
        // Proof digests and verifications, on bytes that are not proofs.
        let hc = [3u32; 8];
        let binding = [0u32; randprotocol_core::types::TX_BINDING_WORDS];
        for junk in [&b""[..], b"junk", &[0xff; 64]] {
            assert_eq!(w.bundle_proof_digest(&hc, junk), zk.bundle_proof_digest(&hc, junk));
            assert_eq!(w.auth_proof_digest(junk), zk.auth_proof_digest(junk));
            assert_eq!(w.verify_auth(&hc, junk, &binding), zk.verify_auth(&hc, junk, &binding));
            assert_eq!(w.verify_bundle(&hc, junk, &binding), zk.verify_bundle(&hc, junk, &binding));
            assert_eq!(w.non_canonical_proof(junk), zk.non_canonical_proof(junk));
        }
        assert_eq!(w.verify_bundle(&hc, b"junk", &binding), Err(ConfidentialError::MalformedProof));
        // The plain call path: `verify_call` is the zkVM's; `decode_call` is a mirror of its
        // pre-verify half and must refuse what it refuses.
        let record = ProgramRecord { id: randprotocol_core::Hash::digest(b"p"), base_pc: 0, words: vec![0x13; 4], code_hash: vec![0; 32], deployed_at: 0, public_digest: None, public_len: 0 };
        for junk in [&b""[..], b"junk"] {
            assert_eq!(w.verify_call(&record, junk), zk.verify_call(&record, junk));
            assert_eq!(w.decode_call(&record, junk), Err(ConfidentialError::MalformedProof));
        }
        // Non-canonical encodings of a real proof (trailing bytes) are malformed, not decoded.
        let real = fixture_proof(0).to_bytes();
        let mut padded = real.clone();
        padded.push(0);
        assert_eq!(w.decode_call(&record, &padded), Err(ConfidentialError::MalformedProof));
        assert_eq!(w.verify_call(&record, &padded), zk.verify_call(&record, &padded));
        // The fixture is a canonical rVM-shaped proof over an empty public input: `decode_call`
        // reads its header and public values off exactly as the zkVM's decode does — the tier,
        // the declared limit, `OUT0..7` and `H_IN` — and does not verify it (admission did that).
        use randprotocol_zkvm::tables::cpu::pv;
        let p = fixture_proof(0);
        let got = w.decode_call(&record, &real).expect("the fixture's header and public values decode");
        assert_eq!(got.tier, p.tier.0 as u8);
        assert_eq!(got.gas_limit, p.public_values[pv::GAS]);
        assert_eq!(got.outputs, std::array::from_fn(|i| p.public_values[pv::OUT0 + i] as u32));
        assert_eq!(got.h_in, std::array::from_fn(|i| p.public_values[pv::IN0 + i] as u32));
        assert_eq!((got.keccak_log_height, got.sha256_log_height), (p.keccak_log_height, p.sha256_log_height));
        // A record that claims a public input the proof's public table does not hold is refused
        // by name (the public-table height is the record's, `PublicValues`), as is a record whose
        // deploy-time public digest is not the one the proof publishes.
        let mut other = record.clone();
        other.public_len = 100_000;
        match w.decode_call(&other, &real) {
            Err(ConfidentialError::InvalidProof(m)) => assert!(m.contains("PublicValues"), "{m}"),
            r => panic!("a mismatched public table must be refused, got {r:?}"),
        }
        let mut wrong_digest = record.clone();
        wrong_digest.public_digest = Some([0xdead; 8]);
        match w.decode_call(&wrong_digest, &real) {
            Err(ConfidentialError::InvalidProof(m)) => assert!(m.contains("PublicValues"), "{m}"),
            r => panic!("a wrong public digest must be refused, got {r:?}"),
        }
        // Warming the hardened call path for a record is a no-op for a junk-free record but must
        // not panic; the plain warm is skipped (it builds a verifier key).
        w.warm_hardened(&record);
    }

    /// The registered artifact (spec §2.3): the wrapper's digest is the rVM's own
    /// `aggregate_program_digest` over the same shape, deterministically.
    #[test]
    fn the_aggregate_program_digest_is_the_rvms_own_build() {
        let (shape, _) = covered(0);
        let w = AggExecutor::new(FriProfile::Test);
        let got = w.aggregate_program_digest(&shape).expect("the fixture shape builds");
        let vk = AggExecutor::inner_key(&shape).unwrap();
        use p3_field::PrimeField64;
        let want = randprotocol_rvm::programs::aggregate_program_digest(&vk.shape, &vk.key).map(|f| f.as_canonical_u64());
        assert_eq!(got, want);
        assert_eq!(
            got,
            w.aggregate_program_digest(&shape).unwrap(),
            "the build is deterministic — the genesis-pinned value is reproducible"
        );
    }

    /// circuits recursion/docs/09 §5's and docs/10 §5's re-vendor checklists: the node's production
    /// aggregate program digest is the current circuits pin, so a stale admission list fails here
    /// instead of verifying an old program (phase 4 reinterpreted opcodes 25/27 under an unchanged
    /// key; phase 5 changed the `QueryBits` tape layout under unchanged keys, and a pre-phase-5
    /// tape does not decode under the new program). The production bundle shape is the fixture
    /// shape at the production profile (the heights are the trace's, not the FRI profile's), as
    /// circuits' `tests/aggregate.rs` builds it; the pin is that test's (`dc350ecf…` pre-phase-4,
    /// `e0eede8b…` at phase 4, `8bc2cecb…` with the MODQ chip, `792a66d4…` at phase 5).
    #[test]
    fn the_production_aggregate_program_digest_is_the_phase_5_pin() {
        let (mut shape, _) = covered(0);
        shape.profile = CoreProfile::Production;
        let got = AggExecutor::new(FriProfile::Production).aggregate_program_digest(&shape).expect("the production shape builds");
        let hex: String = got.iter().map(|w| format!("{w:016x}")).collect();
        assert_eq!(hex, "792a66d4a995c7b3874d38ecb8c971d5494b57b4cce13db11e08a4f9b2f9a982");
    }

    /// Audit v3, AGG-3: the spec admits three rVM tiers (production {21, 22, 23} at constraint
    /// set 8, {20, 21, 22} since the phase-2 row cuts, {19, 20, 21} since rVM phase 4, {18, 19, 20, 21} since rVM phase 5) and nothing checked it. `Machine::verify` builds the verifier key for whatever tier the proof declares *before*
    /// verifying the proof, so a proposer could put an invalid aggregate at an unwarmed tier in a
    /// block and every replica would pay a 30–70 s key build — on the consensus loop, at block
    /// apply — before refusing it.
    #[test]
    fn a_proof_at_an_unadmitted_tier_is_refused() {
        for t in admitted_tiers(FriProfile::Production) {
            assert!(check_tier(FriProfile::Production, *t).is_ok(), "tier {t} is admitted");
        }
        // Tier 18 is admitted since rVM phase 5 (production N=1); 17 and 22 are the rungs beside the set.
        for t in [8u8, 17, 22, 23, 255] {
            match check_tier(FriProfile::Production, t) {
                Err(ConfidentialError::InvalidAggregateProof(m)) => {
                    assert!(m.contains(&t.to_string()), "the refusal names the tier: {m}")
                }
                other => panic!("tier {t} must be refused on a production chain, got {other:?}"),
            }
        }
        // The profiles admit different sets: a test-profile proof's tier is not a production one.
        assert!(check_tier(FriProfile::Test, 18).is_ok());
        assert!(check_tier(FriProfile::Test, 19).is_ok());
        assert!(check_tier(FriProfile::Production, 17).is_err());
        // rVM phase 5: production N=1 is 235 744 rows, tier 18, admitted (phase 4 had it at 19);
        // tier 22 still admits nothing (N ≤ 5 lands at 21).
        assert!(check_tier(FriProfile::Production, 18).is_ok());
        assert!(check_tier(FriProfile::Production, 19).is_ok());
        assert!(check_tier(FriProfile::Production, 21).is_ok());
        assert!(check_tier(FriProfile::Production, 22).is_err());
        assert!(check_tier(FriProfile::Test, 21).is_err());
        assert!(check_tier(FriProfile::Test, 23).is_err());
    }

    /// Cheap refusals, before any program build: the empty cover set and the undecodable proof.
    #[test]
    fn verify_aggregate_refuses_the_empty_set_and_malformed_bytes_cheaply() {
        let (shape, cov) = covered(0);
        let w = AggExecutor::new(FriProfile::Test);
        match w.verify_aggregate(&shape, &[], b"whatever", &[0; 8]) {
            Err(ConfidentialError::InvalidAggregateProof(_)) => {}
            other => panic!("an empty cover set must be a named refusal, got {other:?}"),
        }
        assert_eq!(
            w.verify_aggregate(&shape, &[cov], b"not a postcard proof", &[0; 8]),
            Err(ConfidentialError::MalformedProof)
        );
    }

    /// The conformance suite (spec §4, and the plan's gate): the admission stub is not trusted
    /// until the fullnode's recompute reproduces `circuits/recursion/docs/02-aggregate.md`'s
    /// pinned vectors byte-for-byte — the `inner_vk_digest` (a constant of the fixture shape),
    /// the 118-word bound interface list `[vk ‖ 3 ‖ B(8) ‖ 35·3]` for the 3-proof test-profile
    /// fixture set under the doc's stand-in binding (AGG-2), and its digest.
    /// The list rides on the fixtures' random notes, so this pins against *this* fixture
    /// cache, the same one the doc's worked example measured (regenerated 2026-09-21 after the
    /// original cache was lost with a `/tmp` worktree; the vk digest — the data-independent
    /// half — is unchanged, proving the program and shape did not move). Constraint set 7
    /// (v0.6.1) moved all three with the inner machine: the values are circuits `b9ffc39`'s
    /// `docs/02-aggregate.md`, measured on the cs7 fixture cache generated 2026-09-28 on the
    /// testbox (`/root/recursion-fixtures-cs7`), and this test reproduces them from that cache.
    /// Constraint set 8 (`pv::GAS`, 35 public values a proof) moved them again: circuits
    /// `6d4f124`'s `docs/02-aggregate.md`, measured on a fresh cs8 fixture cache. The final
    /// review's `gas_max` absorb term (circuits `09b032f`) moved each fixture proof's default
    /// `GAS` 16383 → 20479, so the cache was regenerated and the list and its digest moved again
    /// (`36b414c0…` → `5e3d7fb2…`, circuits `6b18928`); the vk digest did not. The phase-2 re-vendor
    /// (circuits `75b7893`, 2026-10-04) runs against the cache re-proved on 2026-10-03
    /// (`~/rand-agg-512-results/out/fixtures`; the droplet sync had brought only the logs), so the
    /// list and its digest moved once more with the notes (`5e3d7fb2…` → `3534960f…`) — data, not
    /// program: the vk digest is unchanged, as `recursion/docs/04` says of the inner machine.
    /// Constraint set 9 (the MODQ chip, circuits `57fb9dc`, 2026-10-11) moved the inner shape and
    /// the proof encoding: the vk digest moved for the first time since constraint set 8
    /// (`346ee184…` → `1b0c4b00…`, circuits recursion/docs/09 §6), the fixtures were re-proved
    /// (`scripts/recursion-fixtures.sh`), and the list and its digest moved with both
    /// (`3534960f…` → `3753f2fd…`).
    #[test]
    fn the_admission_recompute_reproduces_the_pinned_vectors_byte_for_byte() {
        use p3_field::PrimeField64;
        let hex_words = |words: &[randprotocol_rvm::isa::F]| -> String {
            words.iter().map(|w| format!("{:016x}", w.as_canonical_u64())).collect::<Vec<_>>().join("")
        };
        let (shape, _) = covered(0);
        for k in 1..3 {
            let (s, _) = covered(k);
            assert_eq!(s, shape, "the fixture set shares one declared shape");
        }
        let vk = AggExecutor::inner_key(&shape).unwrap();
        // The inner vk digest, a data-independent constant of the shape.
        assert_eq!(
            hex_words(&randprotocol_rvm::shape::inner_vk_digest(&vk.shape, &vk.key)),
            "1b0c4b0043dd5d00d710f10048bfde989a955034d7fd52f1a85595a61339ddc7",
            "the pinned inner_vk_digest"
        );
        // The 118-word interface list, built the way admission builds it: from the covered
        // bundles' `pv::NUM` public values, in cover order, with the binding after the count.
        let pvs: Vec<Vec<u64>> = (0..3).map(|k| covered(k).1.public_values.to_vec()).collect();
        let list = randprotocol_rvm::public_values::interface_words_bound(&vk.shape, &vk.key, &DOC_BINDING, &pvs);
        assert_eq!(list.len(), 4 + 1 + 8 + randprotocol_core::types::pv::NUM * 3);
        assert_eq!(hex_words(&list), INTERFACE_LIST_HEX, "the pinned 118-word interface list");
        assert_eq!(
            hex_words(&randprotocol_rvm::public_values::public_digest(&list)),
            "3753f2fd7ba2091910f1a5eb6b722c3b55e71e7661854c058d95ed446cb186b4",
            "the pinned interface digest"
        );
    }

    /// `docs/02-aggregate.md`'s stand-in binding (its tests' `common::TEST_BINDING`): on a chain
    /// the words are `aggregate_binding(chain_id, aggregator, nonce)`.
    const DOC_BINDING: [u32; 8] =
        [0xA662_0000, 0xA662_0001, 0xA662_0002, 0xA662_0003, 0xA662_0004, 0xA662_0005, 0xA662_0006, 0xA662_0007];

    /// `docs/02-aggregate.md`'s worked example: the 118-word interface list for the 3-proof
    /// test-profile fixture set, each word the canonical `u64` as 16 lowercase hex chars.
    const INTERFACE_LIST_HEX: &str = concat!(
        "1b0c4b0043dd5d00d710f10048bfde989a955034d7fd52f1a85595a61339ddc7",
        "000000000000000300000000a662000000000000a662000100000000a6620002",
        "00000000a662000300000000a662000400000000a662000500000000a6620006",
        "00000000a66200070000000000000000000000000000000e0000000009798e88",
        "000000001bc1014400000000c6454ed8000000006b17834200000000f8f1a540",
        "000000005c25de80000000007983d65e00000000841b3716000000006f35274a",
        "000000000371953700000000a8a42560000000004b291c6600000000b7c2de0e",
        "00000000d6bf7fcf00000000182b470b00000000fb4abd6c00000000d68ddbe1",
        "0000000012f885a60000000032d1718800000000c3bc890400000000d7286a18",
        "0000000056171f8a00000000dc91a25d000000008f77eb5a00000000934a2759",
        "00000000d5389ac8000000002e612784000000008639ed090000000085f58a21",
        "000000004448d889000000006bb9c915000000000671dc2c0000000000004fff",
        "0000000000000000000000000000000e000000006c3312a900000000bb1b0223",
        "00000000d9e09f5b000000001d46c05b00000000d1be87c4000000007b76acd3",
        "000000005e7267ff00000000c4731095000000006f35274a0000000003719537",
        "00000000a8a42560000000004b291c6600000000b7c2de0e00000000d6bf7fcf",
        "00000000182b470b00000000fb4abd6c000000004b556bca00000000341d2f5f",
        "0000000079f436080000000091f8e29c000000001ba6f2fd00000000ad68b2ba",
        "0000000013fa3f2300000000490af7f100000000934a275900000000d5389ac8",
        "000000002e612784000000008639ed090000000085f58a21000000004448d889",
        "000000006bb9c915000000000671dc2c0000000000004fff0000000000000000",
        "000000000000000e00000000d74313f3000000004675ac4000000000f4c1f8eb",
        "00000000a9cf0890000000005dda21530000000043e32a4d0000000002ecb55a",
        "000000005e6e3049000000006f35274a000000000371953700000000a8a42560",
        "000000004b291c6600000000b7c2de0e00000000d6bf7fcf00000000182b470b",
        "00000000fb4abd6c00000000a6a7204c00000000dbb032c800000000e550ab3e",
        "000000004cc1905e000000007a603b2a00000000379776a200000000c7d34ee3",
        "000000003dc30f7b00000000934a275900000000d5389ac8000000002e612784",
        "000000008639ed090000000085f58a21000000004448d889000000006bb9c915",
        "000000000671dc2c0000000000004fff",
    );

    /// An RV32 bundle proof's bytes are not an rVM aggregate proof: the answer is a named error,
    /// never a panic — even if the postcard bytes happen to decode across the two proof types.
    #[test]
    fn an_rv32_bundle_proof_is_not_an_aggregate_proof() {
        let (shape, cov) = covered(0);
        let bundle_proof = fixture_proof(0);
        let w = AggExecutor::new(FriProfile::Test);
        match w.verify_aggregate(&shape, &[cov], &bundle_proof.to_bytes(), &[0; 8]) {
            Err(ConfidentialError::MalformedProof | ConfidentialError::InvalidAggregateProof(_)) => {}
            other => panic!("a bundle proof fed as an aggregate must be a named refusal, got {other:?}"),
        }
    }

    /// The startup obligation (spec §2.3): one call builds the N-generic program and warms one
    /// verifier key per admitted tier and canonical reduce height for N = 1..=max_covers (circuits
    /// docs/06 §5). At the test fixture shape and the chains' `max_covers` 3 that is heights
    /// `2^16` (N=1) and `2^17` (N=2–3) — two heights × three tiers.
    #[test]
    fn warm_aggregation_builds_the_program_and_key() {
        let (shape, _) = covered(0);
        let w = AggExecutor::new(FriProfile::Test);
        let program = aggregate_program(&AggExecutor::inner_key(&shape).unwrap());
        assert_eq!(warm_reduce_heights(&program, 3), vec![16, 17], "the canonical heights for N = 1..=3");
        assert_eq!(warm_reduce_heights(&program, 1000).last(), Some(&randprotocol_rvm::machine::REDUCE_MAX_LOG_HEIGHT), "capped at the ceiling");
        w.warm_aggregation(&shape, 3);
        assert_eq!(w.rvm.cached_keys(), 2 * admitted_tiers(FriProfile::Test).len(), "one key per (tier, canonical height)");
    }

    /// The production warm heights: N = 1 / 2 / 3 at the production bundle shape are the
    /// canonical `2^18` / `2^19` / `2^20`. DSL emission only (`aggregate_program`, no verifier
    /// key build); the shape is read off the production fixture proof, which is not committed, so
    /// without `Production-0.proof` in `RECURSION_FIXTURES` this skips.
    #[test]
    fn the_production_warm_heights_are_the_canonical_three() {
        let dir = std::env::var_os("RECURSION_FIXTURES")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/recursion"));
        let Ok(bytes) = std::fs::read(dir.join("Production-0.proof")) else {
            eprintln!("skipped: no Production-0.proof in {}", dir.display());
            return;
        };
        let p: randprotocol_zkvm::machine::Proof = postcard::from_bytes(&bytes[32..]).expect("a production fixture proof decodes");
        let shape = DeclaredShape {
            profile: CoreProfile::Production,
            tier: p.tier.0 as u8,
            program_log_height: p.program_log_height,
            input_log_height: p.input_log_height,
            keccak_log_height: p.keccak_log_height,
            sha256_log_height: p.sha256_log_height,
            public_log_height: p.public_log_height,
            mem_log_height: p.mem_log_height,
        };
        let program = aggregate_program(&AggExecutor::inner_key(&shape).unwrap());
        assert_eq!(warm_reduce_heights(&program, 3), vec![18, 19, 20]);
    }

    /// The real round-trip: one fixture bundle proof aggregated by the rVM, the proof bytes
    /// verified through the wrapper, the covered bundle's `OUT0..7` back. `#[ignore]`d out of
    /// the gates: the tier-18 prove (tier 19 before the phase-2 row cuts) holds tens of GB live and
    /// takes tens of minutes contended — the runbook's job, run alone:
    /// `RECURSION_FIXTURES=... cargo test --release -p randprotocol-node --lib agg_executor -- --ignored --nocapture`
    #[test]
    #[ignore = "a real tier-18 rVM aggregate prove (projected ≈ 50 GB live, tens of minutes contended); run alone"]
    fn an_aggregate_of_one_fixture_bundle_round_trips_through_the_wrapper() {
        let (shape, cov) = covered(0);
        let inner = fixture_proof(0);
        let vk = AggExecutor::inner_key(&shape).unwrap();
        let m = randprotocol_rvm::machine::Machine::new(FriProfile::Test);
        let binding = randprotocol_core::types::actions::aggregate_binding(7, &randprotocol_core::Address([1; 32]), 0);
        let a = randprotocol_rvm::aggregate::aggregate(&m, &vk, std::slice::from_ref(&inner), &binding, None)
            .expect("one real bundle proof aggregates");
        let w = AggExecutor::new(FriProfile::Test);
        let outs = w
            .verify_aggregate(&shape, std::slice::from_ref(&cov), &a.proof.to_bytes(), &binding)
            .expect("the wrapper verifies the aggregate");
        // AGG-2: the same bytes under another aggregator's binding are refused.
        let other = randprotocol_core::types::actions::aggregate_binding(7, &randprotocol_core::Address([2; 32]), 0);
        match w.verify_aggregate(&shape, std::slice::from_ref(&cov), &a.proof.to_bytes(), &other) {
            Err(ConfidentialError::InvalidAggregateProof(_)) => {}
            other => panic!("an aggregate re-signed by another aggregator must be refused, got {other:?}"),
        }
        let want: [u32; 8] = std::array::from_fn(|k| {
            u32::try_from(cov.public_values[randprotocol_zkvm::tables::cpu::pv::OUT0 + k]).unwrap()
        });
        assert_eq!(outs, vec![want], "the covered bundle's OUT0..7, in cover order");
    }


    // ── tree aggregation (circuits docs/08, spec §4 / §4.1 per-level lists) ─────────────────────

    use randprotocol_core::ledger::aggregation::{AggregationError, RvmHeights, TreeConfig, TreeStepPin};

    /// The cached test tree's declared heights (circuits Task 1b, `$RECURSION_FIXTURES/tree/`,
    /// docs/08 §5): `Test-leaf-0` (`rv32n` at L = 1), `Test-step-0` (level 1, `rv32t_leaf`) and
    /// `Test-root` (level 2, `rv32t_int`). Data a genesis cut reads off the proofs, held here so the
    /// node lib suite runs without the cache; `the_test_tree_heights_are_the_cached_proofs` holds
    /// them to the cache wherever it is present.
    const TEST_LEAF: RvmHeights = RvmHeights { tier: 18, reg_log_height: 19, ram_log_height: 19, poseidon2_log_height: 14, reduce_log_height: 16 };
    // rVM phase 4 (circuits docs/09 §7): both steps are tier 18 and both cross 2^16 reduce rows, so
    // the root declares S_T's header words and the fixed point is level 2 (was level 3, tier 19).
    const TEST_STEP: RvmHeights = RvmHeights { tier: 18, reg_log_height: 19, ram_log_height: 20, poseidon2_log_height: 15, reduce_log_height: 17 };
    const TEST_ROOT: RvmHeights = RvmHeights { tier: 18, reg_log_height: 19, ram_log_height: 20, poseidon2_log_height: 15, reduce_log_height: 17 };

    /// circuits `recursion/tests/pins.json`'s `tree_test` keys (`vk_leaf`, `vk_t_leaf`, `vk_int`),
    /// as canonical u64 limbs: what the rVM's own suite computes from the proved shapes.
    /// rVM phase 4 dropped `vk_fix` (the fixed point is level 2, `vk_int` itself: docs/09 §7).
    const PIN_VK_LEAF: [u64; 4] = [8319022251449045440, 6921460171031583545, 12120586048388560564, 2237657693139026209];
    const PIN_VK_T_LEAF: [u64; 4] = [149934054759036529, 11853972217771236064, 7974370166788545537, 4681341164698736412];
    const PIN_VK_INT: [u64; 4] = [17974589521606301101, 12194447673073698417, 12600030651550503010, 948039196462741351];

    /// A tree proof from `$RECURSION_FIXTURES/tree/{name}.rvmproof` (the bare postcard rVM proof),
    /// with `fixture_proof`'s loud failure.
    fn load_tree(dir: &std::path::Path, name: &str) -> randprotocol_rvm::machine::Proof {
        let path = dir.join("tree").join(format!("{name}.rvmproof"));
        let bytes = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("{}: {e} — the tree tests read circuits' cached test tree (recursion `tests/tree.rs`, docs/08 §5); point RECURSION_FIXTURES at a cache holding tree/", path.display())
        });
        postcard::from_bytes(&bytes).expect("a tree fixture decodes")
    }

    fn heights_of(p: &randprotocol_rvm::machine::Proof) -> RvmHeights {
        RvmHeights {
            tier: p.tier.0 as u8,
            reg_log_height: p.reg_log_height,
            ram_log_height: p.ram_log_height,
            poseidon2_log_height: p.poseidon2_log_height,
            reduce_log_height: p.reduce_log_height,
        }
    }

    /// The test-profile `aggregation_tree` section, built the way a genesis cut computes it: the
    /// heights read off the cached test leaf, step and root, the digests from the rVM's own
    /// `TreeShapes` over them (never this executor's, so a node-side mapping slip is a mismatch).
    /// L = 1, max_depth 2, two listed levels.
    fn test_tree_cfg() -> TreeConfig {
        use p3_field::PrimeField64;
        let (shape, _) = covered(0);
        let inner = AggExecutor::inner_key(&shape).unwrap();
        let s = randprotocol_rvm::aggregate::TreeShapes::build(
            FriProfile::Test,
            &inner,
            rvm_heights(TEST_LEAF),
            &[rvm_heights(TEST_STEP), rvm_heights(TEST_ROOT)],
        )
        .unwrap();
        let u = |d: [randprotocol_rvm::isa::F; 4]| d.map(|f| f.as_canonical_u64());
        let k = s.keys();
        let steps = [TEST_STEP, TEST_ROOT]
            .iter()
            .enumerate()
            .map(|(i, h)| TreeStepPin { heights: *h, program_digest: u(s.steps[i].program.digest()), key: u(k.step_keys[i]) })
            .collect();
        TreeConfig { shape, leaf_size: 1, max_depth: 2, leaf: TEST_LEAF, vk_leaf: u(k.vk_leaf), steps }
    }

    /// The heights above are the cache's (skipped without `RECURSION_FIXTURES`; the in-repo set
    /// has no tree). The leaves and both level-1 steps each declare one shape.
    #[test]
    fn the_test_tree_heights_are_the_cached_proofs() {
        let Some(dir) = std::env::var_os("RECURSION_FIXTURES").map(std::path::PathBuf::from) else {
            eprintln!("skipped: RECURSION_FIXTURES is not set (the in-repo set has no tree/)");
            return;
        };
        for k in 0..4 {
            assert_eq!(heights_of(&load_tree(&dir, &format!("Test-leaf-{k}"))), TEST_LEAF, "leaf {k}");
        }
        for k in 0..2 {
            assert_eq!(heights_of(&load_tree(&dir, &format!("Test-step-{k}"))), TEST_STEP, "step {k}");
        }
        assert_eq!(heights_of(&load_tree(&dir, "Test-root")), TEST_ROOT, "root");
    }

    /// The node's rebuild is circuits': the executor's `tree_digests` over the test section are
    /// the rVM suite's pinned keys, and one entry per listed level, in order.
    #[test]
    #[ignore = "pending rVM phase 5's test-tree fixture regeneration in circuits (recursion/docs/10 §5): T_INT_TEST, the tree_test vk_leaf / vk_t_leaf / vk_int limbs and tests/tree-test-genesis.json are still the phase-4 record; re-sync them and un-ignore"]
    fn the_rebuilt_test_tree_keys_are_the_circuits_pins() {
        let ex = AggExecutor::new(FriProfile::Test);
        let t = test_tree_cfg();
        let d = ex.tree_digests(&t).expect("the test section rebuilds");
        assert_eq!(d.vk_leaf, PIN_VK_LEAF, "vk_leaf");
        assert_eq!(d.steps.len(), 2, "one entry per listed level");
        assert_eq!(d.steps[0].1, PIN_VK_T_LEAF, "level 1's step key (vk_t_leaf)");
        assert_eq!(d.steps[1].1, PIN_VK_INT, "level 2's step key (vk_int)");
        assert_eq!((d.steps[0].0, d.steps[1].0), (t.steps[0].program_digest, t.steps[1].program_digest));
        assert_eq!(ex.tree_builds(), 1);
        ex.tree_digests(&t).unwrap();
        assert_eq!(ex.tree_builds(), 1, "the section is built once (memoised by its whole content)");
    }

    /// The memo is keyed by the whole section: two sections differing only in one level's
    /// heights are two builds with different digests (a key narrower than the section — the
    /// shape, the pins — would hand the second the first's rebuild).
    #[test]
    fn sections_differing_in_one_height_do_not_share_a_rebuild() {
        let ex = AggExecutor::new(FriProfile::Test);
        let a = test_tree_cfg();
        let mut b = a.clone();
        b.steps[1].heights.tier += 1;
        let (da, db) = (ex.tree_digests(&a).unwrap(), ex.tree_digests(&b).unwrap());
        assert_eq!(ex.tree_builds(), 2, "two sections, two builds");
        assert_ne!(da.steps[1].1, db.steps[1].1, "level 2's key follows its own heights");
        assert_eq!(da.steps[0], db.steps[0], "level 1 is the same in both");
        assert_eq!(ex.tree_digests(&a).unwrap(), da, "and each is served from its own entry");
        assert_eq!(ex.tree_builds(), 2);
    }

    /// The startup check (spec §4: "refuses to start on a mismatch"), stricter than admission's
    /// per-depth 7b: the honest section passes, and every pin, flipped alone, is named — keys by
    /// the consuming level (circuits' `at_level`), program digests as `AggregateProgramMismatch`,
    /// whichever level's.
    #[test]
    fn the_tree_pins_are_checked_at_startup() {
        let ex = AggExecutor::new(FriProfile::Test);
        let good = test_tree_cfg();
        check_tree_pins(&ex, &good).expect("the cached test tree's own pins");
        let flip = |f: &dyn Fn(&mut TreeConfig)| {
            let mut t = good.clone();
            f(&mut t);
            check_tree_pins(&ex, &t)
        };
        assert!(matches!(flip(&|t| t.vk_leaf = [1; 4]), Err(TreePinError::Pin(AggregationError::TreeKeyPin { level: 1 }))));
        assert!(matches!(flip(&|t| t.steps[0].key = [1; 4]), Err(TreePinError::Pin(AggregationError::TreeKeyPin { level: 2 }))));
        assert!(matches!(flip(&|t| t.steps[1].key = [1; 4]), Err(TreePinError::Pin(AggregationError::TreeKeyPin { level: 3 }))));
        assert!(matches!(
            flip(&|t| t.steps[0].program_digest = [1; 4]),
            Err(TreePinError::Pin(AggregationError::AggregateProgramMismatch { pinned: [1, 1, 1, 1], .. }))
        ));
        assert!(matches!(
            flip(&|t| t.steps[1].program_digest = [1; 4]),
            Err(TreePinError::Pin(AggregationError::AggregateProgramMismatch { pinned: [1, 1, 1, 1], .. }))
        ));
        // Admission at depth 1 reads neither level-2 pin; startup reads both.
        let mut deep_only = good.clone();
        deep_only.steps[1].key = [1; 4];
        assert!(check_tree_pins(&ex, &deep_only).is_err(), "a level only a depth-2 tree uses is still checked");
    }

    /// The deferred 3a M6 and what makes a section unservable: a leaf size past the rVM's N
    /// ceiling for the shape (no leaf can be proved), a pinned reduce height that is not canonical
    /// for its program (no honest proof declares it), and a `max_depth` past the listed levels
    /// whose last entry is not a fixed point (since rVM phase 4 the two-level test list's last
    /// entry is one, docs/09 §7, so the list cut to level 1 alone stands in). Each refuses
    /// startup as `Unbuildable`, before any pin is compared.
    #[test]
    fn a_tree_section_the_rvm_cannot_serve_refuses_startup() {
        let ex = AggExecutor::new(FriProfile::Test);
        let good = test_tree_cfg();
        let max_n = ex.built_program(&good.shape).unwrap().max_n;
        let refused = |t: &TreeConfig, want: &str| match check_tree_pins(&ex, t) {
            Err(TreePinError::Unbuildable(ConfidentialError::BadDeclaredShape(m))) => assert!(m.contains(want), "{m}"),
            other => panic!("want Unbuildable naming {want:?}, got {other:?}"),
        };
        refused(&TreeConfig { leaf_size: max_n as u8 + 1, ..good.clone() }, "N ceiling");
        let mut t = good.clone();
        t.leaf.reduce_log_height += 1;
        refused(&t, "canonical");
        let mut t = good.clone();
        t.steps[0].heights.reduce_log_height += 1;
        refused(&t, "canonical");
        refused(&TreeConfig { steps: good.steps[..1].to_vec(), max_depth: 2, ..good.clone() }, "fixed point");
        refused(&TreeConfig { steps: Vec::new(), ..good.clone() }, "EmptyTreeSteps");
    }

    /// The test list's fixed point (rVM phase 4, circuits docs/09 §7: it moved from level 3 to
    /// level 2): `rv32t` at the root's shape is `rv32t_int` itself, so the two listed levels
    /// admit a `max_depth` past the list, a third entry at the root's heights rebuilds level 2's
    /// program and `vk_int` exactly, and the startup check passes. (The three-entry list and its
    /// `vk_fix` pin are gone with the level-3 fixed point.)
    #[test]
    #[ignore = "pending rVM phase 5's test-tree fixture regeneration in circuits (recursion/docs/10 §5): T_INT_TEST, the tree_test vk_leaf / vk_t_leaf / vk_int limbs and tests/tree-test-genesis.json are still the phase-4 record; re-sync them and un-ignore"]
    fn the_listed_two_levels_are_a_fixed_point_and_admit_a_deeper_max_depth() {
        use p3_field::PrimeField64;
        let ex = AggExecutor::new(FriProfile::Test);
        let mut t = test_tree_cfg();
        let inner = AggExecutor::inner_key(&t.shape).unwrap();
        let s = randprotocol_rvm::aggregate::TreeShapes::build(
            FriProfile::Test,
            &inner,
            rvm_heights(TEST_LEAF),
            &[rvm_heights(TEST_STEP), rvm_heights(TEST_ROOT)],
        )
        .unwrap();
        assert!(s.fixed_point(), "level 2 is the fixed point");
        let three = randprotocol_rvm::aggregate::TreeShapes::build(
            FriProfile::Test,
            &inner,
            rvm_heights(TEST_LEAF),
            &[rvm_heights(TEST_STEP), rvm_heights(TEST_ROOT), rvm_heights(TEST_ROOT)],
        )
        .unwrap();
        let u = |d: [randprotocol_rvm::isa::F; 4]| d.map(|f| f.as_canonical_u64());
        assert_eq!(u(three.steps[2].program.digest()), u(s.steps[1].program.digest()), "level 3 repeats level 2's program");
        assert_eq!(u(three.keys().step_keys[2]), PIN_VK_INT, "and its key is vk_int");
        t.max_depth = 5;
        check_tree_pins(&ex, &t).expect("a fixed point past the list serves every deeper level");
    }

    /// Crafted roots (`crafted_proof`'s pattern, at level 1's step heights and its program's
    /// degree bits): another tier is refused by the header and builds no key; the digest the
    /// recompute makes under another binding is `TreeRootDigest` and builds no key; the right
    /// digest over an all-zero batch reaches the rVM verify and is refused there.
    #[test]
    fn crafted_tree_roots_are_refused_at_their_step() {
        use p3_field::PrimeField64;
        let ex = AggExecutor::new(FriProfile::Test);
        let t = test_tree_cfg();
        let covered: Vec<CoveredBundle> = (0..2).map(|k| covered(k).1).collect();
        let pvs: Vec<Vec<u64>> = covered.iter().map(|c| c.public_values.to_vec()).collect();
        let inner = AggExecutor::inner_key(&t.shape).unwrap();
        let s = randprotocol_rvm::aggregate::TreeShapes::build(FriProfile::Test, &inner, rvm_heights(t.leaf), &[rvm_heights(TEST_STEP), rvm_heights(TEST_ROOT)]).unwrap();
        let st = t.steps[0].heights;
        let root_for = |binding: &[u32; 8], tier: usize| -> Vec<u8> {
            let d = randprotocol_rvm::aggregate::tree_root_digest(&inner, &pvs, binding, 1, 1, &s.keys()).unwrap();
            let digest: Vec<u64> = d.iter().map(|f| f.as_canonical_u64()).collect();
            let mut bytes = postcard::to_allocvec(&(tier, st.reg_log_height, st.ram_log_height, st.poseidon2_log_height, st.reduce_log_height, digest)).unwrap();
            bytes.extend_from_slice(&[0u8; 4096]);
            let mut p: randprotocol_rvm::machine::Proof = postcard::from_bytes(&bytes).unwrap();
            p.batch.degree_bits = randprotocol_rvm::machine::log_ext_degrees(
                s.root_program(1).unwrap(),
                randprotocol_rvm::machine::Tier(tier),
                st.reg_log_height,
                st.ram_log_height,
                st.poseidon2_log_height,
                st.reduce_log_height,
            );
            p.to_bytes()
        };
        let b = [3u32; 8];
        let before = ex.rvm.cached_keys();
        assert!(matches!(ex.verify_tree(&t, &covered, &root_for(&b, st.tier as usize + 1), &b, 1), Err(ConfidentialError::InvalidAggregateProof(m)) if m.contains("tier")));
        assert!(matches!(ex.verify_tree(&t, &covered, &root_for(&b, st.tier as usize - 1), &b, 1), Err(ConfidentialError::InvalidAggregateProof(m)) if m.contains("tier")), "the tier is exact, not a floor");
        // The root's other declared heights are the level's pins too: a root at the right tier
        // declaring any other height is refused off its header, before any key work.
        for bump in 0..4 {
            let mut p: randprotocol_rvm::machine::Proof = postcard::from_bytes(&root_for(&b, st.tier as usize)).unwrap();
            match bump {
                0 => p.reg_log_height += 1,
                1 => p.ram_log_height += 1,
                2 => p.poseidon2_log_height += 1,
                _ => p.reduce_log_height += 1,
            }
            assert!(
                matches!(ex.verify_tree(&t, &covered, &p.to_bytes(), &b, 1), Err(ConfidentialError::InvalidAggregateProof(m)) if m.contains("heights")),
                "height {bump} off its pin"
            );
        }
        assert!(matches!(ex.verify_tree(&t, &covered, &root_for(&[4; 8], st.tier as usize), &b, 1), Err(ConfidentialError::TreeRootDigest)));
        assert_eq!(ex.rvm.cached_keys(), before, "neither refusal built a key");
        assert!(matches!(ex.verify_tree(&t, &covered, &root_for(&b, st.tier as usize), &b, 1), Err(ConfidentialError::InvalidAggregateProof(_))));
        // A covered run that is no bundle's (an OUT word past u32) is named before the recompute.
        let mut bad = covered.clone();
        bad[1].public_values[randprotocol_core::types::pv::OUT0] = 1 << 40;
        assert!(matches!(ex.verify_tree(&t, &bad, &root_for(&b, st.tier as usize), &b, 1), Err(ConfidentialError::CoveredPublicValues { index: 1 })));
        // A depth the section's list cannot reach without a fixed point is refused, not verified.
        let eight: Vec<CoveredBundle> = (0..8).map(|k| covered[k % 2].clone()).collect();
        let mut deep: randprotocol_rvm::machine::Proof = postcard::from_bytes(&root_for(&b, TEST_ROOT.tier as usize)).unwrap();
        deep.reduce_log_height = TEST_ROOT.reduce_log_height; // level 3 repeats level 2's pins
        assert!(matches!(ex.verify_tree(&t, &eight, &deep.to_bytes(), &b, 3), Err(ConfidentialError::InvalidAggregateProof(m)) if m.contains("fixed point")));
        assert_eq!(ex.rvm.cached_keys(), before + 1, "only the one honest-digest verify built a key");
    }

    /// Step 7a's header read: the tier off a canonical root, nothing built; junk and a padded
    /// encoding are `MalformedProof`.
    #[test]
    fn the_tree_root_tier_is_read_off_a_canonical_header() {
        let ex = AggExecutor::new(FriProfile::Test);
        let (shape, cov) = covered(0);
        let p = crafted_proof(&shape, &[cov], &[3; 8], 19, 16);
        assert_eq!(ex.aggregate_proof_tier(&p), Ok(19));
        let mut padded = p.clone();
        padded.push(0);
        assert_eq!(ex.aggregate_proof_tier(&padded), Err(ConfidentialError::MalformedProof));
        assert_eq!(ex.aggregate_proof_tier(b"junk"), Err(ConfidentialError::MalformedProof));
        assert_eq!(ex.program_builds() + ex.tree_builds(), 0);
    }

    /// The tree's startup warm: one rVM key per listed level, at the level's pinned tier and its
    /// canonical reduce height at N = 2 — what a root of that depth verifies under.
    #[test]
    fn warm_tree_warms_one_root_key_per_listed_level() {
        let ex = AggExecutor::new(FriProfile::Test);
        let t = test_tree_cfg();
        ex.warm_tree(&t);
        assert_eq!(ex.rvm.cached_keys(), t.steps.len());
        ex.warm_tree(&t);
        assert_eq!(ex.rvm.cached_keys(), t.steps.len(), "a second warm hits the cache");
    }

    /// circuits `tests/common`'s `TEST_BINDING`: the binding the cached test tree was proved under.
    /// On a chain `B` is `aggregate_binding(chain, aggregator, nonce)`, a hash no test key can
    /// steer to these words, so [`AsProvedBinding`] stands in for it on the ledger path.
    const TREE_TEST_BINDING: [u32; 8] =
        [0xA662_0000, 0xA662_0001, 0xA662_0002, 0xA662_0003, 0xA662_0004, 0xA662_0005, 0xA662_0006, 0xA662_0007];

    /// The four covered bundles of the cached test tree: circuits' leaves are `rv32n` over bundle
    /// fixtures 0..3, one each (L = 1, `tests/tree.rs`'s `leaves`), read from the same
    /// `$RECURSION_FIXTURES` as `tree/`.
    fn test_tree_covered() -> Vec<CoveredBundle> {
        (0..4).map(|k| covered(k).1).collect()
    }

    fn outs_of(covered: &[CoveredBundle]) -> Vec<[u32; 8]> {
        covered
            .iter()
            .map(|c| std::array::from_fn(|k| u32::try_from(c.public_values[randprotocol_core::types::pv::OUT0 + k]).unwrap()))
            .collect()
    }

    /// The real executor on the ledger path, with one substitution: `verify_tree` receives the
    /// ledger's binding, checks it is the transaction's own (`expect`), and verifies under the
    /// binding the cached root was proved under. Everything else is `AggExecutor`'s — the header
    /// read, the 7b rebuild, the payout note, the recompute and the rVM verify.
    struct AsProvedBinding<'a> {
        ex: &'a AggExecutor,
        expect: [u32; 8],
    }

    impl ConfidentialExecutor for AsProvedBinding<'_> {
        fn auth_header(&self, proof: &[u8]) -> Result<(randprotocol_core::confidential::AuthShape, randprotocol_core::notes::Word8, Option<u64>), randprotocol_core::confidential::ConfidentialError> {
            self.ex.auth_header(proof)
        }
        fn warm_auth_multisig(&self) {
            self.ex.warm_auth_multisig()
        }
        fn auth_multisig_key_ready(&self) -> bool {
            self.ex.auth_multisig_key_ready()
        }
        fn install_msauth_vk(&self, blob: &[u8]) -> Result<(), String> {
            self.ex.install_msauth_vk(blob)
        }
        fn enable_auth_multisig(&self) {
            self.ex.enable_auth_multisig()
        }
        fn build_msauth_key(&self) -> Result<(), String> {
            self.ex.build_msauth_key()
        }
        fn check_program(&self, base_pc: u32, words: &[u32]) -> Result<Vec<u8>, ConfidentialError> {
            self.ex.check_program(base_pc, words)
        }
        fn verify_call(&self, program: &ProgramRecord, proof: &[u8]) -> Result<CallOutcome, ConfidentialError> {
            self.ex.verify_call(program, proof)
        }
        fn public_digest(&self, words: &[u32]) -> Word8 {
            self.ex.public_digest(words)
        }
        fn node_hash(&self, left: &Word8, right: &Word8) -> Word8 {
            self.ex.node_hash(left, right)
        }
        fn hash_domain(&self, domain: u32, msg: &[u32]) -> Word8 {
            self.ex.hash_domain(domain, msg)
        }
        fn note_commitment(&self, pk: &Word8, from: &Word8, amount: u64, asset: u32, time: u32, r: &Word8) -> Word8 {
            self.ex.note_commitment(pk, from, amount, asset, time, r)
        }
        fn bundle_digest(&self, input: &BundleDigestInput) -> Word8 {
            self.ex.bundle_digest(input)
        }
        fn bundle_digest_v3(&self, input: &BundleDigestInput) -> Word8 {
            self.ex.bundle_digest_v3(input)
        }
        fn bundle_proof_digest(&self, hc_bundle: &Word8, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            self.ex.bundle_proof_digest(hc_bundle, proof)
        }
        fn auth_proof_digest(&self, proof: &[u8]) -> Result<Word8, ConfidentialError> {
            self.ex.auth_proof_digest(proof)
        }
        fn verify_auth(&self, hc_auth: &Word8, proof: &[u8], binding: &[u32; 8]) -> Result<Word8, ConfidentialError> {
            self.ex.verify_auth(hc_auth, proof, binding)
        }
        fn verify_bundle(&self, hc: &Word8, proof: &[u8], binding: &[u32; randprotocol_core::types::TX_BINDING_WORDS]) -> Result<(), ConfidentialError> {
            self.ex.verify_bundle(hc, proof, binding)
        }
        fn aggregate_program_digest(&self, shape: &DeclaredShape) -> Result<[u64; 4], ConfidentialError> {
            self.ex.aggregate_program_digest(shape)
        }
        fn verify_aggregate(&self, shape: &DeclaredShape, covered: &[CoveredBundle], proof: &[u8], binding: &[u32; 8]) -> Result<Vec<[u32; 8]>, ConfidentialError> {
            self.ex.verify_aggregate(shape, covered, proof, binding)
        }
        fn aggregate_proof_tier(&self, proof: &[u8]) -> Result<u8, ConfidentialError> {
            self.ex.aggregate_proof_tier(proof)
        }
        fn tree_digests(&self, tree: &TreeConfig) -> Result<TreeDigests, ConfidentialError> {
            self.ex.tree_digests(tree)
        }
        fn verify_tree(&self, tree: &TreeConfig, covered: &[CoveredBundle], proof: &[u8], binding: &[u32; 8], depth: u32) -> Result<Vec<[u32; 8]>, ConfidentialError> {
            assert_eq!(*binding, self.expect, "the ledger hands verify_tree the transaction's own binding");
            self.ex.verify_tree(tree, covered, proof, &TREE_TEST_BINDING, depth)
        }
    }

    /// Final review I1: the cached depth-2 test tree's root (circuits `tests/tree.rs`,
    /// `$RECURSION_FIXTURES/tree/Test-root.rvmproof`) **accepted** through the node — first
    /// `AggExecutor::verify_tree` itself over the four covered bundles at depth 2 (the startup pin
    /// check on the section first), then the ledger's `validate_aggregate` tree path: a genesis
    /// with `aggregation` and an `aggregation_tree` built from the test-profile pins, a registered
    /// aggregator, the four covers coverable, and a `Tree` aggregate signed under the tree domain.
    /// One covered word flipped is refused on both (`TreeRootDigest`), and so is another binding.
    /// Skipped without `RECURSION_FIXTURES` (the in-repo set has no tree/); run it filtered — the
    /// variable suite-wide breaks the pinned-vectors test (AGENTS.md):
    /// `RECURSION_FIXTURES=<circuits>/recursion/target/recursion-fixtures cargo test --release -p randprotocol-node --lib the_cached_test_tree_root_is_admitted`
    #[test]
    fn the_cached_test_tree_root_is_admitted_through_the_executor_and_the_ledger() {
        use randprotocol_core::ledger::aggregation::{AdmittedShape, AggregationConfig};
        use randprotocol_core::types::{Action, AggregateLayout};
        use randprotocol_core::{Hash, Transaction, TxError};
        let Some(dir) = std::env::var_os("RECURSION_FIXTURES").map(std::path::PathBuf::from) else {
            eprintln!("skipped: RECURSION_FIXTURES is not set (the in-repo set has no tree/)");
            return;
        };
        let t = test_tree_cfg();
        let covered = test_tree_covered();
        let root = load_tree(&dir, "Test-root").to_bytes();
        let ex = AggExecutor::new(FriProfile::Test);
        check_tree_pins(&ex, &t).expect("the test section's own pins");

        // 1. The executor: accepted, the four OUT rows in cover order.
        let outs = ex.verify_tree(&t, &covered, &root, &TREE_TEST_BINDING, 2).expect("the cached test tree verifies through AggExecutor");
        assert_eq!(outs, outs_of(&covered), "one OUT row per covered bundle, in cover order");
        let mut tampered = covered.clone();
        tampered[2].public_values[randprotocol_core::types::pv::OUT0] ^= 1;
        assert!(matches!(ex.verify_tree(&t, &tampered, &root, &TREE_TEST_BINDING, 2), Err(ConfidentialError::TreeRootDigest)), "a flipped covered word");
        assert!(matches!(ex.verify_tree(&t, &covered, &root, &[7; 8], 2), Err(ConfidentialError::TreeRootDigest)), "another binding");

        // 2. The ledger: a genesis carrying the section, built as `rand-node genesis` builds one.
        let p0 = fixture_proof(0);
        let hc_words: [u32; 8] = std::array::from_fn(|k| u32::try_from(p0.public_values[randprotocol_core::types::pv::HC0 + k]).unwrap());
        let mut g = crate::storage::fixtures::genesis_file_of(7, &[&crate::storage::fixtures::key(1)], vec![], 2);
        g.aggregation = Some(AggregationConfig {
            bond: 100 * randprotocol_core::UNITS_PER_RAND,
            max_covers: 3,
            subsidy_base: 100 * randprotocol_core::UNITS_PER_RAND,
            halving_blocks: 210_000,
            window: 256,
            admitted_shapes: vec![AdmittedShape {
                shape: t.shape,
                hc: Hash(randprotocol_core::notes::word8_to_bytes(&hc_words)),
                aggregate_program_digest: ex.aggregate_program_digest(&t.shape).unwrap(),
            }],
        });
        g.aggregation_tree = Some(t.clone());
        let gs = g.build(&StubExecutor).expect("a genesis with the test aggregation_tree builds");
        assert_eq!(gs.ledger.aggregation_tree(), Some(&t));
        let mut l = gs.ledger.clone();
        l.set_height(1);
        // The aggregator, registered through the ordinary apply path (a stub-proved bundle burning
        // exactly the bond, as the node's own aggregate tests do).
        let kp = crate::storage::fixtures::key(7);
        let aggregator = kp.public_key().address();
        let payout = randprotocol_core::notes::ShieldedAddress { pk: [7; 8], kem_ek: vec![8; randprotocol_core::notes::KEM_EK_BYTES] };
        let registration = randprotocol_core::types::actions::AggregatorRegistration {
            public_key: kp.public_key().clone(),
            payout: payout.clone(),
            signature: kp.sign(l.binding_domain().aggregator_register_message(7, &aggregator, &payout).as_bytes()),
        };
        let mut b = randprotocol_core::notes::Bundle {
            anchor: l.root(),
            nullifiers: crate::storage::fixtures::pad4([[1; 8], [2; 8]]),
            commitments: crate::storage::fixtures::pad4([[3; 8], [4; 8]]),
            fee: randprotocol_core::gas::BUNDLE_BASE,
            burn_a: 0,
            burn_r: 100 * randprotocol_core::UNITS_PER_RAND,
            burn_asset: 0,
            time: 1,
            envelopes: std::array::from_fn(|k| crate::storage::fixtures::env(k as u8 + 1)),
            proof: vec![],
            auth_commit: [0; 8],
            auth_proof: Vec::new(),
        };
        let d = StubExecutor.bundle_digest(&b.digest_input());
        b.proof = StubExecutor::make_bundle_proof(&crate::storage::fixtures::HC, &d, &[0; 8]);
        let reg = StubExecutor::bound(Transaction::shielded(7, b, Action::RegisterAggregator { registration }));
        let proposer = *l.validators().keys().next().unwrap();
        l.apply_tx(&reg, &proposer, &StubExecutor).expect("the aggregator registers");
        // The four covers, coverable (the bundles the covered records stand for, bucketed).
        let covers: Vec<Hash> = (0..4u8).map(|k| Hash::digest(&[b'c', k])).collect();
        l.set_unsealed_fees(covers.iter().map(|c| (*c, (1_000, proposer, u64::MAX))).collect());
        // The signed `Tree` aggregate carrying the cached root.
        let (r, env, time) = ([9; 8], crate::storage::fixtures::env(9), l.height() as u32);
        let payout_total = l.payout_total_for(&covers).expect("the covers are coverable");
        let tx = Transaction {
            chain_id: 7,
            bundle: None,
            action: Action::Aggregate {
                covers: covers.clone(),
                signature: kp.sign(
                    l.binding_domain()
                        .aggregate_signing_hash_at(
                            AggregateLayout::Tree,
                            7,
                            0,
                            time,
                            &r,
                            &covers,
                            &Hash::digest(&root),
                            &randprotocol_core::types::actions::envelope_digest(&env),
                            payout_total,
                        )
                        .as_bytes(),
                ),
                proof: root.clone(),
                aggregator,
                nonce: 0,
                time,
                r,
                envelope: env,
                payout_total,
                layout: AggregateLayout::Tree,
            },
        };
        let wrapped = AsProvedBinding { ex: &ex, expect: l.binding_domain().aggregate_binding(7, &aggregator, 0) };
        let v = l.validate_aggregate(&tx, &covered, &wrapped).expect("the ledger admits the cached test tree");
        assert_eq!(v.outs, outs, "the ledger's OUT rows are the executor's");
        assert_eq!(v.covered, covered);
        // The same transaction over a flipped covered word: refused at the recompute.
        let r = l.validate_aggregate(&tx, &tampered, &wrapped);
        assert!(matches!(r, Err(TxError::Aggregation(AggregationError::TreeRootDigest))), "{r:?}");
    }

    /// Final review m2: the section circuits prints for a genesis cut — the test tree's, pinned by
    /// circuits `the_test_tree_genesis_section_prints_as_the_nodes_tree_config` as
    /// `tests/tree-test-genesis.json` and vendored beside the rVM — is a `TreeConfig` as
    /// `rand-node genesis --aggregation-tree` reads it (`serde_json`), and it is exactly the
    /// section this suite rebuilds from the test heights.
    #[test]
    #[ignore = "pending rVM phase 5's test-tree fixture regeneration in circuits (recursion/docs/10 §5): T_INT_TEST, the tree_test vk_leaf / vk_t_leaf / vk_int limbs and tests/tree-test-genesis.json are still the phase-4 record; re-sync them and un-ignore"]
    fn the_printed_tree_section_is_a_tree_config() {
        let printed = include_str!("../../randprotocol-rvm/tests/tree-test-genesis.json");
        let t: TreeConfig = serde_json::from_str(printed).expect("the printed section deserializes as a TreeConfig");
        assert_eq!(t, test_tree_cfg(), "the printed section is the rebuilt one, field for field");
        assert_eq!(t.steps[1].key, PIN_VK_INT);
        let again: TreeConfig = serde_json::from_str(&serde_json::to_string(&t).unwrap()).unwrap();
        assert_eq!(again, t, "and it round-trips");
    }

    /// The production depth-2 tree through the node: its section built from the cached
    /// production leaf, step and root (circuits docs/08 §3–§4, L = 2), the startup pin check, then
    /// `verify_tree` over Production-0..7 (L·2^2 = 8 bundles) under the doc binding. **Pending the droplet**: the
    /// production tree is not proved yet, and its keys are tier-21 builds.
    #[test]
    #[ignore = "tree aggregation: the production depth-2 tree (circuits docs/08 §3) — needs tree/Production-{leaf-0,step-0,root}.rvmproof and Production-0..7.proof in RECURSION_FIXTURES and the 256 GB droplet"]
    fn production_tree() {
        use p3_field::PrimeField64;
        let dir = std::path::PathBuf::from(std::env::var_os("RECURSION_FIXTURES").expect("RECURSION_FIXTURES"));
        let bundle = |k: usize| -> randprotocol_zkvm::machine::Proof {
            let bytes = std::fs::read(dir.join(format!("Production-{k}.proof"))).expect("a production bundle fixture");
            postcard::from_bytes(&bytes[32..]).expect("decodes")
        };
        let p0 = bundle(0);
        let shape = DeclaredShape {
            profile: CoreProfile::Production,
            tier: p0.tier.0 as u8,
            program_log_height: p0.program_log_height,
            input_log_height: p0.input_log_height,
            keccak_log_height: p0.keccak_log_height,
            sha256_log_height: p0.sha256_log_height,
            public_log_height: p0.public_log_height,
            mem_log_height: p0.mem_log_height,
        };
        let (leaf, step, root) = (load_tree(&dir, "Production-leaf-0"), load_tree(&dir, "Production-step-0"), load_tree(&dir, "Production-root"));
        let inner = AggExecutor::inner_key(&shape).unwrap();
        let s = randprotocol_rvm::aggregate::TreeShapes::build(FriProfile::Production, &inner, rvm_heights(heights_of(&leaf)), &[rvm_heights(heights_of(&step)), rvm_heights(heights_of(&root))]).unwrap();
        let u = |d: [randprotocol_rvm::isa::F; 4]| d.map(|f| f.as_canonical_u64());
        let k = s.keys();
        let steps = [heights_of(&step), heights_of(&root)]
            .iter()
            .enumerate()
            .map(|(i, h)| TreeStepPin { heights: *h, program_digest: u(s.steps[i].program.digest()), key: u(k.step_keys[i]) })
            .collect();
        let t = TreeConfig { shape, leaf_size: 2, max_depth: 2, leaf: heights_of(&leaf), vk_leaf: u(k.vk_leaf), steps };
        let ex = AggExecutor::new(FriProfile::Production);
        check_tree_pins(&ex, &t).expect("the production section's own pins");
        // L·2^depth covered bundles: fixtures 0..8 at L = 2, depth 2 (circuits' `bundles(0, 4 * L)`).
        let n = (t.leaf_size as usize) << 2;
        let covered: Vec<CoveredBundle> = (0..n)
            .map(|k| {
                let p = bundle(k);
                CoveredBundle { public_values: p.public_values.clone().try_into().unwrap(), shape }
            })
            .collect();
        let outs = ex.verify_tree(&t, &covered, &root.to_bytes(), &DOC_BINDING, 2).expect("the production tree verifies through the node");
        assert_eq!(outs.len(), 8, "one OUT row per covered bundle");
        eprintln!("PRODUCTION_TREE vk_leaf {:?} steps {:?}", t.vk_leaf, t.steps);
    }
}
