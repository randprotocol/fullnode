//! The chain-facing aggregate API (spec §6, amended by M5.2's R5/R6 and M5.3's R6): `aggregate`
//! turns N same-shape RV32-machine proofs into one rVM proof whose four batch public values are
//! the interface digest of `[inner_vk_digest ‖ N ‖ B(8) ‖ 35·N]` — B the chain's
//! `H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖ nonce)` (audit v3, AGG-2) — and
//! `verify_aggregate` checks the digest the node recomputes from the covered bundles before the
//! ordinary rVM `Machine::verify` — the cs6 `verify_public` pattern: the §4.4 list travels with
//! the transaction as auxiliary data, the proof carries only its commitment.
//!
//! The registered artifact is [`aggregate_program`]'s digest: one N-generic program per inner
//! shape, built once at startup and pinned (R6).

use crate::isa::{Program, F};
use crate::machine::{Machine, ProveError, Tier, VerifyError};
use crate::programs::{verify_rv32t, TREE_ARITY};
use crate::public_values::{interface_words_bound, public_digest, tree_step_words};
use crate::shape::{inner_vk_digest, InnerKey, InnerShape, RvmHeights, RvmKey, RvmShape, ShapeError, VerifierShape};
use crate::witness::{TapeError, WitnessTape};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_zkvm::tables::cpu::pv;
use std::sync::Arc;

/// The RV32 machine's `Proof` (its 35 public values ride inside it; the empty public segment's
/// `H_PUB` is a prover-computed constant of the shape, as in M5.1's fixtures).
pub type InnerProof = randprotocol_zkvm::machine::Proof;

/// What an aggregate proves under: one inner shape and its preprocessed cap.
#[derive(Clone, Debug)]
pub struct InnerVerifierKey {
    pub shape: InnerShape,
    pub key: InnerKey,
}

/// The registered aggregate program for a key: the N-generic verifier over its shape,
/// checkpoints off — the build the fullnode runs once at startup and pins by digest (R6).
pub fn aggregate_program(vk: &InnerVerifierKey) -> Program {
    crate::programs::verify_rv32n(&vk.shape, &vk.key, crate::dsl::Checkpoints::Off).program
}

/// spec §6's `AggregateProof`, amended: the batch public values of `proof` are the four-element
/// interface digest; `public` is the §4.4 list as auxiliary data (the `verify_public` pattern).
/// (No `Clone`/`Debug` — `machine::Proof`'s `BatchProof` payload has neither; the plan's derive
/// list narrows to what compiles. A second handle is a `to_bytes` round-trip.)
pub struct AggregateProof {
    pub proof: crate::machine::Proof,
    pub public: Vec<F>,
}

/// Why a set of inner proofs could not be aggregated. (`Debug`-only: the `ProveError` payload
/// has no `Clone`/`PartialEq`, so the plan's derive list narrows to what compiles — the tests
/// match on variants.)
#[derive(Debug)]
pub enum AggregateError {
    /// An aggregate of no proofs.
    Empty,
    /// `proofs[index]`'s declared shape is not the key's — checked for the whole set, cheapest
    /// first, before any tape work.
    WrongShape { index: usize },
    /// `n` proofs put the reduce chip past `REDUCE_MAX_LOG_HEIGHT`: the largest aggregate this
    /// program can be verified at is `max` proofs (`machine::max_reduce_n`; production 5 at the
    /// current constant, docs/06 §3). Checked before any tape work — the final fix wave's
    /// prove-side ceiling (`Machine::prove` refuses the same run as `ProveError::ReduceRows`).
    TooManyProofs { n: usize, max: u64 },
    /// The N-proof tape could not be built (a proof the transcript replay refuses).
    Tape(TapeError),
    /// The aggregate program's run or proof failed.
    Prove(ProveError),
    /// The executed program's published digest disagrees with the host-computed one — a
    /// tape/program mismatch caught at prove time (R6).
    DigestMismatch,
    /// A tree covers exactly `leaf_size · 2^d` proofs, `d ≥ 1` (spec §2's layout rule).
    TreeLayout { covers: usize, leaf_size: usize },
    /// Tree level `level` (0 = a leaf) cannot be built on the pinned shapes: a proof produced
    /// there does not declare its pinned shape, or the level lies past a step list whose last
    /// entry is not a fixed point. The next level's program could not verify it, and the chain
    /// would refuse the root.
    TreeShape { level: u32 },
}

/// Why an aggregate proof did not verify.
#[derive(Debug)]
pub enum VerifyAggregateError {
    /// `public`'s eight binding words are not the binding the chain recomputed from the
    /// transaction's own `(chain, aggregator, nonce)` (audit v3, AGG-2): a proof made under
    /// another aggregator's identity, re-signed.
    BindingMismatch,
    /// `public`'s digest does not equal the proof's batch public values — the list the node
    /// recomputed from the covered bundles is not the list the proof binds.
    DigestMismatch,
    /// The rVM's ordinary `Machine::verify` refused the proof.
    Verify(VerifyError),
}

/// spec §6's `aggregate`, amended: shape-checks every inner proof (cheapest first), builds the
/// N-tape with the binding words behind the count, proves, returns the proof and its §4.4 list.
///
/// `binding` is the chain's `H("rand-aggregate-bind-1", chain_id ‖ aggregator ‖ nonce)` (audit
/// v3, AGG-2): the caller passes its own identity — the aggregate daemon's `(chain, aggregator,
/// nonce)` — and the proof then verifies under exactly that triple.
pub fn aggregate(
    m: &Machine,
    vk: &InnerVerifierKey,
    proofs: &[InnerProof],
    binding: &[u32; 8],
    tier: Option<Tier>,
) -> Result<AggregateProof, AggregateError> {
    if proofs.is_empty() {
        return Err(AggregateError::Empty);
    }
    for (index, p) in proofs.iter().enumerate() {
        if !vk.shape.matches(p) {
            return Err(AggregateError::WrongShape { index });
        }
    }
    let program = aggregate_program(vk);
    let max = crate::machine::max_reduce_n(&program);
    if proofs.len() as u64 > max {
        return Err(AggregateError::TooManyProofs { n: proofs.len(), max });
    }
    let tape = WitnessTape::build_n(m.profile, &vk.shape, &vk.key, proofs, binding)
        .map_err(AggregateError::Tape)?;
    let (proof, _exec) = m.prove(&program, &tape.words, tier).map_err(AggregateError::Prove)?;
    // R6: the proof's published digest is the executed program's own output, committed into the
    // batch public values; it must equal the host-computed one, here, at prove time — not at the
    // chain's admission check.
    let pvs: Vec<Vec<u64>> = proofs.iter().map(|p| p.public_values.clone()).collect();
    let public = interface_words_bound(&vk.shape, &vk.key, binding, &pvs);
    let want: Vec<u64> = public_digest(&public).iter().map(|f| f.as_canonical_u64()).collect();
    if proof.public_values != want {
        return Err(AggregateError::DigestMismatch);
    }
    Ok(AggregateProof { proof, public })
}

/// spec §6's `verify_aggregate`, amended: binding check, digest check, then `Machine::verify`,
/// returning each covered bundle's `OUT0..7` as `[u32; 8]`, in proof order.
///
/// `binding` is the chain's own recompute of `H("rand-aggregate-bind-1", chain_id ‖ aggregator
/// ‖ nonce)` from the transaction carrying the proof (audit v3, AGG-2) — never the words the
/// proof's list carries. The proof binds its list's words through the digest; this check binds
/// those words to the transaction, so a copy of the proof re-signed by another aggregator fails.
pub fn verify_aggregate(
    m: &Machine,
    program: &Program,
    a: &AggregateProof,
    binding: &[u32; 8],
) -> Result<Vec<[u32; 8]>, VerifyAggregateError> {
    let carried = a.public.get(5..5 + 8).ok_or(VerifyAggregateError::BindingMismatch)?;
    if !carried.iter().zip(binding).all(|(c, b)| c.as_canonical_u64() == *b as u64) {
        return Err(VerifyAggregateError::BindingMismatch);
    }
    let want: Vec<u64> = public_digest(&a.public).iter().map(|f| f.as_canonical_u64()).collect();
    if a.proof.public_values != want {
        return Err(VerifyAggregateError::DigestMismatch);
    }
    // The list's `N` (bound to the proof by the digest just checked) fixes the one reduce height
    // the proof may declare: `verify_n` refuses any other before building a key (the final fix
    // wave — the node's key-cache DoS guard, `machine`'s module doc).
    let n = a.public[4].as_canonical_u64();
    m.verify_n(program, &a.proof, n).map_err(VerifyAggregateError::Verify)?;
    // The digest committed to the list's length, so a list that passes the check is well-formed:
    // `[vk(4) ‖ N ‖ B(8) ‖ pv::NUM·N]`, and each proof's run is `pv`'s own layout.
    let n = n as usize;
    assert_eq!(
        a.public.len(),
        5 + 8 + pv::NUM * n,
        "a public list whose digest the proof carries is well-formed"
    );
    Ok((0..n)
        .map(|j| {
            let base = 5 + 8 + pv::NUM * j + pv::OUT0;
            std::array::from_fn(|k| {
                u32::try_from(a.public[base + k].as_canonical_u64())
                    .expect("OUT words are u32-range by the inner machine's construction")
            })
        })
        .collect())
}

// ── tree aggregation (spec §2–§4, §4.1 R2–R4 amended) ─────────────────────────────────────────

/// The child key digests a tree's levels publish (spec §4.1 R2, amended by R3): level 1's `vk_c`
/// is `vk_leaf` (its children are `rv32n` leaves); level `j ≥ 2`'s is `step_keys[j − 2]`, the key
/// of level `j − 1`'s step proofs, and the list's **last entry repeats** for every deeper level
/// (the fixed point). The genesis's `vk_leaf` and `step_keys` (spec §4); the test profile's list
/// is `[vk_t_leaf, vk_int, vk_fix]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeKeys {
    pub vk_leaf: [F; 4],
    pub step_keys: Vec<[F; 4]>,
}

impl TreeKeys {
    /// The `vk_c` a level-`level` step publishes (1-based): `vk_leaf` at 1, then
    /// `step_keys[min(level − 2, len − 1)]`. `None` for level 0 and for a level ≥ 2 when no step
    /// key is pinned.
    pub fn at_level(&self, level: u32) -> Option<[F; 4]> {
        match level {
            0 => None,
            1 => Some(self.vk_leaf),
            j => {
                let last = self.step_keys.len().checked_sub(1)?;
                Some(self.step_keys[(j as usize - 2).min(last)])
            }
        }
    }
}

/// A tree's shapes, each carrying its own program: the leaf (`rv32n`'s proofs) and the
/// per-level step list (spec §4.1 R3): `steps[k − 1]` is the declared shape of level `k`'s proofs,
/// carrying level `k`'s program, `rv32t` built over level `k − 1`'s shape (the leaf's for `k = 1`).
/// The last entry repeats for every deeper level, which is sound only when it is a fixed point
/// ([`TreeShapes::fixed_point`]).
#[derive(Clone, Debug)]
pub struct TreeShapes {
    pub leaf: RvmShape,
    pub steps: Vec<RvmShape>,
}

impl TreeShapes {
    /// From the pinned leaf heights and the per-level step heights (R4): build `rv32n` at the
    /// leaf, then each level's `rv32t` over the shape below it, at that level's heights.
    pub fn build(
        profile: crate::machine::FriProfile,
        inner: &InnerVerifierKey,
        leaf: RvmHeights,
        steps: &[RvmHeights],
    ) -> Result<Self, ShapeError> {
        if steps.is_empty() {
            return Err(ShapeError::EmptyTreeSteps);
        }
        let leaf = RvmShape::try_of_heights(profile, &Arc::new(aggregate_program(inner)), leaf)?;
        let mut out: Vec<RvmShape> = Vec::with_capacity(steps.len());
        for h in steps {
            let child = out.last().unwrap_or(&leaf);
            let program = Arc::new(verify_rv32t(child, crate::dsl::Checkpoints::Off).program);
            out.push(RvmShape::try_of_heights(profile, &program, *h)?);
        }
        Ok(TreeShapes { leaf, steps: out })
    }

    /// The key list: `vk_leaf` over the leaf shape, then each level's proofs' key in order.
    pub fn keys(&self) -> TreeKeys {
        let vk = |s: &RvmShape| inner_vk_digest(s, &RvmKey::of(s.profile, s));
        TreeKeys { vk_leaf: vk(&self.leaf), step_keys: self.steps.iter().map(vk).collect() }
    }

    /// The declared shape of level `level`'s proofs (1-based), carrying that level's program;
    /// the last entry repeats. `None` for level 0 and for an empty list (the fields are public,
    /// so a list put together by hand may be empty), as [`TreeKeys::at_level`] answers.
    pub fn step_at(&self, level: u32) -> Option<&RvmShape> {
        let last = self.steps.len().checked_sub(1)?;
        let k = (level as usize).checked_sub(1)?;
        Some(&self.steps[k.min(last)])
    }

    /// The shape of level `level`'s children (1-based): what that level's tape is built against.
    /// The leaf at level 1; `None` for level 0 and where [`TreeShapes::step_at`] has none.
    pub fn child_at(&self, level: u32) -> Option<&RvmShape> {
        match level {
            0 => None,
            1 => Some(&self.leaf),
            j => self.step_at(j - 1),
        }
    }

    /// The root's program at `depth` (level `depth`'s entry, the last repeating): what AGG-6
    /// checks against `step_digests` and `verify_tree` runs.
    pub fn root_program(&self, depth: u32) -> Option<&Program> {
        self.step_at(depth).map(|s| &*s.program)
    }

    /// Whether the last entry is a fixed point (R3): `rv32t` built over its own shape is its own
    /// program, so it verifies its own proofs and may serve every deeper level. `false` for an
    /// empty list.
    pub fn fixed_point(&self) -> bool {
        self.steps
            .last()
            .is_some_and(|last| crate::programs::tree_step_program_digest(last) == last.program.digest())
    }
}

/// Why a tree aggregate did not verify (spec §4's errors that are the verifier's; the chain adds
/// its own around them). Every variant but `Verify` is answered before `verify_n` builds a key.
#[derive(Debug)]
pub enum VerifyTreeError {
    /// `depth` is 0, or too large for a cover count to exist.
    TreeDepth { depth: u32 },
    /// The covered count is not `leaf_size · 2^depth` (or `leaf_size` is 0).
    TreeLayout { covers: usize, leaf_size: usize },
    /// No key, or not the pinned key, for level `level` (spec §4 Errors, amended): here, an empty
    /// step list under a tree of depth ≥ 2; at the chain, also AGG-6's rebuilt-key mismatch.
    TreeKeyPin { level: u32 },
    /// `covered[index]` is not the inner shape's count of canonical field words with `u32` OUT
    /// words: it cannot be a bundle's public values (and a non-canonical word would alias).
    CoveredPublicValues { index: usize },
    /// The bottom-up recompute is not the proof's four public values.
    TreeRootDigest,
    Verify(VerifyError),
}

/// The root digest the chain expects (ZKQ-5's rule, spec §4): leaf `i` is the flat bound list over
/// its `leaf_size` covered public-value runs, and each level `j ≥ 1` is `[keys.at_level(j) ‖ 2 ‖ B
/// ‖ D_a ‖ D_b]` over adjacent pairs, in cover order, under the one `binding`.
pub fn tree_root_digest(
    inner: &InnerVerifierKey,
    covered: &[Vec<u64>],
    binding: &[u32; 8],
    leaf_size: usize,
    depth: u32,
    keys: &TreeKeys,
) -> Result<[F; 4], VerifyTreeError> {
    let leaves = 1usize.checked_shl(depth).filter(|_| depth >= 1).ok_or(VerifyTreeError::TreeDepth { depth })?;
    if leaf_size == 0 || leaf_size.checked_mul(leaves) != Some(covered.len()) {
        return Err(VerifyTreeError::TreeLayout { covers: covered.len(), leaf_size });
    }
    let level_keys: Vec<[F; 4]> = (1..=depth)
        .map(|j| keys.at_level(j).ok_or(VerifyTreeError::TreeKeyPin { level: j }))
        .collect::<Result<_, _>>()?;
    let npv = inner.shape.num_public_values()[inner.shape.pv_instance()];
    for (index, run) in covered.iter().enumerate() {
        let well_formed = run.len() == npv
            && run.iter().all(|x| *x < F::ORDER_U64)
            && run[pv::OUT0..pv::OUT0 + 8].iter().all(|x| *x <= u32::MAX as u64);
        if !well_formed {
            return Err(VerifyTreeError::CoveredPublicValues { index });
        }
    }
    let mut level: Vec<[F; 4]> = covered
        .chunks(leaf_size)
        .map(|leaf| public_digest(&interface_words_bound(&inner.shape, &inner.key, binding, leaf)))
        .collect();
    for vk in level_keys {
        level = level.chunks(2).map(|p| public_digest(&tree_step_words(&vk, binding, &p[0], &p[1]))).collect();
    }
    debug_assert_eq!(level.len(), 1, "L·2^d covers fold to one root");
    Ok(level[0])
}

/// Spec §4's `verify_tree`: the layout, the bottom-up recompute against the proof's public
/// values, then `Machine::verify_n(root_program, proof, 2)`, so the canonical reduce height holds
/// for the step (R1). Cheap before expensive, in `verify_aggregate`'s order. Returns each covered
/// bundle's `OUT0..7`, in cover order. Choosing `root_program` (level `depth`'s entry of the
/// step list, [`TreeShapes::root_program`]) and pinning the keys belong to the caller: in the
/// chain's case, admission's step 7b.
#[allow(clippy::too_many_arguments)]
pub fn verify_tree(
    m: &Machine,
    root_program: &Program,
    proof: &crate::machine::Proof,
    inner: &InnerVerifierKey,
    covered: &[Vec<u64>],
    binding: &[u32; 8],
    leaf_size: usize,
    depth: u32,
    keys: &TreeKeys,
) -> Result<Vec<[u32; 8]>, VerifyTreeError> {
    let root = tree_root_digest(inner, covered, binding, leaf_size, depth, keys)?;
    let want: Vec<u64> = root.iter().map(|f| f.as_canonical_u64()).collect();
    if proof.public_values != want {
        return Err(VerifyTreeError::TreeRootDigest);
    }
    m.verify_n(root_program, proof, TREE_ARITY).map_err(VerifyTreeError::Verify)?;
    Ok(covered
        .iter()
        .map(|run| std::array::from_fn(|k| run[pv::OUT0 + k] as u32))
        .collect())
}

/// One interior step proved over `children` (of shape `child`, in cover order): the tape, the
/// proof, and the host's own `[vk_c ‖ 2 ‖ B ‖ D_a ‖ D_b]` compared with what the proof publishes,
/// at prove time (`aggregate`'s R6 discipline).
pub fn prove_tree_step(
    m: &Machine,
    child: &RvmShape,
    children: [&crate::machine::Proof; 2],
    binding: &[u32; 8],
    tier: Option<Tier>,
) -> Result<crate::machine::Proof, AggregateError> {
    let program = verify_rv32t(child, crate::dsl::Checkpoints::Off).program;
    let tape = WitnessTape::build_tree_step(m.profile, child, children, binding).map_err(AggregateError::Tape)?;
    let (proof, _exec) = m.prove(&program, &tape.words, tier).map_err(AggregateError::Prove)?;
    let vk = inner_vk_digest(child, &RvmKey::of(m.profile, child));
    let d = |p: &crate::machine::Proof| -> [F; 4] { std::array::from_fn(|k| F::from_u64(p.public_values[k])) };
    let want: Vec<u64> = public_digest(&tree_step_words(&vk, binding, &d(children[0]), &d(children[1])))
        .iter()
        .map(|f| f.as_canonical_u64())
        .collect();
    if proof.public_values != want {
        return Err(AggregateError::DigestMismatch);
    }
    Ok(proof)
}

/// A whole tree on one machine (the aggregate daemon's `--layout tree`): `L·2^d` bundle proofs
/// (`d ≥ 1`) → `2^d` leaves → `d` levels of steps, level `j` over `shapes.child_at(j)`. Refused
/// before any proving: a count that is not `L·2^d`, an empty step list, and a depth past a step
/// list whose last entry is not a fixed point. Every produced proof is checked against its pinned shape before the next
/// level is built on it. Returns the root and `d`.
pub fn aggregate_tree(
    m: &Machine,
    inner: &InnerVerifierKey,
    shapes: &TreeShapes,
    proofs: &[InnerProof],
    binding: &[u32; 8],
    leaf_size: usize,
) -> Result<(crate::machine::Proof, u32), AggregateError> {
    let leaves = proofs.len().checked_div(leaf_size).unwrap_or(0);
    if leaf_size == 0 || !proofs.len().is_multiple_of(leaf_size) || leaves < 2 || !leaves.is_power_of_two() {
        return Err(AggregateError::TreeLayout { covers: proofs.len(), leaf_size });
    }
    let depth = leaves.trailing_zeros();
    let listed = shapes.steps.len() as u32;
    if listed == 0 || (depth > listed && !shapes.fixed_point()) {
        return Err(AggregateError::TreeShape { level: listed + 1 });
    }
    let mut level: Vec<crate::machine::Proof> = Vec::with_capacity(leaves);
    for chunk in proofs.chunks(leaf_size) {
        let p = aggregate(m, inner, chunk, binding, None)?.proof;
        if !shapes.leaf.matches(&p) {
            return Err(AggregateError::TreeShape { level: 0 });
        }
        level.push(p);
    }
    for j in 1..=depth {
        let (child, out) = match (shapes.child_at(j), shapes.step_at(j)) {
            (Some(c), Some(o)) => (c, o),
            _ => return Err(AggregateError::TreeShape { level: j }),
        };
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let p = prove_tree_step(m, child, [&pair[0], &pair[1]], binding, None)?;
            if !out.matches(&p) {
                return Err(AggregateError::TreeShape { level: j });
            }
            next.push(p);
        }
        level = next;
    }
    Ok((level.pop().expect("one root"), depth))
}
