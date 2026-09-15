//! The generated constraint evaluation at `zeta` (spec §4.3): every RV32 chip's constraint DAG,
//! walked once at build time with Plonky3's own symbolic builder and emitted into the DSL as the
//! `alpha`-folded accumulator, plus the recomposed quotient and the Lagrange selectors the identity
//! needs.
//!
//! **Nothing here restates a constraint.** The expressions come from
//! `p3_batch_stark::symbolic::get_symbolic_constraints` against `research`'s own `Chip` AIRs, in the
//! two vectors it returns — base first, then extension, which is the order
//! `LogUpGadget::eval_air_and_lookups` produces them in (`air.eval` emits only base constraints for
//! every chip in this machine, the gadget only extension ones) and therefore the order the native
//! `VerifierConstraintFolder`'s `assert_zero`/`assert_zero_ext` calls happen in. The folder's rule is
//! `accumulator = accumulator·alpha + constraint` per call
//! (`p3-uni-stark-0.7.0/src/folder.rs:374-400`), which is what [`emit_accumulator`] emits.
//!
//! **Sharing.** The symbolic expression is a DAG, not a tree: arithmetic nodes hold their children in
//! `Arc`s and the builder shares them, so a naive recursion would emit an exponential blow-up of the
//! same sub-expressions. Every interior node is therefore emitted once, keyed by the address of its
//! `Arc`'s referent — the same unit `SymbolicExpr::poly_degree` memoises on
//! (`p3-air-0.7.0/src/symbolic/mod.rs:150-163`) and the unit the spike's node count was measured in.
//! *Leaves* are shared too, keyed by what they denote rather than by address, because the builder
//! allocates a fresh `Leaf` node per occurrence of a column: without that, a chip that reads one
//! column in forty constraints would emit forty `LOADE`s of the same cell. Both counts are reported
//! in [`Phase5Cost`].
//!
//! The result is exact, not approximate: every route below is an algebraic identity over the same
//! field elements the native verifier multiplies, so the accumulator the program computes is the
//! *same element* — which is what `tests/verifier.rs` asserts, rather than asserting that the
//! identity happens to hold.

use std::collections::HashMap;

use p3_air::symbolic::{
    AirLayout, BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpr, SymbolicExpression,
    SymbolicExpressionExt,
};
use p3_air::{Air, BaseAir};
use p3_batch_stark::symbolic::get_symbolic_constraints;
use p3_commit::PolynomialSpace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{assert_uniform_tuple_width, InteractionSymbolicBuilder, Kind, LogUpGadget, Lookup};
use shrugg_zkvm::machine::{chips, Chip, Tier, Val};

use crate::dsl::{Array, Builder, Ext, Felt, Ptr};
use crate::isa::{EF, F};
use crate::shape::{natural_domain, InnerShape, VerifierShape};

/// `<EF as BasedVectorSpace<F>>::DIMENSION`, the width of one base-flattened extension value.
const DIMENSION: usize = 2;
const _: () = assert!(DIMENSION == <EF as BasedVectorSpace<F>>::DIMENSION);

/// The four Lagrange selectors of an instance's trace domain at `zeta`
/// (`p3-commit-0.7.0/src/domain.rs:306-315`).
#[derive(Clone, Copy, Debug)]
pub struct Selectors {
    pub is_first_row: Ext,
    pub is_last_row: Ext,
    pub is_transition: Ext,
    pub inv_vanishing: Ext,
}

/// One instance's opened values, already in the DSL, in the form the constraint DAG's leaves name
/// them.
///
/// `trace_next` and `pre_next` are **zero-length when the round opens only one point**, which is what
/// `commitments_with_opening_points` decides from `BaseAir::main_next_row_columns`
/// (`p3-batch-stark-0.7.0/src/verifier/mod.rs:158-170`); a next-row leaf then resolves to zero,
/// exactly as the native folder's zero-padded row does. `perm_local`/`perm_next` are the
/// **recomposed** `aux_width` extension columns, not the `aux_width · DIMENSION` base-flattened
/// values the tape carries.
#[derive(Clone, Copy, Debug)]
pub struct InstanceOpenings {
    pub trace_local: Array<Ext>,
    pub trace_next: Array<Ext>,
    pub pre_local: Array<Ext>,
    pub pre_next: Array<Ext>,
    pub perm_local: Array<Ext>,
    pub perm_next: Array<Ext>,
    pub public_values: Array<Felt>,
    /// The per-lookup `(bus_prefix, beta)` pairs, flattened — `ExtEntry::Challenge`'s index space.
    pub challenges: Array<Ext>,
    /// The instance's committed lookup terminal, `None` when it declares no lookups.
    pub terminal: Option<Ext>,
    pub selectors: Selectors,
}

/// One instance's `Segment::OpenedValues` run, exactly as the tape carries it.
///
/// The query phase re-observes every one of these as a claimed evaluation
/// (`two_adic_pcs.rs:684-703`), in this field order, so they are kept alongside the recomposed form
/// the constraints use rather than being consumed in place.
#[derive(Clone, Debug)]
pub struct RawInstance {
    pub trace_local: Array<Ext>,
    pub trace_next: Array<Ext>,
    pub pre_local: Array<Ext>,
    pub pre_next: Array<Ext>,
    /// One entry per *committed* chunk (`(1 << log_num_quotient_chunks) << is_zk`), each `DIMENSION`
    /// extension values wide.
    pub quotient_chunks: Vec<Array<Ext>>,
    /// The ZK `random` round's `DIMENSION` opened values.
    pub random: Array<Ext>,
    /// `aux_width · DIMENSION` base-flattened permutation values, at `zeta` and at `zeta·g`.
    pub perm_local: Array<Ext>,
    pub perm_next: Array<Ext>,
}

/// Everything `Segment::OpenedValues` yields: the raw runs and the per-instance view the constraint
/// evaluation is written against.
#[derive(Clone, Debug)]
pub struct Openings {
    pub raw: Vec<RawInstance>,
    pub instances: Vec<InstanceOpenings>,
}

/// What one instance's phase-5 block cost. The milestone's exit is a measured number, so the numbers
/// are a byproduct of building the program rather than an estimate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Phase5Cost {
    /// Base and extension constraints folded, i.e. `assert_zero`/`assert_zero_ext` calls.
    pub base_constraints: usize,
    pub ext_constraints: usize,
    /// Distinct interior DAG nodes emitted, and references that hit one already emitted.
    pub nodes: usize,
    pub node_hits: usize,
    /// Distinct leaves emitted, and occurrences that hit one already emitted.
    pub leaves: usize,
    pub leaf_hits: usize,
    /// Instructions the whole block emitted — the selectors, the accumulator, the quotient and the
    /// identity. Phase 5 is fully unrolled, so this is also its cpu rows. (Pre-Task-7 this block
    /// also reported allocator spills/reloads; with the two-pass allocator those exist only at
    /// the replay, where they belong to the program's liveness profile as a whole, not to one
    /// instance — the whole-program numbers live in `dsl::Stats`.)
    pub instrs: usize,
}

// ───────────────────────────────────────────────────────────── reading the tape

/// `Segment::OpenedValues`, read once in its pinned order: per instance `trace_local`, `trace_next`,
/// `preprocessed_local`, `preprocessed_next`, the quotient chunks, `random`, `permutation_local`,
/// `permutation_next` — `OpenedValuesWithLookups`' own field order with `base_opened_values`
/// expanded in place (`crate::witness::Segment::OpenedValues`).
///
/// Every length comes from the [`InnerShape`] and nothing from the proof, which is what
/// `tests/verifier.rs::the_opened_value_segments_are_sized_by_the_shape_alone` pins.
pub fn read_openings<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    pvs: Array<Felt>,
    terminals: &[Ext],
    challenges: &[Array<Ext>],
    zeta: Ext,
) -> Openings {
    assert_eq!(challenges.len(), shape.instances(), "one challenge array per instance");
    // Only one instance declares public values, so the `pvs` array is sliced to its full length
    // for that instance and to nothing for every other. A chip that grew its own would otherwise
    // read the owner's, silently.
    for i in 0..shape.instances() {
        assert!(
            i == shape.pv_instance() || shape.num_public_values()[i] == 0,
            "instance {i} declares {} public values; only instance {} may, because the tape \
             carries exactly one instance's",
            shape.num_public_values()[i],
            shape.pv_instance()
        );
    }
    // One empty allocation the zero-length arrays point at: `hint_ext_array(0)` would still cost an
    // `alloc` — a handle and an `FADDI` — per absent round, for an array nothing ever indexes.
    let nil = b.alloc(0);
    let mut raw = Vec::with_capacity(shape.instances());
    let mut next_terminal = 0usize;
    let mut instances = Vec::with_capacity(shape.instances());

    for (i, challenge) in challenges.iter().enumerate() {
        let w = shape.widths()[i];
        let pre = shape.preprocessed_widths()[i];
        let n_chunks = committed_chunks(shape, i);
        let aux = aux_width(shape, i);

        let trace_local = b.hint_ext_array(w);
        let trace_next = hint_exts(b, if shape.main_next()[i] { w } else { 0 }, nil);
        let pre_local = hint_exts(b, pre, nil);
        let pre_next = hint_exts(b, if shape.pre_next()[i] { pre } else { 0 }, nil);
        let chunk_run = b.hint_ext_array(n_chunks * DIMENSION);
        let quotient_chunks: Vec<Array<Ext>> = (0..n_chunks)
            .map(|c| slice_exts(b, chunk_run, c * DIMENSION, DIMENSION))
            .collect();
        let random = b.hint_ext_array(DIMENSION);
        let perm_local = hint_exts(b, aux * DIMENSION, nil);
        let perm_next = hint_exts(b, aux * DIMENSION, nil);

        raw.push(RawInstance {
            trace_local,
            trace_next,
            pre_local,
            pre_next,
            quotient_chunks,
            random,
            perm_local,
            perm_next,
        });

        let terminal = if shape.num_lookups()[i] > 0 {
            let t = terminals[next_terminal];
            next_terminal += 1;
            Some(t)
        } else {
            None
        };
        instances.push(InstanceOpenings {
            trace_local,
            trace_next,
            pre_local,
            pre_next,
            perm_local: recompose(b, perm_local, aux, nil),
            perm_next: recompose(b, perm_next, aux, nil),
            public_values: Array::new(pvs.base, shape.num_public_values()[i], pvs.stride),
            challenges: *challenge,
            terminal,
            selectors: emit_selectors(b, shape, i, zeta),
        });
    }
    assert_eq!(next_terminal, terminals.len(), "one terminal per instance with lookups");
    Openings { raw, instances }
}

/// The committed quotient-chunk count: `(1 << log_num_quotient_chunks) << is_zk`, and `is_zk() == 1`
/// for this machine's config (`p3-batch-stark-0.7.0/src/verifier/mod.rs:404-418`).
pub fn committed_chunks<S: VerifierShape>(shape: &S, i: usize) -> usize {
    (1usize << shape.log_num_quotient_chunks()[i]) << 1
}

/// `aux_width = num_lookups + 1` — the shared accumulator column plus one fraction column per
/// lookup — or zero where the chip declares none (`p3-lookup-0.7.0/src/symbolic.rs`).
pub fn aux_width<S: VerifierShape>(shape: &S, i: usize) -> usize {
    if shape.num_lookups()[i] > 0 {
        shape.num_lookups()[i] + 1
    } else {
        0
    }
}

/// `n` extension elements off the tape, or an empty array anchored at `nil` when `n == 0`.
fn hint_exts(b: &mut Builder, n: usize, nil: Ptr) -> Array<Ext> {
    if n == 0 {
        Array::new(nil, 0, DIMENSION)
    } else {
        b.hint_ext_array(n)
    }
}

/// `a[at..at + len]`, as its own array. Free: an offset folds into the immediate of every access.
fn slice_exts(b: &mut Builder, a: Array<Ext>, at: usize, len: usize) -> Array<Ext> {
    assert!(at + len <= a.len);
    Array::new(b.offset(a.base, (at * a.stride) as i64), len, a.stride)
}

/// `verify_batch`'s own recompose: `aux · DIMENSION` base-flattened openings back into `aux`
/// extension columns, each `Σ_j ith_basis_element(j) · c[j]`
/// (`p3-field-0.7.0/src/field.rs:1265-1271`).
///
/// `ith_basis_element(0)` is `ONE`, so that term is emitted as the coefficient itself rather than as
/// a multiplication by one — the same element, one row cheaper.
fn recompose(b: &mut Builder, flat: Array<Ext>, aux: usize, nil: Ptr) -> Array<Ext> {
    if aux == 0 {
        return Array::new(nil, 0, DIMENSION);
    }
    assert_eq!(flat.len, aux * DIMENSION);
    let basis: Vec<EF> = (0..DIMENSION)
        .map(|j| {
            <EF as BasedVectorSpace<F>>::ith_basis_element(j).expect("j < DIMENSION")
        })
        .collect();
    let out = b.alloc((aux * DIMENSION) as u64);
    for k in 0..aux {
        let mut acc: Option<Ext> = None;
        for (j, basis_j) in basis.iter().enumerate() {
            let c = b.get_ext(flat, k * DIMENSION + j);
            let term = if basis_j.is_one() {
                c
            } else {
                let w = b.ext_constant(*basis_j);
                b.ext_mul(w, c)
            };
            acc = Some(match acc {
                None => term,
                Some(a) => b.ext_add(a, term),
            });
        }
        b.store_ext(out, (k * DIMENSION) as i64, acc.expect("DIMENSION >= 1"));
    }
    Array::new(out, aux, DIMENSION)
}

// ─────────────────────────────────────────────────────────────────── selectors

/// `trace_domain.selectors_at_point(zeta)` for instance `i`, plus the `OodPointInDomain` check.
///
/// `p3-commit-0.7.0/src/domain.rs:306-315`, term for term: `u = zeta·shift⁻¹`,
/// `z_h = u^(2^log_size) − 1`, `is_first_row = z_h/(u − 1)`, `is_last_row = z_h/(u − g⁻¹)`,
/// `is_transition = u − g⁻¹`, `inv_vanishing = z_h⁻¹`. The shift, the generator's inverse and the
/// domain's log-size are compile-time constants of the shape.
///
/// `z_h⁻¹` is emitted **first**, because it is also the assertion: `Z_H(zeta) != 0` is exactly the
/// `OodPointInDomain` error the native verifier returns, and it is what makes the other two
/// divisions safe — `z_h != 0` means `u^n != 1`, hence `u != 1` and `u != g⁻¹`. An in-domain `zeta`
/// therefore traps at the named checkpoint rather than at an anonymous `EINV` two rows later.
pub fn emit_selectors<S: VerifierShape>(b: &mut Builder, shape: &S, i: usize, zeta: Ext) -> Selectors {
    let cfg = &crate::shape::machine(shape.profile()).config;
    // `base_degree_bits = degree_bits[i] - is_zk`; the selectors are the *trace* domain's.
    let dom = natural_domain(cfg, 1usize << (shape.degree_bits()[i] - 1));
    let shift_inv = dom.shift_inverse();
    let g_inv = dom.subgroup_generator().inverse();

    // The shift is `ONE` for this PCS's natural domains, but the program does not assume it: one
    // `EMULF` per instance against a wrong constant would be a silent divergence.
    let s = b.constant(shift_inv);
    let u = b.ext_mul_base(zeta, s);
    let mut z = u;
    for _ in 0..dom.log_size() {
        z = b.ext_mul(z, z);
    }
    let one = b.ext_constant(EF::ONE);
    let z_h = b.ext_sub(z, one);
    let inv_vanishing =
        b.ext_inv_checked(z_h, &format!("zeta is inside instance {i}'s trace domain"));

    let gi = b.ext_constant(EF::from(g_inv));
    let is_transition = b.ext_sub(u, gi);
    let first_denom = b.ext_sub(u, one);
    let inv_first = b.ext_inv(first_denom);
    let is_first_row = b.ext_mul(z_h, inv_first);
    let inv_last = b.ext_inv(is_transition);
    let is_last_row = b.ext_mul(z_h, inv_last);

    Selectors { is_first_row, is_last_row, is_transition, inv_vanishing }
}

// ──────────────────────────────────────────────────────────────────── quotient

/// `recompose_quotient_from_chunks` for instance `i` (`p3-uni-stark-0.7.0/src/verifier.rs:98-135`),
/// as a DSL sequence.
///
/// `quotient = Σ_i zp_i · chunk_i` with
/// `zp_i = Π_{j≠i} Z_{D_j}(zeta) · Z_{D_j}(first_point(D_i))⁻¹`. The second factor of every term is a
/// compile-time field element — `Z` evaluated at a point of the base field — so the whole product
/// `Π_{j≠i} Z_{D_j}(first_point(D_i))⁻¹` is folded into one constant per chunk here and only the
/// `Z_{D_j}(zeta)` factors are evaluated in the program. The chunk domains themselves come from the
/// shape: `ext_domain.create_disjoint_domain(2^(ext_db + log_chunks)).split_domains(n_chunks)`, which
/// is the construction `commitments_with_opening_points` performs
/// (`p3-batch-stark-0.7.0/src/verifier/mod.rs:181-209`).
pub fn emit_quotient<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    i: usize,
    zeta: Ext,
    chunks: &[Array<Ext>],
) -> Ext {
    let cfg = &crate::shape::machine(shape.profile()).config;
    let ext_db = shape.degree_bits()[i];
    let log_chunks = shape.log_num_quotient_chunks()[i];
    let n_chunks = committed_chunks(shape, i);
    assert_eq!(chunks.len(), n_chunks);
    let ext_dom = natural_domain(cfg, 1usize << ext_db);
    let qdom = ext_dom.create_disjoint_domain(1usize << (ext_db + log_chunks));
    let doms = qdom.split_domains(n_chunks);

    // `Z_{D_j}(zeta)` for every chunk domain, in the DSL.
    let one = b.ext_constant(EF::ONE);
    let z_at_zeta: Vec<Ext> = doms
        .iter()
        .map(|d| {
            let s = b.constant(d.shift_inverse());
            let mut x = b.ext_mul_base(zeta, s);
            for _ in 0..d.log_size() {
                x = b.ext_mul(x, x);
            }
            b.ext_sub(x, one)
        })
        .collect();

    let mut quotient: Option<Ext> = None;
    for (j, chunk) in chunks.iter().enumerate() {
        // The compile-time half of `zp_j`.
        let c: EF = doms
            .iter()
            .enumerate()
            .filter(|(k, _)| *k != j)
            .map(|(_, other)| {
                other
                    .vanishing_poly_at_point(EF::from(doms[j].first_point()))
                    .inverse()
            })
            .product();
        let mut zp = b.ext_constant(c);
        for (k, z) in z_at_zeta.iter().enumerate() {
            if k != j {
                zp = b.ext_mul(zp, *z);
            }
        }
        // `Challenge::from_ext_basis_coefficients(chunk)`, the same recomposition the permutation
        // openings get.
        let value = recompose_one(b, *chunk);
        let term = b.ext_mul(zp, value);
        quotient = Some(match quotient {
            None => term,
            Some(q) => b.ext_add(q, term),
        });
    }
    quotient.expect("a committed quotient has at least one chunk")
}

/// `Challenge::from_ext_basis_coefficients` of one `DIMENSION`-wide run, in the DSL.
fn recompose_one(b: &mut Builder, run: Array<Ext>) -> Ext {
    assert_eq!(run.len, DIMENSION);
    let mut acc: Option<Ext> = None;
    for j in 0..DIMENSION {
        let basis_j =
            <EF as BasedVectorSpace<F>>::ith_basis_element(j).expect("j < DIMENSION");
        let c = b.get_ext(run, j);
        let term = if basis_j.is_one() {
            c
        } else {
            let w = b.ext_constant(basis_j);
            b.ext_mul(w, c)
        };
        acc = Some(match acc {
            None => term,
            Some(a) => b.ext_add(a, term),
        });
    }
    acc.expect("DIMENSION >= 1")
}

// ───────────────────────────────────────────────────────────── lookup challenges

/// The bus-prefix arithmetic `Challenges::new(alpha, beta, max_message_width, next_bus)` does on the
/// host, emitted into the DSL so the program derives the same per-lookup challenge pairs from the two
/// sampled elements — one `Array<Ext>` per instance, laid out
/// `[prefix[bus_0], beta, prefix[bus_1], beta, …]`, which is `ExtEntry::Challenge`'s index space.
///
/// `prefix[k] = alpha + (k + 1)·gamma` with `gamma = beta^W`
/// (`p3-lookup-0.7.0/src/challenges.rs:58-79`), and the bus ids and `W` come from the batch's lookup
/// contexts exactly as `BatchTranscript::sample_perm_challenges` derives them
/// (`p3-batch-stark-0.7.0/src/transcript.rs:119-188`). That derivation is the one piece of p3 logic
/// this crate has to restate — the function returns the challenge *values*, not the bus map — so it
/// is checked against the real function's output element for element in
/// `tests/verifier.rs::the_emitted_lookup_challenges_are_sample_perm_challenges_own_layout`.
pub fn emit_lookup_challenges<S: VerifierShape>(
    b: &mut Builder,
    shape: &S,
    alpha: Ext,
    beta: Ext,
) -> Vec<Array<Ext>> {
    let common = shape.common_data();
    let all: Vec<&[Lookup<F>]> = common.lookups.iter().map(|l| l.as_ref()).collect();
    // `sample_perm_challenges` squeezes *nothing at all* when no instance declares a lookup, and
    // returns an empty layout; this program samples the pair unconditionally in phase 3, so a shape
    // with no lookups would put it one transcript step out of phase from the native verifier for the
    // whole rest of the proof. Every RV32 batch has lookups, and this is where that is pinned.
    assert!(
        all.iter().any(|c| !c.is_empty()),
        "no instance of this shape declares a lookup, so `sample_perm_challenges` would squeeze \
         nothing and the program's phase-3 draw would desynchronise the transcript"
    );
    let (bus_ids, max_message_width, next_bus) = bus_layout(&all);

    let gamma = ext_pow_const(b, beta, max_message_width);
    let mut prefix = alpha;
    let mut bus_prefix = Vec::with_capacity(next_bus);
    for _ in 0..next_bus {
        prefix = b.ext_add(prefix, gamma);
        bus_prefix.push(prefix);
    }

    let nil = b.alloc(0);
    bus_ids
        .iter()
        .enumerate()
        .map(|(i, buses)| {
            assert_eq!(buses.len(), shape.num_lookups()[i], "instance {i}'s lookup count");
            if buses.is_empty() {
                return Array::new(nil, 0, DIMENSION);
            }
            let out = b.alloc((2 * buses.len() * DIMENSION) as u64);
            for (k, &bus) in buses.iter().enumerate() {
                b.store_ext(out, (2 * k * DIMENSION) as i64, bus_prefix[bus]);
                b.store_ext(out, ((2 * k + 1) * DIMENSION) as i64, beta);
                // Checkpointed pair by pair, because the host-side bus assignment above is the one
                // restatement of p3 logic in this crate and the whole layout — which bus each lookup
                // landed on, and the interleaving with `beta` — is what has to be compared.
                b.checkpoint(&format!("challenges[{i}][{}]", 2 * k), bus_prefix[bus]);
                b.checkpoint(&format!("challenges[{i}][{}]", 2 * k + 1), beta);
            }
            Array::new(out, 2 * buses.len(), DIMENSION)
        })
        .collect()
}

/// `sample_perm_challenges`' bus assignment and payload-width scan: global buses share an id by
/// name, local buses take a fresh one each, and the widest payload fixes the power the bus offset
/// sits on. Returns `(bus id per instance per lookup, max_message_width, bus count)`.
fn bus_layout(all: &[&[Lookup<F>]]) -> (Vec<Vec<usize>>, usize, usize) {
    let mut global_index: HashMap<&str, usize> = HashMap::new();
    let mut global_width: HashMap<&str, usize> = HashMap::new();
    let mut next_bus = 0usize;
    let mut max_message_width = 1usize;
    let bus_ids = all
        .iter()
        .map(|contexts| {
            contexts
                .iter()
                .map(|ctx| {
                    let ctx_width = assert_uniform_tuple_width(&ctx.elements, "lookup");
                    max_message_width = max_message_width.max(ctx_width);
                    match &ctx.kind {
                        Kind::Global(name) => {
                            let id = *global_index.entry(name.as_str()).or_insert_with(|| {
                                let id = next_bus;
                                next_bus += 1;
                                id
                            });
                            let expected =
                                *global_width.entry(name.as_str()).or_insert(ctx_width);
                            assert_eq!(
                                expected, ctx_width,
                                "bus {name:?}: tuple widths {expected} and {ctx_width} differ"
                            );
                            id
                        }
                        Kind::Local => {
                            let id = next_bus;
                            next_bus += 1;
                            id
                        }
                    }
                })
                .collect()
        })
        .collect();
    (bus_ids, max_message_width, next_bus)
}

/// `x^e` for a compile-time `e >= 1`, by square-and-multiply — `ceil(log2 e) + popcount(e) − 1`
/// `EMUL`s rather than `e − 1`.
fn ext_pow_const(b: &mut Builder, x: Ext, e: usize) -> Ext {
    assert!(e >= 1, "the bus offset would land on beta^0 and collide with a payload");
    let mut result: Option<Ext> = None;
    let mut base = x;
    let mut k = e;
    while k > 0 {
        if k & 1 == 1 {
            result = Some(match result {
                None => base,
                Some(r) => b.ext_mul(r, base),
            });
        }
        k >>= 1;
        if k > 0 {
            base = b.ext_mul(base, base);
        }
    }
    result.expect("e >= 1")
}

// ───────────────────────────────────────────────────────────────── accumulator

/// Walks one chip's constraints with Plonky3's symbolic builder and emits the folded accumulator
/// `((0·alpha + c_0)·alpha + c_1)·alpha + …` into the DSL, sharing every repeated sub-expression.
pub fn emit_accumulator<A>(
    b: &mut Builder,
    air: &A,
    layout: AirLayout,
    lookups: &[Lookup<F>],
    o: &InstanceOpenings,
    alpha: Ext,
) -> Ext
where
    A: Air<InteractionSymbolicBuilder<F, EF>>,
{
    let mut cost = Phase5Cost::default();
    emit_accumulator_counted(b, air, layout, lookups, o, alpha, &mut cost)
}

/// [`emit_accumulator`], reporting what the walk cost into `cost` (the DAG-sharing statistics the
/// milestone's row budget is written against).
pub fn emit_accumulator_counted<A>(
    b: &mut Builder,
    air: &A,
    layout: AirLayout,
    lookups: &[Lookup<F>],
    o: &InstanceOpenings,
    alpha: Ext,
    cost: &mut Phase5Cost,
) -> Ext
where
    A: Air<InteractionSymbolicBuilder<F, EF>>,
{
    let (base, ext) =
        get_symbolic_constraints::<F, EF, A, LogUpGadget>(air, layout, lookups, &LogUpGadget::new());
    cost.base_constraints += base.len();
    cost.ext_constraints += ext.len();
    let mut cx = Emit::default();
    // `accumulator` starts at zero and every constraint costs one `*= alpha` and one `+=`, the first
    // of which multiplies zero — `VerifierConstraintFolder`'s own shape, kept rather than peeled so
    // the fold is the same sequence of operations and not merely the same result.
    let mut acc = b.ext_constant(EF::ZERO);
    for c in &base {
        let v = cx.base(b, c, o);
        acc = b.ext_mul(acc, alpha);
        acc = b.ext_add(acc, v);
    }
    for c in &ext {
        let v = cx.ext(b, c, o);
        acc = b.ext_mul(acc, alpha);
        acc = b.ext_add(acc, v);
    }
    cost.nodes += cx.nodes;
    cost.node_hits += cx.node_hits;
    cost.leaves += cx.leaves_emitted;
    cost.leaf_hits += cx.leaf_hits;
    acc
}

/// What a leaf denotes. Leaves are shared by *meaning*, not by address: the symbolic builder hands
/// out a fresh `Leaf` node per occurrence of a column, so without this a column read in forty
/// constraints would cost forty `LOADE`s of one cell.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum LeafKey {
    Constant(u64),
    ExtConstant([u64; DIMENSION]),
    Main(usize, usize),
    Preprocessed(usize, usize),
    Public(usize),
    Permutation(usize, usize),
    Challenge(usize),
}

/// The walk's memo tables and counters. One per instance: the pointer keys are only meaningful while
/// the expression vectors this walk borrows are alive.
#[derive(Default)]
#[doc(hidden)]
pub struct Emit {
    /// Interior nodes by the address of their `Arc`'s referent — `Arc` identity, the unit the DAG
    /// shares on. Base and extension nodes are different types, hence different tables.
    base_nodes: HashMap<usize, Ext>,
    ext_nodes: HashMap<usize, Ext>,
    leaves: HashMap<LeafKey, Ext>,
    /// A cached zero, for `Neg`.
    zero: Option<Ext>,
    nodes: usize,
    node_hits: usize,
    leaves_emitted: usize,
    leaf_hits: usize,
}

impl Emit {
    fn zero(&mut self, b: &mut Builder) -> Ext {
        match self.zero {
            Some(z) => z,
            None => {
                let z = b.ext_constant(EF::ZERO);
                self.zero = Some(z);
                z
            }
        }
    }

    #[doc(hidden)]
    pub fn base(&mut self, b: &mut Builder, e: &SymbolicExpression<F>, o: &InstanceOpenings) -> Ext {
        let key = e as *const SymbolicExpression<F> as usize;
        if let Some(v) = self.base_nodes.get(&key) {
            self.node_hits += 1;
            return *v;
        }
        let v = match e {
            SymbolicExpr::Leaf(l) => self.base_leaf(b, l, o),
            SymbolicExpr::Add { x, y, .. } => {
                let (l, r) = (self.base(b, x, o), self.base(b, y, o));
                self.nodes += 1;
                b.ext_add(l, r)
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let (l, r) = (self.base(b, x, o), self.base(b, y, o));
                self.nodes += 1;
                b.ext_sub(l, r)
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.base(b, x, o);
                let z = self.zero(b);
                self.nodes += 1;
                b.ext_sub(z, a)
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let (l, r) = (self.base(b, x, o), self.base(b, y, o));
                self.nodes += 1;
                b.ext_mul(l, r)
            }
        };
        self.base_nodes.insert(key, v);
        v
    }

    fn base_leaf(&mut self, b: &mut Builder, l: &BaseLeaf<F>, o: &InstanceOpenings) -> Ext {
        // The three selectors are already handles: nothing to emit, nothing to share.
        let key = match l {
            BaseLeaf::IsFirstRow => return o.selectors.is_first_row,
            BaseLeaf::IsLastRow => return o.selectors.is_last_row,
            BaseLeaf::IsTransition => return o.selectors.is_transition,
            BaseLeaf::Constant(c) => LeafKey::Constant(c.as_canonical_u64()),
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset } => LeafKey::Main(offset, v.index),
                BaseEntry::Preprocessed { offset } => LeafKey::Preprocessed(offset, v.index),
                BaseEntry::Public => LeafKey::Public(v.index),
                // The spike measured `evaluate_periodic_columns_at` as free because no chip in this
                // machine declares a periodic column. Assert rather than emit wrong code.
                BaseEntry::Periodic => {
                    panic!("periodic columns are not part of this constraint set")
                }
            },
        };
        if let Some(v) = self.leaves.get(&key) {
            self.leaf_hits += 1;
            return *v;
        }
        self.leaves_emitted += 1;
        let v = match key {
            LeafKey::Constant(_) => {
                let BaseLeaf::Constant(c) = l else { unreachable!() };
                b.ext_constant(EF::from(*c))
            }
            LeafKey::Main(offset, index) => window(b, o.trace_local, o.trace_next, offset, index),
            LeafKey::Preprocessed(offset, index) => {
                window(b, o.pre_local, o.pre_next, offset, index)
            }
            LeafKey::Public(index) => {
                let f = b.get(o.public_values, index);
                b.ext_lift(f)
            }
            LeafKey::ExtConstant(_) | LeafKey::Permutation(..) | LeafKey::Challenge(_) => {
                unreachable!("extension leaves do not reach the base emitter")
            }
        };
        self.leaves.insert(key, v);
        v
    }

    #[doc(hidden)]
    pub fn ext(
        &mut self,
        b: &mut Builder,
        e: &SymbolicExpressionExt<F, EF>,
        o: &InstanceOpenings,
    ) -> Ext {
        let key = e as *const SymbolicExpressionExt<F, EF> as usize;
        if let Some(v) = self.ext_nodes.get(&key) {
            self.node_hits += 1;
            return *v;
        }
        let v = match e {
            SymbolicExpr::Leaf(l) => self.ext_leaf(b, l, o),
            SymbolicExpr::Add { x, y, .. } => {
                let (l, r) = (self.ext(b, x, o), self.ext(b, y, o));
                self.nodes += 1;
                b.ext_add(l, r)
            }
            SymbolicExpr::Sub { x, y, .. } => {
                let (l, r) = (self.ext(b, x, o), self.ext(b, y, o));
                self.nodes += 1;
                b.ext_sub(l, r)
            }
            SymbolicExpr::Neg { x, .. } => {
                let a = self.ext(b, x, o);
                let z = self.zero(b);
                self.nodes += 1;
                b.ext_sub(z, a)
            }
            SymbolicExpr::Mul { x, y, .. } => {
                let (l, r) = (self.ext(b, x, o), self.ext(b, y, o));
                self.nodes += 1;
                b.ext_mul(l, r)
            }
        };
        self.ext_nodes.insert(key, v);
        v
    }

    fn ext_leaf(&mut self, b: &mut Builder, l: &ExtLeaf<F, EF>, o: &InstanceOpenings) -> Ext {
        let key = match l {
            // A lifted base sub-tree: the whole tree is preserved inside the leaf, so it is walked
            // by the base emitter and shares through *its* tables.
            ExtLeaf::Base(e) => return self.base(b, e, o),
            ExtLeaf::ExtConstant(c) => {
                let cs: &[F] = c.as_basis_coefficients_slice();
                LeafKey::ExtConstant(std::array::from_fn(|j| cs[j].as_canonical_u64()))
            }
            ExtLeaf::ExtVariable(v) => match v.entry {
                ExtEntry::Permutation { offset } => LeafKey::Permutation(offset, v.index),
                ExtEntry::Challenge => LeafKey::Challenge(v.index),
                // `num_permutation_values == 1` for every instance with lookups, and the value is
                // the committed terminal (`p3-lookup-0.7.0/src/protocol.rs:73`).
                ExtEntry::PermutationValue => {
                    assert_eq!(v.index, 0, "an AIR commits exactly one lookup terminal");
                    return o.terminal.expect("an instance with lookups commits a terminal");
                }
            },
        };
        if let Some(v) = self.leaves.get(&key) {
            self.leaf_hits += 1;
            return *v;
        }
        self.leaves_emitted += 1;
        let v = match key {
            LeafKey::ExtConstant(_) => {
                let ExtLeaf::ExtConstant(c) = l else { unreachable!() };
                b.ext_constant(*c)
            }
            LeafKey::Permutation(offset, index) => {
                window(b, o.perm_local, o.perm_next, offset, index)
            }
            LeafKey::Challenge(index) => b.get_ext(o.challenges, index),
            LeafKey::Constant(_)
            | LeafKey::Main(..)
            | LeafKey::Preprocessed(..)
            | LeafKey::Public(_) => unreachable!("base leaves do not reach the extension emitter"),
        };
        self.leaves.insert(key, v);
        v
    }
}

/// One column of a two-row window. An absent next row resolves to zero, which is what the native
/// folder's zero-padded row gives (`crate::reference::replay`'s `trace_next_zeros`).
fn window(b: &mut Builder, local: Array<Ext>, next: Array<Ext>, offset: usize, index: usize) -> Ext {
    match offset {
        0 => b.get_ext(local, index),
        1 => {
            if next.len == 0 {
                b.ext_constant(EF::ZERO)
            } else {
                b.get_ext(next, index)
            }
        }
        other => panic!("a two-row window has no offset {other}"),
    }
}

// ───────────────────────────────────────────────────────────────── the phase

/// What every instance's constraint block is emitted against: the shape, its chips and their lookup
/// contexts, and the two challenges the fold and the evaluation point come from. Generic over
/// [`VerifierShape`] (M5.4, T5): the RV32 machine's chips and the rVM's own drive the same
/// emitter, since `Emit` walks any AIR's `SymbolicExpression` DAG.
pub struct Batch<'a, S: VerifierShape> {
    pub shape: &'a S,
    /// `chips()` in instance order — [`shape_airs`] for the RV32 machine's shape,
    /// `VerifierShape::constraint_chips` everywhere.
    pub airs: &'a [S::Air],
    /// `CommonData::lookups` in instance order.
    pub lookups: &'a [&'a [Lookup<F>]],
    /// The constraint-folding challenge, drawn in phase 3.
    pub alpha: Ext,
    /// The out-of-domain point, drawn in phase 4.
    pub zeta: Ext,
}

/// Phase 5 for one instance: the accumulator, the quotient, and the identity
/// `accumulator · inv_vanishing == quotient` under the name `"quotient identity[i]"`.
///
/// Both coefficients of the difference are asserted under *one* name rather than through
/// `assert_eq_ext`'s `"… (c0)"`/`"… (c1)"` pair: either failing means the same thing — this
/// instance's constraints do not divide by the vanishing polynomial into the committed quotient — and
/// the tamper tests name the step, not the coefficient.
pub fn emit_instance<S: VerifierShape>(
    b: &mut Builder,
    batch: &Batch<'_, S>,
    o: &Openings,
    i: usize,
    cost: &mut Phase5Cost,
) where
    S::Air: BaseAir<F> + Air<InteractionSymbolicBuilder<F, EF>>,
{
    let (shape, air) = (batch.shape, &batch.airs[i]);
    let inst = &o.instances[i];
    let acc = emit_accumulator_counted(
        b,
        air,
        shape.air_layout(i, air),
        batch.lookups[i],
        inst,
        batch.alpha,
        cost,
    );
    let quotient = emit_quotient(b, shape, i, batch.zeta, &o.raw[i].quotient_chunks);
    b.checkpoint(&format!("accumulator[{i}]"), acc);
    b.checkpoint(&format!("quotient[{i}]"), quotient);
    b.checkpoint(&format!("selectors[{i}].is_first_row"), inst.selectors.is_first_row);
    b.checkpoint(&format!("selectors[{i}].is_last_row"), inst.selectors.is_last_row);
    b.checkpoint(&format!("selectors[{i}].is_transition"), inst.selectors.is_transition);
    b.checkpoint(&format!("selectors[{i}].inv_vanishing"), inst.selectors.inv_vanishing);

    let lhs = b.ext_mul(acc, inst.selectors.inv_vanishing);
    let diff = b.ext_sub(lhs, quotient);
    let (c0, c1) = b.ext_parts(diff);
    let zero = b.zero();
    let name = format!("quotient identity[{i}]");
    b.assert_eq(c0, zero, &name);
    b.assert_eq(c1, zero, &name);
}

/// The chips this shape's instances are, in `chips()`' order — which is instance order.
pub fn shape_airs(shape: &InnerShape) -> Vec<Chip> {
    let airs = chips(Tier(shape.tier), shape.keccak_log_height, shape.sha256_log_height);
    assert_eq!(airs.len(), shape.instances(), "one chip per batch instance");
    for (i, air) in airs.iter().enumerate() {
        assert_eq!(BaseAir::<Val>::width(air), shape.widths()[i], "instance {i}'s trace width");
        assert_eq!(
            BaseAir::<Val>::num_periodic_columns(air),
            0,
            "instance {i} declares periodic columns; the constraint emitter has no leaf for them"
        );
    }
    airs
}
