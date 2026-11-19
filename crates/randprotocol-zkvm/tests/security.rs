//! Constraint set 11's FRI profile gate (ZKVM-111 item 2; `docs/05-roadmap.md`): the RV32 machine
//! moved from rate 1/8, 80 queries, 20 grinding bits to rate 1/4, 92 queries, 24 grinding bits —
//! the rVM's own move (`recursion/docs/07-rvm-rate-quarter.md`, `recursion/tests/security.rs`) —
//! and may do so only if the proven security over **this machine's** chip shapes is not below the
//! old profile's. Computed two ways, as the rVM's gate does:
//!
//! 1. the whitepaper's closed-form unique-decoding bound, `q · log2(2 / (1 + ρ)) + g`;
//! 2. `p3-security`'s best proven regime (unique or list decoding, whichever binds higher), with
//!    the AIR, instance, batching and LogUp terms this machine's batch actually has.
//!
//! The shape is the worst case the verifier admits: tier 20 with every optional chip present at
//! its flat maximum height, the memory table at its ceiling and the poseidon2 table at `t + 2` —
//! the most constraints, the most committed columns and the tallest table any proof can have. The
//! conjectured (random-words) bound is asserted not below the old profile's, and the legacy
//! ethSTARK bound as a floor.
use p3_air::BaseAir;
use p3_field::Field;
use p3_fri::FriParameters;
use p3_lookup::LogUpGadget;
use p3_security::grinding::GrindingSites;
use p3_security::logup::{self, LogUpAir};
use p3_security::shape::{InstanceShape, StarkAirParams};
use p3_security::stark::{conjectured_security_report, proven_security_report};
use randprotocol_zkvm::machine::{Challenge, Chip, FriProfile, Machine, Tier, Val, VerifierKeyShape, MAX_MEM_LOG_HEIGHT};

/// (log_blowup, num_queries, query_pow_bits): the profile constraint sets ≤ 10 proved under.
const OLD: (usize, usize, usize) = (3, 80, 20);
fn new_regime() -> (usize, usize, usize) {
    let p = FriProfile::Production;
    (p.log_blowup(), p.num_queries(), p.pow_bits())
}

fn worst_shape() -> VerifierKeyShape {
    let tier = Tier(20);
    VerifierKeyShape {
        tier,
        program_log_height: randprotocol_zkvm::tables::program::MAX_LOG_HEIGHT,
        input_log_height: randprotocol_zkvm::tables::input::MAX_LOG_HEIGHT,
        keccak_log_height: randprotocol_zkvm::tables::keccak::MAX_LOG_HEIGHT,
        sha256_log_height: tier.max_sha256_log_height(),
        modq_log_height: tier.max_modq_log_height(),
        public_log_height: randprotocol_zkvm::tables::public::MAX_LOG_HEIGHT,
        poseidon2_log_height: tier.max_poseidon2_log_height(),
    }
}

fn regime(p: (usize, usize, usize)) -> p3_security::fri::FriRegime {
    let f: FriParameters<()> = FriParameters {
        log_blowup: p.0,
        log_final_poly_len: 0,
        max_log_arity: 3,
        num_queries: p.1,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: p.2,
        mmcs: (),
    };
    f.security_regime()
}

/// The paper's closed-form unique-decoding bound.
fn paper_udr_bits(p: (usize, usize, usize)) -> f64 {
    let rho = 2f64.powi(-(p.0 as i32));
    p.1 as f64 * (2.0 / (1.0 + rho)).log2() + p.2 as f64
}

/// The batch's shape as `p3-security` wants it, from this machine's chips and its verifier key's
/// packed lookups (built at the Test profile: the lookups and the constraint systems do not depend
/// on the FRI profile, only the commitment does). Batching is counted twice: over committed
/// matrices (optimistic) and over the codewords FRI really combines with powers of alpha
/// (conservative). Every column is counted as opened at both `zeta` and `zeta·g` (conservative).
fn real_shape() -> (StarkAirParams, InstanceShape, InstanceShape, LogUpAir) {
    let shape = worst_shape();
    shape.check().expect("the worst shape is one the verifier admits");
    let m = Machine::new(FriProfile::Test);
    // The lookup contexts are a function of the chip set, not of the heights: take them from the
    // same chip set at tier 10 (a key that builds in a second, where tier 20's preprocessed
    // commitment costs minutes and ~15 GB), after checking the two chip sets agree column for
    // column. The degree bits — the only height-dependent input — are tier 20's.
    let small = VerifierKeyShape { tier: Tier(10), program_log_height: 7, input_log_height: 7, keccak_log_height: 7, sha256_log_height: 7, modq_log_height: 10, public_log_height: 7, poseidon2_log_height: 12 };
    small.check().expect("the tier-10 twin is admitted");
    let common = m.verifier_key_for(small);
    let airs: Vec<Chip> = shape.chips();
    let small_airs: Vec<Chip> = small.chips();
    assert_eq!(airs.len(), small_airs.len());
    for (a, b) in airs.iter().zip(small_airs.iter()) {
        assert_eq!((BaseAir::<Val>::width(a), BaseAir::<Val>::preprocessed_width(a)), (BaseAir::<Val>::width(b), BaseAir::<Val>::preprocessed_width(b)));
    }
    let degree_bits = m.log_ext_degrees_for(shape, MAX_MEM_LOG_HEIGHT);
    let gadget = LogUpGadget::new();
    let (mut num_constraints, mut max_degree, mut num_interactions, mut max_message_width) = (0usize, 1usize, 0usize, 1usize);
    let (mut main, mut quotient, mut pre, mut perm, mut with_lookups, mut preprocessed) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    const DIMENSION: usize = 2; // Challenge over Val
    const HIDING: usize = 4; // the hiding wrapper's random codewords per committed matrix
    for (i, air) in airs.iter().enumerate() {
        let layout = || p3_air::symbolic::AirLayout::from_air(air);
        let trace_len = 1usize << (degree_bits[i] - 1); // ext_db − is_zk
        let (base, ext) = p3_batch_stark::symbolic::get_symbolic_constraints::<Val, Challenge, _, _>(air, layout(), &common.lookups[i], &gadget);
        num_constraints += base.len() + ext.len();
        max_degree = max_degree.max(p3_batch_stark::symbolic::get_max_constraint_degree::<Val, Challenge, _, _>(air, layout(), trace_len, &common.lookups[i], &gadget));
        let log_chunks = p3_batch_stark::symbolic::get_log_num_quotient_chunks::<Val, Challenge, _, _>(air, layout(), trace_len, &common.lookups[i], 1, &gadget);
        for l in common.lookups[i].iter() {
            num_interactions += l.elements.len();
            max_message_width = max_message_width.max(l.elements.iter().map(|t| t.len()).max().unwrap_or(1));
        }
        main += (BaseAir::<Val>::width(air) + HIDING) * 2;
        quotient += 2 * ((1usize << log_chunks) << 1) + HIDING;
        let pw = BaseAir::<Val>::preprocessed_width(air);
        if pw > 0 {
            preprocessed += 1;
            pre += pw * 2;
        }
        let k = common.lookups[i].len();
        if k > 0 {
            with_lookups += 1;
            perm += ((k + 1) * DIMENSION + HIDING) * 2;
        }
    }
    let n = airs.len();
    let random = n * DIMENSION;
    let air = StarkAirParams { num_constraints, max_constraint_degree: max_degree, max_combo: 2 };
    // random + main + quotient (one per instance since constraint set 11) + preprocessed + permutation.
    let matrices = n + n + n + preprocessed + with_lookups;
    let codewords = random + main + quotient + pre + perm;
    let inst_at = |num_batched_functions| InstanceShape {
        log_trace_length: *degree_bits.iter().max().unwrap(),
        modulus_bits: <Challenge as Field>::bits(),
        collision_resistance: 128,
        num_batched_functions,
    };
    let bus = LogUpAir { num_interactions, max_message_width };
    eprintln!("worst shape {shape:?}: {air:?} {:?} {bus:?}", inst_at(codewords));
    eprintln!("batched functions: {matrices} matrices; {codewords} codewords (random {random}, main {main}, quotient {quotient}, preprocessed {pre}, permutation {perm})");
    (air, inst_at(matrices), inst_at(codewords), bus)
}

fn bits(tag: &str, p: (usize, usize, usize), air: &StarkAirParams, inst: &InstanceShape, bus: &LogUpAir) -> (f64, f64, f64, f64) {
    let r = regime(p);
    let g = GrindingSites::NONE;
    let term = logup::security_term(bus, inst, &g).expect("the batch has a LogUp bus");
    let proven = proven_security_report(&r, air, inst, &[term.clone()], &g);
    let conj = conjectured_security_report(&r, air, inst, &[term], &g);
    let (reg, bind) = proven.binding();
    eprintln!(
        "[{tag}] regime {p:?}: paper-UDR {:.2}, p3 proven {:.2} (binds {} in {reg:?}; UDR {:.2}), conjectured {:.2}, legacy {}",
        paper_udr_bits(p),
        proven.security_bits(),
        bind.label,
        proven.udr.security_bits(),
        conj.security_bits(),
        p.0 * p.1 + p.2
    );
    (paper_udr_bits(p), proven.security_bits(), conj.security_bits(), (p.0 * p.1 + p.2) as f64)
}

#[test]
fn the_rate_one_quarter_profile_is_not_below_the_old_proven_floor() {
    assert_eq!(new_regime(), (2, 92, 24));
    let (air, by_matrix, inst, bus) = real_shape();
    // Informational: batching counted per committed matrix (the optimistic count).
    bits("matrices", OLD, &air, &by_matrix, &bus);
    bits("matrices", new_regime(), &air, &by_matrix, &bus);
    // Asserted: batching counted per codeword (the conservative count FRI really combines).
    let (old_paper, old_p3, old_conj, _) = bits("codewords", OLD, &air, &inst, &bus);
    let (new_paper, new_p3, new_conj, new_legacy) = bits("codewords", new_regime(), &air, &inst, &bus);
    // The calibration: the old regime reproduces the paper's ≈ 86 proven bits.
    assert!((old_paper - 86.4).abs() < 0.2, "the paper's own figure for 80/8/20: {old_paper:.2}");
    // The rule: not below the old profile's, both ways (the rVM's gate, `recursion/tests/security.rs`).
    assert!(new_paper >= old_paper - 0.5, "paper's unique-decoding bits fell: {new_paper:.2} < {old_paper:.2} − 0.5");
    assert!(new_p3 >= old_p3 - 0.5, "p3-security's proven bits fell: {new_p3:.2} < {old_p3:.2} − 0.5");
    // Conjectured (random-words): not below the old profile's either. On this machine's worst
    // shape both regimes sit at the same figure (89.80 on 2026-11-19), bound by a term FRI's
    // parameters do not reach (the shape's degree-8 constraints over a 2^25 trace, not the
    // query phase), so the rVM's absolute 95-bit floor is not this machine's — measured, not
    // assumed: the old profile is the reference.
    assert!(new_conj >= old_conj - 0.5, "conjectured bits fell: {new_conj:.2} < {old_conj:.2} − 0.5");
    assert!(new_legacy >= 100.0, "legacy ethSTARK bits: {new_legacy}");
}
