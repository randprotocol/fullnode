//! The rate-¼ phase's gate (`docs/07-rvm-rate-quarter.md`, spec §0.1/§4): the rVM's own FRI
//! profile may move only to a regime whose proven security is not below today's, computed two ways
//! over this machine's *real* chip shapes at the production exit:
//!
//! 1. the whitepaper's closed-form unique-decoding bound, `q · log2(2 / (1 + ρ)) + g`
//!    (`randprotocol_implementation.tex`, "FRI soundness as instantiated");
//! 2. `p3-security`'s best proven regime (unique or list decoding, whichever binds higher), with the
//!    AIR, instance, batching and LogUp terms this batch actually has.
//!
//! Today's regime is the inner profile's (rate ⅛, 80 queries, 20 grinding bits); the new one is
//! `RvmFri::of(Production)`. The conjectured (random-words) bound and the legacy ethSTARK bound are
//! asserted too, as floors.
use std::sync::Arc;

use p3_field::Field;
use p3_fri::FriParameters;
use p3_lookup::LogUpGadget;
use p3_security::grinding::GrindingSites;
use p3_security::logup::{self, LogUpAir};
use p3_security::shape::{InstanceShape, StarkAirParams};
use p3_security::stark::{conjectured_security_report, proven_security_report};
use randprotocol_rvm::isa::{Instr, Op, Program, F};
use randprotocol_rvm::machine::{chips, Challenge, FriProfile, Machine, Tier, Val};
use randprotocol_rvm::shape::RvmShape;
use p3_field::PrimeCharacteristicRing;

/// (log_blowup, num_queries, query_pow_bits).
const OLD: (usize, usize, usize) = (3, 80, 20);
fn new_regime() -> (usize, usize, usize) {
    let f = randprotocol_rvm::machine::RvmFri::of(FriProfile::Production);
    (f.log_blowup, f.num_queries, f.query_pow_bits)
}

/// The production exit's declared heights (`docs/06` §3): cpu `2^20`, reg `2^21`, ram `2^21`,
/// poseidon2 `2^16`, reduce `2^18`; the tallest *extended* table is `2^22`. The program table is
/// the toy program's (tiny, not the exit's `2^20`): the bound reads the chips' constraint systems
/// and the tallest height, neither of which depends on the program.
const PRODUCTION: (Tier, u8, u8, u8, u8) = (Tier(20), 21, 21, 16, 18);

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

/// A two-instruction program: the chips' constraint systems do not depend on the program's words,
/// only the preprocessed table's contents do, and the security model reads the former.
fn toy() -> Arc<Program> {
    Arc::new(Program {
        instrs: vec![
            Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(7) },
            Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO },
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    })
}

/// The real shape of this machine's batch at the production exit, as `p3-security` wants it:
/// the AIR parameters over every chip (constraint count summed, degree and combo maxed), the
/// instance shape at the tallest extended height (twice: batching over the committed-matrix count,
/// and over the codeword count FRI actually combines with powers of alpha), and the LogUp bus.
fn real_shape() -> (StarkAirParams, InstanceShape, InstanceShape, LogUpAir) {
    let (tier, reg, ram, pos, red) = PRODUCTION;
    let program = toy();
    let shape = RvmShape::of(FriProfile::Production, &program, tier, reg, ram, pos, red);
    let m = Machine::new(FriProfile::Production);
    let common = m.verifier_key(&program, tier, red);
    let airs = chips(&program, tier, red);
    let gadget = LogUpGadget::new();
    let mut num_constraints = 0usize;
    let mut max_degree = 1usize;
    let mut num_interactions = 0usize;
    let mut max_message_width = 1usize;
    for (i, air) in airs.iter().enumerate() {
        let layout = shape.air_layout(i, air);
        let trace_len = 1usize << (shape.degree_bits[i] - 1); // ext_db − is_zk
        let (base, ext) = p3_batch_stark::symbolic::get_symbolic_constraints::<Val, Challenge, _, _>(
            air, layout, &common.lookups[i], &gadget,
        );
        num_constraints += base.len() + ext.len();
        max_degree = max_degree.max(p3_batch_stark::symbolic::get_max_constraint_degree::<Val, Challenge, _, _>(
            air, shape.air_layout(i, air), trace_len, &common.lookups[i], &gadget,
        ));
        for l in common.lookups[i].iter() {
            num_interactions += l.elements.len();
            max_message_width = max_message_width.max(l.elements.iter().map(|t| t.len()).max().unwrap_or(1));
        }
    }
    let n = airs.len();
    let with_lookups = shape.num_lookups.iter().filter(|&&k| k > 0).count();
    let preprocessed = shape.preprocessed_widths.iter().filter(|&&w| w > 0).count();
    // `max_combo` is the out-of-domain points a column is opened at (zeta, zeta·g), not the degree.
    let air = StarkAirParams { num_constraints, max_constraint_degree: max_degree, max_combo: 2 };
    // random + main + quotient (one per instance since docs/05) + preprocessed + permutation.
    let matrices = n + n + n + preprocessed + with_lookups;
    // The codewords FRI batches: every column of every committed matrix at every opening point.
    const DIMENSION: usize = 2; // Challenge over Val
    const HIDING: usize = 4; // the hiding wrapper's random codewords per committed matrix
    let pts = |next: bool| 1 + next as usize;
    let random = n * DIMENSION;
    let main: usize = (0..n).map(|i| (shape.widths[i] + HIDING) * pts(shape.main_next[i])).sum();
    let quotient: usize = (0..n)
        .map(|i| 2 * ((1usize << shape.log_num_quotient_chunks[i]) << 1) + HIDING)
        .sum();
    let pre: usize = (0..n)
        .filter(|&i| shape.preprocessed_widths[i] > 0)
        .map(|i| shape.preprocessed_widths[i] * pts(shape.pre_next[i]))
        .sum();
    let perm: usize = (0..n)
        .filter(|&i| shape.num_lookups[i] > 0)
        .map(|i| ((shape.num_lookups[i] + 1) * DIMENSION + HIDING) * 2)
        .sum();
    let codewords = random + main + quotient + pre + perm;
    let inst_at = |num_batched_functions| InstanceShape {
        log_trace_length: *shape.degree_bits.iter().max().unwrap(),
        modulus_bits: <Challenge as Field>::bits(),
        collision_resistance: 128,
        num_batched_functions,
    };
    let (by_matrix, by_codeword) = (inst_at(matrices), inst_at(codewords));
    let bus = LogUpAir { num_interactions, max_message_width };
    eprintln!("real shape: {air:?} {by_codeword:?} {bus:?}");
    eprintln!(
        "batched functions: {matrices} matrices; {codewords} codewords \
         (random {random}, main {main}, quotient {quotient}, preprocessed {pre}, permutation {perm})"
    );
    (air, by_matrix, by_codeword, bus)
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
        paper_udr_bits(p), proven.security_bits(), bind.label, proven.udr.security_bits(), conj.security_bits(),
        p.0 * p.1 + p.2
    );
    (paper_udr_bits(p), proven.security_bits(), conj.security_bits(), (p.0 * p.1 + p.2) as f64)
}

#[test]
fn the_new_rvm_profile_is_not_below_todays_proven_floor() {
    let (air, by_matrix, inst, bus) = real_shape();
    // Informational: batching counted per committed matrix (the optimistic count).
    bits("matrices", OLD, &air, &by_matrix, &bus);
    bits("matrices", new_regime(), &air, &by_matrix, &bus);
    // Asserted: batching counted per codeword (the conservative count FRI really combines).
    let (old_paper, old_p3, _, _) = bits("codewords", OLD, &air, &inst, &bus);
    let (new_paper, new_p3, new_conj, new_legacy) = bits("codewords", new_regime(), &air, &inst, &bus);
    // The calibration: today's regime reproduces the paper's ≈ 86 proven bits.
    assert!((old_paper - 86.4).abs() < 0.2, "the paper's own figure for 80/8/20: {old_paper:.2}");
    assert!(old_p3 >= 85.0, "p3-security at today's regime over the real shape: {old_p3:.2}");
    // The rule (spec §0.1): not below today's, both ways.
    assert!(new_paper >= old_paper - 0.5, "paper's unique-decoding bits fell: {new_paper:.2} < {old_paper:.2} − 0.5");
    assert!(new_p3 >= old_p3 - 0.5, "p3-security's proven bits fell: {new_p3:.2} < {old_p3:.2} − 0.5");
    assert!(new_conj >= 95.0, "conjectured (random-words) bits: {new_conj:.2}");
    assert!(new_legacy >= 100.0, "legacy ethSTARK bits: {new_legacy}");
}
