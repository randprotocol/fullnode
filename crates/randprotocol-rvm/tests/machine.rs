//! The machine skeleton: the tier ladder, declared heights, the degree-bit vector, and the
//! program-keyed verifier-key cache (plan Task 1).
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_rvm::isa::{Instr, Op, Program, F};
use randprotocol_rvm::machine::{
    check_declared_heights, log_ext_degrees, Machine, Tier, VerifyError, TIERS,
};

fn instr(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}

fn toy_program() -> Program {
    Program {
        instrs: vec![
            instr(Op::Faddi, 1, 0, 7),
            instr(Op::Faddi, 2, 0, 5),
            instr(Op::Fadd, 3, 1, 2),
            instr(Op::Public, 0, 3, 0),
            instr(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
    }
}

#[test]
fn the_tier_ladder_is_increasing_and_has_the_exit_rung_and_the_gpu_rung() {
    for w in TIERS.windows(2) {
        assert!(w[0] < w[1], "TIERS must be strictly increasing: {TIERS:?}");
    }
    assert!(TIERS.contains(&21), "the exit rung (R2)");
    assert!(
        TIERS.contains(&23),
        "23: the production N=3 aggregate rung, added with the CUDA backend (M5.4) — \
         host ≥ 160 GB, device 80 GB class; no CPU-only box in this fleet has it"
    );
}

#[test]
fn for_cycles_fits_the_measured_numbers() {
    // The M5.1 measured pre-cut production count, 2^22.44, fits the new rung exactly.
    assert_eq!(Tier::for_cycles(5_682_847), Some(Tier(23)));
    // The production N=3 aggregate's derived rows (the M5.3 model, 328 + 3·1 968 454 + 4).
    assert_eq!(Tier::for_cycles(5_905_862), Some(Tier(23)));
    // Past the rung the ladder ends.
    assert_eq!(Tier::for_cycles(9_000_000), None);
    // The post-cut exit target lands at 21.
    assert_eq!(Tier::for_cycles(1_950_000), Some(Tier(21)));
    assert_eq!(Tier::for_cycles(1_209_871), Some(Tier(21))); // pre-cut test-profile rehearsal
    assert_eq!(Tier::for_cycles(400_000), Some(Tier(19))); // post-cut test-profile twin
    assert_eq!(Tier::for_cycles(15), Some(Tier(8)));
    assert_eq!(Tier(21).max_cycles(), (1 << 21) - 1);
    assert_eq!(Tier(23).max_cycles(), (1 << 23) - 1);
}

#[test]
fn declared_heights_are_range_checked_without_panicking() {
    // The exit shape (tier 21, the sizing section's expected declared heights).
    check_declared_heights(Tier(21), 23, 22, 16, 18).unwrap();
    // An out-of-TIERS tier is an error, not a shift panic (research's audit-ZH3 mirror).
    assert!(matches!(check_declared_heights(Tier(24), 4, 4, 4, 0), Err(VerifyError::Tier)));
    assert!(matches!(check_declared_heights(Tier(99), 4, 4, 4, 0), Err(VerifyError::Tier)));
    // Each declared height is range-checked, reduce's 0 = "no instance" aside.
    assert!(matches!(check_declared_heights(Tier(8), 3, 4, 4, 0), Err(VerifyError::RegHeight)));
    assert!(matches!(check_declared_heights(Tier(8), 4, 27, 4, 0), Err(VerifyError::RamHeight)));
    assert!(matches!(check_declared_heights(Tier(8), 4, 4, 3, 0), Err(VerifyError::Poseidon2Height)));
    assert!(matches!(check_declared_heights(Tier(8), 4, 4, 21, 0), Err(VerifyError::Poseidon2Height)));
    assert!(matches!(check_declared_heights(Tier(8), 4, 4, 4, 1), Err(VerifyError::ReduceHeight)));
    assert!(matches!(check_declared_heights(Tier(8), 4, 4, 4, 21), Err(VerifyError::ReduceHeight)));
    check_declared_heights(Tier(8), 4, 4, 4, 0).unwrap();
}

#[test]
fn log_ext_degrees_matches_a_hand_computed_vector() {
    let p = toy_program(); // 5 instructions -> program_log_height = log2(pad_height(6, 4)) = 3
    // chips() order: program, cpu, reg_memory, ram_memory, poseidon2, public, range; reduce
    // appended when declared. is_zk doubles every committed matrix (+1 per entry).
    let deg = log_ext_degrees(&p, Tier(8), 4, 5, 6, 0);
    assert_eq!(deg, vec![3 + 1, 8 + 1, 4 + 1, 5 + 1, 6 + 1, 3 + 1, 8 + 1]);
    // With the reduce chip present, one more entry, last.
    let deg = log_ext_degrees(&p, Tier(8), 4, 5, 6, 4);
    assert_eq!(deg, vec![3 + 1, 8 + 1, 4 + 1, 5 + 1, 6 + 1, 3 + 1, 8 + 1, 4 + 1]);
}

#[test]
fn the_verifier_key_is_reproducible_and_cached_per_program_tier_reduce() {
    let m = Machine::new(randprotocol_rvm::machine::FriProfile::Test);
    let a = toy_program();
    let mut b = toy_program();
    b.instrs[2] = instr(Op::Fsub, 3, 1, 2);

    let ka1 = m.verifier_key(&a, Tier(8), false);
    let ka2 = m.verifier_key(&a, Tier(8), false);
    assert!(std::sync::Arc::ptr_eq(&ka1, &ka2), "a cache hit returns the same key");
    assert_eq!(m.cached_keys(), 1);

    let kb = m.verifier_key(&b, Tier(8), false);
    assert_eq!(m.cached_keys(), 2);
    // A different program is a different key (R1/R6: the key binds the program).
    assert!(!std::sync::Arc::ptr_eq(&ka1, &kb));

    let kr = m.verifier_key(&a, Tier(8), true);
    assert_eq!(m.cached_keys(), 3);
    assert!(!std::sync::Arc::ptr_eq(&ka1, &kr));
}

#[test]
fn check_program_rejects_an_illegal_word() {
    let mut p = toy_program();
    Machine::check_program(&p).unwrap();
    p.instrs[0] = instr(Op::Faddi, 40, 0, 1); // rd out of range
    assert!(Machine::check_program(&p).is_err());
    p.instrs[0] = instr(Op::Fadd, 1, 2, 99); // rb out of range on a register op
    assert!(Machine::check_program(&p).is_err());
    p.instrs[0] = instr(Op::Eadd, 31, 0, 2); // an extension pair at r31 is not a pair
    assert!(Machine::check_program(&p).is_err());
}

#[test]
fn rejects_only_counts_a_constraint_failure_or_a_verify_error() {
    assert!(common::rejects(|| Err(VerifyError::PublicValues)));
    assert!(common::rejects(|| panic!("constraints not satisfied on row 7: failed constraints = [#1]")));
    assert!(common::rejects(|| panic!(
        "Lookup mismatch (global lookup 'RANGE8'): tuple [\"9\"] has net multiplicity 1. Locations: []"
    )));
    // A trace-builder assert! is not the constraint system catching anything.
    assert!(!common::rejects(|| panic!("memory table needs a padding row: 5 accesses, height 4")));
    assert!(!common::rejects(|| Ok(())));
}
