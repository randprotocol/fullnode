//! Every test here builds a wrong witness and checks the verifier rejects it.
//! In debug builds Plonky3 panics inside `prove_batch` on the first violated
//! constraint; in release builds it produces a proof that fails to verify.
//! `rejects` accepts either — and nothing else.
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use shrugg_zkvm::emulator::{execute, SLOT_W};
use shrugg_zkvm::guests;
use shrugg_zkvm::isa::REG_A1;
use shrugg_zkvm::machine::{build_traces, FriProfile, Machine, Tier, Traces};
use shrugg_zkvm::tables::{alu, byte, cpu, memory, program, F};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// The panic `p3-batch-stark`'s debug constraint checker raises when a row violates a
/// constraint. Its full form is
/// `"constraints not satisfied on row {row_index}: failed constraints = {rendered}"` —
/// the `panic!` at the end of the row loop in
/// `~/.cargo/registry/src/index.crates.io-*/p3-batch-stark-0.7.0/src/check_constraints.rs`
/// (line 132 in that release). Matching the fixed prefix is what separates "the constraint
/// system caught this" from any other unwind.
const CONSTRAINT_PANIC: &str = "constraints not satisfied on row";

/// A tamper counts as rejected only if `verify` returned an error, or if the panic came from
/// the constraint checker above. Anything else — a trace-builder `assert!`, an index out of
/// bounds, a `Lookup mismatch` from the bus-balance checker — means the test tripped over
/// something other than the constraint it was written for, so it must fail rather than pass
/// for the wrong reason.
fn rejects(f: impl FnOnce() -> Result<(), shrugg_zkvm::machine::VerifyError>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => false,
        Ok(Err(_)) => true,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            let is_constraint = msg.contains(CONSTRAINT_PANIC);
            if !is_constraint { eprintln!("rejects(): panic was not a constraint failure: {msg}"); }
            is_constraint
        }
    }
}

#[test]
fn rejects_only_counts_a_constraint_failure_or_a_verify_error() {
    assert!(rejects(|| Err(shrugg_zkvm::machine::VerifyError::PublicValues)));
    assert!(rejects(|| panic!("constraints not satisfied on row 7: failed constraints = [#1]")));
    // A trace-builder `assert!` is not the constraint system catching anything.
    assert!(!rejects(|| panic!("alu table needs a padding row: 5 ops, height 4")));
    assert!(!rejects(|| Ok(())));
}

fn setup() -> (Machine, shrugg_zkvm::isa::Program, Traces) {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &e, Tier(10)).unwrap();
    (m, p, t)
}

#[test]
fn honest_traces_pass() {
    let (m, p, t) = setup();
    let proof = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p, &proof).unwrap();
}

#[test]
fn claiming_a_wrong_output_is_rejected() {
    let (m, p, mut t) = setup();
    t.public_values[cpu::pv::OUT0] = F::from_u32(56);   // fib(10) is 55
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn tampering_a_register_value_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    t.cpu.values[3 * w + cpu::col::C] += F::ONE;         // row 3 writes a wrong rd
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn skipping_a_cycle_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    let last = (0..t.cpu.height()).rev().find(|r| t.cpu.values[r * w + cpu::col::IS_REAL] == F::ONE).unwrap();
    // mark the row before HALT as padding: the chain of pcs breaks
    t.cpu.values[(last - 1) * w + cpu::col::IS_REAL] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn proof_for_one_program_does_not_verify_another() {
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&guests::fib(10), &[], None).unwrap();
    assert!(rejects(|| m.verify(&guests::fib(11), &proof)));
}

#[test]
fn wrong_tier_claim_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.tier = Tier(12);
    assert!(rejects(|| m.verify(&p, &proof)));
}

#[test]
fn a_run_that_does_not_fit_the_tier_is_refused() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(300);   // ~1800 cycles > 2^10 - 1
    assert!(matches!(m.prove(&p, &[], Some(Tier(10))), Err(shrugg_zkvm::machine::ProveError::TooManyCycles { .. })));
    let (proof, _) = m.prove(&p, &[], None).unwrap();
    assert_eq!(proof.tier, Tier(12));
}

#[test]
fn out_of_range_tier_is_an_error_not_a_panic() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.tier = Tier(99);
    proof.public_values[cpu::pv::TIER] = 99;
    assert!(matches!(m.verify(&p, &proof), Err(shrugg_zkvm::machine::VerifyError::Tier)));
}

#[test]
fn wrong_entry_point_claim_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.public_values[cpu::pv::PC_ENTRY] = 4;
    assert!(matches!(m.verify(&p, &proof), Err(shrugg_zkvm::machine::VerifyError::PublicValues)));
}

/// Rewrite an honest `fib(10)` witness so that it claims `out0 = forged`, using nothing
/// but a *padding* row of the ALU table as the source of the arithmetic that justifies it.
///
/// The ALU table provides `(op, a, b, c)` on the ALU bus with count `MULT`. On a padding
/// row every op flag is zero — so the provided `op` decodes as `Add` — the limb range
/// checks and every arithmetic constraint are gated on a flag or on `is_real`, and (before
/// the `(1 − is_real)·MULT = 0` constraint) `MULT` itself was unconstrained. A padding row
/// could therefore hand the CPU an arbitrary `Add` tuple with arbitrary multiplicity.
///
/// The rewrite is a closed edit: `mv a1, t0` (the instruction that stages the output word)
/// is made to produce `forged` instead of `fib(10)`; the register file, every later `a1`
/// read, the `WRITE_OUTPUT` row's `mem_val` and the public output word follow; the honest
/// ALU row that provided the real tuple is retired to `MULT = 0` so the bus still balances,
/// and the forged tuple is planted on the last (padding) ALU row. Nothing else moves.
fn forge_fib_output_through_an_alu_padding_row(t: &mut Traces, forged: u32) {
    let (wc, wm, wa) = (cpu::col::WIDTH, memory::col::WIDTH, alu::col::WIDTH);
    let new = F::from_u32(forged);

    // The `WRITE_OUTPUT` ecall, and the `mv a1, t0` immediately before it that stages a1.
    let ecall_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * wc + cpu::col::SYS_WRITE] == F::ONE).expect("fib writes an output");
    let mv_row = ecall_row - 1;
    assert_eq!(t.cpu.values[mv_row * wc + cpu::col::IS_ALU], F::ONE, "row before the ecall is `mv a1, t0`");
    assert_eq!(t.cpu.values[mv_row * wc + cpu::col::RD], F::from_u32(REG_A1));
    let a_in = t.cpu.values[mv_row * wc + cpu::col::A];
    let honest = t.cpu.values[mv_row * wc + cpu::col::C];
    let write_ts = 4 * t.cpu.values[mv_row * wc + cpu::col::CLK].as_canonical_u64() + SLOT_W as u64;

    // cpu: the `mv` now yields `forged`, and every later ecall reads the new a1.
    t.cpu.values[mv_row * wc + cpu::col::ALU_OUT] = new;
    t.cpu.values[mv_row * wc + cpu::col::C] = new;
    for r in mv_row + 1..t.cpu.height() {
        if t.cpu.values[r * wc + cpu::col::IS_ECALL] == F::ONE { t.cpu.values[r * wc + cpu::col::MEM_VAL] = new; }
    }
    t.public_values[cpu::pv::OUT0] = new;

    // memory: a1's write and every read of it afterwards.
    for r in 0..t.memory.height() {
        let row = &mut t.memory.values[r * wm..(r + 1) * wm];
        if row[memory::col::IS_REAL] == F::ONE
            && row[memory::col::SPACE] == F::ZERO
            && row[memory::col::ADDR] == F::from_u32(REG_A1)
            && row[memory::col::TS].as_canonical_u64() >= write_ts
        {
            row[memory::col::VALUE] = new;
        }
    }

    // alu: retire one honest provider of the real tuple, plant the forged one on padding.
    let honest_row = (0..t.alu.height())
        .find(|r| {
            let row = &t.alu.values[r * wa..(r + 1) * wa];
            row[alu::col::FLAG0] == F::ONE && row[alu::col::A] == a_in && row[alu::col::B] == F::ZERO && row[alu::col::C] == honest && row[alu::col::MULT] != F::ZERO
        })
        .expect("the honest (Add, a, 0, c) tuple is provided somewhere");
    t.alu.values[honest_row * wa + alu::col::MULT] = F::ZERO;
    let pad = t.alu.height() - 1;
    assert_eq!(t.alu.values[pad * wa + alu::col::IS_REAL], F::ZERO, "last alu row is padding");
    t.alu.values[pad * wa + alu::col::A] = a_in;
    t.alu.values[pad * wa + alu::col::B] = F::ZERO;
    t.alu.values[pad * wa + alu::col::C] = new;
    // `word(A0) = A` and `word(C0) = C` are the only ungated constraints that touch these
    // columns, and the limbs' `RANGE8` lookups are counted by `is_real` — so parking the
    // whole word in limb 0 satisfies the recomposition with no range check to answer to.
    t.alu.values[pad * wa + alu::col::A0] = a_in;
    t.alu.values[pad * wa + alu::col::C0] = new;
    t.alu.values[pad * wa + alu::col::MULT] = F::ONE;
}

#[test]
fn a_tuple_forged_on_an_alu_padding_row_is_rejected() {
    let (m, p, mut t) = setup();
    forge_fib_output_through_an_alu_padding_row(&mut t, 999); // fib(10) is 55
    assert_eq!(t.public_values[cpu::pv::OUT0], F::from_u32(999));
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}


#[test]
fn claiming_a_word_in_an_unwritten_output_slot_is_rejected() {
    let (m, p, mut t) = setup();
    // `fib` writes slot 0 only; spec §3.4 says every slot no WRITE_OUTPUT selected is zero.
    assert_eq!(t.public_values[cpu::pv::OUT0 + 1], F::ZERO);
    t.public_values[cpu::pv::OUT0 + 1] = F::from_u32(7);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn non_canonical_public_values_are_an_error_not_a_panic() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    m.verify(&p, &proof).unwrap();
    // `Val::from_u64` does not reduce, so `out0 + p` is the same field element and would
    // otherwise verify — with a different `to_bytes()` and a different apparent output.
    proof.public_values[cpu::pv::OUT0] += F::ORDER_U64;
    assert!(matches!(m.verify(&p, &proof), Err(shrugg_zkvm::machine::VerifyError::PublicValues)));
}

#[test]
fn bumping_a_program_multiplicity_on_a_padding_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = program::col::WIDTH;
    let pad = t.program.height() - 1; // the table is padded past the last instruction
    assert!(pad >= p.len(), "last program row is padding");
    t.program.values[pad * w + program::col::MULT] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn swapping_two_adjacent_memory_rows_is_rejected() {
    let (m, p, mut t) = setup();
    let w = memory::col::WIDTH;
    let real = (0..t.memory.height()).filter(|r| t.memory.values[r * w + memory::col::IS_REAL] == F::ONE).count();
    assert!(real > 4, "fib(10) touches memory plenty");
    // Swapping whole rows leaves the MEMORY multiset and the RANGE8 counts untouched, so
    // both buses still balance: the only thing that can catch this is the ordering AIR.
    let r = real / 2;
    for k in 0..w { t.memory.values.swap(r * w + k, (r + 1) * w + k); }
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}

#[test]
fn bumping_a_byte_pow2_multiplicity_on_a_non_pow2_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = byte::col::WIDTH;
    let row = byte::row_of(200, 5); // b != 0 and a >= 32, so is_pow2 is 0 here
    t.byte.values[row * w + byte::col::M_POW2] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p, &pr) }));
}
