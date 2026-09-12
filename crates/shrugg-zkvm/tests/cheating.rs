//! Every test here builds a wrong witness and checks the verifier rejects it.
//! In debug builds Plonky3 panics inside `prove_batch` on the first violated
//! constraint — either one AIR's own row constraint, or (for a violation only
//! visible across AIR instances, like an unpaid extra table multiplicity) the
//! global lookup-balance check; in release builds it produces a proof that
//! fails to verify. `rejects` accepts any of these — and nothing else.
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use shrugg_zkvm::asm::{ops::*, Assembler};
use shrugg_zkvm::emulator::{execute, SLOT_W};
use shrugg_zkvm::guests;
use shrugg_zkvm::isa::{AluOp, Instr, REG_A0, REG_A1};
use shrugg_zkvm::machine::{build_traces_salted, FriProfile, Machine, Tier, Traces};
use shrugg_zkvm::tables::{alu, cpu, limbs, memory, nibble, poseidon2, program, range, F};

/// `rejects()`, and the two constraint-panic prefixes it matches (`CONSTRAINT_PANIC` and
/// `LOOKUP_BALANCE_PANIC`, referred to by name in the comments below), now live in
/// `tests/common/mod.rs` so that `tests/viewing.rs` and `tests/bundle.rs` use this exact
/// definition instead of their own weaker copies. The discipline it encodes is still this
/// file's, and so is the test below that checks the helper itself.
mod common;
use common::rejects;

#[test]
fn rejects_only_counts_a_constraint_failure_or_a_verify_error() {
    assert!(rejects(|| Err(shrugg_zkvm::machine::VerifyError::PublicValues)));
    assert!(rejects(|| panic!("constraints not satisfied on row 7: failed constraints = [#1]")));
    assert!(rejects(|| panic!("Lookup mismatch (global lookup 'AND4'): tuple [\"9\", \"6\", \"0\"] has net multiplicity 1. Locations: []")));
    // A trace-builder `assert!` is not the constraint system catching anything.
    assert!(!rejects(|| panic!("alu table needs a padding row: 5 ops, height 4")));
    assert!(!rejects(|| Ok(())));
}

fn setup() -> (Machine, shrugg_zkvm::isa::Program, Traces) {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    (m, p, t)
}

#[test]
fn honest_traces_pass() {
    let (m, p, t) = setup();
    let proof = m.prove_traces(&p, &t, Tier(10));
    m.verify(&p.digest(), &proof).unwrap();
}

#[test]
fn claiming_a_wrong_output_is_rejected() {
    let (m, p, mut t) = setup();
    t.public_values[cpu::pv::OUT0] = F::from_u32(56);   // fib(10) is 55
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

#[test]
fn tampering_a_register_value_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    t.cpu.values[3 * w + cpu::col::C] += F::ONE;         // row 3 writes a wrong rd
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

#[test]
fn skipping_a_cycle_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    let last = (0..t.cpu.height()).rev().find(|r| t.cpu.values[r * w + cpu::col::IS_REAL] == F::ONE).unwrap();
    // mark the row before HALT as padding: the chain of pcs breaks
    t.cpu.values[(last - 1) * w + cpu::col::IS_REAL] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

#[test]
fn proof_for_one_program_does_not_verify_another() {
    let m = Machine::new(FriProfile::Test);
    let (proof, _) = m.prove(&guests::fib(10), &[], None).unwrap();
    assert!(rejects(|| m.verify(&guests::fib(11).digest(), &proof)));
}

#[test]
fn wrong_tier_claim_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.tier = Tier(12);
    assert!(rejects(|| m.verify(&p.digest(), &proof)));
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
    assert!(matches!(m.verify(&p.digest(), &proof), Err(shrugg_zkvm::machine::VerifyError::Tier)));
}

/// M3.4: `pc_entry` is no longer independently checked against anything the verifier holds
/// (there is no `program.base_pc` on the verifier's side any more) — it is read out of the
/// proof and only bound *in-circuit* to the digest group's own `PC` (`tables::cpu`'s `eval`).
/// So tampering it post-hoc (without re-proving) is still rejected, but now because the
/// tampered public value no longer matches what the committed trace actually proves — a
/// genuine STARK batch-verification failure, not the early `PublicValues` sanity check.
#[test]
fn wrong_entry_point_claim_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    proof.public_values[cpu::pv::PC_ENTRY] = 4;
    assert!(rejects(|| m.verify(&p.digest(), &proof)));
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
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}


#[test]
fn claiming_a_word_in_an_unwritten_output_slot_is_rejected() {
    let (m, p, mut t) = setup();
    // `fib` writes slot 0 only; spec §3.4 says every slot no WRITE_OUTPUT selected is zero.
    assert_eq!(t.public_values[cpu::pv::OUT0 + 1], F::ZERO);
    t.public_values[cpu::pv::OUT0 + 1] = F::from_u32(7);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

#[test]
fn non_canonical_public_values_are_an_error_not_a_panic() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (mut proof, _) = m.prove(&p, &[], None).unwrap();
    m.verify(&p.digest(), &proof).unwrap();
    // `Val::from_u64` does not reduce, so `out0 + p` is the same field element and would
    // otherwise verify — with a different `to_bytes()` and a different apparent output.
    proof.public_values[cpu::pv::OUT0] += F::ORDER_U64;
    assert!(matches!(m.verify(&p.digest(), &proof), Err(shrugg_zkvm::machine::VerifyError::PublicValues)));
}

#[test]
fn bumping_a_program_multiplicity_on_a_padding_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = program::col::WIDTH;
    let pad = t.program.height() - 1; // the table is padded past the last instruction
    assert!(pad >= p.len(), "last program row is padding");
    t.program.values[pad * w + program::col::MULT] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// The `MULT_WORD` (M3.4 digest-row fetch count) sibling of the test above: a padding row
/// (`valid = 0`) must never answer a `PROGRAM_WORD` lookup either — `mult_word = valid` (the
/// fix in `an_undigested_reachable_program_tail_is_rejected`, below) forces `mult_word = 0`
/// there too, same as the weaker constraint it replaced did on this padding-row case.
#[test]
fn a_bumped_program_word_multiplicity_on_a_padding_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = program::col::WIDTH;
    let pad = t.program.height() - 1;
    assert!(pad >= p.len(), "last program row is padding");
    t.program.values[pad * w + program::col::MULT_WORD] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
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
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

#[test]
fn bumping_a_range_pow2_multiplicity_on_a_non_pow2_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = range::col::WIDTH;
    let row = 200usize; // a=200 ≥ 32, so is_pow2 is 0 here
    t.range.values[row * w + range::col::M_POW2] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

#[test]
fn bumping_a_nibble_and_multiplicity_on_a_padding_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = nibble::col::WIDTH;
    let row = nibble::row_of(9, 6); // an arbitrary valid nibble pair the honest trace never counts
    t.nibble.values[row * w + nibble::col::M_AND] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// The memory-path mirror of `forge_fib_output_through_an_alu_padding_row`, ported to
/// M2.5's read-modify-write store: an honest `store 5; load; output` witness is rewritten
/// so the `SW` delivers a value that was never in any register. Before the CPU pinned
/// `MEM_VAL = B` on store rows (`2c8a39d`), nothing tied the value sent on the MEMORY bus
/// to the register the store reads. M2.5 replaced that single pin with the `MERGED0..3`
/// formula (`MERGED_k = W_k + selp(k)*(bp(k) - W_k)`, `bp` built from `RB0..3`, and
/// `is_store*(B - word(RB0))=0` ties `RB0..3` to `B`): on this program's plain `SW`
/// (`off=0`), `selp(k)=1` for every `k`, so the formula forces `MERGED = word(RB0) = B`
/// structurally. This helper forges `MERGED0..3` directly — bypassing `RB0..3`/`B`, which
/// stay untouched and honestly show `5` — so the row constraint above must reject it,
/// exactly as `2c8a39d`'s `MEM_VAL = B` pin did for the old single-column design.
fn forge_a_store(t: &mut Traces, forged: u32) {
    use shrugg_zkvm::tables::limbs;
    let (wc, wm) = (cpu::col::WIDTH, memory::col::WIDTH);
    let new = F::from_u32(forged);
    let nl = limbs(forged);

    // cpu: the store's own MERGED (the value actually written), the load that reads it
    // back (its own, independent MEM_VAL/W0..3 word witness), the `mv a1, t1` staging the
    // output word, and every ecall row (each reads `a1` through the memory slot).
    for r in 0..t.cpu.height() {
        let row = &mut t.cpu.values[r * wc..(r + 1) * wc];
        if row[cpu::col::IS_SW] == F::ONE { for k in 0..4 { row[cpu::col::MERGED0 + k] = nl[k]; } }
        if row[cpu::col::IS_LW] == F::ONE {
            row[cpu::col::MEM_VAL] = new;
            for k in 0..4 { row[cpu::col::W0 + k] = nl[k]; }
            row[cpu::col::C] = new;
        }
        if row[cpu::col::IS_ECALL] == F::ONE { row[cpu::col::MEM_VAL] = new; }
        if row[cpu::col::IS_ALU] == F::ONE && row[cpu::col::RD] == F::from_u32(REG_A1) && row[cpu::col::RS1] == F::from_u32(6) {
            row[cpu::col::A] = new; row[cpu::col::ALU_OUT] = new; row[cpu::col::C] = new;
        }
    }
    // memory: the RAM cell, and registers t1 (the load's write, the mv's read) and a1.
    for r in 0..t.memory.height() {
        let row = &mut t.memory.values[r * wm..(r + 1) * wm];
        if row[memory::col::IS_REAL] != F::ONE { continue; }
        let ram = row[memory::col::SPACE] == F::ONE;
        let addr = row[memory::col::ADDR];
        if ram && addr == F::from_u32(0x400) { row[memory::col::VALUE] = new; }
        if !ram && (addr == F::from_u32(6) || addr == F::from_u32(REG_A1)) { row[memory::col::VALUE] = new; }
    }
    t.public_values[cpu::pv::OUT0] = new;
}

#[test]
fn storing_a_value_that_was_never_in_a_register_is_rejected() {
    // li s0, 0x1000 ; li t0, 5 ; sw t0, 0(s0) ; lw t1, 0(s0) ; write_output(0, t1) ; halt
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 5));
    a.push(sw(8, 5, 0)); a.push(lw(6, 8, 0));
    a.extend(write_output(0, 6)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 5);
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    forge_a_store(&mut t, 0x0500_0000);
    assert_eq!(t.public_values[cpu::pv::OUT0], F::from_u32(0x0500_0000));
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// M2.4 regression: bitwise rows (`and`/`or`/`xor`) no longer RANGE8-check their
/// `A0..3`/`B0..3`/`C0..3` limbs (`g_ab` is 0 there) — those limbs are now bound
/// solely by the nibble lookups. This bumps the RANGE8 table's own multiplicity at
/// a value that appears as this `and` row's `A0` limb (0x12): nothing on the AND
/// row (or, on inspection, anywhere else in this tiny program) asks the RANGE8 bus
/// for one more count of 0x12, so the bus no longer balances and the proof must
/// fail — confirming the dropped gate didn't leave a residual, silent RANGE8 demand
/// for this limb.
#[test]
fn bumping_range8_on_a_bitwise_rows_now_unconstrained_a_limb_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(5, 0x12)); a.extend(li(6, 0x34));
    a.push(and(7, 5, 6)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    t.range.values[0x12 * range::col::WIDTH + range::col::M_RANGE] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// M2.4 regression: `slt`/`sltu`/`eq` rows no longer RANGE8-check their `C0..3`
/// limb (`g_c` is 0 there) — `C` is bound instead by `(cmp+eq)*C*(C-1)=0`. This
/// bumps the RANGE8 table's multiplicity at value 1 (this `slt` row's `C`, and
/// hence `C0`); the RANGE8 bus no longer has a matching demand for that extra
/// count, so the proof must fail.
#[test]
fn bumping_range8_on_an_slt_rows_now_unconstrained_c_limb_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(5, 3)); a.extend(li(6, 9));
    a.push(slt(7, 5, 6)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    t.range.values[range::col::WIDTH + range::col::M_RANGE] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// M2.5: a store's `MERGED0..3` is the read-modify-write result, bound per byte by
/// `MERGED_k = W_k + selp(k)*(bp(k) - W_k)`. Corrupting one limb to disagree with that
/// formula — even while leaving the *aggregate* value looking plausible — must be caught
/// by the row constraint directly, not just by an accidental downstream mismatch.
#[test]
fn a_store_that_replaces_the_wrong_byte_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0x11223344u32 as i32)); a.extend(li(6, 0xff));
    a.push(sw(8, 5, 0)); a.push(sb(8, 6, 0)); // sets byte 0 to 0xff: word becomes 0x112233ff
    a.push(lw(7, 8, 0)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 0x112233ff);
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let w = cpu::col::WIDTH;
    // Find the SB row and corrupt MERGED to replace byte 1 instead of byte 0.
    let sb_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_SB] == F::ONE).unwrap();
    t.cpu.values[sb_row * w + cpu::col::MERGED0] = F::from_u32(0x44);     // put the old byte 0 back
    t.cpu.values[sb_row * w + cpu::col::MERGED0 + 1] = F::from_u32(0xff); // and corrupt byte 1 instead
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// M2.5: `LB`'s sign extension runs through `SGN`, itself bound to the sign-relevant
/// byte's true top bit only via the `AND4[HI, 8, SGN*8]` lookup — flipping `SGN` (and `C`
/// to match, so the row's own `C` pin stays self-consistent) must be caught by that
/// lookup disagreeing with the nibble table, not by the `C` pin alone.
#[test]
fn a_load_byte_with_flipped_sign_extension_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0xffu32 as i32)); // byte 0xff, top bit set
    a.push(sw(8, 5, 0)); a.push(lb(6, 8, 0)); // LB sign-extends: -1 = 0xffffffff
    a.extend(write_output(0, 6)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 0xffff_ffff);
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let w = cpu::col::WIDTH;
    let lb_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_LB] == F::ONE).unwrap();
    t.cpu.values[lb_row * w + cpu::col::SGN] = F::ZERO; // flip: claim unsigned-looking zero-extend
    t.cpu.values[lb_row * w + cpu::col::C] = F::from_u32(0xff);
    t.public_values[cpu::pv::OUT0] = F::from_u32(0xff);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// M2.5: `IS_LH*OFF0 = 0` is the stated alignment constraint for halfwords — a retagged
/// row claiming `LH` at an odd byte offset must be rejected by the AIR, not merely
/// unreachable through the emulator.
#[test]
fn a_misaligned_lh_is_rejected_by_the_air() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0x1234)); a.push(sw(8, 5, 0));
    a.push(lw(6, 8, 0)); // an ordinary LW so the trace has a row to repurpose
    a.extend(write_output(0, 6)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let w = cpu::col::WIDTH;
    let lw_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_LW] == F::ONE).unwrap();
    // Retag this LW row as an LH with OFF0=1 (byte offset 1 — misaligned for a half).
    t.cpu.values[lw_row * w + cpu::col::IS_LW] = F::ZERO;
    t.cpu.values[lw_row * w + cpu::col::IS_LH] = F::ONE;
    t.cpu.values[lw_row * w + cpu::col::OFF0] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// M2.5: `SB`'s per-byte `MERGED` formula pins `selp(k)=0` for every byte outside `off`,
/// forcing `MERGED_k = W_k` there — corrupting a byte the store never touches must be
/// caught even though the touched byte (`off`) is still correct.
#[test]
fn a_sb_that_changes_a_byte_outside_its_offset_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0x11223344u32 as i32)); a.extend(li(6, 0xff));
    a.push(sw(8, 5, 0)); a.push(sb(8, 6, 1)); // sets byte 1 only: word becomes 0x1122ff44
    a.push(lw(7, 8, 0)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 0x1122ff44);
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let w = cpu::col::WIDTH;
    let sb_row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_SB] == F::ONE).unwrap();
    // Also corrupt byte 2 (outside off=1), leaving byte 1 correct.
    t.cpu.values[sb_row * w + cpu::col::MERGED0 + 2] = F::from_u32(0x00);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// ---------------------------------------------------------------------------------------
// M2.6: the RV32M extension.
// ---------------------------------------------------------------------------------------

fn find_alu_row(t: &Traces, op: shrugg_zkvm::isa::AluOp) -> usize {
    let w = alu::col::WIDTH;
    (0..t.alu.height())
        .find(|r| t.alu.values[r * w + alu::col::FLAG0 + op.code() as usize] == F::ONE)
        .unwrap_or_else(|| panic!("no ALU row for {op:?}"))
}

/// The spec's own `HI = 2^32-1, LO = A*B + 1` product attack: `MULHU(3, 4)` has true
/// `HI = 0` (3*4 = 12 fits in 32 bits). Forging `HI = 0xffff_ffff` needs `CARRY =
/// 0xffff_ffff` (since `T2 = 0` here), but `CARRY`'s own decomposition is only 3 RANGE8
/// limbs (`S1..3`, bounding it to `< 2^24`) — a 4-byte value has no valid encoding there,
/// so `CARRY - carry_limbs = 0` fails directly.
#[test]
fn mulhu_cannot_claim_hi_equals_2_32_minus_1_for_a_small_product() {
    let mut a = Assembler::new(0);
    a.extend(li(5, 3)); a.extend(li(6, 4));
    a.push(mulhu(7, 5, 6)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 0);
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let w = alu::col::WIDTH;
    let row = find_alu_row(&t, shrugg_zkvm::isa::AluOp::Mulhu);
    let forged_carry = 0xffff_ffffu32; // would make HI = T2 + CARRY = 0xffff_ffff
    t.alu.values[row * w + alu::col::Q0 + 3] = F::from_u32(forged_carry); // CARRY column
    // Only 3 limb columns exist for CARRY (S1..3): the forged value's low 3 bytes, dropping
    // the 4th — carry_limbs can only ever reconstruct a < 2^24 value.
    t.alu.values[row * w + alu::col::S0 + 1] = F::from_u32(forged_carry & 0xff);
    t.alu.values[row * w + alu::col::S0 + 2] = F::from_u32((forged_carry >> 8) & 0xff);
    t.alu.values[row * w + alu::col::S0 + 3] = F::from_u32((forged_carry >> 16) & 0xff);
    t.alu.values[row * w + alu::col::C] = F::from_u32(0xffff_ffff);
    for k in 0..4 { t.alu.values[row * w + alu::col::C0 + k] = F::from_u32(0xff); }
    t.public_values[cpu::pv::OUT0] = F::from_u32(0xffff_ffff);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// A supplementary test for the fix this table needed beyond the spec sketch: `LO`'s own
/// byte limbs (`T0..3`) are range-checked *unconditionally* on every mul-family row, not
/// just `mul` rows — without that, a `MULHU`-only row's `HI = T2 + CARRY` check alone does
/// not pin `CARRY` (see the `alu` module doc comment's uniqueness argument), so a forged
/// `CARRY` that still fits the 3-limb `< 2^24` bound (unlike the attack above) would
/// otherwise pass. `MULHU(3, 4)`: honest `CARRY = 0`; forging `CARRY = 100` (well within
/// the 3-limb bound) must still be rejected, this time via the `LO` recomposition
/// (`word(T0..3) = T0 + 2^16*T1 - 2^32*CARRY`) disagreeing.
#[test]
fn a_small_in_range_forged_carry_on_a_mulhu_row_is_still_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(5, 3)); a.extend(li(6, 4));
    a.push(mulhu(7, 5, 6)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 0);
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let w = alu::col::WIDTH;
    let row = find_alu_row(&t, shrugg_zkvm::isa::AluOp::Mulhu);
    let forged_carry = 100u32; // < 2^24, so the CARRY-limb check alone does not catch this
    t.alu.values[row * w + alu::col::Q0 + 3] = F::from_u32(forged_carry);
    t.alu.values[row * w + alu::col::S0 + 1] = F::from_u32(forged_carry & 0xff);
    t.alu.values[row * w + alu::col::S0 + 2] = F::ZERO;
    t.alu.values[row * w + alu::col::S0 + 3] = F::ZERO;
    t.alu.values[row * w + alu::col::C] = F::from_u32(100); // T2 (= 0 here) + forged CARRY
    t.alu.values[row * w + alu::col::C0] = F::from_u32(100);
    t.public_values[cpu::pv::OUT0] = F::from_u32(100);
    // T0..3 (LO's own limbs) are left at their honest value (12, from the real 3*4 = 12),
    // which now disagrees with `T0 + 2^16*T1 - 2^32*CARRY` for the forged CARRY.
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// `R >= B`: `REMU(17, 5) = 2` (`17 = 3*5 + 2`). Re-decompose as `q=2, r=7` — the core
/// identity `|A| = Q*|B| + R` still holds (`17 = 2*5 + 7`) — but `7 >= 5` violates
/// `R < |B|`. Kept otherwise self-consistent (`C`, the magnitude-zero gadget's `INV`) so the
/// only constraint that can catch this is the `R < |B|` range check on `|B| - R - 1`, which
/// has no valid witness once `R >= |B|` (the difference is not representable as 4
/// non-negative bytes for any choice of the diff-limb columns).
#[test]
fn a_remainder_not_smaller_than_the_divisor_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(5, 17)); a.extend(li(6, 5));
    a.push(remu(7, 5, 6)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 2);
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let w = alu::col::WIDTH;
    let row = find_alu_row(&t, shrugg_zkvm::isa::AluOp::Remu);
    t.alu.values[row * w + alu::col::Q0] = F::from_u32(2); // quotient core: 3 -> 2
    t.alu.values[row * w + alu::col::S0] = F::from_u32(7); // remainder core: 2 -> 7 (>= B = 5)
    t.alu.values[row * w + alu::col::C] = F::from_u32(7);
    t.alu.values[row * w + alu::col::C0] = F::from_u32(7);
    t.alu.values[row * w + alu::col::INV] = F::from_u32(7).inverse(); // keep the mag-zero gadget honest
    t.public_values[cpu::pv::OUT0] = F::from_u32(7);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// A wrong `DIVZ` on a nonzero divisor: `DIVU(10, 3) = 3` (`B = 3 != 0`). The naive
/// single-equation is-zero gadget (`B*INVB = 1-DIVZ`) alone is bypassable — set `INVB = 0`
/// and `DIVZ = 1`, satisfying `3*0 = 1-1 = 0` — which is exactly why the table also asserts
/// `DIVZ*B = 0`: with `B = 3` and `DIVZ = 1` forged, `1*3 = 3 != 0` catches it.
#[test]
fn a_wrong_divz_on_a_nonzero_divisor_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(5, 10)); a.extend(li(6, 3));
    a.push(divu(7, 5, 6)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 3);
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let w = alu::col::WIDTH;
    let row = find_alu_row(&t, shrugg_zkvm::isa::AluOp::Divu);
    t.alu.values[row * w + alu::col::DIVZ] = F::ONE; // B = 3 != 0, but claim DIVZ
    t.alu.values[row * w + alu::col::INVB] = F::ZERO; // ... and try to smuggle it past B*INVB=1-DIVZ
    t.alu.values[row * w + alu::col::C] = F::from_u32(0xffff_ffff);
    for k in 0..4 { t.alu.values[row * w + alu::col::C0 + k] = F::from_u32(0xff); }
    t.public_values[cpu::pv::OUT0] = F::from_u32(0xffff_ffff);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// M2.6 regression. An earlier version of this test set `MULT = 1` on the forged row, which
/// (with `IS_REAL = 0`) always fails the older, independent `(1-IS_REAL)*MULT = 0`
/// padding-row invariant regardless of what the one-hot sum/boolean loop (`for i in
/// 0..AluOp::COUNT { assert_bool; sum += flag_i }`, checked against `sum == is_real`)
/// covers — masking whether the loop actually visits all 19 flags or was silently left at
/// the old 11. This version leaves `MULT = 0` (and `A`/`B`/`C` at their padding-row default
/// of zero) and sets *only* the `Mul` flag (index 11), so `(1-IS_REAL)*MULT = (1-0)*0 = 0`
/// holds and that older invariant cannot fire.
///
/// This is *not*, however, a single-constraint regression guard for the sum/boolean loop
/// specifically — confirmed by directly checking, not assumed: shrinking that loop to
/// `0..11` (so it never visits index 11) still rejects this exact row, but via a different
/// mechanism entirely. Setting `FLAG0 + 11` also sets `is_mul = mul+mulh+mulhu+mulhsu` to 1,
/// which activates `mul`'s *unconditional* `RANGE8` lookups on `S1, S2, S3` (`CARRY`'s own
/// limbs) and `T0..3` (`LO`'s own limbs) — seven lookups against value `0` (the padding
/// row's untouched default for those columns) with no corresponding honest `fill_row` call
/// to have accounted for them. That imbalances the global `RANGE8` bus regardless of the
/// sum/boolean loop's range, confirmed directly: on a guest with zero other mul-family rows
/// (so no other row's lookups mask the count), the ablated build fails with `Lookup mismatch
/// (global lookup 'RANGE8'): tuple ["0"] has net multiplicity 7` — exactly those seven. So
/// this row is doubly protected (the sum/boolean loop *and* the mul-family's own
/// unconditional range checks), which is why it cannot cleanly isolate either one — see the
/// task-6 fix report for the full experiment.
#[test]
fn a_mul_flag_set_on_an_otherwise_all_zero_padding_row_is_rejected() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::muldiv();
    let e = execute(&p, &[], 10_000).unwrap();
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let wa = alu::col::WIDTH;
    let pad = t.alu.height() - 1;
    assert_eq!(t.alu.values[pad * wa + alu::col::IS_REAL], F::ZERO, "last alu row is padding");
    assert_eq!(t.alu.values[pad * wa + alu::col::MULT], F::ZERO, "padding row's MULT starts at 0");
    // Set only the `Mul` flag; `A`, `B`, `C` (and every other column) stay at the padding
    // row's default zero, and `MULT` stays 0 — `(1-IS_REAL)*MULT = 0` holds regardless.
    t.alu.values[pad * wa + alu::col::FLAG0 + shrugg_zkvm::isa::AluOp::Mul.code() as usize] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// A sign flip on `MULH`: `MULH(-2, -3) = 0` (`(-2)*(-3) = 6`, fits in the low word). Flip
/// `SA` (claim `A`'s sign is positive when it is actually negative) while leaving the
/// sign-correction `borrow` and `C` as the honest solver found them — the `HI_signed = HI -
/// SA*B - SB*A + borrow*2^32` identity now disagrees with `C`.
#[test]
fn a_sign_flipped_mulh_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(5, -2)); a.extend(li(6, -3)); // (-2)*(-3) = 6, MULH = 0
    a.push(mulh(7, 5, 6)); a.extend(write_output(0, 7)); a.extend(halt());
    let p = a.assemble();
    let m = Machine::new(FriProfile::Test);
    let e = execute(&p, &[], 10_000).unwrap();
    assert_eq!(e.outputs[0], 0);
    let mut t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    let w = alu::col::WIDTH;
    let row = find_alu_row(&t, shrugg_zkvm::isa::AluOp::Mulh);
    assert_eq!(t.alu.values[row * w + alu::col::SA], F::ONE, "A = -2 is negative");
    t.alu.values[row * w + alu::col::SA] = F::ZERO; // flip A's claimed sign
    // `C` (0) and `borrow` are left as the honest solver set them: `rejects()` only needs a
    // genuine mismatch, and the public output stays whatever the (now-inconsistent) row
    // claims so `verify` doesn't reject on a public-value mismatch instead.
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// M3.1: the Poseidon2 table's round-transition constraints are gated by the *preprocessed*
/// `IS_FULL`/`IS_PARTIAL`/idle selectors, not by the main column `IS_REAL` — so they run on
/// every block, including the all-padding blocks `build_traces` currently produces (the
/// emulator doesn't call `POSEIDON2` until M3.2; see `tables::poseidon2`'s module doc
/// comment). That means these three cheating tests need no real event at all: tampering any
/// padding block's own honest, self-consistent permutation trace is already enough to trip
/// the AIR.
#[test]
fn tampering_a_poseidon2_x7_column_is_rejected() {
    let (m, p, mut t) = setup();
    // Row 0 of block 0 is the first full round; flip lane 0's X7 (the S-box output half of
    // `x7 = x3*x3*(mds_light(s)+rc)`, checked unconditionally on every `IS_FULL` row).
    t.poseidon2.values[poseidon2::col::X7_0] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

#[test]
fn tampering_the_poseidon2_in_copy_is_rejected() {
    let (m, p, mut t) = setup();
    let w = poseidon2::col::WIDTH;
    // Row 1 of block 0 must copy row 0's IN down (the "same block" transition invariant);
    // flip it.
    t.poseidon2.values[w + poseidon2::col::IN0] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

#[test]
fn bumping_poseidon2_mult_on_an_idle_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = poseidon2::col::WIDTH;
    // Rows 30/31 of a block are idle (ROUND_ROWS = 30); MULT there must stay 0 via
    // `MULT * (1 - IS_LAST) = 0`, a purely local (`CONSTRAINT_PANIC`) constraint. M3.4:
    // `setup()`'s guest (`fib(10)`) now calls `POSEIDON2` once per digest row (its own hc,
    // `Program::digest_rows()` blocks), so block 0 is real — pick the first genuinely idle
    // block instead of assuming block 0 is padding.
    let idle_block = (0..t.poseidon2.height() / shrugg_zkvm::tables::poseidon2::BLOCK)
        .find(|b| t.poseidon2.values[b * shrugg_zkvm::tables::poseidon2::BLOCK * w + poseidon2::col::IS_REAL] == F::ZERO)
        .expect("some block must be idle padding");
    let idle_row = idle_block * shrugg_zkvm::tables::poseidon2::BLOCK + 30;
    t.poseidon2.values[idle_row * w + poseidon2::col::MULT] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// M3.2: `guests::poseidon2_demo` for `msg`, traced at tier 10.
fn setup_poseidon2(msg: &[u32]) -> (Machine, shrugg_zkvm::isa::Program, Traces) {
    let m = Machine::new(FriProfile::Test);
    let p = guests::poseidon2_demo(msg);
    let e = execute(&p, &[], 10_000).unwrap();
    let t = build_traces_salted(&p, &[], [0u32; 4], &e, Tier(10)).unwrap();
    (m, p, t)
}

/// The cpu-table row indices of one `POSEIDON2` call's ecall row, absorb rows (in order), and
/// write-back rows (in order).
fn hash_rows(t: &Traces) -> (usize, Vec<usize>, Vec<usize>) {
    let w = cpu::col::WIDTH;
    let h = t.cpu.height();
    let ecall = (0..h).find(|&r| t.cpu.values[r * w + cpu::col::SYS_HASH] == F::ONE).expect("an ecall row");
    let absorbs: Vec<usize> = (0..h).filter(|&r| t.cpu.values[r * w + cpu::col::IS_HASH] == F::ONE).collect();
    let writes: Vec<usize> = (0..h).filter(|&r| t.cpu.values[r * w + cpu::col::IS_HASH_OUT] == F::ONE).collect();
    (ecall, absorbs, writes)
}

/// Flipping a written digest word breaks the write-back row's own pin, `HV = byte_sum(HVL)`
/// (the two never leave it), whether or not it also breaks the `HV·2^0 + HV·2^32 = HS_lane`
/// identity or the `MEMORY` permutation against what the emulator actually put in RAM.
#[test]
fn tampering_a_hash_digest_word_is_rejected() {
    let (m, p, mut t) = setup_poseidon2(&[1, 2, 3, 4]);
    let w = cpu::col::WIDTH;
    let (_, _, writes) = hash_rows(&t);
    assert_eq!(writes.len(), 2, "one POSEIDON2 call always has two write-back rows");
    t.cpu.values[writes[0] * w + cpu::col::HV0] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// `n = 5` absorbs a full block then a one-word block, so the final absorb row's lane 1 is
/// inactive: its `HV1` must equal `HS1`, the previous block's own lane 1, carried forward
/// unread rather than pulled from memory. Flipping `HV1` alone (leaving `ACT`/`HS` untouched)
/// trips that copy-forward pin directly — the lane-copy invariant a cheating witness could
/// otherwise use to smuggle an unabsorbed value into the sponge state between two absorb rows.
#[test]
fn tampering_a_hash_state_lane_between_absorb_rows_is_rejected() {
    let (m, p, mut t) = setup_poseidon2(&[1, 2, 3, 4, 5]);
    let w = cpu::col::WIDTH;
    let (_, absorbs, _) = hash_rows(&t);
    assert_eq!(absorbs.len(), 2, "n=5 is one full block plus one partial block");
    let last = absorbs[1];
    assert_eq!(t.cpu.values[last * w + cpu::col::ACT0 + 1], F::ZERO, "lane 1 is inactive on the final (partial) block");
    t.cpu.values[last * w + cpu::col::HV0 + 1] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// Every new selector (`SYS_HASH`, `IS_HASH`, `IS_HASH_OUT`, `HASH_FIN`) must be zero on a
/// padding row — `SELECTORS`' `(1 - is_real)·v(s) = 0` gate, the same invariant class as every
/// other cpu selector. Setting `IS_HASH` in particular also requests a `POSEIDON2` lookup with
/// count 1 (`Count::bounded(is_hash, 1)`) that nothing else on an all-zero padding row can
/// answer, so this doubles as "a POSEIDON2 lookup with count 1 on a non-hash row is rejected".
#[test]
fn bumping_a_new_hash_selector_on_a_padding_row_is_rejected() {
    for &sel in &[cpu::col::SYS_HASH, cpu::col::IS_HASH, cpu::col::IS_HASH_OUT, cpu::col::HASH_FIN] {
        let (m, p, mut t) = setup();
        let w = cpu::col::WIDTH;
        let pad = t.cpu.height() - 1;
        assert_eq!(t.cpu.values[pad * w + cpu::col::IS_REAL], F::ZERO, "last cpu row is padding");
        t.cpu.values[pad * w + sel] = F::ONE;
        assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }), "selector column {sel}");
    }
}

/// CRITICAL 1 regression: before `HASH_PTR` got its own `RANGE8`/`AND4` byte decomposition
/// (`HP0..3`/`HP3_HI`, the `MA0..3`/`MA3_HI` pattern), it was just the raw `a0` register
/// value — an unbounded field element on the `MEMORY` bus. A witness could pick it so that
/// `SPACE_RAM`'s sort key (`1·2^30 + HASH_PTR`, `memory.rs::KEY_SHIFT`) wraps, mod the
/// Goldilocks prime, to alias *any* other key — here, register `a0`'s own key
/// (`0·2^30 + REG_A0`) — letting a hash row's memory access land wherever the witness likes
/// instead of the `n` words it claims to hash. `HP0..3`/`HP3_HI` are deliberately left at
/// their honest (small) values, so this must trip the new recomposition equation
/// (`v(SYS_HASH)·(HASH_PTR - hp) = 0`) directly — a local `CONSTRAINT_PANIC` on the ecall row,
/// not a downstream `MEMORY`-bus imbalance.
#[test]
fn an_unbounded_hash_ptr_that_aliases_a_register_key_is_rejected() {
    let (m, p, mut t) = setup_poseidon2(&[1, 2, 3, 4]);
    let w = cpu::col::WIDTH;
    let (ecall, _, _) = hash_rows(&t);
    let alias = F::from_u32(REG_A0) - F::from_u64(1u64 << 30);
    t.cpu.values[ecall * w + cpu::col::HASH_PTR] = alias;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// CRITICAL 2 regression: without a rule binding the ecall row's routing to `HASH_N`, a
/// witness could skip every absorb row entirely and go straight from the ecall row to a
/// write-back row, publishing the empty-input digest for a nonzero `n` — the `final_absorb`
/// drain rule never fires, since it only lives on `IS_HASH` transitions and there would be no
/// absorb row at all. Relabel `n = 5`'s first absorb row as a write-back row instead (leaving
/// its columns otherwise untouched, in particular its own `HASH_LEFT = 5`, the "left before
/// this row" value an honest absorb row carries): this trips both new rules directly — the
/// ecall row's own `SYS_HASH·n(IS_HASH_OUT)·HASH_N = 0` (now `1·1·5 != 0`) and the write-back
/// row's own `IS_HASH_OUT·(1-HASH_FIN)·HASH_LEFT = 0` (now `1·1·5 != 0`) — local
/// `CONSTRAINT_PANIC`s, not a `PROGRAM`/`POSEIDON2`-bus imbalance.
#[test]
fn skipping_every_absorb_row_for_a_nonzero_hash_n_is_rejected() {
    let (m, p, mut t) = setup_poseidon2(&[1, 2, 3, 4, 5]);
    let w = cpu::col::WIDTH;
    let (ecall, absorbs, _) = hash_rows(&t);
    assert_eq!(absorbs.len(), 2, "n=5 needs two absorb rows");
    assert_eq!(absorbs[0], ecall + 1, "the first absorb row follows the ecall row directly");
    assert_eq!(t.cpu.values[absorbs[0] * w + cpu::col::HASH_LEFT], F::from_u32(5));
    t.cpu.values[absorbs[0] * w + cpu::col::IS_HASH] = F::ZERO;
    t.cpu.values[absorbs[0] * w + cpu::col::IS_HASH_OUT] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// CRITICAL 3 regression: `hv_lo + hv_hi·2^32 = hs_lane` is only a field identity, and for any
/// lane `< 2^32-1` the non-canonical pair `(lane+1, 2^32-1)` satisfies it too (`(lane+1) +
/// (2^32-1)·2^32 = lane + p ≡ lane mod p`) with both words still individually `< 2^32` — so the
/// existing `RANGE8`/`HVL` byte check does not catch it either. `n = 0`'s digest is all-zero,
/// so lane 0 is exactly `0`, one of the rare values with such an alternate: `1 +
/// (2^32-1)·2^32 = p ≡ 0`. Re-encode it as `(lo=1, hi=2^32-1)`, including the gadget columns a
/// "smart" cheating witness would also have to update to keep the canonical-check gadget's
/// first equation satisfied (`d = hi-(2^32-1) = 0` forces `HIMAX = 1` regardless of `INV`, so
/// there is no way to leave `HIMAX = 0` here) — only the second equation, `HIMAX·lo = 0`, is
/// left to catch `lo = 1 != 0`.
#[test]
fn a_non_canonical_digest_word_encoding_is_rejected() {
    let (m, p, mut t) = setup_poseidon2(&[]);
    let w = cpu::col::WIDTH;
    let (_, absorbs, writes) = hash_rows(&t);
    assert!(absorbs.is_empty(), "n=0 has no absorb rows");
    let row = writes[0];
    assert_eq!(t.cpu.values[row * w + cpu::col::HS0], F::ZERO, "n=0's digest is all-zero");
    t.cpu.values[row * w + cpu::col::HV0] = F::ONE;
    t.cpu.values[row * w + cpu::col::HV0 + 1] = F::from_u32(0xFFFF_FFFF);
    let (lo_limbs, hi_limbs) = (limbs(1), limbs(0xFFFF_FFFF));
    for j in 0..4 {
        t.cpu.values[row * w + cpu::col::HVL0_0 + j] = lo_limbs[j];
        t.cpu.values[row * w + cpu::col::HVL0_0 + 4 + j] = hi_limbs[j];
    }
    t.cpu.values[row * w + cpu::col::HIMAX0] = F::ONE;
    t.cpu.values[row * w + cpu::col::INV0] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// MINOR regression: `is_hash` and `is_hash_out` set together on the same row must be
/// rejected outright, not merely fall through whichever half's constraints happen to notice.
#[test]
fn a_row_claiming_to_be_both_an_absorb_and_a_write_back_row_is_rejected() {
    let (m, p, mut t) = setup_poseidon2(&[1, 2, 3, 4]);
    let w = cpu::col::WIDTH;
    let (_, absorbs, _) = hash_rows(&t);
    assert_eq!(absorbs.len(), 1, "n=4 is exactly one full block");
    t.cpu.values[absorbs[0] * w + cpu::col::IS_HASH_OUT] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// CRITICAL 2b regression (round 2): before the three `n(HASH_FIN) = 0`/"followed by
/// `HASH_FIN = 1`" routing rules, a witness could route the `n = 0` case straight from the
/// ecall row to the *second* write-back row, skipping the first — digest words 0..3 are then
/// never written at all, so a guest reading `ptr..ptr+3` back would see whatever was already
/// in RAM instead of the honest zeros: a valid proof of a non-honest execution. Flip the
/// (otherwise honest) first write-back row's own `HASH_FIN` from 0 to 1, i.e. pretend it is
/// the only write-back row present — trips `SYS_HASH·n(IS_HASH_OUT)·n(HASH_FIN) = 0` directly
/// on the ecall row, a local `CONSTRAINT_PANIC`.
#[test]
fn skipping_the_first_write_back_row_is_rejected() {
    let (m, p, mut t) = setup_poseidon2(&[]);
    let w = cpu::col::WIDTH;
    let (ecall, absorbs, writes) = hash_rows(&t);
    assert!(absorbs.is_empty(), "n=0 has no absorb rows");
    assert_eq!(writes.len(), 2, "one POSEIDON2 call always has two write-back rows");
    assert_eq!(writes[0], ecall + 1, "the first write-back row follows the ecall row directly");
    assert_eq!(t.cpu.values[writes[0] * w + cpu::col::HASH_FIN], F::ZERO);
    t.cpu.values[writes[0] * w + cpu::col::HASH_FIN] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// M3.4: the program table as a witness trace with an in-circuit decoder, and the digest
// prefix that computes `hc`.

/// Flip one `BIT` column on a real instruction row without touching `WORD` (or the `FIELDS`
/// that were honestly derived from the *original* bits) — the bit-decomposition constraint
/// `WORD == Σ bit_i·2^i` is what this table is built on, so any single flipped bit trips it
/// directly, independent of what that bit even controls.
#[test]
fn tampering_a_program_bit_column_changes_the_digest_and_is_rejected() {
    let (m, p, mut t) = setup();
    assert!(!p.is_empty(), "fib(10) has instructions");
    t.program.values[program::col::BIT0] += F::ONE; // row 0's bit 0
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// `verify` checks `pv[HC0..HC7]` against the caller-supplied `hc` *before* the STARK batch
/// check even runs — a proof for `fib(10)` checked against `fib(11)`'s digest is rejected
/// structurally (`VerifyError::PublicValues`), which `rejects()` still accepts (it takes any
/// `VerifyError`, not just a constraint-system panic).
#[test]
fn claiming_a_digest_that_does_not_match_the_program_is_rejected() {
    let (m, p, t) = setup();
    let proof = m.prove_traces(&p, &t, Tier(10));
    let wrong_hc = guests::fib(11).digest();
    assert_ne!(wrong_hc, p.digest());
    assert!(rejects(|| m.verify(&wrong_hc, &proof)));
}

/// M3.4 ruling: the eight M-extension ops are legal only under `OP_ALU` with `funct7 = 1` —
/// no flag in the decoder ever maps an `OP_ALUI`-opcode word to an M op (the `funct7` bits of
/// an ALUI word are just part of its sign-extended immediate, never a "claim M-extension"
/// signal, exactly mirroring `isa::Instr::decode`). Tamper an honest ALUI row's `ALU_OP`
/// field to claim `MUL` directly: no combination of (legitimately derivable) flags can
/// produce that value on an `OP_ALUI` row, so the field-consistency equation `ALU_OP ==
/// (flag-weighted sum)` must fail.
#[test]
fn an_alui_word_claiming_mul_is_rejected() {
    let (m, p, mut t) = setup();
    let w = program::col::WIDTH;
    let row = (0..p.len())
        .find(|&i| { let d = Instr::decode(p.words[i]).unwrap().decoded(); d.is_alu == 1 && d.is_imm == 1 })
        .expect("fib(10) uses at least one ALUI op (e.g. an ADDI)");
    t.program.values[row * w + program::col::ALU_OP] = F::from_u32(AluOp::Mul.code());
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// The digest-row count is bound to the program's length exactly like M3.2's absorb-row
/// count is bound to `n` (`skipping_every_absorb_row_for_a_nonzero_hash_n_is_rejected`
/// above): ending the digest group one row early — turning the true last digest row back into
/// an ordinary row — desyncs `DIGEST_LAST`'s own pin (`is_digest*(DIGEST_LAST-(1-n(IS_DIGEST)))
/// = 0`, now violated one row earlier than the witness updated it) and, even if it hadn't,
/// would leave the program table's now-unconsumed `PROGRAM_WORD` provides for the dropped
/// words unpaid.
#[test]
fn skipping_a_digest_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    let dr = p.digest_rows();
    assert!(dr > 1, "fib(10)'s program needs more than one digest row");
    t.cpu.values[(dr - 1) * w + cpu::col::IS_DIGEST] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// CRITICAL regression (M3.4 fix): before `MULT_WORD` was pinned to equal `VALID` exactly,
/// the table's own constraint was the one-sided `mult_word · (1 − valid) = 0` — a no-op on
/// any `valid = 1` row (`mult_word · (1 − 1) = mult_word · 0 = 0` regardless of `mult_word`'s
/// value). That let a real, decodable instruction sit in the program table with `valid = 1`
/// but `mult_word = 0`: it would never be claimed by any digest row's `PROGRAM_WORD` lookup
/// (so it would never enter `hc`), while remaining fully `valid = 1` — and hence fetchable,
/// and at runtime reachable via a computed jump (`JALR`) past the honestly-digested
/// `base_pc..base_pc+4·len` window — on the ordinary `PROGRAM` bus. Under the *old* AIR this
/// witness was not merely undetected by this one constraint, it was a fully valid, verifying
/// proof: `hc` would bind a strict prefix of the executable program, not the program actually
/// run.
///
/// Reproduce exactly that witness against `fib(10)`, then check it against the *fixed* AIR.
/// `fib(10)`'s program table (`MIN_HEIGHT = 16` floor) has spare padding rows past the last
/// real instruction; overwrite the first one with a real, decodable instruction (reusing one
/// of the program's own words) at the PC `program_trace` already continues the honest
/// arithmetic sequence to (so the separate "no address aliasing" invariant is untouched) —
/// `VALID` comes out `1` — and leave `MULT_WORD` at its padding-row default, `0`. This alone
/// (no change to the cpu table needed — `program_trace`'s own honest `mult`/fetch bookkeeping
/// for the *real* program is untouched, so this is "append an escaped instruction to the
/// program table" in its simplest form) now violates `mult_word = valid` directly on the
/// tampered row: a local `CONSTRAINT_PANIC` on the `program` table, not a downstream
/// `PROGRAM_WORD` lookup-balance check — the row-level equality alone is now strong enough to
/// catch the escape without needing anything to actually consume (or even fetch) the row.
#[test]
fn an_undigested_reachable_program_tail_is_rejected() {
    let (m, p, mut t) = setup();
    let w = program::col::WIDTH;
    let extra = p.len(); // first padding row past the digested program
    assert!(t.program.height() > extra, "fib(10)'s program table has spare padding rows");
    let pc = p.pc_of(extra); // continues program_trace's own honest PC sequence
    let word = p.words[0]; // reuse a real, decodable instruction
    let mut row = vec![F::ZERO; w];
    program::fill_word_row(&mut row, pc, word);
    assert_eq!(row[program::col::VALID], F::ONE, "the reused word must decode");
    assert_eq!(row[program::col::MULT_WORD], F::ZERO, "fill_word_row never sets MULT_WORD");
    t.program.values[extra * w..(extra + 1) * w].copy_from_slice(&row);
    // VALID = 1, MULT_WORD = 0: the exact witness the old, one-sided constraint accepted.
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

/// IMPORTANT regression: mirrors `a_row_claiming_to_be_both_an_absorb_and_a_write_back_row_is_rejected`
/// above, one selector pair over — `IS_DIGEST` must be exclusive with `IS_HASH` too (and,
/// symmetrically, with `IS_HASH_OUT`; both are pinned in `tables::cpu.rs`). `Count::bounded(is_hash
/// + is_digest, 1)` (the shared `POSEIDON2` lookup both row kinds feed) is only a valid 0/1
/// selector if a row can never claim both at once — otherwise it would double-count one
/// `POSEIDON2` call's worth of bus demand while also falling through both row kinds' own
/// selector-gated constraints half-unconstrained on whichever half its own logic doesn't cover.
/// Take an honest absorb row from a `POSEIDON2` call and additionally claim `IS_DIGEST`: trips
/// `is_digest · is_hash = 0` directly, a local `CONSTRAINT_PANIC`.
#[test]
fn a_row_claiming_to_be_both_a_digest_and_an_absorb_row_is_rejected() {
    let (m, p, mut t) = setup_poseidon2(&[1, 2, 3, 4]);
    let w = cpu::col::WIDTH;
    let (_, absorbs, _) = hash_rows(&t);
    assert_eq!(absorbs.len(), 1, "n=4 is exactly one full block");
    t.cpu.values[absorbs[0] * w + cpu::col::IS_DIGEST] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// M4.1: the input commitment — READ_INPUT bound to a committed H_IN via the new `input`
// table and the split INPUT_DIGEST/INPUT_READ buses (review round 1, C1).

/// The fixed salt every hand-tampered witness below uses — value is arbitrary, only its
/// *consistency* with what a given `Traces` was actually built with matters.
const TEST_SALT: [u32; 4] = [0u32; 4];

fn setup_with_inputs(inputs: &[u32]) -> (Machine, shrugg_zkvm::isa::Program, Traces) {
    let m = Machine::new(FriProfile::Test);
    let p = guests::balance_check(1000); // reads inputs 0..3 once each
    let e = execute(&p, inputs, 10_000).unwrap();
    let t = build_traces_salted(&p, inputs, TEST_SALT, &e, Tier(10)).unwrap();
    (m, p, t)
}

/// Rewrites `t`'s indigest region in place as if H_IN had only ever committed to
/// `new_inputs` (a prefix of the original inputs `t` was built with, needing the *same*
/// number of real indigest rows — i.e. `new_inputs.len()` and the original `n_in` fall in the
/// same `⌈./4⌉` block), while leaving the `input` witness table (and hence the guest's own
/// reads) completely untouched. This is the shared "shrink the digest's own declared n_in"
/// step behind cheating tests (d) and (f): it recomputes the salt row's header, the real
/// block's absorbed words and inactive-lane carry, `HASH_LEFT`'s own `LEFT0/LEFT0+1`
/// byte-limb re-encoding (and the `range` table's matching multiplicity shift, since RANGE8 is
/// exact-count accounting — leaving this out would reject on a RANGE8 imbalance instead of the
/// intended `INPUT_DIGEST` one), the last real row's canonical `IHVL/IHIMAX/IINV` encoding,
/// the two permutation entries in the poseidon2 table (this only holds for a guest with no
/// `POSEIDON2` syscalls of its own, true of `guests::balance_check`, so the program digest's
/// own permutations plus the indigest ones are the *entire* poseidon2 event list — see
/// `machine::build_traces_salted`), and `pv::IN0..7` — everything an honest
/// `hash::input_digest_rows(salt, new_inputs)` computation would produce — mirroring
/// `tables::cpu::fill_input_digest_rows` by hand against an already-built `Traces`.
fn shrink_declared_n_in(t: &mut Traces, p: &shrugg_zkvm::isa::Program, salt: [u32; 4], new_inputs: &[u32]) {
    let w = cpu::col::WIDTH;
    let offset = p.digest_rows();
    let blocks = shrugg_zkvm::hash::input_digest_rows(salt, new_inputs);
    let n = blocks.len();
    let rw = range::col::WIDTH;
    // RANGE8 is exact-count accounting (`RangeCounts`/`range_trace`): every RANGE8-checked
    // byte column this loop overwrites (`LEFT0/LEFT0+1`, and — on the last row —
    // `IHVL0..31`) changes which byte values the cpu table demands, so the `range` table's
    // own supply must shift by the same amount, tracked generically here as (old, new) byte
    // pairs, or a RANGE8 imbalance (not the intended INPUT_DIGEST one) rejects the witness
    // instead.
    let mut range_byte_edits: Vec<(u32, u32)> = Vec::new();
    for (i, blk) in blocks.iter().enumerate() {
        let r0 = (offset + i) * w;
        t.cpu.values[r0 + cpu::col::HASH_N] = F::from_u32(new_inputs.len() as u32);
        let old_left = t.cpu.values[r0 + cpu::col::HASH_LEFT].as_canonical_u64() as u32;
        t.cpu.values[r0 + cpu::col::HASH_LEFT] = F::from_u32(blk.left_before);
        let (old_l0, old_l1) = (old_left & 0xff, (old_left >> 8) & 0xff);
        let (new_l0, new_l1) = (blk.left_before & 0xff, (blk.left_before >> 8) & 0xff);
        t.cpu.values[r0 + cpu::col::LEFT0] = F::from_u32(new_l0);
        t.cpu.values[r0 + cpu::col::LEFT0 + 1] = F::from_u32(new_l1);
        range_byte_edits.push((old_l0, new_l0));
        range_byte_edits.push((old_l1, new_l1));
        for k in 0..8 { t.cpu.values[r0 + cpu::col::HS0 + k] = blk.state_in[k]; }
        for k in 0..4 {
            t.cpu.values[r0 + cpu::col::ACT0 + k] = F::from_bool(blk.active[k]);
            t.cpu.values[r0 + cpu::col::HV0 + k] = if blk.active[k] { F::from_u32(blk.words[k]) } else { blk.state_in[k] };
        }
        if i + 1 == n {
            let words = shrugg_zkvm::hash::split_digest([blk.state_out[0], blk.state_out[1], blk.state_out[2], blk.state_out[3]]);
            for kk in 0..8 {
                let old_bytes: [u32; 4] = core::array::from_fn(|j| t.cpu.values[r0 + cpu::col::IHVL0 + 4 * kk + j].as_canonical_u64() as u32);
                let new_bl = limbs(words[kk]);
                for j in 0..4 {
                    let new_byte = new_bl[j].as_canonical_u64() as u32;
                    range_byte_edits.push((old_bytes[j], new_byte));
                    t.cpu.values[r0 + cpu::col::IHVL0 + 4 * kk + j] = new_bl[j];
                }
            }
            for j in 0..4usize {
                let hi = words[2 * j + 1];
                if hi == u32::MAX {
                    t.cpu.values[r0 + cpu::col::IHIMAX0 + j] = F::ONE;
                    t.cpu.values[r0 + cpu::col::IINV0 + j] = F::ZERO;
                } else {
                    t.cpu.values[r0 + cpu::col::IHIMAX0 + j] = F::ZERO;
                    t.cpu.values[r0 + cpu::col::IINV0 + j] = (F::from_u32(hi) - F::from_u32(u32::MAX)).inverse();
                }
            }
            // Seed the row right after (the first ordinary instruction row) with this block's
            // final state, exactly as `fill_input_digest_rows` does.
            let r1 = (offset + n) * w;
            for k in 0..8 { t.cpu.values[r1 + cpu::col::HS0 + k] = blk.state_out[k]; }
        }
    }
    for (old_byte, new_byte) in range_byte_edits {
        t.range.values[old_byte as usize * rw + range::col::M_RANGE] -= F::ONE;
        t.range.values[new_byte as usize * rw + range::col::M_RANGE] += F::ONE;
    }
    // Rebuild the poseidon2 table's program-digest + indigest permutation entries — the only
    // two event sources for a guest with no `POSEIDON2` syscalls of its own.
    let digest_blocks = shrugg_zkvm::hash::program_digest_rows(p.base_pc, &p.words);
    let to_events = |blocks: &[shrugg_zkvm::hash::DigestBlock]| -> Vec<poseidon2::Poseidon2Event> {
        blocks.iter().map(|blk| {
            let mut input = blk.state_in;
            for k in 0..4 { if blk.active[k] { input[k] = F::from_u32(blk.words[k]); } }
            poseidon2::Poseidon2Event { input, output: blk.state_out }
        }).collect()
    };
    let all: Vec<poseidon2::Poseidon2Event> = to_events(&digest_blocks).into_iter().chain(to_events(&blocks)).collect();
    t.poseidon2 = poseidon2::poseidon2_trace(&all, t.poseidon2.height());
    // pv::IN0..7
    let hin = shrugg_zkvm::hash::input_digest(salt, new_inputs);
    for k in 0..8 { t.public_values[cpu::pv::IN0 + k] = F::from_u32(hin[k]); }
}

// (a) two reads of the same index returning different words rejects.
#[test]
fn two_reads_of_the_same_index_returning_different_words_is_rejected() {
    // A tiny hand-built guest: read input[0] twice into two registers, output their XOR
    // (0 if honest), so the second read's row is easy to locate and its C column easy to
    // tamper independently of the first.
    let mut a = Assembler::new(0);
    a.extend(read_input(0));
    a.push(mv(5, REG_A0)); // t0 = first read
    a.extend(read_input(0));
    a.push(xor(6, 5, REG_A0)); // t1 = t0 ^ second read (0 if honest)
    a.extend(write_output(0, 6));
    a.extend(halt());
    let p = a.assemble();
    let inputs = [7u32];
    let e = execute(&p, &inputs, 10_000).unwrap();
    assert_eq!(e.outputs[0], 0, "two honest reads of the same index must agree");
    let m = Machine::new(FriProfile::Test);
    let mut t = build_traces_salted(&p, &inputs, [0u32; 4], &e, Tier(10)).unwrap();
    let w = cpu::col::WIDTH;
    // Locate the second SYS_READ row (there are exactly two) and forge its returned word.
    let read_rows: Vec<usize> = (0..t.cpu.height()).filter(|&i| t.cpu.values[i * w + cpu::col::SYS_READ] == F::ONE).collect();
    assert_eq!(read_rows.len(), 2);
    t.cpu.values[read_rows[1] * w + cpu::col::C] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// (b) a read of a word not in the committed inputs (the input table's own row tampered)
// rejects — the SYS_READ row's honestly-returned C no longer matches what H_IN absorbed.
#[test]
fn a_read_disagreeing_with_the_committed_input_word_is_rejected() {
    let (m, p, mut t) = setup_with_inputs(&[400, 250, 300, 75]);
    let iw = shrugg_zkvm::tables::input::col::WIDTH;
    t.input.values[0 * iw + shrugg_zkvm::tables::input::col::WORD] += F::ONE; // tamper index 0's committed word
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// (c) H_IN in pv tampered rejects.
#[test]
fn tampering_h_in_in_public_values_is_rejected() {
    let (m, p, mut t) = setup_with_inputs(&[400, 250, 300, 75]);
    t.public_values[cpu::pv::IN0] += F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// (d) declaring n_in smaller than the reads rejects — I3 (review round 1): rewritten to
// exercise the property against the split-bus design. Shrinking only the *digest's* declared
// n_in (via `shrink_declared_n_in`, which recomputes everything the digest itself is
// responsible for, so no *other* check trips first) while leaving the `input` table exactly
// as built for the real 4-word vector leaves its now-unclaimed 4th real row's `IS_REAL = 1`
// supply on `INPUT_DIGEST` unmatched — the read of that same index still succeeds fine on
// `INPUT_READ`, which is untouched.
#[test]
fn declaring_n_in_smaller_than_the_reads_is_rejected() {
    let (m, p, mut t) = setup_with_inputs(&[400, 250, 300, 75]); // n_in = 4, exactly 1 real indigest row
    shrink_declared_n_in(&mut t, &p, TEST_SALT, &[400, 250, 300]);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// (f) the full C1 witness (n_in 4→3 with the 4th word still read via MULT_READ) is rejected —
// the reviewer's exact concrete cheating witness against the pre-split single-bus design: (1)
// shrink the digest's declared n_in (as in (d)), (2) additionally zero the orphaned input
// row's `MULT_READ` to try to "hide" its now-unclaimed mandatory-copy slot. Under the split
// design `MULT_READ` no longer feeds `INPUT_DIGEST` at all, so step (2) is powerless: the
// row's `IS_REAL = 1` supply on `INPUT_DIGEST` stays unclaimed regardless.
#[test]
fn the_c1_witness_shrinking_n_in_while_still_reading_the_dropped_word_is_rejected() {
    let (m, p, mut t) = setup_with_inputs(&[400, 250, 300, 75]);
    shrink_declared_n_in(&mut t, &p, TEST_SALT, &[400, 250, 300]);
    let iw = shrugg_zkvm::tables::input::col::WIDTH;
    t.input.values[3 * iw + shrugg_zkvm::tables::input::col::MULT_READ] = F::ZERO;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// (g) an extra real input row at IDX = n_in is rejected — the "dual form" of (f): appending a
// committed word past the digest's own declared n_in leaves an unclaimed `IS_REAL = 1` supply
// on `INPUT_DIGEST` regardless of whether anything else claims to read it. What this witness
// stands in for — a genuine `READ_INPUT(n_in)` — is exactly what the emulator refuses
// (checked directly below), which is why the witness has to be built by hand.
#[test]
fn an_extra_real_input_row_at_idx_equal_to_n_in_is_rejected() {
    assert!(matches!(
        execute(&guests::balance_check(1000), &[400u32, 250, 300], 10_000),
        Err(shrugg_zkvm::emulator::ExecError::InputIndex(3))
    ), "a READ_INPUT past the supplied inputs is exactly what the emulator refuses");
    let (m, p, mut t) = setup_with_inputs(&[400, 250, 300, 75]); // n_in = 4
    let iw = shrugg_zkvm::tables::input::col::WIDTH;
    assert!(t.input.height() > 4, "spare padding rows past the 4 real ones");
    t.input.values[4 * iw + shrugg_zkvm::tables::input::col::WORD] = F::from_u32(999);
    t.input.values[4 * iw + shrugg_zkvm::tables::input::col::IS_REAL] = F::ONE;
    // MULT_READ stays 0 — nothing needs to claim to read this row for INPUT_DIGEST alone
    // (an unclaimed IS_REAL = 1 supply the digest never demands) to reject it.
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// (h) I2 (review round 2, N1): the *faithful* regression — a genuinely appended, all-inactive
// indigest row after a block-aligned n_in (n_in = 4, so HASH_LEFT is already fully drained to
// 0 on the one real block), built so that *only* the lane-0 rule stands between it and
// acceptance: everything else the AIR demands (INDIGEST_LAST moved to the new row, the
// canonical H_IN encoding moved with it, the new row's own genuine POSEIDON2 permutation
// wired into the poseidon2 table and into the row after it, the whole rest of the cpu table's
// CLK chain shifted by one, MEMORY and RANGE8 kept exactly balanced) is made fully consistent
// by hand. Round 1's version repurposed the very next row in place, leaving INDIGEST_LAST = 1
// on the real row while the new row also claimed IS_INDIGEST = 1 — a shape the untouched
// chain rule at the real→new transition (`is_indigest * (INDIGEST_LAST - (1 - n(IS_INDIGEST)))
// = 0`) already rejects on its own, independent of the lane-0 rule, so it never actually
// exercised I2.
//
// Discrimination check, run by hand against this same witness: restoring the old,
// `HASH_LEFT`-gated rule (`is_indigest * HASH_LEFT * (1 - ACT0) = 0`) makes the witness
// VERIFY (it's vacuous here, since the appended row's `HASH_LEFT = 0`); the current rule
// (`is_real_indigest * (1 - ACT0) = 0`) rejects it, by that single constraint alone.
///
/// Builds the faithful witness described above from an honest `Traces`, mutating `t.cpu` (row
/// insertion + CLK shift), `t.memory` (rebuilt at the shifted `CLK` offset — every access after
/// the insertion point moves by one timestamp unit), `t.range` (RANGE8 is exact-count
/// accounting: every byte-column value this edit changes — the moved `IHVL0..31`/new row's
/// `LEFT0/LEFT0+1`/`IDX0/IDX0+1`, and whatever `memory_trace` itself demands at the two
/// offsets — is tracked and applied as a delta), `t.poseidon2` (append the new row's own
/// permutation event), and `t.public_values` (`pv::IN0..7` becomes the canonical encoding of
/// `perm(H_honest)`, the gratuitous extra permutation's actual output).
fn append_gratuitous_indigest_permutation(p: &shrugg_zkvm::isa::Program, inputs: &[u32], mut t: Traces) -> Traces {
    let e = execute(p, inputs, 10_000).unwrap();
    let w = cpu::col::WIDTH;
    let height = t.cpu.height();
    let real_row = p.digest_rows() + 1; // the one real indigest row (right after the salt row)
    let insert_at = real_row + 1; // == p.digest_rows() + input_digest_row_count(inputs.len())

    // The real row's own permutation output — already seeded (by `fill_input_digest_rows`)
    // into what is, before this edit, the first ordinary instruction row's HS0..7.
    let real_state_out: [F; 8] = core::array::from_fn(|k| t.cpu.values[insert_at * w + cpu::col::HS0 + k]);
    let new_state_out = shrugg_zkvm::hash::permute_state(real_state_out);

    let mut range_removed: Vec<u32> = Vec::new();
    let mut range_added: Vec<u32> = Vec::new();

    // The real row is no longer last: clear INDIGEST_LAST and its canonical encoding (moving
    // to the new row below). RANGE8's demand for the old IHVL bytes disappears with it.
    t.cpu.values[real_row * w + cpu::col::INDIGEST_LAST] = F::ZERO;
    for kk in 0..32 {
        let old_byte = t.cpu.values[real_row * w + cpu::col::IHVL0 + kk].as_canonical_u64() as u32;
        range_removed.push(old_byte);
        t.cpu.values[real_row * w + cpu::col::IHVL0 + kk] = F::ZERO;
    }
    for c in 0..4 {
        t.cpu.values[real_row * w + cpu::col::IHIMAX0 + c] = F::ZERO;
        t.cpu.values[real_row * w + cpu::col::IINV0 + c] = F::ZERO;
    }

    let real_hash_idx = t.cpu.values[real_row * w + cpu::col::HASH_IDX].as_canonical_u64() as u32;
    let base_pc = t.cpu.values[real_row * w + cpu::col::PC];
    let new_clk = t.cpu.values[real_row * w + cpu::col::CLK] + F::ONE;

    let mut new_row = vec![F::ZERO; w];
    new_row[cpu::col::IS_REAL] = F::ONE;
    new_row[cpu::col::IS_INDIGEST] = F::ONE;
    new_row[cpu::col::INDIGEST_LAST] = F::ONE;
    new_row[cpu::col::HASH_N] = F::from_u32(4);
    new_row[cpu::col::HASH_LEFT] = F::ZERO; // carried in — the real block already drained it
    new_row[cpu::col::HASH_IDX] = F::from_u32(real_hash_idx + 1);
    new_row[cpu::col::CLK] = new_clk;
    new_row[cpu::col::PC] = base_pc;
    new_row[cpu::col::NEXT_PC] = base_pc; // is_indigest holds PC still
    for k in 0..8 { new_row[cpu::col::HS0 + k] = real_state_out[k]; }
    for k in 0..4 { new_row[cpu::col::HV0 + k] = real_state_out[k]; } // ACT = 0: inactive-lane carry
    let (l0, l1) = (0u32, 0u32); // byte limbs of HASH_LEFT = 0
    new_row[cpu::col::LEFT0] = F::from_u32(l0);
    new_row[cpu::col::LEFT0 + 1] = F::from_u32(l1);
    range_added.push(l0);
    range_added.push(l1);
    let new_idx = real_hash_idx + 1;
    let (i0, i1) = (new_idx & 0xff, (new_idx >> 8) & 0xff);
    new_row[cpu::col::IDX0] = F::from_u32(i0);
    new_row[cpu::col::IDX0 + 1] = F::from_u32(i1);
    range_added.push(i0);
    range_added.push(i1);

    // The gratuitous extra permutation's own canonical H_IN encoding, moved here.
    let words = shrugg_zkvm::hash::split_digest([new_state_out[0], new_state_out[1], new_state_out[2], new_state_out[3]]);
    for kk in 0..8 {
        let bl = limbs(words[kk]);
        for j in 0..4 {
            range_added.push(bl[j].as_canonical_u64() as u32);
            new_row[cpu::col::IHVL0 + 4 * kk + j] = bl[j];
        }
    }
    for j in 0..4usize {
        let hi = words[2 * j + 1];
        if hi == u32::MAX {
            new_row[cpu::col::IHIMAX0 + j] = F::ONE;
        } else {
            new_row[cpu::col::IINV0 + j] = (F::from_u32(hi) - F::from_u32(u32::MAX)).inverse();
        }
    }

    // Splice the new row in right after the real one, shifting every later row down by one
    // (CLK bumped for every IS_REAL row, since one more genuine cycle now precedes them) —
    // drop the table's very last (all-zero-plus-WRITTEN-accumulator padding) row to keep the
    // height fixed; there are hundreds of identical padding rows to spare.
    let mut values = Vec::with_capacity(height * w);
    values.extend_from_slice(&t.cpu.values[..insert_at * w]);
    values.extend_from_slice(&new_row);
    for row in insert_at..height - 1 {
        let mut r: Vec<F> = t.cpu.values[row * w..(row + 1) * w].to_vec();
        if row == insert_at {
            // The (now-shifted) first ordinary row is where the extra permutation's own
            // output belongs: POSEIDON2's n(HS0..7) must equal permute(new_row's state_in).
            for k in 0..8 { r[cpu::col::HS0 + k] = new_state_out[k]; }
        }
        if r[cpu::col::IS_REAL] == F::ONE { r[cpu::col::CLK] += F::ONE; }
        values.extend_from_slice(&r);
    }
    assert_eq!(values.len(), height * w);
    t.cpu = p3_matrix::dense::RowMajorMatrix::new(values, w);

    // MEMORY: every shifted row's CLK (hence every SLOT timestamp, `ts = CLK*4 + slot`) moved
    // by one — rebuild the whole table at the new offset (`insert_at + 1`, matching the shift
    // above exactly) rather than hand-patching timestamps.
    let mem_height = t.memory.height();
    let mut old_mem_range = range::RangeCounts::default();
    let _ = memory::memory_trace(&e.events, insert_at as u32, mem_height, &mut old_mem_range);
    let mut new_mem_range = range::RangeCounts::default();
    t.memory = memory::memory_trace(&e.events, (insert_at + 1) as u32, mem_height, &mut new_mem_range);

    // RANGE8 is exact-count accounting: apply the cpu-side byte-demand deltas collected above,
    // plus whatever delta the memory rebuild itself introduced (a pure CLK-offset shift should
    // leave every same-address delta unchanged, but this is computed, not assumed).
    let rw = range::col::WIDTH;
    for b in range_removed { t.range.values[b as usize * rw + range::col::M_RANGE] -= F::ONE; }
    for b in range_added { t.range.values[b as usize * rw + range::col::M_RANGE] += F::ONE; }
    for v in 0..256usize {
        let old_c = old_mem_range.range.get(v).copied().unwrap_or(0);
        let new_c = new_mem_range.range.get(v).copied().unwrap_or(0);
        if new_c > old_c { t.range.values[v * rw + range::col::M_RANGE] += F::from_u32((new_c - old_c) as u32); }
        if old_c > new_c { t.range.values[v * rw + range::col::M_RANGE] -= F::from_u32((old_c - new_c) as u32); }
    }

    // POSEIDON2: append the new row's own genuine permutation event.
    let digest_blocks = shrugg_zkvm::hash::program_digest_rows(p.base_pc, &p.words);
    let indigest_blocks = shrugg_zkvm::hash::input_digest_rows(TEST_SALT, inputs);
    let extra_block = shrugg_zkvm::hash::DigestBlock {
        idx: new_idx,
        left_before: 0,
        words: [0; 4],
        active: [false; 4],
        state_in: real_state_out,
        state_out: new_state_out,
    };
    let to_events = |blocks: &[shrugg_zkvm::hash::DigestBlock]| -> Vec<poseidon2::Poseidon2Event> {
        blocks.iter().map(|blk| {
            let mut input = blk.state_in;
            for k in 0..4 { if blk.active[k] { input[k] = F::from_u32(blk.words[k]); } }
            poseidon2::Poseidon2Event { input, output: blk.state_out }
        }).collect()
    };
    let all: Vec<poseidon2::Poseidon2Event> = to_events(&digest_blocks)
        .into_iter()
        .chain(to_events(&indigest_blocks))
        .chain(to_events(std::slice::from_ref(&extra_block)))
        .collect();
    t.poseidon2 = poseidon2::poseidon2_trace(&all, t.poseidon2.height());

    // pv::IN0..7 = the canonical encoding of perm(H_honest) — the gratuitous extra
    // permutation's actual output, exactly what an otherwise-honest prover computing H_IN off
    // this witness would publish.
    for k in 0..8 { t.public_values[cpu::pv::IN0 + k] = F::from_u32(words[k]); }

    t
}

#[test]
fn an_appended_all_inactive_indigest_row_after_a_block_aligned_n_in_is_rejected() {
    let inputs = [400u32, 250, 300, 75]; // n_in = 4, one full real block
    let (m, p, t) = setup_with_inputs(&inputs);
    let t = append_gratuitous_indigest_permutation(&p, &inputs, t);
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}

// (e) out-of-window MULT_READ = 1 on a padding row rejects.
#[test]
fn a_mult_read_bumped_on_an_input_padding_row_is_rejected() {
    let (m, p, mut t) = setup_with_inputs(&[400, 250, 300, 75]);
    let iw = shrugg_zkvm::tables::input::col::WIDTH;
    assert!(t.input.height() > 4, "the input table has spare padding rows past the 4 real ones");
    t.input.values[4 * iw + shrugg_zkvm::tables::input::col::MULT_READ] = F::ONE;
    assert!(rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) }));
}
