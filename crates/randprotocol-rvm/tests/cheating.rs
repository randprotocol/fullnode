//! The soundness suite (plan Tasks 6, 8, 10): every test builds a wrong witness and checks the
//! machine rejects it, through `rejects()` and nothing else — a per-instance constraint-checker
//! panic (`CONSTRAINT_PANIC`), a global lookup-balance panic (`LOOKUP_BALANCE_PANIC`), or a
//! verify error counts; anything else means the test tripped on something it did not mean to.
mod common;

use common::rejects;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use randprotocol_rvm::emulator::execute;
use randprotocol_rvm::isa::{F, Instr, Op, Program};
use randprotocol_rvm::machine::{build_traces, FriProfile, Machine, Tier, Traces};
use randprotocol_rvm::tables::{cpu, memory, poseidon2, program as program_table, public as public_table};

fn i(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}
fn ir(op: Op, rd: u8, ra: u8, rb: u8) -> Instr {
    i(op, rd, ra, rb as u64)
}

/// The honest setup: one program touching every table — base and extension arithmetic, an `INV`,
/// a store/load round trip, a permutation, and the four published words R5 requires.
fn setup() -> (Machine, Program, Traces) {
    let p = Program {
        instrs: vec![
            i(Op::Faddi, 1, 0, 7),          // 0
            i(Op::Faddi, 2, 0, 5),          // 1
            ir(Op::Fadd, 3, 1, 2),          // 2: r3 = 12
            i(Op::Inv, 4, 3, 0),            // 3: r4 = 12^-1
            i(Op::Faddi, 5, 0, 100),        // 4
            i(Op::Store, 2, 5, 3),          // 5: mem[103] = 5
            i(Op::Load, 6, 5, 3),           // 6: r6 = 5
            i(Op::Faddi, 7, 0, 64),         // 7: ptr
            i(Op::Store, 1, 7, 0),          // 8: mem[64] = 7
            i(Op::Store, 2, 7, 1),          // 9: mem[65] = 5
            i(Op::Poseidon2, 0, 7, 0),      // 10: permute cells 64..71
            i(Op::Load, 8, 7, 0),           // 11
            i(Op::Public, 0, 3, 0),         // 12
            i(Op::Public, 0, 6, 0),         // 13
            i(Op::Public, 0, 8, 0),         // 14
            i(Op::Public, 0, 4, 0),         // 15
            i(Op::Halt, 0, 0, 0),           // 16
        ],
        checkpoints: vec![],
    };
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

fn prove_and_verify(m: &Machine, p: &Program, t: &Traces) -> Result<(), randprotocol_rvm::machine::VerifyError> {
    let proof = m.prove_traces(p, t, Tier(8));
    m.verify(p, &proof)
}

#[test]
fn honest_traces_pass() {
    let (m, p, t) = setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

#[test]
fn a_wrong_arithmetic_result_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Row 2 is the FADD: claim the sum is 13, not 12.
    t.cpu.values[2 * w + cpu::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_skipped_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Mark the LOAD row as padding: the pc chain and the CLK chain break.
    t.cpu.values[6 * w + cpu::col::IS_REAL] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_bad_inv_hint_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Row 3 is the INV: any value but the true inverse fails `ra·rd = 1`.
    t.cpu.values[3 * w + cpu::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn an_address_above_two_to_the_twentyfour_with_forged_limbs_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // The LOAD row's limb columns are what pins its address below 2^24; shifting one limb is a
    // forged range proof. (The honest machine refuses the address outright at the emulator —
    // `tests/cpu.rs` — this is the row-level range check that makes the AIR agree.)
    t.cpu.values[6 * w + cpu::col::LIMB0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_register_write_to_r0_surfacing_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Rewrite the FADD to target r0, and claim the write is not dropped (RD_IS_ZERO = 0 while
    // RD = 0): the is-zero gadget itself fails first.
    t.cpu.values[2 * w + cpu::col::RD] = F::ZERO;
    t.cpu.values[2 * w + cpu::col::RD_IS_ZERO] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_fetch_count_short_by_one_is_rejected() {
    let (m, p, mut t) = setup();
    let w = program_table::col::WIDTH;
    // The FADD lives at program row 2; drop its fetch count and the cpu's fetch is unclaimed.
    let mult = t.program.values[2 * w + program_table::col::MULT];
    assert_eq!(mult, F::ONE);
    t.program.values[2 * w + program_table::col::MULT] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_skipped_permutation_is_rejected() {
    let (m, p, mut t) = setup();
    let w = poseidon2::col::WIDTH;
    // The one real permutation row vanishes (its bus claims go with it): the cpu's dispatch has
    // no provider — and the memory table's reads and writes have no sender either.
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_REAL] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_REAL] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::MULT] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::IS_PERM] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn an_extra_permutation_is_rejected() {
    let (m, p, mut t) = setup();
    let w = poseidon2::col::WIDTH;
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_REAL] == F::ONE).unwrap();
    // Clone the real row into the padding row after it: a permutation nothing dispatched.
    for c in 0..w {
        t.poseidon2.values[(row + 1) * w + c] = t.poseidon2.values[row * w + c];
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_tampered_memory_value_is_rejected() {
    let (m, p, mut t) = setup();
    let w = memory::col::WIDTH;
    // The "wrong Merkle sibling" shape: the value the RAM table claims a read returned is not
    // the value last written — read-after-write is the transition constraint that catches it.
    let row = (0..t.ram.height()).find(|r| {
        t.ram.values[r * w + memory::col::IS_REAL] == F::ONE
            && t.ram.values[r * w + memory::col::IS_WRITE] == F::ZERO
    }).unwrap();
    t.ram.values[row * w + memory::col::VALUE] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_forged_public_value_is_rejected() {
    let (m, p, t) = setup();
    // (a) The batch public values, tampered after the fact: the transcript binds them.
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.public_values[0] += 1;
    assert!(rejects(|| m.verify(&p, &proof)));
    // (b) The public table's own VALUE column: the selector tie `VALUE = pv[i]` fails on the row.
    let (_, _, mut t2) = setup();
    let w = public_table::col::WIDTH;
    t2.public.values[w + public_table::col::VALUE] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t2)));
}

#[test]
fn a_proof_of_one_program_does_not_verify_against_another() {
    let (m, p, t) = setup();
    let proof = m.prove_traces(&p, &t, Tier(8));
    let mut other = p.clone();
    other.instrs[2] = ir(Op::Fsub, 3, 1, 2);
    // R1: the preprocessed cap binds the program — a different program is a different key.
    assert!(rejects(|| m.verify(&other, &proof)));
}

#[test]
fn a_proof_at_the_wrong_tier_is_rejected() {
    let (m, p, t) = setup();
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.tier = Tier(10);
    assert!(rejects(|| m.verify(&p, &proof)));
}

#[test]
fn an_out_of_range_tier_is_an_error_not_a_panic() {
    let (m, p, t) = setup();
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.tier = Tier(99);
    assert!(matches!(m.verify(&p, &proof), Err(randprotocol_rvm::machine::VerifyError::Tier)));
}

// ── Task 8: the reduce chip's tranche ─────────────────────────────────────────────────────────
use p3_field::BasedVectorSpace;
use randprotocol_rvm::isa::EF;
use randprotocol_rvm::tables::reduce as reduce_table;

/// An honest setup with one four-column `REDUCE` run, for the tranche.
fn reduce_setup() -> (Machine, Program, Traces, Vec<F>) {
    use randprotocol_rvm::dsl::{Builder, Checkpoints};
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(31);
    let vals: Vec<EF> = (0..4).map(|_| common::random_ext(&mut rng)).collect();
    let row: Vec<F> = (0..4).map(|_| common::random_felt(&mut rng)).collect();
    let inv = common::random_ext(&mut rng);
    let alpha = common::random_ext(&mut rng);
    let mut b = Builder::new(Checkpoints::Off);
    let mut tape: Vec<F> = vec![];
    let vals_a = b.hint_ext_array(4);
    for v in &vals {
        tape.extend_from_slice(v.as_basis_coefficients_slice());
    }
    let row_a = b.hint_array(4);
    tape.extend_from_slice(&row);
    let inv_h = b.ext_constant(inv);
    let zero = b.ext_constant(EF::ZERO);
    let one = b.ext_constant(EF::ONE);
    let alpha_h = b.ext_constant(alpha);
    let (ro, _ap) = b.reduce(vals_a, row_a, inv_h, zero, one, alpha_h);
    b.public_ext(ro);
    b.public_ext(ro);
    let p = b.finish();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &tape, 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t, tape)
}

fn reduce_verify(m: &Machine, p: &Program, t: &Traces) -> Result<(), randprotocol_rvm::machine::VerifyError> {
    let proof = m.prove_traces(p, t, Tier(8));
    m.verify(p, &proof)
}

#[test]
fn honest_reduce_traces_pass() {
    let (m, p, t, _) = reduce_setup();
    assert!(t.reduce.is_some(), "the setup's batch carries the reduce table");
    reduce_verify(&m, &p, &t).unwrap();
}

#[test]
fn a_wrong_accumulated_value_in_the_reduction_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    // The second row's accumulator, shifted by one: the chain to the next row fails.
    r.values[w + reduce_table::col::ACC0] += F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

#[test]
fn a_dropped_column_in_the_reduction_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    // Claim the run ends a column early: IS_LAST on the LEN=2 row — the is-one gadget refuses it.
    let len2 = (0..r.height()).find(|i| r.values[i * w + reduce_table::col::LEN] == F::TWO).unwrap();
    r.values[len2 * w + reduce_table::col::IS_LAST] = F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

#[test]
fn a_forged_descriptor_field_in_the_reduction_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    // The descriptor's `inv`, forged on the chip's first row: the RAM message's value no longer
    // matches the read the memory table holds.
    r.values[reduce_table::col::INV0] += F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

#[test]
fn a_reduce_dispatch_with_no_chip_run_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    // The whole run vanishes: the cpu's dispatch has no provider (and the run's reads and
    // write-backs have no sender either).
    for i in 0..r.height() {
        r.values[i * w + reduce_table::col::IS_REAL] = F::ZERO;
        r.values[i * w + reduce_table::col::IS_FIRST] = F::ZERO;
        r.values[i * w + reduce_table::col::IS_LAST] = F::ZERO;
    }
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

#[test]
fn a_reduce_proof_declaring_no_table_is_rejected() {
    let (m, p, t, _) = reduce_setup();
    // The keccak pattern's verify-side rule: a proof carrying a reduce instance cannot declare
    // `reduce_log_height = 0` — the degree-bits vector's length mismatches the batch's.
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.reduce_log_height = 0;
    assert!(matches!(
        m.verify(&p, &proof),
        Err(randprotocol_rvm::machine::VerifyError::Tier)
    ));
}

// ── Task 9: the poseidon2 chip's SPONGE row kind tranche ──────────────────────────────────────

/// An honest setup with one `SPONGE` absorb over a four-word message.
fn sponge_setup() -> (Machine, Program, Traces) {
    use randprotocol_rvm::dsl::{Builder, Checkpoints, Digest, Liveness};
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(41);
    let mut b = Builder::with_liveness(Checkpoints::Off, Liveness::On);
    let mut tape: Vec<F> = vec![];
    let src = b.alloc(4);
    for k in 0..4i64 {
        let w = common::random_felt(&mut rng);
        let v = b.hint();
        tape.push(w);
        b.store(src, k, v);
    }
    // Hint the words into the cells, then one absorb block: `sponge` emits one `SPONGE` here.
    let out = Digest(b.alloc(4));
    randprotocol_rvm::dsl::hash::sponge(&mut b, src, 4, out);
    for k in 0..4 {
        let v = b.load(out.0, k);
        b.public(v);
    }
    let p = b.finish();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &tape, 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

#[test]
fn an_absorb_row_with_a_wrong_source_cell_is_rejected() {
    let (m, p, mut t) = sponge_setup();
    let w = memory::col::WIDTH;
    // The RAM trace's read of the absorb's first source cell, shifted by one: read-after-write
    // is the transition constraint that refuses it (the "wrong Merkle sibling" shape again).
    let row = (0..t.ram.height()).find(|r| {
        t.ram.values[r * w + memory::col::IS_REAL] == F::ONE
            && t.ram.values[r * w + memory::col::IS_WRITE] == F::ZERO
    }).unwrap();
    t.ram.values[row * w + memory::col::VALUE] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_skipped_absorb_is_rejected() {
    let (m, p, mut t) = sponge_setup();
    let w = poseidon2::col::WIDTH;
    // The absorb row vanishes (its SPONGE-bus claims go with it): the cpu's dispatch has no
    // provider — `LOOKUP_BALANCE_PANIC` on `SPONGE`.
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_SPONGE] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_SPONGE] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::IS_REAL] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::MULT] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_sponge_row_claiming_the_plain_poseidon2_kind_is_rejected() {
    let (m, p, mut t) = sponge_setup();
    let w = poseidon2::col::WIDTH;
    // The absorb row claims to be a plain in-place permutation instead: the SPONGE bus loses
    // its entry and POSEIDON2 gains one nobody dispatched.
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_SPONGE] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_SPONGE] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::IS_PERM] = F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

// ── Task 10: the full-suite pass — the remaining per-table tamper vectors ─────────────────────

#[test]
fn a_padding_row_with_a_selector_set_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // AGENTS.md invariant 2: on a padding row every send count is a selector expression, so one
    // hot selector is one sum over `IS_REAL = 0` — the count constraint itself refuses it before
    // any bus comes into it.
    let pad = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_REAL] == F::ZERO).unwrap();
    t.cpu.values[pad * w + cpu::col::SEL0 + Op::Fadd as usize] = F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_forged_memory_delta_limb_is_rejected() {
    let (m, p, mut t) = setup();
    let w = memory::col::WIDTH;
    // The `(addr, ts)` sort's delta, forged by one limb: the delta-equality constraint fails on
    // the row (and a forged limb is exactly what the RANGE8 lookup exists to refuse).
    let row = (0..t.ram.height()).find(|r| t.ram.values[r * w + memory::col::IS_REAL] == F::ONE).unwrap();
    t.ram.values[row * w + memory::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_published_value_out_of_order_is_rejected() {
    let (m, p, mut t) = setup();
    let w = public_table::col::WIDTH;
    // Rows 1 and 2 of the public table swapped: `SEL_i·(IDX − i) = 0` and `VALUE = pv[i]` cannot
    // both hold on the swapped rows.
    t.public.values.swap(1 * w + public_table::col::VALUE, 2 * w + public_table::col::VALUE);
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}
