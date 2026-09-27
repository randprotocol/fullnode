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

// ── RVM-1: the STOREE high lane (the 2026-09-27 recursion-VM report) ──────────────────────────
//
// An extension value is the pair `(c0, c1)` in registers `(rd, rd + 1)` or cells `(a, a + 1)`.
// Before RVM-1's fix a STOREE row sent `RAM.write(a + 1, D1)` but no `REG` message read `rd + 1`,
// so `D1` — the stored high lane — was a free witness column: the emulator filled it honestly,
// the trace builder mirrored the gap, and nothing in the constraint system disagreed with a
// prover who put anything else there. LOADE then read the forged lane back as if it had been
// computed. The vectors below forge that lane (a) in a hand-written program, (b) in a value the
// DSL's register allocator spilled on its own (RVM-1a: every spill is a STOREE/LOADE pair, so
// every spilled extension value was forgeable), and (c) for symmetry on the LOADE side, which
// was always bound. Each is refused three ways, so the tests show the *constraints* refusing it
// and not only the host: through the honest `build_traces` (whose read-after-write assertion may
// refuse first — a host check, not a proof-system one), and through two hand-built trace sets
// that skip every host assertion — the register table an unfixed trace builder would produce
// (no read of `rd + 1`: after the fix the cpu's new `REG` message has no receiver, a bus
// imbalance), and the fixed builder's register table with its forged read kept (the memory
// table's read-after-write constraint refuses it).
use randprotocol_rvm::emulator::{Execution, MemAccess};
use randprotocol_rvm::tables::{pad_height, range};

/// The forged lane: `0xC0FFEE`, the report's value.
const FORGED: u64 = 0xC0FFEE;

/// `TS_RD1_READ`: the slot of the cpu's new `REG` read of `rd + 1` on a STOREE row. The unfixed
/// builder's register table is the fixed one's minus every access at this slot on a STOREE row
/// (before the fix there are none, so the filter is the identity and both tables are the
/// honest builder's).
const TS_RD1_READ: u32 = 5;

/// The report's program (§5.1): store `(11, 22)`, load it back, publish the loaded high lane
/// first and the register it came from last — so a forgery shows up as a published word that
/// disagrees with the register file inside one proof's own public values.
fn storee_program() -> Program {
    Program {
        instrs: vec![
            i(Op::Faddi, 2, 0, 11),   // 0: r2 = 11
            i(Op::Faddi, 3, 0, 22),   // 1: r3 = 22
            i(Op::Faddi, 6, 0, 1000), // 2: r6 = 1000
            i(Op::Storee, 2, 6, 0),   // 3: mem[1000..1002] = (r2, r3)
            i(Op::Loade, 4, 6, 0),    // 4: (r4, r5) = mem[1000..1002]
            i(Op::Public, 0, 5, 0),   // 5: publish r5 (honestly 22)
            i(Op::Public, 0, 4, 0),   // 6: publish r4 = 11
            i(Op::Public, 0, 2, 0),   // 7: publish r2 = 11
            i(Op::Public, 0, 3, 0),   // 8: publish r3 = 22, straight from the register file
            i(Op::Halt, 0, 0, 0),     // 9
        ],
        checkpoints: vec![],
    }
}

/// Rewrite, in an honest run, exactly what the loaded high lane being `value` implies: the
/// LOADE row's `d[1]` and its read of `a + 1`, then the one PUBLIC that reads `rd + 1` (its
/// operand and the published word). With `storee = Some(s)`, the STOREE row's `d[1]` and its
/// write of `a + 1` too — the RVM-1 forgery; with `None`, the stored lane stays honest and only
/// the load lies — vector (c). Everything the forged register reaches is checked to be that one
/// PUBLIC (and HALT), so the rewritten run is internally consistent everywhere the constraints
/// could look except where the finding says they do not.
fn forge_high_lane(exec: &mut Execution, storee: Option<usize>, loade: usize, value: F) {
    let l = &exec.events[loade];
    assert_eq!(l.instr.op, Op::Loade, "event {loade} is the LOADE");
    let cell = l.mem[1].addr;
    let reg = l.instr.rd + 1;
    if let Some(s) = storee {
        let e = &mut exec.events[s];
        assert_eq!(e.instr.op, Op::Storee, "event {s} is the STOREE");
        assert!(e.mem[1].is_write && e.mem[1].addr == cell, "the STOREE writes the cell the LOADE reads");
        e.d[1] = value;
        e.mem[1].value = value;
        // Nothing between the store and the load touches the cell: the forged write is the
        // last write the load's read sees.
        for (k, e) in exec.events[s + 1..loade].iter().enumerate() {
            assert!(e.mem.iter().all(|m| m.addr != cell), "event {} touches the forged cell", s + 1 + k);
        }
    }
    let l = &mut exec.events[loade];
    assert!(!l.mem[1].is_write);
    l.d[1] = value;
    l.mem[1].value = value;
    let mut published = exec.events[..loade].iter().filter(|e| e.instr.op == Op::Public).count();
    let mut reached = 0;
    for e in exec.events[loade + 1..].iter_mut() {
        match e.instr.op {
            Op::Public => {
                if e.instr.ra == reg {
                    e.a[0] = value;
                    exec.public[published] = value;
                    reached += 1;
                }
                published += 1;
            }
            Op::Halt => {}
            other => panic!("the forged register must reach only PUBLIC rows, found {other:?}"),
        }
    }
    assert_eq!(reached, 1, "exactly one PUBLIC publishes the forged lane");
}

/// `memory::memory_trace` minus its host assertions (strictly increasing keys, read-after-write,
/// fresh reads zero): the same columns computed the same way, so a forged access list turns into
/// a trace the *constraints* have to refuse. On an honest list it is `memory_trace` exactly
/// (`the_unchecked_memory_trace_is_memory_trace_on_honest_input` below pins that).
fn memory_trace_unchecked(accesses: &[MemAccess], height: usize, counts: &mut range::RangeCounts) -> p3_matrix::dense::RowMajorMatrix<F> {
    use memory::col::*;
    let mut rows: Vec<&MemAccess> = accesses.iter().collect();
    rows.sort_by_key(|a| (a.addr, a.ts));
    assert!(rows.len() < height);
    let mut v = F::zero_vec(height * WIDTH);
    for (k, r) in rows.iter().enumerate() {
        let base = k * WIDTH;
        v[base + ADDR] = F::from_u64(r.addr);
        v[base + TS] = F::from_u64(r.ts as u64);
        v[base + VALUE] = r.value;
        v[base + IS_WRITE] = F::from_bool(r.is_write);
        v[base + IS_REAL] = F::ONE;
        if let Some(nx) = rows.get(k + 1) {
            let changed = nx.addr != r.addr;
            let delta: u64 = if changed { nx.addr - r.addr - 1 } else { (nx.ts as u64).wrapping_sub(r.ts as u64 + 1) };
            v[base + ADDR_CHANGED] = F::from_bool(changed);
            v[base + DIFF_INV] = if changed { F::from_u64(nx.addr - r.addr).inverse() } else { F::ZERO };
            for (j, c) in [D0, D1, D2, D3].iter().enumerate() {
                let limb = (delta >> (8 * j)) as u32 & 0xff;
                v[base + c] = F::from_u32(limb);
                counts.range8(limb);
            }
        }
    }
    p3_matrix::dense::RowMajorMatrix::new(v, WIDTH)
}

/// Every table, built from the run's events the way `build_traces` builds them, except that the
/// register and RAM access lists are given explicitly and both memory tables go through
/// [`memory_trace_unchecked`] — the "honest trace builder bypassed" path. No REDUCE rows (the
/// programs here have none).
fn traces_bypassing_host_checks(p: &Program, exec: &Execution, tier: Tier, reg_acc: &[MemAccess], ram_acc: &[MemAccess]) -> Traces {
    use randprotocol_rvm::machine::{program_log_height, MIN_LOG_HEIGHT};
    assert!(exec.events.iter().all(|e| e.reduce.is_none()));
    let mut counts = range::RangeCounts::default();
    let cpu_t = cpu::cpu_trace(&exec.events, tier.cpu_height(), &mut counts);
    let reg_lh = pad_height(reg_acc.len() + 1, 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8;
    let reg = memory_trace_unchecked(reg_acc, 1 << reg_lh, &mut counts);
    let ram_lh = pad_height(ram_acc.len() + 1, 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8;
    let ram = memory_trace_unchecked(ram_acc, 1 << ram_lh, &mut counts);
    let perms = cpu::perm_events(&exec.events);
    let p2 = poseidon2::poseidon2_log_height(perms.len());
    Traces {
        program: program_table::program_trace(p, &exec.events, 1 << program_log_height(p.instrs.len())),
        cpu: cpu_t,
        reg,
        ram,
        poseidon2: poseidon2::poseidon2_trace(&perms, 1 << p2),
        public: public_table::public_trace(&exec.public, public_table::HEIGHT),
        range: range::range_trace(&counts),
        reduce: None,
        public_values: exec.public.clone(),
        reg_log_height: reg_lh,
        ram_log_height: ram_lh,
        poseidon2_log_height: p2,
        reduce_log_height: 0,
    }
}

fn prove_and_verify_at(m: &Machine, p: &Program, t: &Traces, tier: Tier) -> Result<(), randprotocol_rvm::machine::VerifyError> {
    let proof = m.prove_traces(p, t, tier);
    m.verify(p, &proof)
}

/// The three ways a forged run can reach the prover, each of which must be refused. `what` names
/// the forgery in the failure message, which is the red a missing constraint produces.
fn assert_forged_run_is_refused(m: &Machine, p: &Program, forged: &Execution, tier: Tier, what: &str) {
    let published: Vec<u64> = forged.public.iter().map(|x| x.as_canonical_u64()).collect();
    // (1) The honest trace builder on the forged run. Its read-after-write `assert!` refusing
    // the run is a *host* refusal — worth having, but a prover need not run it — so it is
    // accepted here and the constraint-level refusal is shown by (2) and (3).
    let honest_path = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let t = build_traces(p, forged, tier).unwrap();
        prove_and_verify_at(m, p, &t, tier)
    }));
    match honest_path {
        Ok(Ok(())) => panic!("{what}: the forged run VERIFIED through the honest trace builder, publishing {published:?}"),
        Ok(Err(_)) => {}
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            assert!(
                msg.contains("read does not match last write") || msg.contains(common::CONSTRAINT_PANIC) || msg.contains(common::LOOKUP_BALANCE_PANIC),
                "{what}: the honest path failed for an unrelated reason: {msg}"
            );
        }
    }
    let ram = cpu::ram_accesses(&forged.events);
    let reg_fixed = cpu::register_accesses(&forged.events);
    // (2) The register table an unfixed trace builder produces: no read of `rd + 1` on a STOREE
    // row. After the fix the cpu row still sends that read, and nothing receives it.
    let reg_unfixed: Vec<MemAccess> = reg_fixed
        .iter()
        .copied()
        .filter(|a| !(a.ts % 16 == TS_RD1_READ && forged.events[(a.ts / 16) as usize].instr.op == Op::Storee))
        .collect();
    let t = traces_bypassing_host_checks(p, forged, tier, &reg_unfixed, &ram);
    assert!(
        rejects(|| prove_and_verify_at(m, p, &t, tier)),
        "{what}: the forged run VERIFIED with the unfixed builder's register table, publishing {published:?}"
    );
    // (3) The fixed builder's register table with the forged read of `rd + 1` in it, host checks
    // skipped: the memory table's read-after-write constraint has to refuse it.
    let t = traces_bypassing_host_checks(p, forged, tier, &reg_fixed, &ram);
    assert!(
        rejects(|| prove_and_verify_at(m, p, &t, tier)),
        "{what}: the forged run VERIFIED with the register table carrying its forged read, publishing {published:?}"
    );
}

#[test]
fn the_unchecked_memory_trace_is_memory_trace_on_honest_input() {
    let p = storee_program();
    let exec = execute(&p, &[], 1000).unwrap();
    for acc in [cpu::register_accesses(&exec.events), cpu::ram_accesses(&exec.events)] {
        let h = pad_height(acc.len() + 1, 16);
        let (mut c1, mut c2) = (range::RangeCounts::default(), range::RangeCounts::default());
        assert_eq!(memory::memory_trace(&acc, h, &mut c1).values, memory_trace_unchecked(&acc, h, &mut c2).values);
        assert_eq!(c1.range, c2.range);
    }
    // And the bypass path proves an honest run: what (2)/(3) refuse is the forgery, not the path.
    let m = Machine::new(FriProfile::Test);
    let t = traces_bypassing_host_checks(&p, &exec, Tier(8), &cpu::register_accesses(&exec.events), &cpu::ram_accesses(&exec.events));
    prove_and_verify_at(&m, &p, &t, Tier(8)).unwrap();
}

/// (a) RVM-1 itself: the report's ten-instruction program with the stored high lane forged to
/// `0xC0FFEE` while `r3` still holds 22.
#[test]
fn a_forged_storee_high_lane_is_rejected() {
    let p = storee_program();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 1000).unwrap();
    assert_eq!(exec.public, [22u64, 11, 11, 22].map(F::from_u64).to_vec(), "the honest run");
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    prove_and_verify(&m, &p, &t).unwrap();

    let mut forged = exec.clone();
    forge_high_lane(&mut forged, Some(3), 4, F::from_u64(FORGED));
    assert_eq!(forged.public, [FORGED, 11, 11, 22].map(F::from_u64).to_vec(), "the forged run");
    assert_forged_run_is_refused(&m, &p, &forged, Tier(8), "RVM-1 (a), a forged STOREE high lane");
}

/// (b) RVM-1a: the same forgery on a value the DSL's allocator spilled by itself. Fourteen
/// extension values are live at once against the allocator's twelve register pairs, so the
/// replay spills; `x`, defined first and used last, is reloaded (LOADE into scratch) only to be
/// published. The test finds its spill — a STOREE with `ra = r0`, the allocator's absolute form —
/// and forges the spilled high lane.
#[test]
fn a_forged_spilled_extension_value_is_rejected() {
    use randprotocol_rvm::dsl::{Builder, Checkpoints};
    let ef = |a: u64, b: u64| EF::from_basis_coefficients_slice(&[F::from_u64(a), F::from_u64(b)]).unwrap();
    let mut b = Builder::new(Checkpoints::Off);
    let x = b.ext_constant(ef(11, 22));
    let others: Vec<_> = (0..13u64).map(|k| b.ext_constant(ef(100 + k, 200 + k))).collect();
    let mut acc = others[0];
    for o in &others[1..] {
        acc = b.ext_add(acc, *o);
    }
    b.public_ext(acc);
    b.public_ext(x);
    let p = b.finish();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let tier = Tier::for_cycles(exec.cpu_rows()).unwrap();
    let t = build_traces(&p, &exec, tier).unwrap();
    prove_and_verify_at(&m, &p, &t, tier).unwrap();
    assert_eq!(exec.public[2..], [F::from_u64(11), F::from_u64(22)], "x is published last");

    // `x`'s reload is the last LOADE; its spill is the STOREE (r0-relative) that wrote the cell.
    let loade = exec.events.iter().rposition(|e| e.instr.op == Op::Loade).expect("x was spilled and reloaded");
    let cell = exec.events[loade].mem[0].addr;
    let storee = exec.events[..loade]
        .iter()
        .rposition(|e| e.instr.op == Op::Storee && e.mem[0].addr == cell)
        .expect("the spill that wrote x's cell");
    assert_eq!(exec.events[storee].instr.ra, 0, "a spill: the allocator's absolute-address STOREE");
    assert_eq!(exec.events[storee].d, [F::from_u64(11), F::from_u64(22)], "the spilled value is x");

    let mut forged = exec.clone();
    forge_high_lane(&mut forged, Some(storee), loade, F::from_u64(FORGED));
    assert_eq!(forged.public[3], F::from_u64(FORGED));
    assert_forged_run_is_refused(&m, &p, &forged, tier, "RVM-1a (b), a forged spilled extension value");
}

/// (c) Symmetry: a forged LOADE high lane with the stored lane honest. LOADE writes both lanes to
/// registers from its two RAM reads, so this was bound before RVM-1's fix and must stay so.
#[test]
fn a_forged_loade_high_lane_is_rejected() {
    let p = storee_program();
    let m = Machine::new(FriProfile::Test);
    let mut forged = execute(&p, &[], 1000).unwrap();
    forge_high_lane(&mut forged, None, 4, F::from_u64(FORGED));
    assert_eq!(forged.public, [FORGED, 11, 11, 22].map(F::from_u64).to_vec());
    assert_forged_run_is_refused(&m, &p, &forged, Tier(8), "(c), a forged LOADE high lane");
}
