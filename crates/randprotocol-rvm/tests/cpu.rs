//! The cpu table and the machine end-to-end (plan Task 6): per-opcode proofs, the boundary
//! conditions the machine refuses at the emulator level, the 1 000-state permutation-equality
//! contract in proofs, and the auto-tier rule.
mod common;

use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use randprotocol_rvm::emulator::ExecError;
use randprotocol_rvm::isa::{F, Instr, Op, Program};
use randprotocol_rvm::machine::{FriProfile, Machine, ProveError, Tier};

fn i(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}
fn ir(op: Op, rd: u8, ra: u8, rb: u8) -> Instr {
    i(op, rd, ra, rb as u64)
}
fn prog(instrs: Vec<Instr>) -> Program {
    Program { instrs, checkpoints: vec![] }
}

fn prove_and_verify(p: &Program, w: &[F]) -> (randprotocol_rvm::machine::Proof, randprotocol_rvm::emulator::Execution) {
    let m = Machine::new(FriProfile::Test);
    let (proof, exec) = m.prove(p, w, None).unwrap();
    m.verify(p, &proof).unwrap();
    (proof, exec)
}

#[test]
fn base_field_arithmetic_proves_and_verifies() {
    // r1 = 7, r2 = 5; r3 = 12, r4 = 2, r5 = 35, r6 = 16; publish them.
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 7),
        i(Op::Faddi, 2, 0, 5),
        ir(Op::Fadd, 3, 1, 2),
        ir(Op::Fsub, 4, 1, 2),
        ir(Op::Fmul, 5, 1, 2),
        i(Op::Faddi, 6, 1, 9),
        i(Op::Mov, 7, 3, 0),
        i(Op::Public, 0, 3, 0),
        i(Op::Public, 0, 4, 0),
        i(Op::Public, 0, 5, 0),
        i(Op::Public, 0, 6, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    let (proof, exec) = prove_and_verify(&p, &[]);
    assert_eq!(exec.public, [12u64, 2, 35, 16].map(F::from_u64).to_vec());
    assert_eq!(proof.public_values, vec![12, 2, 35, 16]);
    assert_eq!(proof.tier, Tier(8), "a 12-row run lands at the smallest tier");
}

#[test]
fn extension_arithmetic_proves_and_verifies() {
    use p3_field::BasedVectorSpace;
    use randprotocol_rvm::isa::EF;
    let x = EF::from_basis_coefficients_slice(&[F::from_u64(3), F::from_u64(4)]).unwrap();
    let y = EF::from_basis_coefficients_slice(&[F::from_u64(5), F::from_u64(6)]).unwrap();
    let xy = x * y;
    let seven = F::from_u64(7);
    // E1 = x, E3 = y; E5 = x*y; E7 = x*7 (EMULF); publish all four lanes.
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 3),
        i(Op::Faddi, 2, 0, 4),
        i(Op::Faddi, 3, 0, 5),
        i(Op::Faddi, 4, 0, 6),
        ir(Op::Emul, 5, 1, 3),
        i(Op::Faddi, 20, 0, 7),
        ir(Op::Emulf, 7, 1, 20),
        i(Op::Public, 0, 5, 0),
        i(Op::Public, 0, 6, 0),
        i(Op::Public, 0, 7, 0),
        i(Op::Public, 0, 8, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    let (proof, _) = prove_and_verify(&p, &[]);
    let mut want: Vec<u64> = xy.as_basis_coefficients_slice().iter().map(|c: &F| c.as_canonical_u64()).collect();
    want.extend((x * seven).as_basis_coefficients_slice().iter().map(|c: &F| c.as_canonical_u64()));
    assert_eq!(proof.public_values, want);
}

#[test]
fn inv_and_einv_are_hint_and_check_and_the_zero_trap_is_never_provable() {
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 9),
        i(Op::Inv, 2, 1, 0),
        ir(Op::Fmul, 3, 1, 2),
        i(Op::Faddi, 4, 0, 3),
        i(Op::Faddi, 5, 0, 4),
        i(Op::Einv, 6, 4, 0),
        i(Op::Public, 0, 3, 0),
        i(Op::Public, 0, 6, 0),
        i(Op::Public, 0, 7, 0),
        i(Op::Public, 0, 2, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    let (proof, _) = prove_and_verify(&p, &[]);
    assert_eq!(proof.public_values[0], 1, "the row constrains ra*rd = 1");

    // A trap is an emulator error, so no trace exists to prove: the DSL's assertion mechanism
    // works at the machine level exactly as at the emulator level.
    let trap = prog(vec![i(Op::Inv, 2, 0, 0), i(Op::Halt, 0, 0, 0)]);
    let m = Machine::new(FriProfile::Test);
    assert!(matches!(m.prove(&trap, &[], None), Err(ProveError::Exec(ExecError::InverseOfZero { pc: 0 }))));
    let trap_e = prog(vec![i(Op::Faddi, 2, 0, 0), i(Op::Einv, 2, 0, 0), i(Op::Halt, 0, 0, 0)]);
    assert!(matches!(m.prove(&trap_e, &[], None), Err(ProveError::Exec(_))));
}

#[test]
fn load_store_and_their_extension_forms_round_trip_through_memory() {
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 100), // r1 = base
        i(Op::Faddi, 2, 0, 42),
        i(Op::Store, 2, 1, 3),
        i(Op::Load, 4, 1, 3),
        i(Op::Faddi, 5, 0, 11),
        i(Op::Faddi, 6, 0, 12),
        i(Op::Storee, 5, 1, 8),
        i(Op::Loade, 7, 1, 8),
        i(Op::Public, 0, 4, 0),
        i(Op::Public, 0, 7, 0),
        i(Op::Public, 0, 8, 0),
        i(Op::Public, 0, 4, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    let (proof, _) = prove_and_verify(&p, &[]);
    assert_eq!(proof.public_values, vec![42, 11, 12, 42]);
}

#[test]
fn control_flow_hint_and_halt_prove_and_verify() {
    // A counted loop: r1 = 3; loop { r2 += 10; r1 -= 1 } while r1 != 0; then two hints.
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 3),
        i(Op::Faddi, 2, 2, 10),
        i(Op::Faddi, 1, 1, F::ORDER_U64 - 1),
        i(Op::Jne, 1, 0, 1),
        i(Op::Hint, 5, 0, 0),
        i(Op::Hinte, 6, 0, 0),
        i(Op::Public, 0, 2, 0),
        i(Op::Public, 0, 5, 0),
        i(Op::Public, 0, 6, 0),
        i(Op::Public, 0, 7, 0),
        i(Op::Jmp, 0, 0, 11),
        i(Op::Faddi, 9, 0, 1),
        i(Op::Halt, 0, 0, 0),
    ]);
    let w = [F::from_u64(77), F::from_u64(88), F::from_u64(99)];
    let (proof, _) = prove_and_verify(&p, &w);
    assert_eq!(proof.public_values, vec![30, 77, 88, 99]);
}

#[test]
fn poseidon2_permutes_eight_cells_in_place_and_the_result_is_provable() {
    let mut instrs = vec![i(Op::Faddi, 1, 0, 64)];
    for k in 0..8u64 {
        instrs.push(i(Op::Faddi, 2, 0, k + 1));
        instrs.push(i(Op::Store, 2, 1, k));
    }
    instrs.push(i(Op::Poseidon2, 0, 1, 0));
    for k in 0..4u64 {
        instrs.push(i(Op::Load, 3, 1, k));
        instrs.push(i(Op::Public, 0, 3, 0));
    }
    instrs.push(i(Op::Halt, 0, 0, 0));
    let (proof, _) = prove_and_verify(&prog(instrs), &[]);
    let want = randprotocol_zkvm::hash::permute_state(core::array::from_fn(|k| F::from_u64(k as u64 + 1)));
    assert_eq!(proof.public_values, want[..4].iter().map(|c| c.as_canonical_u64()).collect::<Vec<_>>());
}

#[test]
fn addresses_at_or_above_two_to_the_twentyfour_are_emulator_errors_not_proofs() {
    let m = Machine::new(FriProfile::Test);
    // A load from 2^24.
    let p = prog(vec![i(Op::Faddi, 1, 0, 1 << 24), i(Op::Load, 2, 1, 0), i(Op::Halt, 0, 0, 0)]);
    assert!(matches!(m.prove(&p, &[], None), Err(ProveError::Exec(ExecError::AddressOutOfRange { .. }))));
    // A poseidon2 whose eight cells cross the limit (the last legal pointer is 2^24 - 8).
    let p = prog(vec![i(Op::Faddi, 1, 0, (1 << 24) - 7), i(Op::Poseidon2, 0, 1, 0), i(Op::Halt, 0, 0, 0)]);
    assert!(matches!(m.prove(&p, &[], None), Err(ProveError::Exec(ExecError::AddressOutOfRange { .. }))));
    // A branch target at the limit.
    let p = prog(vec![i(Op::Jmp, 0, 0, 1 << 24), i(Op::Halt, 0, 0, 0)]);
    assert!(matches!(m.prove(&p, &[], None), Err(ProveError::Exec(ExecError::PcOutOfRange(_)))));
}

#[test]
fn the_permutation_equality_contract_holds_in_a_proof_over_one_thousand_random_states() {
    // The in-proof half of spec §7's contract: the program stores 1 000 random states, has the
    // chip permute each in place, and asserts — in-program, against `HINT`-supplied reference
    // outputs — that every lane matches. A wrong chip output is a trap: no proof exists.
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(21);
    let states: Vec<[F; 8]> = (0..1000)
        .map(|_| core::array::from_fn(|_| common::random_felt(&mut rng)))
        .collect();
    let (p, tape) = contract_program(&states);
    let m = Machine::new(FriProfile::Test);
    let (proof, exec) = m.prove(&p, &tape, None).unwrap();
    assert_eq!(exec.cpu_rows(), 1 + 1000 * 50 + 5, "50 rows per state, plus the four publishes and the halt");
    assert_eq!(proof.tier, Tier(16));
    m.verify(&p, &proof).unwrap();

    // The tampered twin: one reference word off by one — the program traps, so no proof.
    let mut bad_tape = tape.clone();
    let last = bad_tape.len() - 1;
    bad_tape[last] += F::ONE;
    assert!(matches!(m.prove(&p, &bad_tape, None), Err(ProveError::Exec(ExecError::InverseOfZero { .. }))));
}

/// The contract program: per state, `HINT` the 8 input words into cells at a fresh pointer,
/// `POSEIDON2` there, then per lane load the result and trap unless it equals the next
/// (reference) hint — the reference outputs appended to the tape after each state's inputs.
fn contract_program(states: &[[F; 8]]) -> (Program, Vec<F>) {
    let mut instrs = vec![i(Op::Faddi, 1, 0, 64)];
    let mut tape = Vec::new();
    for state in states {
        // r1 advances by 8 per state.
        instrs.push(i(Op::Faddi, 1, 1, 8));
        for k in 0..8u64 {
            instrs.push(i(Op::Hint, 2, 0, 0));
            instrs.push(i(Op::Store, 2, 1, k));
            tape.push(state[k as usize]);
        }
        instrs.push(i(Op::Poseidon2, 0, 1, 0));
        let want = randprotocol_zkvm::hash::permute_state(*state);
        for k in 0..8u64 {
            instrs.push(i(Op::Load, 3, 1, k));
            instrs.push(i(Op::Hint, 4, 0, 0));
            tape.push(want[k as usize]);
            instrs.push(ir(Op::Fsub, 5, 3, 4));
            // If out == ref, skip the trap.
            let jeq_at = instrs.len();
            instrs.push(i(Op::Jeq, 5, 0, (jeq_at + 2) as u64));
            instrs.push(i(Op::Inv, 30, 0, 0));
        }
    }
    // Publish the digest slots the machine requires: four words, here just the zero register.
    for _ in 0..4 {
        instrs.push(i(Op::Public, 0, 0, 0));
    }
    instrs.push(i(Op::Halt, 0, 0, 0));
    (prog(instrs), tape)
}

// ── The binding rule, checked per opcode against the AIR itself (RVM-1, report §9 item 4) ──────
//
// `tables/cpu.rs` states its soundness rule above the bus sends: every message's address and
// value columns are constrained operand columns on every row kind that sends. RVM-1 broke it —
// STOREE wrote `D1` to RAM and nothing bound `D1` — and no test noticed, because the rule was
// prose. This is the rule as a test. It does not read a hand-kept list of what `eval` sends: it
// runs `CpuAir::eval` through Plonky3's own symbolic interaction builder and reads the `REG`/`RAM`
// messages and the base constraints `eval` actually emits, so deleting a send (the RVM-1 fix's
// `REG` read of `rd + 1` included) changes what this test sees.
//
// For each opcode, a message is *sent* when its count evaluates non-zero on a real row with that
// opcode's selector hot (and `rd ≠ 0`, so the `r0` write-drop gadget does not hide a write). A
// read message binds the value column it carries — the memory table ties it to the last write.
// A *write* (to a register or a RAM cell) is the one kind of message that can carry a free
// column into state, so each written column must be bound, on that opcode's rows, by at least
// one of: a `REG` read carrying the same column, a `RAM` read carrying it, or an ALU identity —
// a base constraint gated by the opcode's own selector that depends on the column. The only
// opcodes allowed a free written value are HINT/HINTE, whose value *is* the witness tape by
// design (spec §3: the rVM's nondeterminism is the tape and nothing else).
//
// `DECLARED` below is the same statement written out per opcode — the data a reviewer reads —
// and the test checks it both ways against what `eval` emits: every written column is declared,
// and every declared binding is one `eval` really has.
use p3_air::symbolic::{AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
use p3_air::Air;
use p3_lookup::InteractionSymbolicBuilder;
use randprotocol_rvm::isa::EF;
use randprotocol_rvm::tables::{bus, cpu};

/// How a written value column is bound on an opcode's rows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Bound {
    /// A `REG` read message on the same row carries the column.
    RegRead,
    /// A `RAM` read message on the same row carries the column.
    RamRead,
    /// A base constraint gated by the opcode's selector depends on the column.
    Alu,
    /// The column is the program's witness tape by design (HINT/HINTE only).
    Witness,
}

/// Per opcode, every column the row *writes* (to a register or to RAM) and how it is bound.
/// Opcodes that write nothing (JMP, JEQ, JNE, PUBLIC, POSEIDON2, HALT, REDUCE, SPONGE — the
/// dispatched chips' own RAM traffic is theirs, not the cpu row's) have no entry.
const DECLARED: &[(Op, &[(usize, Bound)])] = {
    use cpu::col::{D0, D1};
    use Bound::*;
    &[
        (Op::Fadd, &[(D0, Alu)]),
        (Op::Fsub, &[(D0, Alu)]),
        (Op::Fmul, &[(D0, Alu)]),
        (Op::Faddi, &[(D0, Alu)]),
        (Op::Fmuli, &[(D0, Alu)]),
        (Op::Eadd, &[(D0, Alu), (D1, Alu)]),
        (Op::Esub, &[(D0, Alu), (D1, Alu)]),
        (Op::Emul, &[(D0, Alu), (D1, Alu)]),
        (Op::Emulf, &[(D0, Alu), (D1, Alu)]),
        (Op::Inv, &[(D0, Alu)]),
        (Op::Einv, &[(D0, Alu), (D1, Alu)]),
        (Op::Mov, &[(D0, Alu)]),
        (Op::Load, &[(D0, RamRead)]),
        (Op::Store, &[(D0, RegRead)]),
        (Op::Loade, &[(D0, RamRead), (D1, RamRead)]),
        // RVM-1: before the fix `D1` here had no binding at all.
        (Op::Storee, &[(D0, RegRead), (D1, RegRead)]),
        (Op::Hint, &[(D0, Witness)]),
        (Op::Hinte, &[(D0, Witness), (D1, Witness)]),
    ]
};

fn col_name(c: usize) -> String {
    use cpu::col::*;
    match c {
        A0 => "A0".into(),
        A1 => "A1".into(),
        B0 => "B0".into(),
        B1 => "B1".into(),
        D0 => "D0".into(),
        D1 => "D1".into(),
        other => format!("col {other}"),
    }
}

/// A base-field symbolic expression at one row pair (`cur`, `next`), on a transition row that is
/// neither the first nor the last — the rows every opcode constraint lives on.
fn eval_at(e: &SymbolicExpression<F>, cur: &[F], next: &[F]) -> F {
    match e {
        SymbolicExpr::Leaf(l) => match l {
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset: 0 } => cur[v.index],
                BaseEntry::Main { offset: 1 } => next[v.index],
                other => panic!("a main-trace-only AIR read {other:?}"),
            },
            BaseLeaf::IsFirstRow | BaseLeaf::IsLastRow => F::ZERO,
            BaseLeaf::IsTransition => F::ONE,
            BaseLeaf::Constant(c) => *c,
        },
        SymbolicExpr::Add { x, y, .. } => eval_at(x, cur, next) + eval_at(y, cur, next),
        SymbolicExpr::Sub { x, y, .. } => eval_at(x, cur, next) - eval_at(y, cur, next),
        SymbolicExpr::Neg { x, .. } => -eval_at(x, cur, next),
        SymbolicExpr::Mul { x, y, .. } => eval_at(x, cur, next) * eval_at(y, cur, next),
    }
}

/// The single main-trace column a message field is, or `None` for anything composite.
fn as_column(e: &SymbolicExpression<F>) -> Option<usize> {
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) if v.entry == (BaseEntry::Main { offset: 0 }) => Some(v.index),
        _ => None,
    }
}

/// One `REG`/`RAM` message as `eval` emits it: the bus, the value column, write or read, and the
/// count expression.
struct Message {
    bus: &'static str,
    value: usize,
    is_write: bool,
    count: SymbolicExpression<F>,
}

fn cpu_messages_and_constraints() -> (Vec<Message>, Vec<SymbolicExpression<F>>) {
    let mut sb = InteractionSymbolicBuilder::<F, EF>::new(AirLayout::from_air::<F>(&cpu::CpuAir));
    cpu::CpuAir.eval(&mut sb);
    let zeros = vec![F::ZERO; cpu::col::WIDTH];
    let mut msgs = Vec::new();
    for i in sb.global_interactions() {
        let bus = if i.bus_name == bus::REG.name() {
            "REG"
        } else if i.bus_name == bus::RAM.name() {
            "RAM"
        } else {
            continue;
        };
        assert_eq!(i.fields.len(), 4, "a memory message is (addr, ts, value, is_write)");
        let value = as_column(&i.fields[2]).unwrap_or_else(|| panic!("a {bus} message's value is one column"));
        let w = eval_at(&i.fields[3], &zeros, &zeros);
        assert!(w == F::ZERO || w == F::ONE, "is_write is a constant flag");
        msgs.push(Message { bus, value, is_write: w == F::ONE, count: i.count.clone() });
    }
    (msgs, sb.base_constraints())
}

/// A real row with `op`'s selector hot (all other selectors cold), every other column random,
/// and `rd ≠ 0`; `op = None` leaves every selector cold.
fn row(op: Option<Op>, rng: &mut impl rand::Rng) -> Vec<F> {
    use cpu::col::*;
    let mut r: Vec<F> = (0..WIDTH).map(|_| common::random_felt(rng)).collect();
    for k in 0..cpu::NUM_SELECTORS {
        r[SEL0 + k] = F::ZERO;
    }
    if let Some(op) = op {
        r[SEL0 + op as usize] = F::ONE;
    }
    r[IS_REAL] = F::ONE;
    r[RD_IS_ZERO] = F::ZERO;
    r
}

/// Does constraint `c` depend on column `col` at this row pair? Two random perturbations, so a
/// chance cancellation cannot hide a dependency.
fn depends(c: &SymbolicExpression<F>, cur: &[F], next: &[F], col: usize, rng: &mut impl rand::Rng) -> bool {
    let base = eval_at(c, cur, next);
    (0..2).any(|_| {
        let mut moved = cur.to_vec();
        moved[col] += common::random_felt(rng) + F::ONE;
        eval_at(c, &moved, next) != base
    })
}

#[test]
fn every_value_the_cpu_row_writes_is_bound_on_every_opcode() {
    use std::collections::{BTreeMap, BTreeSet};
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x52_564d_31);
    let (msgs, constraints) = cpu_messages_and_constraints();
    assert!(msgs.iter().any(|m| m.bus == "REG") && msgs.iter().any(|m| m.bus == "RAM"), "eval sends on both buses");

    let mut failures: Vec<String> = Vec::new();
    for op in Op::ALL {
        let cur = row(Some(op), &mut rng);
        let next = row(None, &mut rng);
        let sent: Vec<&Message> = msgs.iter().filter(|m| eval_at(&m.count, &cur, &next) != F::ZERO).collect();
        let reads = |bus: &str| -> BTreeSet<usize> { sent.iter().filter(|m| m.bus == bus && !m.is_write).map(|m| m.value).collect() };
        let (reg_reads, ram_reads) = (reads("REG"), reads("RAM"));
        let written: BTreeSet<usize> = sent.iter().filter(|m| m.is_write).map(|m| m.value).collect();
        // An ALU identity for `op` on `col`: a constraint that depends on `col` with `op`'s
        // selector hot and not with every selector cold — gated by the opcode, so the equality
        // gadget and the other ungated row checks (which read `D0` on every row) do not count.
        let alu = |col: usize, rng: &mut rand::rngs::StdRng| -> bool {
            let cold = row(None, rng);
            constraints.iter().any(|c| depends(c, &cur, &next, col, rng) && !depends(c, &cold, &next, col, rng))
        };
        let declared: BTreeMap<usize, Bound> =
            DECLARED.iter().find(|(o, _)| *o == op).map(|(_, b)| b.iter().copied().collect()).unwrap_or_default();

        for &col in &written {
            let bound_by: Vec<Bound> = [
                (reg_reads.contains(&col), Bound::RegRead),
                (ram_reads.contains(&col), Bound::RamRead),
                (alu(col, &mut rng), Bound::Alu),
                (matches!(op, Op::Hint | Op::Hinte), Bound::Witness),
            ]
            .into_iter()
            .filter_map(|(yes, b)| yes.then_some(b))
            .collect();
            if bound_by.is_empty() {
                failures.push(format!(
                    "{}: writes {} and NOTHING binds it (no REG read, no RAM read, no ALU identity carries it)",
                    op.mnemonic(),
                    col_name(col)
                ));
            }
            match declared.get(&col) {
                None => failures.push(format!("{}: writes {} but DECLARED has no binding for it", op.mnemonic(), col_name(col))),
                Some(b) if !bound_by.contains(b) => failures.push(format!(
                    "{}: {} is declared bound by {b:?}, but eval binds it by {bound_by:?}",
                    op.mnemonic(),
                    col_name(col)
                )),
                Some(_) => {}
            }
        }
        for col in declared.keys().filter(|c| !written.contains(c)) {
            failures.push(format!("{}: DECLARED lists {} but eval sends no write carrying it", op.mnemonic(), col_name(*col)));
        }
    }
    assert!(failures.is_empty(), "the cpu table's binding rule is broken:\n  {}", failures.join("\n  "));
}
