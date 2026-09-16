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
