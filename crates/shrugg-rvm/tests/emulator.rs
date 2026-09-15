//! The emulator is the rVM's reference semantics: one test per instruction group, and the event
//! log M5.2's tables are generated from.
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use shrugg_rvm::emulator::{execute, ExecError};
use shrugg_rvm::isa::{Instr, Op, Program, F, MEM_LIMIT};

fn prog(instrs: Vec<Instr>) -> Program {
    Program { instrs, checkpoints: vec![] }
}
fn i(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}
fn ir(op: Op, rd: u8, ra: u8, rb: u8) -> Instr {
    i(op, rd, ra, rb as u64)
}

#[test]
fn base_field_arithmetic_instructions_match_the_field() {
    // r1 = 7, r2 = 5; r3 = r1+r2, r4 = r1-r2, r5 = r1*r2, r6 = r1+9, r7 = r1*9, r8 = r1
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 7),
        i(Op::Faddi, 2, 0, 5),
        ir(Op::Fadd, 3, 1, 2),
        ir(Op::Fsub, 4, 1, 2),
        ir(Op::Fmul, 5, 1, 2),
        i(Op::Faddi, 6, 1, 9),
        i(Op::Fmuli, 7, 1, 9),
        i(Op::Mov, 8, 1, 0),
        i(Op::Public, 0, 3, 0),
        i(Op::Public, 0, 4, 0),
        i(Op::Public, 0, 5, 0),
        i(Op::Public, 0, 6, 0),
        i(Op::Public, 0, 7, 0),
        i(Op::Public, 0, 8, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    let e = execute(&p, &[], 1000).unwrap();
    assert_eq!(e.public, [12u64, 2, 35, 16, 63, 7].map(F::from_u64).to_vec());
    assert_eq!(e.cpu_rows(), 15);
    assert_eq!(e.permutations(), 0);
}

#[test]
fn extension_instructions_match_binomial_extension_field() {
    use p3_field::BasedVectorSpace;
    use shrugg_rvm::isa::EF;
    let (x, y) = (
        EF::from_basis_coefficients_slice(&[F::from_u64(3), F::from_u64(4)]).unwrap(),
        EF::from_basis_coefficients_slice(&[F::from_u64(5), F::from_u64(6)]).unwrap(),
    );
    // E1 = (r1, r2) = x, E3 = (r3, r4) = y, E5 = x+y, E7 = x-y, E9 = x*y, E11 = x*7
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 3),
        i(Op::Faddi, 2, 0, 4),
        i(Op::Faddi, 3, 0, 5),
        i(Op::Faddi, 4, 0, 6),
        ir(Op::Eadd, 5, 1, 3),
        ir(Op::Esub, 7, 1, 3),
        ir(Op::Emul, 9, 1, 3),
        i(Op::Faddi, 20, 0, 7),
        ir(Op::Emulf, 11, 1, 20),
        ir(Op::Einv, 13, 1, 0),
        i(Op::Public, 0, 5, 0),
        i(Op::Public, 0, 6, 0),
        i(Op::Public, 0, 7, 0),
        i(Op::Public, 0, 8, 0),
        i(Op::Public, 0, 9, 0),
        i(Op::Public, 0, 10, 0),
        i(Op::Public, 0, 11, 0),
        i(Op::Public, 0, 12, 0),
        i(Op::Public, 0, 13, 0),
        i(Op::Public, 0, 14, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    let e = execute(&p, &[], 1000).unwrap();
    let got: Vec<EF> =
        e.public.as_chunks::<2>().0.iter().map(|c| EF::from_basis_coefficients_slice(c).unwrap()).collect();
    assert_eq!(got, vec![x + y, x - y, x * y, x * F::from_u64(7), x.inverse()]);
}

#[test]
fn inv_and_einv_are_hint_and_check_and_reject_zero() {
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 9),
        i(Op::Inv, 2, 1, 0),
        ir(Op::Fmul, 3, 1, 2),
        i(Op::Public, 0, 3, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    let e = execute(&p, &[], 1000).unwrap();
    assert_eq!(e.public, vec![F::ONE], "the row constrains ra*rd = 1");
    // No witness word is consumed: the emulator supplies the hint (spec §10).
    assert_eq!(e.hints_read, 0);

    let bad = prog(vec![i(Op::Inv, 2, 0, 0), i(Op::Halt, 0, 0, 0)]);
    assert_eq!(execute(&bad, &[], 1000), Err(ExecError::InverseOfZero { pc: 0 }));
    let bad_e = prog(vec![i(Op::Einv, 2, 0, 0), i(Op::Halt, 0, 0, 0)]);
    assert_eq!(execute(&bad_e, &[], 1000), Err(ExecError::InverseOfZero { pc: 0 }));
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
        i(Op::Halt, 0, 0, 0),
    ]);
    let e = execute(&p, &[], 1000).unwrap();
    assert_eq!(e.public, [42u64, 11, 12].map(F::from_u64).to_vec());
    let writes: Vec<u64> = e
        .events
        .iter()
        .flat_map(|ev| ev.mem.iter())
        .filter(|m| m.is_write)
        .map(|m| m.addr)
        .collect();
    assert_eq!(writes, vec![103, 108, 109]);
}

#[test]
fn an_address_at_or_above_two_to_the_twentyfour_is_an_error() {
    let p = prog(vec![i(Op::Faddi, 1, 0, MEM_LIMIT), i(Op::Load, 2, 1, 0), i(Op::Halt, 0, 0, 0)]);
    assert_eq!(execute(&p, &[], 1000), Err(ExecError::AddressOutOfRange { pc: 1, addr: MEM_LIMIT }));
    // POSEIDON2 needs eight cells, so the last legal pointer is 2^24 - 8.
    let p = prog(vec![
        i(Op::Faddi, 1, 0, MEM_LIMIT - 7),
        i(Op::Poseidon2, 0, 1, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    assert_eq!(
        execute(&p, &[], 1000),
        Err(ExecError::AddressOutOfRange { pc: 1, addr: MEM_LIMIT - 7 + 7 })
    );
}

#[test]
fn control_flow_hint_public_and_halt() {
    // A counted loop: r1 = 3; loop { r2 += 10; r1 -= 1 } while r1 != 0
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 3),
        i(Op::Faddi, 2, 2, 10),               // pc 1: body
        i(Op::Faddi, 1, 1, F::ORDER_U64 - 1), // r1 -= 1
        i(Op::Jne, 1, 0, 1),                  // branch to pc 1 while r1 != r0
        i(Op::Hint, 5, 0, 0),
        i(Op::Hinte, 6, 0, 0),
        i(Op::Public, 0, 2, 0),
        i(Op::Public, 0, 5, 0),
        i(Op::Public, 0, 6, 0),
        i(Op::Public, 0, 7, 0),
        i(Op::Jmp, 0, 0, 11),
        i(Op::Faddi, 9, 0, 1), // the JMP skips this
        i(Op::Halt, 0, 0, 0),
    ]);
    let w = [F::from_u64(77), F::from_u64(88), F::from_u64(99)];
    let e = execute(&p, &w, 1000).unwrap();
    assert_eq!(e.public, [30u64, 77, 88, 99].map(F::from_u64).to_vec());
    assert_eq!(e.hints_read, 3);
    assert_eq!(execute(&p, &w[..1], 1000), Err(ExecError::HintExhausted { pc: 5 }));
    assert_eq!(execute(&p, &w, 4), Err(ExecError::OutOfCycles(4)));
}

#[test]
fn jeq_branches_on_equality_and_a_target_above_two_to_the_twentyfour_is_an_error() {
    // r1 = 1; the first JEQ is not taken (r1 != r0), the second is, so pc 3 never runs.
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 1),
        i(Op::Jeq, 1, 0, 6),
        i(Op::Jeq, 0, 0, 4),
        i(Op::Faddi, 1, 0, 99), // the taken JEQ skips this
        i(Op::Public, 0, 1, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    let e = execute(&p, &[], 1000).unwrap();
    assert_eq!(e.public, vec![F::ONE]);
    assert_eq!(e.cpu_rows(), 5);
    assert_eq!(e.histogram()[Op::Jeq as usize], 2);
    // A branch target is a pc, so it is bounded by 2^24 like every address.
    let far = prog(vec![i(Op::Jmp, 0, 0, MEM_LIMIT), i(Op::Halt, 0, 0, 0)]);
    assert_eq!(execute(&far, &[], 1000), Err(ExecError::PcOutOfRange(MEM_LIMIT)));
}

#[test]
fn poseidon2_permutes_eight_cells_in_place_and_is_counted() {
    let mut instrs = vec![i(Op::Faddi, 1, 0, 64)];
    for k in 0..8u64 {
        instrs.push(i(Op::Faddi, 2, 0, k + 1));
        instrs.push(i(Op::Store, 2, 1, k));
    }
    instrs.push(i(Op::Poseidon2, 0, 1, 0));
    for k in 0..8u64 {
        instrs.push(i(Op::Load, 3, 1, k));
        instrs.push(i(Op::Public, 0, 3, 0));
    }
    instrs.push(i(Op::Halt, 0, 0, 0));
    let e = execute(&prog(instrs), &[], 1000).unwrap();
    let want = shrugg_zkvm::hash::permute_state(core::array::from_fn(|k| F::from_u64(k as u64 + 1)));
    assert_eq!(e.public, want.to_vec());
    assert_eq!(e.permutations(), 1);
    let ev = e.events.iter().find(|ev| ev.perm.is_some()).unwrap();
    let perm = ev.perm.unwrap();
    assert_eq!(perm.ptr, 64);
    assert_eq!(perm.output, want);
    assert_eq!(ev.mem.len(), 16, "eight reads then eight writes");
}

#[test]
fn the_event_log_records_every_memory_access_in_timestamp_order() {
    let p = prog(vec![
        i(Op::Faddi, 1, 0, 8),
        i(Op::Faddi, 2, 0, 5),
        i(Op::Store, 2, 1, 0),
        i(Op::Load, 3, 1, 0),
        i(Op::Halt, 0, 0, 0),
    ]);
    let e = execute(&p, &[], 1000).unwrap();
    let ts: Vec<u32> = e.events.iter().flat_map(|ev| ev.mem.iter()).map(|m| m.ts).collect();
    assert!(ts.windows(2).all(|w| w[0] < w[1]), "timestamps strictly increase: {ts:?}");
    assert_eq!(e.mem_accesses(), 2);
    assert_eq!(e.histogram()[Op::Faddi as usize], 2);
}
