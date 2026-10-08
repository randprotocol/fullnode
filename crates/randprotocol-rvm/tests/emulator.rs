//! The emulator is the rVM's reference semantics: one test per instruction group, and the event
//! log M5.2's tables are generated from.
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use randprotocol_rvm::emulator::{execute, ExecError, PermKind};
use randprotocol_rvm::isa::{Instr, Op, Program, F, MEM_LIMIT};

fn prog(instrs: Vec<Instr>) -> Program {
    Program { instrs, checkpoints: vec![], reduce_layout: vec![] }
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
    use randprotocol_rvm::isa::EF;
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
    let want = randprotocol_zkvm::hash::permute_state(core::array::from_fn(|k| F::from_u64(k as u64 + 1)));
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

#[test]
fn hintn_writes_eight_witness_words_at_ra_plus_imm() {
    let p = Program { instrs: vec![
        i(Op::Faddi, 1, 0, 100),            // r1 = 100
        i(Op::Hintn, 0, 1, 4),              // mem[104..112] = w[0..8]
        i(Op::Load, 2, 1, 4),               // r2 = mem[104]
        i(Op::Load, 3, 1, 11),              // r3 = mem[111]
        i(Op::Public, 0, 2, 0), i(Op::Public, 0, 3, 0), i(Op::Halt, 0, 0, 0),
    ], checkpoints: vec![], reduce_layout: vec![] };
    let tape: Vec<F> = (1..=8).map(F::from_u64).collect();
    let exec = execute(&p, &tape, 100).unwrap();
    assert_eq!(exec.public, vec![F::from_u64(1), F::from_u64(8)]);
    assert_eq!(exec.hints_read, 8);
    let hintn = &exec.events[1];
    assert_eq!(hintn.mem.len(), 8, "eight RAM writes");
    assert!(hintn.mem.iter().all(|m| m.is_write));
    assert_eq!(hintn.mem[0].addr, 104);
    assert_eq!(hintn.mem[7].addr, 111);
    assert_eq!(hintn.mem[7].value, F::from_u64(8));
    // The cpu AIR's `ts(k)` for the k-th write: slot k of row clk = 1.
    for (k, m) in hintn.mem.iter().enumerate() {
        assert_eq!(m.ts, 16 + k as u32, "write {k} at slot {k}");
    }
}

#[test]
fn hintn_with_seven_words_left_is_hint_exhausted() {
    let p = Program { instrs: vec![i(Op::Faddi, 1, 0, 100), i(Op::Hintn, 0, 1, 0), i(Op::Halt, 0, 0, 0)], checkpoints: vec![], reduce_layout: vec![] };
    let tape: Vec<F> = (1..=7).map(F::from_u64).collect();
    assert_eq!(execute(&p, &tape, 100), Err(ExecError::HintExhausted { pc: 1 }));
}

#[test]
fn hintn_whose_top_cell_is_at_two_to_the_twentyfour_is_refused() {
    let p = Program { instrs: vec![i(Op::Faddi, 1, 0, (1 << 24) - 7), i(Op::Hintn, 0, 1, 0), i(Op::Halt, 0, 0, 0)], checkpoints: vec![], reduce_layout: vec![] };
    let tape: Vec<F> = (1..=8).map(F::from_u64).collect();
    assert_eq!(execute(&p, &tape, 100), Err(ExecError::AddressOutOfRange { pc: 1, addr: 1 << 24 }));
    // One lower is the last legal base.
    let p = Program { instrs: vec![i(Op::Faddi, 1, 0, (1 << 24) - 8), i(Op::Hintn, 0, 1, 0), i(Op::Halt, 0, 0, 0)], checkpoints: vec![], reduce_layout: vec![] };
    assert!(execute(&p, &tape, 100).is_ok());
}

#[test]
fn compress_orders_the_children_by_the_bit_and_keeps_four_lanes() {
    let (d, s): (Vec<F>, Vec<F>) = ((1..=4).map(F::from_u64).collect(), (11..=14).map(F::from_u64).collect());
    let run = |bit: u64| {
        let mut instrs = vec![i(Op::Faddi, 1, 0, 64), i(Op::Faddi, 2, 0, 80), i(Op::Faddi, 3, 0, bit)];
        for k in 0..4 { instrs.push(i(Op::Faddi, 4, 0, 1 + k)); instrs.push(i(Op::Store, 4, 1, k)); }
        for k in 0..4 { instrs.push(i(Op::Faddi, 4, 0, 11 + k)); instrs.push(i(Op::Store, 4, 2, k)); }
        instrs.push(ir(Op::Compress, 3, 1, 2));
        for k in 0..4 { instrs.push(i(Op::Load, 5, 1, k)); instrs.push(i(Op::Public, 0, 5, 0)); }
        instrs.push(i(Op::Halt, 0, 0, 0));
        execute(&Program { instrs, checkpoints: vec![], reduce_layout: vec![] }, &[], 1000).unwrap()
    };
    let want = |input: [F; 8]| randprotocol_zkvm::hash::permute_state(input)[..4].to_vec();
    let ds: [F; 8] = core::array::from_fn(|k| if k < 4 { d[k] } else { s[k - 4] });
    let sd: [F; 8] = core::array::from_fn(|k| if k < 4 { s[k] } else { d[k - 4] });
    assert_eq!(run(0).public, want(ds));
    assert_eq!(run(1).public, want(sd));
    let ev = run(1).events.iter().find(|e| e.instr.op == Op::Compress).cloned().unwrap();
    assert_eq!(ev.mem.len(), 12, "4 + 4 reads, 4 writes");
    assert_eq!(ev.d[0], F::ONE, "the bit is read from rd into D0");
    match ev.perm.unwrap().kind { PermKind::Compress { sib: 80, bit: true } => {}, k => panic!("{k:?}") }
}

#[test]
fn compress_refuses_a_non_boolean_bit() {
    let p = Program { instrs: vec![i(Op::Faddi, 1, 0, 64), i(Op::Faddi, 2, 0, 80), i(Op::Faddi, 3, 0, 2), ir(Op::Compress, 3, 1, 2), i(Op::Halt, 0, 0, 0)], checkpoints: vec![], reduce_layout: vec![] };
    assert_eq!(execute(&p, &[], 100), Err(ExecError::NonBooleanBit { pc: 3 }));
}

use randprotocol_rvm::isa::ReduceEntry;

/// Cut D's honest chain over `common`'s 267 fixture, inlined: vals (10,0) (20,0) (30,0) at 100,
/// row 4 5 6 at 120, inv (1,0) at 210, alpha (3,0) at 212, the result at 214.
fn chain(split: bool) -> Program {
    let mut v = vec![];
    for (addr, val) in [(100u64, 10u64), (101, 0), (102, 20), (103, 0), (104, 30), (105, 0), (120, 4), (121, 5), (122, 6), (210, 1), (211, 0), (212, 3), (213, 0)] {
        v.push(i(Op::Faddi, 1, 0, val));
        v.push(i(Op::Store, 1, 0, addr));
    }
    let e = ReduceEntry { vals: 100, row: 120, len: 3, key: 210, alpha: 212, res: 214, chain_start: true, carry: false };
    let layout = if split {
        vec![ReduceEntry { len: 2, carry: true, ..e }, ReduceEntry { vals: 104, row: 122, len: 1, chain_start: false, ..e }]
    } else {
        vec![e]
    };
    for id in 0..layout.len() as u64 {
        v.push(i(Op::Reduce, 0, 0, id));
    }
    v.push(i(Op::Load, 3, 0, 214));
    for _ in 0..4 {
        v.push(i(Op::Public, 0, 3, 0));
    }
    v.push(i(Op::Halt, 0, 0, 0));
    Program { instrs: v, checkpoints: vec![], reduce_layout: layout }
}

#[test]
fn a_reduce_chain_accumulates_across_its_entries_and_writes_once() {
    for split in [false, true] {
        let exec = execute(&chain(split), &[], 1000).unwrap();
        assert_eq!(exec.public[0], F::from_u64(267), "(10−4)·1 + (20−5)·3 + (30−6)·9, split {split}");
        let writes: usize = exec.events.iter().filter(|e| e.reduce.is_some()).map(|e| e.mem.iter().filter(|m| m.is_write).count()).sum();
        assert_eq!(writes, 2, "one result write per chain, split {split}");
    }
}

#[test]
fn a_carry_not_consumed_by_the_next_instruction_is_refused() {
    let mut p = chain(true);
    let at = p.instrs.iter().position(|x| x.op == Op::Reduce).unwrap();
    p.instrs.insert(at + 1, i(Op::Faddi, 9, 0, 1));
    assert!(matches!(execute(&p, &[], 1000), Err(ExecError::ReduceChain { entry: 1, .. })));
}

#[test]
fn a_continuation_entry_dispatched_without_its_carry_is_refused() {
    let mut p = chain(true);
    let at = p.instrs.iter().position(|x| x.op == Op::Reduce).unwrap();
    p.instrs.remove(at); // entry 0 never runs
    assert!(matches!(execute(&p, &[], 1000), Err(ExecError::ReduceChain { entry: 1, .. })));
}

#[test]
fn an_entry_id_past_the_layout_is_refused() {
    let mut p = chain(false);
    let at = p.instrs.iter().position(|x| x.op == Op::Reduce).unwrap();
    p.instrs[at] = i(Op::Reduce, 0, 0, 5);
    assert_eq!(execute(&p, &[], 1000).unwrap_err(), ExecError::ReduceLayout { pc: at as u32, entry: 5 });
}

/// Fix round 1 (Task 1a review): a hostile entry whose `u64::MAX` bases would wrap `base + 1` back
/// into range is refused before any cell is read — the same bound `check_program` applies.
#[test]
fn a_layout_entry_whose_addresses_wrap_is_refused() {
    let mut p = chain(false);
    p.reduce_layout[0] = ReduceEntry { key: u64::MAX, vals: u64::MAX, len: 1, row: 0, alpha: 0, res: 2, chain_start: true, carry: false };
    let at = p.instrs.iter().position(|x| x.op == Op::Reduce).unwrap();
    assert_eq!(execute(&p, &[], 1000).unwrap_err(), ExecError::ReduceLayout { pc: at as u32, entry: 0 });
}

#[test]
fn fold_reads_the_row_and_writes_the_fold_after_the_salts() {
    use p3_field::BasedVectorSpace;
    use randprotocol_rvm::isa::EF;
    let ys: Vec<EF> = (1..=4u64).map(|k| EF::from_basis_coefficients_slice(&[F::from_u64(k), F::from_u64(10 * k)]).unwrap()).collect();
    let u = EF::from_basis_coefficients_slice(&[F::from_u64(3), F::from_u64(5)]).unwrap();
    let mut v = vec![];
    for (k, y) in ys.iter().enumerate() {
        for (l, w) in y.as_basis_coefficients_slice().iter().enumerate() {
            v.push(Instr { op: Op::Faddi, rd: 1, ra: 0, b: *w });
            v.push(i(Op::Store, 1, 0, 300 + 2 * k as u64 + l as u64));
        }
    }
    v.extend([i(Op::Faddi, 2, 0, 3), i(Op::Faddi, 3, 0, 5), i(Op::Faddi, 4, 0, 300), i(Op::Fold, 2, 4, 4)]);
    v.extend([i(Op::Loade, 6, 0, 300 + 8 + 4), i(Op::Public, 0, 6, 0), i(Op::Public, 0, 7, 0), i(Op::Halt, 0, 0, 0)]);
    let exec = execute(&prog(v), &[], 1000).unwrap();
    let want = randprotocol_rvm::emulator::fold_dft_horner(&ys, u);
    assert_eq!(exec.public, want.as_basis_coefficients_slice().to_vec());
    let ev = exec.events.iter().find(|e| e.instr.op == Op::Fold).unwrap();
    assert_eq!(ev.mem.len(), 2 * 4 + 2, "two reads per value, two result writes");
    assert_eq!(ev.d, [F::from_u64(3), F::from_u64(5)], "u is read from the rd pair");
}

#[test]
fn fold_refuses_an_arity_outside_two_four_eight() {
    let p = prog(vec![i(Op::Faddi, 4, 0, 300), i(Op::Fold, 2, 4, 3), i(Op::Halt, 0, 0, 0)]);
    assert_eq!(execute(&p, &[], 100), Err(ExecError::FoldArity { pc: 1, arity: 3 }));
}

fn pow_prog(bits: &[u64], off: u64, len: u64, g: F, base: F) -> Program {
    let mut v = vec![];
    for (k, &bit) in bits.iter().enumerate() {
        v.push(i(Op::Faddi, 1, 0, bit));
        v.push(i(Op::Store, 1, 0, 400 + k as u64));
    }
    v.extend([Instr { op: Op::Faddi, rd: 2, ra: 0, b: g }, Instr { op: Op::Faddi, rd: 3, ra: 0, b: base }, i(Op::Faddi, 4, 0, 400)]);
    v.extend([i(Op::Pow, 2, 4, off + 256 * len), i(Op::Load, 6, 0, 464), i(Op::Public, 0, 6, 0), i(Op::Halt, 0, 0, 0)]);
    prog(v)
}

#[test]
fn pow_is_the_bit_selected_power() {
    use p3_field::TwoAdicField;
    let bits: Vec<u64> = (0..64).map(|k| (0x9e37_79b9u64 >> (k % 32)) & 1).collect();
    let (off, len) = (5u64, 11u64);
    let g = F::two_adic_generator(len as usize);
    let exec = execute(&pow_prog(&bits, off, len, g, F::GENERATOR), &[], 10_000).unwrap();
    let mut want = F::GENERATOR;
    for k in 0..len {
        if bits[(off + k) as usize] == 1 {
            want *= g.exp_u64(1 << (len - 1 - k));
        }
    }
    assert_eq!(exec.public, vec![want]);
}

#[test]
fn pow_refuses_a_non_boolean_bit_and_a_bad_shape() {
    let mut bits = vec![0u64; 64];
    bits[3] = 2;
    assert_eq!(execute(&pow_prog(&bits, 0, 8, F::TWO, F::ONE), &[], 10_000).unwrap_err(), ExecError::NonBooleanBit { pc: 131 });
    let bits = vec![0u64; 64];
    assert!(matches!(execute(&pow_prog(&bits, 60, 8, F::TWO, F::ONE), &[], 10_000), Err(ExecError::PowShape { .. })));
}
