use shrugg_zkvm::emulator::*;
use shrugg_zkvm::guests;
use shrugg_zkvm::asm::{ops::*, Assembler};
use shrugg_zkvm::isa::*;

fn run(p: &Program, inputs: &[u32]) -> Execution { execute(p, inputs, 1 << 16).unwrap() }

#[test]
fn fib_outputs_the_right_number() {
    let e = run(&guests::fib(20), &[]);
    assert!(e.halted);
    assert_eq!(e.outputs[0], 6765);
    assert_eq!(e.outputs[1..], [0; 7]);
}

#[test]
fn memcpy_and_sort() {
    assert_eq!(run(&guests::memcpy(8), &[]).outputs[0], 36);
    let e = run(&guests::bubble_sort(&[9, 3, 0xffff_fff0, 1, 7, 3]), &[]);
    assert_eq!((e.outputs[0], e.outputs[1]), (1, 0xffff_fff0));
}

#[test]
fn balance_check_reads_private_inputs() {
    assert_eq!(run(&guests::balance_check(1000), &[400, 250, 300, 75]).outputs[0], 1);
    assert_eq!(run(&guests::balance_check(1000), &[1, 2, 3, 4]).outputs[0], 0);
}

#[test]
fn events_carry_what_the_cpu_table_needs() {
    // addi t0, x0, 7 ; sw x0(0x100) <- t0 ; lw t1, 0x100(x0) ; halt
    let mut a = Assembler::new(0);
    a.push(addi(5, 0, 7)); a.push(sw(0, 5, 0x100)); a.push(lw(6, 0, 0x100)); a.extend(halt());
    let e = run(&a.assemble(), &[]);
    let ev = &e.events[0];
    assert_eq!((ev.pc, ev.next_pc, ev.a, ev.c, ev.alu_out), (0, 4, 0, 7, 7));
    assert_eq!(ev.accesses.len(), 3, "rs1 read, rs2 read, rd write");
    assert_eq!(ev.accesses[2], MemAccess { space: SPACE_REG, addr: 5, slot: SLOT_W, value: 7, is_write: true });
    assert_eq!(ev.alu, vec![AluEvent { op: AluOp::Add, a: 0, b: 7, c: 7 }]);
    let ev = &e.events[1];
    assert_eq!((ev.mem_addr, ev.mem_val), (0x40, 7));
    assert_eq!(ev.accesses[2], MemAccess { space: SPACE_RAM, addr: 0x40, slot: SLOT_MEM, value: 7, is_write: true });
    assert_eq!(ev.accesses.len(), 3, "no rd write for sw");
    let ev = &e.events[2];
    assert_eq!((ev.mem_addr, ev.mem_val, ev.c), (0x40, 7, 7));
    let last = e.events.last().unwrap();
    assert_eq!(last.sys, Some(Syscall::Halt));
    assert_eq!(last.mem_addr, 11);
    assert_eq!(last.accesses.len(), 3, "a7 read, a0 read, a1 read via mem slot");
}

#[test]
fn errors_are_reported() {
    let mut a = Assembler::new(0); a.push(lw(6, 0, 2)); a.extend(halt());
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::Misaligned(2));
    let mut a = Assembler::new(0); a.push(addi(0, 0, 0));
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::BadPc(4));
    let mut a = Assembler::new(0); a.label("l"); a.jal(0, "l");
    assert_eq!(execute(&a.assemble(), &[], 10).unwrap_err(), ExecError::OutOfCycles(10));
    let mut a = Assembler::new(0); a.extend(write_output(0, 5)); a.extend(write_output(0, 5)); a.extend(halt());
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::DoubleWrite(0));
}

#[test]
fn branch_and_shift_sign_edge_cases() {
    // t0 = -1; t1 = 1; bge t0,t1 -> not taken (signed); bgeu t0,t1 -> taken; sra t2 = t0 >> 4 = -1
    let mut a = Assembler::new(0);
    a.extend(li(5, -1)); a.extend(li(6, 1));
    a.branch(BranchCond::Ge, 5, 6, "wrong");
    a.branch(BranchCond::Geu, 5, 6, "ok");
    a.label("wrong"); a.extend(li(7, 99)); a.jal(0, "end");
    a.label("ok"); a.push(srai(7, 5, 4));
    a.label("end"); a.extend(write_output(0, 7)); a.extend(halt());
    assert_eq!(run(&a.assemble(), &[]).outputs[0], 0xffff_ffff);
}


#[test]
fn alu_mix_covers_every_op_and_jalr() {
    let p = guests::alu_mix();
    let e = run(&p, &[]);
    assert!(e.halted);

    // Every AluOp variant really reaches the ALU bus, `Eq` included — it has no encoding of
    // its own, so it can only arrive through a branch.
    let mut seen = std::collections::HashSet::new();
    for ev in &e.events { for a in &ev.alu { seen.insert(a.op); } }
    for op in AluOp::ALL { assert!(seen.contains(&op), "{op:?} never executed"); }

    // Exactly one JALR, through a register target, linking pc + 4 and skipping one word.
    assert_eq!(e.events.iter().filter(|ev| ev.dec.is_jalr == 1).count(), 1);
    let j = e.events.iter().find(|ev| ev.dec.is_jalr == 1).unwrap();
    assert_eq!(j.c, j.pc + 4, "jalr links pc + 4");
    assert_eq!(j.next_pc, j.pc + 8, "jalr jumps over the instruction after it");

    // out0 is the XOR fold of every result, recomputed here straight from the reference
    // semantics rather than copied out of a run.
    let (x, y) = (0xdead_beefu32, 0x0f0f_1234u32);
    let folded: [(AluOp, u32, u32); 14] = [
        (AluOp::Add, x, y), (AluOp::Sub, x, y), (AluOp::And, x, y), (AluOp::Or, x, y), (AluOp::Xor, x, y),
        (AluOp::Sll, y, 12), (AluOp::Srl, x, 12), (AluOp::Sra, x, 12),
        (AluOp::Sll, y, 20), (AluOp::Srl, x, 24), (AluOp::Sra, x, 31),
        (AluOp::And, x, 0xffff_ff00), (AluOp::Or, x, 0x7ff), (AluOp::Xor, x, 0xffff_ffff),
    ];
    let acc = folded.iter().fold(0u32, |a, (op, l, r)| a ^ op.eval(*l, *r)) ^ j.c;
    assert_eq!(e.outputs[0], acc);
    assert_eq!(e.outputs[0], 0xd11c_8282);

    // out1 counts the six compares: signed x < y, unsigned y < x, x < -1, y < ~0 — four.
    // The `bad` and `skipped` arms both write 0x7ff, so 4 also proves neither ran.
    assert_eq!(e.outputs[1], 4);
    assert_eq!(e.outputs[2..], [0; 6]);
}
