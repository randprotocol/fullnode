use shrugg_zkvm::emulator::*;
use shrugg_zkvm::guests;
use shrugg_zkvm::asm::{ops::*, Assembler};
use shrugg_zkvm::isa::*;

fn run(p: &Program, inputs: &[u32]) -> Execution { execute(p, inputs, 1 << 16).unwrap() }

/// M3.2: the `POSEIDON2` syscall (`guests::poseidon2_demo`, which hashes its message in place
/// and outputs the 8-word digest) must agree with `hash::sponge_hash` — the host-side
/// `PaddingFreeSponge<_, 8, 4, 4>` reference — for every block-boundary case: empty (no
/// permutation, all-zero digest), one partial block, one exact full block, one full block plus
/// a partial one, two full blocks, and a message spanning many blocks. Also checks the row
/// count the syscall emits: 1 ecall row, `n.div_ceil(4)` absorb rows (0 when `n = 0`), and 2
/// write-back rows — exactly what `tables::cpu`'s hash-row columns expect per call.
#[test]
fn poseidon2_syscall_matches_native_reference_for_various_lengths() {
    for n in [0usize, 1, 4, 5, 8, 100] {
        let msg: Vec<u32> = (1..=n as u32).collect();
        let p = guests::poseidon2_demo(&msg);
        let e = run(&p, &[]);
        let want = shrugg_zkvm::hash::sponge_hash(&msg);
        assert_eq!(&e.outputs[..8], &want[..], "n={n}: digest");
        let hash_rows = e.events.iter().filter(|ev| ev.hash_row.is_some()).count();
        assert_eq!(hash_rows, 1 + n.div_ceil(4) + 2, "n={n}: hash row count");
    }
}

/// `n = 0` is the sponge's empty-input case: no permutation runs at all, and the digest is the
/// all-zero state's own first 4 lanes.
#[test]
fn poseidon2_of_the_empty_message_is_the_all_zero_digest() {
    assert_eq!(shrugg_zkvm::hash::sponge_hash(&[]), [0u32; 8]);
    let e = run(&guests::poseidon2_demo(&[]), &[]);
    assert_eq!(&e.outputs[..8], &[0u32; 8]);
}

/// `n > POSEIDON2_MAX_WORDS` is rejected before any absorption happens.
#[test]
fn poseidon2_over_the_word_limit_is_rejected() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000));
    a.extend(call_poseidon2(0x1000 / 4, (POSEIDON2_MAX_WORDS + 1) as usize));
    a.extend(halt());
    let err = execute(&a.assemble(), &[], 1 << 16).unwrap_err();
    assert_eq!(err, ExecError::Poseidon2WordCount(POSEIDON2_MAX_WORDS + 1));
}

/// Audit ZM4 (2026-09-12): `ptr >= 2^30` emulates fine but can never satisfy the AIR (the cpu
/// table bounds `HASH_PTR < 2^30` via the ecall row's `HP0..3`/`HP3_HI` decomposition), so the
/// emulator — the crate's reference semantics — rejects it, and the boundary pointer just
/// below still runs.
#[test]
fn poseidon2_pointer_at_or_above_2_to_the_30_is_an_execution_error() {
    let mut a = Assembler::new(0);
    a.extend(call_poseidon2(1 << 30, 4)); // ptr words = 2^30
    a.extend(halt());
    let err = execute(&a.assemble(), &[], 1 << 16).unwrap_err();
    assert_eq!(err, ExecError::Poseidon2Ptr(1 << 30));

    let mut a = Assembler::new(0);
    a.extend(call_poseidon2(((1u32 << 30) - 8) as i32, 4)); // every derived address stays < 2^30
    a.extend(halt());
    run(&a.assemble(), &[]);
}

#[test]
fn sub_word_loads_and_stores_match_the_spec() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0x11223344u32 as i32));
    a.push(sw(8, 5, 0));
    a.push(lb(6, 8, 0)); a.extend(write_output(0, 6));   // byte 0 = 0x44, sign-extends to 0x44
    a.push(lbu(6, 8, 3)); a.extend(write_output(1, 6));  // byte 3 = 0x11
    a.push(lh(6, 8, 2)); a.extend(write_output(2, 6));   // half at 2 = 0x1122
    a.extend(halt());
    let e = run(&a.assemble(), &[]);
    assert_eq!((e.outputs[0], e.outputs[1], e.outputs[2]), (0x44, 0x11, 0x1122));
}

#[test]
fn sub_word_signed_loads_sign_extend_and_unsigned_loads_zero_extend() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0xffu32 as i32));
    a.push(sw(8, 5, 0));
    a.push(lb(6, 8, 0)); a.extend(write_output(0, 6));   // signed: 0xff -> -1 -> 0xffff_ffff
    a.push(lbu(6, 8, 0)); a.extend(write_output(1, 6));  // unsigned: 0xff -> 0xff
    a.extend(li(5, 0xff00u32 as i32));
    a.push(sw(8, 5, 4));
    a.push(lh(6, 8, 4)); a.extend(write_output(2, 6));   // signed half: 0xff00 -> 0xffff_ff00
    a.push(lhu(6, 8, 4)); a.extend(write_output(3, 6));  // unsigned half: 0xff00
    a.extend(halt());
    let e = run(&a.assemble(), &[]);
    assert_eq!(e.outputs[0], 0xffff_ffff);
    assert_eq!(e.outputs[1], 0xff);
    assert_eq!(e.outputs[2], 0xffff_ff00);
    assert_eq!(e.outputs[3], 0xff00);
}

#[test]
fn a_sub_word_store_is_a_read_modify_write_that_leaves_other_bytes_alone() {
    let mut a = Assembler::new(0);
    a.extend(li(8, 0x1000)); a.extend(li(5, 0x11223344u32 as i32)); a.extend(li(6, 0xab));
    a.push(sw(8, 5, 0));
    a.push(sb(8, 6, 1));            // only byte 1 becomes 0xab: 0x1122ab44
    a.push(lw(7, 8, 0)); a.extend(write_output(0, 7));
    a.extend(halt());
    let e = run(&a.assemble(), &[]);
    assert_eq!(e.outputs[0], 0x1122ab44);
}

#[test]
fn misaligned_half_load_and_store_are_rejected() {
    // `Misaligned` carries the actual byte address (`alu_out`), matching `errors_are_reported`'s
    // existing convention (`lw(6, 0, 2)` -> `Misaligned(2)`, not `Misaligned(0)`).
    let mut a = Assembler::new(0); a.extend(li(8, 0x1000)); a.push(lh(6, 8, 1)); a.extend(halt());
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::Misaligned(0x1001));
    let mut a = Assembler::new(0); a.extend(li(8, 0x1000)); a.extend(li(5, 1)); a.push(sh(8, 5, 1)); a.extend(halt());
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::Misaligned(0x1001));
}

#[test]
fn misaligned_word_load_and_store_are_still_rejected() {
    let mut a = Assembler::new(0); a.push(lw(6, 0, 2)); a.extend(halt());
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::Misaligned(2));
    let mut a = Assembler::new(0); a.extend(li(5, 1)); a.push(sw(0, 5, 2)); a.extend(halt());
    assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::Misaligned(2));
}

#[test]
fn byte_and_half_loads_are_never_misaligned_except_half_on_an_odd_offset() {
    // lb/sb at every offset succeed; lh/sh only at offsets 0 and 2.
    for off in 0..4i32 {
        let mut a = Assembler::new(0); a.extend(li(8, 0x1000)); a.push(lb(6, 8, off)); a.extend(halt());
        execute(&a.assemble(), &[], 100).unwrap();
    }
    for off in [0i32, 2] {
        let mut a = Assembler::new(0); a.extend(li(8, 0x1000)); a.push(lh(6, 8, off)); a.extend(halt());
        execute(&a.assemble(), &[], 100).unwrap();
    }
    for off in [1i32, 3] {
        let mut a = Assembler::new(0); a.extend(li(8, 0x1000)); a.push(lh(6, 8, off)); a.extend(halt());
        assert_eq!(execute(&a.assemble(), &[], 100).unwrap_err(), ExecError::Misaligned(0x1000 + off as u32));
    }
}

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
    // u32::MAX + 2 wraps to 1: without the carry flag the bit would say "under threshold".
    assert_eq!(run(&guests::balance_check(1000), &[u32::MAX, 2, 0, 0]).outputs[0], 1, "a wrapped sum is still over threshold");
    assert_eq!(run(&guests::balance_check(u32::MAX), &[u32::MAX, 0, 0, 0]).outputs[0], 1, "exactly at threshold counts");
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
    // `mem_val` is now the pre-store word (unwritten memory reads zero); the merged word
    // (7) goes out separately on `SLOT_W` — a store is a read-modify-write of one word.
    assert_eq!((ev.mem_addr, ev.mem_val), (0x40, 0));
    assert_eq!(ev.accesses[2], MemAccess { space: SPACE_RAM, addr: 0x40, slot: SLOT_MEM, value: 0, is_write: false });
    assert_eq!(ev.accesses[3], MemAccess { space: SPACE_RAM, addr: 0x40, slot: SLOT_W, value: 7, is_write: true });
    assert_eq!(ev.accesses.len(), 4, "rs1 read, rs2 read, RAM read (SLOT_MEM), RAM write (SLOT_W)");
    let ev = &e.events[2];
    assert_eq!((ev.mem_addr, ev.mem_val, ev.c), (0x40, 7, 7));
    let last = e.events.last().unwrap();
    assert_eq!(last.sys, Some(Syscall::Halt));
    assert_eq!(last.mem_addr, 11);
    assert_eq!(last.accesses.len(), 3, "a7 read, a0 read, a1 read via mem slot");
}

#[test]
fn sub_word_checksum_guest_matches_hand_computed_reference() {
    let e = run(&guests::sub_word_checksum(), &[]);
    assert!(e.halted);
    // word0 = 0x7fff0281 (bytes 0x81 02 ff 7f), word1 = 0x00ff8001 (halves 0x8001 00ff).
    assert_eq!(e.outputs[1], 0x7fff_0281);
    assert_eq!(e.outputs[2], 0x00ff_8001);
    // XOR fold of: LB(0)=0xffff_ff81, LBU(0)=0x81, LB(3)=0x7f, LH(4)=0xffff_8001,
    // LHU(4)=0x8001, LH(6)=0xff, LW(0)=word0, LW(4)=word1.
    let folded = [0xffff_ff81u32, 0x81, 0x7f, 0xffff_8001, 0x8001, 0xff, 0x7fff_0281, 0x00ff_8001];
    let acc = folded.iter().fold(0u32, |a, x| a ^ x);
    assert_eq!(e.outputs[0], acc);
    assert_eq!(e.outputs[0], 0x7f00_7d00);
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

    // Every RV32I AluOp variant really reaches the ALU bus, `Eq` included — it has no
    // encoding of its own, so it can only arrive through a branch. The M-extension variants
    // (M2.6) are `alu_mix`'s successor's job — see `muldiv_covers_every_op`.
    let mut seen = std::collections::HashSet::new();
    for ev in &e.events { for a in &ev.alu { seen.insert(a.op); } }
    for op in [AluOp::Add, AluOp::Sub, AluOp::And, AluOp::Or, AluOp::Xor, AluOp::Sll, AluOp::Srl, AluOp::Sra, AluOp::Slt, AluOp::Sltu, AluOp::Eq] {
        assert!(seen.contains(&op), "{op:?} never executed");
    }

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

#[test]
fn muldiv_covers_every_op() {
    let p = guests::muldiv();
    let e = run(&p, &[]);
    assert!(e.halted);

    let mut seen = std::collections::HashSet::new();
    for ev in &e.events { for a in &ev.alu { seen.insert(a.op); } }
    for op in [AluOp::Mul, AluOp::Mulh, AluOp::Mulhu, AluOp::Mulhsu, AluOp::Div, AluOp::Divu, AluOp::Rem, AluOp::Remu] {
        assert!(seen.contains(&op), "{op:?} never executed");
    }

    // Recomputed straight from `AluOp::eval` — the reference semantics — not copied out of
    // a run, mirroring `alu_mix_covers_every_op_and_jalr`'s style.
    let neg1 = 0xffff_ffffu32;
    let min = 0x8000_0000u32;
    let folded: [(AluOp, u32, u32); 16] = [
        (AluOp::Mul, 6, 7),
        (AluOp::Mulh, neg1, neg1),
        (AluOp::Mulhu, neg1, neg1),
        (AluOp::Mulhsu, neg1, 7),
        (AluOp::Divu, 6, 7),
        (AluOp::Remu, 6, 7),
        (AluOp::Div, neg1, 7),
        (AluOp::Rem, neg1, 7),
        (AluOp::Divu, 6, 0),
        (AluOp::Remu, 6, 0),
        (AluOp::Div, min, neg1),
        (AluOp::Rem, min, neg1),
        (AluOp::Div, (-4i32) as u32, 2),
        (AluOp::Rem, (-4i32) as u32, 2),
        (AluOp::Div, (-3i32) as u32, 10),
        (AluOp::Rem, (-3i32) as u32, 10),
    ];
    let acc = folded.iter().fold(0u32, |a, (op, l, r)| a ^ op.eval(*l, *r));
    assert_eq!(e.outputs[0], acc);
}

/// M4.2: `SYS_KECCAK` permutes the 50 words at the **word** address in `a0` in place, in
/// exactly one cpu row (`next_pc = pc + 4`) — the chip, not the cpu table, does the 24 rounds.
/// The 100 RAM accesses it makes (50 reads at slot 0, then 50 writes at slot 1) are kept in
/// `keccak_accesses`, apart from the ecall row's own register accesses, because Task 4's keccak
/// table is what sends them on the `MEMORY` bus; the memory *table* still records all of them.
#[test]
fn sys_keccak_permutes_fifty_words_in_place_in_one_cycle() {
    use shrugg_zkvm::keccak::{keccak_f, state_to_words, words_to_state};
    const BUF: i32 = 0x400; // byte address; word address 0x100
    const T0: u32 = 5;
    const T1: u32 = 6;
    let mut a = Assembler::new(0);
    // store words 0..50 = w at BUF, call KECCAK, publish word 0 and word 49
    for w in 0..50u32 {
        a.extend(li(T0, (w * 0x0101_0101 + 7) as i32));
        a.push(sw(REG_ZERO, T0, BUF + 4 * w as i32));
    }
    a.extend(call_keccak(BUF / 4));
    a.push(lw(T1, REG_ZERO, BUF));
    a.extend(write_output(0, T1));
    a.push(lw(T1, REG_ZERO, BUF + 4 * 49));
    a.extend(write_output(1, T1));
    a.extend(halt());
    let exec = run(&a.assemble(), &[]);
    let mut expected = words_to_state(&std::array::from_fn(|w| (w as u32) * 0x0101_0101 + 7));
    keccak_f(&mut expected);
    let words = state_to_words(&expected);
    assert_eq!(exec.outputs[0], words[0]);
    assert_eq!(exec.outputs[1], words[49]);
    let ev = exec.events.iter().find(|e| matches!(e.sys, Some(Syscall::Keccak { .. }))).unwrap();
    let row = ev.keccak_row.as_ref().unwrap();
    assert_eq!(row.ptr, (BUF / 4) as u32);
    assert_eq!(row.output, words);
    assert_eq!(ev.keccak_accesses.len(), 100);
    assert!(ev.keccak_accesses[..50].iter().all(|m| !m.is_write && m.slot == 0));
    assert!(ev.keccak_accesses[50..].iter().all(|m| m.is_write && m.slot == 1));
    assert_eq!(ev.next_pc, ev.pc + 4, "one cpu row per KECCAK call");
}

/// M4.2 (controller ruling 2): the AIR bounds a `SYS_KECCAK` row's `HASH_PTR` to
/// `ptr < 0x3000_0000` (`HP3_HI ∈ {0,1,2}`), so the chip's own `PTR + w` address arithmetic
/// cannot wrap or alias another `MEMORY` key. The emulator — the reference semantics — must
/// refuse the same pointers rather than produce a trace no AIR can prove.
#[test]
fn a_keccak_pointer_past_the_provable_range_is_an_error() {
    const T0: u32 = 5;
    let program = |ptr: u32| {
        let mut a = Assembler::new(0);
        a.extend(li(REG_A7, SYS_KECCAK as i32));
        a.extend(li(REG_A0, ptr as i32));
        a.push(ecall());
        a.extend(li(T0, 1));
        a.extend(write_output(0, T0));
        a.extend(halt());
        a.assemble()
    };
    let limit = 0x3000_0000u32 - 50;
    assert!(matches!(
        execute(&program(limit + 1), &[], 1 << 16),
        Err(ExecError::KeccakPtrOutOfRange(p)) if p == limit + 1
    ));
    // The largest still-permitted pointer runs (and permutes 50 words of untouched zeros).
    let e = execute(&program(limit), &[], 1 << 16).unwrap();
    assert_eq!(e.events.iter().filter(|ev| ev.keccak_row.is_some()).count(), 1);
}
