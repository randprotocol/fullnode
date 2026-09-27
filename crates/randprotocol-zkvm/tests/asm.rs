use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::guests;
use randprotocol_zkvm::isa::*;

#[test]
fn labels_resolve_to_relative_offsets() {
    let mut a = Assembler::new(0);
    a.push(addi(1, 0, 3));          // 0x00
    a.label("loop");                // 0x04
    a.push(addi(1, 1, -1));         // 0x04
    a.branch(BranchCond::Ne, 1, 0, "loop"); // 0x08 -> -4
    a.jal(0, "end");                // 0x0c -> +8
    a.push(addi(2, 0, 99));         // 0x10 (skipped)
    a.label("end");                 // 0x14
    for i in halt() { a.push(i); }
    let p = a.assemble();
    assert_eq!(p.instr_at(8), Some(Instr::Branch { cond: BranchCond::Ne, rs1: 1, rs2: 0, imm: (-4i32) as u32 }));
    assert_eq!(p.instr_at(12), Some(Instr::Jal { rd: 0, imm: 8 }));
}

#[test]
fn li_handles_negative_and_large_values() {
    // li expands to lui+addi; check by decoding and simulating the two steps
    for v in [0i32, 1, -1, 2047, 2048, -2048, -2049, 0x7fff_ffff, i32::MIN, 0x1234_5678] {
        let seq = li(5, v);
        let mut acc: u32 = 0;
        for i in seq {
            match i {
                Instr::Lui { imm, .. } => acc = imm,
                Instr::AluImm { op: AluOp::Add, imm, rs1, .. } => { if rs1 == 0 { acc = imm } else { acc = acc.wrapping_add(imm) } }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(acc, v as u32, "li {v}");
    }
}

#[test]
fn every_guest_decodes() {
    for (name, p, _inputs) in guests::all() {
        for (i, w) in p.words.iter().enumerate() {
            Instr::decode(*w).unwrap_or_else(|e| panic!("{name} word {i}: {e:?}"));
        }
    }
}

/// Audit ZM3 (2026-09-12): out-of-range immediates used to be silently truncated by `encode`
/// (`& 0xfff`, `bits(..)`) — wrong code, no error. They now panic at the choke point.
#[test]
#[should_panic(expected = "does not fit 12 bits")]
fn an_out_of_range_i_type_immediate_panics_at_encode() {
    let _ = addi(1, 1, 5000).encode();
}

#[test]
#[should_panic(expected = "does not fit 12 bits")]
fn an_out_of_range_store_offset_panics_at_encode() {
    let _ = sw(1, 2, 4096).encode();
}

#[test]
#[should_panic(expected = "does not fit 5 bits")]
fn an_out_of_range_shift_amount_panics_at_encode() {
    let _ = Instr::AluImm { op: AluOp::Sll, rd: 1, rs1: 2, imm: 32 }.encode();
}

/// The assembler's label path: a branch target past the 13-bit B-immediate range (±4096 bytes)
/// used to silently encode the wrong offset — even the wrong direction.
#[test]
#[should_panic(expected = "does not fit 13 bits")]
fn a_branch_to_a_far_label_panics_at_assemble() {
    let mut a = Assembler::new(0);
    a.branch(BranchCond::Eq, 0, 0, "far");
    for _ in 0..2000 { a.push(addi(0, 0, 0)); } // +8000 bytes: past +4095
    a.label("far");
    a.extend(halt());
    let _ = a.assemble();
}

/// `lui`/`auipc` with the low 12 bits set used to have them silently masked off.
#[test]
#[should_panic(expected = "low 12 bits set")]
fn a_lui_with_low_bits_set_panics_at_encode() {
    let _ = Instr::Lui { rd: 1, imm: 0xdead_beef }.encode();
}

#[test]
#[should_panic(expected = "at least one value")]
fn bubble_sort_rejects_empty_input() {
    let _ = guests::bubble_sort(&[]);
}

/// M4.2: `call_keccak` is the `KECCAK` syscall's three-instruction sequence — syscall number in
/// `a7`, the state's **word** address in `a0`, `ecall` — and every instruction of it round-trips
/// through the machine's own encoder.
#[test]
fn call_keccak_passes_the_syscall_number_and_a_word_address() {
    let seq = call_keccak(0x400 / 4);
    assert_eq!(seq, vec![addi(REG_A7, 0, SYS_KECCAK as i32), addi(REG_A0, 0, 0x400 / 4), Instr::Ecall]);
    for i in &seq { assert_eq!(Instr::decode(i.encode()).unwrap(), *i); }
}

/// Constraint set 6: `ops::read_public` is the `READ_PUBLIC` syscall's sequence — number 6 in
/// `a7`, the index in `a0`, `ecall` — and the emulator answers it from the public segment.
#[test]
fn ops_read_public_assembles_to_a7_six_and_a0_idx() {
    use randprotocol_zkvm::asm::{ops::read_public, Assembler};
    let mut a = Assembler::new(0);
    a.extend(read_public(9));
    a.extend(randprotocol_zkvm::asm::ops::halt());
    let p = a.assemble();
    let e = randprotocol_zkvm::emulator::execute(&p, &[], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 77], 100).unwrap();
    assert!(e.events.iter().any(|ev| matches!(ev.sys, Some(randprotocol_zkvm::emulator::Syscall::ReadPublic { idx: 9, word: 77 }))));
}

/// ISA-5 (the 2026-09-27 zkVM review): the `ops` helpers masked their operands *before* `encode`
/// could see them — `slli(rd, rs1, 33)` became a shift by 1, `lui(rd, 0xdead_beef)` became
/// `lui(rd, 0xdead_b000)` — so ZM3's range checks at `encode` never fired for code written
/// through them. The helpers now pass the operand through and `encode` refuses it.
#[test]
#[should_panic(expected = "does not fit 5 bits")]
fn an_out_of_range_shift_amount_panics_through_the_helper() {
    let _ = slli(1, 2, 33).encode();
}

#[test]
#[should_panic(expected = "does not fit 5 bits")]
fn an_out_of_range_srai_amount_panics_through_the_helper() {
    let _ = srai(1, 2, 32).encode();
}

#[test]
#[should_panic(expected = "low 12 bits set")]
fn a_lui_with_low_bits_set_panics_through_the_helper() {
    let _ = lui(1, 0xdead_beef).encode();
}

#[test]
#[should_panic(expected = "low 12 bits set")]
fn an_auipc_with_low_bits_set_panics_through_the_helper() {
    let _ = auipc(1, 0x0000_1001).encode();
}

/// A register index is a 5-bit field; `rd = 32` used to be shifted into `funct3`'s bits — a
/// different instruction, silently. `encode` refuses every register field above 31.
#[test]
#[should_panic(expected = "register")]
fn a_register_index_past_31_panics_at_encode() {
    let _ = addi(32, 0, 0).encode();
}

#[test]
#[should_panic(expected = "register")]
fn a_source_register_index_past_31_panics_at_encode() {
    let _ = add(1, 2, 40).encode();
}
