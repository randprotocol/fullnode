//! `asm.rs` at its edges: `li` over every boundary of the lui/addi split (checked by running the
//! result, not by inspecting it), the instruction counts the syscall helpers promise, and the
//! assembler's label rules.
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::emulator::{execute, ExecError};
use randprotocol_zkvm::isa::*;

const T0: u32 = 5;

/// Materialises each value with `li` into s4..s11 and publishes them, eight at a time.
fn li_values(values: &[i32]) -> Vec<u32> {
    let mut out = Vec::new();
    for chunk in values.chunks(8) {
        let mut a = Assembler::new(0);
        for (i, v) in chunk.iter().enumerate() {
            a.extend(li(20 + i as u32, *v));
        }
        for i in 0..chunk.len() {
            a.extend(write_output(i as u32, 20 + i as u32));
        }
        a.extend(halt());
        let e = execute(&a.assemble(), &[], &[], 1 << 12).unwrap();
        out.extend_from_slice(&e.outputs[..chunk.len()]);
    }
    out
}

#[test]
fn li_materialises_every_boundary_of_the_lui_addi_split() {
    let edges = [
        0i32, 1, -1, 2047, 2048, -2048, -2049, 0x7ff, 0x800, 0xfff, 0x1000, 0x17ff, 0x1800,
        0x7fff_ffff, 0x7fff_f800, 0x7fff_f7ff, i32::MIN, i32::MIN + 1, i32::MIN + 2048, i32::MIN + 2047,
        0x1234_5678, -0x1234_5678, 0xffff_f7ffu32 as i32, 0xffff_f800u32 as i32, 0x8000_07ffu32 as i32,
        0x8000_0800u32 as i32, 0x0000_8000, -0x8000, 0x7fff, -0x7fff,
    ];
    assert_eq!(li_values(&edges), edges.iter().map(|v| *v as u32).collect::<Vec<_>>());
}

#[test]
fn li_materialises_random_values_exactly() {
    use rand::Rng;
    let mut rng = rand::rng();
    let values: Vec<i32> = (0..512).map(|_| rng.next_u32() as i32).collect();
    assert_eq!(li_values(&values), values.iter().map(|v| *v as u32).collect::<Vec<_>>());
}

#[test]
fn li_uses_one_instruction_when_it_can_and_two_otherwise() {
    for v in [0i32, 2047, -2048] {
        assert_eq!(li(T0, v).len(), 1, "{v}: addi alone");
        assert_eq!(li(T0, v)[0], addi(T0, 0, v));
    }
    for v in [0x1000i32, 0x7fff_f000, i32::MIN] {
        assert_eq!(li(T0, v).len(), 1, "{v:#x}: lui alone");
        assert_eq!(li(T0, v)[0], lui(T0, v as u32));
    }
    for v in [2048i32, -2049, 0x1234_5678, -1 - 0x1000] {
        let seq = li(T0, v);
        assert_eq!(seq.len(), 2, "{v:#x}: lui + addi");
        assert!(matches!(seq[0], Instr::Lui { rd, .. } if rd == T0));
        assert!(matches!(seq[1], Instr::AluImm { op: AluOp::Add, rd, rs1, .. } if rd == T0 && rs1 == T0));
    }
}

#[test]
fn the_syscall_helpers_have_fixed_instruction_counts_and_registers() {
    assert_eq!(halt().len(), 2);
    assert_eq!(halt(), vec![addi(REG_A7, 0, SYS_HALT as i32), ecall()]);
    assert_eq!(write_output(3, T0), vec![addi(REG_A7, 0, SYS_WRITE_OUTPUT as i32), addi(REG_A0, 0, 3), mv(REG_A1, T0), ecall()]);
    assert_eq!(read_input(2), vec![addi(REG_A7, 0, SYS_READ_INPUT as i32), addi(REG_A0, 0, 2), ecall()]);
    assert_eq!(read_public(2), vec![addi(REG_A7, 0, SYS_READ_PUBLIC as i32), addi(REG_A0, 0, 2), ecall()]);
    assert_eq!(call_poseidon2(0x40, 9).len(), 4);
    assert_eq!(call_poseidon2(0x4000, 9).len(), 4, "a pointer with a zero low part is one lui");
    assert_eq!(call_poseidon2(0x4001, 9).len(), 5, "a wide pointer with a low part costs lui + addi");
    assert_eq!(call_poseidon2_len(0x40, 9)[0], addi(REG_A7, 0, SYS_POSEIDON2_LEN as i32));
    assert_eq!(call_keccak(0x40), vec![addi(REG_A7, 0, SYS_KECCAK as i32), addi(REG_A0, 0, 0x40), ecall()]);
    assert_eq!(call_sha256(0x40), vec![addi(REG_A7, 0, SYS_SHA256 as i32), addi(REG_A0, 0, 0x40), ecall()]);
    assert_eq!(mv(1, 2), addi(1, 2, 0));
}

#[test]
fn labels_resolve_forward_backward_and_at_the_end_of_the_program() {
    let mut a = Assembler::new(0x100);
    a.label("start");                          // index 0
    a.push(addi(T0, T0, 1));
    a.jal(0, "fwd");                           // index 1 -> index 4: +12
    a.push(addi(T0, T0, 100));
    a.push(addi(T0, T0, 100));
    a.label("fwd");                            // index 4
    a.branch(BranchCond::Eq, 0, 0, "start");   // index 4 -> 0: -16 … but only taken once below
    a.label("end");                            // index 5 == len
    let p = a.assemble();
    assert_eq!(p.len(), 5);
    assert_eq!(p.instr_at(0x104), Some(Instr::Jal { rd: 0, imm: 12 }));
    assert_eq!(p.instr_at(0x110), Some(Instr::Branch { cond: BranchCond::Eq, rs1: 0, rs2: 0, imm: (-16i32) as u32 }));
    // `beq x0, x0` always jumps back, so this spins until the budget runs out.
    assert_eq!(execute(&p, &[], &[], 50).unwrap_err(), ExecError::OutOfCycles(50));

    // A jump to a label placed after the last instruction lands one past the end.
    let mut a = Assembler::new(0);
    a.jal(0, "end");
    a.push(addi(T0, T0, 1));
    a.label("end");
    let p = a.assemble();
    assert_eq!(p.instr_at(0), Some(Instr::Jal { rd: 0, imm: 8 }));
    assert_eq!(execute(&p, &[], &[], 50).unwrap_err(), ExecError::BadPc(8));
}

#[test]
fn a_branch_to_its_own_label_spins_in_place() {
    let mut a = Assembler::new(0);
    a.label("here");
    a.branch(BranchCond::Eq, 0, 0, "here");
    let p = a.assemble();
    assert_eq!(p.words, vec![Instr::Branch { cond: BranchCond::Eq, rs1: 0, rs2: 0, imm: 0 }.encode()]);
    let err = execute(&p, &[], &[], 7).unwrap_err();
    assert_eq!(err, ExecError::OutOfCycles(7));
}

#[test]
#[should_panic(expected = "duplicate label")]
fn a_duplicate_label_panics() {
    let mut a = Assembler::new(0);
    a.label("l");
    a.push(addi(0, 0, 0));
    a.label("l");
}

#[test]
#[should_panic(expected = "unknown label")]
fn an_unknown_label_panics_at_assemble() {
    let mut a = Assembler::new(0);
    a.jal(0, "nowhere");
    a.assemble();
}

#[test]
#[should_panic(expected = "does not fit 13 bits")]
fn a_backward_branch_past_4096_bytes_panics_at_assemble() {
    let mut a = Assembler::new(0);
    a.label("top");
    for _ in 0..1025 { a.push(addi(0, 0, 0)); }
    a.branch(BranchCond::Eq, 0, 0, "top");   // -4100
    a.assemble();
}

#[test]
fn a_backward_branch_of_exactly_4096_bytes_assembles() {
    let mut a = Assembler::new(0);
    a.label("top");
    for _ in 0..1024 { a.push(addi(0, 0, 0)); }
    a.branch(BranchCond::Eq, 0, 0, "top");   // -4096, the most negative 13-bit offset
    let p = a.assemble();
    assert_eq!(Instr::decode(*p.words.last().unwrap()), Ok(Instr::Branch { cond: BranchCond::Eq, rs1: 0, rs2: 0, imm: (-4096i32) as u32 }));
    let mut a = Assembler::new(0);
    a.label("top");
    for _ in 0..1024 { a.push(addi(0, 0, 0)); }
    a.jal(0, "top");                         // -4096: fine for JAL
    let p = a.assemble();
    assert_eq!(Instr::decode(*p.words.last().unwrap()), Ok(Instr::Jal { rd: 0, imm: (-4096i32) as u32 }));
}
