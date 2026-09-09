use shrugg_zkvm::isa::*;

#[test]
fn alu_ops_match_reference_semantics() {
    assert_eq!(AluOp::Add.eval(0xffff_ffff, 1), 0);
    assert_eq!(AluOp::Sub.eval(0, 1), 0xffff_ffff);
    assert_eq!(AluOp::Sll.eval(1, 31), 0x8000_0000);
    assert_eq!(AluOp::Sll.eval(1, 32), 1);              // shift amount masked to 5 bits
    assert_eq!(AluOp::Srl.eval(0x8000_0000, 31), 1);
    assert_eq!(AluOp::Sra.eval(0x8000_0000, 31), 0xffff_ffff);
    assert_eq!(AluOp::Sra.eval(0x7fff_ffff, 4), 0x07ff_ffff);
    assert_eq!(AluOp::Slt.eval(0xffff_ffff, 0), 1);     // -1 < 0
    assert_eq!(AluOp::Slt.eval(0, 0xffff_ffff), 0);
    assert_eq!(AluOp::Sltu.eval(0xffff_ffff, 0), 0);
    assert_eq!(AluOp::Sltu.eval(0, 1), 1);
    assert_eq!(AluOp::Eq.eval(5, 5), 1);
    assert_eq!(AluOp::Eq.eval(5, 6), 0);
    assert_eq!(AluOp::Xor.eval(0xf0f0, 0x0ff0), 0xff00);
}

#[test]
fn encode_decode_roundtrip_every_variant() {
    let cases = vec![
        Instr::Lui { rd: 5, imm: 0xdead_b000 },
        Instr::Auipc { rd: 6, imm: 0x0000_1000 },
        Instr::Jal { rd: 1, imm: (-8i32) as u32 },
        Instr::Jalr { rd: 0, rs1: 1, imm: 0 },
        Instr::Branch { cond: BranchCond::Ne, rs1: 3, rs2: 4, imm: (-12i32) as u32 },
        Instr::Branch { cond: BranchCond::Geu, rs1: 3, rs2: 4, imm: 4094 },
        Instr::Lw { rd: 7, rs1: 2, imm: (-4i32) as u32 },
        Instr::Sw { rs1: 2, rs2: 7, imm: 2047 },
        Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 1, imm: (-1i32) as u32 },
        Instr::AluImm { op: AluOp::Sra, rd: 1, rs1: 1, imm: 7 },
        Instr::AluImm { op: AluOp::Srl, rd: 1, rs1: 1, imm: 31 },
        Instr::AluImm { op: AluOp::Sltu, rd: 1, rs1: 1, imm: 1 },
        Instr::AluReg { op: AluOp::Sub, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Sra, rd: 9, rs1: 10, rs2: 11 },
        Instr::Ecall,
    ];
    for i in cases {
        let w = i.encode();
        assert_eq!(Instr::decode(w).unwrap(), i, "word {w:#010x}");
    }
}

#[test]
fn known_encodings_match_the_riscv_spec() {
    // addi x1, x0, 5  = 0x00500093
    assert_eq!(Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 0, imm: 5 }.encode(), 0x0050_0093);
    // add x3, x1, x2 = 0x002081b3
    assert_eq!(Instr::AluReg { op: AluOp::Add, rd: 3, rs1: 1, rs2: 2 }.encode(), 0x0020_81b3);
    // ecall = 0x00000073
    assert_eq!(Instr::Ecall.encode(), 0x0000_0073);
    // beq x1, x2, +8 = 0x00208463
    assert_eq!(Instr::Branch { cond: BranchCond::Eq, rs1: 1, rs2: 2, imm: 8 }.encode(), 0x0020_8463);
    // lw x5, 4(x2) = 0x00412283
    assert_eq!(Instr::Lw { rd: 5, rs1: 2, imm: 4 }.encode(), 0x0041_2283);
    // sw x5, 4(x2) = 0x00512223
    assert_eq!(Instr::Sw { rs1: 2, rs2: 5, imm: 4 }.encode(), 0x0051_2223);
}

#[test]
fn decoded_selectors() {
    let d = Instr::AluImm { op: AluOp::Xor, rd: 3, rs1: 4, imm: 9 }.decoded();
    assert_eq!((d.is_alu, d.alu_op, d.is_imm, d.writes_rd, d.rd, d.rs1, d.imm), (1, 4, 1, 1, 3, 4, 9));
    let d = Instr::AluReg { op: AluOp::Add, rd: 0, rs1: 4, rs2: 5 }.decoded();
    assert_eq!(d.writes_rd, 0, "x0 is never written");
    let d = Instr::Branch { cond: BranchCond::Ge, rs1: 1, rs2: 2, imm: 8 }.decoded();
    assert_eq!((d.is_branch, d.br_op, d.br_neg, d.is_imm), (1, 8, 1, 0));
    let d = Instr::Ecall.decoded();
    assert_eq!((d.is_ecall, d.rs1, d.rs2, d.rd, d.writes_rd), (1, 17, 10, 10, 0));
    let d = Instr::Lw { rd: 2, rs1: 3, imm: 4 }.decoded();
    assert_eq!((d.is_load, d.is_imm, d.writes_rd), (1, 1, 1));
    assert_eq!(Decoded::NUM_FIELDS, 18);
    assert_eq!(d.to_fields()[0], 2);
}
