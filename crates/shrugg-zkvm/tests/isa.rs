use shrugg_zkvm::guests;
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
fn m_extension_matches_riscv_semantics() {
    assert_eq!(AluOp::Mul.eval(0xffff_ffff, 2), 0xffff_fffe);
    assert_eq!(AluOp::Mulhu.eval(0xffff_ffff, 0xffff_ffff), 0xffff_fffe);
    assert_eq!(AluOp::Mulh.eval((-2i32) as u32, (-3i32) as u32), 0);
    assert_eq!(AluOp::Mulhsu.eval((-1i32) as u32, 1), 0xffff_ffff);
    assert_eq!(AluOp::Divu.eval(10, 0), 0xffff_ffff);
    assert_eq!(AluOp::Remu.eval(10, 0), 10);
    assert_eq!(AluOp::Div.eval(0x8000_0000, 0xffff_ffff), 0x8000_0000);
    assert_eq!(AluOp::Rem.eval(0x8000_0000, 0xffff_ffff), 0);
    assert_eq!(AluOp::Divu.eval(10, 3), 3);
    assert_eq!(AluOp::Remu.eval(10, 3), 1);
    // DIV/REM by zero, signed side too.
    assert_eq!(AluOp::Div.eval((-5i32) as u32, 0), 0xffff_ffff);
    assert_eq!(AluOp::Rem.eval((-5i32) as u32, 0), (-5i32) as u32);
    // ordinary signed division/remainder, truncating toward zero.
    assert_eq!(AluOp::Div.eval((-7i32) as u32, 2), (-3i32) as u32);
    assert_eq!(AluOp::Rem.eval((-7i32) as u32, 2), (-1i32) as u32);
    assert_eq!(AluOp::Div.eval((-4i32) as u32, 2), (-2i32) as u32);
    assert_eq!(AluOp::Rem.eval((-4i32) as u32, 2), 0);
}

#[test]
fn m_extension_is_register_register_only_alu_imm_rejects_reserved_shift_funct7() {
    // The immediate opcode has no funct7 concept for non-shift ops (those bits are part of
    // the 12-bit immediate); the only place funct7 is meaningful in an I-type ALU encoding
    // is the shift-immediate family (SLLI/SRLI/SRAI), where it must be 0 or 0x20. This locks
    // in that funct7 = 1 (the M-extension's selector on the R-type opcode) is never a valid
    // shift-immediate encoding: `slli x1, x2, 5` = 0x0051_1093; forcing its funct7 bits to 1
    // (reserved, matching neither SLLI's 0 nor SRAI's 0x20) must be rejected.
    let w = 0x0051_1093 | (1 << 25);
    assert!(Instr::decode(w).is_err());
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
        Instr::Load { rd: 7, rs1: 2, imm: (-4i32) as u32, width: Width::Word, signed: false },
        Instr::Store { rs1: 2, rs2: 7, imm: 2047, width: Width::Word },
        Instr::Load { rd: 3, rs1: 2, imm: 8, width: Width::Byte, signed: true },
        Instr::Load { rd: 3, rs1: 2, imm: 8, width: Width::Byte, signed: false },
        Instr::Load { rd: 3, rs1: 2, imm: 8, width: Width::Half, signed: true },
        Instr::Load { rd: 3, rs1: 2, imm: 8, width: Width::Half, signed: false },
        Instr::Store { rs1: 2, rs2: 7, imm: 8, width: Width::Byte },
        Instr::Store { rs1: 2, rs2: 7, imm: 8, width: Width::Half },
        Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 1, imm: (-1i32) as u32 },
        Instr::AluImm { op: AluOp::Sra, rd: 1, rs1: 1, imm: 7 },
        Instr::AluImm { op: AluOp::Srl, rd: 1, rs1: 1, imm: 31 },
        Instr::AluImm { op: AluOp::Sltu, rd: 1, rs1: 1, imm: 1 },
        Instr::AluReg { op: AluOp::Sub, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Sra, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Mul, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Mulh, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Mulhu, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Mulhsu, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Div, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Divu, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Rem, rd: 9, rs1: 10, rs2: 11 },
        Instr::AluReg { op: AluOp::Remu, rd: 9, rs1: 10, rs2: 11 },
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
    assert_eq!(Instr::Load { rd: 5, rs1: 2, imm: 4, width: Width::Word, signed: false }.encode(), 0x0041_2283);
    // sw x5, 4(x2) = 0x00512223
    assert_eq!(Instr::Store { rs1: 2, rs2: 5, imm: 4, width: Width::Word }.encode(), 0x0051_2223);
    // lb x5, 4(x2) = 0x00410283
    assert_eq!(Instr::Load { rd: 5, rs1: 2, imm: 4, width: Width::Byte, signed: true }.encode(), 0x0041_0283);
    // lbu x5, 4(x2) = 0x00414283
    assert_eq!(Instr::Load { rd: 5, rs1: 2, imm: 4, width: Width::Byte, signed: false }.encode(), 0x0041_4283);
    // lh x5, 4(x2) = 0x00411283
    assert_eq!(Instr::Load { rd: 5, rs1: 2, imm: 4, width: Width::Half, signed: true }.encode(), 0x0041_1283);
    // lhu x5, 4(x2) = 0x00415283
    assert_eq!(Instr::Load { rd: 5, rs1: 2, imm: 4, width: Width::Half, signed: false }.encode(), 0x0041_5283);
    // sb x5, 4(x2) = 0x00510223
    assert_eq!(Instr::Store { rs1: 2, rs2: 5, imm: 4, width: Width::Byte }.encode(), 0x0051_0223);
    // sh x5, 4(x2) = 0x00511223
    assert_eq!(Instr::Store { rs1: 2, rs2: 5, imm: 4, width: Width::Half }.encode(), 0x0051_1223);
    // mul x3, x1, x2 = 0x022081b3 (funct7 = 1, funct3 = 0)
    assert_eq!(Instr::AluReg { op: AluOp::Mul, rd: 3, rs1: 1, rs2: 2 }.encode(), 0x0220_81b3);
    // div x3, x1, x2 = 0x0220c1b3 (funct7 = 1, funct3 = 4)
    assert_eq!(Instr::AluReg { op: AluOp::Div, rd: 3, rs1: 1, rs2: 2 }.encode(), 0x0220_c1b3);
    // remu x3, x1, x2 = 0x0220f1b3 (funct7 = 1, funct3 = 7)
    assert_eq!(Instr::AluReg { op: AluOp::Remu, rd: 3, rs1: 1, rs2: 2 }.encode(), 0x0220_f1b3);
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
    let d = Instr::Load { rd: 2, rs1: 3, imm: 4, width: Width::Word, signed: false }.decoded();
    assert_eq!((d.is_lw, d.is_imm, d.writes_rd), (1, 1, 1));
    assert_eq!(Decoded::NUM_FIELDS, 23);
    assert_eq!(d.to_fields()[0], 2);

    let d = Instr::Load { rd: 2, rs1: 3, imm: 4, width: Width::Byte, signed: true }.decoded();
    assert_eq!((d.is_lb, d.is_lh, d.is_lw, d.signed), (1, 0, 0, 1));
    let d = Instr::Load { rd: 2, rs1: 3, imm: 4, width: Width::Byte, signed: false }.decoded();
    assert_eq!((d.is_lb, d.signed), (1, 0));
    let d = Instr::Load { rd: 2, rs1: 3, imm: 4, width: Width::Half, signed: true }.decoded();
    assert_eq!((d.is_lh, d.signed), (1, 1));
    let d = Instr::Store { rs1: 2, rs2: 3, imm: 4, width: Width::Byte }.decoded();
    assert_eq!((d.is_sb, d.is_sh, d.is_sw), (1, 0, 0));
    let d = Instr::Store { rs1: 2, rs2: 3, imm: 4, width: Width::Half }.decoded();
    assert_eq!((d.is_sb, d.is_sh, d.is_sw), (0, 1, 0));
}

#[test]
fn flat_binary_round_trips_every_guest() {
    for (name, program, _inputs) in guests::all() {
        let bytes = program.to_flat_binary();
        let reloaded = Program::from_flat_binary(program.base_pc, &bytes)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(reloaded, program, "{name}: round trip changed the program");
    }
}

#[test]
fn flat_binary_rejects_empty() {
    assert_eq!(Program::from_flat_binary(0, &[]), Err(LoadError::Empty));
}

#[test]
fn flat_binary_rejects_length_not_a_multiple_of_four() {
    assert_eq!(Program::from_flat_binary(0, &[1, 2, 3]), Err(LoadError::Length(3)));
}

#[test]
fn flat_binary_rejects_misaligned_base_pc() {
    let bytes = guests::fib(1).to_flat_binary();
    assert_eq!(Program::from_flat_binary(2, &bytes), Err(LoadError::BasePc(2)));
}

#[test]
fn flat_binary_rejects_a_program_longer_than_the_table_can_hold() {
    // The loader's ceiling is the 16-bit `HASH_LEFT` bound (`tables::cpu`'s `LEFT0..1`),
    // below the program table's `MAX_LOG_HEIGHT` shape ceiling. One word past it — building
    // the bytes of any decodable word (`ADDI x0, x0, 0`, encoding 0x0000_0013) keeps this
    // test about the length bound alone, not accidentally about a decode failure.
    let max_words = u16::MAX as usize;
    let bytes = vec![0x13u8, 0x00, 0x00, 0x00].repeat(max_words + 1);
    assert_eq!(
        Program::from_flat_binary(0, &bytes),
        Err(LoadError::TooLong(max_words + 1))
    );
}

#[test]
fn flat_binary_reports_the_index_of_an_undecodable_word() {
    // Two good words, then a raw all-ones word `Instr::decode` rejects (opcode 0x7f is not
    // any of `OP_LUI/AUIPC/JAL/JALR/BRANCH/LOAD/STORE/ALUI/ALU/SYSTEM`).
    let mut bytes = vec![0x13u8, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    match Program::from_flat_binary(0, &bytes) {
        Err(LoadError::Decode { index: 2, word: 0xffff_ffff, .. }) => {}
        other => panic!("expected Decode{{index:2,..}}, got {other:?}"),
    }
}
