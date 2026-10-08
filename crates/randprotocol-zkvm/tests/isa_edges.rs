//! `isa.rs` at its edges: every immediate field at both ends of its range, the decode table
//! exhaustively over its funct bits, the reserved encodings it must refuse, the pre-decoded
//! selector set, and the two loaders' precedence and boundary cases.
//!
//! `tests/isa.rs` covers one representative of each instruction form; this file is the
//! boundary sweep around it. Everything here is host-side and instant.
use randprotocol_zkvm::isa::*;

// ─────────────────────────── immediates at both ends ───────────────────────────

fn roundtrip(i: Instr) {
    let w = i.encode();
    assert_eq!(Instr::decode(w), Ok(i), "word {w:#010x} for {i:?}");
}

#[test]
fn i_type_immediates_round_trip_at_both_ends_of_12_bits() {
    for imm in [-2048i32, -2047, -1, 0, 1, 2046, 2047] {
        let imm = imm as u32;
        roundtrip(Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 2, imm });
        roundtrip(Instr::AluImm { op: AluOp::Slt, rd: 1, rs1: 2, imm });
        roundtrip(Instr::AluImm { op: AluOp::Sltu, rd: 1, rs1: 2, imm });
        roundtrip(Instr::AluImm { op: AluOp::Xor, rd: 1, rs1: 2, imm });
        roundtrip(Instr::AluImm { op: AluOp::Or, rd: 1, rs1: 2, imm });
        roundtrip(Instr::AluImm { op: AluOp::And, rd: 1, rs1: 2, imm });
        roundtrip(Instr::Jalr { rd: 1, rs1: 2, imm });
        roundtrip(Instr::Load { rd: 1, rs1: 2, imm, width: Width::Word, signed: false });
        roundtrip(Instr::Load { rd: 1, rs1: 2, imm, width: Width::Byte, signed: true });
        roundtrip(Instr::Store { rs1: 2, rs2: 1, imm, width: Width::Word });
        roundtrip(Instr::Store { rs1: 2, rs2: 1, imm, width: Width::Half });
    }
}

#[test]
fn an_addi_of_minus_2048_decodes_as_add_not_sub() {
    // The top seven bits of the I-immediate are 0x40 here, which on an R-type word would be
    // SUB's funct7. The immediate opcode has no funct7: it is still ADD with imm = -2048.
    let w = Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 0, imm: (-2048i32) as u32 }.encode();
    assert_eq!(w, 0x8000_0093);
    assert_eq!(Instr::decode(w), Ok(Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 0, imm: 0xffff_f800 }));
    // And -1, whose top bits are all ones (an impossible funct7 on the R-type side).
    assert_eq!(Instr::decode(0xfff0_0093), Ok(Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 0, imm: 0xffff_ffff }));
}

#[test]
fn branch_offsets_round_trip_at_both_ends_of_13_bits_for_every_condition() {
    for cond in [BranchCond::Eq, BranchCond::Ne, BranchCond::Lt, BranchCond::Ge, BranchCond::Ltu, BranchCond::Geu] {
        for imm in [-4096i32, -4094, -2, 0, 2, 4092, 4094] {
            roundtrip(Instr::Branch { cond, rs1: 3, rs2: 4, imm: imm as u32 });
        }
    }
}

#[test]
fn jal_offsets_round_trip_at_both_ends_of_21_bits() {
    for imm in [-(1i32 << 20), -(1i32 << 20) + 2, -2, 0, 2, (1i32 << 20) - 4, (1i32 << 20) - 2] {
        roundtrip(Instr::Jal { rd: 1, imm: imm as u32 });
        roundtrip(Instr::Jal { rd: 0, imm: imm as u32 });
    }
}

#[test]
fn shift_amounts_round_trip_at_0_and_31() {
    for op in [AluOp::Sll, AluOp::Srl, AluOp::Sra] {
        for sh in [0u32, 1, 30, 31] {
            roundtrip(Instr::AluImm { op, rd: 1, rs1: 2, imm: sh });
        }
    }
    // The decoded shamt is the five rs2 bits, nothing else: `srai x1, x2, 31` is 0x41f1_5093.
    assert_eq!(Instr::AluImm { op: AluOp::Sra, rd: 1, rs1: 2, imm: 31 }.encode(), 0x41f1_5093);
    assert_eq!(Instr::decode(0x41f1_5093), Ok(Instr::AluImm { op: AluOp::Sra, rd: 1, rs1: 2, imm: 31 }));
}

#[test]
fn upper_immediates_round_trip_at_their_extremes() {
    for imm in [0u32, 0x0000_1000, 0x7fff_f000, 0x8000_0000, 0xffff_f000] {
        roundtrip(Instr::Lui { rd: 31, imm });
        roundtrip(Instr::Auipc { rd: 31, imm });
        roundtrip(Instr::Lui { rd: 0, imm });
    }
}

#[test]
fn register_fields_round_trip_at_0_and_31() {
    for (rd, rs1, rs2) in [(0, 0, 0), (31, 31, 31), (31, 0, 31), (0, 31, 0), (1, 2, 3)] {
        for op in AluOp::ALL {
            if op == AluOp::Eq { continue; }
            roundtrip(Instr::AluReg { op, rd, rs1, rs2 });
        }
        roundtrip(Instr::Branch { cond: BranchCond::Ltu, rs1, rs2, imm: 8 });
        roundtrip(Instr::Store { rs1, rs2, imm: 4, width: Width::Byte });
        roundtrip(Instr::Load { rd, rs1, imm: 4, width: Width::Half, signed: false });
        roundtrip(Instr::Jalr { rd, rs1, imm: 0 });
    }
}

// ─────────────────────────── the decode table, exhaustively ───────────────────────────

#[test]
fn every_opcode_outside_the_ten_known_ones_is_refused_by_its_opcode() {
    let known = [0x37u32, 0x17, 0x6f, 0x67, 0x63, 0x03, 0x23, 0x13, 0x33, 0x73];
    for op in 0u32..128 {
        let got = Instr::decode(op);
        if known.contains(&op) {
            assert!(got.is_ok(), "opcode {op:#04x} with every other field zero is a legal instruction: {got:?}");
        } else {
            assert_eq!(got, Err(DecodeError::Opcode(op)), "opcode {op:#04x}");
        }
    }
}

#[test]
fn r_type_decode_admits_exactly_the_rv32im_funct_pairs() {
    // Every (funct3, funct7) pair on the OP opcode: RV32I's funct7 ∈ {0, 0x20 (SUB/SRA only)},
    // RV32M's funct7 = 1; anything else is reserved.
    for f3 in 0u32..8 {
        for f7 in 0u32..128 {
            let w = f7 << 25 | 2 << 20 | 1 << 15 | f3 << 12 | 3 << 7 | 0x33;
            let legal = f7 == 0 || f7 == 1 || (f7 == 0x20 && (f3 == 0 || f3 == 5));
            let got = Instr::decode(w);
            assert_eq!(got.is_ok(), legal, "funct3 {f3} funct7 {f7:#04x}: {got:?}");
            if !legal {
                assert_eq!(got, Err(DecodeError::Funct((f7 << 3) | f3)));
            }
        }
    }
    // The two 0x20 forms decode to what the spec says they are.
    assert_eq!(Instr::decode(0x4020_80b3), Ok(Instr::AluReg { op: AluOp::Sub, rd: 1, rs1: 1, rs2: 2 }));
    assert_eq!(Instr::decode(0x4020_d0b3), Ok(Instr::AluReg { op: AluOp::Sra, rd: 1, rs1: 1, rs2: 2 }));
}

#[test]
fn i_type_alu_decode_admits_every_immediate_except_reserved_shift_funct7s() {
    for f3 in 0u32..8 {
        for imm in 0u32..4096 {
            let w = imm << 20 | 1 << 15 | f3 << 12 | 3 << 7 | 0x13;
            let f7 = imm >> 5;
            let legal = match f3 { 1 => f7 == 0, 5 => f7 == 0 || f7 == 0x20, _ => true };
            let got = Instr::decode(w);
            assert_eq!(got.is_ok(), legal, "funct3 {f3} imm {imm:#05x}: {got:?}");
            match got {
                Ok(Instr::AluImm { op, imm: got_imm, .. }) if f3 == 1 || f3 == 5 => {
                    assert_eq!(got_imm, imm & 31, "a shift's immediate is its five shamt bits");
                    assert_eq!(op, if f3 == 1 { AluOp::Sll } else if f7 == 0 { AluOp::Srl } else { AluOp::Sra });
                }
                Ok(Instr::AluImm { imm: got_imm, .. }) => assert_eq!(got_imm, ((imm << 20) as i32 >> 20) as u32, "sign-extended"),
                Ok(other) => panic!("{other:?}"),
                // Every reserved shift funct7 is reported through the funct table, which runs
                // before the shamt check — `DecodeError::Shamt` is never produced.
                Err(DecodeError::Funct(code)) => assert_eq!(code, (f7 << 3) | f3),
                Err(e) => panic!("{e:?}"),
            }
        }
    }
}

#[test]
fn reserved_branch_load_and_store_funct3s_are_refused() {
    for f3 in [2u32, 3] {
        assert_eq!(Instr::decode(f3 << 12 | 0x63), Err(DecodeError::Funct(f3)), "branch funct3 {f3}");
    }
    for f3 in [3u32, 6, 7] {
        assert_eq!(Instr::decode(f3 << 12 | 0x03), Err(DecodeError::Funct(f3)), "load funct3 {f3}");
    }
    for f3 in 3u32..8 {
        assert_eq!(Instr::decode(f3 << 12 | 0x23), Err(DecodeError::Funct(f3)), "store funct3 {f3}");
    }
    // The remaining load funct3s are the five widths.
    for (f3, width, signed) in [(0, Width::Byte, true), (1, Width::Half, true), (2, Width::Word, false), (4, Width::Byte, false), (5, Width::Half, false)] {
        assert_eq!(Instr::decode(f3 << 12 | 0x03), Ok(Instr::Load { rd: 0, rs1: 0, imm: 0, width, signed }));
    }
}

#[test]
fn only_the_bare_ecall_word_is_a_system_instruction() {
    assert_eq!(Instr::decode(0x0000_0073), Ok(Instr::Ecall));
    // ebreak, and any SYSTEM word with a register or funct field set, is not an instruction here.
    assert_eq!(Instr::decode(0x0010_0073), Err(DecodeError::Opcode(0x73)), "ebreak");
    assert_eq!(Instr::decode(0x0000_00f3), Err(DecodeError::Opcode(0x73)), "rd = 1");
    assert_eq!(Instr::decode(0x0000_1073), Err(DecodeError::Opcode(0x73)), "csrrw");
    assert_eq!(Instr::decode(0x3020_0073), Err(DecodeError::Opcode(0x73)), "mret");
}

#[test]
fn jalr_with_any_nonzero_funct3_is_refused_with_that_funct3() {
    for f3 in 1u32..8 {
        assert_eq!(Instr::decode(f3 << 12 | 0x67), Err(DecodeError::Funct(f3)));
    }
}

// ─────────────────────────── encode refuses what it cannot hold ───────────────────────────

#[test]
#[should_panic(expected = "JAL offset")]
fn a_jal_offset_of_two_to_the_20_panics_at_encode() {
    Instr::Jal { rd: 0, imm: 1 << 20 }.encode();
}

#[test]
#[should_panic(expected = "JAL offset")]
fn a_jal_offset_below_minus_two_to_the_20_panics_at_encode() {
    Instr::Jal { rd: 0, imm: (-(1i32 << 20) - 2) as u32 }.encode();
}

#[test]
#[should_panic(expected = "JAL offset")]
fn an_odd_jal_offset_panics_at_encode() {
    Instr::Jal { rd: 0, imm: 3 }.encode();
}

#[test]
#[should_panic(expected = "branch offset")]
fn a_branch_offset_of_4096_panics_at_encode() {
    Instr::Branch { cond: BranchCond::Eq, rs1: 0, rs2: 0, imm: 4096 }.encode();
}

#[test]
#[should_panic(expected = "branch offset")]
fn an_odd_branch_offset_panics_at_encode() {
    Instr::Branch { cond: BranchCond::Eq, rs1: 0, rs2: 0, imm: 5 }.encode();
}

#[test]
#[should_panic(expected = "does not fit 12 bits")]
fn a_jalr_offset_of_2048_panics_at_encode() {
    Instr::Jalr { rd: 0, rs1: 1, imm: 2048 }.encode();
}

#[test]
#[should_panic(expected = "does not fit 12 bits")]
fn a_load_offset_of_minus_2049_panics_at_encode() {
    Instr::Load { rd: 1, rs1: 1, imm: (-2049i32) as u32, width: Width::Word, signed: false }.encode();
}

#[test]
#[should_panic(expected = "does not fit 5 bits")]
fn a_negative_shift_amount_panics_at_encode() {
    Instr::AluImm { op: AluOp::Sll, rd: 1, rs1: 1, imm: (-1i32) as u32 }.encode();
}

#[test]
#[should_panic(expected = "low 12 bits set")]
fn an_auipc_with_low_bits_set_panics_at_encode() {
    Instr::Auipc { rd: 1, imm: 0x1001 }.encode();
}

// ─────────────────────────── the selector set ───────────────────────────

#[test]
fn every_instruction_sets_exactly_one_kind_selector() {
    let every: Vec<Instr> = vec![
        Instr::Lui { rd: 1, imm: 0x1000 },
        Instr::Auipc { rd: 1, imm: 0x1000 },
        Instr::Jal { rd: 1, imm: 8 },
        Instr::Jalr { rd: 1, rs1: 2, imm: 0 },
        Instr::Branch { cond: BranchCond::Lt, rs1: 1, rs2: 2, imm: 8 },
        Instr::Load { rd: 1, rs1: 2, imm: 0, width: Width::Byte, signed: true },
        Instr::Load { rd: 1, rs1: 2, imm: 0, width: Width::Half, signed: false },
        Instr::Load { rd: 1, rs1: 2, imm: 0, width: Width::Word, signed: false },
        Instr::Store { rs1: 1, rs2: 2, imm: 0, width: Width::Byte },
        Instr::Store { rs1: 1, rs2: 2, imm: 0, width: Width::Half },
        Instr::Store { rs1: 1, rs2: 2, imm: 0, width: Width::Word },
        Instr::AluImm { op: AluOp::Add, rd: 1, rs1: 2, imm: 1 },
        Instr::AluReg { op: AluOp::Mulhsu, rd: 1, rs1: 2, rs2: 3 },
        Instr::Ecall,
    ];
    for i in &every {
        let d = i.decoded();
        let kinds = [d.is_alu, d.is_branch, d.is_lb, d.is_lh, d.is_lw, d.is_sb, d.is_sh, d.is_sw, d.is_jal, d.is_jalr, d.is_lui, d.is_auipc, d.is_ecall];
        assert_eq!(kinds.iter().sum::<u32>(), 1, "{i:?}: {kinds:?}");
        assert!(kinds.iter().all(|k| *k <= 1));
        let expect_imm = matches!(i, Instr::Jalr { .. } | Instr::Load { .. } | Instr::Store { .. } | Instr::AluImm { .. });
        assert_eq!(d.is_imm == 1, expect_imm, "{i:?}: is_imm");
        assert_eq!(d.signed == 1, matches!(i, Instr::Load { signed: true, .. }), "{i:?}: signed");
        // Every selector is a bit; only the four operand fields may be anything else.
        for (k, f) in d.to_fields().iter().enumerate() {
            assert!(k < 4 || *f <= 1 || k == 5 || k == 8, "{i:?}: field {k} = {f}");
        }
    }
}

#[test]
fn writes_rd_is_zero_exactly_when_rd_is_x0() {
    let kinds: Vec<fn(u32) -> Instr> = vec![
        |rd| Instr::Lui { rd, imm: 0 },
        |rd| Instr::Auipc { rd, imm: 0 },
        |rd| Instr::Jal { rd, imm: 0 },
        |rd| Instr::Jalr { rd, rs1: 1, imm: 0 },
        |rd| Instr::Load { rd, rs1: 1, imm: 0, width: Width::Word, signed: false },
        |rd| Instr::AluImm { op: AluOp::Add, rd, rs1: 1, imm: 0 },
        |rd| Instr::AluReg { op: AluOp::Add, rd, rs1: 1, rs2: 2 },
    ];
    for k in &kinds {
        assert_eq!(k(0).decoded().writes_rd, 0, "{:?}", k(0));
        for rd in [1u32, 2, 10, 31] { assert_eq!(k(rd).decoded().writes_rd, 1, "{:?}", k(rd)); }
    }
    // Branches and stores never write; ecall's rd is a0 but the selector is clear (the syscall
    // decides at runtime, `emulator::execute`).
    assert_eq!(Instr::Branch { cond: BranchCond::Eq, rs1: 1, rs2: 2, imm: 8 }.decoded().writes_rd, 0);
    assert_eq!(Instr::Store { rs1: 1, rs2: 2, imm: 0, width: Width::Word }.decoded().writes_rd, 0);
    assert_eq!(Instr::Ecall.decoded().writes_rd, 0);
}

#[test]
fn to_fields_is_the_documented_23_field_order() {
    let d = Instr::Load { rd: 7, rs1: 9, imm: 0xffff_fffc, width: Width::Half, signed: false }.decoded();
    assert_eq!(d.to_fields(), [7, 9, 0, 0xffff_fffc, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let d = Instr::Branch { cond: BranchCond::Ltu, rs1: 3, rs2: 4, imm: 0xffff_fff8 }.decoded();
    assert_eq!(d.to_fields(), [0, 3, 4, 0xffff_fff8, 0, 0, 0, 1, AluOp::Sltu.code(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let d = Instr::AluReg { op: AluOp::Remu, rd: 5, rs1: 6, rs2: 7 }.decoded();
    assert_eq!(d.to_fields(), [5, 6, 7, 0, 1, AluOp::Remu.code(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert_eq!(Decoded::default().to_fields(), [0; 23]);
}

#[test]
fn branch_selectors_name_the_compare_and_its_negation() {
    let cases = [
        (BranchCond::Eq, AluOp::Eq, 0), (BranchCond::Ne, AluOp::Eq, 1),
        (BranchCond::Lt, AluOp::Slt, 0), (BranchCond::Ge, AluOp::Slt, 1),
        (BranchCond::Ltu, AluOp::Sltu, 0), (BranchCond::Geu, AluOp::Sltu, 1),
    ];
    for (cond, op, neg) in cases {
        let d = Instr::Branch { cond, rs1: 1, rs2: 2, imm: 4 }.decoded();
        assert_eq!((d.br_op, d.br_neg), (op.code(), neg), "{cond:?}");
        assert_eq!(cond.alu_op(), op);
        assert_eq!(cond.negate(), neg == 1);
    }
}

#[test]
fn alu_op_codes_are_dense_and_round_trip() {
    assert_eq!(AluOp::ALL.len(), AluOp::COUNT);
    for (i, op) in AluOp::ALL.iter().enumerate() {
        assert_eq!(op.code() as usize, i);
        assert_eq!(AluOp::from_code(op.code()), *op);
    }
}

#[test]
fn branch_conditions_take_at_the_signed_and_unsigned_boundaries() {
    let (min, max, neg1) = (0x8000_0000u32, 0x7fff_ffffu32, 0xffff_ffffu32);
    // (a, b): Eq Ne Lt Ge Ltu Geu
    let table = [
        ((min, max), [false, true, true, false, false, true]),
        ((max, min), [false, true, false, true, true, false]),
        ((neg1, 0), [false, true, true, false, false, true]),
        ((0, neg1), [false, true, false, true, true, false]),
        ((min, min), [true, false, false, true, false, true]),
        ((neg1, neg1), [true, false, false, true, false, true]),
        ((1, 2), [false, true, true, false, true, false]),
    ];
    let conds = [BranchCond::Eq, BranchCond::Ne, BranchCond::Lt, BranchCond::Ge, BranchCond::Ltu, BranchCond::Geu];
    for ((a, b), want) in table {
        for (cond, w) in conds.iter().zip(want) {
            assert_eq!(cond.taken(a, b), w, "{cond:?}({a:#x}, {b:#x})");
        }
        // Each pair of conditions is the other's negation.
        for k in [0, 2, 4] {
            assert_ne!(conds[k].taken(a, b), conds[k + 1].taken(a, b));
        }
    }
}

// ─────────────────────────── Program ───────────────────────────

#[test]
fn instr_at_answers_only_aligned_pcs_inside_the_program() {
    let p = Program::new(0x1000, vec![0x13, 0x13, 0x73]);
    assert_eq!(p.instr_at(0x0ffc), None, "below base");
    assert_eq!(p.instr_at(0x1001), None, "misaligned");
    assert_eq!(p.instr_at(0x1002), None, "misaligned");
    assert_eq!(p.instr_at(0x1000), Some(Instr::AluImm { op: AluOp::Add, rd: 0, rs1: 0, imm: 0 }));
    assert_eq!(p.instr_at(0x1008), Some(Instr::Ecall));
    assert_eq!(p.instr_at(0x100c), None, "one past the end");
    assert_eq!(p.pc_of(2), 0x1008);
    assert_eq!(p.len(), 3);
    assert!(!p.is_empty());
    // A word that does not decode is `None` too, not a panic — `instr_at` is the fetch path.
    let bad = Program::new(0, vec![0xffff_ffff]);
    assert_eq!(bad.instr_at(0), None);
}

#[test]
fn digest_rows_is_ceil_len_over_four_floored_at_one() {
    for (len, rows) in [(0usize, 1usize), (1, 1), (3, 1), (4, 1), (5, 2), (8, 2), (9, 3), (16, 4), (17, 5)] {
        let p = Program::new(0, vec![0x13; len]);
        assert_eq!(p.digest_rows(), rows, "len {len}");
        assert_eq!(randprotocol_zkvm::hash::program_digest_rows(0, &p.words).len(), rows);
    }
}

#[test]
fn code_hash_is_the_digest_as_64_hex_chars() {
    let p = Program::new(0x1000, vec![0x13, 0x73]);
    let h = p.code_hash();
    assert_eq!(h.len(), 64);
    assert_eq!(h, p.digest().iter().map(|w| format!("{w:08x}")).collect::<String>());
    assert_ne!(h, Program::new(0x1004, vec![0x13, 0x73]).code_hash(), "base_pc is in hc");
}

#[test]
#[should_panic]
fn a_program_with_a_misaligned_base_pc_panics() {
    Program::new(2, vec![0x13]);
}

// ─────────────────────────── the flat-binary loader ───────────────────────────

#[test]
fn flat_binary_errors_have_a_fixed_precedence() {
    // empty beats everything
    assert_eq!(Program::from_flat_binary(2, &[]), Err(LoadError::Empty));
    // length beats base_pc
    assert_eq!(Program::from_flat_binary(2, &[0x13, 0, 0, 0, 0x13]), Err(LoadError::Length(5)));
    for n in [1usize, 2, 3, 5, 6, 7, 9] {
        assert_eq!(Program::from_flat_binary(0, &vec![0x13u8; n]), Err(LoadError::Length(n)), "{n} bytes");
    }
    // base_pc beats decode
    assert_eq!(Program::from_flat_binary(2, &[0xff, 0xff, 0xff, 0xff]), Err(LoadError::BasePc(2)));
    for base in [1u32, 2, 3, 0xffff_fffe] {
        assert_eq!(Program::from_flat_binary(base, &0x13u32.to_le_bytes()), Err(LoadError::BasePc(base)));
    }
}

#[test]
fn flat_binary_names_the_first_undecodable_word_with_its_error() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x0000_0013u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_3003u32.to_le_bytes()); // load funct3 3
    bytes.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    assert_eq!(Program::from_flat_binary(0, &bytes), Err(LoadError::Decode { index: 1, word: 0x3003, err: DecodeError::Funct(3) }));
    let shamt = (0x0051_1093u32 | (1 << 25)).to_le_bytes();
    assert_eq!(Program::from_flat_binary(0, &shamt), Err(LoadError::Decode { index: 0, word: 0x0251_1093, err: DecodeError::Funct((1 << 3) | 1) }));
    let ebreak = 0x0010_0073u32.to_le_bytes();
    assert_eq!(Program::from_flat_binary(0, &ebreak), Err(LoadError::Decode { index: 0, word: 0x0010_0073, err: DecodeError::Opcode(0x73) }));
}

#[test]
fn flat_binary_accepts_65535_words_and_refuses_65536() {
    let nop = 0x0000_0013u32.to_le_bytes();
    let ok: Vec<u8> = nop.iter().copied().cycle().take(4 * 65535).collect();
    let p = Program::from_flat_binary(0x1000, &ok).unwrap();
    assert_eq!(p.len(), 65535);
    assert_eq!(p.digest_rows(), 16384);
    let too_long: Vec<u8> = nop.iter().copied().cycle().take(4 * 65536).collect();
    assert_eq!(Program::from_flat_binary(0x1000, &too_long), Err(LoadError::TooLong(65536)));
}

#[test]
fn flat_binary_round_trips_with_the_base_pc_carried_out_of_band() {
    let p = Program::new(0x8000, vec![0x0000_0013, 0x0050_0093, 0x0000_0073]);
    let bytes = p.to_flat_binary();
    assert_eq!(bytes.len(), 12);
    assert_eq!(&bytes[4..8], &[0x93, 0x00, 0x50, 0x00], "little-endian words");
    assert_eq!(Program::from_flat_binary(0x8000, &bytes), Ok(p.clone()));
    // The binary itself carries no base: the same bytes at another base are another program
    // with another digest.
    let other = Program::from_flat_binary(0x9000, &bytes).unwrap();
    assert_eq!(other.words, p.words);
    assert_ne!(other.digest(), p.digest());
}

// ─────────────────────────── the image loader ───────────────────────────

const NOP: u32 = 0x0000_0013;

#[test]
fn an_all_zero_data_segment_needs_no_prologue() {
    let text = vec![NOP, NOP, 0x73];
    let image = Program::to_flat_image(0x1000, &text, 0x2000, &[0, 0, 0, 0]);
    let p = Program::from_flat_image(&image).unwrap();
    let flat = Program::from_flat_binary(0x1000, &Program::new(0x1000, text.clone()).to_flat_binary()).unwrap();
    assert_eq!(p, flat, "zero words are not stored, so nothing precedes the text");
    assert_eq!(p.base_pc, 0x1000);
    assert_eq!(p.digest(), flat.digest());
}

#[test]
fn the_prologue_costs_two_or_three_instructions_per_nonzero_word() {
    let text = vec![NOP, 0x73];
    let prologue_len = |data: &[u32]| {
        let p = Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0x2000, data)).unwrap();
        assert_eq!(&p.words[p.len() - text.len()..], &text[..], "the text follows the prologue");
        assert_eq!(p.base_pc, 0x1000 - 4 * (p.len() - text.len()) as u32, "the prologue sits right below the text");
        p.len() - text.len()
    };
    // One window (`lui t1, 0x2000`: one instruction) plus, per non-zero word, `li t0` (one or
    // two instructions) and one `sw`.
    assert_eq!(prologue_len(&[1]), 1 + 1 + 1, "small value: addi + sw");
    assert_eq!(prologue_len(&[0x1000]), 1 + 1 + 1, "multiple of 4096: lui + sw");
    assert_eq!(prologue_len(&[0xdead_beef]), 1 + 2 + 1, "full word: lui + addi + sw");
    assert_eq!(prologue_len(&[1, 0, 0, 2]), 1 + 2 * 2, "zeros cost nothing");
    assert_eq!(prologue_len(&[0xdead_beef; 3]), 1 + 3 * 3);
}

#[test]
fn hc_binds_the_data_segment() {
    let text = vec![NOP, 0x73];
    let a = Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0x2000, &[1, 2])).unwrap();
    let b = Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0x2000, &[1, 3])).unwrap();
    let c = Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0x3000, &[1, 2])).unwrap();
    assert_ne!(a.digest(), b.digest(), "a different data word");
    assert_ne!(a.digest(), c.digest(), "the same data at a different address");
    assert_eq!(a.base_pc, b.base_pc);
}

#[test]
fn the_image_loader_checks_text_alignment_before_data_alignment() {
    let text = vec![NOP];
    assert_eq!(Program::from_flat_image(&Program::to_flat_image(0x1002, &text, 0x2002, &[1])), Err(LoadError::Base(0x1002)));
}

#[test]
fn a_text_segment_running_past_the_address_space_is_a_range_error() {
    let text = vec![NOP; 4];
    assert_eq!(
        Program::from_flat_image(&Program::to_flat_image(0xffff_fff4, &text, 0x1000, &[])),
        Err(LoadError::Range { base: 0xffff_fff4, n_words: 4 })
    );
    // Ending exactly at 2^32 counts as wrapping (`base + 4·n` must fit a u32).
    assert_eq!(
        Program::from_flat_image(&Program::to_flat_image(0xffff_fff0, &text, 0x1000, &[])),
        Err(LoadError::Range { base: 0xffff_fff0, n_words: 4 })
    );
    // And the text's range is checked before the data's.
    assert_eq!(
        Program::from_flat_image(&Program::to_flat_image(0xffff_fff0, &text, 0xffff_fffc, &[1, 2])),
        Err(LoadError::Range { base: 0xffff_fff0, n_words: 4 })
    );
}

#[test]
fn a_text_linked_too_low_for_a_single_data_word_is_refused_with_the_prologue_size() {
    // One non-zero word costs 3 instructions (lui t1; addi t0; sw) = 12 bytes; a text at 8
    // leaves 8.
    assert_eq!(
        Program::from_flat_image(&Program::to_flat_image(8, &[NOP], 0x2000, &[1])),
        Err(LoadError::PrologueRoom { text_base: 8, words: 3 })
    );
    // At 12 it fits exactly, and the program then starts at pc 0.
    let p = Program::from_flat_image(&Program::to_flat_image(12, &[NOP], 0x2000, &[1])).unwrap();
    assert_eq!(p.base_pc, 0);
    assert_eq!(p.len(), 4);
}

#[test]
fn an_image_whose_prologue_pushes_it_past_65535_words_is_too_long() {
    let text = vec![NOP; 65535];
    let fits = Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0x5_0000, &[])).unwrap();
    assert_eq!(fits.len(), 65535);
    assert_eq!(
        Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0x5_0000, &[1])),
        Err(LoadError::TooLong(65538)),
        "65535 text words plus a 3-word prologue"
    );
}

#[test]
fn the_image_header_is_six_little_endian_words() {
    let img = Program::to_flat_image(0x1000, &[NOP, 0x73], 0x2000, &[9]);
    assert_eq!(img.len(), 4 * (IMAGE_HEADER_WORDS + 3));
    let word = |i: usize| u32::from_le_bytes(img[4 * i..4 * i + 4].try_into().unwrap());
    assert_eq!(word(0), IMAGE_MAGIC);
    assert_eq!(&img[..4], b"RAND");
    assert_eq!(word(1), IMAGE_VERSION);
    assert_eq!((word(2), word(3), word(4), word(5)), (0x1000, 2, 0x2000, 1));
    assert_eq!((word(6), word(7), word(8)), (NOP, 0x73, 9));
    // Exactly the header, with no body at all, is a segment-count error, not a crash.
    assert_eq!(Program::from_flat_image(&img[..4 * IMAGE_HEADER_WORDS]), Err(LoadError::Segments { n_text: 2, n_data: 1, words: 0 }));
}
