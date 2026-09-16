use randprotocol_zkvm::guests;
use randprotocol_zkvm::isa::*;
use randprotocol_zkvm::machine::Tier;

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
    // Audit ZH2 (2026-09-12): the loader's ceiling is the 16-bit `HASH_LEFT` bound
    // (`tables::cpu`'s `LEFT0..1`), below the program table's `MAX_LOG_HEIGHT` shape ceiling.
    // One word past it — building the bytes of any decodable word (`ADDI x0, x0, 0`, encoding
    // 0x0000_0013) keeps this test about the length bound alone, not accidentally about a
    // decode failure.
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

// ---------------------------------------------------------------------------------------------
// M4.3's image container: a guest's `.text` plus a data segment the loader writes into RAM with a
// synthesised `li`/`sw` prologue (`Program::from_flat_image`).
// ---------------------------------------------------------------------------------------------

/// The compatibility guarantee the M4.3 loader has to keep: a container with **no** data segment
/// is the old flat binary. `keccak256.bin` — M4.2's committed exit guest — must come out of it
/// word-for-word identical, same `base_pc`, same `hc`, so wrapping an existing guest in the new
/// format can never change the program a verifier accepted.
#[test]
fn an_empty_data_segment_gives_exactly_the_flat_binary_program_and_hc() {
    const BIN: &[u8] = include_bytes!("../guests-compiled/bin/keccak256.bin");
    let flat = Program::from_flat_binary(0x1000, BIN).unwrap();
    let image = Program::to_flat_image(0x1000, &flat.words, 0, &[]);
    let loaded = Program::from_flat_image(&image).unwrap();
    assert_eq!(loaded, flat, "an empty data segment must not change the program");
    assert_eq!(loaded.base_pc, 0x1000, "and the text keeps its link address");
    assert_eq!(loaded.digest(), flat.digest(), "so hc is unchanged");
    assert_eq!(loaded.code_hash(), flat.code_hash());
}

/// The prologue runs before the guest's entry and leaves RAM holding the data segment: a text that
/// loads two data words and outputs them sees the *image's* values, not zeros.
#[test]
fn the_data_segment_is_in_ram_before_the_guest_entry_runs() {
    use randprotocol_zkvm::asm::{ops::*, Assembler};
    // The data: 0x20000 = 0xdead_beef, 0x20004 = 0 (skipped by the prologue, read back as zero),
    // 0x20008 = 42. `lw` offsets are from a base the text loads itself.
    let data_base = 0x2_0000u32;
    let data = [0xdead_beefu32, 0, 42];
    let mut a = Assembler::new(0); // base_pc is the container's, not the assembler's
    a.extend(li(5, data_base as i32));
    a.push(lw(6, 5, 0));
    a.push(lw(7, 5, 8));
    a.extend(write_output(0, 6));
    a.extend(write_output(1, 7));
    a.extend(halt());
    let text = a.assemble().words;

    let image = Program::to_flat_image(0x1_0000, &text, data_base, &data);
    let p = Program::from_flat_image(&image).unwrap();
    // the prologue sits immediately below the text: two non-zero words, `li`+`li`+`sw` each plus
    // one base load, and control falls through into the text with no jump
    assert!(p.base_pc < 0x1_0000 && p.words.len() > text.len());
    assert_eq!(p.words[p.words.len() - text.len()..], text[..], "the text is loaded verbatim");
    assert_eq!(p.base_pc + 4 * (p.words.len() - text.len()) as u32, 0x1_0000);

    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(12).max_cycles()).unwrap();
    assert_eq!(exec.outputs[0], 0xdead_beef, "the data word was never written to RAM");
    assert_eq!(exec.outputs[1], 42);

    // and it proves and verifies — the data is part of the program, so `hc` binds it
    let m = randprotocol_zkvm::machine::Machine::new(randprotocol_zkvm::machine::FriProfile::Test);
    let (proof, _) = m.prove(&p, &[], &[], None).unwrap();
    m.verify(&p.digest(), &proof).unwrap();
    // a different data segment is a different program: `hc` changes
    let other = Program::from_flat_image(&Program::to_flat_image(0x1_0000, &text, data_base, &[1, 0, 42])).unwrap();
    assert_ne!(other.digest(), p.digest());
}

/// Zero words cost nothing: the prologue writes only what is non-zero, because the memory table
/// constrains the first read of a fresh address to be zero.
#[test]
fn the_prologue_skips_zero_data_words() {
    let text = vec![0x0000_0013u32]; // NOP
    let none = Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0x2000, &[0; 64])).unwrap();
    assert_eq!(none.words, text, "an all-zero data segment needs no prologue at all");
    assert_eq!(none.base_pc, 0x1000);
    let one = Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0x2000, &[0, 0, 7, 0])).unwrap();
    // one non-zero word costs four instructions: `lui`+`addi` to point the base register at
    // 0x2008, one `addi` for the value (7 fits the immediate) and the `sw`.
    assert_eq!(one.words.len(), text.len() + 4);
}

/// A data segment wider than the store immediate's ±2 KiB reach: the prologue re-points its base
/// register rather than emitting an out-of-range offset (AGENTS.md invariant 3's bug class, which
/// `Instr::encode` would now panic on rather than silently truncate).
#[test]
fn the_prologue_repoints_its_base_register_past_the_immediate_range() {
    use randprotocol_zkvm::asm::{ops::*, Assembler};
    let data_base = 0x4_0000u32;
    let n = 2048; // 8 KiB of data, four times the immediate's reach
    let data: Vec<u32> = (0..n).map(|i| 0x100 + i as u32).collect();
    // read the first, middle and last word back
    let mut a = Assembler::new(0);
    a.extend(li(5, data_base as i32));
    a.push(lw(6, 5, 0));
    a.extend(li(8, (data_base + 4 * (n as u32 - 1)) as i32));
    a.push(lw(7, 8, 0));
    a.extend(write_output(0, 6));
    a.extend(write_output(1, 7));
    a.extend(halt());
    let text = a.assemble().words;
    let p = Program::from_flat_image(&Program::to_flat_image(0x2_0000, &text, data_base, &data)).unwrap();
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], Tier(14).max_cycles()).unwrap();
    assert_eq!(exec.outputs[0], 0x100);
    assert_eq!(exec.outputs[1], 0x100 + n as u32 - 1);
}

#[test]
fn the_image_loader_rejects_a_malformed_container() {
    let text = vec![0x0000_0013u32];
    let good = Program::to_flat_image(0x1000, &text, 0x2000, &[1]);
    assert_eq!(Program::from_flat_image(&[]), Err(LoadError::Empty));
    assert_eq!(Program::from_flat_image(&good[..good.len() - 1]), Err(LoadError::Length(good.len() - 1)));
    // a header that is not one
    assert_eq!(Program::from_flat_image(&[0u8; 4]), Err(LoadError::Length(4)));
    let mut bad_magic = good.clone();
    bad_magic[..4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(Program::from_flat_image(&bad_magic), Err(LoadError::Magic(0)));
    let mut bad_version = good.clone();
    bad_version[4..8].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(Program::from_flat_image(&bad_version), Err(LoadError::Version(2)));
    // segment lengths that do not account for the body
    let mut short = good.clone();
    short[12..16].copy_from_slice(&9u32.to_le_bytes()); // n_text = 9, body has 2 words
    assert_eq!(Program::from_flat_image(&short), Err(LoadError::Segments { n_text: 9, n_data: 1, words: 2 }));
    assert_eq!(
        Program::from_flat_image(&Program::to_flat_image(0x1000, &[], 0x2000, &[])),
        Err(LoadError::Segments { n_text: 0, n_data: 0, words: 0 }),
        "a container with no text is not a program"
    );
    // misaligned bases
    assert_eq!(Program::from_flat_image(&Program::to_flat_image(0x1002, &text, 0x2000, &[1])), Err(LoadError::Base(0x1002)));
    assert_eq!(Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0x2002, &[1])), Err(LoadError::Base(0x2002)));
    // a data segment whose last address does not fit a u32 — its own variant, so it is not confused
    // with a misaligned base
    assert_eq!(
        Program::from_flat_image(&Program::to_flat_image(0x1000, &text, 0xffff_fffc, &[1, 2])),
        Err(LoadError::Range { base: 0xffff_fffc, n_words: 2 })
    );
    // a data segment written over the text's own addresses: the prologue's stores would land on
    // addresses the guest's code and jump tables refer to. `mkimage.py` refuses to build such a
    // container; the loader is the trust boundary that must refuse to load one.
    let four = vec![0x0000_0013u32; 4]; // four NOPs at 0x1000..0x1010
    for data_base in [0x1000, 0x1004, 0x100c] {
        match Program::from_flat_image(&Program::to_flat_image(0x1000, &four, data_base, &[7, 7])) {
            Err(LoadError::Overlap { text_end: 0x1010, data_base: got }) => assert_eq!(got, data_base),
            other => panic!("expected Overlap at {data_base:#x}, got {other:?}"),
        }
    }
    // one word *below* the text still overlaps it (the data's own last word lands on 0x1000) …
    assert!(matches!(
        Program::from_flat_image(&Program::to_flat_image(0x1000, &four, 0xffc, &[7, 7])),
        Err(LoadError::Overlap { .. })
    ));
    // … while abutting the text on either side is fine, and is what the committed `evm.bin` does
    // (its `.rodata` starts exactly at the end of its `.text`).
    assert!(Program::from_flat_image(&Program::to_flat_image(0x1000, &four, 0x1010, &[7, 7])).is_ok());
    assert!(Program::from_flat_image(&Program::to_flat_image(0x1000, &four, 0xff8, &[7, 7])).is_ok());
    // a text linked too low for its own prologue: 64 non-zero words need 3 instructions each
    match Program::from_flat_image(&Program::to_flat_image(0x40, &text, 0x2000, &[0xdead_beef; 64])) {
        Err(LoadError::PrologueRoom { text_base: 0x40, words }) => assert!(words > 16, "{words}"),
        other => panic!("expected PrologueRoom, got {other:?}"),
    }
}

/// Constraint set 6: `H_PUB` is `H_IN`'s unsalted twin — `program_digest`'s header-and-chain
/// shape over `domain::PUB`, with no salt block, so a verifier holding the words can recompute
/// it (which is exactly what a salted `H_IN` cannot support).
#[test]
fn public_digest_is_the_unsalted_twin_of_the_program_digest() {
    use randprotocol_zkvm::hash::{public_digest, public_digest_row_count, public_digest_rows};
    // Header-only: one permutation even for an empty segment, so H_PUB is never the all-zero digest.
    assert_eq!(public_digest_row_count(0), 1);
    assert_eq!(public_digest_rows(&[]).len(), 1);
    assert_ne!(public_digest(&[]), [0u32; 8]);
    // One block per four words, ceil.
    assert_eq!(public_digest_row_count(1), 1);
    assert_eq!(public_digest_row_count(4), 1);
    assert_eq!(public_digest_row_count(5), 2);
    // Unsalted: a pure function of the words. Two calls agree; H_IN's does not (it takes a salt).
    assert_eq!(public_digest(&[1, 2, 3]), public_digest(&[1, 2, 3]));
    // Length is in the capacity header, so trailing zeros are not a collision.
    assert_ne!(public_digest(&[1, 2, 3]), public_digest(&[1, 2, 3, 0]));
    // The domain separates it from H_IN's own space and from hc's.
    assert_ne!(public_digest(&[1, 2, 3, 4]), randprotocol_zkvm::hash::input_digest([0; 4], &[1, 2, 3, 4]));
    // And the chain of blocks is the same overwrite-mode chain the other two digests use.
    let blocks = public_digest_rows(&[1, 2, 3, 4, 5]);
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].left_before, 5);
    assert_eq!(blocks[1].left_before, 1);
    assert_eq!(blocks[1].active, [true, false, false, false]);
    assert_eq!(randprotocol_zkvm::hash::split_digest([blocks[1].state_out[0], blocks[1].state_out[1], blocks[1].state_out[2], blocks[1].state_out[3]]), public_digest(&[1, 2, 3, 4, 5]));
}
