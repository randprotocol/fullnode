//! The SBPF v1 instruction encoding (M4.4 Task 5): `isa::decode` is a byte split of one 8-byte
//! slot, and every opcode byte the interpreter implements is classified — with the v2-only bytes
//! (the `BPF_PQR` class, `HOR64_IMM`, `RETURN`) deliberately unclassified, so they trap.
//!
//! The byte values are checked against `solana-sbpf` 0.11.1's own `ebpf` constants, which is the
//! differential oracle for everything above this layer (`tests/sbpf_interp.rs`).

use sbpf_core::isa::{self, opc, Class, Insn};

fn slot(bytes: [u8; 8]) -> u64 {
    u64::from_le_bytes(bytes)
}

#[test]
fn decode_splits_the_slot_fields() {
    // `add64 r1, 5`: opcode, then `src << 4 | dst`, then the 16-bit offset, then the 32-bit imm.
    let i = isa::decode(slot([0x07, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00]));
    assert_eq!(i, Insn { opc: opc::ADD64_IMM, dst: 1, src: 0, off: 0, imm: 5 });

    // `src` is the high nibble of byte 1, `dst` the low one: `mov64 r1, r3`.
    let i = isa::decode(slot([0xbf, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    assert_eq!((i.opc, i.dst, i.src), (opc::MOV64_REG, 1, 3));

    // A negative `off` and a negative `imm` sign-extend out of their fields.
    let i = isa::decode(slot([0x15, 0x02, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff]));
    assert_eq!((i.opc, i.dst, i.off, i.imm), (opc::JEQ_IMM, 2, -2, -1));
    let i = isa::decode(slot([0x15, 0x02, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80]));
    assert_eq!((i.off, i.imm), (i16::MIN, i32::MIN));

    // Registers only ever come out of a nibble, so nothing can index past r15 (let alone r10).
    let i = isa::decode(slot([0xbf, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
    assert_eq!((i.dst, i.src), (15, 15));
}

#[test]
fn lddw_pairs_two_slots_into_one_imm64() {
    let lo = isa::decode(slot([0x18, 0x01, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12]));
    let hi = isa::decode(slot([0x00, 0x00, 0x00, 0x00, 0xf0, 0xde, 0xbc, 0x9a]));
    assert_eq!(lo.opc, opc::LD_DW_IMM);
    assert_eq!(isa::lddw_imm64(lo, hi), 0x9abc_def0_1234_5678);

    // The low half is taken as *unsigned* 32 bits: a negative low imm must not smear ones into
    // the high half (this is `solana_sbpf::ebpf::augment_lddw_unchecked`'s masking).
    let lo = isa::decode(slot([0x18, 0x01, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff]));
    let hi = isa::decode(slot([0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]));
    assert_eq!(isa::lddw_imm64(lo, hi), 0x0000_0001_ffff_ffff);
}

/// Every opcode byte the SBPF v1 interpreter implements, with the class `isa::classify` must put
/// it in. Transcribed from the M4.4 plan's Task 5 interface list and cross-checked below against
/// `solana_sbpf::ebpf`'s constants of the same names.
#[rustfmt::skip]
const V1_OPCODES: &[(u8, Class)] = &[
    (opc::LD_DW_IMM, Class::Ld),
    (opc::LD_B_REG, Class::Ld), (opc::LD_H_REG, Class::Ld), (opc::LD_W_REG, Class::Ld), (opc::LD_DW_REG, Class::Ld),
    (opc::ST_B_IMM, Class::St), (opc::ST_H_IMM, Class::St), (opc::ST_W_IMM, Class::St), (opc::ST_DW_IMM, Class::St),
    (opc::ST_B_REG, Class::St), (opc::ST_H_REG, Class::St), (opc::ST_W_REG, Class::St), (opc::ST_DW_REG, Class::St),
    (opc::ADD32_IMM, Class::Alu32), (opc::ADD32_REG, Class::Alu32),
    (opc::SUB32_IMM, Class::Alu32), (opc::SUB32_REG, Class::Alu32),
    (opc::MUL32_IMM, Class::Alu32), (opc::MUL32_REG, Class::Alu32),
    (opc::DIV32_IMM, Class::Alu32), (opc::DIV32_REG, Class::Alu32),
    (opc::OR32_IMM, Class::Alu32), (opc::OR32_REG, Class::Alu32),
    (opc::AND32_IMM, Class::Alu32), (opc::AND32_REG, Class::Alu32),
    (opc::LSH32_IMM, Class::Alu32), (opc::LSH32_REG, Class::Alu32),
    (opc::RSH32_IMM, Class::Alu32), (opc::RSH32_REG, Class::Alu32),
    (opc::NEG32, Class::Alu32),
    (opc::MOD32_IMM, Class::Alu32), (opc::MOD32_REG, Class::Alu32),
    (opc::XOR32_IMM, Class::Alu32), (opc::XOR32_REG, Class::Alu32),
    (opc::MOV32_IMM, Class::Alu32), (opc::MOV32_REG, Class::Alu32),
    (opc::ARSH32_IMM, Class::Alu32), (opc::ARSH32_REG, Class::Alu32),
    (opc::LE, Class::Alu32), (opc::BE, Class::Alu32),
    (opc::ADD64_IMM, Class::Alu64), (opc::ADD64_REG, Class::Alu64),
    (opc::SUB64_IMM, Class::Alu64), (opc::SUB64_REG, Class::Alu64),
    (opc::MUL64_IMM, Class::Alu64), (opc::MUL64_REG, Class::Alu64),
    (opc::DIV64_IMM, Class::Alu64), (opc::DIV64_REG, Class::Alu64),
    (opc::OR64_IMM, Class::Alu64), (opc::OR64_REG, Class::Alu64),
    (opc::AND64_IMM, Class::Alu64), (opc::AND64_REG, Class::Alu64),
    (opc::LSH64_IMM, Class::Alu64), (opc::LSH64_REG, Class::Alu64),
    (opc::RSH64_IMM, Class::Alu64), (opc::RSH64_REG, Class::Alu64),
    (opc::NEG64, Class::Alu64),
    (opc::MOD64_IMM, Class::Alu64), (opc::MOD64_REG, Class::Alu64),
    (opc::XOR64_IMM, Class::Alu64), (opc::XOR64_REG, Class::Alu64),
    (opc::MOV64_IMM, Class::Alu64), (opc::MOV64_REG, Class::Alu64),
    (opc::ARSH64_IMM, Class::Alu64), (opc::ARSH64_REG, Class::Alu64),
    (opc::JA, Class::Jmp),
    (opc::JEQ_IMM, Class::Jmp), (opc::JEQ_REG, Class::Jmp),
    (opc::JGT_IMM, Class::Jmp), (opc::JGT_REG, Class::Jmp),
    (opc::JGE_IMM, Class::Jmp), (opc::JGE_REG, Class::Jmp),
    (opc::JLT_IMM, Class::Jmp), (opc::JLT_REG, Class::Jmp),
    (opc::JLE_IMM, Class::Jmp), (opc::JLE_REG, Class::Jmp),
    (opc::JSET_IMM, Class::Jmp), (opc::JSET_REG, Class::Jmp),
    (opc::JNE_IMM, Class::Jmp), (opc::JNE_REG, Class::Jmp),
    (opc::JSGT_IMM, Class::Jmp), (opc::JSGT_REG, Class::Jmp),
    (opc::JSGE_IMM, Class::Jmp), (opc::JSGE_REG, Class::Jmp),
    (opc::JSLT_IMM, Class::Jmp), (opc::JSLT_REG, Class::Jmp),
    (opc::JSLE_IMM, Class::Jmp), (opc::JSLE_REG, Class::Jmp),
    (opc::CALL_IMM, Class::Call), (opc::CALL_REG, Class::Call),
    (opc::EXIT, Class::Exit),
];

#[test]
fn every_v1_opcode_byte_is_classified() {
    // The plan's interface list names 91 opcode bytes (its "112" counts the names in prose, not
    // the distinct bytes); the count is pinned so a dropped line cannot silently shrink the ISA.
    assert_eq!(V1_OPCODES.len(), 91);
    let mut seen = [false; 256];
    for &(byte, class) in V1_OPCODES {
        assert!(!seen[byte as usize], "opcode byte {byte:#04x} listed twice");
        seen[byte as usize] = true;
        assert_eq!(isa::classify(byte), Some(class), "opcode byte {byte:#04x}");
    }
}

#[test]
fn the_v2_only_opcode_bytes_are_not_classified() {
    // The whole `BPF_PQR` class (SDIV/SREM/UDIV/UREM/LMUL/UHMUL/SHMUL) plus `HOR64_IMM` and
    // `RETURN` exist only from SBPF v2 on, so v1 must not recognise any of them.
    let v2_only: &[u8] = &[
        0x86, 0x8e, 0x96, 0x9e, // LMUL32/64 imm+reg
        0x36, 0x3e, // UHMUL64 imm+reg
        0xb6, 0xbe, // SHMUL64 imm+reg
        0x46, 0x4e, 0x56, 0x5e, // UDIV32/64 imm+reg
        0x66, 0x6e, 0x76, 0x7e, // UREM32/64 imm+reg
        0xc6, 0xce, 0xd6, 0xde, // SDIV32/64 imm+reg
        0xe6, 0xee, 0xf6, 0xfe, // SREM32/64 imm+reg
        0xf7, // HOR64_IMM
        0x9d, // RETURN
    ];
    for &byte in v2_only {
        assert_eq!(isa::classify(byte), None, "opcode byte {byte:#04x} must be v2-only");
    }
    // And nothing outside the v1 list is classified at all.
    let mut listed = [false; 256];
    for &(byte, _) in V1_OPCODES {
        listed[byte as usize] = true;
    }
    for byte in 0..=255u8 {
        if !listed[byte as usize] {
            assert_eq!(isa::classify(byte), None, "opcode byte {byte:#04x}");
        }
    }
}

#[test]
fn the_opcode_bytes_match_solana_sbpf() {
    use solana_sbpf::ebpf;
    macro_rules! same {
        ($($name:ident),* $(,)?) => { $( assert_eq!(opc::$name, ebpf::$name, stringify!($name)); )* };
    }
    same!(
        LD_DW_IMM, LD_B_REG, LD_H_REG, LD_W_REG, LD_DW_REG, ST_B_IMM, ST_H_IMM, ST_W_IMM,
        ST_DW_IMM, ST_B_REG, ST_H_REG, ST_W_REG, ST_DW_REG, ADD32_IMM, ADD32_REG, SUB32_IMM,
        SUB32_REG, MUL32_IMM, MUL32_REG, DIV32_IMM, DIV32_REG, OR32_IMM, OR32_REG, AND32_IMM,
        AND32_REG, LSH32_IMM, LSH32_REG, RSH32_IMM, RSH32_REG, NEG32, MOD32_IMM, MOD32_REG,
        XOR32_IMM, XOR32_REG, MOV32_IMM, MOV32_REG, ARSH32_IMM, ARSH32_REG, LE, BE, ADD64_IMM,
        ADD64_REG, SUB64_IMM, SUB64_REG, MUL64_IMM, MUL64_REG, DIV64_IMM, DIV64_REG, OR64_IMM,
        OR64_REG, AND64_IMM, AND64_REG, LSH64_IMM, LSH64_REG, RSH64_IMM, RSH64_REG, NEG64,
        MOD64_IMM, MOD64_REG, XOR64_IMM, XOR64_REG, MOV64_IMM, MOV64_REG, ARSH64_IMM, ARSH64_REG,
        JA, JEQ_IMM, JEQ_REG, JGT_IMM, JGT_REG, JGE_IMM, JGE_REG, JLT_IMM, JLT_REG, JLE_IMM,
        JLE_REG, JSET_IMM, JSET_REG, JNE_IMM, JNE_REG, JSGT_IMM, JSGT_REG, JSGE_IMM, JSGE_REG,
        JSLT_IMM, JSLT_REG, JSLE_IMM, JSLE_REG, CALL_IMM, CALL_REG, EXIT,
    );
}

#[test]
fn decode_agrees_with_solana_sbpf_on_random_slots() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(4401);
    for _ in 0..2_000 {
        let bytes: [u8; 8] = core::array::from_fn(|_| rand::RngExt::random(&mut rng));
        let ours = isa::decode(u64::from_le_bytes(bytes));
        let theirs = solana_sbpf::ebpf::get_insn(&bytes, 0);
        assert_eq!(ours.opc, theirs.opc);
        assert_eq!(ours.dst, theirs.dst);
        assert_eq!(ours.src, theirs.src);
        assert_eq!(ours.off, theirs.off);
        assert_eq!(i64::from(ours.imm), theirs.imm);
    }
}
