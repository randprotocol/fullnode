//! The SBPF v1 instruction encoding: one 8-byte slot per instruction, decoded by a byte split.
//!
//! ```text
//!  byte 0    byte 1        bytes 2-3        bytes 4-7
//! +--------+-------------+----------------+------------------+
//! | opcode | src<<4 |dst | off (i16, LE)  | imm (i32, LE)    |
//! +--------+-------------+----------------+------------------+
//! ```
//!
//! `LD_DW_IMM` is the one instruction that spans two slots: the second slot's `imm` is the high
//! half of a 64-bit immediate ([`lddw_imm64`]), and its other fields are ignored.

/// One decoded instruction slot. `dst` and `src` come out of a nibble each, so neither can name a
/// register past 15 — the interpreter still rejects anything above `r10`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Insn {
    pub opc: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

/// Splits one little-endian slot into its fields. Total — every one of the 2^64 slots decodes;
/// whether the opcode means anything is [`classify`]'s question and the interpreter's.
#[inline]
pub fn decode(slot: u64) -> Insn {
    Insn {
        opc: slot as u8,
        dst: (slot >> 8) as u8 & 0x0f,
        src: (slot >> 12) as u8 & 0x0f,
        off: (slot >> 16) as u16 as i16,
        imm: (slot >> 32) as u32 as i32,
    }
}

/// The 64-bit immediate of an `lddw`: the low half is its *unsigned* 32 bits (a negative low imm
/// must not smear ones into the high half), the high half is the next slot's imm.
#[inline]
pub fn lddw_imm64(lo: Insn, hi: Insn) -> u64 {
    (lo.imm as u32 as u64) | ((hi.imm as u32 as u64) << 32)
}

/// Bytes 0-7 of one slot, as the loader and the assembler build them.
#[inline]
pub fn encode(i: Insn) -> u64 {
    (i.opc as u64)
        | ((i.src as u64 & 0x0f) << 12)
        | ((i.dst as u64 & 0x0f) << 8)
        | ((i.off as u16 as u64) << 16)
        | ((i.imm as u32 as u64) << 32)
}

/// What kind of instruction an opcode byte is. Only the v1 set is classified; everything else —
/// the whole `BPF_PQR` class, `HOR64_IMM`, `RETURN`, and every unassigned byte — is [`None`], and
/// the interpreter halts on it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    /// A load: `lddw` and the four `ldx` widths.
    Ld,
    /// A store: the four `st` (immediate) and four `stx` (register) widths.
    St,
    /// 32-bit arithmetic, plus `le`/`be`.
    Alu32,
    /// 64-bit arithmetic.
    Alu64,
    /// `ja` and the 22 conditional jumps.
    Jmp,
    /// `call imm` and `callx`.
    Call,
    /// `exit`.
    Exit,
}

/// Every opcode byte SBPF v1 assigns, and its class. The single source of truth for "is this a v1
/// instruction" — the interpreter's dispatch and this function are checked against each other by
/// `research/tests/sbpf_isa.rs`, which also pins each byte against `solana_sbpf::ebpf`'s constant
/// of the same name.
pub fn classify(byte: u8) -> Option<Class> {
    use opc::*;
    Some(match byte {
        LD_DW_IMM | LD_B_REG | LD_H_REG | LD_W_REG | LD_DW_REG => Class::Ld,
        ST_B_IMM | ST_H_IMM | ST_W_IMM | ST_DW_IMM | ST_B_REG | ST_H_REG | ST_W_REG | ST_DW_REG => {
            Class::St
        }
        ADD32_IMM | ADD32_REG | SUB32_IMM | SUB32_REG | MUL32_IMM | MUL32_REG | DIV32_IMM
        | DIV32_REG | OR32_IMM | OR32_REG | AND32_IMM | AND32_REG | LSH32_IMM | LSH32_REG
        | RSH32_IMM | RSH32_REG | NEG32 | MOD32_IMM | MOD32_REG | XOR32_IMM | XOR32_REG
        | MOV32_IMM | MOV32_REG | ARSH32_IMM | ARSH32_REG | LE | BE => Class::Alu32,
        ADD64_IMM | ADD64_REG | SUB64_IMM | SUB64_REG | MUL64_IMM | MUL64_REG | DIV64_IMM
        | DIV64_REG | OR64_IMM | OR64_REG | AND64_IMM | AND64_REG | LSH64_IMM | LSH64_REG
        | RSH64_IMM | RSH64_REG | NEG64 | MOD64_IMM | MOD64_REG | XOR64_IMM | XOR64_REG
        | MOV64_IMM | MOV64_REG | ARSH64_IMM | ARSH64_REG => Class::Alu64,
        JA | JEQ_IMM | JEQ_REG | JGT_IMM | JGT_REG | JGE_IMM | JGE_REG | JLT_IMM | JLT_REG
        | JLE_IMM | JLE_REG | JSET_IMM | JSET_REG | JNE_IMM | JNE_REG | JSGT_IMM | JSGT_REG
        | JSGE_IMM | JSGE_REG | JSLT_IMM | JSLT_REG | JSLE_IMM | JSLE_REG => Class::Jmp,
        CALL_IMM | CALL_REG => Class::Call,
        EXIT => Class::Exit,
        _ => return None,
    })
}

/// Every SBPF v1 opcode byte, named as `solana_sbpf::ebpf` names it. The v2-only opcodes (the
/// `BPF_PQR` class — `SDIV`/`SREM`/`UDIV`/`UREM`/`LMUL`/`UHMUL`/`SHMUL` — plus `HOR64_IMM` and
/// `RETURN`) are deliberately absent: the interpreter halts on them.
#[allow(missing_docs)]
pub mod opc {
    // Loads and stores.
    pub const LD_DW_IMM: u8 = 0x18;
    pub const LD_B_REG: u8 = 0x71;
    pub const LD_H_REG: u8 = 0x69;
    pub const LD_W_REG: u8 = 0x61;
    pub const LD_DW_REG: u8 = 0x79;
    pub const ST_B_IMM: u8 = 0x72;
    pub const ST_H_IMM: u8 = 0x6a;
    pub const ST_W_IMM: u8 = 0x62;
    pub const ST_DW_IMM: u8 = 0x7a;
    pub const ST_B_REG: u8 = 0x73;
    pub const ST_H_REG: u8 = 0x6b;
    pub const ST_W_REG: u8 = 0x63;
    pub const ST_DW_REG: u8 = 0x7b;

    // 32-bit arithmetic.
    pub const ADD32_IMM: u8 = 0x04;
    pub const ADD32_REG: u8 = 0x0c;
    pub const SUB32_IMM: u8 = 0x14;
    pub const SUB32_REG: u8 = 0x1c;
    pub const MUL32_IMM: u8 = 0x24;
    pub const MUL32_REG: u8 = 0x2c;
    pub const DIV32_IMM: u8 = 0x34;
    pub const DIV32_REG: u8 = 0x3c;
    pub const OR32_IMM: u8 = 0x44;
    pub const OR32_REG: u8 = 0x4c;
    pub const AND32_IMM: u8 = 0x54;
    pub const AND32_REG: u8 = 0x5c;
    pub const LSH32_IMM: u8 = 0x64;
    pub const LSH32_REG: u8 = 0x6c;
    pub const RSH32_IMM: u8 = 0x74;
    pub const RSH32_REG: u8 = 0x7c;
    pub const NEG32: u8 = 0x84;
    pub const MOD32_IMM: u8 = 0x94;
    pub const MOD32_REG: u8 = 0x9c;
    pub const XOR32_IMM: u8 = 0xa4;
    pub const XOR32_REG: u8 = 0xac;
    pub const MOV32_IMM: u8 = 0xb4;
    pub const MOV32_REG: u8 = 0xbc;
    pub const ARSH32_IMM: u8 = 0xc4;
    pub const ARSH32_REG: u8 = 0xcc;
    pub const LE: u8 = 0xd4;
    pub const BE: u8 = 0xdc;

    // 64-bit arithmetic.
    pub const ADD64_IMM: u8 = 0x07;
    pub const ADD64_REG: u8 = 0x0f;
    pub const SUB64_IMM: u8 = 0x17;
    pub const SUB64_REG: u8 = 0x1f;
    pub const MUL64_IMM: u8 = 0x27;
    pub const MUL64_REG: u8 = 0x2f;
    pub const DIV64_IMM: u8 = 0x37;
    pub const DIV64_REG: u8 = 0x3f;
    pub const OR64_IMM: u8 = 0x47;
    pub const OR64_REG: u8 = 0x4f;
    pub const AND64_IMM: u8 = 0x57;
    pub const AND64_REG: u8 = 0x5f;
    pub const LSH64_IMM: u8 = 0x67;
    pub const LSH64_REG: u8 = 0x6f;
    pub const RSH64_IMM: u8 = 0x77;
    pub const RSH64_REG: u8 = 0x7f;
    pub const NEG64: u8 = 0x87;
    pub const MOD64_IMM: u8 = 0x97;
    pub const MOD64_REG: u8 = 0x9f;
    pub const XOR64_IMM: u8 = 0xa7;
    pub const XOR64_REG: u8 = 0xaf;
    pub const MOV64_IMM: u8 = 0xb7;
    pub const MOV64_REG: u8 = 0xbf;
    pub const ARSH64_IMM: u8 = 0xc7;
    pub const ARSH64_REG: u8 = 0xcf;

    // Control flow.
    pub const JA: u8 = 0x05;
    pub const JEQ_IMM: u8 = 0x15;
    pub const JEQ_REG: u8 = 0x1d;
    pub const JGT_IMM: u8 = 0x25;
    pub const JGT_REG: u8 = 0x2d;
    pub const JGE_IMM: u8 = 0x35;
    pub const JGE_REG: u8 = 0x3d;
    pub const JLT_IMM: u8 = 0xa5;
    pub const JLT_REG: u8 = 0xad;
    pub const JLE_IMM: u8 = 0xb5;
    pub const JLE_REG: u8 = 0xbd;
    pub const JSET_IMM: u8 = 0x45;
    pub const JSET_REG: u8 = 0x4d;
    pub const JNE_IMM: u8 = 0x55;
    pub const JNE_REG: u8 = 0x5d;
    pub const JSGT_IMM: u8 = 0x65;
    pub const JSGT_REG: u8 = 0x6d;
    pub const JSGE_IMM: u8 = 0x75;
    pub const JSGE_REG: u8 = 0x7d;
    pub const JSLT_IMM: u8 = 0xc5;
    pub const JSLT_REG: u8 = 0xcd;
    pub const JSLE_IMM: u8 = 0xd5;
    pub const JSLE_REG: u8 = 0xdd;
    pub const CALL_IMM: u8 = 0x85;
    pub const CALL_REG: u8 = 0x8d;
    pub const EXIT: u8 = 0x95;
}
