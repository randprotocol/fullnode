//! A small assembler so guests can be written in Rust source without a RISC-V toolchain.
use crate::isa::*;
use std::collections::HashMap;

enum Item { Instr(Instr), Branch { cond: BranchCond, rs1: u32, rs2: u32, label: String }, Jal { rd: u32, label: String } }

pub struct Assembler { base_pc: u32, items: Vec<Item>, labels: HashMap<String, usize> }

impl Assembler {
    pub fn new(base_pc: u32) -> Self { Self { base_pc, items: Vec::new(), labels: HashMap::new() } }
    pub fn label(&mut self, name: &str) { assert!(self.labels.insert(name.to_string(), self.items.len()).is_none(), "duplicate label {name}"); }
    pub fn push(&mut self, i: Instr) { self.items.push(Item::Instr(i)); }
    pub fn extend(&mut self, is: impl IntoIterator<Item = Instr>) { for i in is { self.push(i); } }
    pub fn branch(&mut self, cond: BranchCond, rs1: u32, rs2: u32, label: &str) { self.items.push(Item::Branch { cond, rs1, rs2, label: label.into() }); }
    pub fn jal(&mut self, rd: u32, label: &str) { self.items.push(Item::Jal { rd, label: label.into() }); }
    pub fn assemble(self) -> Program {
        let target = |label: &str, from: usize| -> u32 {
            let to = *self.labels.get(label).unwrap_or_else(|| panic!("unknown label {label}"));
            ((to as i64 - from as i64) * 4) as i32 as u32
        };
        let words = self.items.iter().enumerate().map(|(i, it)| match it {
            Item::Instr(x) => x.encode(),
            Item::Branch { cond, rs1, rs2, label } => Instr::Branch { cond: *cond, rs1: *rs1, rs2: *rs2, imm: target(label, i) }.encode(),
            Item::Jal { rd, label } => Instr::Jal { rd: *rd, imm: target(label, i) }.encode(),
        }).collect();
        Program::new(self.base_pc, words)
    }
}

/// Mnemonic helpers. Immediates are `i32` for readability and stored sign-extended.
pub mod ops {
    use crate::isa::*;
    fn imm(i: i32) -> u32 { i as u32 }
    pub fn addi(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Add, rd, rs1, imm: imm(i) } }
    pub fn andi(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::And, rd, rs1, imm: imm(i) } }
    pub fn ori(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Or, rd, rs1, imm: imm(i) } }
    pub fn xori(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Xor, rd, rs1, imm: imm(i) } }
    pub fn slti(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Slt, rd, rs1, imm: imm(i) } }
    pub fn sltiu(rd: u32, rs1: u32, i: i32) -> Instr { Instr::AluImm { op: AluOp::Sltu, rd, rs1, imm: imm(i) } }
    pub fn slli(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Sll, rd, rs1, imm: sh & 31 } }
    pub fn srli(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Srl, rd, rs1, imm: sh & 31 } }
    pub fn srai(rd: u32, rs1: u32, sh: u32) -> Instr { Instr::AluImm { op: AluOp::Sra, rd, rs1, imm: sh & 31 } }
    macro_rules! rrr { ($($name:ident => $op:ident),*) => { $( pub fn $name(rd: u32, rs1: u32, rs2: u32) -> Instr { Instr::AluReg { op: AluOp::$op, rd, rs1, rs2 } } )* } }
    rrr!(add => Add, sub => Sub, and => And, or => Or, xor => Xor, sll => Sll, srl => Srl, sra => Sra, slt => Slt, sltu => Sltu,
         mul => Mul, mulh => Mulh, mulhu => Mulhu, mulhsu => Mulhsu, div => Div, divu => Divu, rem => Rem, remu => Remu);
    // M2.5: `Instr::Lw`/`Sw` became `Instr::Load`/`Store { width, .. }` (sub-word memory
    // access) — ported from upstream `asm.rs`'s `ops` module, which has the full byte/half/word
    // set; only `lw`/`sw` are used by this crate's local guests today.
    pub fn lb(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Byte, signed: true } }
    pub fn lbu(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Byte, signed: false } }
    pub fn lh(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Half, signed: true } }
    pub fn lhu(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Half, signed: false } }
    pub fn lw(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Load { rd, rs1, imm: imm(off), width: Width::Word, signed: false } }
    pub fn sb(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Store { rs1, rs2, imm: imm(off), width: Width::Byte } }
    pub fn sh(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Store { rs1, rs2, imm: imm(off), width: Width::Half } }
    pub fn sw(rs1: u32, rs2: u32, off: i32) -> Instr { Instr::Store { rs1, rs2, imm: imm(off), width: Width::Word } }
    pub fn lui(rd: u32, upper: u32) -> Instr { Instr::Lui { rd, imm: upper & 0xffff_f000 } }
    pub fn auipc(rd: u32, upper: u32) -> Instr { Instr::Auipc { rd, imm: upper & 0xffff_f000 } }
    pub fn jalr(rd: u32, rs1: u32, off: i32) -> Instr { Instr::Jalr { rd, rs1, imm: imm(off) } }
    pub fn ecall() -> Instr { Instr::Ecall }
    pub fn mv(rd: u32, rs: u32) -> Instr { addi(rd, rs, 0) }
    /// Load a 32-bit constant: `lui` + `addi` when needed.
    pub fn li(rd: u32, v: i32) -> Vec<Instr> {
        if (-2048..=2047).contains(&v) { return vec![addi(rd, 0, v)]; }
        let v = v as u32;
        let lo = ((v & 0xfff) as i32) << 20 >> 20;           // sign-extended low 12
        let hi = v.wrapping_sub(lo as u32) & 0xffff_f000;     // upper 20 compensating for negative lo
        if lo == 0 { vec![lui(rd, hi)] } else { vec![lui(rd, hi), addi(rd, rd, lo)] }
    }
    pub fn halt() -> Vec<Instr> { let mut v = li(REG_A7, SYS_HALT as i32); v.push(ecall()); v }
    pub fn write_output(slot: u32, reg: u32) -> Vec<Instr> {
        let mut v = li(REG_A7, SYS_WRITE_OUTPUT as i32); v.extend(li(REG_A0, slot as i32)); v.push(mv(REG_A1, reg)); v.push(ecall()); v
    }
    /// Emit the chain effect "transfer amount (lo, hi registers) to recipient `index`":
    /// out0 = 1, out1 = index, out2 = lo, out3 = hi. Uses a2 as scratch (write_output
    /// clobbers only a7, a0, a1).
    pub fn emit_transfer(index: u32, amount_lo_reg: u32, amount_hi_reg: u32) -> Vec<Instr> {
        let mut v = Vec::new();
        v.extend(li(REG_A2, 1)); v.extend(write_output(0, REG_A2));
        v.extend(li(REG_A2, index as i32)); v.extend(write_output(1, REG_A2));
        v.extend(write_output(2, amount_lo_reg));
        v.extend(write_output(3, amount_hi_reg));
        v
    }
    /// Result lands in a0.
    pub fn read_input(idx: u32) -> Vec<Instr> { let mut v = li(REG_A7, SYS_READ_INPUT as i32); v.extend(li(REG_A0, idx as i32)); v.push(ecall()); v }
    /// M3.2: hashes `n` words at word address `ptr_words` (`a0`, the `MEM_ADDR` word-address
    /// convention) with the `POSEIDON2` sponge, overwriting `ptr_words..ptr_words+8` with the
    /// 8-word digest in place. Ported from upstream `asm.rs`'s `ops` module for
    /// `guests::poseidon2_demo`.
    pub fn call_poseidon2(ptr_words: i32, n: usize) -> Vec<Instr> {
        let mut v = li(REG_A7, SYS_POSEIDON2 as i32);
        v.extend(li(REG_A0, ptr_words));
        v.extend(li(REG_A1, n as i32));
        v.push(ecall());
        v
    }
}
