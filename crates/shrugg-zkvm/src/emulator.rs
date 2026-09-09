//! Native executor that records exactly the events the tables need. Also the
//! reference semantics: if the emulator and the AIR disagree, the AIR is wrong.
use crate::isa::*;
use std::collections::HashMap;

pub const SLOT_R1: u32 = 0; pub const SLOT_R2: u32 = 1; pub const SLOT_MEM: u32 = 2; pub const SLOT_W: u32 = 3;
pub const SPACE_REG: u32 = 0; pub const SPACE_RAM: u32 = 1;
/// Register `a1` is read through the memory slot on ecall rows.
pub const ECALL_MEM_REG: u32 = REG_A1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemAccess { pub space: u32, pub addr: u32, pub slot: u32, pub value: u32, pub is_write: bool }
impl MemAccess { pub fn ts(&self, clk: u32) -> u32 { 4 * clk + self.slot } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AluEvent { pub op: AluOp, pub a: u32, pub b: u32, pub c: u32 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscall { Halt, WriteOutput { slot: u32, word: u32 }, ReadInput { idx: u32, word: u32 } }

#[derive(Clone, Debug)]
pub struct CycleEvent {
    pub clk: u32, pub pc: u32, pub next_pc: u32, pub instr: Instr, pub dec: Decoded,
    pub a: u32, pub b: u32, pub c: u32, pub alu_out: u32, pub tgt: u32, pub mem_addr: u32, pub mem_val: u32,
    pub sys: Option<Syscall>, pub accesses: Vec<MemAccess>, pub alu: Vec<AluEvent>,
}

#[derive(Clone, Debug)]
pub struct Execution { pub events: Vec<CycleEvent>, pub outputs: [u32; NUM_OUTPUTS], pub halted: bool }
impl Execution { pub fn cycles(&self) -> usize { self.events.len() } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecError { OutOfCycles(usize), BadPc(u32), Misaligned(u32), BadSyscall(u32), OutputSlot(u32), DoubleWrite(u32), InputIndex(u32) }

pub fn execute(program: &Program, inputs: &[u32], max_cycles: usize) -> Result<Execution, ExecError> {
    let mut regs = [0u32; 32];
    let mut ram: HashMap<u32, u32> = HashMap::new(); // word address -> value; unwritten reads are 0
    let mut outputs = [0u32; NUM_OUTPUTS];
    let mut written = [false; NUM_OUTPUTS];
    let mut events = Vec::new();
    let mut pc = program.base_pc;
    for clk in 0..max_cycles as u32 {
        let instr = program.instr_at(pc).ok_or(ExecError::BadPc(pc))?;
        let dec = instr.decoded();
        let a = regs[dec.rs1 as usize];
        let b = regs[dec.rs2 as usize];
        let mut acc = vec![
            MemAccess { space: SPACE_REG, addr: dec.rs1, slot: SLOT_R1, value: a, is_write: false },
            MemAccess { space: SPACE_REG, addr: dec.rs2, slot: SLOT_R2, value: b, is_write: false },
        ];
        let mut alu = Vec::new();
        let (mut c, mut alu_out, mut tgt, mut mem_addr, mut mem_val, mut sys) = (0u32, 0u32, 0u32, 0u32, 0u32, None);
        let mut next_pc = pc.wrapping_add(4);
        let b_eff = if dec.is_imm == 1 { dec.imm } else { b };
        // slot-1 ALU
        let op1 = if dec.is_alu == 1 { Some(AluOp::from_code(dec.alu_op)) } else if dec.is_branch == 1 { Some(AluOp::from_code(dec.br_op)) } else if dec.is_load + dec.is_store + dec.is_jalr == 1 { Some(AluOp::Add) } else { None };
        if let Some(op) = op1 { alu_out = op.eval(a, b_eff); alu.push(AluEvent { op, a, b: b_eff, c: alu_out }); }
        // slot-2 ALU: pc + imm
        if dec.is_branch + dec.is_jal + dec.is_auipc == 1 { tgt = pc.wrapping_add(dec.imm); alu.push(AluEvent { op: AluOp::Add, a: pc, b: dec.imm, c: tgt }); }
        match instr {
            Instr::AluImm { .. } | Instr::AluReg { .. } => c = alu_out,
            Instr::Lui { imm, .. } => c = imm,
            Instr::Auipc { .. } => c = tgt,
            Instr::Jal { .. } => { c = pc.wrapping_add(4); next_pc = tgt; }
            Instr::Jalr { .. } => { c = pc.wrapping_add(4); next_pc = alu_out; }
            Instr::Branch { .. } => { let taken = (alu_out == 1) != (dec.br_neg == 1); if taken { next_pc = tgt; } }
            Instr::Lw { .. } => {
                if alu_out % 4 != 0 { return Err(ExecError::Misaligned(alu_out)); }
                mem_addr = alu_out / 4; mem_val = *ram.get(&mem_addr).unwrap_or(&0); c = mem_val;
                acc.push(MemAccess { space: SPACE_RAM, addr: mem_addr, slot: SLOT_MEM, value: mem_val, is_write: false });
            }
            Instr::Sw { .. } => {
                if alu_out % 4 != 0 { return Err(ExecError::Misaligned(alu_out)); }
                mem_addr = alu_out / 4; mem_val = b; ram.insert(mem_addr, b);
                acc.push(MemAccess { space: SPACE_RAM, addr: mem_addr, slot: SLOT_MEM, value: b, is_write: true });
            }
            Instr::Ecall => {
                mem_addr = ECALL_MEM_REG; mem_val = regs[ECALL_MEM_REG as usize];
                acc.push(MemAccess { space: SPACE_REG, addr: ECALL_MEM_REG, slot: SLOT_MEM, value: mem_val, is_write: false });
                let (num, arg0, arg1) = (a, b, mem_val);
                sys = Some(match num {
                    SYS_HALT => Syscall::Halt,
                    SYS_WRITE_OUTPUT => {
                        let slot = arg0 as usize;
                        if slot >= NUM_OUTPUTS { return Err(ExecError::OutputSlot(arg0)); }
                        if written[slot] { return Err(ExecError::DoubleWrite(arg0)); }
                        written[slot] = true; outputs[slot] = arg1;
                        Syscall::WriteOutput { slot: arg0, word: arg1 }
                    }
                    SYS_READ_INPUT => {
                        let word = *inputs.get(arg0 as usize).ok_or(ExecError::InputIndex(arg0))?;
                        c = word;
                        Syscall::ReadInput { idx: arg0, word }
                    }
                    other => return Err(ExecError::BadSyscall(other)),
                });
            }
        }
        let writes = dec.writes_rd == 1 || matches!(sys, Some(Syscall::ReadInput { .. }));
        if writes {
            regs[dec.rd as usize] = c;
            acc.push(MemAccess { space: SPACE_REG, addr: dec.rd, slot: SLOT_W, value: c, is_write: true });
        }
        regs[0] = 0;
        let halted = matches!(sys, Some(Syscall::Halt));
        events.push(CycleEvent { clk, pc, next_pc, instr, dec, a, b, c, alu_out, tgt, mem_addr, mem_val, sys, accesses: acc, alu });
        if halted { return Ok(Execution { events, outputs, halted: true }); }
        pc = next_pc;
    }
    Err(ExecError::OutOfCycles(max_cycles))
}
