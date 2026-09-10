//! Native executor that records exactly the events the tables need. Also the
//! reference semantics: if the emulator and the AIR disagree, the AIR is wrong.
use crate::isa::*;
use crate::machine::Val;
use p3_field::PrimeCharacteristicRing;
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
pub enum Syscall { Halt, WriteOutput { slot: u32, word: u32 }, ReadInput { idx: u32, word: u32 }, Poseidon2 { ptr: u32, n: u32 } }

/// Which row of a `POSEIDON2` syscall's row group a `CycleEvent` is, and the extra fields that
/// row alone needs (the cpu table's hash-row columns, `docs/02-tables-and-buses.md`). `None` on
/// every ordinary (non-hash) row.
///
/// A sponge state's lanes are *not* bounded to `u32` in general — only the rate lanes (0..3)
/// get overwritten by small absorbed words each block; the capacity lanes (4..7), and every
/// lane after any permutation, are uniformly-distributed field elements that routinely exceed
/// `u32::MAX`. So `state_in`/`state_out`/`state` below are `[Val; 8]` (the same field the cpu
/// table's `HS0..7` columns hold), not `[u32; 8]` — truncating them would silently diverge from
/// `hash::sponge_hash` on any call absorbing more than one block.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashRow {
    /// The ecall row itself (`sys == Some(Syscall::Poseidon2 { ptr, n })`); carried again here
    /// so `cpu_trace` doesn't have to match on `sys` to find it.
    Ecall { ptr: u32, n: u32 },
    /// One absorbed block. `idx`: 0-based block index (this row's `HASH_IDX`). `left_before`:
    /// words not yet absorbed before this row (this row's `HASH_LEFT`). `words`/`active`: the
    /// (up to 4) machine words placed into state lanes 0..3 this block and which lanes are a
    /// genuine memory read (a prefix of `true`s; a `false` lane's `words` entry is unused —
    /// the sponge does not overwrite it, `state_in`'s own lane survives instead). `state_in`:
    /// the sponge state entering this row (the end of the previous block, or all-zero for the
    /// first). `state_out`: the permutation's output — what the *next* row's `HS0..7` must
    /// equal, and the state the `POSEIDON2` bus lookup asks for on this row.
    Absorb { idx: u32, left_before: u32, words: [u32; 4], active: [bool; 4], state_in: [Val; 8], state_out: [Val; 8] },
    /// One of the two digest write-back rows. `fin`: true on the second (ends the
    /// instruction). `words`: the 4 machine words this row writes (lo/hi of two digest lanes).
    /// `state`: the final sponge state (identical on both write-back rows — the cpu AIR copies
    /// it forward from the first to the second); its lanes 0..3 are the digest.
    WriteOut { fin: bool, words: [u32; 4], state: [Val; 8] },
}

#[derive(Clone, Debug)]
pub struct CycleEvent {
    pub clk: u32, pub pc: u32, pub next_pc: u32, pub instr: Instr, pub dec: Decoded,
    pub a: u32, pub b: u32, pub c: u32, pub alu_out: u32, pub tgt: u32, pub mem_addr: u32, pub mem_val: u32,
    pub sys: Option<Syscall>, pub accesses: Vec<MemAccess>, pub alu: Vec<AluEvent>,
    pub hash_row: Option<HashRow>,
}

#[derive(Clone, Debug)]
pub struct Execution { pub events: Vec<CycleEvent>, pub outputs: [u32; NUM_OUTPUTS], pub halted: bool }
impl Execution { pub fn cycles(&self) -> usize { self.events.len() } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecError { OutOfCycles(usize), BadPc(u32), Misaligned(u32), BadSyscall(u32), OutputSlot(u32), DoubleWrite(u32), InputIndex(u32), Poseidon2WordCount(u32) }

pub fn execute(program: &Program, inputs: &[u32], max_cycles: usize) -> Result<Execution, ExecError> {
    let mut regs = [0u32; 32];
    let mut ram: HashMap<u32, u32> = HashMap::new(); // word address -> value; unwritten reads are 0
    let mut outputs = [0u32; NUM_OUTPUTS];
    let mut written = [false; NUM_OUTPUTS];
    let mut events: Vec<CycleEvent> = Vec::new();
    let mut pc = program.base_pc;
    // One iteration of this loop is one *instruction*, but `POSEIDON2` pushes several rows
    // (`CycleEvent`s) per instruction — so `clk` (one tick per row) and the `max_cycles` row
    // budget are tracked independently of the loop that fetches/decodes instructions.
    let mut clk: u32 = 0;
    loop {
        if events.len() >= max_cycles { return Err(ExecError::OutOfCycles(max_cycles)); }
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
        let is_load = dec.is_lb + dec.is_lh + dec.is_lw;
        let is_store = dec.is_sb + dec.is_sh + dec.is_sw;
        let op1 = if dec.is_alu == 1 { Some(AluOp::from_code(dec.alu_op)) } else if dec.is_branch == 1 { Some(AluOp::from_code(dec.br_op)) } else if is_load + is_store + dec.is_jalr == 1 { Some(AluOp::Add) } else { None };
        if let Some(op) = op1 { alu_out = op.eval(a, b_eff); alu.push(AluEvent { op, a, b: b_eff, c: alu_out }); }
        // slot-2 ALU: pc + imm
        if dec.is_branch + dec.is_jal + dec.is_auipc == 1 { tgt = pc.wrapping_add(dec.imm); alu.push(AluEvent { op: AluOp::Add, a: pc, b: dec.imm, c: tgt }); }
        // POSEIDON2 dispatches a whole row-group and `continue`s the outer loop itself; every
        // other instruction kind (including the other ecall syscalls) falls through to the
        // single-event push at the bottom, unchanged from before M3.2.
        let mut hashed = false;
        match instr {
            Instr::AluImm { .. } | Instr::AluReg { .. } => c = alu_out,
            Instr::Lui { imm, .. } => c = imm,
            Instr::Auipc { .. } => c = tgt,
            Instr::Jal { .. } => { c = pc.wrapping_add(4); next_pc = tgt; }
            Instr::Jalr { .. } => { c = pc.wrapping_add(4); next_pc = alu_out; }
            Instr::Branch { .. } => { let taken = (alu_out == 1) != (dec.br_neg == 1); if taken { next_pc = tgt; } }
            Instr::Load { width, signed, .. } => {
                let off = alu_out & 3;
                let bad = match width { Width::Word => off != 0, Width::Half => off != 0 && off != 2, Width::Byte => false };
                if bad { return Err(ExecError::Misaligned(alu_out)); }
                mem_addr = alu_out >> 2;
                mem_val = *ram.get(&mem_addr).unwrap_or(&0);
                c = match width {
                    Width::Byte => { let byte = (mem_val >> (8 * off)) & 0xff; if signed { sext(byte, 8) } else { byte } }
                    Width::Half => { let half = (mem_val >> (8 * off)) & 0xffff; if signed { sext(half, 16) } else { half } }
                    Width::Word => mem_val,
                };
                acc.push(MemAccess { space: SPACE_RAM, addr: mem_addr, slot: SLOT_MEM, value: mem_val, is_write: false });
            }
            Instr::Store { width, .. } => {
                let off = alu_out & 3;
                let bad = match width { Width::Word => off != 0, Width::Half => off != 0 && off != 2, Width::Byte => false };
                if bad { return Err(ExecError::Misaligned(alu_out)); }
                mem_addr = alu_out >> 2;
                let old = *ram.get(&mem_addr).unwrap_or(&0);
                let merged = match width {
                    Width::Byte => (old & !(0xffu32 << (8 * off))) | ((b & 0xff) << (8 * off)),
                    Width::Half => (old & !(0xffffu32 << (8 * off))) | ((b & 0xffff) << (8 * off)),
                    Width::Word => b,
                };
                mem_val = old;
                ram.insert(mem_addr, merged);
                acc.push(MemAccess { space: SPACE_RAM, addr: mem_addr, slot: SLOT_MEM, value: old, is_write: false });
                acc.push(MemAccess { space: SPACE_RAM, addr: mem_addr, slot: SLOT_W, value: merged, is_write: true });
            }
            Instr::Ecall => {
                mem_addr = ECALL_MEM_REG; mem_val = regs[ECALL_MEM_REG as usize];
                acc.push(MemAccess { space: SPACE_REG, addr: ECALL_MEM_REG, slot: SLOT_MEM, value: mem_val, is_write: false });
                let (num, arg0, arg1) = (a, b, mem_val);
                if num == SYS_POSEIDON2 {
                    let (ptr, n) = (arg0, arg1);
                    if n > POSEIDON2_MAX_WORDS { return Err(ExecError::Poseidon2WordCount(n)); }
                    // ecall row: HASH_LEFT = n, HASH_IDX = 0, HS0..7 = 0 — all pinned by the AIR
                    // directly from HASH_N/the zero sentinel, so `cpu_trace` only needs `ptr`/`n`.
                    events.push(CycleEvent {
                        clk, pc, next_pc: pc, instr, dec, a, b, c: 0, alu_out, tgt, mem_addr, mem_val,
                        sys: Some(Syscall::Poseidon2 { ptr, n }), accesses: acc.clone(), alu: alu.clone(),
                        hash_row: Some(HashRow::Ecall { ptr, n }),
                    });
                    clk += 1;

                    let mut state = [Val::ZERO; 8];
                    let mut left = n;
                    let mut idx = 0u32;
                    while left > 0 {
                        if events.len() >= max_cycles { return Err(ExecError::OutOfCycles(max_cycles)); }
                        let cnt = left.min(4);
                        let mut words = [0u32; 4];
                        let mut active = [false; 4];
                        let mut racc = Vec::new();
                        let mut merged = state;
                        for k in 0..4usize {
                            if (k as u32) < cnt {
                                let addr = ptr.wrapping_add(4 * idx).wrapping_add(k as u32);
                                let w = *ram.get(&addr).unwrap_or(&0);
                                words[k] = w;
                                active[k] = true;
                                merged[k] = Val::from_u32(w);
                                racc.push(MemAccess { space: SPACE_RAM, addr, slot: k as u32, value: w, is_write: false });
                            }
                            // inactive lanes: `merged[k]` stays `state[k]` — the sponge's
                            // overwrite never touches a lane past the absorbed count.
                        }
                        let state_in = state;
                        let state_out = crate::hash::permute_state(merged);
                        events.push(CycleEvent {
                            clk, pc, next_pc: pc, instr, dec: Decoded::default(), a: 0, b: 0, c: 0,
                            alu_out: 0, tgt: 0, mem_addr: 0, mem_val: 0, sys: None, accesses: racc, alu: Vec::new(),
                            hash_row: Some(HashRow::Absorb { idx, left_before: left, words, active, state_in, state_out }),
                        });
                        state = state_out;
                        left -= cnt;
                        idx += 1;
                        clk += 1;
                    }

                    // Digest: the final state's first 4 lanes, each a canonical u64 split into
                    // lo/hi u32 words (`hash::split_digest`) — the sponge's `OUT = 4` truncation.
                    let digest_words = crate::hash::split_digest([state[0], state[1], state[2], state[3]]);
                    for (fin, half) in [(false, 0usize), (true, 1usize)] {
                        if events.len() >= max_cycles { return Err(ExecError::OutOfCycles(max_cycles)); }
                        let mut wacc = Vec::new();
                        let mut words = [0u32; 4];
                        for k in 0..4usize {
                            let w = digest_words[half * 4 + k];
                            let addr = ptr.wrapping_add((half * 4 + k) as u32);
                            words[k] = w;
                            wacc.push(MemAccess { space: SPACE_RAM, addr, slot: k as u32, value: w, is_write: true });
                            ram.insert(addr, w);
                        }
                        let row_next_pc = if fin { pc.wrapping_add(4) } else { pc };
                        events.push(CycleEvent {
                            clk, pc, next_pc: row_next_pc, instr, dec: Decoded::default(), a: 0, b: 0, c: 0,
                            alu_out: 0, tgt: 0, mem_addr: 0, mem_val: 0, sys: None, accesses: wacc, alu: Vec::new(),
                            hash_row: Some(HashRow::WriteOut { fin, words, state }),
                        });
                        clk += 1;
                    }
                    regs[0] = 0;
                    pc = pc.wrapping_add(4);
                    hashed = true;
                } else {
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
        }
        if hashed {
            // `POSEIDON2` already pushed its whole row group above (including its own
            // register/memory-write bookkeeping and `regs[0] = 0`/`pc` advance) — do not fall
            // through to the single-event push below, which would push a stray extra row.
            continue;
        }
        let writes = dec.writes_rd == 1 || matches!(sys, Some(Syscall::ReadInput { .. }));
        if writes {
            regs[dec.rd as usize] = c;
            acc.push(MemAccess { space: SPACE_REG, addr: dec.rd, slot: SLOT_W, value: c, is_write: true });
        }
        regs[0] = 0;
        let halted = matches!(sys, Some(Syscall::Halt));
        events.push(CycleEvent { clk, pc, next_pc, instr, dec, a, b, c, alu_out, tgt, mem_addr, mem_val, sys, accesses: acc, alu, hash_row: None });
        clk += 1;
        if halted { return Ok(Execution { events, outputs, halted: true }); }
        pc = next_pc;
    }
}
