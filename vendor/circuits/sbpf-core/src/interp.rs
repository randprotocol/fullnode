//! The SBPF v1 interpreter: `loop { fetch, meter, dispatch }` over eleven 64-bit registers.
//!
//! Every semantic here is the one `solana_sbpf::interpreter::Interpreter::step` has for
//! `SBPFVersion::V0` — including the parts that are easy to get wrong:
//!
//! * a 32-bit `add`/`sub`/`mul` **sign**-extends its result into the 64-bit register, while
//!   `or`/`and`/`xor`/`lsh`/`rsh`/`arsh`/`mod`/`div`/`neg`/`mov` zero-extend it;
//! * shift amounts are masked (five bits for the 32-bit forms, six for the 64-bit ones);
//! * `sub` takes `dst - imm`, not v2's swapped `imm - dst`;
//! * `div`/`mod` are unsigned, and a zero divisor — register **or** immediate — is an exceptional
//!   halt (`solana-sbpf` leaves the immediate case to its verifier, which this crate has no
//!   equivalent of: the halt is the safe reading);
//! * `le`/`be` accept only 16, 32 and 64, and `le` is the identity on a little-endian host;
//! * `r6..r9` are callee-saved: a call stashes them with the frame pointer and `exit` restores
//!   them;
//! * frames are *fixed*: `r10` moves up one [`STACK_FRAME`] per call, and the push that would make
//!   the depth [`MAX_CALL_DEPTH`] is refused.
//!
//! No register index, jump target, call target or address is trusted: a nibble naming a register
//! above `r10`, a slot outside the text, a divisor of zero and an address outside every region are
//! each a [`Halt`], never a panic.
//!
//! # `call imm`
//!
//! `solana-sbpf` resolves `call imm` through a function registry keyed by a murmur3 hash that its
//! ELF loader writes into the immediate. This crate does not carry a registry: [`crate::elf::load`]
//! rewrites every call site in place instead, so at run time the encoding says what it is —
//! `src == 0` is a **slot-relative** call (`target = pc + 1 + imm`, which is also what the
//! toolchain emits for an intra-object call and needs no relocation at all) and `src == 1` is a
//! syscall whose `imm` is the murmur3 hash of its name. The two resolve to the same targets the
//! registry would; keeping it in the instruction is what lets `Program` be four slices and two
//! integers, with nothing to allocate.

use crate::isa::{self, opc, Insn};
use crate::memory::{Memory, MAX_CALL_DEPTH, STACK_FRAME};
use crate::{elf::Program, Host};

/// Solana's default compute budget, and the only clock this interpreter has: exceeding it is an
/// exceptional halt. Per-syscall compute costs are not modelled (M4.4 plan, "Instruction meter").
pub const MAX_INSTRUCTIONS: u64 = 200_000;

/// Why a run stopped. Everything but [`Halt::Exit`] is an *exceptional* halt, which
/// [`crate::abi::run_call`] publishes as status 2 with the post-state pinned to the pre-state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Halt {
    /// The program returned normally. Never produced by [`Vm::run`], which returns `r0` instead;
    /// present so a caller can name the non-exceptional outcome.
    Exit,
    /// A load or store touched a byte outside every region it may touch. Carries the faulting
    /// address (the start of the access, as `solana-sbpf` reports it).
    AccessViolation(u64),
    /// An opcode byte SBPF v1 does not assign, or one whose immediate is out of range (`le`/`be`).
    BadInsn(u8),
    /// A `div` or `mod` by zero.
    DivByZero,
    /// A `call` naming a syscall this interpreter does not implement.
    UnknownSyscall(u32),
    /// The 64th nested frame.
    CallDepth,
    /// [`MAX_INSTRUCTIONS`] executed.
    InstructionLimit,
    /// The ELF is not an SBPF v1 shared object this loader can load.
    BadElf,
    /// A jump, call, return or fetch outside the text.
    BadJump,
    /// Reserved for a frame that would leave the static stack. Frames are fixed and
    /// [`MAX_CALL_DEPTH`] × [`STACK_FRAME`] is exactly the stack, so [`Halt::CallDepth`] is what
    /// actually fires; a future dynamic-frame version reports this instead.
    StackOverflow,
    /// A syscall that deliberately aborts (`abort`, `sol_panic_`) or refuses its arguments.
    Trap(&'static str),
}

/// One run's machine state. About 3 KiB: the eleven registers, the pc, the meter, the frame stack
/// (return pcs, saved `r6..r9`, saved frame pointers) and the borrowed memory — small enough to
/// live on the guest's 64 KiB stack, which is why the big arrays are the caller's
/// ([`crate::abi::Workspace`]).
pub struct Vm<'a, H: Host> {
    /// The chip-backed operations. `pub` because the syscalls reach it.
    pub host: &'a mut H,
    /// The text being executed, and where it sits in the program region.
    pub program: &'a Program<'a>,
    /// The four regions.
    pub mem: Memory<'a>,
    /// `r0..r10`. `r10` is the frame pointer; there is no `r11` (that is `solana-sbpf`'s pc slot).
    pub regs: [u64; 11],
    /// The next slot to execute, in slots from the start of the text.
    pub pc: u64,
    /// The bump allocator's cursor into the heap region: bytes handed out by `sol_alloc_free_`.
    pub heap_used: usize,
    ret_pc: [u64; MAX_CALL_DEPTH],
    saved_scratch: [[u64; 4]; MAX_CALL_DEPTH],
    saved_fp: [u64; MAX_CALL_DEPTH],
    depth: usize,
    max_depth: usize,
    meter: u64,
}

impl<'a, H: Host> Vm<'a, H> {
    /// `r1` = the input region's base, `r10` = the top of frame 0, `pc` = the entrypoint,
    /// everything else zero — `solana_sbpf::vm::EbpfVm::new`'s state for a fixed-frame version.
    pub fn new(host: &'a mut H, program: &'a Program<'a>, mem: Memory<'a>) -> Self {
        let mut regs = [0u64; 11];
        regs[1] = crate::memory::REGION_INPUT;
        regs[10] = crate::memory::REGION_STACK + STACK_FRAME as u64;
        Vm {
            host,
            pc: program.entry_pc as u64,
            program,
            mem,
            regs,
            heap_used: 0,
            ret_pc: [0; MAX_CALL_DEPTH],
            saved_scratch: [[0; 4]; MAX_CALL_DEPTH],
            saved_fp: [0; MAX_CALL_DEPTH],
            depth: 0,
            max_depth: 0,
            meter: 0,
        }
    }

    /// How many instructions the run executed. An `lddw` spans two slots but counts once.
    pub fn instructions_executed(&self) -> u64 {
        self.meter
    }

    /// The current call depth: 0 once a run has returned normally.
    pub fn call_depth(&self) -> usize {
        self.depth
    }

    /// The deepest the frame stack ever got during the run — the number the 8 × 4 KiB stack has to
    /// be big enough for, and the one the M4.4 plan asks Task 6 to *measure* rather than assume
    /// (`docs/04-guests.md`: an SPL Token `Transfer` nests 0 calls deep). Counted on the way in, so
    /// a run refused at [`MAX_CALL_DEPTH`] reports that depth rather than the last one that fitted.
    pub fn max_call_depth(&self) -> usize {
        self.max_depth
    }

    /// Runs to `exit` at depth 0, and returns `r0` — or the [`Halt`] that stopped it.
    pub fn run(&mut self) -> Result<u64, Halt> {
        loop {
            if self.meter >= MAX_INSTRUCTIONS {
                return Err(Halt::InstructionLimit);
            }
            self.meter += 1;
            if let Some(r0) = self.step()? {
                return Ok(r0);
            }
        }
    }

    /// The slot at `pc`, or [`Halt::BadJump`] if it is not wholly inside the text.
    fn slot_at(&self, pc: u64) -> Result<u64, Halt> {
        let start = match pc.checked_mul(8) {
            Some(s) if s <= usize::MAX as u64 => s as usize,
            _ => return Err(Halt::BadJump),
        };
        match self.program.text.get(start..start.wrapping_add(8)) {
            Some(b) => Ok(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])),
            None => Err(Halt::BadJump),
        }
    }

    /// Saves the caller's frame and opens a new one, as `push_frame` does: `r6..r9` and `r10` are
    /// stashed, the return pc is the slot after the call, and `r10` moves up one fixed frame.
    fn push_frame(&mut self, return_pc: u64) -> Result<(), Halt> {
        // `depth` is only ever incremented below and only past this check, so it indexes.
        self.saved_scratch[self.depth] = [self.regs[6], self.regs[7], self.regs[8], self.regs[9]];
        self.saved_fp[self.depth] = self.regs[10];
        self.ret_pc[self.depth] = return_pc;
        self.depth += 1;
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
        if self.depth == MAX_CALL_DEPTH {
            return Err(Halt::CallDepth);
        }
        self.regs[10] += STACK_FRAME as u64;
        Ok(())
    }

    /// One instruction. `Ok(None)` means carry on, `Ok(Some(r0))` that the program exited.
    #[allow(clippy::cognitive_complexity)]
    fn step(&mut self) -> Result<Option<u64>, Halt> {
        let pc = self.pc;
        let i: Insn = isa::decode(self.slot_at(pc)?);
        // Registers come out of a nibble, so `dst`/`src` can name r11..r15, which do not exist.
        // `solana-sbpf` leaves that to its verifier; refusing it here is what keeps every indexing
        // below in bounds without a runtime check per access.
        if i.dst > 10 || i.src > 10 {
            return Err(Halt::BadInsn(i.opc));
        }
        let (d, s) = (i.dst as usize, i.src as usize);
        let imm64 = i.imm as i64 as u64;
        let mut next_pc = pc.wrapping_add(1);
        // `pc + 1 + off`, the target of every taken conditional jump and of `ja`.
        let jump_to = (next_pc as i64).wrapping_add(i.off as i64) as u64;

        match i.opc {
            // ---- loads ------------------------------------------------------------------------
            opc::LD_DW_IMM => {
                let hi = isa::decode(self.slot_at(pc.wrapping_add(1))?);
                self.regs[d] = isa::lddw_imm64(i, hi);
                next_pc = pc.wrapping_add(2);
            }
            opc::LD_B_REG | opc::LD_H_REG | opc::LD_W_REG | opc::LD_DW_REG => {
                let size = match i.opc {
                    opc::LD_B_REG => 1,
                    opc::LD_H_REG => 2,
                    opc::LD_W_REG => 4,
                    _ => 8,
                };
                let addr = (self.regs[s] as i64).wrapping_add(i.off as i64) as u64;
                self.regs[d] = self.mem.load(addr, size)?;
            }

            // ---- stores -----------------------------------------------------------------------
            opc::ST_B_IMM | opc::ST_H_IMM | opc::ST_W_IMM | opc::ST_DW_IMM | opc::ST_B_REG
            | opc::ST_H_REG | opc::ST_W_REG | opc::ST_DW_REG => {
                let size = match i.opc {
                    opc::ST_B_IMM | opc::ST_B_REG => 1,
                    opc::ST_H_IMM | opc::ST_H_REG => 2,
                    opc::ST_W_IMM | opc::ST_W_REG => 4,
                    _ => 8,
                };
                let from_reg = matches!(
                    i.opc,
                    opc::ST_B_REG | opc::ST_H_REG | opc::ST_W_REG | opc::ST_DW_REG
                );
                let v = if from_reg { self.regs[s] } else { imm64 };
                let addr = (self.regs[d] as i64).wrapping_add(i.off as i64) as u64;
                self.mem.store(addr, size, v)?;
            }

            // ---- 32-bit arithmetic ------------------------------------------------------------
            // The three that sign-extend their 32-bit result.
            opc::ADD32_IMM => self.regs[d] = (self.regs[d] as i32).wrapping_add(i.imm) as i64 as u64,
            opc::ADD32_REG => {
                self.regs[d] = (self.regs[d] as i32).wrapping_add(self.regs[s] as i32) as i64 as u64
            }
            opc::SUB32_IMM => self.regs[d] = (self.regs[d] as i32).wrapping_sub(i.imm) as i64 as u64,
            opc::SUB32_REG => {
                self.regs[d] = (self.regs[d] as i32).wrapping_sub(self.regs[s] as i32) as i64 as u64
            }
            opc::MUL32_IMM => self.regs[d] = (self.regs[d] as i32).wrapping_mul(i.imm) as i64 as u64,
            opc::MUL32_REG => {
                self.regs[d] = (self.regs[d] as i32).wrapping_mul(self.regs[s] as i32) as i64 as u64
            }
            // And the rest, which zero-extend.
            opc::DIV32_IMM => {
                let v = i.imm as u32;
                if v == 0 {
                    return Err(Halt::DivByZero);
                }
                self.regs[d] = u64::from(self.regs[d] as u32 / v);
            }
            opc::DIV32_REG => {
                let v = self.regs[s] as u32;
                if v == 0 {
                    return Err(Halt::DivByZero);
                }
                self.regs[d] = u64::from(self.regs[d] as u32 / v);
            }
            opc::MOD32_IMM => {
                let v = i.imm as u32;
                if v == 0 {
                    return Err(Halt::DivByZero);
                }
                self.regs[d] = u64::from(self.regs[d] as u32 % v);
            }
            opc::MOD32_REG => {
                let v = self.regs[s] as u32;
                if v == 0 {
                    return Err(Halt::DivByZero);
                }
                self.regs[d] = u64::from(self.regs[d] as u32 % v);
            }
            opc::OR32_IMM => self.regs[d] = u64::from(self.regs[d] as u32 | i.imm as u32),
            opc::OR32_REG => self.regs[d] = u64::from(self.regs[d] as u32 | self.regs[s] as u32),
            opc::AND32_IMM => self.regs[d] = u64::from(self.regs[d] as u32 & i.imm as u32),
            opc::AND32_REG => self.regs[d] = u64::from(self.regs[d] as u32 & self.regs[s] as u32),
            opc::XOR32_IMM => self.regs[d] = u64::from(self.regs[d] as u32 ^ i.imm as u32),
            opc::XOR32_REG => self.regs[d] = u64::from(self.regs[d] as u32 ^ self.regs[s] as u32),
            opc::LSH32_IMM => {
                self.regs[d] = u64::from((self.regs[d] as u32).wrapping_shl(i.imm as u32))
            }
            opc::LSH32_REG => {
                self.regs[d] = u64::from((self.regs[d] as u32).wrapping_shl(self.regs[s] as u32))
            }
            opc::RSH32_IMM => {
                self.regs[d] = u64::from((self.regs[d] as u32).wrapping_shr(i.imm as u32))
            }
            opc::RSH32_REG => {
                self.regs[d] = u64::from((self.regs[d] as u32).wrapping_shr(self.regs[s] as u32))
            }
            opc::ARSH32_IMM => {
                self.regs[d] = u64::from((self.regs[d] as i32).wrapping_shr(i.imm as u32) as u32)
            }
            opc::ARSH32_REG => {
                self.regs[d] =
                    u64::from((self.regs[d] as i32).wrapping_shr(self.regs[s] as u32) as u32)
            }
            opc::NEG32 => self.regs[d] = u64::from((self.regs[d] as i32).wrapping_neg() as u32),
            opc::MOV32_IMM => self.regs[d] = u64::from(i.imm as u32),
            opc::MOV32_REG => self.regs[d] = u64::from(self.regs[s] as u32),
            // `le` is the identity on a little-endian host (both `solana-sbpf`'s `to_le()` and
            // this are no-ops there) and truncates to the named width; `be` swaps those bytes.
            opc::LE => {
                self.regs[d] = match i.imm {
                    16 => u64::from(self.regs[d] as u16),
                    32 => u64::from(self.regs[d] as u32),
                    64 => self.regs[d],
                    _ => return Err(Halt::BadInsn(i.opc)),
                }
            }
            opc::BE => {
                self.regs[d] = match i.imm {
                    16 => u64::from((self.regs[d] as u16).swap_bytes()),
                    32 => u64::from((self.regs[d] as u32).swap_bytes()),
                    64 => self.regs[d].swap_bytes(),
                    _ => return Err(Halt::BadInsn(i.opc)),
                }
            }

            // ---- 64-bit arithmetic ------------------------------------------------------------
            opc::ADD64_IMM => self.regs[d] = self.regs[d].wrapping_add(imm64),
            opc::ADD64_REG => self.regs[d] = self.regs[d].wrapping_add(self.regs[s]),
            opc::SUB64_IMM => self.regs[d] = self.regs[d].wrapping_sub(imm64),
            opc::SUB64_REG => self.regs[d] = self.regs[d].wrapping_sub(self.regs[s]),
            opc::MUL64_IMM => self.regs[d] = self.regs[d].wrapping_mul(imm64),
            opc::MUL64_REG => self.regs[d] = self.regs[d].wrapping_mul(self.regs[s]),
            opc::DIV64_IMM | opc::DIV64_REG | opc::MOD64_IMM | opc::MOD64_REG => {
                let v = if matches!(i.opc, opc::DIV64_IMM | opc::MOD64_IMM) {
                    imm64
                } else {
                    self.regs[s]
                };
                if v == 0 {
                    return Err(Halt::DivByZero);
                }
                self.regs[d] = if matches!(i.opc, opc::DIV64_IMM | opc::DIV64_REG) {
                    self.regs[d] / v
                } else {
                    self.regs[d] % v
                };
            }
            opc::OR64_IMM => self.regs[d] |= imm64,
            opc::OR64_REG => self.regs[d] |= self.regs[s],
            opc::AND64_IMM => self.regs[d] &= imm64,
            opc::AND64_REG => self.regs[d] &= self.regs[s],
            opc::XOR64_IMM => self.regs[d] ^= imm64,
            opc::XOR64_REG => self.regs[d] ^= self.regs[s],
            opc::LSH64_IMM => self.regs[d] = self.regs[d].wrapping_shl(i.imm as u32),
            opc::LSH64_REG => self.regs[d] = self.regs[d].wrapping_shl(self.regs[s] as u32),
            opc::RSH64_IMM => self.regs[d] = self.regs[d].wrapping_shr(i.imm as u32),
            opc::RSH64_REG => self.regs[d] = self.regs[d].wrapping_shr(self.regs[s] as u32),
            opc::ARSH64_IMM => {
                self.regs[d] = (self.regs[d] as i64).wrapping_shr(i.imm as u32) as u64
            }
            opc::ARSH64_REG => {
                self.regs[d] = (self.regs[d] as i64).wrapping_shr(self.regs[s] as u32) as u64
            }
            opc::NEG64 => self.regs[d] = (self.regs[d] as i64).wrapping_neg() as u64,
            opc::MOV64_IMM => self.regs[d] = imm64,
            opc::MOV64_REG => self.regs[d] = self.regs[s],

            // ---- control flow -----------------------------------------------------------------
            opc::JA => next_pc = jump_to,
            opc::JEQ_IMM => taken(self.regs[d] == imm64, &mut next_pc, jump_to),
            opc::JEQ_REG => taken(self.regs[d] == self.regs[s], &mut next_pc, jump_to),
            opc::JNE_IMM => taken(self.regs[d] != imm64, &mut next_pc, jump_to),
            opc::JNE_REG => taken(self.regs[d] != self.regs[s], &mut next_pc, jump_to),
            opc::JGT_IMM => taken(self.regs[d] > imm64, &mut next_pc, jump_to),
            opc::JGT_REG => taken(self.regs[d] > self.regs[s], &mut next_pc, jump_to),
            opc::JGE_IMM => taken(self.regs[d] >= imm64, &mut next_pc, jump_to),
            opc::JGE_REG => taken(self.regs[d] >= self.regs[s], &mut next_pc, jump_to),
            opc::JLT_IMM => taken(self.regs[d] < imm64, &mut next_pc, jump_to),
            opc::JLT_REG => taken(self.regs[d] < self.regs[s], &mut next_pc, jump_to),
            opc::JLE_IMM => taken(self.regs[d] <= imm64, &mut next_pc, jump_to),
            opc::JLE_REG => taken(self.regs[d] <= self.regs[s], &mut next_pc, jump_to),
            opc::JSET_IMM => taken(self.regs[d] & imm64 != 0, &mut next_pc, jump_to),
            opc::JSET_REG => taken(self.regs[d] & self.regs[s] != 0, &mut next_pc, jump_to),
            opc::JSGT_IMM => taken((self.regs[d] as i64) > i.imm as i64, &mut next_pc, jump_to),
            opc::JSGT_REG => {
                taken((self.regs[d] as i64) > self.regs[s] as i64, &mut next_pc, jump_to)
            }
            opc::JSGE_IMM => taken((self.regs[d] as i64) >= i.imm as i64, &mut next_pc, jump_to),
            opc::JSGE_REG => {
                taken((self.regs[d] as i64) >= self.regs[s] as i64, &mut next_pc, jump_to)
            }
            opc::JSLT_IMM => taken((self.regs[d] as i64) < i.imm as i64, &mut next_pc, jump_to),
            opc::JSLT_REG => {
                taken((self.regs[d] as i64) < self.regs[s] as i64, &mut next_pc, jump_to)
            }
            opc::JSLE_IMM => taken((self.regs[d] as i64) <= i.imm as i64, &mut next_pc, jump_to),
            opc::JSLE_REG => {
                taken((self.regs[d] as i64) <= self.regs[s] as i64, &mut next_pc, jump_to)
            }

            opc::CALL_IMM => {
                if i.src == 1 {
                    // A syscall: the loader put murmur3 of its name in the immediate.
                    crate::syscalls::dispatch(self, i.imm as u32)?;
                } else if i.src == 0 {
                    // A slot-relative call. The frame is pushed first and the target checked
                    // after, as `solana-sbpf` does, so a too-deep call reports its depth.
                    self.push_frame(next_pc)?;
                    let target = (next_pc as i64).wrapping_add(i.imm as i64) as u64;
                    self.slot_at(target)?;
                    next_pc = target;
                } else {
                    // `src` is the loader's own marker; nothing else is a call it produced.
                    return Err(Halt::BadInsn(i.opc));
                }
            }
            opc::CALL_REG => {
                // v1 takes the target *address* from the register the immediate names (v2 moved
                // it to `src`); anything but r0..r10 is not a register.
                let r = i.imm as u32 as usize;
                if r > 10 {
                    return Err(Halt::BadInsn(i.opc));
                }
                let addr = self.regs[r];
                self.push_frame(next_pc)?;
                let target = addr.wrapping_sub(self.program.text_va) / 8;
                self.slot_at(target)?;
                next_pc = target;
            }
            opc::EXIT => {
                if self.depth == 0 {
                    return Ok(Some(self.regs[0]));
                }
                self.depth -= 1;
                self.regs[10] = self.saved_fp[self.depth];
                let saved = self.saved_scratch[self.depth];
                self.regs[6..10].copy_from_slice(&saved);
                next_pc = self.ret_pc[self.depth];
                self.slot_at(next_pc)?;
            }

            other => return Err(Halt::BadInsn(other)),
        }
        self.pc = next_pc;
        Ok(None)
    }
}

/// `if cond { next_pc = target }` — the one shape all 22 conditional jumps share.
#[inline]
fn taken(cond: bool, next_pc: &mut u64, target: u64) {
    if cond {
        *next_pc = target;
    }
}
