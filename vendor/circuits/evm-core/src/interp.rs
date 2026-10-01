//! The interpreter (Task 3 of the M4.3 plan): the ERC-20 subset of the EVM — stack, memory,
//! calldata, code, `SLOAD`/`SSTORE` over Merkle witnesses, 256-bit arithmetic, `KECCAK256`, logs,
//! `RETURN`/`REVERT` — with the Shanghai static gas schedule and no allocation.
//!
//! Everything the run needs is a fixed-size array, sized by the plan's limits, and none of it is
//! heap-allocated. The three big ones — the 1024-entry stack (32 KiB), 64 KiB of memory and the
//! jumpdest bitmap over 24 KiB of code (3 KiB) — live in [`Buffers`], which the [`Interpreter`]
//! **borrows**: the guest keeps one `Buffers` in `.bss` (`static mut B: Buffers = Buffers::ZERO;`,
//! all-zero so it costs no image bytes) and the `Interpreter` itself is a ~2 KiB value that costs
//! nothing to move, so neither [`Interpreter::new`]'s return nor [`Interpreter::run`]'s `self`
//! ever puts 100 KiB on the guest's 64 KiB stack. `abi::Workspace` is the whole `.bss` block —
//! the decoded input plus these buffers — and `abi::run_call` is what the guest actually calls.
//!
//! **Out of scope traps.** Every opcode outside the plan's list — the `CALL`/`CREATE` family,
//! precompiles, the block- and account-info opcodes, `TLOAD`/`TSTORE`, `MCOPY`, `BLOBHASH`,
//! `RETURNDATACOPY` with a non-zero length — halts with [`Halt::Trap`], with the single exception
//! of `0xfe`, which is [`Halt::Invalid`]. A trap is an exceptional halt: status word 2.
//!
//! **Gas** is a counter with the Shanghai static schedule for the supported subset and no refunds
//! and no warm/cold access list — `SLOAD` is always 2100 and `SSTORE` is 20 000 or 2 900 on the
//! pre-value alone. Every exceptional halt consumes the whole limit, as the EVM does; only
//! `STOP`/`RETURN`/`REVERT` leave gas on the table.
//!
//! **Logs keep their topics and drop their data.** The data range is still bounds-checked and paid
//! for (8 gas a byte, plus any memory expansion), because a contract's gas must not depend on what
//! the guest chooses to bind. The public output hashes the topics only (Task 4).

use core::cmp::min;

use crate::keccak256;
use crate::storage::{StorageError, StorageTree};
use crate::u256::U256;
use crate::Host;

/// The EVM's stack depth.
pub const STACK_LIMIT: usize = 1024;
/// The interpreter's memory, an `.bss` array rather than a growable buffer: a range past it is an
/// exceptional halt, not an expansion.
pub const MAX_MEMORY_BYTES: usize = 65_536;
/// EIP-170's contract size.
pub const MAX_CODE_BYTES: usize = 24_576;
/// The most calldata one call may carry (plan's Global Constraints).
pub const MAX_CALLDATA_BYTES: usize = 4_096;
/// The most `RETURN`/`REVERT` data one call may produce.
pub const MAX_RETURN_BYTES: usize = 1_024;
/// The most logs one call may emit.
pub const MAX_LOGS: usize = 8;
/// `LOG0`–`LOG4`.
pub const MAX_TOPICS: usize = 4;

// The Shanghai schedule, named as the yellow paper's tiers.
const G_BASE: u64 = 2;
const G_VERYLOW: u64 = 3;
const G_LOW: u64 = 5;
const G_MID: u64 = 8;
const G_HIGH: u64 = 10;
const G_JUMPDEST: u64 = 1;
const G_EXP: u64 = 10;
const G_EXP_BYTE: u64 = 50;
const G_KECCAK256: u64 = 30;
const G_KECCAK256_WORD: u64 = 6;
const G_SLOAD: u64 = 2_100;
/// A write that turns a zero slot non-zero.
const G_SSTORE_SET: u64 = 20_000;
/// Every other write. No refunds, so clearing a slot costs this too.
const G_SSTORE_RESET: u64 = 2_900;
const G_LOG: u64 = 375;
const G_LOG_TOPIC: u64 = 375;
const G_LOG_DATA: u64 = 8;
/// Per word of `CALLDATACOPY`/`CODECOPY`, on top of the `verylow` base.
const G_COPY_WORD: u64 = 3;
/// The linear term of memory expansion; the quadratic one is `w²/512`.
const G_MEMORY: u64 = 3;

/// The call's environment: the three context opcodes the subset supports, plus the gas limit.
/// An address is its 20 bytes right-aligned in a 256-bit word, as the EVM keeps them.
#[derive(Clone, Copy, Debug)]
pub struct Env {
    pub address: U256,
    pub caller: U256,
    pub callvalue: U256,
    pub gas_limit: u64,
}

/// Why the run ended. [`Outcome::status`] collapses this to the plan's status word: `Stop`/`Return`
/// are success, `Revert` is a revert, and every other variant is an exceptional halt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Halt {
    /// `STOP`, or running off the end of the code.
    Stop,
    Return,
    Revert,
    OutOfGas,
    StackUnderflow,
    /// A push onto a full 1024-entry stack.
    StackOverflow,
    /// `JUMP`/`JUMPI` to something that is not a `JUMPDEST` outside push data.
    BadJump,
    /// The `0xfe` opcode.
    Invalid,
    /// An opcode outside the plan's subset.
    Trap(u8),
    /// The bytecode touched a slot no witness was supplied for.
    NoWitness,
    /// A supplied witness does not hash to the current storage root.
    BadWitness,
    /// A static capacity was exceeded: a memory range past [`MAX_MEMORY_BYTES`], return data past
    /// [`MAX_RETURN_BYTES`], a log past [`MAX_LOGS`], or a witness past `MAX_WITNESSES`.
    OutOfBounds,
}

/// One emitted log's topics. The data is dropped (the plan's ruling) — only the topics are bound
/// by the public output, so only the topics are kept.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Log {
    pub n_topics: u8,
    pub topics: [U256; MAX_TOPICS],
}

impl Log {
    pub const EMPTY: Log = Log { n_topics: 0, topics: [U256::ZERO; MAX_TOPICS] };
}

/// What the run produced. `ret`/`logs` are fixed-size, so `ret_len`/`n_logs` say how much of each
/// is real.
///
/// The logs emitted *before* a `REVERT` are still here: dropping them is the output layer's job,
/// not the interpreter's — Task 4's `OutputDigest` hashes an empty log set whenever the status is
/// not 1, so a reverted call binds no logs however many were emitted. Keeping them here means the
/// interpreter has one behaviour rather than two and a host-side test can see what the bytecode
/// actually did.
pub struct Outcome {
    pub halt: Halt,
    pub gas_used: u64,
    pub ret: [u8; MAX_RETURN_BYTES],
    pub ret_len: usize,
    pub logs: [Log; MAX_LOGS],
    pub n_logs: usize,
}

impl Outcome {
    /// The plan's status word (`out0`): 1 success, 0 revert, 2 exceptional halt.
    pub fn status(&self) -> u32 {
        match self.halt {
            Halt::Stop | Halt::Return => 1,
            Halt::Revert => 0,
            _ => 2,
        }
    }
}

/// The interpreter's three big working arrays, with no borrows of their own so they can sit in a
/// guest's `.bss` as a plain `static mut B: Buffers = Buffers::ZERO;` and be lent to an
/// [`Interpreter`] rather than copied into one. 99.6 KiB; the fields are private because only the
/// interpreter may touch them, and [`Interpreter::new`] resets the two that must start clean.
pub struct Buffers {
    stack: [U256; STACK_LIMIT],
    memory: [u8; MAX_MEMORY_BYTES],
    /// Bit `i` is set iff `code[i]` is a `JUMPDEST` that is not inside a `PUSHn`'s immediate.
    jumpdests: [u32; MAX_CODE_BYTES / 32],
    /// How many bytes of `memory`, and how many words of `jumpdests`, the *previous* run left
    /// non-zero — so [`Interpreter::new`] can clear exactly those instead of all 68 KiB.
    ///
    /// This is a cycle-count matter, not a correctness one: zeroing the whole 64 KiB array cost
    /// ~50 000 guest cycles a call (M4.3's measurement — most of a whole tier's budget) for a
    /// guest whose `.bss` the machine already guarantees starts zeroed, and a *fresh* workspace's
    /// `Buffers::ZERO` therefore needs no clearing at all. `memory`'s high-water mark is the
    /// EVM's own `msize`, which every access bumps through [`Interpreter::mem`].
    dirty_mem: usize,
    dirty_jd: usize,
}

impl Buffers {
    /// All zeros — a valid, unused set of buffers, and a `const` so a `static` holding one lands
    /// in `.bss` (no image bytes) instead of `.data`.
    pub const ZERO: Buffers = Buffers {
        stack: [U256::ZERO; STACK_LIMIT],
        memory: [0; MAX_MEMORY_BYTES],
        jumpdests: [0; MAX_CODE_BYTES / 32],
        dirty_mem: 0,
        dirty_jd: 0,
    };
}

/// The EVM interpreter over one contract's code, calldata and storage witnesses.
///
/// `h`, `code`, `calldata`, `storage` and the big [`Buffers`] are borrowed; only the return buffer
/// and the logs (2 KiB, and both move straight into the [`Outcome`]) are owned. See the module docs
/// on why the big arrays are borrowed rather than owned.
pub struct Interpreter<'a, H: Host> {
    h: &'a mut H,
    code: &'a [u8],
    calldata: &'a [u8],
    env: Env,
    storage: &'a mut StorageTree,
    bufs: &'a mut Buffers,
    sp: usize,
    /// The highest touched byte rounded up to 32 — what `MSIZE` pushes and what memory expansion
    /// is charged against.
    msize: usize,
    pc: usize,
    gas: u64,
    ret: [u8; MAX_RETURN_BYTES],
    ret_len: usize,
    logs: [Log; MAX_LOGS],
    n_logs: usize,
    /// Set by `new` when the code or the calldata is above its limit, and returned by `run` before
    /// a single opcode executes. An over-long input is the prover's doing, so it has to be an
    /// exceptional halt the proof reports — never a panic, which in the guest is an abort and no
    /// proof at all.
    pre_halt: Option<Halt>,
}

impl<'a, H: Host> Interpreter<'a, H> {
    /// Never panics. `code` above [`MAX_CODE_BYTES`] or `calldata` above [`MAX_CALLDATA_BYTES`]
    /// arms `pre_halt`, which [`run`](Interpreter::run) returns as an exceptional halt before
    /// anything executes, so the storage root, the return data, the logs and the gas counter are all
    /// left as they were. Both lengths come out of the prover-supplied input vector, so neither may
    /// be an `assert!`: a panicking guest aborts and produces no proof at all, where an exceptional
    /// halt produces a proof that says the call was invalid. Task 4's input cursor refuses the same
    /// two lengths at parse time; this is the belt to its braces.
    ///
    /// `bufs` may be a set of buffers a previous run used: the memory and the jumpdest bitmap are
    /// reset here (EVM memory reads as zero, and `scan_jumpdests` only ever *sets* bits), while
    /// the stack needs no reset because `sp` starts at zero and nothing is read above it.
    pub fn new(
        h: &'a mut H,
        code: &'a [u8],
        calldata: &'a [u8],
        env: Env,
        storage: &'a mut StorageTree,
        bufs: &'a mut Buffers,
    ) -> Self {
        let pre_halt = if code.len() > MAX_CODE_BYTES || calldata.len() > MAX_CALLDATA_BYTES {
            Some(Halt::OutOfBounds)
        } else {
            None
        };
        // Nothing past either cap is ever stored or read: the slices are capped here (they are
        // borrowed, so this copies nothing), which is also what keeps `scan_jumpdests` inside the
        // bitmap without a second branch.
        let code = &code[..min(code.len(), MAX_CODE_BYTES)];
        let calldata = &calldata[..min(calldata.len(), MAX_CALLDATA_BYTES)];
        // Only what a previous run dirtied, which on a fresh `Buffers::ZERO` (the guest's `.bss`,
        // and the first call of any host test) is nothing at all.
        bufs.memory[..bufs.dirty_mem].fill(0);
        bufs.jumpdests[..bufs.dirty_jd].fill(0);
        bufs.dirty_mem = 0;
        bufs.dirty_jd = code.len().div_ceil(32);
        scan_jumpdests(code, &mut bufs.jumpdests);
        Interpreter {
            h,
            code,
            calldata,
            env,
            storage,
            bufs,
            sp: 0,
            msize: 0,
            pc: 0,
            gas: env.gas_limit,
            ret: [0; MAX_RETURN_BYTES],
            ret_len: 0,
            logs: [Log::EMPTY; MAX_LOGS],
            n_logs: 0,
            pre_halt,
        }
    }

    /// Execute until the code halts.
    pub fn run(mut self) -> Outcome {
        if let Some(halt) = self.pre_halt {
            // The call never began, so nothing was spent — the "an exceptional halt burns the whole
            // limit" rule below is about a run that started and then failed, and this is a malformed
            // call rather than a failed one. Everything else is untouched by construction: `ret`,
            // `logs` and the gas counter are as `new` left them and the storage tree still holds the
            // pre-state root.
            return Outcome {
                halt,
                gas_used: 0,
                ret: self.ret,
                ret_len: self.ret_len,
                logs: self.logs,
                n_logs: self.n_logs,
            };
        }
        let halt = loop {
            match self.step() {
                Ok(None) => {}
                Ok(Some(h)) | Err(h) => break h,
            }
        };
        // Every exceptional halt consumes the whole limit, as the EVM does; `INVALID`, a trap, a
        // bad jump and a stack fault are all "the run was invalid", and nothing downstream reads
        // the gas of a status-2 outcome anyway.
        let left = match halt {
            Halt::Stop | Halt::Return | Halt::Revert => self.gas,
            _ => 0,
        };
        // What the next run has to clear: every byte this one could have written is below `msize`.
        self.bufs.dirty_mem = self.msize;
        Outcome {
            halt,
            gas_used: self.env.gas_limit - left,
            ret: self.ret,
            ret_len: self.ret_len,
            logs: self.logs,
            n_logs: self.n_logs,
        }
    }

    /// One opcode. `Ok(None)` continues, `Ok(Some(h))` is an orderly halt, `Err(h)` is one raised
    /// by `?` from a charge, a stack access or a memory access.
    fn step(&mut self) -> Result<Option<Halt>, Halt> {
        let pc = self.pc;
        let Some(&op) = self.code.get(pc) else {
            return Ok(Some(Halt::Stop));
        };
        self.pc = pc + 1;
        self.charge(static_gas(op))?;
        match op {
            0x00 => return Ok(Some(Halt::Stop)),

            // ---- arithmetic ----
            0x01 => self.binary(|a, b| a.add(b))?,
            0x02 => self.binary(|a, b| a.mul(b))?,
            0x03 => self.binary(|a, b| a.sub(b))?,
            0x04 => self.binary(|a, b| a.div(b))?,
            0x05 => self.binary(|a, b| a.sdiv(b))?,
            0x06 => self.binary(|a, b| a.rem(b))?,
            0x07 => self.binary(|a, b| a.smod(b))?,
            0x08 => {
                let (a, b, m) = (self.pop()?, self.pop()?, self.pop()?);
                self.push(a.addmod(&b, &m))?;
            }
            0x09 => {
                let (a, b, m) = (self.pop()?, self.pop()?, self.pop()?);
                self.push(a.mulmod(&b, &m))?;
            }
            0x0a => {
                let (base, e) = (self.pop()?, self.pop()?);
                self.charge(G_EXP + G_EXP_BYTE * e.byte_len() as u64)?;
                self.push(base.exp(&e))?;
            }
            0x0b => self.binary(|b, x| x.signextend(b))?,

            // ---- comparison and bitwise ----
            0x10 => self.binary(|a, b| bool_word(a.lt(b)))?,
            0x11 => self.binary(|a, b| bool_word(b.lt(a)))?,
            0x12 => self.binary(|a, b| bool_word(a.slt(b)))?,
            0x13 => self.binary(|a, b| bool_word(b.slt(a)))?,
            0x14 => self.binary(|a, b| bool_word(a == b))?,
            0x15 => {
                let a = self.pop()?;
                self.push(bool_word(a.is_zero()))?;
            }
            0x16 => self.binary(|a, b| a.and(b))?,
            0x17 => self.binary(|a, b| a.or(b))?,
            0x18 => self.binary(|a, b| a.xor(b))?,
            0x19 => {
                let a = self.pop()?;
                self.push(a.not())?;
            }
            0x1a => self.binary(|i, x| x.byte(i))?,
            0x1b => self.binary(|n, x| x.shl(n))?,
            0x1c => self.binary(|n, x| x.shr(n))?,
            0x1d => self.binary(|n, x| x.sar(n))?,

            // ---- keccak ----
            0x20 => {
                let (offset, size) = (self.pop()?, self.pop()?);
                let len = len_arg(&size)?;
                self.charge(G_KECCAK256 + G_KECCAK256_WORD * words(len))?;
                let start = self.mem(&offset, len)?;
                let d = keccak256(&mut *self.h, &self.bufs.memory[start..start + len]);
                self.push(U256::from_be_bytes(&d))?;
            }

            // ---- environment ----
            0x30 => self.push(self.env.address)?,
            0x33 => self.push(self.env.caller)?,
            0x34 => self.push(self.env.callvalue)?,
            0x35 => {
                let offset = self.pop()?;
                self.push(read_padded(self.calldata, &offset))?;
            }
            0x36 => self.push(U256::from_u32(self.calldata.len() as u32))?,
            0x37 => self.copy_to_memory(self.calldata)?,
            0x38 => self.push(U256::from_u32(self.code.len() as u32))?,
            0x39 => self.copy_to_memory(self.code)?,
            0x3d => self.push(U256::ZERO)?,
            0x3e => {
                // No call is ever made, so the return-data buffer is always empty: copying
                // nothing out of it is a no-op, copying anything out of it cannot be honoured.
                let (_dest, _offset, size) = (self.pop()?, self.pop()?, self.pop()?);
                if !size.is_zero() {
                    return Ok(Some(Halt::Trap(op)));
                }
            }

            // ---- stack, memory, storage, flow ----
            0x50 => {
                self.pop()?;
            }
            0x51 => {
                let offset = self.pop()?;
                let start = self.mem(&offset, 32)?;
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&self.bufs.memory[start..start + 32]);
                self.push(U256::from_be_bytes(&bytes))?;
            }
            0x52 => {
                let (offset, value) = (self.pop()?, self.pop()?);
                let start = self.mem(&offset, 32)?;
                self.bufs.memory[start..start + 32].copy_from_slice(&value.to_be_bytes());
            }
            0x53 => {
                let (offset, value) = (self.pop()?, self.pop()?);
                let start = self.mem(&offset, 1)?;
                self.bufs.memory[start] = value.low_u32() as u8;
            }
            0x54 => {
                let slot = self.pop()?;
                let v = self.storage.load(&mut *self.h, &slot).map_err(halt_of)?;
                self.push(v)?;
            }
            0x55 => {
                let (slot, value) = (self.pop()?, self.pop()?);
                // The cost needs the pre-value, so the witness is read (and verified) first; the
                // second lookup inside `store` is free, `verify` being idempotent.
                let prev = self.storage.load(&mut *self.h, &slot).map_err(halt_of)?;
                let cost = if prev.is_zero() && !value.is_zero() {
                    G_SSTORE_SET
                } else {
                    G_SSTORE_RESET
                };
                self.charge(cost)?;
                self.storage.store(&mut *self.h, &slot, value).map_err(halt_of)?;
            }
            0x56 => {
                let dest = self.pop()?;
                self.jump(&dest)?;
            }
            0x57 => {
                let (dest, cond) = (self.pop()?, self.pop()?);
                // The destination is only validated when the branch is taken, as the EVM does.
                if !cond.is_zero() {
                    self.jump(&dest)?;
                }
            }
            0x58 => self.push(U256::from_u32(pc as u32))?,
            0x59 => self.push(U256::from_u32(self.msize as u32))?,
            // Its own 2 is already charged, so this is the gas the *next* opcode may spend.
            0x5a => self.push(U256::from_u64(self.gas))?,
            0x5b => {}

            // ---- pushes, dups, swaps ----
            0x5f => self.push(U256::ZERO)?,
            0x60..=0x7f => {
                let n = (op - 0x5f) as usize;
                // Immediate data running off the end of the code reads as zeros, as the EVM does.
                let mut b = [0u8; 32];
                for i in 0..n {
                    b[32 - n + i] = self.code.get(pc + 1 + i).copied().unwrap_or(0);
                }
                self.push(U256::from_be_bytes(&b))?;
                self.pc = pc + 1 + n;
            }
            0x80..=0x8f => {
                let n = (op - 0x7f) as usize;
                if self.sp < n {
                    return Err(Halt::StackUnderflow);
                }
                let v = self.bufs.stack[self.sp - n];
                self.push(v)?;
            }
            0x90..=0x9f => {
                let n = (op - 0x8f) as usize;
                if self.sp < n + 1 {
                    return Err(Halt::StackUnderflow);
                }
                self.bufs.stack.swap(self.sp - 1, self.sp - 1 - n);
            }

            // ---- logs ----
            0xa0..=0xa4 => {
                let n = (op - 0xa0) as usize;
                self.charge(G_LOG + G_LOG_TOPIC * n as u64)?;
                let (offset, size) = (self.pop()?, self.pop()?);
                let len = len_arg(&size)?;
                // The data is dropped but still paid for and bounds-checked, so what the guest
                // binds never changes what the bytecode costs.
                self.charge(G_LOG_DATA * len as u64)?;
                self.mem(&offset, len)?;
                if self.n_logs == MAX_LOGS {
                    return Err(Halt::OutOfBounds);
                }
                let mut log = Log::EMPTY;
                log.n_topics = n as u8;
                for i in 0..n {
                    log.topics[i] = self.pop()?;
                }
                self.logs[self.n_logs] = log;
                self.n_logs += 1;
            }

            // ---- halts ----
            0xf3 | 0xfd => {
                let (offset, size) = (self.pop()?, self.pop()?);
                let len = len_arg(&size)?;
                if len > MAX_RETURN_BYTES {
                    return Err(Halt::OutOfBounds);
                }
                let start = self.mem(&offset, len)?;
                self.ret[..len].copy_from_slice(&self.bufs.memory[start..start + len]);
                self.ret_len = len;
                return Ok(Some(if op == 0xf3 { Halt::Return } else { Halt::Revert }));
            }
            0xfe => return Ok(Some(Halt::Invalid)),

            _ => return Ok(Some(Halt::Trap(op))),
        }
        Ok(None)
    }

    fn charge(&mut self, cost: u64) -> Result<(), Halt> {
        self.gas = self.gas.checked_sub(cost).ok_or(Halt::OutOfGas)?;
        Ok(())
    }

    fn push(&mut self, v: U256) -> Result<(), Halt> {
        if self.sp == STACK_LIMIT {
            return Err(Halt::StackOverflow);
        }
        self.bufs.stack[self.sp] = v;
        self.sp += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<U256, Halt> {
        if self.sp == 0 {
            return Err(Halt::StackUnderflow);
        }
        self.sp -= 1;
        Ok(self.bufs.stack[self.sp])
    }

    /// The shape every two-operand opcode has: pop the top two — `a` is the top — and push
    /// `f(&a, &b)`.
    fn binary(&mut self, f: impl FnOnce(&U256, &U256) -> U256) -> Result<(), Halt> {
        let (a, b) = (self.pop()?, self.pop()?);
        self.push(f(&a, &b))
    }

    /// Resolve a memory range to a start index, charging any expansion and bumping `msize`. A
    /// zero-length access touches nothing and pays nothing, whatever its offset — the EVM's rule,
    /// and what makes `RETURN(huge, 0)` legal.
    fn mem(&mut self, offset: &U256, len: usize) -> Result<usize, Halt> {
        if len == 0 {
            return Ok(0);
        }
        if !offset.fits_u32() {
            return Err(Halt::OutOfBounds);
        }
        let start = offset.low_u32() as usize;
        let end = start.checked_add(len).ok_or(Halt::OutOfBounds)?;
        if end > MAX_MEMORY_BYTES {
            return Err(Halt::OutOfBounds);
        }
        let w = words(end);
        let want = w as usize * 32;
        if want > self.msize {
            self.charge(expansion_cost(w) - expansion_cost(words(self.msize)))?;
            self.msize = want;
        }
        Ok(start)
    }

    /// `CALLDATACOPY`/`CODECOPY`: pop destination, source offset and length, charge the per-word
    /// term and the expansion, then copy with zero padding past the end of `src`.
    fn copy_to_memory(&mut self, src: &[u8]) -> Result<(), Halt> {
        let (dest, offset, size) = (self.pop()?, self.pop()?, self.pop()?);
        let len = len_arg(&size)?;
        self.charge(G_COPY_WORD * words(len))?;
        let start = self.mem(&dest, len)?;
        let from = src_offset(&offset);
        for i in 0..len {
            let s = from.saturating_add(i as u64);
            self.bufs.memory[start + i] = if s < src.len() as u64 { src[s as usize] } else { 0 };
        }
        Ok(())
    }

    /// `JUMP`/`JUMPI`'s destination check: a `JUMPDEST` inside the code and outside push data.
    fn jump(&mut self, dest: &U256) -> Result<(), Halt> {
        if !dest.fits_u32() {
            return Err(Halt::BadJump);
        }
        let t = dest.low_u32() as usize;
        if t >= self.code.len() || (self.bufs.jumpdests[t / 32] >> (t % 32)) & 1 == 0 {
            return Err(Halt::BadJump);
        }
        self.pc = t;
        Ok(())
    }
}

/// Set bit `i` for every `JUMPDEST` at `i` that is not inside a `PUSHn`'s immediate — the one scan
/// of the code the interpreter does, and the reason `JUMP` is a bitmap test rather than a rescan.
pub fn scan_jumpdests(code: &[u8], bits: &mut [u32; MAX_CODE_BYTES / 32]) {
    let mut i = 0;
    while i < code.len() {
        let op = code[i];
        if op == 0x5b {
            bits[i / 32] |= 1 << (i % 32);
        }
        // `PUSH1`–`PUSH32` (`PUSH0` carries no immediate, so it is not in this range).
        i += if (0x60..=0x7f).contains(&op) { 1 + (op - 0x5f) as usize } else { 1 };
    }
}

/// The Shanghai static gas of `op`: the part that does not depend on the operands. Opcodes whose
/// cost is wholly dynamic (`EXP`, `KECCAK256`, `SSTORE`, `LOGn`) charge it in their own arm and are
/// zero here, as are the free ones (`STOP`, `RETURN`, `REVERT`, `INVALID`) and every unsupported
/// byte, which traps before its cost could matter.
pub const fn static_gas(op: u8) -> u64 {
    match op {
        0x5b => G_JUMPDEST,
        // base
        0x30 | 0x33 | 0x34 | 0x36 | 0x38 | 0x3d | 0x50 | 0x58 | 0x59 | 0x5a | 0x5f => G_BASE,
        // verylow: ADD/SUB, every comparison and bitwise opcode, CALLDATALOAD, MLOAD/MSTORE/
        // MSTORE8, the copies' base, PUSHn, DUPn, SWAPn
        0x01 | 0x03 | 0x10..=0x1d | 0x35 | 0x37 | 0x39 | 0x3e | 0x51..=0x53 | 0x60..=0x9f => {
            G_VERYLOW
        }
        // low
        0x02 | 0x04..=0x07 | 0x0b => G_LOW,
        // mid
        0x08 | 0x09 | 0x56 => G_MID,
        // high
        0x57 => G_HIGH,
        0x54 => G_SLOAD,
        _ => 0,
    }
}

/// Memory expansion's cost at `w` words: `3w + ⌊w²/512⌋`.
fn expansion_cost(w: u64) -> u64 {
    G_MEMORY * w + w * w / 512
}

/// Bytes rounded up to whole 32-byte words.
fn words(bytes: usize) -> u64 {
    (bytes as u64 + 31) / 32
}

/// A stack operand used as a byte count. Anything that cannot be a memory range is
/// [`Halt::OutOfBounds`] rather than a gas charge computed from a 256-bit number.
fn len_arg(v: &U256) -> Result<usize, Halt> {
    if !v.fits_u32() || v.low_u32() as usize > MAX_MEMORY_BYTES {
        return Err(Halt::OutOfBounds);
    }
    Ok(v.low_u32() as usize)
}

/// A read offset into calldata or code as a `u64`, so that an offset near `u32::MAX` cannot wrap
/// the index on a 32-bit target. Anything too wide for a `u32` is simply past the end of every
/// source, and reads as `u64::MAX` — all padding.
fn src_offset(v: &U256) -> u64 {
    if v.fits_u32() {
        v.low_u32() as u64
    } else {
        u64::MAX
    }
}

/// 32 bytes of `src` from `offset`, zero-padded past its end — `CALLDATALOAD`.
fn read_padded(src: &[u8], offset: &U256) -> U256 {
    let from = src_offset(offset);
    let mut b = [0u8; 32];
    for i in 0..32 {
        let s = from.saturating_add(i as u64);
        if s < src.len() as u64 {
            b[i] = src[s as usize];
        }
    }
    U256::from_be_bytes(&b)
}

/// Every storage failure is an exceptional halt; `TooMany` and `DuplicateIndex` cannot reach here
/// (only `StorageTree::push` returns them, and Task 4's input cursor is what calls that — where
/// both become a `ParseError` and the canonical malformed output), but both are input defects of
/// the same kind as a capacity overrun.
fn halt_of(e: StorageError) -> Halt {
    match e {
        StorageError::NoWitness => Halt::NoWitness,
        StorageError::BadWitness => Halt::BadWitness,
        StorageError::TooMany | StorageError::DuplicateIndex => Halt::OutOfBounds,
    }
}

/// The EVM's boolean: `1` or `0` in a 256-bit word.
fn bool_word(b: bool) -> U256 {
    if b {
        U256::ONE
    } else {
        U256::ZERO
    }
}
