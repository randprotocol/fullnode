//! The rVM's reference semantics, and the instrument M5.1 measures with.
//!
//! [`execute`] runs a [`Program`] against a witness tape and returns one [`Event`] per executed
//! instruction, carrying everything M5.2's tables are generated from: the `pc`/`next_pc` pair, the
//! three operand values, every memory access with its timestamp, and the Poseidon2 permutation
//! the row dispatches (`POSEIDON2` rows only). Cpu rows and permutations per verified inner proof
//! are therefore counted rather than estimated.
//!
//! Two rules from the spec show up as errors here and as unsatisfiable rows in M5.2, and neither
//! is ever a panic: an inverse of zero (`INV`/`EINV` take their hint from the emulator, spec §10,
//! so a zero operand cannot be papered over by a witness) and an address at or above
//! [`MEM_LIMIT`].

use std::collections::HashMap;

use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};

use crate::isa::{DecodeError, Instr, Op, Program, EF, F, MEM_LIMIT, NUM_REGS};

/// Timestamp slots per cpu row. Sixteen is what `POSEIDON2`'s eight reads and eight writes need;
/// M5.2's `memory` table asks only for strict monotonicity, which `16·clk + k` gives.
pub const TS_PER_ROW: u32 = 16;

/// The `REDUCE` run's timestamp slots, shared with the `reduce` chip's memory messages (Task 8):
/// the 11 descriptor cells at slots `0..11`, the per-column reads reusing slots `11..14`
/// (distinct addresses per column, which is all the memory table's monotonicity asks), and the
/// four write-backs at slots 14–15 (distinct addresses from the reads).
pub const TS_RUN_PZ0: u32 = 11;
pub const TS_RUN_PZ1: u32 = 12;
pub const TS_RUN_PX: u32 = 13;
pub const TS_WB_ACC0: u32 = 14;
pub const TS_WB_ACC1: u32 = 15;
pub const TS_WB_APOW0: u32 = 14;
pub const TS_WB_APOW1: u32 = 15;

/// One cell read or written, at the timestamp `16·clk + k` of its slot in the row.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct MemAccess {
    pub addr: u64,
    pub ts: u32,
    pub value: F,
    pub is_write: bool,
}

/// The width-8 permutation a `POSEIDON2` row dispatches, over the eight cells at `ptr`.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PermEvent {
    pub ptr: u64,
    pub input: [F; 8],
    pub output: [F; 8],
    /// `Some(src)` for a `SPONGE` absorb (the four source cells at `src` feeding rate lanes 0–3),
    /// `None` for a plain `POSEIDON2` (all eight cells from `ptr`).
    pub src: Option<u64>,
}

/// One run of the batch-opening reduction a `REDUCE` row dispatches (Task 8): the descriptor
/// the chip's first row reads, its run length, and the run constants. The accumulator and the
/// running power are chained in and out through the descriptor in memory.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ReduceEvent {
    pub descr_ptr: u64,
    pub vals_base: u64,
    pub row_base: u64,
    pub len: u32,
    pub inv: [F; 2],
    pub acc: [F; 2],
    pub apow: [F; 2],
    pub alpha: [F; 2],
}

/// One executed instruction.
///
/// `d`, `a` and `b_val` are the row's three operand values, one per encoded slot: `d` is what the
/// instruction writes to `rd` (or, for `STORE`/`STOREE`/`JEQ`/`JNE`, what it reads from it), `a`
/// what it reads from `ra`, and `b_val` the fourth word's value — the pair read from `rb` for the
/// register-operand opcodes, `[imm, 0]` otherwise. Lane 1 is zero for a base-field operand, and a
/// slot the opcode does not use at all is `[0, 0]`.
#[derive(Clone, PartialEq, Debug)]
pub struct Event {
    pub clk: u32,
    pub pc: u32,
    pub next_pc: u32,
    pub instr: Instr,
    pub a: [F; 2],
    pub b_val: [F; 2],
    pub d: [F; 2],
    pub mem: Vec<MemAccess>,
    pub perm: Option<PermEvent>,
    pub reduce: Option<ReduceEvent>,
}

/// A completed run: the event log, the public values the program appended, the number of witness
/// words consumed, and the highest cell address touched (zero if the program touched no memory).
#[derive(Clone, PartialEq, Debug)]
pub struct Execution {
    pub events: Vec<Event>,
    pub public: Vec<F>,
    pub hints_read: usize,
    pub max_addr: u64,
}

impl Execution {
    /// One row per executed instruction.
    pub fn cpu_rows(&self) -> usize {
        self.events.len()
    }

    /// The `poseidon2` chip's height: one permutation per `POSEIDON2` row, nothing else.
    pub fn permutations(&self) -> usize {
        self.events.iter().filter(|e| e.perm.is_some()).count()
    }

    /// The `memory` table's height.
    pub fn mem_accesses(&self) -> usize {
        self.events.iter().map(|e| e.mem.len()).sum()
    }

    /// How often each opcode ran, indexed by `op as usize`.
    pub fn histogram(&self) -> [usize; Op::COUNT] {
        let mut out = [0usize; Op::COUNT];
        for e in &self.events {
            out[e.instr.op as usize] += 1;
        }
        out
    }
}

/// Why a run stopped short. Every variant carries the `pc` (or the limit) that explains it; a
/// failed in-program assertion arrives as `InverseOfZero`, which `Program::checkpoint_at` turns
/// back into the name of the assertion.
#[derive(Clone, PartialEq, Debug)]
pub enum ExecError {
    Decode { pc: u32, err: DecodeError },
    PcOutOfRange(u64),
    AddressOutOfRange { pc: u32, addr: u64 },
    InverseOfZero { pc: u32 },
    HintExhausted { pc: u32 },
    OutOfCycles(usize),
    /// A `REDUCE` descriptor declared a zero-length run: there is nothing to reduce, and a
    /// `REDUCE` of zero columns is a build-time mistake (the program must not emit it).
    ReduceZeroLength { pc: u32 },
}

/// Run `p` against `witness` for at most `max_cycles` instructions.
///
/// Stops on `HALT`. Running past the end of the instruction list, or past `max_cycles`, is
/// [`ExecError::OutOfCycles`] — a program that does not halt has not produced a proof either way.
/// `max_cycles` must stay below `2^28` for the `16·clk + k` timestamps to fit a `u32`; M5.1's
/// programs are four orders of magnitude under that.
pub fn execute(p: &Program, witness: &[F], max_cycles: usize) -> Result<Execution, ExecError> {
    let mut regs = [F::ZERO; NUM_REGS];
    let mut mem: HashMap<u64, F> = HashMap::new();
    let mut run = Execution { events: Vec::new(), public: Vec::new(), hints_read: 0, max_addr: 0 };
    let mut pc: u32 = 0;

    loop {
        let clk = run.events.len();
        if clk >= max_cycles {
            return Err(ExecError::OutOfCycles(max_cycles));
        }
        let clk = clk as u32;
        let instr = *p
            .instrs
            .get(pc as usize)
            .ok_or(ExecError::OutOfCycles(max_cycles))?;

        // The emulator validates what `Instr::decode` validates — an `Instr` built by hand
        // (the DSL's own output is never encoded before it runs) gets the same treatment.
        let rd = reg(instr.rd, "rd", pc)? as usize;
        let ra = reg(instr.ra, "ra", pc)? as usize;
        let op = instr.op;

        let mut mems: Vec<MemAccess> = Vec::new();
        let mut perm = None;
        let mut reduce = None;
        let mut a = [F::ZERO; 2];
        let mut b_val = if op.b_is_register() { [F::ZERO; 2] } else { [instr.b, F::ZERO] };
        let mut d = [F::ZERO; 2];
        let mut next_pc = pc.wrapping_add(1);

        match op {
            Op::Fadd | Op::Fsub | Op::Fmul => {
                let rb = reg_b(&instr, pc)? as usize;
                a[0] = regs[ra];
                b_val[0] = regs[rb];
                d[0] = match op {
                    Op::Fadd => a[0] + b_val[0],
                    Op::Fsub => a[0] - b_val[0],
                    _ => a[0] * b_val[0],
                };
                set(&mut regs, rd, d[0]);
            }
            Op::Faddi | Op::Fmuli => {
                a[0] = regs[ra];
                d[0] = if op == Op::Faddi { a[0] + instr.b } else { a[0] * instr.b };
                set(&mut regs, rd, d[0]);
            }
            Op::Eadd | Op::Esub | Op::Emul => {
                pair(instr.rd, "rd", pc)?;
                pair(instr.ra, "ra", pc)?;
                let rb = pair(reg_b(&instr, pc)?, "rb", pc)? as usize;
                a = [regs[ra], regs[ra + 1]];
                b_val = [regs[rb], regs[rb + 1]];
                let (x, y) = (ext(a), ext(b_val));
                d = parts(match op {
                    Op::Eadd => x + y,
                    Op::Esub => x - y,
                    _ => x * y,
                });
                set_pair(&mut regs, rd, d);
            }
            Op::Emulf => {
                pair(instr.rd, "rd", pc)?;
                pair(instr.ra, "ra", pc)?;
                let rb = reg_b(&instr, pc)? as usize;
                a = [regs[ra], regs[ra + 1]];
                b_val[0] = regs[rb];
                d = parts(ext(a) * b_val[0]);
                set_pair(&mut regs, rd, d);
            }
            Op::Inv => {
                a[0] = regs[ra];
                d[0] = a[0].try_inverse().ok_or(ExecError::InverseOfZero { pc })?;
                set(&mut regs, rd, d[0]);
            }
            Op::Einv => {
                pair(instr.rd, "rd", pc)?;
                pair(instr.ra, "ra", pc)?;
                a = [regs[ra], regs[ra + 1]];
                d = parts(ext(a).try_inverse().ok_or(ExecError::InverseOfZero { pc })?);
                set_pair(&mut regs, rd, d);
            }
            Op::Mov => {
                a[0] = regs[ra];
                d[0] = a[0];
                set(&mut regs, rd, d[0]);
            }
            Op::Load | Op::Store | Op::Loade | Op::Storee => {
                let cells = if matches!(op, Op::Load | Op::Store) { 1 } else { 2 };
                if cells == 2 {
                    pair(instr.rd, "rd", pc)?;
                }
                a[0] = regs[ra];
                let addr = (a[0] + instr.b).as_canonical_u64();
                for k in 0..cells {
                    bounded(pc, addr + k)?;
                }
                match op {
                    Op::Load | Op::Loade => {
                        for k in 0..cells {
                            d[k as usize] = read(&mem, &mut mems, clk, addr + k);
                        }
                        set(&mut regs, rd, d[0]);
                        if cells == 2 {
                            set(&mut regs, rd + 1, d[1]);
                        }
                    }
                    _ => {
                        d[0] = regs[rd];
                        if cells == 2 {
                            d[1] = regs[rd + 1];
                        }
                        for k in 0..cells {
                            write(&mut mem, &mut mems, clk, addr + k, d[k as usize]);
                        }
                    }
                }
            }
            Op::Jmp | Op::Jeq | Op::Jne => {
                // The branch forms compare the two register slots; `JMP` uses neither.
                let taken = match op {
                    Op::Jmp => true,
                    _ => {
                        d[0] = regs[rd];
                        a[0] = regs[ra];
                        (d[0] == a[0]) == (op == Op::Jeq)
                    }
                };
                if taken {
                    let target = instr.b.as_canonical_u64();
                    if target >= MEM_LIMIT {
                        return Err(ExecError::PcOutOfRange(target));
                    }
                    next_pc = target as u32;
                }
            }
            Op::Hint | Op::Hinte => {
                let cells = if op == Op::Hint { 1 } else { 2 };
                if cells == 2 {
                    pair(instr.rd, "rd", pc)?;
                }
                if run.hints_read + cells > witness.len() {
                    return Err(ExecError::HintExhausted { pc });
                }
                for k in 0..cells {
                    d[k] = witness[run.hints_read + k];
                }
                run.hints_read += cells;
                set(&mut regs, rd, d[0]);
                if cells == 2 {
                    set(&mut regs, rd + 1, d[1]);
                }
            }
            Op::Public => {
                a[0] = regs[ra];
                run.public.push(a[0]);
            }
            Op::Poseidon2 => {
                a[0] = regs[ra];
                let ptr = a[0].as_canonical_u64();
                for k in 0..8 {
                    bounded(pc, ptr + k)?;
                }
                let input: [F; 8] =
                    core::array::from_fn(|k| read(&mem, &mut mems, clk, ptr + k as u64));
                let output = shrugg_zkvm::hash::permute_state(input);
                for (k, value) in output.iter().enumerate() {
                    write(&mut mem, &mut mems, clk, ptr + k as u64, *value);
                }
                perm = Some(PermEvent { ptr, input, output, src: None });
            }
            Op::Reduce => {
                a[0] = regs[ra];
                let descr = a[0].as_canonical_u64();
                for k in 0..11u64 {
                    bounded(pc, descr + k)?;
                }
                let mut d = [F::ZERO; 11];
                for (k, c) in d.iter_mut().enumerate() {
                    *c = read_at(&mem, &mut mems, clk, k as u32, descr + k as u64);
                }
                let vals_base = d[0].as_canonical_u64();
                let row_base = d[1].as_canonical_u64();
                let len = d[2].as_canonical_u64() as usize;
                if len == 0 {
                    return Err(ExecError::ReduceZeroLength { pc });
                }
                bounded(pc, vals_base + 2 * len as u64 - 1)?;
                bounded(pc, row_base + len as u64 - 1)?;
                let (inv, mut acc, mut apow, alpha) = ([d[3], d[4]], [d[5], d[6]], [d[7], d[8]], [d[9], d[10]]);
                for k in 0..len as u64 {
                    let pz = [
                        read_at(&mem, &mut mems, clk, TS_RUN_PZ0, vals_base + 2 * k),
                        read_at(&mem, &mut mems, clk, TS_RUN_PZ1, vals_base + 2 * k + 1),
                    ];
                    let px = read_at(&mem, &mut mems, clk, TS_RUN_PX, row_base + k);
                    let diff = ext([pz[0], pz[1]]) - px;
                    let t = ext(apow) * diff;
                    let t = t * ext(inv);
                    acc = parts(ext(acc) + t);
                    apow = parts(ext(apow) * ext(alpha));
                }
                write_at(&mut mem, &mut mems, clk, TS_WB_ACC0, descr + 5, acc[0]);
                write_at(&mut mem, &mut mems, clk, TS_WB_ACC1, descr + 6, acc[1]);
                write_at(&mut mem, &mut mems, clk, TS_WB_APOW0, descr + 7, apow[0]);
                write_at(&mut mem, &mut mems, clk, TS_WB_APOW1, descr + 8, apow[1]);
                reduce = Some(ReduceEvent {
                    descr_ptr: descr,
                    vals_base,
                    row_base,
                    len: len as u32,
                    inv,
                    acc: [d[5], d[6]],
                    apow: [d[7], d[8]],
                    alpha,
                });
            }
            Op::Sponge => {
                a[0] = regs[ra];
                let rb = reg_b(&instr, pc)? as usize;
                b_val[0] = regs[rb];
                let ptr = a[0].as_canonical_u64();
                let src = b_val[0].as_canonical_u64();
                bounded(pc, ptr + 7)?;
                bounded(pc, src + 3)?;
                let mut input = [F::ZERO; 8];
                for k in 0..4u64 {
                    input[k as usize] = read(&mem, &mut mems, clk, src + k);
                }
                for k in 0..4u64 {
                    input[4 + k as usize] = read(&mem, &mut mems, clk, ptr + 4 + k);
                }
                let output = shrugg_zkvm::hash::permute_state(input);
                for (k, value) in output.iter().enumerate() {
                    write(&mut mem, &mut mems, clk, ptr + k as u64, *value);
                }
                perm = Some(PermEvent { ptr, input, output, src: Some(src) });
            }
            Op::Halt => next_pc = pc,
        }

        for access in &mems {
            run.max_addr = run.max_addr.max(access.addr);
        }
        run.events.push(Event { clk, pc, next_pc, instr, a, b_val, d, mem: mems, perm, reduce });
        if op == Op::Halt {
            return Ok(run);
        }
        pc = next_pc;
    }
}

/// `r0` reads as zero and ignores writes; that is what makes `FADDI rd, r0, imm` a load-immediate
/// and `JNE rd, r0, target` a "while non-zero".
fn set(regs: &mut [F; NUM_REGS], idx: usize, value: F) {
    if idx != 0 {
        regs[idx] = value;
    }
}

fn set_pair(regs: &mut [F; NUM_REGS], idx: usize, value: [F; 2]) {
    set(regs, idx, value[0]);
    set(regs, idx + 1, value[1]);
}

/// The extension element a register (or cell) pair holds: `c0 + c1·X`.
fn ext(c: [F; 2]) -> EF {
    EF::from_basis_coefficients_fn(|k| c[k])
}

fn parts(x: EF) -> [F; 2] {
    let c = x.as_basis_coefficients_slice();
    [c[0], c[1]]
}

fn reg(idx: u8, slot: &'static str, pc: u32) -> Result<u8, ExecError> {
    if idx as usize >= NUM_REGS {
        return Err(ExecError::Decode {
            pc,
            err: DecodeError::Register { slot, value: idx as u64 },
        });
    }
    Ok(idx)
}

/// An extension slot names `(idx, idx + 1)`, so `idx + 1` must be a register too. The DSL never
/// allocates a pair at `r31`; a hand-written program that does is an error, not a panic.
fn pair(idx: u8, slot: &'static str, pc: u32) -> Result<u8, ExecError> {
    if idx as usize + 1 >= NUM_REGS {
        return Err(ExecError::Decode {
            pc,
            err: DecodeError::Register { slot, value: idx as u64 + 1 },
        });
    }
    Ok(idx)
}

/// The fourth word as a register index, rejecting a non-canonical or out-of-range one on the full
/// field element rather than on `Instr::rb`'s truncation.
fn reg_b(instr: &Instr, pc: u32) -> Result<u8, ExecError> {
    let value = instr.b.as_canonical_u64();
    if value >= NUM_REGS as u64 {
        return Err(ExecError::Decode {
            pc,
            err: DecodeError::Register { slot: "rb", value },
        });
    }
    Ok(value as u8)
}

fn bounded(pc: u32, addr: u64) -> Result<(), ExecError> {
    if addr >= MEM_LIMIT {
        return Err(ExecError::AddressOutOfRange { pc, addr });
    }
    Ok(())
}

fn read(mem: &HashMap<u64, F>, log: &mut Vec<MemAccess>, clk: u32, addr: u64) -> F {
    let value = mem.get(&addr).copied().unwrap_or(F::ZERO);
    log.push(MemAccess { addr, ts: ts(clk, log.len()), value, is_write: false });
    value
}

fn write(mem: &mut HashMap<u64, F>, log: &mut Vec<MemAccess>, clk: u32, addr: u64, value: F) {
    mem.insert(addr, value);
    log.push(MemAccess { addr, ts: ts(clk, log.len()), value, is_write: true });
}

fn ts(clk: u32, slot: usize) -> u32 {
    clk * TS_PER_ROW + slot as u32
}

/// `read` with an explicit slot: the `REDUCE` case reuses slots across its run's columns
/// (distinct addresses per column), which the position-based helpers cannot express.
fn read_at(mem: &HashMap<u64, F>, log: &mut Vec<MemAccess>, clk: u32, slot: u32, addr: u64) -> F {
    let value = mem.get(&addr).copied().unwrap_or(F::ZERO);
    log.push(MemAccess { addr, ts: clk * TS_PER_ROW + slot, value, is_write: false });
    value
}

/// `write` with an explicit slot (see [`read_at`]).
fn write_at(mem: &mut HashMap<u64, F>, log: &mut Vec<MemAccess>, clk: u32, slot: u32, addr: u64, value: F) {
    mem.insert(addr, value);
    log.push(MemAccess { addr, ts: clk * TS_PER_ROW + slot, value, is_write: true });
}
