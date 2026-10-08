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

/// The `REDUCE` run's timestamp slots, shared with the reduce chip's memory messages (Cut D): the
/// entry's inverse key at slots 0–1, the chain's alpha at 2–3 (chain starts only), each column's
/// three reads reusing slots 11–13 (distinct addresses per column, which is all the memory table's
/// monotonicity asks), and the chain's result at 14–15.
pub const TS_KEY0: u32 = 0;
pub const TS_KEY1: u32 = 1;
pub const TS_ALPHA0: u32 = 2;
pub const TS_ALPHA1: u32 = 3;
pub const TS_RUN_PZ0: u32 = 11;
pub const TS_RUN_PZ1: u32 = 12;
pub const TS_RUN_PX: u32 = 13;
pub const TS_RES0: u32 = 14;
pub const TS_RES1: u32 = 15;

/// A `FOLD` run's slots (Cut E2): every phase-1 row reads its value at slots 0–1 (distinct
/// addresses per row), the last row writes the result at 14–15.
pub const TS_FOLD_Y0: u32 = 0;
pub const TS_FOLD_Y1: u32 = 1;
pub const TS_FOLD_RES0: u32 = 14;
pub const TS_FOLD_RES1: u32 = 15;

/// A `POW` run's slots (Cut F): every row reads its bit at slot 0 (distinct addresses per row),
/// the last row writes the output at 15.
pub const TS_POW_BIT: u32 = 0;
pub const TS_POW_OUT: u32 = 15;

/// One cell read or written, at the timestamp `16·clk + k` of its slot in the row.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct MemAccess {
    pub addr: u64,
    pub ts: u32,
    pub value: F,
    pub is_write: bool,
}

/// The width-8 permutation a `POSEIDON2`, `SPONGE` or `COMPRESS` row dispatches. `ptr` is the
/// state the output is written back to; `input` is the permutation's input as the chip sees it
/// (for `COMPRESS`, already ordered by the bit).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PermEvent {
    pub ptr: u64,
    pub input: [F; 8],
    pub output: [F; 8],
    pub kind: PermKind,
}

/// Which row kind of the Poseidon2 chip a permutation event is.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PermKind {
    /// `POSEIDON2`: the eight cells at `ptr`, in place.
    Perm,
    /// `SPONGE`: four cells at `src` into lanes 0–3, the state's lanes 4–7 kept, eight written.
    Sponge { src: u64 },
    /// `COMPRESS` (Cut C): `[state(4) ‖ sib(4)]` when `bit` is clear, `[sib ‖ state]` when set;
    /// lanes 0–3 of the output written back to `ptr`.
    Compress { sib: u64, bit: bool },
}

/// One `REDUCE` dispatch (Cut D): the layout entry, its column count, the key and alpha it ran
/// with, and the accumulator/running power on entry and on exit (equal at a chain's seam).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ReduceEvent {
    pub entry: u32,
    pub len: u32,
    pub inv: [F; 2],
    pub alpha: [F; 2],
    pub acc_in: [F; 2],
    pub apow_in: [F; 2],
    pub acc_out: [F; 2],
    pub apow_out: [F; 2],
}

/// One `FOLD` dispatch (Cut E2): the row it read, the point, the result.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct FoldEvent {
    pub msg: u64,
    pub arity: u32,
    pub u: [F; 2],
    pub ys: [[F; 2]; 8],
    pub out: [F; 2],
}

/// One `POW` dispatch (Cut F).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PowEvent {
    pub base: u64,
    pub off: u32,
    pub len: u32,
    pub g: F,
    pub s0: F,
    pub out: F,
}

/// The state a carrying entry hands to the next row's `REDUCE`.
#[derive(Clone, Copy)]
struct ReduceCarry {
    entry: u32,
    clk: u32,
    acc: [F; 2],
    apow: [F; 2],
    alpha: [F; 2],
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
    pub fold: Option<FoldEvent>,
    pub pow: Option<PowEvent>,
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

    /// The `poseidon2` chip's height: one permutation per `POSEIDON2`, `SPONGE` or `COMPRESS`
    /// row — every row whose event carries a permutation — and nothing else.
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
    /// A `REDUCE` layout entry declared a zero-length run: there is nothing to reduce, and a
    /// `REDUCE` of zero columns is a build-time mistake (the program must not register it;
    /// `machine::check_layout` refuses it at registration too).
    ReduceZeroLength { pc: u32 },
    /// A `REDUCE` naming no entry of the program's layout, or an entry naming a cell outside the
    /// `2^24`-cell address space (`isa::layout_entry_in_bounds`, the registration check's bound).
    ReduceLayout { pc: u32, entry: u64 },
    /// A chain's hand-over broken: a carrying entry not followed, on the very next row, by a
    /// `REDUCE` of the next entry; or a continuation entry dispatched without that carry.
    ReduceChain { pc: u32, entry: u64 },
    /// A `COMPRESS` whose `rd` is neither 0 nor 1: the index bit of a Merkle level is a bit, and
    /// a program that hands it anything else is a build-time mistake (the chip's `BIT` is
    /// boolean, so the row would be unprovable anyway).
    NonBooleanBit { pc: u32 },
    /// A FOLD whose immediate is not 2, 4 or 8.
    FoldArity { pc: u32, arity: u64 },
    /// A POW immediate whose run is empty or leaves the 64 bits.
    PowShape { pc: u32, imm: u64 },
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
    let mut chain: Option<ReduceCarry> = None;

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
        if let Some(c) = &chain {
            if op != Op::Reduce {
                return Err(ExecError::ReduceChain { pc, entry: c.entry as u64 });
            }
        }

        let mut mems: Vec<MemAccess> = Vec::new();
        let mut perm = None;
        let mut reduce = None;
        let mut fold = None;
        let mut pow = None;
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
                let output = randprotocol_zkvm::hash::permute_state(input);
                for (k, value) in output.iter().enumerate() {
                    write(&mut mem, &mut mems, clk, ptr + k as u64, *value);
                }
                perm = Some(PermEvent { ptr, input, output, kind: PermKind::Perm });
            }
            Op::Reduce => {
                a[0] = regs[ra];
                let id = instr.b.as_canonical_u64();
                let le = *p.reduce_layout.get(id as usize).ok_or(ExecError::ReduceLayout { pc, entry: id })?;
                if le.len == 0 {
                    return Err(ExecError::ReduceZeroLength { pc });
                }
                // The layout's own legality, exactly `machine::check_layout`'s: every base and the
                // length inside the 2^24-cell space before any sum (so no top can wrap), then every
                // top. An illegal entry is the layout's fault, not a run's: `ReduceLayout`.
                if !crate::isa::layout_entry_in_bounds(&le) {
                    return Err(ExecError::ReduceLayout { pc, entry: id });
                }
                let len = le.len as u64;
                let inv = [read_at(&mem, &mut mems, clk, TS_KEY0, le.key), read_at(&mem, &mut mems, clk, TS_KEY1, le.key + 1)];
                let (mut acc, mut apow, alpha) = if le.chain_start {
                    if chain.is_some() {
                        return Err(ExecError::ReduceChain { pc, entry: id });
                    }
                    let alpha = [read_at(&mem, &mut mems, clk, TS_ALPHA0, le.alpha), read_at(&mem, &mut mems, clk, TS_ALPHA1, le.alpha + 1)];
                    ([F::ZERO; 2], [F::ONE, F::ZERO], alpha)
                } else {
                    match chain.take() {
                        Some(c) if c.entry as u64 == id && c.clk + 1 == clk => (c.acc, c.apow, c.alpha),
                        _ => return Err(ExecError::ReduceChain { pc, entry: id }),
                    }
                };
                let (acc_in, apow_in) = (acc, apow);
                for k in 0..len {
                    let pz = [
                        read_at(&mem, &mut mems, clk, TS_RUN_PZ0, le.vals + 2 * k),
                        read_at(&mem, &mut mems, clk, TS_RUN_PZ1, le.vals + 2 * k + 1),
                    ];
                    let px = read_at(&mem, &mut mems, clk, TS_RUN_PX, le.row + k);
                    let diff = ext(pz) - px;
                    let t = ext(apow) * diff * ext(inv);
                    acc = parts(ext(acc) + t);
                    apow = parts(ext(apow) * ext(alpha));
                }
                if le.carry {
                    chain = Some(ReduceCarry { entry: id as u32 + 1, clk, acc, apow, alpha });
                } else {
                    write_at(&mut mem, &mut mems, clk, TS_RES0, le.res, acc[0]);
                    write_at(&mut mem, &mut mems, clk, TS_RES1, le.res + 1, acc[1]);
                }
                reduce = Some(ReduceEvent { entry: id as u32, len: le.len, inv, alpha, acc_in, apow_in, acc_out: acc, apow_out: apow });
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
                let output = randprotocol_zkvm::hash::permute_state(input);
                for (k, value) in output.iter().enumerate() {
                    write(&mut mem, &mut mems, clk, ptr + k as u64, *value);
                }
                perm = Some(PermEvent { ptr, input, output, kind: PermKind::Sponge { src } });
            }
            Op::Hintn => {
                a[0] = regs[ra];
                let base = (a[0] + instr.b).as_canonical_u64();
                // The top cell bounds the whole run: `base` is canonical (below `p < 2^64 − 7`),
                // so `base + 7` cannot wrap, and `base + 7 < 2^24` puts every cell below it too.
                bounded(pc, base + 7)?;
                if run.hints_read + 8 > witness.len() {
                    return Err(ExecError::HintExhausted { pc });
                }
                // `write` takes its slot from the position in `mems`, empty until now: the eight
                // writes land at slots 0..7, which is what the cpu AIR's `ts(k)` sends.
                for k in 0..8u64 {
                    let w = witness[run.hints_read + k as usize];
                    write(&mut mem, &mut mems, clk, base + k, w);
                }
                run.hints_read += 8;
            }
            Op::Compress => {
                let rb = reg_b(&instr, pc)? as usize;
                a[0] = regs[ra];
                b_val[0] = regs[rb];
                d[0] = regs[rd];
                let bit = if d[0] == F::ZERO {
                    false
                } else if d[0] == F::ONE {
                    true
                } else {
                    return Err(ExecError::NonBooleanBit { pc });
                };
                let (ptr, sib) = (a[0].as_canonical_u64(), b_val[0].as_canonical_u64());
                bounded(pc, ptr + 3)?;
                bounded(pc, sib + 3)?;
                // `read`/`write` take their slot from the position in `mems`, empty until now: the
                // state reads land at slots 0..3, the sibling reads at 4..7, the write-backs at
                // 8..11 — the chip's `IS_COMPRESS` timestamps exactly.
                let dg: [F; 4] = core::array::from_fn(|k| read(&mem, &mut mems, clk, ptr + k as u64));
                let sb: [F; 4] = core::array::from_fn(|k| read(&mem, &mut mems, clk, sib + k as u64));
                let input: [F; 8] = core::array::from_fn(|k| match (bit, k < 4) {
                    (false, true) => dg[k],
                    (false, false) => sb[k - 4],
                    (true, true) => sb[k],
                    (true, false) => dg[k - 4],
                });
                let output = randprotocol_zkvm::hash::permute_state(input);
                for k in 0..4 {
                    write(&mut mem, &mut mems, clk, ptr + k as u64, output[k]);
                }
                perm = Some(PermEvent { ptr, input, output, kind: PermKind::Compress { sib, bit } });
            }
            Op::Fold => {
                pair(instr.rd, "rd", pc)?;
                a[0] = regs[ra];
                d = [regs[rd], regs[rd + 1]];
                let arity = instr.b.as_canonical_u64();
                if !matches!(arity, 2 | 4 | 8) {
                    return Err(ExecError::FoldArity { pc, arity });
                }
                let msg = a[0].as_canonical_u64();
                let res = msg + 2 * arity + crate::isa::FOLD_SALT_CELLS;
                bounded(pc, res + 1)?;
                let mut ys = [[F::ZERO; 2]; 8];
                for (k, y) in ys.iter_mut().enumerate().take(arity as usize) {
                    *y = [
                        read_at(&mem, &mut mems, clk, TS_FOLD_Y0, msg + 2 * k as u64),
                        read_at(&mem, &mut mems, clk, TS_FOLD_Y1, msg + 2 * k as u64 + 1),
                    ];
                }
                let yse: Vec<EF> = ys[..arity as usize].iter().map(|y| ext(*y)).collect();
                let out = parts(fold_dft_horner(&yse, ext(d)));
                write_at(&mut mem, &mut mems, clk, TS_FOLD_RES0, res, out[0]);
                write_at(&mut mem, &mut mems, clk, TS_FOLD_RES1, res + 1, out[1]);
                fold = Some(FoldEvent { msg, arity: arity as u32, u: d, ys, out });
            }
            Op::Pow => {
                pair(instr.rd, "rd", pc)?;
                a[0] = regs[ra];
                d = [regs[rd], regs[rd + 1]];
                let imm = instr.b.as_canonical_u64();
                let (off, len) = (imm % 256, imm / 256);
                if len == 0 || len >= 256 || off + len > 64 {
                    return Err(ExecError::PowShape { pc, imm });
                }
                let base = a[0].as_canonical_u64();
                bounded(pc, base + 64)?;
                let (mut g, mut s) = (d[0], d[1]);
                for t in 0..len {
                    let bit = read_at(&mem, &mut mems, clk, TS_POW_BIT, base + off + len - 1 - t);
                    if bit != F::ZERO && bit != F::ONE {
                        return Err(ExecError::NonBooleanBit { pc });
                    }
                    s *= F::ONE + bit * (g - F::ONE);
                    g = g.square();
                }
                write_at(&mut mem, &mut mems, clk, TS_POW_OUT, base + 64, s);
                pow = Some(PowEvent { base, off: off as u32, len: len as u32, g: d[0], s0: d[1], out: s });
            }
            Op::Halt => next_pc = pc,
        }

        for access in &mems {
            run.max_addr = run.max_addr.max(access.addr);
        }
        run.events.push(Event { clk, pc, next_pc, instr, a, b_val, d, mem: mems, perm, reduce, fold, pow });
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

/// The fold run's coefficient table for one arity (Cut E2): row `k` (the row reading `y_k`),
/// column `j` = `(1/a)·c_k^{−(a−1−j)}`, `c_k = g_a^{rev(k)}`, zero for `j ≥ a` — so after the
/// phase-1 rows, accumulator `j` holds `B_{a−1−j}` (the inverse DFT, spec §2.3) and phase 2's
/// Horner reads them top coefficient first.
pub fn fold_coefficients(log_arity: usize) -> Vec<[F; 8]> {
    use p3_field::TwoAdicField;
    let a = 1usize << log_arity;
    let g = F::two_adic_generator(log_arity);
    let inv_a = F::from_usize(a).inverse();
    (0..a)
        .map(|k| {
            let w = g.exp_u64(p3_util::reverse_bits_len(k, log_arity) as u64).inverse();
            core::array::from_fn(|j| if j < a { inv_a * w.exp_u64((a - 1 - j) as u64) } else { F::ZERO })
        })
        .collect()
}

/// `Σ_m B_m·u^m` through [`fold_coefficients`] — the emulator's fold, and so the chip's
/// reference. `tests/fold_identity.rs` pins it to `TwoAdicFriFolding::fold_row`.
pub fn fold_dft_horner(ys: &[EF], u: EF) -> EF {
    let c = fold_coefficients(ys.len().trailing_zeros() as usize);
    let d: Vec<EF> = (0..ys.len()).map(|j| ys.iter().zip(&c).fold(EF::ZERO, |acc, (y, row)| acc + *y * row[j])).collect();
    d.iter().fold(EF::ZERO, |acc, &dj| acc * u + dj)
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
