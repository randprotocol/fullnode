//! The rVM instruction set, its encoding and the program digest (spec §3).
//!
//! Every instruction is one cpu row and one four-element word group `[opcode | rd | ra |
//! rb-or-imm]`. Operands are register indices (`r0..r31`, `r0` pinned to zero) or an immediate
//! field element; an extension operand `E` is the pair `(r, r+1)` — value `c0 + c1·X`.
//!
//! Opcode numbering is the spec table's reading order, fixed by `Op as u8` and pinned by
//! `tests/isa.rs`: **changing it changes every program digest**, hence every verifier key the
//! fullnode has registered.

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};

/// The rVM's word: one Goldilocks element, the same field the RV32 machine is proved over.
pub type F = randprotocol_zkvm::machine::Val;
/// The extension field every challenge and every FRI value lives in, stored as the pair
/// `(c0, c1)` in two consecutive registers or memory cells.
pub type EF = randprotocol_zkvm::machine::Challenge;

/// An extension element is two base elements, which is what "the pair `(r, r+1)`" means; if the
/// machine's `Challenge` ever changed degree, every extension opcode below would be wrong.
const _: () = assert!(<EF as BasedVectorSpace<F>>::DIMENSION == 2);

/// `r0..r31`; `r0` reads as zero and ignores writes.
pub const NUM_REGS: usize = 32;
/// Memory is a flat array of cells addressed by a field element below `2^24`; `pc` likewise.
/// Violations are emulator errors here and range-check failures in M5.2.
pub const MEM_LIMIT: u64 = 1 << 24;
/// The hash domain of the rVM program digest. `randprotocol_zkvm::notes::domain` is occupied through 14
/// (`SBPF_OUT`) and both digests share one permutation, so this must not collide with it.
pub const RVM_PROGRAM_DOMAIN: u64 = 15;
/// Cut E2: the cells between a committed row and its fold result (the row's salts).
pub const FOLD_SALT_CELLS: u64 = 4;

/// The thirty opcodes: the spec table's twenty-four in its reading order, then the
/// appended ones (`REDUCE`, `SPONGE`, `HINTN`, `COMPRESS`, `FOLD`, `POW`), each at the next free number so no earlier
/// opcode — and so no earlier program's digest — ever moves.
///
/// Precompiles are added when the measurement asks for one (`docs/00`'s decision, re-taken in
/// `docs/06`): `COMPRESS` for one Merkle level (Cut C, measured at 33 rows a level; the walk stays
/// a compiled loop of them, and there is no `MERKLE`), and in phase 3 `FOLD` for one FRI fold
/// round (the reduce chip's fold run) and `POW` for the index powers (its pow run) — declined at
/// 5.68 M rows, where the fold rounds and the bit-selected powers were ≈ 164 k rows (≈ 3 %) of the
/// program, and taken at 893 606, where they were 124 560 rows (13.9 %; `fold_round` 36 640 and
/// `bit_selected_power` 87 920, docs/06 §1). Phase 3 landed at 585 686 rows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Op {
    /// `rd = ra + rb`
    Fadd = 0,
    /// `rd = ra - rb`
    Fsub,
    /// `rd = ra * rb`
    Fmul,
    /// `rd = ra + imm`
    Faddi,
    /// `rd = ra * imm`
    Fmuli,
    /// `Ed = Ea + Eb`
    Eadd,
    /// `Ed = Ea - Eb`
    Esub,
    /// `Ed = Ea * Eb`
    Emul,
    /// `Ed = Ea * rb` (extension × base)
    Emulf,
    /// `rd = ra⁻¹`, the inverse supplied as a hint by the emulator; the row constrains
    /// `ra·rd = 1`, which is unsatisfiable when `ra = 0`.
    Inv,
    /// `Ed = Ea⁻¹`, the same hint-and-check shape over the extension.
    Einv,
    /// `rd = ra`
    Mov,
    /// `rd = mem[ra + imm]`
    Load,
    /// `mem[ra + imm] = rd`
    Store,
    /// `Ed = mem[ra + imm .. ra + imm + 2]`
    Loade,
    /// `mem[ra + imm .. ra + imm + 2] = Ed`
    Storee,
    /// `pc = imm`
    Jmp,
    /// `pc = imm` if `rd == ra`
    Jeq,
    /// `pc = imm` if `rd != ra`
    Jne,
    /// `rd = the next witness word`
    Hint,
    /// `Ed = the next two witness words`
    Hinte,
    /// append `ra` to the public values
    Public,
    /// permute the eight cells at `ra..ra+8` in place
    Poseidon2,
    /// end the program
    Halt,
    /// one run of the batch-opening reduction: layout entry `imm` (Cut D, phase 3) — the chip
    /// reads the run's columns, its inverse key, and at a chain start the batching challenge, all
    /// at addresses the verifier key commits; a carrying entry hands its accumulator to entry
    /// `imm + 1` on the next row, a closing one writes it to the entry's `res`. Opcode 24.
    Reduce,
    /// absorb the four cells at `rb..rb+4` into rate lanes 0..3 of the state at `ra..ra+8` and
    /// permute the state in place — one `PaddingFreeSponge` absorb block. The work is the
    /// poseidon2 chip's second row kind; one cpu row per block. M5.2 Task 9, appended —
    /// opcode 25.
    Sponge,
    /// `mem[ra + imm .. ra + imm + 8] = the next eight witness words` — eight `HINT; STORE` pairs
    /// in one row (Cut B, 2026-10-03). The words ride on the cpu row's `W0..W7`, free witness
    /// exactly as `HINT`'s `D0` is; `rd` is unused. Opcode 26, appended; 0–25 never move.
    Hintn,
    /// one Merkle level: `bit = rd`, the running digest at `ra` (4 cells), the sibling at `rb`
    /// (4 cells); `mem[ra..ra+4] = permute(bit == 0 ? [digest ‖ sib] : [sib ‖ digest])[0..4]`.
    /// The work is the poseidon2 chip's third row kind; a non-boolean bit is an emulator error.
    /// Cut C, opcode 27, appended; 0–26 never move.
    Compress,
    /// one FRI fold round (phase 3, Cut E2): `rd` is the pair holding `u = β·s⁻¹`, `ra` the
    /// committed row's base (`2a` cells), `imm` the arity `a ∈ {2, 4, 8}`; the reduce chip's fold
    /// run (an inverse DFT then Horner, 2a rows) writes `Σ_m B_m·u^m` to the two cells after the
    /// row's four salts. Opcode 28, appended; 0–27 never move.
    Fold,
    /// the index power (phase 3, Cut F): `rd` the pair (G, base), `ra` a 65-cell bits buffer,
    /// `imm = off + 256·L`; the reduce chip's pow run (one row per bit) writes
    /// `base·Π_t (1 + bit_{off+L−1−t}·(G^{2^t} − 1))` to cell 64. Opcode 29.
    Pow,
}

impl Op {
    pub const COUNT: usize = 30;

    /// Every opcode, at the index of its own discriminant (pinned by `tests/isa.rs`).
    pub const ALL: [Op; Self::COUNT] = [
        Op::Fadd,
        Op::Fsub,
        Op::Fmul,
        Op::Faddi,
        Op::Fmuli,
        Op::Eadd,
        Op::Esub,
        Op::Emul,
        Op::Emulf,
        Op::Inv,
        Op::Einv,
        Op::Mov,
        Op::Load,
        Op::Store,
        Op::Loade,
        Op::Storee,
        Op::Jmp,
        Op::Jeq,
        Op::Jne,
        Op::Hint,
        Op::Hinte,
        Op::Public,
        Op::Poseidon2,
        Op::Halt,
        Op::Reduce,
        Op::Sponge,
        Op::Hintn,
        Op::Compress,
        Op::Fold,
        Op::Pow,
    ];

    pub fn from_u8(x: u8) -> Option<Self> {
        Self::ALL.get(x as usize).copied()
    }

    pub fn mnemonic(self) -> &'static str {
        match self {
            Op::Fadd => "FADD",
            Op::Fsub => "FSUB",
            Op::Fmul => "FMUL",
            Op::Faddi => "FADDI",
            Op::Fmuli => "FMULI",
            Op::Eadd => "EADD",
            Op::Esub => "ESUB",
            Op::Emul => "EMUL",
            Op::Emulf => "EMULF",
            Op::Inv => "INV",
            Op::Einv => "EINV",
            Op::Mov => "MOV",
            Op::Load => "LOAD",
            Op::Store => "STORE",
            Op::Loade => "LOADE",
            Op::Storee => "STOREE",
            Op::Jmp => "JMP",
            Op::Jeq => "JEQ",
            Op::Jne => "JNE",
            Op::Hint => "HINT",
            Op::Hinte => "HINTE",
            Op::Public => "PUBLIC",
            Op::Poseidon2 => "POSEIDON2",
            Op::Halt => "HALT",
            Op::Reduce => "REDUCE",
            Op::Sponge => "SPONGE",
            Op::Hintn => "HINTN",
            Op::Compress => "COMPRESS",
            Op::Fold => "FOLD",
            Op::Pow => "POW",
        }
    }

    /// Does the fourth encoded word name a register (rather than an immediate)?
    ///
    /// `JEQ`/`JNE` are *not* in this set: their operands are `ra, rb, imm` (spec §3), and with
    /// only four words the two compared registers occupy the `rd` and `ra` slots, leaving the
    /// fourth word for the branch target — which is a `pc` below `2^24`, not a register index.
    pub fn b_is_register(self) -> bool {
        matches!(
            self,
            Op::Fadd | Op::Fsub | Op::Fmul | Op::Eadd | Op::Esub | Op::Emul | Op::Emulf | Op::Sponge | Op::Compress
        )
    }
}

/// One decoded instruction: the opcode, the two register slots, and the fourth word — a register
/// index (when [`Op::b_is_register`]) or an immediate field element.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Instr {
    pub op: Op,
    pub rd: u8,
    pub ra: u8,
    pub b: F,
}

/// Why four words are not an instruction. Both variants carry the offending canonical value, so
/// a bad program word can be reported without a second look at the encoding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError {
    Opcode(u64),
    Register { slot: &'static str, value: u64 },
    /// Cut D: a reduce-layout entry no run could have (zero length, a cell at or above 2^24, or a chain that does not hand over).
    Layout { entry: u32 },
    /// Cut F: a `POW` immediate whose run is empty or leaves the 64 bits (`off + L > 64`). The
    /// chip range-checks the two bytes but not their sum — the key commits the immediate, so it
    /// is checked once, here, as the layout is.
    PowShape { imm: u64 },
}

impl Instr {
    pub fn encode(&self) -> [F; 4] {
        [F::from_u8(self.op as u8), F::from_u8(self.rd), F::from_u8(self.ra), self.b]
    }

    pub fn decode(words: [F; 4]) -> Result<Self, DecodeError> {
        let raw = words[0].as_canonical_u64();
        let op = u8::try_from(raw)
            .ok()
            .and_then(Op::from_u8)
            .ok_or(DecodeError::Opcode(raw))?;
        let rd = reg(words[1], "rd")?;
        let ra = reg(words[2], "ra")?;
        if op.b_is_register() {
            reg(words[3], "rb")?;
        }
        Ok(Instr { op, rd, ra, b: words[3] })
    }

    /// The register index in the fourth word, for the opcodes that have one.
    pub fn rb(&self) -> u8 {
        self.b.as_canonical_u64() as u8
    }
}

/// A register slot: canonical, and below [`NUM_REGS`].
fn reg(word: F, slot: &'static str) -> Result<u8, DecodeError> {
    let value = word.as_canonical_u64();
    if value >= NUM_REGS as u64 {
        return Err(DecodeError::Register { slot, value });
    }
    Ok(value as u8)
}

/// One entry of a program's reduce layout (phase 3, Cut D): one run of the batch-opening
/// reduction, every address a compile-time constant of the program. The reduce chip's
/// preprocessed region holds the layout, so the verifier key commits it, and a `REDUCE`
/// instruction names an entry by its index (the immediate) — a descriptor is never a witness
/// value (spec §6 ruling 3). `vals` holds `len` extension values (2·len cells), `row` the `len`
/// base cells, `key` the run's inverse key (2 cells), `alpha` the batching challenge (2 cells,
/// read when `chain_start`), `res` the chain's result (2 cells, written when `!carry`).
/// `carry` hands the accumulator and the running power to entry `id + 1`, dispatched on the very
/// next cpu row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReduceEntry {
    pub vals: u64,
    pub row: u64,
    pub len: u32,
    pub key: u64,
    pub alpha: u64,
    pub res: u64,
    pub chain_start: bool,
    pub carry: bool,
}

/// Whether every cell a layout entry names lies inside the `2^24`-cell address space (Cut D). The
/// bases and the length are bounded first, so the tops are computed without wrapping: a hostile
/// `u64::MAX` base must not wrap `base + 1` back into range. The one bound the registration check
/// (`machine::check_layout`) and the emulator both apply — the reduce chip range-checks nothing.
pub fn layout_entry_in_bounds(e: &ReduceEntry) -> bool {
    if [e.vals, e.row, e.key, e.alpha, e.res, e.len as u64].iter().any(|&x| x >= MEM_LIMIT) {
        return false;
    }
    let len = e.len as u64;
    len == 0 || [e.vals + 2 * len - 1, e.row + len - 1, e.key + 1, e.alpha + 1, e.res + 1].iter().all(|&top| top < MEM_LIMIT)
}

/// A program: the instruction list, plus the builder's `pc -> name` table for the assertion
/// traps, which is what makes "the program refused at *this* step" a checked claim.
/// `checkpoints` is sorted by `pc` and carries no weight in the digest.
#[derive(Clone, Debug, Default)]
pub struct Program {
    pub instrs: Vec<Instr>,
    pub checkpoints: Vec<(u32, String)>,
    /// Cut D: the reduce layout, committed by the verifier key and absorbed into [`Program::digest`].
    pub reduce_layout: Vec<ReduceEntry>,
}

impl Program {
    pub fn encode(&self) -> Vec<[F; 4]> {
        self.instrs.iter().map(Instr::encode).collect()
    }

    /// The digest that binds this program, mirroring `randprotocol_zkvm::hash::program_digest`'s
    /// construction (`research/src/hash.rs`): the header — the domain tag and the instruction
    /// count — is seeded into the *capacity* lanes of the first permutation's input, then each
    /// instruction's four encoded words overwrite rate lanes `0..4` and the state is permuted
    /// once. Exactly one permutation per instruction, which is the height M5.2's `program` table
    /// is sized against; and since the length is mixed in before any word content, a program is
    /// never a trailing-zero extension of another (the padding-free-sponge concern
    /// `research/AGENTS.md` records).
    pub fn digest(&self) -> [F; 4] {
        let mut state = [F::ZERO; 8];
        state[4] = F::from_u64(RVM_PROGRAM_DOMAIN);
        state[5] = F::from_u64(self.instrs.len() as u64);
        // Cut D: a program with a reduce layout absorbs its length into capacity lane 6 and then
        // two blocks per entry after the instructions. A program without one keeps its digest.
        if !self.reduce_layout.is_empty() {
            state[6] = F::from_u64(self.reduce_layout.len() as u64);
        }
        for instr in &self.instrs {
            state[..4].copy_from_slice(&instr.encode());
            state = randprotocol_zkvm::hash::permute_state(state);
        }
        for e in &self.reduce_layout {
            state[..4].copy_from_slice(&[F::from_u64(e.vals), F::from_u64(e.row), F::from_u32(e.len), F::from_u64(e.key)]);
            state = randprotocol_zkvm::hash::permute_state(state);
            let flags = e.chain_start as u64 + 2 * e.carry as u64;
            state[..4].copy_from_slice(&[F::from_u64(e.alpha), F::from_u64(e.res), F::from_u64(flags), F::ZERO]);
            state = randprotocol_zkvm::hash::permute_state(state);
        }
        [state[0], state[1], state[2], state[3]]
    }

    /// The number of permutations [`Program::digest`] costs: one per instruction, two per
    /// reduce-layout entry (Cut D).
    pub fn digest_rows(&self) -> usize {
        self.instrs.len() + 2 * self.reduce_layout.len()
    }

    /// The name of the checkpoint at `pc`, if any — how `ExecError::InverseOfZero { pc }` from a
    /// trap becomes the name of the assertion that failed.
    pub fn checkpoint_at(&self, pc: u32) -> Option<&str> {
        self.checkpoints
            .binary_search_by_key(&pc, |(at, _)| *at)
            .ok()
            .map(|i| self.checkpoints[i].1.as_str())
    }
}
