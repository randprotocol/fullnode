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
pub type F = shrugg_zkvm::machine::Val;
/// The extension field every challenge and every FRI value lives in, stored as the pair
/// `(c0, c1)` in two consecutive registers or memory cells.
pub type EF = shrugg_zkvm::machine::Challenge;

/// An extension element is two base elements, which is what "the pair `(r, r+1)`" means; if the
/// machine's `Challenge` ever changed degree, every extension opcode below would be wrong.
const _: () = assert!(<EF as BasedVectorSpace<F>>::DIMENSION == 2);

/// `r0..r31`; `r0` reads as zero and ignores writes.
pub const NUM_REGS: usize = 32;
/// Memory is a flat array of cells addressed by a field element below `2^24`; `pc` likewise.
/// Violations are emulator errors here and range-check failures in M5.2.
pub const MEM_LIMIT: u64 = 1 << 24;
/// The hash domain of the rVM program digest. `shrugg_zkvm::notes::domain` is occupied through 14
/// (`SBPF_OUT`) and both digests share one permutation, so this must not collide with it.
pub const RVM_PROGRAM_DOMAIN: u64 = 15;

/// The twenty-four opcodes, in the spec table's reading order.
///
/// Deliberately absent: `FRIFOLD`, `EXPBITS`, `MERKLE` precompiles — the verifier's fold and
/// Merkle-path steps are compiled sequences of these, and a precompile is added only if the
/// measurement in M5.1 Task 6 asks for one.
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
    /// one run of the batch-opening reduction over the 11-cell descriptor at `ra`
    /// (`[vals_base, row_base, len, inv(2), acc(2), apow(2), alpha(2)]`): `acc += Σ_k
    /// apow·(vals_k − row_k)·inv` and `apow ·= alpha`, chained in and out through the
    /// descriptor. The work is the `reduce` chip's; one cpu row per run. M5.2 Task 8, appended —
    /// opcode 24; opcodes 0–23 never move.
    Reduce,
    /// absorb the four cells at `rb..rb+4` into rate lanes 0..3 of the state at `ra..ra+8` and
    /// permute the state in place — one `PaddingFreeSponge` absorb block. The work is the
    /// poseidon2 chip's second row kind; one cpu row per block. M5.2 Task 9, appended —
    /// opcode 25.
    Sponge,
}

impl Op {
    pub const COUNT: usize = 26;

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
            Op::Fadd | Op::Fsub | Op::Fmul | Op::Eadd | Op::Esub | Op::Emul | Op::Emulf | Op::Sponge
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

/// A program: the instruction list, plus the builder's `pc -> name` table for the assertion
/// traps, which is what makes "the program refused at *this* step" a checked claim.
/// `checkpoints` is sorted by `pc` and carries no weight in the digest.
#[derive(Clone, Debug, Default)]
pub struct Program {
    pub instrs: Vec<Instr>,
    pub checkpoints: Vec<(u32, String)>,
}

impl Program {
    pub fn encode(&self) -> Vec<[F; 4]> {
        self.instrs.iter().map(Instr::encode).collect()
    }

    /// The digest that binds this program, mirroring `shrugg_zkvm::hash::program_digest`'s
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
        for instr in &self.instrs {
            state[..4].copy_from_slice(&instr.encode());
            state = shrugg_zkvm::hash::permute_state(state);
        }
        [state[0], state[1], state[2], state[3]]
    }

    /// The number of permutations [`Program::digest`] costs: one per instruction.
    pub fn digest_rows(&self) -> usize {
        self.instrs.len()
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
