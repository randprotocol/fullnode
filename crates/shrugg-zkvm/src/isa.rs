//! The RV32I subset of milestone 1, its encoding, and the pre-decoded selector
//! set that the program table commits and the CPU table consumes.

pub const REG_ZERO: u32 = 0;
pub const REG_RA: u32 = 1;
pub const REG_SP: u32 = 2;
pub const REG_A0: u32 = 10;
pub const REG_A1: u32 = 11;
pub const REG_A2: u32 = 12;
pub const REG_A7: u32 = 17;

pub const SYS_HALT: u32 = 0;
pub const SYS_WRITE_OUTPUT: u32 = 1;
pub const SYS_READ_INPUT: u32 = 2;
/// M3.2: `a0 = ptr` (a WORD address, `MEM_ADDR`'s convention), `a1 = n` words (`0 <= n <=
/// 4096`). Hashes the `n` words at `ptr` with the Poseidon2 sponge (rate 4, overwrite mode, no
/// padding — see `hash::sponge_hash`) and overwrites `ptr..ptr+8` with the 8 lo/hi digest
/// words in place. `ptr` must be `< 2^30` — the same bound the cpu AIR puts on every word
/// address (`tables::cpu`'s `MA0..3`/`HP0..3` decompositions); the emulator rejects anything
/// larger with `ExecError::Poseidon2Ptr` (audit ZM4, 2026-09-12).
pub const SYS_POSEIDON2: u32 = 3;
/// Hard cap on `POSEIDON2`'s word count: 4096 words is 1024 absorbed blocks, comfortably
/// within a tier's cycle budget while still bounding the emulator's per-syscall work.
pub const POSEIDON2_MAX_WORDS: u32 = 4096;
/// M4.2: `a0 = ptr` (a WORD address, `MEM_ADDR`'s convention), pointing at the `KECCAK_WORDS`
/// words of a Keccak-f[1600] state in `keccak::state_to_words`' lo/hi-per-lane layout. Applies
/// one permutation in place and takes no other argument. Unlike `POSEIDON2` this is a single
/// cpu row: the keccak chip (`tables::keccak`) proves the 24 rounds off the cpu table, so the
/// cpu only witnesses the call, never the rounds.
pub const SYS_KECCAK: u32 = 4;
/// The permutation's state width in machine words: 25 lanes x 2 words (`keccak::WORDS`).
pub const KECCAK_WORDS: u32 = 50;
/// The ABI constant above and the host reference's own state width are the same number stated
/// twice (`isa` is the syscall contract, `keccak` is the layout); keep them from drifting.
const _: () = assert!(KECCAK_WORDS as usize == crate::keccak::WORDS);
/// M4.4: `a0 = ptr` (a WORD address, `MEM_ADDR`'s convention), pointing at the `SHA256_WORDS`
/// words of one SHA-256 compression's argument: words `0..16` are the 512-bit message block as
/// sixteen **big-endian-valued** 32-bit words (word `i` is `u32::from_be_bytes` of the block's
/// bytes `4i..4i+4`, i.e. `sha256::bytes_to_words`' layout), words `16..24` are the chaining
/// state `H`. Applies one compression, `H <- H + f(H, W)`, over words `16..24` in place and
/// leaves the message words untouched; it takes no other argument. Like `KECCAK` — and unlike
/// `POSEIDON2` — this is a single cpu row: the sha256 chip (`tables::sha256`) proves the 64
/// rounds off the cpu table, so the cpu only witnesses the call. `ptr` is bounded the same way
/// (`ExecError::Sha256PtrOutOfRange` / `emulator::SHA256_PTR_LIMIT`). Padding and the
/// Merkle-Damgard loop are the guest's, in `guest_sdk::sha256`.
pub const SYS_SHA256: u32 = 5;
/// One message block plus one chaining state in machine words: 16 + 8 (`sha256::WORDS`).
pub const SHA256_WORDS: u32 = 24;
/// The ABI constant above and the host reference's own buffer width are the same number stated
/// twice (`isa` is the syscall contract, `sha256` is the layout); keep them from drifting.
const _: () = assert!(SHA256_WORDS as usize == crate::sha256::WORDS);
/// M4.1's `READ_INPUT`, on the **public** segment: `a0 = idx` in, `a0 = word` out, no second
/// argument, one cpu row. The words it draws from are committed to the unsalted `H_PUB`
/// (`pv::PUB0..7`), which a verifier holding them recomputes — so a value read here is bound to
/// something the chain can check, unlike a private input under the hiding `H_IN`.
pub const SYS_READ_PUBLIC: u32 = 6;
pub const NUM_OUTPUTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum AluOp {
    Add = 0, Sub = 1, And = 2, Or = 3, Xor = 4, Sll = 5, Srl = 6, Sra = 7, Slt = 8, Sltu = 9, Eq = 10,
    // M2.6: the RV32M extension. Register-register only (`OP_ALU` with `funct7 = 1`) — RISC-V
    // has no immediate form of any of these.
    Mul = 11, Mulh = 12, Mulhu = 13, Mulhsu = 14, Div = 15, Divu = 16, Rem = 17, Remu = 18,
}

impl AluOp {
    pub const COUNT: usize = 19;
    pub const ALL: [AluOp; 19] = [
        AluOp::Add, AluOp::Sub, AluOp::And, AluOp::Or, AluOp::Xor, AluOp::Sll, AluOp::Srl, AluOp::Sra, AluOp::Slt, AluOp::Sltu, AluOp::Eq,
        AluOp::Mul, AluOp::Mulh, AluOp::Mulhu, AluOp::Mulhsu, AluOp::Div, AluOp::Divu, AluOp::Rem, AluOp::Remu,
    ];
    pub fn code(self) -> u32 { self as u32 }
    pub fn from_code(c: u32) -> AluOp { Self::ALL[c as usize] }
    /// Reference semantics. The ALU table proves exactly this function.
    pub fn eval(self, a: u32, b: u32) -> u32 {
        let s = b & 31;
        match self {
            AluOp::Add => a.wrapping_add(b),
            AluOp::Sub => a.wrapping_sub(b),
            AluOp::And => a & b,
            AluOp::Or => a | b,
            AluOp::Xor => a ^ b,
            AluOp::Sll => a << s,
            AluOp::Srl => a >> s,
            AluOp::Sra => ((a as i32) >> s) as u32,
            AluOp::Slt => ((a as i32) < (b as i32)) as u32,
            AluOp::Sltu => (a < b) as u32,
            AluOp::Eq => (a == b) as u32,
            AluOp::Mul => a.wrapping_mul(b),
            AluOp::Mulh => (((a as i32 as i64) * (b as i32 as i64)) >> 32) as u32,
            AluOp::Mulhu => (((a as u64) * (b as u64)) >> 32) as u32,
            AluOp::Mulhsu => (((a as i32 as i64) * (b as u64 as i64)) >> 32) as u32,
            AluOp::Div => {
                if b == 0 { 0xffff_ffff }
                else if a == 0x8000_0000 && b == 0xffff_ffff { 0x8000_0000 }
                else { ((a as i32).wrapping_div(b as i32)) as u32 }
            }
            AluOp::Divu => if b == 0 { 0xffff_ffff } else { a / b },
            AluOp::Rem => {
                if b == 0 { a }
                else if a == 0x8000_0000 && b == 0xffff_ffff { 0 }
                else { ((a as i32).wrapping_rem(b as i32)) as u32 }
            }
            AluOp::Remu => if b == 0 { a } else { a % b },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BranchCond { Eq, Ne, Lt, Ge, Ltu, Geu }

impl BranchCond {
    /// The compare the ALU performs; `negate` flips its result.
    pub fn alu_op(self) -> AluOp { match self { Self::Eq | Self::Ne => AluOp::Eq, Self::Lt | Self::Ge => AluOp::Slt, Self::Ltu | Self::Geu => AluOp::Sltu } }
    pub fn negate(self) -> bool { matches!(self, Self::Ne | Self::Ge | Self::Geu) }
    pub fn taken(self, a: u32, b: u32) -> bool { (self.alu_op().eval(a, b) == 1) != self.negate() }
    fn funct3(self) -> u32 { match self { Self::Eq => 0, Self::Ne => 1, Self::Lt => 4, Self::Ge => 5, Self::Ltu => 6, Self::Geu => 7 } }
    fn from_funct3(f: u32) -> Option<Self> { Some(match f { 0 => Self::Eq, 1 => Self::Ne, 4 => Self::Lt, 5 => Self::Ge, 6 => Self::Ltu, 7 => Self::Geu, _ => return None }) }
}

/// Sub-word load/store width. Memory itself stays word-addressed (`RAM` in the `memory`
/// table is keyed by word address); `Width` only selects how many bytes of the addressed
/// word a `Load`/`Store` touches, and — for loads — whether the result is sign-extended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Width { Byte, Half, Word }

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Instr {
    Lui { rd: u32, imm: u32 },
    Auipc { rd: u32, imm: u32 },
    Jal { rd: u32, imm: u32 },
    Jalr { rd: u32, rs1: u32, imm: u32 },
    Branch { cond: BranchCond, rs1: u32, rs2: u32, imm: u32 },
    Load { rd: u32, rs1: u32, imm: u32, width: Width, signed: bool },
    Store { rs1: u32, rs2: u32, imm: u32, width: Width },
    AluImm { op: AluOp, rd: u32, rs1: u32, imm: u32 },
    AluReg { op: AluOp, rd: u32, rs1: u32, rs2: u32 },
    Ecall,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError { Opcode(u32), Funct(u32), Shamt(u32) }

// `pub(crate)`, not private: `tables::program`'s in-circuit decoder (M3.4) mirrors
// `Instr::decode` opcode-for-opcode and needs these exact same values, rather than a second,
// independently-typed set of literals that could drift from this one.
pub(crate) const OP_LUI: u32 = 0x37; pub(crate) const OP_AUIPC: u32 = 0x17; pub(crate) const OP_JAL: u32 = 0x6f; pub(crate) const OP_JALR: u32 = 0x67;
pub(crate) const OP_BRANCH: u32 = 0x63; pub(crate) const OP_LOAD: u32 = 0x03; pub(crate) const OP_STORE: u32 = 0x23;
pub(crate) const OP_ALUI: u32 = 0x13; pub(crate) const OP_ALU: u32 = 0x33; pub(crate) const OP_SYSTEM: u32 = 0x73;

/// M-extension `funct3` order (standard RV32M): `MUL=0 MULH=1 MULHSU=2 MULHU=3 DIV=4 DIVU=5
/// REM=6 REMU=7`, always `funct7 = 1`. Register-register only — there is no RV32M immediate
/// form, so this is only ever reached from `Instr::AluReg`'s encode/decode path.
fn m_funct(op: AluOp) -> (u32, u32) {
    let f3 = match op {
        AluOp::Mul => 0, AluOp::Mulh => 1, AluOp::Mulhsu => 2, AluOp::Mulhu => 3,
        AluOp::Div => 4, AluOp::Divu => 5, AluOp::Rem => 6, AluOp::Remu => 7,
        _ => unreachable!("m_funct called on a non-M-extension op"),
    };
    (f3, 1)
}
fn m_from_funct3(f3: u32) -> Result<AluOp, DecodeError> {
    Ok(match f3 {
        0 => AluOp::Mul, 1 => AluOp::Mulh, 2 => AluOp::Mulhsu, 3 => AluOp::Mulhu,
        4 => AluOp::Div, 5 => AluOp::Divu, 6 => AluOp::Rem, 7 => AluOp::Remu,
        _ => return Err(DecodeError::Funct(f3)),
    })
}
fn alu_funct(op: AluOp) -> (u32, u32) {
    // (funct3, funct7)
    match op {
        AluOp::Add => (0, 0), AluOp::Sub => (0, 0x20), AluOp::Sll => (1, 0), AluOp::Slt => (2, 0), AluOp::Sltu => (3, 0),
        AluOp::Xor => (4, 0), AluOp::Srl => (5, 0), AluOp::Sra => (5, 0x20), AluOp::Or => (6, 0), AluOp::And => (7, 0),
        AluOp::Eq => unreachable!("EQ is not an encodable instruction"),
        AluOp::Mul | AluOp::Mulh | AluOp::Mulhu | AluOp::Mulhsu | AluOp::Div | AluOp::Divu | AluOp::Rem | AluOp::Remu => m_funct(op),
    }
}
fn alu_from_funct(f3: u32, f7: u32, imm_form: bool) -> Result<AluOp, DecodeError> {
    Ok(match (f3, f7) {
        (0, 0) => AluOp::Add,
        (0, 0x20) if !imm_form => AluOp::Sub,
        (0, _) if imm_form => AluOp::Add,
        (1, 0) => AluOp::Sll,
        (2, _) if imm_form => AluOp::Slt, (2, 0) => AluOp::Slt,
        (3, _) if imm_form => AluOp::Sltu, (3, 0) => AluOp::Sltu,
        (4, _) if imm_form => AluOp::Xor, (4, 0) => AluOp::Xor,
        (5, 0) => AluOp::Srl, (5, 0x20) => AluOp::Sra,
        (6, _) if imm_form => AluOp::Or, (6, 0) => AluOp::Or,
        (7, _) if imm_form => AluOp::And, (7, 0) => AluOp::And,
        _ => return Err(DecodeError::Funct((f7 << 3) | f3)),
    })
}
pub(crate) fn sext(x: u32, bits: u32) -> u32 { ((x << (32 - bits)) as i32 >> (32 - bits)) as u32 }
fn bits(w: u32, hi: u32, lo: u32) -> u32 { (w >> lo) & ((1u32 << (hi - lo + 1)) - 1) }

impl Instr {
    pub fn encode(&self) -> u32 {
        // Audit ZM3 (2026-09-12): every immediate is stored sign-extended in a `u32`, but the
        // encoding fields are narrower — so an out-of-range immediate used to be *silently
        // truncated* by the `& 0xfff`/`bits(..)` masks below, producing wrong code with no
        // error (the emulator and the AIR then faithfully prove the misassembled program; this
        // is AGENTS.md invariant 3's bug class, now caught rather than only documented).
        // Assert the ranges here, the one choke point where the value is still known —
        // host-side only, matching `Assembler::label`'s own panic on a duplicate label;
        // `decode` never calls this.
        let i_type = |imm: u32, rs1: u32, f3: u32, rd: u32, op: u32| {
            assert!((-2048..=2047).contains(&(imm as i32)), "I-type immediate {} does not fit 12 bits", imm as i32);
            (imm & 0xfff) << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op
        };
        match *self {
            Instr::Lui { rd, imm } => { assert_eq!(imm & 0xfff, 0, "LUI immediate {imm:#x} has low 12 bits set"); (imm & 0xffff_f000) | rd << 7 | OP_LUI }
            Instr::Auipc { rd, imm } => { assert_eq!(imm & 0xfff, 0, "AUIPC immediate {imm:#x} has low 12 bits set"); (imm & 0xffff_f000) | rd << 7 | OP_AUIPC }
            Instr::Jal { rd, imm } => {
                assert!((-(1 << 20)..=(1 << 20) - 1).contains(&(imm as i32)) && imm & 1 == 0, "JAL offset {} does not fit 21 bits", imm as i32);
                bits(imm, 20, 20) << 31 | bits(imm, 10, 1) << 21 | bits(imm, 11, 11) << 20 | bits(imm, 19, 12) << 12 | rd << 7 | OP_JAL
            }
            Instr::Jalr { rd, rs1, imm } => i_type(imm, rs1, 0, rd, OP_JALR),
            Instr::Branch { cond, rs1, rs2, imm } => {
                assert!((-4096..=4095).contains(&(imm as i32)) && imm & 1 == 0, "branch offset {} does not fit 13 bits", imm as i32);
                bits(imm, 12, 12) << 31 | bits(imm, 10, 5) << 25 | rs2 << 20 | rs1 << 15 | cond.funct3() << 12 | bits(imm, 4, 1) << 8 | bits(imm, 11, 11) << 7 | OP_BRANCH
            }
            Instr::Load { rd, rs1, imm, width, signed } => {
                let f3 = match (width, signed) {
                    (Width::Byte, true) => 0, (Width::Half, true) => 1, (Width::Word, _) => 2,
                    (Width::Byte, false) => 4, (Width::Half, false) => 5,
                };
                i_type(imm, rs1, f3, rd, OP_LOAD)
            }
            Instr::Store { rs1, rs2, imm, width } => {
                assert!((-2048..=2047).contains(&(imm as i32)), "S-type immediate {} does not fit 12 bits", imm as i32);
                let f3 = match width { Width::Byte => 0, Width::Half => 1, Width::Word => 2 };
                bits(imm, 11, 5) << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | bits(imm, 4, 0) << 7 | OP_STORE
            }
            Instr::AluImm { op, rd, rs1, imm } => {
                let (f3, f7) = alu_funct(op);
                let imm = if matches!(op, AluOp::Sll | AluOp::Srl | AluOp::Sra) {
                    assert!(imm < 32, "shift amount {imm} does not fit 5 bits");
                    (imm & 31) | f7 << 5
                } else { imm };
                i_type(imm, rs1, f3, rd, OP_ALUI)
            }
            Instr::AluReg { op, rd, rs1, rs2 } => { let (f3, f7) = alu_funct(op); f7 << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | rd << 7 | OP_ALU }
            Instr::Ecall => OP_SYSTEM,
        }
    }

    pub fn decode(w: u32) -> Result<Instr, DecodeError> {
        let op = w & 0x7f; let rd = bits(w, 11, 7); let f3 = bits(w, 14, 12); let rs1 = bits(w, 19, 15); let rs2 = bits(w, 24, 20); let f7 = bits(w, 31, 25);
        let imm_i = sext(bits(w, 31, 20), 12);
        Ok(match op {
            OP_LUI => Instr::Lui { rd, imm: w & 0xffff_f000 },
            OP_AUIPC => Instr::Auipc { rd, imm: w & 0xffff_f000 },
            OP_JAL => { let imm = bits(w, 31, 31) << 20 | bits(w, 19, 12) << 12 | bits(w, 20, 20) << 11 | bits(w, 30, 21) << 1; Instr::Jal { rd, imm: sext(imm, 21) } }
            OP_JALR => Instr::Jalr { rd, rs1, imm: imm_i },
            OP_BRANCH => { let imm = bits(w, 31, 31) << 12 | bits(w, 7, 7) << 11 | bits(w, 30, 25) << 5 | bits(w, 11, 8) << 1; Instr::Branch { cond: BranchCond::from_funct3(f3).ok_or(DecodeError::Funct(f3))?, rs1, rs2, imm: sext(imm, 13) } }
            OP_LOAD => {
                let (width, signed) = match f3 {
                    0 => (Width::Byte, true), 1 => (Width::Half, true), 2 => (Width::Word, false),
                    4 => (Width::Byte, false), 5 => (Width::Half, false),
                    _ => return Err(DecodeError::Funct(f3)),
                };
                Instr::Load { rd, rs1, imm: imm_i, width, signed }
            }
            OP_STORE => {
                let width = match f3 { 0 => Width::Byte, 1 => Width::Half, 2 => Width::Word, _ => return Err(DecodeError::Funct(f3)) };
                Instr::Store { rs1, rs2, imm: sext(bits(w, 31, 25) << 5 | bits(w, 11, 7), 12), width }
            }
            OP_ALUI => {
                let shift = matches!(f3, 1 | 5);
                let op = alu_from_funct(f3, if shift { f7 } else { 0 }, true)?;
                let imm = if shift { if f7 != 0 && f7 != 0x20 { return Err(DecodeError::Shamt(f7)); } rs2 } else { imm_i };
                Instr::AluImm { op, rd, rs1, imm }
            }
            OP_ALU => {
                // funct7 = 1 selects the M extension exclusively; every other funct7 goes
                // through the RV32I decode table, which already rejects funct7 = 1 (no
                // pattern in `alu_from_funct` matches it).
                let op = if f7 == 1 { m_from_funct3(f3)? } else { alu_from_funct(f3, f7, false)? };
                Instr::AluReg { op, rd, rs1, rs2 }
            }
            OP_SYSTEM if w == OP_SYSTEM => Instr::Ecall,
            _ => return Err(DecodeError::Opcode(op)),
        })
    }

    pub fn decoded(&self) -> Decoded {
        let mut d = Decoded::default();
        let wr = |rd: u32| (rd != 0) as u32;
        match *self {
            Instr::Lui { rd, imm } => { d.rd = rd; d.imm = imm; d.is_lui = 1; d.writes_rd = wr(rd); }
            Instr::Auipc { rd, imm } => { d.rd = rd; d.imm = imm; d.is_auipc = 1; d.writes_rd = wr(rd); }
            Instr::Jal { rd, imm } => { d.rd = rd; d.imm = imm; d.is_jal = 1; d.writes_rd = wr(rd); }
            Instr::Jalr { rd, rs1, imm } => { d.rd = rd; d.rs1 = rs1; d.imm = imm; d.is_jalr = 1; d.is_imm = 1; d.writes_rd = wr(rd); }
            Instr::Branch { cond, rs1, rs2, imm } => { d.rs1 = rs1; d.rs2 = rs2; d.imm = imm; d.is_branch = 1; d.br_op = cond.alu_op().code(); d.br_neg = cond.negate() as u32; }
            Instr::Load { rd, rs1, imm, width, signed } => {
                d.rd = rd; d.rs1 = rs1; d.imm = imm; d.is_imm = 1; d.writes_rd = wr(rd); d.signed = signed as u32;
                match width { Width::Byte => d.is_lb = 1, Width::Half => d.is_lh = 1, Width::Word => d.is_lw = 1 }
            }
            Instr::Store { rs1, rs2, imm, width } => {
                d.rs1 = rs1; d.rs2 = rs2; d.imm = imm; d.is_imm = 1;
                match width { Width::Byte => d.is_sb = 1, Width::Half => d.is_sh = 1, Width::Word => d.is_sw = 1 }
            }
            Instr::AluImm { op, rd, rs1, imm } => { d.rd = rd; d.rs1 = rs1; d.imm = imm; d.is_alu = 1; d.alu_op = op.code(); d.is_imm = 1; d.writes_rd = wr(rd); }
            Instr::AluReg { op, rd, rs1, rs2 } => { d.rd = rd; d.rs1 = rs1; d.rs2 = rs2; d.is_alu = 1; d.alu_op = op.code(); d.writes_rd = wr(rd); }
            Instr::Ecall => { d.rs1 = REG_A7; d.rs2 = REG_A0; d.rd = REG_A0; d.is_ecall = 1; }
        }
        d
    }
}

/// The PROGRAM bus message minus `pc`. Every field is a small non-negative
/// integer; booleans are 0/1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    pub rd: u32, pub rs1: u32, pub rs2: u32, pub imm: u32,
    pub is_alu: u32, pub alu_op: u32, pub is_imm: u32,
    pub is_branch: u32, pub br_op: u32, pub br_neg: u32,
    pub is_lb: u32, pub is_lh: u32, pub is_lw: u32,
    pub is_sb: u32, pub is_sh: u32, pub is_sw: u32, pub signed: u32,
    pub is_jal: u32, pub is_jalr: u32,
    pub is_lui: u32, pub is_auipc: u32, pub is_ecall: u32, pub writes_rd: u32,
}
impl Decoded {
    pub const NUM_FIELDS: usize = 23;
    pub fn to_fields(&self) -> [u32; 23] {
        [self.rd, self.rs1, self.rs2, self.imm, self.is_alu, self.alu_op, self.is_imm, self.is_branch, self.br_op, self.br_neg,
         self.is_lb, self.is_lh, self.is_lw, self.is_sb, self.is_sh, self.is_sw, self.signed,
         self.is_jal, self.is_jalr, self.is_lui, self.is_auipc, self.is_ecall, self.writes_rd]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program { pub base_pc: u32, pub words: Vec<u32> }
impl Program {
    pub fn new(base_pc: u32, words: Vec<u32>) -> Self { assert_eq!(base_pc % 4, 0); Self { base_pc, words } }
    pub fn len(&self) -> usize { self.words.len() }
    pub fn is_empty(&self) -> bool { self.words.is_empty() }
    pub fn pc_of(&self, index: usize) -> u32 { self.base_pc + 4 * index as u32 }
    pub fn instr_at(&self, pc: u32) -> Option<Instr> {
        if pc < self.base_pc || pc % 4 != 0 { return None; }
        self.words.get(((pc - self.base_pc) / 4) as usize).and_then(|w| Instr::decode(*w).ok())
    }

    /// Number of cpu-table digest rows `hc` costs to prove: one Poseidon2 permutation per
    /// up-to-4-word group of the program, at least 1 (so even the degenerate empty program
    /// gets one permutation absorbing its domain/base_pc/len header — see `hash::program_digest`'s
    /// doc comment for why that header never gets its own row). `tables::cpu::cpu_trace`,
    /// `Machine::build_traces`'s cycle count and `Program::digest` all agree on this number.
    /// The `max(1)` case is a *digest-function* convenience only (audit ZL3, 2026-09-12): an
    /// empty program is unprovable by construction — the AIR forces lane 0 active on every
    /// digest row (`(is_hash + is_digest)·(1 − ACT0) = 0`) — and the emulator never gets that
    /// far anyway (`instr_at` on an empty program is `BadPc`, and `from_flat_binary` rejects
    /// empty images).
    pub fn digest_rows(&self) -> usize { self.words.len().div_ceil(4).max(1) }

    /// hc: the in-circuit program commitment (M3.4). `tables::cpu`'s digest rows compute
    /// exactly this, row group by row group, absorbing `words` into `POSEIDON2` and pinning
    /// the result to `pv::HC0..HC7` — see `hash::program_digest`'s doc comment for the exact
    /// sponge construction and why it costs exactly `digest_rows()` permutations.
    pub fn digest(&self) -> [u32; 8] { crate::hash::program_digest(self.base_pc, &self.words) }

    /// hc as hex — the M3.4 replacement for `Machine::code_hash` (which, before M3.4, hashed
    /// the *preprocessed* program-table commitment; that commitment is program-independent
    /// now, so it can no longer serve as a program identity). Plain big-endian hex of the 8
    /// digest words, no `Machine`/tier involved — `hc` doesn't depend on either.
    pub fn code_hash(&self) -> String {
        self.digest().iter().map(|w| format!("{w:08x}")).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    Empty,
    Length(usize),
    BasePc(u32),
    TooLong(usize),
    Decode { index: usize, word: u32, err: DecodeError },
    /// M4.3's image container: the first word is not [`IMAGE_MAGIC`].
    Magic(u32),
    /// A container version this loader does not know.
    Version(u32),
    /// The header's two segment lengths do not account for exactly the words that follow.
    Segments { n_text: usize, n_data: usize, words: usize },
    /// A text or data base address that is not a multiple of 4.
    Base(u32),
    /// A segment whose last address does not exist: `base + 4 · n_words` wraps `u32`. Reported for
    /// whichever of the two segments wraps.
    Range { base: u32, n_words: usize },
    /// A data segment that would be written over the text's own address range. The two are
    /// different spaces in this machine (the program is fetched, RAM is loaded), but the guest's
    /// linker lays them out in one address space and its `lui`-based references assume that layout,
    /// so a container claiming otherwise is malformed rather than merely odd — `mkimage.py` refuses
    /// to build one and this is the same check at the loading end.
    Overlap { text_end: u32, data_base: u32 },
    /// The synthesised data prologue does not fit below the text segment's load address: `words`
    /// instructions need `4 · words` bytes of program space before `text_base`.
    PrologueRoom { text_base: u32, words: usize },
}

/// The first word of an M4.3 image container: `b"RAND"` read little-endian.
pub const IMAGE_MAGIC: u32 = 0x444e_4152;
/// The only container layout this loader knows.
pub const IMAGE_VERSION: u32 = 1;
/// `[magic, version, text_base, n_text, data_base, n_data]`.
pub const IMAGE_HEADER_WORDS: usize = 6;

/// The two registers the synthesised data prologue uses — `t0` (the value) and `t1` (the window
/// base). It runs before the guest's `_start`, which sets `sp` and calls `main` itself, so no
/// register it touches is live (`guest-sdk`'s entry block).
const PROLOGUE_VAL: u32 = 5;
const PROLOGUE_BASE: u32 = 6;

/// The instructions that write `data` (loaded at `data_base`) into RAM: for each **non-zero** word,
/// `li t0, word` and an `sw` through a base register `t1` re-pointed every 2 KiB so the store's
/// offset always fits RISC-V's signed 12-bit S-type immediate (AGENTS.md invariant 3).
///
/// A zero word is skipped, not stored: the memory AIR constrains the first access to a fresh
/// address, when it is a read, to carry value 0 — `IS_REAL · ADDR_CHANGED · (1 − IS_WRITE) · VALUE`
/// on the transition and the same product on the first row (`tables::memory`) — so RAM already
/// holds exactly what the image says for those words, and not by the trace builder's goodwill. That
/// is what makes the prologue proportional to a guest's *non-zero* data rather than to its whole
/// `.rodata`.
fn data_prologue(data_base: u32, data: &[u32]) -> Vec<Instr> {
    use crate::asm::ops::{li, sw};
    let mut out = Vec::new();
    let mut window: Option<u32> = None;
    for (i, &word) in data.iter().enumerate() {
        if word == 0 {
            continue;
        }
        let addr = data_base + 4 * i as u32;
        // A new window whenever the offset would leave the immediate's range (2044 keeps the
        // store word-aligned as well as in range).
        if window.is_none_or(|base| addr - base > 2044) {
            out.extend(li(PROLOGUE_BASE, addr as i32));
            window = Some(addr);
        }
        out.extend(li(PROLOGUE_VAL, word as i32));
        out.push(sw(PROLOGUE_BASE, PROLOGUE_VAL, (addr - window.unwrap()) as i32));
    }
    out
}

impl Program {
    /// The M4.1 flat-binary loader: little-endian words, `base_pc % 4 == 0`, every word must
    /// decode (`Instr::decode`, the same check `program_trace` enforces as a panic on a
    /// hand-built `Program` — this is the friendly, `Result`-returning path in front of it).
    /// The size cap is **65535 words** (audit ZH2, 2026-09-12), not the program table's
    /// `MAX_LOG_HEIGHT` shape ceiling: the digest rows' `HASH_LEFT` (= the program's word count
    /// on the first digest row) is a 16-bit value in the AIR (`tables::cpu`'s `LEFT0..1` byte
    /// limbs), so a longer program can never satisfy the AIR no matter the tier — rejecting it
    /// here keeps that from surfacing as an opaque constraint failure deep inside `prove_batch`
    /// (`machine::ProveError::ProgramTooLong` is the same bound on the `Machine::prove` path).
    ///
    /// This is the loader for a guest with **no data segment**; a compiled guest that has one
    /// (`.rodata`: jump tables, string literals, any constant LLVM chose to materialise) is
    /// packaged as an image container and loaded by [`from_flat_image`](Program::from_flat_image).
    pub fn from_flat_binary(base_pc: u32, bytes: &[u8]) -> Result<Program, LoadError> {
        if bytes.is_empty() { return Err(LoadError::Empty); }
        if bytes.len() % 4 != 0 { return Err(LoadError::Length(bytes.len())); }
        if base_pc % 4 != 0 { return Err(LoadError::BasePc(base_pc)); }
        let words: Vec<u32> = bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        let max_words = u16::MAX as usize;
        if words.len() > max_words { return Err(LoadError::TooLong(words.len())); }
        for (index, &word) in words.iter().enumerate() {
            if let Err(err) = Instr::decode(word) { return Err(LoadError::Decode { index, word, err }); }
        }
        Ok(Program::new(base_pc, words))
    }

    /// The M4.3 image loader: a guest's `.text` **and its data segment** in one file, with the
    /// data written into RAM by a prologue this function synthesises.
    ///
    /// Until M4.3 a compiled guest had to have an empty `.rodata`/`.data`, because the flat image
    /// populated the instruction space only and RAM starts zero (`docs/01-isa.md`). That is fine
    /// for a hand-written sponge loop and impossible for a real compiler output: LLVM puts a
    /// `match`'s jump table, every panic `Location` and any constant it decides not to
    /// rematerialise into `.rodata`, and a guest whose data is missing does not fail — it reads
    /// zeros and computes the wrong answer, or jumps to `pc 0`.
    ///
    /// The fix needs nothing from the machine: the loader emits `li`/`sw` pairs that write the
    /// data words to their link addresses, places them **immediately before** the text so control
    /// falls through into the guest's own `_start` with no jump, and reports the whole thing as one
    /// `Program`. The data is therefore part of the program, so `hc` binds it exactly as it binds
    /// the code, and a verifier that accepts `hc` has accepted the constants too. The guest keeps
    /// its link addresses (its `lui`-based absolute references to `.bss`, and its jump tables'
    /// absolute entries, would not survive being moved), which is why the prologue goes below
    /// `text_base` and why a guest with a data segment must be linked with enough room there
    /// (`guests-compiled/evm/evm.ld` raises `ORIGIN` to `0x10000`; `LoadError::PrologueRoom` is
    /// the check).
    ///
    /// Container layout, all words little-endian:
    ///
    /// ```text
    /// [IMAGE_MAGIC, IMAGE_VERSION, text_base, n_text, data_base, n_data, text…, data…]
    /// ```
    ///
    /// `n_data = 0` is a first-class case: the prologue is empty, `base_pc = text_base`, and the
    /// `Program` is word-for-word the one [`from_flat_binary`](Program::from_flat_binary) builds
    /// from the same text — same words, same `hc` (`tests/isa.rs`).
    pub fn from_flat_image(bytes: &[u8]) -> Result<Program, LoadError> {
        if bytes.is_empty() { return Err(LoadError::Empty); }
        if bytes.len() % 4 != 0 { return Err(LoadError::Length(bytes.len())); }
        let all: Vec<u32> = bytes.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        if all.len() < IMAGE_HEADER_WORDS { return Err(LoadError::Length(bytes.len())); }
        if all[0] != IMAGE_MAGIC { return Err(LoadError::Magic(all[0])); }
        if all[1] != IMAGE_VERSION { return Err(LoadError::Version(all[1])); }
        let (text_base, n_text, data_base, n_data) = (all[2], all[3] as usize, all[4], all[5] as usize);
        let body = &all[IMAGE_HEADER_WORDS..];
        if n_text == 0 || n_text.checked_add(n_data) != Some(body.len()) {
            return Err(LoadError::Segments { n_text, n_data, words: body.len() });
        }
        if text_base % 4 != 0 { return Err(LoadError::Base(text_base)); }
        if data_base % 4 != 0 { return Err(LoadError::Base(data_base)); }
        // Both segments' last addresses have to exist. The data one matters because
        // `data_base + 4·(n_data − 1)` is computed in `u32` when the prologue is built, and a header
        // that wraps it would silently address the wrong RAM; the text one because its end bounds
        // the overlap check just below. Hence `u64` arithmetic here, once, rather than a wrapping
        // `u32` sum in either place.
        let text_end = text_base as u64 + 4 * n_text as u64;
        let data_end = data_base as u64 + 4 * n_data as u64;
        if text_end > u32::MAX as u64 {
            return Err(LoadError::Range { base: text_base, n_words: n_text });
        }
        if data_end > u32::MAX as u64 {
            return Err(LoadError::Range { base: data_base, n_words: n_data });
        }
        // And the data has to lie outside the text: the prologue's stores would otherwise write
        // over addresses the guest's own code and jump tables refer to. `data_base == text_end` is
        // the normal case — the linker puts `.rodata` immediately after `.text`, which is exactly
        // what the committed `evm.bin` does — so this is a strict overlap test, not an adjacency one.
        if n_data > 0 && (data_base as u64) < text_end && (text_base as u64) < data_end {
            return Err(LoadError::Overlap { text_end: text_end as u32, data_base });
        }
        let (text, data) = body.split_at(n_text);

        let prologue = data_prologue(data_base, data);
        // The prologue lives below `text_base`, so it needs that much program space to exist.
        if 4 * prologue.len() as u64 > text_base as u64 {
            return Err(LoadError::PrologueRoom { text_base, words: prologue.len() });
        }
        let mut words: Vec<u32> = prologue.iter().map(Instr::encode).collect();
        let base_pc = text_base - 4 * words.len() as u32;
        words.extend_from_slice(text);
        if words.len() > u16::MAX as usize { return Err(LoadError::TooLong(words.len())); }
        // Only the text needs checking — every prologue word came from `Instr::encode` — but the
        // whole vector is checked anyway, at the same cost, so the invariant "every word of a
        // loaded program decodes" holds by construction of this function rather than by argument.
        for (index, &word) in words.iter().enumerate() {
            if let Err(err) = Instr::decode(word) { return Err(LoadError::Decode { index, word, err }); }
        }
        Ok(Program::new(base_pc, words))
    }

    /// The inverse: little-endian bytes of every word, `base_pc` carried only in the
    /// `Program` itself (a flat binary has no header — the loader's caller supplies
    /// `base_pc` out of band, exactly `guests::compiled::fib`'s `0x1000` literal does).
    pub fn to_flat_binary(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.words.len() * 4);
        for w in &self.words { out.extend_from_slice(&w.to_le_bytes()); }
        out
    }

    /// The image container [`from_flat_image`](Program::from_flat_image) reads, for tests and for
    /// `guests-compiled/mkimage.py`'s reference: header, text words, data words.
    pub fn to_flat_image(text_base: u32, text: &[u32], data_base: u32, data: &[u32]) -> Vec<u8> {
        let mut words = vec![IMAGE_MAGIC, IMAGE_VERSION, text_base, text.len() as u32, data_base, data.len() as u32];
        words.extend_from_slice(text);
        words.extend_from_slice(data);
        let mut out = Vec::with_capacity(words.len() * 4);
        for w in &words { out.extend_from_slice(&w.to_le_bytes()); }
        out
    }
}

