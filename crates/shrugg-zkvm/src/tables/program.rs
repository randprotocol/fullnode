//! M3.4: the program table as a **main** (witness) trace with an in-circuit decoder, instead
//! of a preprocessed ROM the verifier holds in the clear. Each row carries a raw 32-bit
//! instruction `WORD`, its bit decomposition, and the same 23 `Decoded` fields the old
//! preprocessed table carried — but now every field is *proved* to be a function of `WORD`
//! via a bit-level decoder that mirrors `isa::Instr::decode`/`Instr::decoded` opcode by
//! opcode, rather than being trusted host input. `VALID` is 1 iff `WORD` is a legal encoding
//! (one the decoder recognizes and every funct/shamt check `Instr::decode` makes passes) and
//! 0 otherwise — `docs/02-tables-and-buses.md`'s "in-circuit decoder" section has the full
//! argument. `hc` (`isa::Program::digest`/`hash::program_digest`) is the commitment that
//! replaces the old preprocessed Merkle root; `tables::cpu`'s digest rows compute it
//! in-circuit from this table's `PROGRAM_WORD` bus.
//!
//! ## Two buses, one table
//!
//! `PROGRAM` (unchanged in shape from M1–M3.3): `(pc, 23 decoded fields)`, consumed by an
//! ordinary cpu instruction-fetch row. `PROGRAM_WORD` (new): `(pc, word)`, consumed only by
//! cpu's digest rows (`tables::cpu`'s `IS_DIGEST`) — kept separate so a digest row's raw-word
//! lookups can never be mistaken for (or double-count against) an ordinary fetch's own
//! multiplicity bookkeeping. `MULT` (the `PROGRAM` fetch count) is forced to 0 wherever `VALID
//! = 0` (AGENTS.md invariant 2) — a row that isn't a legal instruction can never be fetched,
//! which also means every real program word must decode (`program_trace` panics otherwise,
//! exactly as the old preprocessed builder did) — this table cannot commit to a program
//! containing an instruction the emulator could never execute. `MULT_WORD` is pinned harder —
//! see the next section.
//!
//! ## `hc` binds the whole executable program — every valid row is digested, not just `len` of them
//!
//! `MULT_WORD` is constrained to equal `VALID` *exactly* (`mult_word = valid`), not merely
//! zeroed wherever `VALID = 0` the way an ordinary bus multiplicity gate would read (M2's ALU
//! padding-row lesson, AGENTS.md invariant 2). The weaker, one-sided form —
//! `mult_word · (1 − valid) = 0` — was this table's actual constraint through the first cut of
//! M3.4 and was a real gap: it forces `mult_word = 0` on invalid rows but leaves it *free* on
//! valid ones, so a `VALID = 1` row (a real, decodable instruction) could supply zero copies
//! of its own `(pc, word)` to `PROGRAM_WORD` and simply never be digested — while remaining
//! fully fetchable and executable via `PROGRAM`, e.g. as a `JALR` target past the honest
//! `base_pc + 4·len` digest range. `hc` would then bind a strict prefix of the executable
//! program, not the whole thing.
//!
//! With `mult_word = valid`, `PROGRAM_WORD`'s LogUp balance becomes a set-equality argument
//! instead of a mere counting one. The consume side is exactly `len` distinct messages — one
//! per `base_pc + 4·j` for each `j < len`, in the order `tables::cpu`'s digest rows absorb
//! them. The provide side is now exactly one message per valid row, at that row's own `pc`
//! (unique across the table — see "No address aliasing" below). LogUp balance requires every
//! provided message to be matched by demand and vice versa, so the set of valid rows' `pc`
//! values must *equal* `{base_pc + 4·j : j < len}`: `len` comes out equal to the number of
//! valid rows, and each digested word is exactly the word the corresponding row actually
//! holds. A prover who honestly sets `mult_word = 1` on an extra valid row placed outside that
//! window supplies a message nothing demands, and the bus fails to balance —
//! `LOOKUP_BALANCE_PANIC` on `PROGRAM_WORD`, the ordinary lookup-balance rejection every other
//! bus relies on. The simpler witness — reproducing the original gap directly, a valid row
//! left at `mult_word = 0` — never even reaches that global check: it trips the local
//! `mult_word = valid` equation on its own row first (`CONSTRAINT_PANIC`), since `0 ≠ 1` there.
//! Either way, there is no way to be `VALID = 1` and excluded from `hc`.
//! `tests/cheating.rs::an_undigested_reachable_program_tail_is_rejected` reproduces the
//! simpler (local) case, since that's the original gap verbatim; `docs/02-tables-and-buses.md`/
//! `docs/03-privacy.md` carry the same set-equality argument at the bus and privacy level
//! respectively.
//!
//! ## No address aliasing without knowing `base_pc`
//!
//! Since `PC` is now a witness column (not host-trusted preprocessed data), a dishonest
//! prover could in principle try to alias two rows to the same `pc` (letting one table row
//! answer for two different logical instructions) unless something rules that out. The fix
//! needs no reference value the verifier doesn't have: every row's `PC` is pinned to be
//! exactly 4 more than the row before it (`PC` a strictly increasing arithmetic sequence,
//! unconditionally, padding rows included — harmless there, nothing reads them). Over any
//! realistic table height (far below the Goldilocks characteristic) that makes every row's
//! `PC` distinct, full stop, regardless of what absolute value the sequence starts at — so
//! `PROGRAM`/`PROGRAM_WORD` lookups can never be satisfied by the "wrong" row. The starting
//! value itself needs no separate check: `tables::cpu`'s own digest-row `PC` chain and
//! ordinary fetches only ever ask this table for `pc` values consistent with *some* fixed
//! base, and the `LogUp` bus balance itself is what forces the cpu table's chosen base to
//! agree with whatever this table's rows actually start at — a mismatched base simply fails
//! to find any providing row, the ordinary lookup-balance rejection every other bus relies on.
use super::{bus, F};
use crate::emulator::{CycleEvent, HashRow};
use crate::isa::{
    AluOp, BranchCond, Decoded, Instr, Program, OP_ALU, OP_ALUI, OP_AUIPC, OP_BRANCH, OP_JAL, OP_JALR, OP_LOAD, OP_LUI, OP_STORE, OP_SYSTEM,
    REG_A0, REG_A7,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use std::collections::HashMap;

pub mod col {
    pub const PC: usize = 0;
    pub const WORD: usize = 1;
    /// 32: little-endian boolean bits of `WORD` (`BIT0` = bit 0 = the opcode's LSB).
    pub const BIT0: usize = 2;
    // The 23 `Decoded` fields, in exactly `isa::Decoded::to_fields`'s order — this block is
    // the `PROGRAM` bus message (minus `pc`), unchanged in shape since M1.
    pub const RD: usize = 34;
    pub const RS1: usize = 35;
    pub const RS2: usize = 36;
    pub const IMM: usize = 37;
    pub const IS_ALU: usize = 38;
    pub const ALU_OP: usize = 39;
    pub const IS_IMM: usize = 40;
    pub const IS_BRANCH: usize = 41;
    pub const BR_OP: usize = 42;
    pub const BR_NEG: usize = 43;
    pub const IS_LB: usize = 44;
    pub const IS_LH: usize = 45;
    pub const IS_LW: usize = 46;
    pub const IS_SB: usize = 47;
    pub const IS_SH: usize = 48;
    pub const IS_SW: usize = 49;
    pub const SIGNED: usize = 50;
    pub const IS_JAL: usize = 51;
    pub const IS_JALR: usize = 52;
    pub const IS_LUI: usize = 53;
    pub const IS_AUIPC: usize = 54;
    pub const IS_ECALL: usize = 55;
    pub const WRITES_RD: usize = 56;
    pub const VALID: usize = 57;
    pub const MULT: usize = 58;
    pub const MULT_WORD: usize = 59;
    /// Is-zero gadget on the final `RD` field (the same two-constraint pattern `alu.rs` uses
    /// for `DIVZ`/`INVB`): `RD_IS_ZERO` is 1 iff `RD == 0`, so `WRITES_RD = (1-RD_IS_ZERO) *
    /// (the writer-opcode group)` matches `Instr::decoded`'s `wr(rd) = (rd != 0) as u32`.
    pub const RD_IS_ZERO: usize = 60;
    pub const RD_INV: usize = 61;
    /// 46: one legality/decode flag per (opcode, funct3, funct7) case `Instr::decode`
    /// recognizes — see the `flags` module below for the exact list and order. Each is a
    /// boolean column pinned `flag * (op mismatch or funct mismatch) = 0`; their sum is
    /// `VALID`. At most one can ever be forced nonzero on a given row (the opcode/funct
    /// patterns are pairwise disjoint), so this sum is itself always 0 or 1.
    pub const FLAG0: usize = 62;
    pub const WIDTH: usize = FLAG0 + super::flags::COUNT;
}

/// The 46 legality/decode flags in a fixed order, mirroring `isa::Instr::decode`'s `match`
/// arms one case at a time. `program_trace` sets exactly one of these per legal row (matching
/// `Instr::decode(word)`); the AIR pins each to require both its opcode and its funct
/// condition, so a word not matching *any* flag's conditions forces `VALID = 0`.
pub mod flags {
    pub const LUI: usize = 0;
    pub const AUIPC: usize = 1;
    pub const JAL: usize = 2;
    pub const JALR: usize = 3;
    // BranchCond order: Eq, Ne, Lt, Ge, Ltu, Geu (funct3 0,1,4,5,6,7) — `isa::BranchCond::from_funct3`.
    pub const BR_EQ: usize = 4;
    pub const BR_NE: usize = 5;
    pub const BR_LT: usize = 6;
    pub const BR_GE: usize = 7;
    pub const BR_LTU: usize = 8;
    pub const BR_GEU: usize = 9;
    // Load width/sign order: LB(f3=0,signed) LH(f3=1,signed) LW(f3=2) LBU(f3=4) LHU(f3=5).
    pub const LD_LB: usize = 10;
    pub const LD_LH: usize = 11;
    pub const LD_LW: usize = 12;
    pub const LD_LBU: usize = 13;
    pub const LD_LHU: usize = 14;
    // Store width order: SB(f3=0) SH(f3=1) SW(f3=2).
    pub const ST_SB: usize = 15;
    pub const ST_SH: usize = 16;
    pub const ST_SW: usize = 17;
    // OP_ALUI (imm_form=true): every f3 is legal; f3 in {1,5} (shifts) additionally requires
    // the real funct7 bits to be 0 or 0x20 (`isa::Instr::decode`'s `Shamt` check) — f3 not in
    // {1,5} ignores funct7 entirely (those bits are just part of the sign-extended immediate).
    pub const ALUI_ADD: usize = 18;
    pub const ALUI_SLL: usize = 19; // f7 == 0
    pub const ALUI_SLT: usize = 20;
    pub const ALUI_SLTU: usize = 21;
    pub const ALUI_XOR: usize = 22;
    pub const ALUI_SRL: usize = 23; // f7 == 0
    pub const ALUI_SRA: usize = 24; // f7 == 0x20
    pub const ALUI_OR: usize = 25;
    pub const ALUI_AND: usize = 26;
    // OP_ALU, funct7 != 1 (register-register RV32I, `isa::alu_funct`'s inverse table).
    pub const ALU_ADD: usize = 27; // f3=0 f7=0
    pub const ALU_SUB: usize = 28; // f3=0 f7=0x20
    pub const ALU_SLL: usize = 29; // f3=1 f7=0
    pub const ALU_SLT: usize = 30; // f3=2 f7=0
    pub const ALU_SLTU: usize = 31; // f3=3 f7=0
    pub const ALU_XOR: usize = 32; // f3=4 f7=0
    pub const ALU_SRL: usize = 33; // f3=5 f7=0
    pub const ALU_SRA: usize = 34; // f3=5 f7=0x20
    pub const ALU_OR: usize = 35; // f3=6 f7=0
    pub const ALU_AND: usize = 36; // f3=7 f7=0
    // OP_ALU, funct7 == 1 exclusively (M2.6 M-extension, `isa::m_from_funct3`'s order):
    // MUL MULH MULHSU MULHU DIV DIVU REM REMU.
    pub const ALUM_MUL: usize = 37;
    pub const ALUM_MULH: usize = 38;
    pub const ALUM_MULHSU: usize = 39;
    pub const ALUM_MULHU: usize = 40;
    pub const ALUM_DIV: usize = 41;
    pub const ALUM_DIVU: usize = 42;
    pub const ALUM_REM: usize = 43;
    pub const ALUM_REMU: usize = 44;
    // OP_SYSTEM *and* the whole word equals `OP_SYSTEM` (`isa::Instr::decode`'s literal
    // `OP_SYSTEM if w == OP_SYSTEM` guard — every other bit must be zero, not just the opcode).
    pub const ECALL: usize = 45;
    pub const COUNT: usize = 46;
}

pub const MESSAGE_LEN: usize = 1 + Decoded::NUM_FIELDS;

/// The smallest program-table height ever built, regardless of how short the program is —
/// matches the pre-M3.4 preprocessed builder's own floor.
pub const MIN_HEIGHT: usize = 16;
pub const MIN_LOG_HEIGHT: u8 = 4; // 1 << 4 == MIN_HEIGHT
/// Ceiling on the *declared* (proof-carried) program-table log-height (`Proof::
/// program_log_height`) — `2^22` rows is a program of up to ~4M words, comfortably past
/// anything this crate's guests or any conceivable RV32 program compiled for it need; a
/// verifier rejects anything larger before it can be used to size a table and panic on an
/// absurd shift (`machine::Machine::verify`).
pub const MAX_LOG_HEIGHT: u8 = 22;

/// M3.4 (fix): the program table's height is a **proof-declared** parameter now, not a
/// function of the tier alone — `Tier::program_height() = cpu_height()` was not a safe bound:
/// a digest row absorbs up to 4 `PROGRAM_WORD`s per *cycle*, so a program with `len` up to
/// `4·(cpu_height − 1)` words fits the cycle budget while needing far more than `cpu_height`
/// program-table rows to hold its own words. `pad_height(len + 1, MIN_HEIGHT)` (the same
/// "+1 padding row, floor at `MIN_HEIGHT`" rule the old preprocessed builder used) is the
/// honest prover's minimal choice; `program_log_height` is its base-2 log, what `Proof` and
/// `Machine::verify` actually carry/check (`log_ext_degrees` wants a log-height directly, and
/// a log fits in a `u8` where a height might not, at the `MAX_LOG_HEIGHT` ceiling).
///
/// **Soundness**, since the verifier no longer bounds this against anything itself: `hc`
/// (`hash::program_digest`) binds `(base_pc, len, words)` — the capacity-lane header commits
/// to the exact word count and base address — and `MULT_WORD = VALID` (this module's doc
/// comment, "`hc` binds the whole executable program") turns `PROGRAM_WORD`'s balance into a
/// set-equality argument, not a counting one: the digest rows demand exactly `len` distinct
/// messages, one per `base_pc + 4·j` for `j < len`, and every valid program-table row supplies
/// exactly one message at its own `pc` — so balancing forces the two sets equal, `len` rows for
/// `len` demands, no fewer and no more (and no valid row left outside the digested window). A
/// prover who declares a table too small to hold `len` real rows simply cannot build a
/// balancing witness (some `PROGRAM_WORD` provide `hc` demands has nowhere to live); a prover
/// who declares one larger than necessary only wastes their own proving time and the
/// verifier's degree-bits check — the declared height *sizes* the table, it never lets a
/// prover shrink, pad, or silently extend past the program the digest itself is bound to. See
/// `docs/03-privacy.md`.
pub fn program_log_height(len: usize) -> u8 {
    super::pad_height(len + 1, MIN_HEIGHT).trailing_zeros() as u8
}

use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct ProgramAir;

impl<Fld> BaseAir<Fld> for ProgramAir {
    fn width(&self) -> usize { WIDTH }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ProgramAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let bit = |i: usize| -> AB::Expr { v(BIT0 + i) };

        // No aliasing without a host-trusted `pc`: every row's `PC` is exactly 4 more than
        // the row before it (see the module doc comment). Unconditional — harmless on
        // padding rows, nothing reads them.
        b.when_transition().assert_zero(n(PC) - v(PC) - AB::Expr::from_u32(4));

        // Bit decomposition: WORD = sum(bit_i * 2^i), each bit boolean.
        for i in 0..32 { b.assert_bool(bit(i)); }
        let word_from_bits: AB::Expr = (0..32).map(|i| bit(i) * AB::Expr::from_u64(1u64 << i)).sum();
        b.assert_zero(v(WORD) - word_from_bits);

        // The raw bit-field reads `Instr::decode` makes: op (7 bits), f3 (3 bits), f7 (7
        // bits), rd/rs1/rs2 (5 bits each) — all degree 1 in the bit columns.
        let op: AB::Expr = (0..7).map(|i| bit(i) * AB::Expr::from_u32(1 << i)).sum();
        let f3: AB::Expr = (0..3).map(|i| bit(12 + i) * AB::Expr::from_u32(1 << i)).sum();
        let f7: AB::Expr = (0..7).map(|i| bit(25 + i) * AB::Expr::from_u32(1 << i)).sum();
        let raw_rd: AB::Expr = (0..5).map(|i| bit(7 + i) * AB::Expr::from_u32(1 << i)).sum();
        let raw_rs1: AB::Expr = (0..5).map(|i| bit(15 + i) * AB::Expr::from_u32(1 << i)).sum();
        let raw_rs2: AB::Expr = (0..5).map(|i| bit(20 + i) * AB::Expr::from_u32(1 << i)).sum();

        // Immediate formats. Every sign-extended field replicates the word's own MSB (bit
        // 31) into every bit above the format's native width — a single linear correction
        // term, since sign-extending a fixed-width field is linear in its top bit.
        let two32 = AB::Expr::from_u64(1u64 << 32);
        let sign = bit(31);
        // U-type (LUI/AUIPC): the raw top 20 bits, bottom 12 zeroed — no sign extension.
        let u_imm: AB::Expr = (12..32).map(|i| bit(i) * AB::Expr::from_u64(1u64 << i)).sum();
        // I-type (JALR/LOAD/ALUI non-shift): sext(bits[31:20], 12).
        let i_imm: AB::Expr = (20..32).map(|i| bit(i) * AB::Expr::from_u32(1 << (i - 20))).sum::<AB::Expr>()
            + sign.clone() * (two32.clone() - AB::Expr::from_u32(1 << 12));
        // S-type (STORE): sext(bits[31:25] << 5 | bits[11:7], 12).
        let s_imm: AB::Expr = (25..32).map(|i| bit(i) * AB::Expr::from_u32(1 << (i - 25 + 5))).sum::<AB::Expr>()
            + (7..12).map(|i| bit(i) * AB::Expr::from_u32(1 << (i - 7))).sum::<AB::Expr>()
            + sign.clone() * (two32.clone() - AB::Expr::from_u32(1 << 12));
        // B-type (BRANCH): sext(bits[31]<<12 | bits[7]<<11 | bits[30:25]<<5 | bits[11:8]<<1, 13).
        let b_imm: AB::Expr = sign.clone() * AB::Expr::from_u32(1 << 12)
            + bit(7) * AB::Expr::from_u32(1 << 11)
            + (25..31).map(|i| bit(i) * AB::Expr::from_u32(1 << (i - 25 + 5))).sum::<AB::Expr>()
            + (8..12).map(|i| bit(i) * AB::Expr::from_u32(1 << (i - 8 + 1))).sum::<AB::Expr>()
            + sign.clone() * (two32.clone() - AB::Expr::from_u32(1 << 13));
        // J-type (JAL): sext(bits[31]<<20 | bits[19:12]<<12 | bits[20]<<11 | bits[30:21]<<1, 21).
        let j_imm: AB::Expr = sign.clone() * AB::Expr::from_u32(1 << 20)
            + (12..20).map(|i| bit(i) * AB::Expr::from_u32(1 << i)).sum::<AB::Expr>()
            + bit(20) * AB::Expr::from_u32(1 << 11)
            + (21..31).map(|i| bit(i) * AB::Expr::from_u32(1 << (i - 21 + 1))).sum::<AB::Expr>()
            + sign * (two32 - AB::Expr::from_u32(1 << 21));

        // 46 legality/decode flags: each pinned by an opcode-match constraint and (where
        // needed) a funct-match constraint. A word matching no flag's conditions leaves
        // every flag at 0, forcing VALID = 0 below.
        let f = |i: usize| -> AB::Expr { v(FLAG0 + i) };
        for i in 0..flags::COUNT { b.assert_bool(f(i)); }
        let pin_op = |b: &mut AB, i: usize, code: u32| b.assert_zero(f(i) * (op.clone() - AB::Expr::from_u32(code)));
        let pin_f3 = |b: &mut AB, i: usize, code: u32| b.assert_zero(f(i) * (f3.clone() - AB::Expr::from_u32(code)));
        let pin_f7 = |b: &mut AB, i: usize, code: u32| b.assert_zero(f(i) * (f7.clone() - AB::Expr::from_u32(code)));

        pin_op(b, flags::LUI, OP_LUI);
        pin_op(b, flags::AUIPC, OP_AUIPC);
        pin_op(b, flags::JAL, OP_JAL);
        pin_op(b, flags::JALR, OP_JALR); // no funct3 requirement, matches `Instr::decode`'s literal `OP_JALR => ..` arm

        for (i, code) in [(flags::BR_EQ, 0u32), (flags::BR_NE, 1), (flags::BR_LT, 4), (flags::BR_GE, 5), (flags::BR_LTU, 6), (flags::BR_GEU, 7)] {
            pin_op(b, i, OP_BRANCH);
            pin_f3(b, i, code);
        }
        for (i, code) in [(flags::LD_LB, 0u32), (flags::LD_LH, 1), (flags::LD_LW, 2), (flags::LD_LBU, 4), (flags::LD_LHU, 5)] {
            pin_op(b, i, OP_LOAD);
            pin_f3(b, i, code);
        }
        for (i, code) in [(flags::ST_SB, 0u32), (flags::ST_SH, 1), (flags::ST_SW, 2)] {
            pin_op(b, i, OP_STORE);
            pin_f3(b, i, code);
        }
        // ALUI non-shift ops: f7 ignored entirely (it's part of the sign-extended immediate).
        for (i, code) in [(flags::ALUI_ADD, 0u32), (flags::ALUI_SLT, 2), (flags::ALUI_SLTU, 3), (flags::ALUI_XOR, 4), (flags::ALUI_OR, 6), (flags::ALUI_AND, 7)] {
            pin_op(b, i, OP_ALUI);
            pin_f3(b, i, code);
        }
        // ALUI shift ops: f7 must be exactly 0 or 0x20 (`isa::Instr::decode`'s `Shamt` check).
        pin_op(b, flags::ALUI_SLL, OP_ALUI); pin_f3(b, flags::ALUI_SLL, 1); pin_f7(b, flags::ALUI_SLL, 0);
        pin_op(b, flags::ALUI_SRL, OP_ALUI); pin_f3(b, flags::ALUI_SRL, 5); pin_f7(b, flags::ALUI_SRL, 0);
        pin_op(b, flags::ALUI_SRA, OP_ALUI); pin_f3(b, flags::ALUI_SRA, 5); pin_f7(b, flags::ALUI_SRA, 0x20);
        // ALU (register-register), funct7 != 1: exact (f3, f7) match, `isa::alu_funct`'s table.
        for (i, f3c, f7c) in [
            (flags::ALU_ADD, 0u32, 0u32), (flags::ALU_SUB, 0, 0x20), (flags::ALU_SLL, 1, 0), (flags::ALU_SLT, 2, 0), (flags::ALU_SLTU, 3, 0),
            (flags::ALU_XOR, 4, 0), (flags::ALU_SRL, 5, 0), (flags::ALU_SRA, 5, 0x20), (flags::ALU_OR, 6, 0), (flags::ALU_AND, 7, 0),
        ] {
            pin_op(b, i, OP_ALU);
            pin_f3(b, i, f3c);
            pin_f7(b, i, f7c);
        }
        // ALU M-extension, funct7 == 1 exclusively (M3.4 ruling: legal only under OP_ALU with
        // funct7 = 1 — an OP_ALUI word claiming an M op is never valid, since none of the
        // ALUI flags above ever match funct7 = 1 in the first place).
        for (i, code) in [
            (flags::ALUM_MUL, 0u32), (flags::ALUM_MULH, 1), (flags::ALUM_MULHSU, 2), (flags::ALUM_MULHU, 3),
            (flags::ALUM_DIV, 4), (flags::ALUM_DIVU, 5), (flags::ALUM_REM, 6), (flags::ALUM_REMU, 7),
        ] {
            pin_op(b, i, OP_ALU);
            pin_f3(b, i, code);
            pin_f7(b, i, 1);
        }
        // ECALL: the whole word must equal OP_SYSTEM, not just its opcode field.
        b.assert_zero(f(flags::ECALL) * (v(WORD) - AB::Expr::from_u32(OP_SYSTEM)));

        let sum = |idx: &[usize]| -> AB::Expr { idx.iter().map(|&i| f(i)).sum() };
        let branch_flags = [flags::BR_EQ, flags::BR_NE, flags::BR_LT, flags::BR_GE, flags::BR_LTU, flags::BR_GEU];
        let load_flags = [flags::LD_LB, flags::LD_LH, flags::LD_LW, flags::LD_LBU, flags::LD_LHU];
        let store_flags = [flags::ST_SB, flags::ST_SH, flags::ST_SW];
        let alui_flags = [
            flags::ALUI_ADD, flags::ALUI_SLL, flags::ALUI_SLT, flags::ALUI_SLTU, flags::ALUI_XOR, flags::ALUI_SRL, flags::ALUI_SRA, flags::ALUI_OR, flags::ALUI_AND,
        ];
        let alui_shift_flags = [flags::ALUI_SLL, flags::ALUI_SRL, flags::ALUI_SRA];
        let alu_flags = [
            flags::ALU_ADD, flags::ALU_SUB, flags::ALU_SLL, flags::ALU_SLT, flags::ALU_SLTU, flags::ALU_XOR, flags::ALU_SRL, flags::ALU_SRA, flags::ALU_OR, flags::ALU_AND,
        ];
        let alum_flags = [
            flags::ALUM_MUL, flags::ALUM_MULH, flags::ALUM_MULHSU, flags::ALUM_MULHU, flags::ALUM_DIV, flags::ALUM_DIVU, flags::ALUM_REM, flags::ALUM_REMU,
        ];

        let g_lui = f(flags::LUI);
        let g_auipc = f(flags::AUIPC);
        let g_jal = f(flags::JAL);
        let g_jalr = f(flags::JALR);
        let g_branch = sum(&branch_flags);
        let g_load = sum(&load_flags);
        let g_store = sum(&store_flags);
        let g_alui = sum(&alui_flags);
        let g_alui_shift = sum(&alui_shift_flags);
        let g_alui_nonshift = g_alui.clone() - g_alui_shift.clone();
        let g_alu_reg = sum(&alu_flags);
        let g_alu_m = sum(&alum_flags);
        let g_ecall = f(flags::ECALL);

        // VALID: the sum of all 46 flags. At most one can ever be nonzero on a given row (the
        // opcode/funct patterns above are pairwise disjoint), so this is always 0 or 1.
        let valid_sum: AB::Expr = (0..flags::COUNT).map(f).sum();
        b.assert_zero(valid_sum - v(VALID));

        // Field formulas: each `Decoded` field as the flag-weighted sum of the raw bits or
        // fixed override `Instr::decoded` assigns for that instruction kind — mirroring that
        // function's own `match` arm by arm, so a witness cannot claim VALID = 1 while
        // disagreeing with what the bits actually decode to.
        let rd_writer_group = g_lui.clone() + g_auipc.clone() + g_jal.clone() + g_jalr.clone() + g_load.clone() + g_alui.clone() + g_alu_reg.clone() + g_alu_m.clone();
        let rd_expr = raw_rd * rd_writer_group.clone() + AB::Expr::from_u32(REG_A0) * g_ecall.clone();
        b.assert_zero(v(RD) - rd_expr);

        let rs1_group = g_jalr.clone() + g_branch.clone() + g_load.clone() + g_store.clone() + g_alui.clone() + g_alu_reg.clone() + g_alu_m.clone();
        let rs1_expr = raw_rs1 * rs1_group + AB::Expr::from_u32(REG_A7) * g_ecall.clone();
        b.assert_zero(v(RS1) - rs1_expr);

        let rs2_group = g_branch.clone() + g_store.clone() + g_alu_reg.clone() + g_alu_m.clone();
        let rs2_expr = raw_rs2.clone() * rs2_group + AB::Expr::from_u32(REG_A0) * g_ecall.clone();
        b.assert_zero(v(RS2) - rs2_expr);

        let imm_expr = (g_lui.clone() + g_auipc.clone()) * u_imm
            + g_jal.clone() * j_imm
            + (g_jalr.clone() + g_load.clone() + g_alui_nonshift) * i_imm
            + g_branch.clone() * b_imm
            + g_store.clone() * s_imm
            + g_alui_shift * raw_rs2;
        b.assert_zero(v(IMM) - imm_expr);

        let is_alu_expr = g_alui.clone() + g_alu_reg.clone() + g_alu_m.clone();
        b.assert_zero(v(IS_ALU) - is_alu_expr);

        let code = |op: AluOp| AB::Expr::from_u32(op.code());
        let alu_op_expr = f(flags::ALUI_ADD) * code(AluOp::Add) + f(flags::ALUI_SLL) * code(AluOp::Sll) + f(flags::ALUI_SLT) * code(AluOp::Slt)
            + f(flags::ALUI_SLTU) * code(AluOp::Sltu) + f(flags::ALUI_XOR) * code(AluOp::Xor) + f(flags::ALUI_SRL) * code(AluOp::Srl)
            + f(flags::ALUI_SRA) * code(AluOp::Sra) + f(flags::ALUI_OR) * code(AluOp::Or) + f(flags::ALUI_AND) * code(AluOp::And)
            + f(flags::ALU_ADD) * code(AluOp::Add) + f(flags::ALU_SUB) * code(AluOp::Sub) + f(flags::ALU_SLL) * code(AluOp::Sll)
            + f(flags::ALU_SLT) * code(AluOp::Slt) + f(flags::ALU_SLTU) * code(AluOp::Sltu) + f(flags::ALU_XOR) * code(AluOp::Xor)
            + f(flags::ALU_SRL) * code(AluOp::Srl) + f(flags::ALU_SRA) * code(AluOp::Sra) + f(flags::ALU_OR) * code(AluOp::Or) + f(flags::ALU_AND) * code(AluOp::And)
            + f(flags::ALUM_MUL) * code(AluOp::Mul) + f(flags::ALUM_MULH) * code(AluOp::Mulh) + f(flags::ALUM_MULHSU) * code(AluOp::Mulhsu)
            + f(flags::ALUM_MULHU) * code(AluOp::Mulhu) + f(flags::ALUM_DIV) * code(AluOp::Div) + f(flags::ALUM_DIVU) * code(AluOp::Divu)
            + f(flags::ALUM_REM) * code(AluOp::Rem) + f(flags::ALUM_REMU) * code(AluOp::Remu);
        b.assert_zero(v(ALU_OP) - alu_op_expr);

        b.assert_zero(v(IS_IMM) - (g_alui.clone() + g_jalr.clone() + g_load.clone() + g_store.clone()));
        b.assert_zero(v(IS_BRANCH) - g_branch.clone());
        let br = |c: BranchCond| AB::Expr::from_u32(c.alu_op().code());
        let br_op_expr = f(flags::BR_EQ) * br(BranchCond::Eq) + f(flags::BR_NE) * br(BranchCond::Ne) + f(flags::BR_LT) * br(BranchCond::Lt)
            + f(flags::BR_GE) * br(BranchCond::Ge) + f(flags::BR_LTU) * br(BranchCond::Ltu) + f(flags::BR_GEU) * br(BranchCond::Geu);
        b.assert_zero(v(BR_OP) - br_op_expr);
        b.assert_zero(v(BR_NEG) - (f(flags::BR_NE) + f(flags::BR_GE) + f(flags::BR_GEU)));

        b.assert_zero(v(IS_LB) - (f(flags::LD_LB) + f(flags::LD_LBU)));
        b.assert_zero(v(IS_LH) - (f(flags::LD_LH) + f(flags::LD_LHU)));
        b.assert_zero(v(IS_LW) - f(flags::LD_LW));
        b.assert_zero(v(IS_SB) - f(flags::ST_SB));
        b.assert_zero(v(IS_SH) - f(flags::ST_SH));
        b.assert_zero(v(IS_SW) - f(flags::ST_SW));
        b.assert_zero(v(SIGNED) - (f(flags::LD_LB) + f(flags::LD_LH)));
        b.assert_zero(v(IS_JAL) - g_jal);
        b.assert_zero(v(IS_JALR) - g_jalr);
        b.assert_zero(v(IS_LUI) - g_lui);
        b.assert_zero(v(IS_AUIPC) - g_auipc);
        b.assert_zero(v(IS_ECALL) - g_ecall);

        // writes_rd: `(rd != 0)` (the two-constraint is-zero gadget, `alu.rs`'s `DIVZ`
        // pattern) times the writer-opcode group — matches `Instr::decoded`'s `wr(rd)`.
        b.assert_bool(v(RD_IS_ZERO));
        b.assert_zero(v(RD) * v(RD_INV) - (one.clone() - v(RD_IS_ZERO)));
        b.assert_zero(v(RD_IS_ZERO) * v(RD));
        let wr_rd = one.clone() - v(RD_IS_ZERO);
        b.assert_zero(v(WRITES_RD) - wr_rd * rd_writer_group);

        // The PROGRAM bus (ordinary instruction fetch, unchanged shape) and the new
        // PROGRAM_WORD bus (M3.4 digest rows). `MULT` is forced to 0 on any row where
        // `VALID = 0` — a padding row, or a genuinely undecodable real word (which
        // `program_trace` never produces, since it panics on one, the same way the old
        // preprocessed builder did) — AGENTS.md invariant 2. `MULT_WORD` is pinned to equal
        // `VALID` *exactly* (not merely zeroed on invalid rows): every valid row must supply
        // exactly one `PROGRAM_WORD` copy of its own `(pc, word)`, never zero. See this
        // module's doc comment ("`hc` binds the whole executable program") for why a
        // one-sided `mult_word · (1 − valid) = 0` bound is not enough — a `VALID = 1` row left
        // free to supply zero copies could sit outside the digest entirely while still being
        // fetchable and executable.
        let mult = v(MULT);
        let mult_word = v(MULT_WORD);
        b.assert_zero(mult.clone() * (one - v(VALID)));
        b.assert_zero(mult_word.clone() - v(VALID));
        let msg: Vec<AB::Expr> = std::iter::once(v(PC)).chain((0..Decoded::NUM_FIELDS).map(|k| v(RD + k))).collect();
        bus::PROGRAM.table_entry(b, msg, mult);
        bus::PROGRAM_WORD.table_entry(b, [v(PC), v(WORD)], mult_word);
    }
}

/// A main-trace matrix at exactly `height` rows: `PC/WORD/`bits/decoded fields/`VALID` for
/// `0..program.len()`, `MULT`/`MULT_WORD` fetch-count bookkeeping, all-zero (hence `VALID =
/// 0`, see the module doc comment) padding for the rest. `height` is the caller's
/// responsibility — M3.4 (fix): a *proof-declared* value (`program_log_height`'s doc comment),
/// not a function of the tier, so this table's shape depends on the program's own length again
/// (unlike M3.4's first cut) while the verifier key it folds into stays keyed by that declared
/// log-height rather than the program itself (still program-independent — see
/// `Machine::verifier_key`).
///
/// Fills one row (`row.len() == col::WIDTH`) at `pc`/`word`: the bit decomposition (always),
/// and — only if `Instr::decode(word)` succeeds — the 23 `Decoded` fields, `VALID = 1`, and the
/// matching legality flag. An undecodable `word` leaves every field/flag at its `zero_vec`
/// default (`VALID = 0`), including `RD_IS_ZERO = 1` (the is-zero gadget's own unconditional
/// invariant — `RD` stays 0 there too, exactly the padding-row case `program_trace` below
/// handles the same way). Never panics, unlike `program_trace` (which uses this for every real
/// program row and then enforces its own "every real word decodes" invariant on top) — this is
/// what lets `tests/tables.rs::program_decoder_equals_instr_decode` compare the decoder's own
/// output against `Instr::decode` for arbitrary (including undecodable) words directly, without
/// going through `Program`'s host-side, panic-on-error API.
pub fn fill_word_row(row: &mut [F], pc: u32, word: u32) {
    row[PC] = F::from_u32(pc);
    row[WORD] = F::from_u32(word);
    for k in 0..32 { row[BIT0 + k] = F::from_bool((word >> k) & 1 == 1); }
    match Instr::decode(word) {
        Ok(instr) => {
            let d = instr.decoded();
            for (k, field) in d.to_fields().iter().enumerate() { row[RD + k] = F::from_u32(*field); }
            row[VALID] = F::ONE;
            if d.rd != 0 { row[RD_INV] = F::from_u32(d.rd).inverse(); } else { row[RD_IS_ZERO] = F::ONE; }
            set_flags(&mut row[FLAG0..FLAG0 + flags::COUNT], instr);
        }
        Err(_) => row[RD_IS_ZERO] = F::ONE,
    }
}

/// Panics if `program` contains a word `Instr::decode` rejects: exactly the old preprocessed
/// builder's own invariant (`ProgramAir::preprocessed_trace`'s `.expect(..)`), preserved here
/// — this table can only ever commit to a program every one of whose words is something the
/// emulator could actually execute.
pub fn program_trace(program: &Program, events: &[CycleEvent], height: usize) -> RowMajorMatrix<F> {
    assert!(program.len() <= height, "program table needs {} rows, height {height}", program.len());
    let mut counts: HashMap<u32, u64> = HashMap::new();
    // M3.2: a `POSEIDON2` row-group's absorb/write-back rows share their ecall row's `pc`
    // without being separate fetches (`tables::cpu`'s eval gates the PROGRAM lookup off on
    // them) — only count a genuine fetch: an ordinary row, or the ecall row itself. M3.4:
    // digest rows are not `CycleEvent`s at all (they precede the first one), so they never
    // appear in `events` and never touch this ordinary-fetch count.
    let fetches = |e: &CycleEvent| !matches!(e.hash_row, Some(HashRow::Absorb { .. }) | Some(HashRow::WriteOut { .. }));
    for e in events.iter().filter(|e| fetches(e)) { *counts.entry(e.pc).or_default() += 1; }

    let mut v = F::zero_vec(height * col::WIDTH);
    for i in 0..program.len() {
        let r = &mut v[i * col::WIDTH..(i + 1) * col::WIDTH];
        let pc = program.pc_of(i);
        let word = program.words[i];
        fill_word_row(r, pc, word);
        assert_eq!(r[VALID], F::ONE, "program contains an undecodable word");
        r[MULT] = F::from_u64(*counts.get(&pc).unwrap_or(&0));
        // Every proof includes exactly one traversal of the whole program for the digest,
        // regardless of how the program actually ran — so every real row's `PROGRAM_WORD`
        // fetch count is unconditionally 1.
        r[MULT_WORD] = F::ONE;
    }
    // Padding rows: `PC` still increments by 4 (the AIR's transition rule is unconditional),
    // and `RD_IS_ZERO` must still satisfy the is-zero gadget for `RD = 0` (that gadget is
    // unconditional too, not gated by `VALID` — it feeds `WRITES_RD`, which the padding-row
    // `WORD = 0` decode already forces to 0 via every flag being 0). Everything else stays at
    // the `zero_vec` default — `WORD = 0` decodes as no known opcode, so `VALID` comes out 0
    // with no special-casing needed.
    let last_pc = if program.is_empty() { program.base_pc.wrapping_sub(4) } else { program.pc_of(program.len() - 1) };
    for i in program.len()..height {
        v[i * col::WIDTH + PC] = F::from_u32(last_pc.wrapping_add(4 * (i - program.len() + 1) as u32));
        v[i * col::WIDTH + RD_IS_ZERO] = F::ONE;
    }
    RowMajorMatrix::new(v, col::WIDTH)
}

/// Sets exactly the one flag `Instr::decode` would have taken to reach `instr`, mirroring
/// `program_trace`'s use of `flags`'s layout. `instr` and `word` (via `Instr::decode`) always
/// agree by construction (the caller just decoded `word` into `instr`), so this only needs to
/// dispatch on `instr`'s own shape, not re-inspect the raw bits.
fn set_flags(row: &mut [F], instr: Instr) {
    use crate::isa::{Instr::*, Width};
    let set = |row: &mut [F], i: usize| row[i] = F::ONE;
    match instr {
        Lui { .. } => set(row, flags::LUI),
        Auipc { .. } => set(row, flags::AUIPC),
        Jal { .. } => set(row, flags::JAL),
        Jalr { .. } => set(row, flags::JALR),
        Branch { cond, .. } => set(row, match cond {
            BranchCond::Eq => flags::BR_EQ, BranchCond::Ne => flags::BR_NE, BranchCond::Lt => flags::BR_LT,
            BranchCond::Ge => flags::BR_GE, BranchCond::Ltu => flags::BR_LTU, BranchCond::Geu => flags::BR_GEU,
        }),
        Load { width, signed, .. } => set(row, match (width, signed) {
            (Width::Byte, true) => flags::LD_LB, (Width::Half, true) => flags::LD_LH, (Width::Word, _) => flags::LD_LW,
            (Width::Byte, false) => flags::LD_LBU, (Width::Half, false) => flags::LD_LHU,
        }),
        Store { width, .. } => set(row, match width { Width::Byte => flags::ST_SB, Width::Half => flags::ST_SH, Width::Word => flags::ST_SW }),
        AluImm { op, .. } => set(row, match op {
            AluOp::Add => flags::ALUI_ADD, AluOp::Sll => flags::ALUI_SLL, AluOp::Slt => flags::ALUI_SLT, AluOp::Sltu => flags::ALUI_SLTU,
            AluOp::Xor => flags::ALUI_XOR, AluOp::Srl => flags::ALUI_SRL, AluOp::Sra => flags::ALUI_SRA, AluOp::Or => flags::ALUI_OR, AluOp::And => flags::ALUI_AND,
            _ => unreachable!("no M-extension immediate form"),
        }),
        AluReg { op, .. } => set(row, match op {
            AluOp::Add => flags::ALU_ADD, AluOp::Sub => flags::ALU_SUB, AluOp::Sll => flags::ALU_SLL, AluOp::Slt => flags::ALU_SLT, AluOp::Sltu => flags::ALU_SLTU,
            AluOp::Xor => flags::ALU_XOR, AluOp::Srl => flags::ALU_SRL, AluOp::Sra => flags::ALU_SRA, AluOp::Or => flags::ALU_OR, AluOp::And => flags::ALU_AND,
            AluOp::Mul => flags::ALUM_MUL, AluOp::Mulh => flags::ALUM_MULH, AluOp::Mulhsu => flags::ALUM_MULHSU, AluOp::Mulhu => flags::ALUM_MULHU,
            AluOp::Div => flags::ALUM_DIV, AluOp::Divu => flags::ALUM_DIVU, AluOp::Rem => flags::ALUM_REM, AluOp::Remu => flags::ALUM_REMU,
            AluOp::Eq => unreachable!("EQ is not an encodable instruction"),
        }),
        Ecall => set(row, flags::ECALL),
    }
}
