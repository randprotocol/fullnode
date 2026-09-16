//! The rVM's cpu table (plan, "The tables and buses"): one row per executed instruction, the
//! fetch from `program` on the `PROGRAM` bus, decode by one-hot selectors, the base and
//! extension ALU, the `INV`/`EINV` hint-and-check, control flow, and the machine's bus sends.
//!
//! There is no register file in the row (plan R4): registers are cells `2^24 + idx` on the
//! register memory table, read and written through `REG` messages built from the 5-bit
//! range-checked index columns, and RAM stays below `2^24` on the `RAM` bus with 3-byte-limb
//! range checks — the only range checks in the machine. The reference semantics is
//! `emulator::execute` (the AGENTS.md rule: if this AIR and the emulator disagree, the AIR is
//! wrong); every row's operand values come straight from the emulator's `Event`.
use super::{bus, range::RangeCounts, F};
use crate::emulator::{Event, MemAccess};
use crate::isa::Op;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const CLK: usize = 0;
    pub const PC: usize = 1;
    pub const NEXT_PC: usize = 2;
    /// The four fetched words, consumed on `PROGRAM` as `[PC, OP, RD, RA, B]`.
    pub const OP: usize = 3;
    pub const RD: usize = 4;
    pub const RA: usize = 5;
    pub const B: usize = 6;
    /// 26: one-hot opcode selectors, in `Op as u8` order.
    pub const SEL0: usize = 7;
    /// The operand values: the `ra` pair, the `rb` pair (or `[imm, 0]`), the result pair.
    pub const A0: usize = 33;
    pub const A1: usize = 34;
    pub const B0: usize = 35;
    pub const B1: usize = 36;
    pub const D0: usize = 37;
    pub const D1: usize = 38;
    /// 5-bit decompositions of the three register indices — the `rd, ra, rb < 32` decode check
    /// the emulator performs, and what makes every `REG` address `2^24 + idx` with `idx < 32`.
    pub const RD_BIT0: usize = 39; // 5
    pub const RA_BIT0: usize = 44; // 5
    pub const RB_BIT0: usize = 49; // 5
    /// The 3 address limbs of the row kind's address subject (a `RANGE8` lookup each).
    pub const LIMB0: usize = 54;
    pub const LIMB1: usize = 55;
    pub const LIMB2: usize = 56;
    /// The `r0` write-drop gadget (the `alu.rs` two-constraint pattern).
    pub const RD_IS_ZERO: usize = 57;
    pub const RD_INV: usize = 58;
    /// The branch equality gadget on `D0 − A0`.
    pub const EQ_AUX: usize = 59;
    pub const EQ_INV: usize = 60;
    /// The running count of `PUBLIC` rows.
    pub const PUB_IDX: usize = 61;
    pub const IS_REAL: usize = 62;
    /// Task 9: the `SPONGE` source pointer's own three limbs (`B0 + 3 < 2^24`, gated on
    /// `IS_SPONGE` — the one row kind with two addresses).
    pub const G2LIMB0: usize = 63;
    pub const G2LIMB1: usize = 64;
    pub const G2LIMB2: usize = 65;
    pub const WIDTH: usize = 66;
}
use col::*;

pub const NUM_SELECTORS: usize = 26;

/// Timestamp slots of the row's `REG` messages (the `RAM` messages use the emulator's own slots:
/// 0..1 for the cpu's loads/stores, 0..15 for a dispatched permutation — see `emulator.rs`).
const TS_RA: u32 = 0;
const TS_RA1: u32 = 1;
const TS_RB: u32 = 2;
const TS_RB1: u32 = 3;
const TS_RD_READ: u32 = 4;
const TS_RD_WRITE: u32 = 8;
const TS_RD1_WRITE: u32 = 9;

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuAir;

impl<Fld: Field> BaseAir<Fld> for CpuAir {
    fn width(&self) -> usize { col::WIDTH }
}

/// Selector sets, as sums of one-hot columns. Centralised here so the AIR's gating and the
/// trace builder's accounting read from one table — the per-opcode access pattern is exactly
/// `emulator::execute`'s `match`.
struct Sels;
impl Sels {
    /// Read the `ra` pair.
    const EXT_READ_RA: &'static [Op] = &[Op::Eadd, Op::Esub, Op::Emul, Op::Emulf, Op::Einv];
    /// Read the `rb` pair.
    const EXT_READ_RB: &'static [Op] = &[Op::Eadd, Op::Esub, Op::Emul];
    /// Ops whose fourth word names a register (`rb`), mirroring `Op::b_is_register`.
    const B_REG: &'static [Op] = &[Op::Fadd, Op::Fsub, Op::Fmul, Op::Eadd, Op::Esub, Op::Emul, Op::Emulf, Op::Sponge];
    /// Read `rd` (the compared or stored value).
    const READ_RD: &'static [Op] = &[Op::Jeq, Op::Jne, Op::Store, Op::Storee];
    /// Write `rd`.
    const WRITE_RD: &'static [Op] = &[
        Op::Fadd, Op::Fsub, Op::Fmul, Op::Faddi, Op::Fmuli, Op::Eadd, Op::Esub, Op::Emul,
        Op::Emulf, Op::Inv, Op::Einv, Op::Mov, Op::Load, Op::Loade, Op::Hint, Op::Hinte,
    ];
    /// Write the `rd` pair.
    const EXT_WRITE_RD: &'static [Op] =
        &[Op::Eadd, Op::Esub, Op::Emul, Op::Emulf, Op::Einv, Op::Loade, Op::Hinte];
    /// Rows whose address subject is `A0 + B` (one RAM cell).
    const MEM1: &'static [Op] = &[Op::Load, Op::Store];
    /// Rows whose address subject is `A0 + B + 1` (two RAM cells).
    const MEM2: &'static [Op] = &[Op::Loade, Op::Storee];
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for CpuAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let sixteen = AB::Expr::from_u32(16);
        let reg_base = AB::Expr::from_u64(1 << 24);

        let is_real = v(IS_REAL);
        b.assert_bool(is_real.clone());

        // ── boundary and the row chain ──
        {
            let mut f = b.when_first_row();
            f.assert_one(is_real.clone());
            f.assert_zero(v(CLK));
            f.assert_zero(v(PC));
            f.assert_zero(v(PUB_IDX));
        }
        b.when_last_row().assert_zero(is_real.clone());
        {
            let mut t = b.when_transition();
            t.assert_zero((one.clone() - is_real.clone()) * n(IS_REAL));
            t.assert_zero(n(IS_REAL) * (n(CLK) - v(CLK) - one.clone()));
            t.assert_zero(n(IS_REAL) * (n(PC) - v(NEXT_PC)));
            // The last real row is a HALT, and nothing runs after a HALT.
            t.assert_zero(is_real.clone() * (one.clone() - n(IS_REAL)) * (one.clone() - v(SEL0 + Op::Halt as usize)));
            t.assert_zero(n(IS_REAL) * (n(PUB_IDX) - v(PUB_IDX) - v(SEL0 + Op::Public as usize)));
        }

        // ── fetch and decode ──
        let sel = |op: Op| v(SEL0 + op as usize);
        let sel_sum = |set: &[Op]| -> AB::Expr { set.iter().map(|op| sel(*op)).sum() };
        for k in 0..NUM_SELECTORS {
            b.assert_bool(v(SEL0 + k));
        }
        {
            let sum: AB::Expr = (0..NUM_SELECTORS).map(|k| v(SEL0 + k)).sum();
            b.assert_eq(sum, is_real.clone());
            let op_from_sels: AB::Expr = (0..NUM_SELECTORS).map(|k| v(SEL0 + k) * AB::Expr::from_u32(k as u32)).sum();
            b.assert_zero(v(OP) - op_from_sels);
        }
        // The fetch itself: one per real row, consumed from the program table (AGENTS.md
        // invariant 2 — padding fetches nothing). Provider calls are `table_entry`; consumer
        // calls are `lookup_key`, exactly as `RANGE8` above.
        bus::PROGRAM.lookup_key(b, [v(PC), v(OP), v(RD), v(RA), v(B)], Count::bounded(is_real.clone(), 1));

        // ── register index range checks: rd, ra, rb < 32, in 5 boolean bits ──
        for k in 0..5 {
            b.assert_bool(v(RD_BIT0 + k));
            b.assert_bool(v(RA_BIT0 + k));
            b.assert_bool(v(RB_BIT0 + k));
        }
        let from_bits = |base: usize| -> AB::Expr {
            (0..5).map(|k| v(base + k) * AB::Expr::from_u32(1 << k)).sum()
        };
        let is_b_reg = sel_sum(Sels::B_REG);
        b.assert_zero(v(RD) - from_bits(RD_BIT0));
        b.assert_zero(v(RA) - from_bits(RA_BIT0));
        b.assert_zero(is_b_reg.clone() * (v(B) - from_bits(RB_BIT0)));

        // ── the immediate form: B0/B1 is [B, 0] unless the fourth word names a register ──
        b.assert_zero((one.clone() - is_b_reg.clone()) * (v(B0) - v(B)));
        b.assert_zero((one.clone() - is_b_reg.clone()) * v(B1));
        // Base register ops leave the second `rb` lane zero.
        b.assert_zero((sel(Op::Fadd) + sel(Op::Fsub) + sel(Op::Fmul) + sel(Op::Emulf)) * v(B1));

        // ── the ALU, mirroring `emulator::execute` case by case ──
        let seven = AB::Expr::from_u64(7);
        b.assert_zero(sel(Op::Fadd) * (v(D0) - v(A0) - v(B0)));
        b.assert_zero(sel(Op::Fsub) * (v(D0) - v(A0) + v(B0)));
        b.assert_zero(sel(Op::Fmul) * (v(D0) - v(A0) * v(B0)));
        b.assert_zero(sel(Op::Faddi) * (v(D0) - v(A0) - v(B)));
        b.assert_zero(sel(Op::Fmuli) * (v(D0) - v(A0) * v(B)));
        b.assert_zero(sel(Op::Eadd) * (v(D0) - v(A0) - v(B0)));
        b.assert_zero(sel(Op::Eadd) * (v(D1) - v(A1) - v(B1)));
        b.assert_zero(sel(Op::Esub) * (v(D0) - v(A0) + v(B0)));
        b.assert_zero(sel(Op::Esub) * (v(D1) - v(A1) + v(B1)));
        // X² = 7 in the degree-2 binomial extension.
        b.assert_zero(sel(Op::Emul) * (v(D0) - v(A0) * v(B0) - seven.clone() * v(A1) * v(B1)));
        b.assert_zero(sel(Op::Emul) * (v(D1) - v(A0) * v(B1) - v(A1) * v(B0)));
        b.assert_zero(sel(Op::Emulf) * (v(D0) - v(A0) * v(B0)));
        b.assert_zero(sel(Op::Emulf) * (v(D1) - v(A1) * v(B0)));
        // The hint-and-check inverses: unsatisfiable at zero, which is what makes the DSL's
        // assertion traps unprovable at the machine level too.
        b.assert_zero(sel(Op::Inv) * (v(A0) * v(D0) - one.clone()));
        b.assert_zero(sel(Op::Einv) * (v(A0) * v(D0) + seven * v(A1) * v(D1) - one.clone()));
        b.assert_zero(sel(Op::Einv) * (v(A0) * v(D1) + v(A1) * v(D0)));
        b.assert_zero(sel(Op::Mov) * (v(D0) - v(A0)));

        // ── the r0 write-drop gadget (unconditional; RD is always in 0..31 by the bits) ──
        b.assert_bool(v(RD_IS_ZERO));
        b.assert_zero(v(RD) * v(RD_INV) - (one.clone() - v(RD_IS_ZERO)));
        b.assert_zero(v(RD_IS_ZERO) * v(RD));

        // ── control: the equality gadget and NEXT_PC ──
        b.assert_bool(v(EQ_AUX));
        b.assert_zero((v(D0) - v(A0)) * v(EQ_INV) - (one.clone() - v(EQ_AUX)));
        b.assert_zero(v(EQ_AUX) * (v(D0) - v(A0)));
        let taken = sel(Op::Jmp) + sel(Op::Jeq) * v(EQ_AUX) + sel(Op::Jne) * (one.clone() - v(EQ_AUX));
        // Gated on real rows: padding computes no next pc.
        b.assert_zero(
            is_real.clone()
                * (v(NEXT_PC)
                    - sel(Op::Halt) * v(PC)
                    - (one.clone() - sel(Op::Halt)) * (taken.clone() * v(B) + (one.clone() - taken.clone()) * (v(PC) + one.clone()))),
        );

        // ── the address range check: the row kind's subject, in three bytes ──
        let is_mem = sel_sum(Sels::MEM1) + sel_sum(Sels::MEM2);
        let subject = sel_sum(Sels::MEM1) * (v(A0) + v(B))
            + sel_sum(Sels::MEM2) * (v(A0) + v(B) + one.clone())
            + (sel(Op::Poseidon2) + sel(Op::Sponge)) * (v(A0) + AB::Expr::from_u32(7))
            + taken.clone() * v(B);
        let needs_check = is_mem.clone() + sel(Op::Poseidon2) + sel(Op::Sponge) + taken.clone();
        let limbs = v(LIMB0) + v(LIMB1) * AB::Expr::from_u32(1 << 8) + v(LIMB2) * AB::Expr::from_u32(1 << 16);
        b.assert_zero(needs_check.clone() * (subject - limbs));
        for l in [LIMB0, LIMB1, LIMB2] {
            bus::RANGE8.lookup_key(b, [v(l)], Count::bounded(needs_check.clone(), 1));
        }
        // Group 2 (Task 9): the `SPONGE` source pointer's own check, `B0 + 3 < 2^24`.
        let subject2 = sel(Op::Sponge) * (v(B0) + AB::Expr::from_u32(3));
        let limbs2 = v(G2LIMB0) + v(G2LIMB1) * AB::Expr::from_u32(1 << 8) + v(G2LIMB2) * AB::Expr::from_u32(1 << 16);
        b.assert_zero(sel(Op::Sponge) * (subject2 - limbs2));
        for l in [G2LIMB0, G2LIMB1, G2LIMB2] {
            bus::RANGE8.lookup_key(b, [v(l)], Count::bounded(sel(Op::Sponge), 1));
        }

        // ── register traffic (REG) and RAM traffic (RAM) ──
        let ts = |slot: u32| sixteen.clone() * v(CLK) + AB::Expr::from_u32(slot);
        // `IS_REAL` minus the no-`ra` opcodes: 1 on a real row that reads `ra`, 0 on the four
        // that do not — and 0 on padding, where the selector sum is 0 (AGENTS.md invariant 2).
        let uses_ra = is_real.clone() - (sel(Op::Jmp) + sel(Op::Hint) + sel(Op::Hinte) + sel(Op::Halt));
        let ext_read_ra = sel_sum(Sels::EXT_READ_RA);
        let ext_read_rb = sel_sum(Sels::EXT_READ_RB);
        let reads_rd = sel_sum(Sels::READ_RD);
        let writes_rd = sel_sum(Sels::WRITE_RD) * (one.clone() - v(RD_IS_ZERO));
        let ext_writes_rd = sel_sum(Sels::EXT_WRITE_RD);
        // AGENTS.md invariant 1: every message's address and value columns are the constrained
        // operand and index columns above, on every row kind that sends; invariant 2: every count
        // is a selector sum, zero on rows that do not perform the access.
        let count = |e: AB::Expr| Count::bounded(e, 1);
        bus::REG.send(b, [reg_base.clone() + v(RA), ts(TS_RA), v(A0), AB::Expr::ZERO], count(uses_ra));
        bus::REG.send(b, [reg_base.clone() + v(RA) + one.clone(), ts(TS_RA1), v(A1), AB::Expr::ZERO], count(ext_read_ra));
        bus::REG.send(b, [reg_base.clone() + from_bits(RB_BIT0), ts(TS_RB), v(B0), AB::Expr::ZERO], count(is_b_reg.clone()));
        bus::REG.send(b, [reg_base.clone() + from_bits(RB_BIT0) + one.clone(), ts(TS_RB1), v(B1), AB::Expr::ZERO], count(ext_read_rb));
        bus::REG.send(b, [reg_base.clone() + v(RD), ts(TS_RD_READ), v(D0), AB::Expr::ZERO], count(reads_rd));
        bus::REG.send(b, [reg_base.clone() + v(RD), ts(TS_RD_WRITE), v(D0), one.clone()], count(writes_rd));
        bus::REG.send(b, [reg_base.clone() + v(RD) + one.clone(), ts(TS_RD1_WRITE), v(D1), one.clone()], count(ext_writes_rd));

        bus::RAM.send(b, [v(A0) + v(B), ts(0), v(D0), AB::Expr::ZERO], count(sel(Op::Load)));
        bus::RAM.send(b, [v(A0) + v(B), ts(0), v(D0), one.clone()], count(sel(Op::Store)));
        bus::RAM.send(b, [v(A0) + v(B), ts(0), v(D0), AB::Expr::ZERO], count(sel(Op::Loade)));
        bus::RAM.send(b, [v(A0) + v(B) + one.clone(), ts(1), v(D1), AB::Expr::ZERO], count(sel(Op::Loade)));
        bus::RAM.send(b, [v(A0) + v(B), ts(0), v(D0), one.clone()], count(sel(Op::Storee)));
        bus::RAM.send(b, [v(A0) + v(B) + one.clone(), ts(1), v(D1), one.clone()], count(sel(Op::Storee)));

        // ── the dispatched chips and the public interface ──
        bus::POSEIDON2.lookup_key(b, [v(CLK), v(A0)], Count::bounded(sel(Op::Poseidon2), 1));
        bus::SPONGE.lookup_key(b, [v(CLK), v(A0), v(B0)], Count::bounded(sel(Op::Sponge), 1));
        bus::REDUCE.lookup_key(b, [v(CLK), v(A0)], Count::bounded(sel(Op::Reduce), 1));
        bus::PUBLIC.lookup_key(b, [v(PUB_IDX), v(A0)], Count::bounded(sel(Op::Public), 1));
    }
}

/// The register-file traffic one execution makes, synthesized from the events — the emulator
/// keeps registers in a local array, so the `REG` table's accesses are derived here from the
/// same slot map the AIR uses (the two are the same statement of the access pattern; the bus
/// balance is what proves they agree).
pub fn register_accesses(events: &[Event]) -> Vec<MemAccess> {
    let mut out = Vec::new();
    let base = super::memory::REGISTER_BASE;
    let mut push = |clk: u32, slot: u32, idx: u64, value: F, is_write: bool| {
        out.push(MemAccess { addr: base + idx, ts: clk * 16 + slot, value, is_write });
    };
    for e in events {
        let (clk, op) = (e.clk, e.instr.op);
        let (rd, ra) = (e.instr.rd as u64, e.instr.ra as u64);
        let uses_ra = !matches!(op, Op::Jmp | Op::Hint | Op::Hinte | Op::Halt);
        if uses_ra {
            push(clk, TS_RA, ra, e.a[0], false);
        }
        if Sels::EXT_READ_RA.contains(&op) {
            push(clk, TS_RA1, ra + 1, e.a[1], false);
        }
        if Sels::B_REG.contains(&op) {
            let rb = e.instr.rb() as u64;
            push(clk, TS_RB, rb, e.b_val[0], false);
            if Sels::EXT_READ_RB.contains(&op) {
                push(clk, TS_RB1, rb + 1, e.b_val[1], false);
            }
        }
        if Sels::READ_RD.contains(&op) {
            push(clk, TS_RD_READ, rd, e.d[0], false);
        }
        if Sels::WRITE_RD.contains(&op) && rd != 0 {
            push(clk, TS_RD_WRITE, rd, e.d[0], true);
        }
        if Sels::EXT_WRITE_RD.contains(&op) {
            push(clk, TS_RD1_WRITE, rd + 1, e.d[1], true);
        }
    }
    out
}

/// One row per event, padding to the tier's height with the gadget columns set (the
/// unconditional gadgets — `RD_IS_ZERO` on `RD = 0`, the equality gadget on `D0 − A0 = 0` —
/// must hold on padding rows too, the `program.rs` padding lesson).
pub fn cpu_trace(events: &[Event], height: usize, counts: &mut RangeCounts) -> RowMajorMatrix<F> {
    assert!(events.len() < height, "cpu table needs a padding row: {} rows, height {height}", events.len());
    let mut v = F::zero_vec(height * col::WIDTH);
    let mut pub_idx = 0u32;
    for (i, e) in events.iter().enumerate() {
        let r = &mut v[i * col::WIDTH..(i + 1) * col::WIDTH];
        fill_row(r, e, &mut pub_idx, counts);
    }
    for i in events.len()..height {
        let r = &mut v[i * col::WIDTH..(i + 1) * col::WIDTH];
        r[RD_IS_ZERO] = F::ONE;
        r[EQ_AUX] = F::ONE;
        r[PUB_IDX] = F::from_u64(pub_idx as u64);
    }
    RowMajorMatrix::new(v, col::WIDTH)
}

fn fill_row(r: &mut [F], e: &Event, pub_idx: &mut u32, counts: &mut RangeCounts) {
    r[IS_REAL] = F::ONE;
    r[CLK] = F::from_u64(e.clk as u64);
    r[PC] = F::from_u64(e.pc as u64);
    r[NEXT_PC] = F::from_u64(e.next_pc as u64);
    let w = e.instr.encode();
    r[OP] = w[0];
    r[RD] = w[1];
    r[RA] = w[2];
    r[B] = w[3];
    r[SEL0 + e.instr.op as usize] = F::ONE;
    r[A0] = e.a[0];
    r[A1] = e.a[1];
    r[B0] = e.b_val[0];
    r[B1] = e.b_val[1];
    r[D0] = e.d[0];
    r[D1] = e.d[1];
    let bits = |x: u8, base: usize, r: &mut [F]| {
        for k in 0..5 {
            r[base + k] = F::from_bool((x >> k) & 1 == 1);
        }
    };
    bits(e.instr.rd, RD_BIT0, r);
    bits(e.instr.ra, RA_BIT0, r);
    if e.instr.op.b_is_register() {
        bits(e.instr.rb(), RB_BIT0, r);
    }
    if e.instr.rd == 0 {
        r[RD_IS_ZERO] = F::ONE;
    } else {
        r[RD_INV] = F::from_u64(e.instr.rd as u64).inverse();
    }
    // The equality gadget, and the address limbs for the row kind's subject — both computed
    // exactly as the AIR recomputes them (research's audit-ZM2 lesson).
    let diff = e.d[0] - e.a[0];
    if diff == F::ZERO {
        r[EQ_AUX] = F::ONE;
    } else {
        r[EQ_INV] = diff.inverse();
    }
    let taken = match e.instr.op {
        Op::Jmp => true,
        Op::Jeq => diff == F::ZERO,
        Op::Jne => diff != F::ZERO,
        _ => false,
    };
    let subject: Option<u64> = match e.instr.op {
        Op::Load | Op::Store => Some(e.mem[0].addr),
        Op::Loade | Op::Storee => Some(e.mem[0].addr + 1),
        Op::Poseidon2 | Op::Sponge => Some(e.a[0].as_canonical_u64() + 7),
        Op::Jmp | Op::Jeq | Op::Jne if taken => Some(e.instr.b.as_canonical_u64()),
        _ => None,
    };
    if let Some(s) = subject {
        assert!(s < 1 << 24, "the emulator bounds every address below 2^24");
        for (k, c) in [LIMB0, LIMB1, LIMB2].iter().enumerate() {
            let limb = (s >> (8 * k)) as u32 & 0xff;
            r[*c] = F::from_u32(limb);
            counts.range8(limb);
        }
    }
    if e.instr.op == Op::Sponge {
        // The source pointer is the `rb` register's value (`e.b_val[0]`); `+ 3` is its far end.
        let s = e.b_val[0].as_canonical_u64() + 3;
        assert!(s < 1 << 24, "the emulator bounds the sponge source below 2^24");
        for (k, c) in [G2LIMB0, G2LIMB1, G2LIMB2].iter().enumerate() {
            let limb = (s >> (8 * k)) as u32 & 0xff;
            r[*c] = F::from_u32(limb);
            counts.range8(limb);
        }
    }
    r[PUB_IDX] = F::from_u64(*pub_idx as u64);
    if e.instr.op == Op::Public {
        *pub_idx += 1;
    }
}

/// Re-export for `build_traces`: the event log's RAM-class accesses (every emulator-logged
/// access is below `2^24` by construction).
pub fn ram_accesses(events: &[Event]) -> Vec<MemAccess> {
    events.iter().flat_map(|e| e.mem.iter().copied()).collect()
}

/// The `(clk, event)` pairs the poseidon2 chip's trace is built from.
pub fn perm_events(events: &[Event]) -> Vec<(u32, crate::emulator::PermEvent)> {
    events.iter().filter_map(|e| e.perm.map(|p| (e.clk, p))).collect()
}
