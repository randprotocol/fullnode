//! One row per cycle. Fetches from PROGRAM, reads and writes through MEMORY,
//! delegates arithmetic to ALU. The only table with public values.
use super::{bus, byte::ByteCounts, limbs, program::MESSAGE_LEN, F};
use crate::emulator::{CycleEvent, Syscall, ECALL_MEM_REG, SLOT_MEM, SLOT_R1, SLOT_R2, SLOT_W};
use crate::isa::{NUM_OUTPUTS, SYS_HALT as SYS_NUM_HALT, SYS_READ_INPUT, SYS_WRITE_OUTPUT};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const CLK: usize = 0; pub const PC: usize = 1; pub const NEXT_PC: usize = 2; pub const IS_REAL: usize = 3;
    pub const DEC0: usize = 4;
    pub const RD: usize = 4; pub const RS1: usize = 5; pub const RS2: usize = 6; pub const IMM: usize = 7;
    pub const IS_ALU: usize = 8; pub const ALU_OP: usize = 9; pub const IS_IMM: usize = 10; pub const IS_BRANCH: usize = 11;
    pub const BR_OP: usize = 12; pub const BR_NEG: usize = 13; pub const IS_LOAD: usize = 14; pub const IS_STORE: usize = 15;
    pub const IS_JAL: usize = 16; pub const IS_JALR: usize = 17; pub const IS_LUI: usize = 18; pub const IS_AUIPC: usize = 19;
    pub const IS_ECALL: usize = 20; pub const WRITES_RD: usize = 21;
    pub const A: usize = 22; pub const B: usize = 23; pub const C: usize = 24; pub const ALU_OUT: usize = 25; pub const TGT: usize = 26;
    pub const MEM_ADDR: usize = 27; pub const MEM_VAL: usize = 28;
    pub const SYS_HALT: usize = 29; pub const SYS_WRITE: usize = 30; pub const SYS_READ: usize = 31;
    pub const OUT_SEL0: usize = 32;
    /// `WRITTEN_i` is the running count of `OUT_SEL_i` over rows `0..=this one`. It is
    /// boolean on every row, so a slot can be written at most once (the emulator's
    /// `DoubleWrite` rule), and because `OUT_SEL_i` is zero on padding rows the value
    /// survives to the last row, where it says whether slot `i` was ever written.
    pub const WRITTEN0: usize = OUT_SEL0 + crate::isa::NUM_OUTPUTS;  // 40
    /// The four byte limbs of `MEM_ADDR` on load/store rows: what makes word alignment a
    /// stated constraint rather than a side effect of the memory table's key ordering.
    pub const MA0: usize = WRITTEN0 + crate::isa::NUM_OUTPUTS;       // 48
    pub const WIDTH: usize = MA0 + 4;                                // 52
    /// Columns that must be zero on padding rows.
    pub const SELECTORS: [usize; 15] = [IS_ALU, IS_IMM, IS_BRANCH, IS_LOAD, IS_STORE, IS_JAL, IS_JALR, IS_LUI, IS_AUIPC, IS_ECALL, WRITES_RD, SYS_HALT, SYS_WRITE, SYS_READ, BR_NEG];
}
pub mod pv { pub const PC_ENTRY: usize = 0; pub const TIER: usize = 1; pub const OUT0: usize = 2; pub const NUM: usize = 2 + crate::isa::NUM_OUTPUTS; }
use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuAir;

impl<Fld> BaseAir<Fld> for CpuAir {
    fn width(&self) -> usize { WIDTH }
    fn num_public_values(&self) -> usize { pv::NUM }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for CpuAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let pvs: Vec<AB::Expr> = b.public_values().iter().map(|p| (*p).into()).collect();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let four = AB::Expr::from_u32(4);
        let is_real = v(IS_REAL);

        b.assert_bool(is_real.clone());
        for s in SELECTORS { b.assert_bool(v(s)); b.assert_zero((one.clone() - is_real.clone()) * v(s)); }
        {
            let mut f = b.when_first_row();
            f.assert_one(v(IS_REAL));
            f.assert_zero(v(CLK));
            f.assert_eq(v(PC), pvs[pv::PC_ENTRY].clone());
        }
        b.when_last_row().assert_zero(v(IS_REAL));
        {
            let mut t = b.when_transition();
            t.assert_zero((one.clone() - is_real.clone()) * n(IS_REAL));
            t.assert_zero(n(IS_REAL) * (n(CLK) - v(CLK) - one.clone()));
            t.assert_zero(n(IS_REAL) * (n(PC) - v(NEXT_PC)));
            // the last real row is a HALT, and nothing runs after a HALT
            t.assert_zero(is_real.clone() * (one.clone() - n(IS_REAL)) * (one.clone() - v(SYS_HALT)));
            t.assert_zero(v(SYS_HALT) * n(IS_REAL));
        }

        // fetch
        let msg: Vec<AB::Expr> = std::iter::once(v(PC)).chain((0..MESSAGE_LEN - 1).map(|k| v(DEC0 + k))).collect();
        bus::PROGRAM.lookup_key(b, msg, Count::bounded(is_real.clone(), 1));

        // operand select and ALU delegation
        let b_eff = v(IS_IMM) * v(IMM) + (one.clone() - v(IS_IMM)) * v(B);
        let op1 = v(IS_ALU) * v(ALU_OP) + v(IS_BRANCH) * v(BR_OP);
        let uses_slot1 = v(IS_ALU) + v(IS_BRANCH) + v(IS_LOAD) + v(IS_STORE) + v(IS_JALR);
        bus::ALU.lookup_key(b, [op1, v(A), b_eff, v(ALU_OUT)], Count::bounded(uses_slot1, 1));
        let uses_slot2 = v(IS_BRANCH) + v(IS_JAL) + v(IS_AUIPC);
        bus::ALU.lookup_key(b, [AB::Expr::ZERO, v(PC), v(IMM), v(TGT)], Count::bounded(uses_slot2, 1));

        // rd value
        b.assert_zero(v(IS_ALU) * (v(C) - v(ALU_OUT)));
        b.assert_zero(v(IS_LOAD) * (v(C) - v(MEM_VAL)));
        b.assert_zero((v(IS_JAL) + v(IS_JALR)) * (v(C) - v(PC) - four.clone()));
        b.assert_zero(v(IS_LUI) * (v(C) - v(IMM)));
        b.assert_zero(v(IS_AUIPC) * (v(C) - v(TGT)));
        // On every other kind of row (branch, store, ecall HALT/WRITE_OUTPUT) nothing above
        // defines C, and it is never sent on the WRITES_RD/SYS_READ register-write message
        // either, so without this constraint C is a completely free column there: a malicious
        // witness could set it to anything with no other constraint noticing. `cpu_trace`
        // always leaves it at the emulator's own `c = 0` default for these rows (see
        // `emulator::execute`), so this cannot reject any honest trace. Pin it to that same
        // zero sentinel.
        let defines_c = v(IS_ALU) + v(IS_LOAD) + v(IS_JAL) + v(IS_JALR) + v(IS_LUI) + v(IS_AUIPC) + v(SYS_READ);
        b.assert_zero((one.clone() - defines_c) * v(C));

        // next pc
        let taken = v(ALU_OUT) + v(BR_NEG) - v(ALU_OUT) * v(BR_NEG) * AB::Expr::TWO;
        let fallthrough = v(PC) + four.clone();
        b.assert_zero(v(IS_BRANCH) * (v(NEXT_PC) - fallthrough.clone() - taken * (v(TGT) - fallthrough.clone())));
        b.assert_zero(v(IS_JAL) * (v(NEXT_PC) - v(TGT)));
        b.assert_zero(v(IS_JALR) * (v(NEXT_PC) - v(ALU_OUT)));
        b.assert_zero(is_real.clone() * (one.clone() - v(IS_BRANCH) - v(IS_JAL) - v(IS_JALR)) * (v(NEXT_PC) - fallthrough));

        // memory
        let is_mem = v(IS_LOAD) + v(IS_STORE);
        b.assert_zero(is_mem.clone() * (v(MEM_ADDR) * four.clone() - v(ALU_OUT)));
        // Alignment, stated. `MEM_ADDR·4 = ALU_OUT` alone is a field identity: a misaligned
        // `ALU_OUT` just yields `MEM_ADDR = ALU_OUT·4⁻¹ mod p`, and until now that was
        // defeated only by accident — such a key cannot be ordered in the memory table. The
        // four byte limbs plus the `AND8` check of the top limb against `0xC0` bound
        // `MEM_ADDR` to `[0, 2^30)`. With `ALU_OUT` already 32-bit (the ALU table's own limb
        // range checks) the product `MEM_ADDR·4 < 2^32` cannot wrap, so the identity holds
        // over the integers and `ALU_OUT` really is a multiple of 4.
        let mut ma = AB::Expr::ZERO;
        for i in 0..4 { ma += v(MA0 + i) * AB::Expr::from_u32(1 << (8 * i)); }
        b.assert_zero(is_mem.clone() * (v(MEM_ADDR) - ma));
        for i in 0..4 { bus::RANGE8.lookup_key(b, [v(MA0 + i)], Count::bounded(is_mem.clone(), 1)); }
        bus::AND8.lookup_key(b, [v(MA0 + 3), AB::Expr::from_u32(0xC0), AB::Expr::ZERO], Count::bounded(is_mem.clone(), 1));
        b.assert_zero(v(IS_ECALL) * (v(MEM_ADDR) - AB::Expr::from_u32(ECALL_MEM_REG)));
        let ts = |slot: u32| v(CLK) * four.clone() + AB::Expr::from_u32(slot);
        let zero = AB::Expr::ZERO;
        bus::MEMORY.send(b, [zero.clone(), v(RS1), ts(SLOT_R1), v(A), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::MEMORY.send(b, [zero.clone(), v(RS2), ts(SLOT_R2), v(B), zero.clone()], Count::bounded(is_real.clone(), 1));
        bus::MEMORY.send(b, [is_mem.clone(), v(MEM_ADDR), ts(SLOT_MEM), v(MEM_VAL), v(IS_STORE)], Count::bounded(is_mem + v(IS_ECALL), 1));
        bus::MEMORY.send(b, [zero.clone(), v(RD), ts(SLOT_W), v(C), one.clone()], Count::bounded(v(WRITES_RD) + v(SYS_READ), 1));

        // syscalls: a = number, b = arg0, mem_val = arg1
        let sys_sum = v(SYS_HALT) + v(SYS_WRITE) + v(SYS_READ);
        b.assert_zero(v(IS_ECALL) * (sys_sum.clone() - one.clone()));
        b.assert_zero((one.clone() - v(IS_ECALL)) * sys_sum);
        b.assert_zero(v(SYS_HALT) * (v(A) - AB::Expr::from_u32(SYS_NUM_HALT)));
        b.assert_zero(v(SYS_WRITE) * (v(A) - AB::Expr::from_u32(SYS_WRITE_OUTPUT)));
        b.assert_zero(v(SYS_READ) * (v(A) - AB::Expr::from_u32(SYS_READ_INPUT)));
        let mut sel_sum = AB::Expr::ZERO;
        for i in 0..NUM_OUTPUTS {
            let s = v(OUT_SEL0 + i);
            b.assert_bool(s.clone());
            b.assert_zero(s.clone() * (v(B) - AB::Expr::from_u32(i as u32)));
            b.assert_zero(s.clone() * (v(MEM_VAL) - pvs[pv::OUT0 + i].clone()));
            sel_sum += s;
        }
        b.assert_eq(sel_sum, v(SYS_WRITE));
        // Spec §3.4: an output slot no `WRITE_OUTPUT` ever selected is zero. Only the slots
        // a `WRITE_OUTPUT` row selects are pinned above, so without this a never-written
        // slot's `pv[OUT0 + i]` is a free public value. `WRITTEN_i` accumulates `OUT_SEL_i`;
        // asserting it boolean on every row also caps each slot at one write. `OUT_SEL_i` is
        // zero on every padding row (its sum is `SYS_WRITE`, a `SELECTORS` entry), so the
        // accumulator holds its final value through the padding to the last row.
        for i in 0..NUM_OUTPUTS {
            b.assert_bool(v(WRITTEN0 + i));
            b.when_first_row().assert_eq(v(WRITTEN0 + i), v(OUT_SEL0 + i));
            b.when_transition().assert_eq(n(WRITTEN0 + i), v(WRITTEN0 + i) + n(OUT_SEL0 + i));
            b.when_last_row().assert_zero((one.clone() - v(WRITTEN0 + i)) * pvs[pv::OUT0 + i].clone());
        }
    }
}

pub fn public_values(pc_entry: u32, tier_log2: usize, outputs: &[u32; NUM_OUTPUTS]) -> Vec<F> {
    let mut v = vec![F::from_u32(pc_entry), F::from_u64(tier_log2 as u64)];
    v.extend(outputs.iter().map(|o| F::from_u32(*o)));
    v
}

/// `counts` receives the `RANGE8`/`AND8` lookups the alignment limbs declare, in lock-step
/// with the interactions the AIR above evaluates.
pub fn cpu_trace(events: &[CycleEvent], height: usize, counts: &mut ByteCounts) -> RowMajorMatrix<F> {
    assert!(events.len() < height, "cpu table needs a padding row: {} cycles, height {height}", events.len());
    let mut v = F::zero_vec(height * WIDTH);
    let mut written = [0u32; NUM_OUTPUTS];
    for (i, e) in events.iter().enumerate() {
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        r[CLK] = F::from_u32(e.clk); r[PC] = F::from_u32(e.pc); r[NEXT_PC] = F::from_u32(e.next_pc); r[IS_REAL] = F::ONE;
        for (k, f) in e.dec.to_fields().iter().enumerate() { r[DEC0 + k] = F::from_u32(*f); }
        r[A] = F::from_u32(e.a); r[B] = F::from_u32(e.b); r[C] = F::from_u32(e.c);
        r[ALU_OUT] = F::from_u32(e.alu_out); r[TGT] = F::from_u32(e.tgt);
        r[MEM_ADDR] = F::from_u32(e.mem_addr); r[MEM_VAL] = F::from_u32(e.mem_val);
        if e.dec.is_load == 1 || e.dec.is_store == 1 {
            let ml = limbs(e.mem_addr);
            for k in 0..4 { r[MA0 + k] = ml[k]; counts.range8((e.mem_addr >> (8 * k)) & 0xff); }
            counts.and8((e.mem_addr >> 24) & 0xff, 0xC0);
        }
        match e.sys {
            Some(Syscall::Halt) => r[SYS_HALT] = F::ONE,
            Some(Syscall::WriteOutput { slot, .. }) => { r[SYS_WRITE] = F::ONE; r[OUT_SEL0 + slot as usize] = F::ONE; written[slot as usize] += 1; }
            Some(Syscall::ReadInput { .. }) => r[SYS_READ] = F::ONE,
            None => {}
        }
        for (k, w) in written.iter().enumerate() { r[WRITTEN0 + k] = F::from_u32(*w); }
    }
    // The accumulator must carry its final value through the padding: the last row is where
    // `(1 − written_i)·pv[out_i] = 0` reads it.
    for i in events.len()..height {
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        for (k, w) in written.iter().enumerate() { r[WRITTEN0 + k] = F::from_u32(*w); }
    }
    RowMajorMatrix::new(v, WIDTH)
}
