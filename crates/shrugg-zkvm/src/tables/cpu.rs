//! One row per cycle. Fetches from PROGRAM, reads and writes through MEMORY,
//! delegates arithmetic to ALU. The only table with public values.
use super::{bus, limbs, nibble::NibbleCounts, program::MESSAGE_LEN, range::RangeCounts, F};
use crate::emulator::{CycleEvent, HashRow, Syscall, ECALL_MEM_REG, SLOT_MEM, SLOT_R1, SLOT_R2, SLOT_W, SPACE_RAM};
use crate::isa::{Program, NUM_OUTPUTS, SYS_HALT as SYS_NUM_HALT, SYS_POSEIDON2, SYS_READ_INPUT, SYS_WRITE_OUTPUT};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const CLK: usize = 0; pub const PC: usize = 1; pub const NEXT_PC: usize = 2; pub const IS_REAL: usize = 3;
    pub const DEC0: usize = 4;
    pub const RD: usize = 4; pub const RS1: usize = 5; pub const RS2: usize = 6; pub const IMM: usize = 7;
    pub const IS_ALU: usize = 8; pub const ALU_OP: usize = 9; pub const IS_IMM: usize = 10; pub const IS_BRANCH: usize = 11;
    pub const BR_OP: usize = 12; pub const BR_NEG: usize = 13;
    /// M2.5: one-hot per load/store mnemonic, replacing the old `IS_LOAD`/`IS_STORE`
    /// booleans. `is_load`/`is_store` are now *expressions* — `IS_LB+IS_LH+IS_LW` and
    /// `IS_SB+IS_SH+IS_SW` — not columns.
    pub const IS_LB: usize = 14; pub const IS_LH: usize = 15; pub const IS_LW: usize = 16;
    pub const IS_SB: usize = 17; pub const IS_SH: usize = 18; pub const IS_SW: usize = 19;
    /// Set for `LB`/`LH` (signed loads); meaningless (and left 0) on every other row.
    pub const SIGNED: usize = 20;
    pub const IS_JAL: usize = 21; pub const IS_JALR: usize = 22; pub const IS_LUI: usize = 23; pub const IS_AUIPC: usize = 24;
    pub const IS_ECALL: usize = 25; pub const WRITES_RD: usize = 26;
    pub const A: usize = 27; pub const B: usize = 28; pub const C: usize = 29; pub const ALU_OUT: usize = 30; pub const TGT: usize = 31;
    pub const MEM_ADDR: usize = 32; pub const MEM_VAL: usize = 33;
    pub const SYS_HALT: usize = 34; pub const SYS_WRITE: usize = 35; pub const SYS_READ: usize = 36;
    pub const OUT_SEL0: usize = 37;
    /// `WRITTEN_i` is the running count of `OUT_SEL_i` over rows `0..=this one`. It is
    /// boolean on every row, so a slot can be written at most once (the emulator's
    /// `DoubleWrite` rule), and because `OUT_SEL_i` is zero on padding rows the value
    /// survives to the last row, where it says whether slot `i` was ever written.
    pub const WRITTEN0: usize = OUT_SEL0 + crate::isa::NUM_OUTPUTS;  // 45
    /// The four byte limbs of `MEM_ADDR` (the WORD address) on load/store rows: what makes
    /// word alignment a stated constraint rather than a side effect of the memory table's
    /// key ordering. Unchanged in role since M2.3/M2.4 — M2.5 only adds the `OFF0/OFF1`
    /// sub-word offset alongside this, it does not touch what `MA0..3` decompose.
    pub const MA0: usize = WRITTEN0 + crate::isa::NUM_OUTPUTS;       // 53
    /// `MA0+3`'s high nibble, for the alignment bound (see the `is_mem` block in `eval`).
    pub const MA3_HI: usize = MA0 + 4;                               // 57
    /// The byte offset of the access within its word, `ALU_OUT & 3`, as two booleans:
    /// `off = OFF0 + 2*OFF1`. Meaningful (and range-relevant) only on load/store rows.
    pub const OFF0: usize = MA3_HI + 1;                              // 58
    pub const OFF1: usize = OFF0 + 1;                                // 59
    /// The four byte limbs of `MEM_VAL` (the word actually in memory — the read value for
    /// a load, the *pre-store* value for a store) on every load/store row, RANGE8-checked.
    pub const W0: usize = OFF1 + 1;                                  // 60
    /// The byte selected by `OFF0/OFF1` out of `W0..3`: meaningful on `LB`/`SB` rows.
    pub const BYTE: usize = W0 + 4;                                  // 64
    /// The halfword selected by `OFF1` out of `W0..3`: meaningful on `LH`/`SH` rows.
    pub const HALF: usize = BYTE + 1;                                // 65
    /// The sign-relevant byte's high nibble (`BYTE`'s for `LB`, the top byte of `HALF`'s
    /// halfword for `LH`) — an isolated extraction, so its low-nibble companion gets its
    /// own dummy `AND4` range check, exactly the M2.4 sign-bit pattern in `alu.rs`.
    pub const HI: usize = HALF + 1;                                  // 66
    /// The sign bit of that byte: `HI`'s top bit, via `AND4[HI, 8, SGN*8]`.
    pub const SGN: usize = HI + 1;                                   // 67
    /// The four byte limbs of `B` (the value read from `rs2`) on store rows, RANGE8-checked
    /// — this is what ties a store's written bytes back to a value that was actually in a
    /// register (the M1 store-forgery invariant, generalized to sub-word stores).
    pub const RB0: usize = SGN + 1;                                  // 68
    /// The merged word a store writes back: `W0..3` with the bytes `OFF0/OFF1`/width select
    /// replaced by the corresponding bytes of `B` (`RB0..3`), everything else left alone —
    /// a read-modify-write over the addressed word, spelled out per byte.
    pub const MERGED0: usize = RB0 + 4;                              // 72
    // M3.2: hash rows (POSEIDON2). Three row kinds share these columns, over and above an
    // ordinary row: the ecall row that dispatches the syscall (`SYS_HASH`), an absorb row per
    // 4-word (or partial) block (`IS_HASH`), and two digest write-back rows (`IS_HASH_OUT`,
    // the second marked `HASH_FIN`). See `docs/02-tables-and-buses.md` for the full row-kind
    // argument; `emulator::HashRow` is the reference this trace builder mirrors.
    pub const SYS_HASH: usize = MERGED0 + 4;                         // 76: ecall row dispatches POSEIDON2
    pub const IS_HASH: usize = SYS_HASH + 1;                         // 77: absorb row
    pub const IS_HASH_OUT: usize = IS_HASH + 1;                      // 78: digest write-back row (2 per call)
    pub const HASH_FIN: usize = IS_HASH_OUT + 1;                     // 79: 1 on the second write-back row only
    pub const HASH_PTR: usize = HASH_FIN + 1;                        // 80: word address, constant across the group
    pub const HASH_N: usize = HASH_PTR + 1;                          // 81: word count, constant across the group
    pub const HASH_LEFT: usize = HASH_N + 1;                         // 82: words not yet absorbed, before this row
    pub const HASH_IDX: usize = HASH_LEFT + 1;                       // 83: absorbed-block index, before this row
    /// 8: the sponge state as of the end of the previous block (absorb rows), or the final
    /// state (both write-back rows, identical on both — copied forward from row 1 to row 2).
    /// A field element, not a byte-range-bounded quantity: a capacity lane, or any lane after
    /// a permutation, routinely exceeds `2^32` (see `emulator::HashRow`'s doc comment) — so
    /// these columns carry no RANGE8 lookup of their own, unlike every other multi-limb value
    /// in this table.
    pub const HS0: usize = HASH_IDX + 1;                             // 84..91
    /// 4: this row's 4 machine words — the words absorbed (or, on an inactive absorb lane,
    /// copied from `HS`) on an absorb row; the 4 written words on a write-back row.
    pub const HV0: usize = HS0 + 8;                                  // 92..95
    /// 4: absorb-row lane-activity booleans (a contiguous prefix of `true`s; lane 0 is always
    /// active on a real absorb row).
    pub const ACT0: usize = HV0 + 4;                                 // 96..99
    /// 2: byte limbs of this row's `HASH_LEFT` (absorb rows only) — bounds it to 16 bits,
    /// comfortably more than `POSEIDON2_MAX_WORDS = 4096` needs.
    pub const LEFT0: usize = ACT0 + 4;                               // 100,101
    /// 2: byte limbs of this row's `HASH_IDX` (absorb rows only).
    pub const IDX0: usize = LEFT0 + 2;                               // 102,103
    /// 16: 4 byte limbs each of `HV0..3`, write-back rows only — what lets `HV0..3` be pinned
    /// as an honest `u32` decomposition of two `HS` lanes (`hs_lane_j = HV_2j + HV_2j+1·2^32`).
    pub const HVL0_0: usize = IDX0 + 2;                              // 104..119
    /// 4 byte limbs of `HASH_PTR` plus `HP0+3`'s high nibble — the exact `MA0..3`/`MA3_HI`
    /// pattern, bounding `HASH_PTR < 2^30`. Checked once, on the ecall row only: `HASH_PTR`
    /// is copied unchanged across the rest of the row-group (the `continues` transition), so
    /// bounding it there bounds every row's `HASH_PTR`, and with it every derived hash
    /// address (`HASH_PTR + 4·HASH_IDX + k <= HASH_PTR + 4099` for the worst-case `HASH_IDX <
    /// 1024`, `HASH_PTR + k <= HASH_PTR + 7` for a write) — comfortably under `2^32` with no
    /// wraparound, exactly as `MA0..3`'s own comment argues for `MEM_ADDR·4 + off`.
    pub const HP0: usize = HVL0_0 + 16;                              // 120..123
    pub const HP3_HI: usize = HP0 + 4;                               // 124
    /// The "is this lane's high word the maximum u32 value" flag and its zero-check inverse
    /// witness, one pair per write-back row's two digest lanes (`j = 0`: `HV0/HV1`; `j = 1`:
    /// `HV2/HV3`) — the gadget that rules out the non-canonical `(lo+1, 2^32-1)` alternate
    /// encoding of any lane `< 2^32-1` (see the write-back constraints in `eval`).
    pub const HIMAX0: usize = HP3_HI + 1;                            // 125,126
    pub const INV0: usize = HIMAX0 + 2;                              // 127,128
    // M3.4: digest rows. `⌈len/4⌉` rows (`IS_DIGEST`) precede the first instruction row,
    // reusing hash rows' `HS0..7`/`HV0..3`/`ACT0..3`/`HASH_LEFT`/`HASH_IDX`/`LEFT0..1`/
    // `IDX0..1` machinery (a digest row is an absorb row whose four words come from the
    // `PROGRAM_WORD` bus instead of a memory read — see `docs/02-tables-and-buses.md`).
    // `HASH_N` (reused, digest rows only) carries the program's word count; `PC` (reused)
    // carries `base_pc`, constant across the whole group via the ordinary `NEXT_PC = PC`
    // chain. Only the final digest word encoding is genuinely new: `DHVL0..31` (the 8 output
    // words' byte limbs, RANGE8-checked) and `DHIMAX0..3`/`DINV0..3` (the same
    // canonical-encoding gadget `HIMAX0..1`/`INV0..1` uses for hash write-back rows, one pair
    // per digest lane) — needed because a digest row publishes all 4 sponge-output lanes (8
    // words) on a single row, not 2 lanes per row across two write-back rows like a
    // `POSEIDON2` syscall does.
    pub const IS_DIGEST: usize = INV0 + 2;                           // 129
    /// 1 on the transition row out of the digest prefix (the last digest row) only, 0
    /// everywhere else — a dedicated witness column (not a recomputed expression) so that
    /// every downstream constraint that needs "is this the last digest row" can gate on a
    /// plain degree-1 column read instead of the degree-2 `IS_DIGEST*(1-n(IS_DIGEST))`
    /// expression, keeping this table's already degree-8-pinned packed lookups from
    /// growing past that ceiling.
    pub const DIGEST_LAST: usize = IS_DIGEST + 1;                    // 130
    pub const DHVL0: usize = DIGEST_LAST + 1;                        // 131..162
    pub const DHIMAX0: usize = DHVL0 + 32;                           // 163..166
    pub const DINV0: usize = DHIMAX0 + 4;                            // 167..170
    pub const WIDTH: usize = DINV0 + 4;                              // 174
    /// Columns that must be zero on padding rows.
    pub const SELECTORS: [usize; 25] = [
        IS_ALU, IS_IMM, IS_BRANCH, IS_LB, IS_LH, IS_LW, IS_SB, IS_SH, IS_SW, SIGNED,
        IS_JAL, IS_JALR, IS_LUI, IS_AUIPC, IS_ECALL, WRITES_RD, SYS_HALT, SYS_WRITE, SYS_READ, BR_NEG,
        SYS_HASH, IS_HASH, IS_HASH_OUT, HASH_FIN, IS_DIGEST,
    ];
}
pub mod pv {
    pub const PC_ENTRY: usize = 0; pub const TIER: usize = 1; pub const OUT0: usize = 2;
    /// M3.4: the in-circuit program digest, pinned by the last digest row. Replaces the
    /// verifier-held `Program` — `Machine::verify` now checks `pv[HC0..HC7] == hc` instead.
    pub const HC0: usize = OUT0 + crate::isa::NUM_OUTPUTS;
    pub const NUM: usize = HC0 + 8;
}
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
        let c8 = |k: u32| AB::Expr::from_u32(1u32 << (8 * k));
        let is_real = v(IS_REAL);

        b.assert_bool(is_real.clone());
        for s in SELECTORS { b.assert_bool(v(s)); b.assert_zero((one.clone() - is_real.clone()) * v(s)); }
        {
            let mut f = b.when_first_row();
            f.assert_one(v(IS_REAL));
            f.assert_zero(v(CLK));
            // M3.4: row 0 of the cpu table is now the first *digest* row (there is always at
            // least one, `Program::digest_rows()` is `max(1, ..)`), not the first
            // instruction — `pv::PC_ENTRY` is bound to its `PC` (= `base_pc`, by the
            // constant-across-the-group chain below), which then flows into the first
            // instruction row's own `PC` via the ordinary `NEXT_PC` transition rule, exactly
            // as it flowed directly before M3.4.
            f.assert_one(v(IS_DIGEST));
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
            // M3.4: `IS_DIGEST` is a contiguous prefix — once it drops to 0 (the first
            // instruction row) it never returns to 1.
            t.assert_zero((one.clone() - v(IS_DIGEST)) * n(IS_DIGEST));
        }

        // M3.2 hash rows: absorb (`IS_HASH`) and write-back (`IS_HASH_OUT`) rows are
        // continuations of the ecall instruction the row before them (or before that) already
        // fetched — not new fetches — so the PROGRAM lookup is gated off there.
        let is_hash = v(IS_HASH);
        let is_hash_out = v(IS_HASH_OUT);
        let is_digest = v(IS_DIGEST);
        let is_hash_any = is_hash.clone() + is_hash_out.clone();
        // M3.4: digest rows share every "this is not an ordinary per-instruction row" gate a
        // hash row already needed (no PROGRAM fetch, no DEC/register/memory-value columns, no
        // per-slot MEMORY send) — `off_cpu` is `is_hash_any` generalized to include them.
        let off_cpu = is_hash_any.clone() + is_digest.clone();
        // MINOR (fix): explicit mutual exclusivity. Nothing else directly forbids a row
        // claiming to be *both* an absorb row and a write-back row at once; every other
        // hash-row constraint happens to be gated by one selector or the other (never by
        // their product), so a row with both set would otherwise fall through every one of
        // them unconstrained on whichever half its own logic doesn't already cover.
        b.assert_zero(is_hash.clone() * is_hash_out.clone());
        // IMPORTANT (fix): `IS_DIGEST` is likewise exclusive with both hash-row selectors.
        // `is_hash_or_digest = is_hash + is_digest` (below, feeding e.g. the `POSEIDON2`
        // lookup's `Count::bounded(is_hash_or_digest, 1)`) is only a valid 0/1 selector — and
        // only correctly counts "this row makes one POSEIDON2 call" — if a row can never claim
        // both `is_hash` and `is_digest` (or `is_hash_out` and `is_digest`) at once; without
        // these, a row doing so would double a bus count `Count::bounded` assumes is at most 1
        // while also falling through both rows' selector-gated constraints half-unconstrained,
        // the same gap the `is_hash · is_hash_out` case above closes.
        b.assert_zero(is_digest.clone() * is_hash.clone());
        b.assert_zero(is_digest.clone() * is_hash_out.clone());
        // 1 on every row of a `POSEIDON2` row-group except its very last (the `HASH_FIN`
        // write-back row): the ecall row, every absorb row, and the first write-back row. Used
        // below to (a) carry `HASH_PTR`/`HASH_N` forward across the whole group and (b) pin
        // `NEXT_PC = PC` on every row but the last (PC only advances once the whole
        // instruction — all its rows — has retired).
        let continues = v(SYS_HASH) + is_hash.clone() + is_hash_out.clone() - v(HASH_FIN);

        // fetch. M3.4: digest rows are `is_real = 1` (they count as cycles) but are not an
        // ordinary instruction fetch either — excluded via `off_cpu`, same as hash rows.
        let msg: Vec<AB::Expr> = std::iter::once(v(PC)).chain((0..MESSAGE_LEN - 1).map(|k| v(DEC0 + k))).collect();
        bus::PROGRAM.lookup_key(b, msg, Count::bounded(is_real.clone() - off_cpu.clone(), 1));

        // Absorb/write-back rows carry none of the ordinary per-instruction machinery: every
        // decoded field (`DEC0..DEC22`, i.e. `RD..WRITES_RD` — 23 columns), the other two
        // syscall selectors, and the register/memory value columns that would otherwise feed
        // an ordinary row's bus sends are pinned to zero. Without this, those columns are
        // completely free on a hash row (the PROGRAM lookup that would normally pin `DEC0..22`
        // is gated off above) and a cheating witness could smuggle an extra, self-consistent
        // ALU/branch/WRITE_OUTPUT/register-read claim through an absorb or write-back row —
        // the AGENTS.md invariant-1 bug class, generalized to a new row kind. `MEM_ADDR` is
        // included because it is one of the four MEMORY-send address terms generalized below.
        for k in 0..MESSAGE_LEN - 1 { b.assert_zero(off_cpu.clone() * v(DEC0 + k)); }
        b.assert_zero(off_cpu.clone() * v(SYS_HALT));
        b.assert_zero(off_cpu.clone() * v(SYS_WRITE));
        b.assert_zero(off_cpu.clone() * v(SYS_READ));
        b.assert_zero(off_cpu.clone() * v(A));
        b.assert_zero(off_cpu.clone() * v(B));
        b.assert_zero(off_cpu.clone() * v(MEM_VAL));
        b.assert_zero(off_cpu.clone() * v(MEM_ADDR));

        // `is_load`/`is_store` are expressions now, not columns (M2.5): one-hot sums over
        // the per-width selectors the program table pre-decodes.
        let is_load = v(IS_LB) + v(IS_LH) + v(IS_LW);
        let is_store = v(IS_SB) + v(IS_SH) + v(IS_SW);
        let is_mem = is_load.clone() + is_store.clone();

        // operand select and ALU delegation
        let b_eff = v(IS_IMM) * v(IMM) + (one.clone() - v(IS_IMM)) * v(B);
        let op1 = v(IS_ALU) * v(ALU_OP) + v(IS_BRANCH) * v(BR_OP);
        let uses_slot1 = v(IS_ALU) + v(IS_BRANCH) + is_mem.clone() + v(IS_JALR);
        bus::ALU.lookup_key(b, [op1, v(A), b_eff, v(ALU_OUT)], Count::bounded(uses_slot1, 1));
        let uses_slot2 = v(IS_BRANCH) + v(IS_JAL) + v(IS_AUIPC);
        bus::ALU.lookup_key(b, [AB::Expr::ZERO, v(PC), v(IMM), v(TGT)], Count::bounded(uses_slot2, 1));

        // rd value
        b.assert_zero(v(IS_ALU) * (v(C) - v(ALU_OUT)));
        b.assert_zero((v(IS_JAL) + v(IS_JALR)) * (v(C) - v(PC) - four.clone()));
        b.assert_zero(v(IS_LUI) * (v(C) - v(IMM)));
        b.assert_zero(v(IS_AUIPC) * (v(C) - v(TGT)));
        // On every other kind of row (branch, store, ecall HALT/WRITE_OUTPUT) nothing above
        // (or below) defines C, and it is never sent on the WRITES_RD/SYS_READ register-write
        // message either, so without this constraint C is a completely free column there: a
        // malicious witness could set it to anything with no other constraint noticing.
        // `cpu_trace` always leaves it at the emulator's own `c = 0` default for these rows
        // (see `emulator::execute`), so this cannot reject any honest trace. Pin it to that
        // same zero sentinel.
        let defines_c = v(IS_ALU) + is_load.clone() + v(IS_JAL) + v(IS_JALR) + v(IS_LUI) + v(IS_AUIPC) + v(SYS_READ);
        b.assert_zero((one.clone() - defines_c) * v(C));

        // next pc
        let taken = v(ALU_OUT) + v(BR_NEG) - v(ALU_OUT) * v(BR_NEG) * AB::Expr::TWO;
        let fallthrough = v(PC) + four.clone();
        b.assert_zero(v(IS_BRANCH) * (v(NEXT_PC) - fallthrough.clone() - taken * (v(TGT) - fallthrough.clone())));
        b.assert_zero(v(IS_JAL) * (v(NEXT_PC) - v(TGT)));
        b.assert_zero(v(IS_JALR) * (v(NEXT_PC) - v(ALU_OUT)));
        // A hash row-group's PC stands still until its very last row (`continues = 0` only
        // there); every other row's `NEXT_PC = PC`.
        b.assert_zero(continues.clone() * (v(NEXT_PC) - v(PC)));
        // M3.4: a digest row's `PC` (= `base_pc`) also stands still across the whole digest
        // group — unconditionally, including its own last row, so the constant flows through
        // the ordinary `n(PC) = v(NEXT_PC)` chain into the first instruction row's `PC`.
        b.assert_zero(is_digest.clone() * (v(NEXT_PC) - v(PC)));
        b.assert_zero(
            is_real.clone() * (one.clone() - v(IS_BRANCH) - v(IS_JAL) - v(IS_JALR) - continues.clone() - is_digest.clone()) * (v(NEXT_PC) - fallthrough),
        );

        // memory: address, alignment, and the word actually in memory
        //
        // `ALU_OUT` is the byte address; `MEM_ADDR` (word address) and `OFF0/OFF1` (the
        // byte offset within the word, `off = OFF0 + 2*OFF1`) are its quotient and
        // remainder by 4, both *stated*, not just implied by `MEM_ADDR·4 + off = ALU_OUT`
        // alone — that identity is a field relation only, and unconstrained `MEM_ADDR` could
        // satisfy it with `MEM_ADDR = (ALU_OUT − off)·4⁻¹ mod p` for any `off` a cheating
        // witness likes. What rules that out, exactly as it did pre-M2.5 (`docs/01-isa.md`):
        // `MEM_ADDR` is decomposed into four RANGE8-checked byte limbs `MA0..3`, bounded
        // below 2^30 by a nibble bound on the top limb (`MA3_HI`, `AND4[MA3_HI, 0xC, 0]`,
        // the M2.3 replacement for the old `AND8` byte-table check) — so `MEM_ADDR` is an
        // honest integer in `[0, 2^30)`, and with `ALU_OUT` already 32-bit (the ALU table's
        // own limb checks) and `off` a sum of two booleans (`< 4`), `MEM_ADDR·4 + off < 2^32`
        // cannot wrap: the identity holds over the integers, not just mod p.
        b.assert_bool(v(OFF0));
        b.assert_bool(v(OFF1));
        let off = v(OFF0) + AB::Expr::TWO * v(OFF1);
        let mut ma = AB::Expr::ZERO;
        for i in 0..4 { ma += v(MA0 + i) * AB::Expr::from_u32(1 << (8 * i)); }
        b.assert_zero(is_mem.clone() * (v(MEM_ADDR) - ma));
        for i in 0..4 { bus::RANGE8.lookup_key(b, [v(MA0 + i)], Count::bounded(is_mem.clone(), 1)); }
        let ma3_lo = v(MA0 + 3) - AB::Expr::from_u32(16) * v(MA3_HI);
        bus::AND4.lookup_key(b, [ma3_lo, AB::Expr::ZERO, AB::Expr::ZERO], Count::bounded(is_mem.clone(), 1));
        bus::AND4.lookup_key(b, [v(MA3_HI), AB::Expr::from_u32(0xC), AB::Expr::ZERO], Count::bounded(is_mem.clone(), 1));
        b.assert_zero(is_mem.clone() * (v(MEM_ADDR) * four.clone() + off.clone() - v(ALU_OUT)));
        // Sub-word alignment: a full word must sit on a word boundary, a half on a 2-byte
        // boundary; a byte is never misaligned. Spec M2.5, verbatim.
        b.assert_zero((v(IS_LW) + v(IS_SW)) * (v(OFF0) + v(OFF1)));
        b.assert_zero((v(IS_LH) + v(IS_SH)) * v(OFF0));
        b.assert_zero(v(IS_ECALL) * (v(MEM_ADDR) - AB::Expr::from_u32(ECALL_MEM_REG)));

        // The word actually in memory at `MEM_ADDR` (the read value for a load, the
        // pre-store value for a store — `emulator::execute` pushes exactly this as the
        // `SLOT_MEM` read for both), decomposed the same way as `MEM_ADDR`.
        let mem_word = |base: usize| v(base) + v(base + 1) * c8(1) + v(base + 2) * c8(2) + v(base + 3) * c8(3);
        for i in 0..4 { bus::RANGE8.lookup_key(b, [v(W0 + i)], Count::bounded(is_mem.clone(), 1)); }
        b.assert_zero(is_mem.clone() * (v(MEM_VAL) - mem_word(W0)));

        // Byte/halfword select out of the word, by `OFF0/OFF1`.
        let sel = |k: usize| -> AB::Expr {
            match k {
                0 => (one.clone() - v(OFF0)) * (one.clone() - v(OFF1)),
                1 => v(OFF0) * (one.clone() - v(OFF1)),
                2 => (one.clone() - v(OFF0)) * v(OFF1),
                3 => v(OFF0) * v(OFF1),
                _ => unreachable!(),
            }
        };
        let byte = (0..4).map(|k| sel(k) * v(W0 + k)).sum::<AB::Expr>();
        b.assert_zero((v(IS_LB) + v(IS_SB)) * (v(BYTE) - byte));
        let half = (one.clone() - v(OFF1)) * (v(W0) + c8(1) * v(W0 + 1)) + v(OFF1) * (v(W0 + 2) + c8(1) * v(W0 + 3));
        b.assert_zero((v(IS_LH) + v(IS_SH)) * (v(HALF) - half));

        // Sign extension for LB/LH: the sign-relevant byte is BYTE itself for LB, and the
        // top byte of whichever half OFF1 selected for LH (W1 if OFF1=0, W3 if OFF1=1) —
        // reusing the already-committed word limbs rather than dividing HALF back apart.
        // Isolated nibble extraction (this byte's low nibble has no other lookup on this
        // row), so it needs its own dummy AND4 range check — the same pattern as the ALU
        // table's sign-bit extraction (M2.4, `alu.rs::nibble_lo_dummy_range`).
        let sign_byte = v(IS_LB) * v(BYTE) + v(IS_LH) * ((one.clone() - v(OFF1)) * v(W0 + 1) + v(OFF1) * v(W0 + 3));
        let is_sub_load = v(IS_LB) + v(IS_LH);
        let hi_lo = sign_byte - AB::Expr::from_u32(16) * v(HI);
        bus::AND4.lookup_key(b, [hi_lo, AB::Expr::ZERO, AB::Expr::ZERO], Count::bounded(is_sub_load.clone(), 1));
        bus::AND4.lookup_key(b, [v(HI), AB::Expr::from_u32(8), v(SGN) * AB::Expr::from_u32(8)], Count::bounded(is_sub_load, 1));

        // The loaded value, sign/zero-extended.
        let two32 = AB::Expr::from_u64(1u64 << 32);
        let c_load = v(IS_LB) * (v(BYTE) + v(SGN) * v(SIGNED) * (two32.clone() - AB::Expr::from_u32(1 << 8)))
            + v(IS_LH) * (v(HALF) + v(SGN) * v(SIGNED) * (two32 - AB::Expr::from_u32(1 << 16)))
            + v(IS_LW) * v(MEM_VAL);
        b.assert_zero(is_load.clone() * (v(C) - c_load));

        // Stores: `B` (rs2's value, already read every row) decomposes into byte limbs
        // `RB0..3` — exactly the M1 store-forgery invariant (`2c8a39d`), generalized: a
        // store's written bytes must trace back to a value that was actually in a register.
        for i in 0..4 { bus::RANGE8.lookup_key(b, [v(RB0 + i)], Count::bounded(is_store.clone(), 1)); }
        b.assert_zero(is_store.clone() * (v(B) - mem_word(RB0)));
        // Which byte(s) of the word this store overwrites, and with what.
        let selp = |k: usize| -> AB::Expr {
            v(IS_SW) + v(IS_SH) * (if k <= 1 { one.clone() - v(OFF1) } else { v(OFF1) }) + v(IS_SB) * sel(k)
        };
        let bp = |k: usize| -> AB::Expr {
            v(IS_SW) * v(RB0 + k) + v(IS_SH) * (if k == 0 || k == 2 { v(RB0) } else { v(RB0 + 1) }) + v(IS_SB) * v(RB0)
        };
        // MERGED: a read-modify-write over the word, spelled out per byte — untouched bytes
        // carry `W_k` forward, touched bytes take `bp(k)`. (When IS_SW=1, `selp(k)=1` for
        // every k and `bp(k)=RB0+k`, so `MERGED_k = RB0+k`, i.e. `merged = word(RB0) = B` —
        // this is the invariant the doc comment below states in words.)
        for k in 0..4usize {
            b.assert_zero(is_store.clone() * (v(MERGED0 + k) - v(W0 + k) - selp(k) * (bp(k) - v(W0 + k))));
        }
        let merged = mem_word(MERGED0);

        let ts = |slot: u32| v(CLK) * four.clone() + AB::Expr::from_u32(slot);
        let zero = AB::Expr::ZERO;
        // M3.2: every one of the four per-cycle slots doubles as a hash-row slot — an absorb
        // row reads `HASH_PTR + 4·HASH_IDX + k` into `HV_k` (`k` = the slot's own index 0..3,
        // matching `ACT0..3`/`HV0..3` 1:1: slot `SLOT_R1`→`HV0`, … `SLOT_W`→`HV3`); a
        // write-back row writes `HASH_PTR + k + 4·HASH_FIN`. Every "ordinary" (non-hash)
        // formula below already evaluates to exactly 0 whenever `is_hash_any = 1` — either
        // because its inputs are DEC-derived (forced 0 above) or, for slot 0/1's count and
        // every slot's `is_write`, via an explicit `(1 - is_hash_any)` gate (`is_real` is the
        // one input here that is *not* DEC-derived) — so the hash terms below are pure
        // *additions* to the existing per-slot formulas, not replacements of them.
        let space_ram = AB::Expr::from_u32(SPACE_RAM);
        let hash_addr = |k: u32| v(HASH_PTR) + v(HASH_IDX) * four.clone() + AB::Expr::from_u32(k);
        let write_addr = |k: u32| v(HASH_PTR) + AB::Expr::from_u32(k) + v(HASH_FIN) * four.clone();

        // M3.4: `count0`/`count1`'s ordinary-row term excludes digest rows too (`off_cpu`,
        // not just `is_hash_any`) — a digest row sends nothing at all on any of the four
        // memory slots, unlike a hash row (which still reads/writes through them).
        let space0 = zero.clone() + space_ram.clone() * is_hash_any.clone();
        let addr0 = v(RS1) + hash_addr(0) * is_hash.clone() + write_addr(0) * is_hash_out.clone();
        let value0 = v(A) + v(HV0) * is_hash_any.clone();
        let count0 = is_real.clone() * (one.clone() - off_cpu.clone()) + v(ACT0) * is_hash.clone() + is_hash_out.clone();
        bus::MEMORY.send(b, [space0, addr0, ts(SLOT_R1), value0, is_hash_out.clone()], Count::bounded(count0, 1));

        let space1 = zero.clone() + space_ram.clone() * is_hash_any.clone();
        let addr1 = v(RS2) + hash_addr(1) * is_hash.clone() + write_addr(1) * is_hash_out.clone();
        let value1 = v(B) + v(HV0 + 1) * is_hash_any.clone();
        let count1 = is_real.clone() * (one.clone() - off_cpu.clone()) + v(ACT0 + 1) * is_hash.clone() + is_hash_out.clone();
        bus::MEMORY.send(b, [space1, addr1, ts(SLOT_R2), value1, is_hash_out.clone()], Count::bounded(count1, 1));

        // A load's or a store's own access is always a READ of the word that was there —
        // `MEM_VAL`. A store's *write* goes out separately below, on `SLOT_W`.
        let space2 = is_mem.clone() + space_ram.clone() * is_hash_any.clone();
        let addr2 = v(MEM_ADDR) + hash_addr(2) * is_hash.clone() + write_addr(2) * is_hash_out.clone();
        let value2 = v(MEM_VAL) + v(HV0 + 2) * is_hash_any.clone();
        let count2 = is_mem.clone() + v(IS_ECALL) + v(ACT0 + 2) * is_hash.clone() + is_hash_out.clone();
        bus::MEMORY.send(b, [space2, addr2, ts(SLOT_MEM), value2, is_hash_out.clone()], Count::bounded(count2, 1));

        // `SLOT_W`: a register writeback (space 0, addr RD, value C — WRITES_RD or SYS_READ
        // rows), a store's word write (space 1/RAM, addr MEM_ADDR, value MERGED — the pin
        // that replaces `2c8a39d`'s "a store's mem_val is the rs2 value": now "the written
        // value is MERGED, and MERGED = B when IS_SW", proved structurally by the MERGED
        // formula above), or (M3.2) a hash row's 4th lane. No two of the three ever coincide
        // on one row (a store never sets WRITES_RD/SYS_READ, and both are DEC-derived, forced
        // 0 on hash rows), so the shared slot still carries exactly one message.
        let slot_w_space = is_store.clone() + space_ram * is_hash_any.clone();
        let slot_w_addr = is_store.clone() * v(MEM_ADDR) + (one.clone() - is_store.clone()) * v(RD)
            + hash_addr(3) * is_hash.clone() + write_addr(3) * is_hash_out.clone();
        let slot_w_val = is_store.clone() * merged + (one.clone() - is_store.clone()) * v(C) + v(HV0 + 3) * is_hash_any.clone();
        let slot_w_is_write = (one.clone() - is_hash_any.clone()) + is_hash_out.clone();
        let count3 = v(WRITES_RD) + v(SYS_READ) + is_store.clone() + v(ACT0 + 3) * is_hash.clone() + is_hash_out.clone();
        bus::MEMORY.send(b, [slot_w_space, slot_w_addr, ts(SLOT_W), slot_w_val, slot_w_is_write], Count::bounded(count3, 1));

        // syscalls: a = number, b = arg0, mem_val = arg1
        let sys_sum = v(SYS_HALT) + v(SYS_WRITE) + v(SYS_READ) + v(SYS_HASH);
        b.assert_zero(v(IS_ECALL) * (sys_sum.clone() - one.clone()));
        b.assert_zero((one.clone() - v(IS_ECALL)) * sys_sum);
        b.assert_zero(v(SYS_HALT) * (v(A) - AB::Expr::from_u32(SYS_NUM_HALT)));
        b.assert_zero(v(SYS_WRITE) * (v(A) - AB::Expr::from_u32(SYS_WRITE_OUTPUT)));
        b.assert_zero(v(SYS_READ) * (v(A) - AB::Expr::from_u32(SYS_READ_INPUT)));

        // M3.2: the `POSEIDON2` ecall row. `a0` (already read into `B` every ecall row) is the
        // word pointer; `a1` (read through `MEM_VAL`, the memory slot, exactly like every other
        // ecall's second argument) is the word count. The group starts with the whole count
        // still to absorb, at block 0, sponge state all-zero.
        b.assert_zero(v(SYS_HASH) * (v(A) - AB::Expr::from_u32(SYS_POSEIDON2)));
        b.assert_zero(v(SYS_HASH) * (v(HASH_PTR) - v(B)));
        b.assert_zero(v(SYS_HASH) * (v(HASH_N) - v(MEM_VAL)));
        b.assert_zero(v(SYS_HASH) * (v(HASH_LEFT) - v(HASH_N)));
        b.assert_zero(v(SYS_HASH) * v(HASH_IDX));
        for i in 0..8 { b.assert_zero(v(SYS_HASH) * v(HS0 + i)); }
        // CRITICAL 1 (fix): `HASH_PTR` is otherwise just the raw `a0` register value — an
        // unbounded field element on the `MEMORY` bus. `MEMORY`'s own consistency check only
        // range-checks the *delta* between consecutive sorted `(space, addr)` keys (via
        // `D0..3`), never an address's absolute magnitude, so an unbounded `HASH_PTR` could
        // alias any other address the key arithmetic `space·2^30 + addr` (`memory.rs::
        // KEY_SHIFT`) wraps into mod `p` — exactly the failure `MA0..3`/`MA3_HI` already rule
        // out for ordinary `MEM_ADDR`. Bound `HASH_PTR` the same way, decomposed into `HP0..3`
        // (`RANGE8`) plus `HP3_HI`'s top-nibble mask (`AND4[HP3_HI, 0xC, 0]`), checked once on
        // the ecall row: `HASH_PTR < 2^30` there, and `continues` below copies it unchanged to
        // every other row of the group, so every row's `HASH_PTR` — and hence every derived
        // hash address, `HASH_PTR + 4·HASH_IDX + k <= HASH_PTR + 4099` (absorb, `HASH_IDX <
        // 2^16` via `IDX0..1`) or `HASH_PTR + k <= HASH_PTR + 7` (write-back) — stays comfortably
        // under `2^32` with no wraparound, the same argument `MA0..3`'s doc comment makes for
        // `MEM_ADDR·4 + off`.
        {
            let mut hp = AB::Expr::ZERO;
            for i in 0..4 { hp += v(HP0 + i) * AB::Expr::from_u32(1 << (8 * i)); }
            b.assert_zero(v(SYS_HASH) * (v(HASH_PTR) - hp));
            for i in 0..4 { bus::RANGE8.lookup_key(b, [v(HP0 + i)], Count::bounded(v(SYS_HASH), 1)); }
            let hp3_lo = v(HP0 + 3) - AB::Expr::from_u32(16) * v(HP3_HI);
            bus::AND4.lookup_key(b, [hp3_lo, AB::Expr::ZERO, AB::Expr::ZERO], Count::bounded(v(SYS_HASH), 1));
            bus::AND4.lookup_key(b, [v(HP3_HI), AB::Expr::from_u32(0xC), AB::Expr::ZERO], Count::bounded(v(SYS_HASH), 1));
        }
        {
            let mut t = b.when_transition();
            // `HASH_PTR`/`HASH_N` are constant across the whole row-group.
            t.assert_zero(continues.clone() * (n(HASH_PTR) - v(HASH_PTR)));
            t.assert_zero(continues.clone() * (n(HASH_N) - v(HASH_N)));
            // The row right after the ecall row — the first absorb row if `n > 0`, or
            // directly the first write-back row if `n = 0` — starts the sponge at the
            // all-zero state and inherits `HASH_LEFT = n`/`HASH_IDX = 0` from the ecall row
            // (its own `HASH_LEFT`/`HASH_IDX`, which an absorb row's own update formula below
            // then chains from).
            for i in 0..8 { t.assert_zero(v(SYS_HASH) * n(HS0 + i)); }
            t.assert_zero(v(SYS_HASH) * (n(HASH_LEFT) - v(HASH_LEFT)));
            t.assert_zero(v(SYS_HASH) * (n(HASH_IDX) - v(HASH_IDX)));
            // CRITICAL 2 (fix): without a rule tying the ecall row's routing to `HASH_N`, a
            // witness could go straight from the ecall row to a write-back row (skipping every
            // absorb row) for *any* `HASH_N`, publishing the empty-input digest for a nonzero
            // word count — the `final_absorb` drain rule below never fires, since it lives on
            // `IS_HASH` transitions and there would be no absorb row at all. Two rules close
            // this: the row after the ecall row must be either an absorb row or a write-back
            // row (never anything else, e.g. an ordinary row splicing the group), and it can
            // only be a write-back row when `HASH_N = 0`.
            t.assert_zero(v(SYS_HASH) * (n(IS_HASH) + n(IS_HASH_OUT) - one.clone()));
            t.assert_zero(v(SYS_HASH) * n(IS_HASH_OUT) * v(HASH_N));
            // CRITICAL 2b (fix, round 2): the rule above stops a nonzero-`HASH_N` call from
            // routing straight to *a* write-back row, but a zero-`HASH_N` call legitimately
            // does route straight to a write-back row — and without this, nothing stopped it
            // from routing to the *second* one (`HASH_FIN = 1`) directly, skipping the first
            // write-back row entirely. That would never write digest words 0..3 at all, so a
            // guest reading `ptr..ptr+3` back would see whatever was already in RAM instead of
            // the honest zeros — a valid proof of a non-honest execution. The row right after
            // the ecall row, if it is a write-back row, must be the *first* one.
            t.assert_zero(v(SYS_HASH) * n(IS_HASH_OUT) * n(HASH_FIN));
            // The second write-back row needs the same `HS0..7` (specifically lanes 2/3, the
            // digest's third/fourth field elements) the first row established from the last
            // absorb's `POSEIDON2` lookup — nothing else propagates it there.
            let out_continues = is_hash_out.clone() * (one.clone() - v(HASH_FIN));
            for i in 0..8 { t.assert_zero(out_continues.clone() * (n(HS0 + i) - v(HS0 + i))); }
        }

        // Absorb rows: `ACT0..3` is a boolean, non-increasing (contiguous-prefix) pattern —
        // lane 0 is always active on a real absorb *or digest* row — and `active_sum` is how
        // many words this row actually absorbs (from memory on a hash row, from `PROGRAM_WORD`
        // on a digest row).
        for i in 0..4 { b.assert_bool(v(ACT0 + i)); }
        for i in 1..4 { b.assert_zero(v(ACT0 + i) * (one.clone() - v(ACT0 + i - 1))); }
        b.assert_zero((is_hash.clone() + is_digest.clone()) * (one.clone() - v(ACT0)));
        let active_sum = v(ACT0) + v(ACT0 + 1) + v(ACT0 + 2) + v(ACT0 + 3);
        {
            let mut t = b.when_transition();
            // `HASH_LEFT` chains to the next row exactly as the emulator's absorb loop does:
            // `left` drops by this row's `active_sum` — true whether the next row is another
            // absorb row or (the last block) the first write-back row, whose `HASH_LEFT`
            // `cpu_trace` leaves at the same zero_vec default the "must fully drain" rule
            // below requires there anyway.
            t.assert_zero(is_hash.clone() * (v(HASH_LEFT) - active_sum.clone() - n(HASH_LEFT)));
            // `HASH_IDX`'s increment-by-one chain, by contrast, is meaningful only between two
            // absorb rows — a write-back row's `HASH_IDX` column carries no obligation at all
            // (`cpu_trace` leaves it at 0, not `idx + 1`), so this must be gated by `not_final`,
            // not bare `is_hash`.
            let not_final = is_hash.clone() * n(IS_HASH);
            t.assert_zero(not_final.clone() * (n(HASH_IDX) - v(HASH_IDX) - one.clone()));
            // Every absorb row but the last one absorbs a *full* block: without this, a
            // witness could split the same total word count across more, smaller blocks than
            // the honest `PaddingFreeSponge` schedule — a different, non-standard hash of the
            // same message (the permutation runs once per block regardless of how full it
            // is), not merely a differently-shaped but equivalent trace. "Last" means the next
            // row is not itself an absorb row.
            t.assert_zero(not_final * (one.clone() - v(ACT0 + 3)));
            // The *last* absorb row (next row is not `IS_HASH`) must fully drain `HASH_LEFT`
            // to 0 — it cannot stop early and leave words unabsorbed, nor (combined with the
            // `HASH_LEFT` chain above, which already forbids `active_sum` exceeding
            // `HASH_LEFT` without a huge, RANGE8-rejected wraparound) over-absorb.
            let final_absorb = is_hash.clone() * (one.clone() - n(IS_HASH));
            t.assert_zero(final_absorb * n(HASH_LEFT));
            // CRITICAL 2b (fix, round 2), the absorb-side twin of the `SYS_HASH` rule above:
            // the row right after the last absorb row, if it is a write-back row (the only
            // legitimate case once absorption has actually happened), must be the *first* one,
            // not the second — otherwise digest words 0..3 are never written.
            t.assert_zero(is_hash.clone() * n(IS_HASH_OUT) * n(HASH_FIN));
        }
        // Inactive lanes are not overwritten by the sponge: `HV_k` carries the previous
        // state's own lane `k` forward instead of a memory read (hash rows) or a
        // `PROGRAM_WORD` lookup (digest rows).
        let is_hash_or_digest = is_hash.clone() + is_digest.clone();
        for i in 0..4 { b.assert_zero(is_hash_or_digest.clone() * (one.clone() - v(ACT0 + i)) * (v(HV0 + i) - v(HS0 + i))); }
        // `HASH_LEFT`/`HASH_IDX` range checks (byte limbs), the same purpose `MA0..3` serves
        // for `MEM_ADDR`: without this, a wrong `HASH_LEFT`/`HASH_IDX` could only be caught via
        // a field-arithmetic identity, satisfiable by a huge wraparound value a cheating
        // witness could otherwise pick freely. `HASH_LEFT`'s 16-bit bound (`LEFT0..1`, both
        // `RANGE8`-checked) comfortably covers `POSEIDON2_MAX_WORDS = 4096`. On a *hash* row,
        // `HASH_IDX`'s top limb is tightened further, to `< 4` rather than `< 256`: the nibble
        // table has no entries with `a >= 16`, so requesting `AND4[IDX1, 3, IDX1]` (instead of
        // a plain `RANGE8[IDX1]`) only finds a match when `IDX1 & 3 == IDX1`, i.e. `IDX1 < 4`
        // — giving `HASH_IDX = IDX0 + 256·IDX1 < 1024`, exactly `POSEIDON2_MAX_WORDS / 4`, the
        // largest block index a `POSEIDON2` syscall can ever reach. M3.4's digest rows have no
        // such small fixed cap (a program can run to many thousands of words, unlike a single
        // hash call's 4096-word limit), so they get only the plain `RANGE8[IDX1]` bound
        // (`HASH_IDX < 65536`, comfortably more than any real program's `digest_rows()`) —
        // gated by `is_digest` alone, not reusing the hash-only AND4 tightening.
        b.assert_zero(is_hash_or_digest.clone() * (v(LEFT0) + v(LEFT0 + 1) * AB::Expr::from_u32(256) - v(HASH_LEFT)));
        b.assert_zero(is_hash_or_digest.clone() * (v(IDX0) + v(IDX0 + 1) * AB::Expr::from_u32(256) - v(HASH_IDX)));
        for c in [LEFT0, LEFT0 + 1, IDX0] { bus::RANGE8.lookup_key(b, [v(c)], Count::bounded(is_hash_or_digest.clone(), 1)); }
        bus::RANGE8.lookup_key(b, [v(IDX0 + 1)], Count::bounded(is_digest.clone(), 1));
        bus::AND4.lookup_key(b, [v(IDX0 + 1), AB::Expr::from_u32(3), v(IDX0 + 1)], Count::bounded(is_hash.clone(), 1));
        // The `POSEIDON2` lookup: `state_in` overwrites lanes 0..3 of the row's entering state
        // (`HS`) with this row's `HV`, keeping the capacity lanes 4..7; `state_out` is the
        // *next* row's `HS0..7` — so this single bus interaction is what proves the chain from
        // one absorb row's state to the next is a genuine Poseidon2 permutation, for every
        // absorb row (including the last, whose `state_out` becomes the first write-back row's
        // `HS`, i.e. the digest) *and* every digest row (M3.4; including its own last row,
        // whose `state_out` becomes `n(HS)` — pinned to `pv::HC0..HC7` below).
        let state_in: Vec<AB::Expr> = (0..8).map(|i| if i < 4 { v(HV0 + i) } else { v(HS0 + i) }).collect();
        let state_out: Vec<AB::Expr> = (0..8).map(|i| n(HS0 + i)).collect();
        bus::POSEIDON2.lookup_key(b, state_in.into_iter().chain(state_out).collect::<Vec<_>>(), Count::bounded(is_hash_or_digest.clone(), 1));

        // M3.4 digest rows: `PROGRAM_WORD` lookups in place of a memory read, one per active
        // lane, keyed by `pc_k = base_pc + 4*(4*block_index + k)` (`Program::pc_of`'s own
        // indexing, `4*block_index + k` being this word's position in the program).
        let digest_pc = |k: u32| v(PC) + (v(HASH_IDX) * AB::Expr::from_u32(4) + AB::Expr::from_u32(k)) * AB::Expr::from_u32(4);
        for k in 0..4u32 {
            bus::PROGRAM_WORD.lookup_key(b, [digest_pc(k), v(HV0 + k as usize)], Count::bounded(is_digest.clone() * v(ACT0 + k as usize), 1));
        }

        // M3.4: the digest group's own bookkeeping — `PC` (`base_pc`) and `HASH_N` (`len`,
        // reused) are seeded once, on the very first cpu-table row (`when_first_row`, since
        // there is no ecall row preceding a digest group the way `SYS_HASH` precedes a hash
        // group), then carried forward across the whole group exactly like `HASH_PTR`/
        // `HASH_N` are for hash rows. `HASH_LEFT` starts at `HASH_N`, drains by `active_sum`
        // each row, and must hit exactly 0 the moment `IS_DIGEST` drops to 0 — the same
        // `n`-binding pattern M3.2's absorb rows use, so a digest row cannot be skipped for a
        // nonzero-length program (`docs/02-tables-and-buses.md`).
        {
            let mut f = b.when_first_row();
            for i in [0usize, 1, 2, 3, 7] { f.assert_zero(v(HS0 + i)); }
            f.assert_eq(v(HS0 + 4), AB::Expr::from_u32(crate::hash::HC_DOMAIN));
            f.assert_eq(v(HS0 + 5), v(PC));
            f.assert_eq(v(HS0 + 6), v(HASH_N));
            f.assert_zero(v(HASH_IDX));
            f.assert_eq(v(HASH_LEFT), v(HASH_N));
        }
        // `DIGEST_LAST` (see its column doc comment): pinned to 0 whenever this isn't a digest
        // row at all, and — on a digest row — to `1 - n(IS_DIGEST)`, i.e. exactly 1 on the
        // transition out of the digest prefix. Together these two (each used once) replace
        // the degree-2 expression `IS_DIGEST*(1-n(IS_DIGEST))` with a degree-1 witness column
        // for every downstream use below.
        b.assert_bool(v(DIGEST_LAST));
        b.assert_zero((one.clone() - is_digest.clone()) * v(DIGEST_LAST));
        let digest_last = v(DIGEST_LAST);
        // The final digest: `n(HS0..3)` (read below, inside `when_transition`) is the state
        // after the last digest row's own `POSEIDON2` permutation — the sponge output.
        // Encoded canonically into 8 lo/hi machine words (`DHVL0..31`, RANGE8-checked;
        // `DHIMAX0..3`/`DINV0..3` the same non-canonical-encoding-rejecting gadget M3.2's hash
        // write-back rows use, `HIMAX0..1`/`INV0..1`, one pair per lane here instead of two
        // rows of two) and pinned to `pv::HC0..HC7`. The byte-limb/pv-pinning half needs only
        // the current row, so it runs outside `when_transition` (bus lookups can't be issued
        // through a `FilteredAirBuilder` alongside a separate live borrow of `b`); only the
        // "next row's `HS`" half genuinely needs `when_transition`.
        for k in 0..8 {
            for j in 0..4 { bus::RANGE8.lookup_key(b, [v(DHVL0 + 4 * k + j)], Count::bounded(digest_last.clone(), 1)); }
            let byte_sum: AB::Expr = (0..4).map(|j| v(DHVL0 + 4 * k + j) * AB::Expr::from_u32(1 << (8 * j))).sum();
            b.assert_zero(digest_last.clone() * (pvs[pv::HC0 + k].clone() - byte_sum));
        }
        for j in 0..4usize { b.assert_bool(v(DHIMAX0 + j)); }
        {
            let mut t = b.when_transition();
            t.assert_zero(is_digest.clone() * (v(DIGEST_LAST) - (one.clone() - n(IS_DIGEST))));
            let not_final_digest = is_digest.clone() * n(IS_DIGEST);
            // `HASH_N` (`len`) only needs to persist digest-row-to-digest-row — unlike `PC`
            // (whose constant-carry deliberately continues one row further, into the first
            // instruction row, to become its entry `PC`), nothing reads `HASH_N` past the
            // digest prefix, and the first instruction row's own `HASH_N` column legitimately
            // stays at its unrelated `zero_vec` default there. Gating this by `not_final_digest`
            // (not bare `is_digest`) is what keeps this from wrongly demanding `len` survive
            // into that row too.
            t.assert_zero(not_final_digest.clone() * (n(HASH_N) - v(HASH_N)));
            t.assert_zero(is_digest.clone() * (v(HASH_LEFT) - active_sum.clone() - n(HASH_LEFT)));
            t.assert_zero(not_final_digest.clone() * (n(HASH_IDX) - v(HASH_IDX) - one.clone()));
            t.assert_zero(not_final_digest * (one.clone() - v(ACT0 + 3)));
            t.assert_zero(digest_last.clone() * n(HASH_LEFT));

            let two32 = AB::Expr::from_u64(1u64 << 32);
            for j in 0..4usize {
                let lo = v(DHVL0 + 8 * j) + v(DHVL0 + 8 * j + 1) * AB::Expr::from_u32(1 << 8) + v(DHVL0 + 8 * j + 2) * AB::Expr::from_u32(1 << 16) + v(DHVL0 + 8 * j + 3) * AB::Expr::from_u32(1 << 24);
                let hi = v(DHVL0 + 8 * j + 4) + v(DHVL0 + 8 * j + 5) * AB::Expr::from_u32(1 << 8) + v(DHVL0 + 8 * j + 6) * AB::Expr::from_u32(1 << 16) + v(DHVL0 + 8 * j + 7) * AB::Expr::from_u32(1 << 24);
                t.assert_zero(digest_last.clone() * (lo.clone() + hi.clone() * two32.clone() - n(HS0 + j)));
                let d = hi - AB::Expr::from_u32(0xFFFF_FFFF);
                t.assert_zero(digest_last.clone() * (d * v(DINV0 + j) - (one.clone() - v(DHIMAX0 + j))));
                t.assert_zero(digest_last.clone() * v(DHIMAX0 + j) * lo);
            }
        }

        // CRITICAL 2 (fix, continued): the first write-back row's own `HASH_LEFT` must be 0,
        // full stop — regardless of how it got there. This is what actually closes the escape:
        // the `SYS_HASH` transition rules above stop a witness from *routing* around the
        // absorb rows, but without this, a witness that does exactly that could still set the
        // copied-forward `HASH_LEFT` (via the `SYS_HASH -> next` copy) to whatever the ecall
        // row claims and nothing would ever check it against 0. In the honest trace this is
        // always already true — `cpu_trace` leaves write-back rows' `HASH_LEFT` at its
        // `zero_vec` default, and the `n = 0` case's own copy from the ecall row is 0 too — so
        // this cannot reject any honest witness.
        b.assert_zero(is_hash_out.clone() * (one.clone() - v(HASH_FIN)) * v(HASH_LEFT));
        // CRITICAL 2b (fix, round 2): the first write-back row's own next row must be the
        // second write-back row (`IS_HASH_OUT = 1, HASH_FIN = 1`) — the third and last piece
        // that rules out ever skipping the first write-back row (see the two `n(HASH_FIN) = 0`
        // routing rules above, on the ecall row and the last absorb row): together the three
        // cover every way a witness could route *into* a `HASH_FIN = 1` row, so a `POSEIDON2`
        // call now always writes both digest rows or the proof does not verify. Degree 4
        // (`is_hash_out·(1-HASH_FIN)` is degree 2, `1 - n(IS_HASH_OUT)·n(HASH_FIN)` is degree
        // 2), still under this table's degree-8 ceiling.
        b.when_transition().assert_zero(
            is_hash_out.clone() * (one.clone() - v(HASH_FIN)) * (one.clone() - n(IS_HASH_OUT) * n(HASH_FIN)),
        );

        // Write-back rows: `HV0..3` is this row's 4 written machine words, which must be an
        // honest `u32` decomposition (`HVL0..15`, RANGE8-checked) of two `HS` lanes — lanes
        // 0/1 on the first write-back row, 2/3 on the second (`hs_lane_j` below), i.e. exactly
        // the digest field elements the last absorb's `POSEIDON2` lookup established.
        for k in 0..4 {
            for j in 0..4 { bus::RANGE8.lookup_key(b, [v(HVL0_0 + 4 * k + j)], Count::bounded(is_hash_out.clone(), 1)); }
            let byte_sum: AB::Expr = (0..4).map(|j| v(HVL0_0 + 4 * k + j) * AB::Expr::from_u32(1 << (8 * j))).sum();
            b.assert_zero(is_hash_out.clone() * (v(HV0 + k) - byte_sum));
        }
        let two32 = AB::Expr::from_u64(1u64 << 32);
        // CRITICAL 3 (fix): `hv_lo + hv_hi·2^32 = hs_lane` alone is only a *field* identity —
        // for any lane value `v < 2^32 - 1` the non-canonical pair `(v+1, 2^32-1)` also
        // satisfies it (`(v+1) + (2^32-1)·2^32 = v + p ≡ v mod p`), and both words are still
        // individually `< 2^32` so the existing `RANGE8`/`HVL` check does not catch it either.
        // The only *canonical* (base-`2^32`) representation with `hi = 2^32-1` is `lo = 0`
        // (the field's single largest element, `p - 1`) — every other value with that `hi` is
        // the non-canonical alternate of some smaller lane. `HIMAX_j` (a zero-check flag on
        // `d = hi - (2^32-1)`, `INV_j` its inverse witness) forces exactly that: `d = 0` always
        // forces `HIMAX_j = 1` regardless of `INV_j` (the first equation's left side vanishes),
        // and `HIMAX_j·lo = 0` then forces `lo = 0` whenever `HIMAX_j = 1` — closing the
        // non-canonical case (`hi = 2^32-1, lo != 0`) while leaving every ordinary lane
        // (`hi != 2^32-1`, `INV_j = d⁻¹`, `HIMAX_j = 0`) and the one legitimate `hi = 2^32-1`
        // case (`lo = 0`) satisfiable.
        for j in 0..2usize {
            let hs_lane = (one.clone() - v(HASH_FIN)) * v(HS0 + j) + v(HASH_FIN) * v(HS0 + j + 2);
            b.assert_zero(is_hash_out.clone() * (v(HV0 + 2 * j) + v(HV0 + 2 * j + 1) * two32.clone() - hs_lane));
            b.assert_bool(v(HIMAX0 + j));
            let d = v(HV0 + 2 * j + 1) - AB::Expr::from_u32(0xFFFF_FFFF);
            b.assert_zero(is_hash_out.clone() * (d * v(INV0 + j) - (one.clone() - v(HIMAX0 + j))));
            b.assert_zero(is_hash_out.clone() * v(HIMAX0 + j) * v(HV0 + 2 * j));
        }
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

pub fn public_values(pc_entry: u32, tier_log2: usize, outputs: &[u32; NUM_OUTPUTS], hc: &[u32; 8]) -> Vec<F> {
    let mut v = vec![F::from_u32(pc_entry), F::from_u64(tier_log2 as u64)];
    v.extend(outputs.iter().map(|o| F::from_u32(*o)));
    v.extend(hc.iter().map(|o| F::from_u32(*o)));
    v
}

/// M3.4: fills the `⌈len/4⌉`-row digest prefix (`v[0..digest_rows*WIDTH]`) from
/// `hash::program_digest_rows` — the same per-block state the `IS_DIGEST` AIR rows chain
/// through, plus the final row's canonical 8-word output encoding (`DHVL0..31`/
/// `DHIMAX0..3`/`DINV0..3`), mirroring hash write-back rows' own `HIMAX`/`INV` construction.
fn fill_digest_rows(v: &mut [F], program: &Program, range: &mut RangeCounts) {
    let blocks = crate::hash::program_digest_rows(program.base_pc, &program.words);
    let n = blocks.len();
    for (i, blk) in blocks.iter().enumerate() {
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        r[CLK] = F::from_u32(i as u32);
        r[PC] = F::from_u32(program.base_pc);
        r[NEXT_PC] = F::from_u32(program.base_pc);
        r[IS_REAL] = F::ONE;
        r[IS_DIGEST] = F::ONE;
        r[HASH_N] = F::from_u32(program.words.len() as u32);
        r[HASH_LEFT] = F::from_u32(blk.left_before);
        r[HASH_IDX] = F::from_u32(blk.idx);
        for k in 0..8 { r[HS0 + k] = blk.state_in[k]; }
        for k in 0..4 {
            r[ACT0 + k] = F::from_bool(blk.active[k]);
            r[HV0 + k] = if blk.active[k] { F::from_u32(blk.words[k]) } else { blk.state_in[k] };
        }
        let (l0, l1) = (blk.left_before & 0xff, (blk.left_before >> 8) & 0xff);
        r[LEFT0] = F::from_u32(l0); r[LEFT0 + 1] = F::from_u32(l1);
        range.range8(l0); range.range8(l1);
        let (i0, i1) = (blk.idx & 0xff, (blk.idx >> 8) & 0xff);
        r[IDX0] = F::from_u32(i0); r[IDX0 + 1] = F::from_u32(i1);
        range.range8(i0);
        // Digest rows use the plain 16-bit `RANGE8[IDX1]` bound, not the hash-only `< 4`
        // AND4 tightening (`Program::digest_rows()` can exceed `POSEIDON2_MAX_WORDS / 4` —
        // see the AIR's comment on this same check).
        range.range8(i1);
        if i + 1 == n {
            r[DIGEST_LAST] = F::ONE;
            let digest = crate::hash::split_digest([blk.state_out[0], blk.state_out[1], blk.state_out[2], blk.state_out[3]]);
            for (k, &w) in digest.iter().enumerate() {
                let wl = limbs(w);
                for j in 0..4 { r[DHVL0 + 4 * k + j] = wl[j]; range.range8((w >> (8 * j)) & 0xff); }
            }
            for j in 0..4usize {
                let hi = digest[2 * j + 1];
                if hi == u32::MAX { r[DHIMAX0 + j] = F::ONE; } else {
                    let d = F::from_u32(hi) - F::from_u32(u32::MAX);
                    r[DINV0 + j] = d.inverse();
                }
            }
        }
    }
    // The AIR's canonical-encoding pin on the last digest row reads `n(HS0..3)` — the state
    // *entering* the row right after the digest prefix (the first instruction row, or the
    // next digest row in the always-≥1-block case). Nothing else populates that row's `HS`
    // (an ordinary instruction row's own event data has no notion of it), so it must be
    // seeded here explicitly, exactly as the last digest block's own permutation output —
    // mirroring how a hash absorb row's `state_out` becomes the *next* row's `HS` via that
    // row's own event data (`HashRow::Absorb`'s `state_in` chain); here there is no such next
    // event, so the digest builder writes it directly.
    if let Some(last) = blocks.last() {
        let r = &mut v[n * WIDTH..(n + 1) * WIDTH];
        for k in 0..8 { r[HS0 + k] = last.state_out[k]; }
    }
}

/// `range`/`nibble` receive the `RANGE8`/`AND4` lookups the alignment limbs declare, in
/// lock-step with the interactions the AIR above evaluates. `program` is needed for M3.4's
/// digest-row prefix (`Program::digest_rows()` rows, `hash::program_digest_rows`) — the
/// witness's own traversal of the whole program for `hc`, distinct from `events`'ordinary
/// per-cycle rows, which now start `digest_rows` rows later (`CLK` shifted the same amount).
pub fn cpu_trace(program: &Program, events: &[CycleEvent], height: usize, range: &mut RangeCounts, nibble: &mut NibbleCounts) -> RowMajorMatrix<F> {
    let digest_rows = program.digest_rows();
    assert!(
        digest_rows + events.len() < height,
        "cpu table needs a padding row: {digest_rows} digest rows + {} cycles, height {height}",
        events.len()
    );
    let mut v = F::zero_vec(height * WIDTH);
    fill_digest_rows(&mut v, program, range);
    let mut written = [0u32; NUM_OUTPUTS];
    let mut hash_ptr_n: Option<(u32, u32)> = None;
    for (i, e) in events.iter().enumerate() {
        let r = &mut v[(digest_rows + i) * WIDTH..(digest_rows + i + 1) * WIDTH];
        r[CLK] = F::from_u32(digest_rows as u32 + e.clk); r[PC] = F::from_u32(e.pc); r[NEXT_PC] = F::from_u32(e.next_pc); r[IS_REAL] = F::ONE;
        for (k, f) in e.dec.to_fields().iter().enumerate() { r[DEC0 + k] = F::from_u32(*f); }
        r[A] = F::from_u32(e.a); r[B] = F::from_u32(e.b); r[C] = F::from_u32(e.c);
        r[ALU_OUT] = F::from_u32(e.alu_out); r[TGT] = F::from_u32(e.tgt);
        r[MEM_ADDR] = F::from_u32(e.mem_addr); r[MEM_VAL] = F::from_u32(e.mem_val);
        let is_load = e.dec.is_lb == 1 || e.dec.is_lh == 1 || e.dec.is_lw == 1;
        let is_store = e.dec.is_sb == 1 || e.dec.is_sh == 1 || e.dec.is_sw == 1;
        if is_load || is_store {
            let ml = limbs(e.mem_addr);
            for k in 0..4 { r[MA0 + k] = ml[k]; range.range8((e.mem_addr >> (8 * k)) & 0xff); }
            let ma3 = (e.mem_addr >> 24) & 0xff;
            let (ma3_lo, ma3_hi) = (ma3 & 0xf, ma3 >> 4);
            r[MA3_HI] = F::from_u32(ma3_hi);
            nibble.and4(ma3_lo, 0);
            nibble.and4(ma3_hi, 0xC);

            // The sub-word offset `ALU_OUT & 3`, and the word actually in memory (`MEM_VAL`
            // — the read value for a load, the pre-store value for a store).
            let off = e.alu_out & 3;
            let (off0, off1) = (off & 1, (off >> 1) & 1);
            r[OFF0] = F::from_u32(off0); r[OFF1] = F::from_u32(off1);
            let wl = limbs(e.mem_val);
            for k in 0..4 { r[W0 + k] = wl[k]; range.range8((e.mem_val >> (8 * k)) & 0xff); }

            if e.dec.is_lb == 1 || e.dec.is_sb == 1 {
                let byte = (e.mem_val >> (8 * off)) & 0xff;
                r[BYTE] = F::from_u32(byte);
            }
            if e.dec.is_lh == 1 || e.dec.is_sh == 1 {
                let half = (e.mem_val >> (16 * off1)) & 0xffff;
                r[HALF] = F::from_u32(half);
            }
            if e.dec.is_lb == 1 || e.dec.is_lh == 1 {
                let sign_byte = if e.dec.is_lb == 1 { (e.mem_val >> (8 * off)) & 0xff } else if off1 == 0 { (e.mem_val >> 8) & 0xff } else { (e.mem_val >> 24) & 0xff };
                let (lo, hi) = (sign_byte & 0xf, sign_byte >> 4);
                r[HI] = F::from_u32(hi);
                r[SGN] = F::from_u32(hi >> 3);
                nibble.and4(lo, 0);
                nibble.and4(hi, 8);
            }
            if is_store {
                let bl = limbs(e.b);
                for k in 0..4 { r[RB0 + k] = bl[k]; range.range8((e.b >> (8 * k)) & 0xff); }
                // Read-modify-write, mirroring `emulator::execute`'s `Store` arm exactly:
                // `e.mem_val` is the pre-store word, `e.b` is rs2's value.
                let merged = if e.dec.is_sw == 1 {
                    e.b
                } else if e.dec.is_sh == 1 {
                    (e.mem_val & !(0xffffu32 << (8 * off))) | ((e.b & 0xffff) << (8 * off))
                } else {
                    (e.mem_val & !(0xffu32 << (8 * off))) | ((e.b & 0xff) << (8 * off))
                };
                let mgl = limbs(merged);
                for k in 0..4 { r[MERGED0 + k] = mgl[k]; }
            }
        }
        match e.sys {
            Some(Syscall::Halt) => r[SYS_HALT] = F::ONE,
            Some(Syscall::WriteOutput { slot, .. }) => { r[SYS_WRITE] = F::ONE; r[OUT_SEL0 + slot as usize] = F::ONE; written[slot as usize] += 1; }
            Some(Syscall::ReadInput { .. }) => r[SYS_READ] = F::ONE,
            Some(Syscall::Poseidon2 { .. }) => r[SYS_HASH] = F::ONE,
            None => {}
        }
        // M3.2 hash rows. `hash_ptr_n` remembers the group's `(ptr, n)` from its ecall row
        // (`HashRow::Absorb`/`WriteOut` don't carry them again — every row of one group is
        // adjacent in `events`, in emission order, so the ecall row is always seen first).
        if let Some(h) = e.hash_row {
            match h {
                HashRow::Ecall { ptr, n } => {
                    hash_ptr_n = Some((ptr, n));
                    r[HASH_PTR] = F::from_u32(ptr);
                    r[HASH_N] = F::from_u32(n);
                    r[HASH_LEFT] = F::from_u32(n);
                    // HASH_IDX and HS0..7 stay at the `zero_vec` default — the AIR pins both to
                    // 0 on the ecall row directly.
                    // CRITICAL 1 (fix): HASH_PTR's own RANGE8/AND4-checked byte decomposition —
                    // the MA0..3/MA3_HI pattern, checked once here since HASH_PTR is copied
                    // unchanged across the rest of the row-group.
                    let hpl = limbs(ptr);
                    for k in 0..4 { r[HP0 + k] = hpl[k]; range.range8((ptr >> (8 * k)) & 0xff); }
                    let hp3 = (ptr >> 24) & 0xff;
                    let (hp3_lo, hp3_hi) = (hp3 & 0xf, hp3 >> 4);
                    r[HP3_HI] = F::from_u32(hp3_hi);
                    nibble.and4(hp3_lo, 0);
                    nibble.and4(hp3_hi, 0xC);
                }
                HashRow::Absorb { idx, left_before, words, active, state_in, .. } => {
                    r[IS_HASH] = F::ONE;
                    let (ptr, n) = hash_ptr_n.expect("absorb row without a preceding ecall row");
                    r[HASH_PTR] = F::from_u32(ptr);
                    r[HASH_N] = F::from_u32(n);
                    r[HASH_LEFT] = F::from_u32(left_before);
                    r[HASH_IDX] = F::from_u32(idx);
                    for i in 0..8 { r[HS0 + i] = state_in[i]; }
                    for k in 0..4 {
                        r[ACT0 + k] = F::from_bool(active[k]);
                        r[HV0 + k] = if active[k] { F::from_u32(words[k]) } else { state_in[k] };
                    }
                    let (l0, l1) = (left_before & 0xff, (left_before >> 8) & 0xff);
                    r[LEFT0] = F::from_u32(l0); r[LEFT0 + 1] = F::from_u32(l1);
                    range.range8(l0); range.range8(l1);
                    let (i0, i1) = (idx & 0xff, (idx >> 8) & 0xff);
                    r[IDX0] = F::from_u32(i0); r[IDX0 + 1] = F::from_u32(i1);
                    range.range8(i0);
                    // `IDX0+1`'s tightened `< 4` bound: `AND4[i1, 3, i1]`, not `RANGE8`.
                    nibble.and4(i1, 3);
                }
                HashRow::WriteOut { fin, words, state } => {
                    r[IS_HASH_OUT] = F::ONE;
                    if fin { r[HASH_FIN] = F::ONE; }
                    let (ptr, n) = hash_ptr_n.expect("write-back row without a preceding ecall row");
                    r[HASH_PTR] = F::from_u32(ptr);
                    r[HASH_N] = F::from_u32(n);
                    for i in 0..8 { r[HS0 + i] = state[i]; }
                    for k in 0..4 {
                        r[HV0 + k] = F::from_u32(words[k]);
                        let bl = limbs(words[k]);
                        for j in 0..4 { r[HVL0_0 + 4 * k + j] = bl[j]; range.range8((words[k] >> (8 * j)) & 0xff); }
                    }
                    // CRITICAL 3 (fix): HIMAX_j/INV_j, the canonical-encoding zero-check gadget
                    // — see the AIR comment. `hi == u32::MAX` is the one case that needs the
                    // flag set (and no inverse, since `d = 0` there); every other `hi` gets the
                    // genuine field inverse of `d`.
                    for j in 0..2usize {
                        let hi = words[2 * j + 1];
                        if hi == u32::MAX {
                            r[HIMAX0 + j] = F::ONE;
                        } else {
                            let d = F::from_u32(hi) - F::from_u32(u32::MAX);
                            r[INV0 + j] = d.inverse();
                        }
                    }
                }
            }
        }
        for (k, w) in written.iter().enumerate() { r[WRITTEN0 + k] = F::from_u32(*w); }
    }
    // The accumulator must carry its final value through the padding: the last row is where
    // `(1 − written_i)·pv[out_i] = 0` reads it.
    for i in (digest_rows + events.len())..height {
        let r = &mut v[i * WIDTH..(i + 1) * WIDTH];
        for (k, w) in written.iter().enumerate() { r[WRITTEN0 + k] = F::from_u32(*w); }
    }
    RowMajorMatrix::new(v, WIDTH)
}
