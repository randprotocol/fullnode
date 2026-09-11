//! 32-bit ALU as four byte limbs. Add/sub/compare share one adder; bitwise ops
//! go through the nibble table (two lookups per limb — low then derived high
//! nibble); shifts are proved as exact integer identities that cannot wrap in
//! Goldilocks, with the shift amount and a handful of isolated sign/overflow
//! bits extracted through the nibble table too.
//!
//! ## M2.6 — the RV32M extension
//!
//! **Multiplication** (`mul, mulh, mulhu, mulhsu`). Split `A = AL + 2^16*AH`,
//! `B = BL + 2^16*BH` into 16-bit halves (sums of the existing byte limbs). The schoolbook
//! expansion `A*B = T0 + 2^16*T1 + 2^32*T2` (`T0=AL*BL, T1=AL*BH+AH*BL, T2=AH*BH`) is an
//! *exact* integer identity — no modular reduction — and since `A*B <= (2^32-1)^2 =
//! 2^64-2^33+1 < p`, it holds as a genuine field equation too. Writing the true 64-bit
//! product's halves as `LO + 2^32*HI = A*B`, algebra gives `LO = T0 + 2^16*T1 -
//! 2^32*CARRY` and `HI = T2 + CARRY` for `CARRY := HI - T2` (the classic schoolbook carry,
//! honestly `< 2^17`).
//!
//! **The soundness gap the spec's own `HI = 2^32-1` attack (and this table's required
//! cheating test) targets, and the fix**: `T0,T1,T2` are *forced* (not free) to their exact
//! values by the identity above, given `AL,AH,BL,BH < 2^16` (themselves forced by
//! `A0..3`/`B0..3`'s ordinary RANGE8 checks — `is_mul` is not excluded from `g_ab`). `CARRY`
//! is the only free witness, bounded by its own 3-byte RANGE8 decomposition to `< 2^24`
//! (looser than the honest `< 2^17`, but — see below — still sufficient; "looser but
//! sufficient" is a controller ruling, not sloppiness). Fixing `T0,T1`, the map
//! `CARRY ↦ LO(CARRY) mod p` is injective on any interval shorter than `p`, and for
//! `CARRY != CARRY*` (the honest value) the resulting `LO(CARRY)`, reduced to its unique
//! representative in `[0, p)`, is either `>= 2^32` (if `CARRY < CARRY*`) or within
//! `2^56` of `p` (if `CARRY > CARRY*`, via field wraparound) — either way, provably outside
//! `[0, 2^32)`. Since `mul` also RANGE8-checks `C0..3` (an ordinary 32-bit result, exactly
//! like `add`/`sub`), `C = LO` can only pass its own range check for the honest `CARRY`. But
//! that argument, by itself, only binds `CARRY` on `mul` rows (where the `C = LO` check
//! actually fires) — a `mulhu`-only row's `C = HI` check does *not*, on its own, pin `CARRY`
//! at all (`HI(CARRY) = T2 + CARRY` is *additive*, not the `2^32`-amplified map `LO` gets, so
//! nearby forged `CARRY` values give nearby, still-in-range, still-wrong `HI` values). The
//! fix: `LO`'s own byte limbs (`T0..3`, physically idle for the mul family otherwise) are
//! RANGE8-checked and pinned to `T0 + 2^16*T1 - 2^32*CARRY` *unconditionally* on every
//! mul-family row, not just `mul` rows. That reintroduces the amplified uniqueness argument
//! on every row regardless of which output is selected, so `CARRY` — hence `HI` — is pinned
//! to its honest value everywhere. `mulhu`, `mulh`, `mulhsu` all inherit this even though
//! none of them individually range-check `HI`.
//!
//! Sign correction for `mulh`/`mulhsu`: `HI_signed = HI - SA*B - [mulh]*SB*A` (mod `2^32`,
//! `MULHSU` uses only `SA` since it treats `B` as unsigned), with a single boolean `borrow`
//! reintroducing `2^32` when the subtraction underflows. A single bit suffices — case
//! analysis over `(SA,SB) in {0,1}^2` (using `HI < 2^32`, `SA*B, SB*A < 2^32`) shows the true
//! value of `HI - SA*B - [mulh]*SB*A` always lands in `(-2^32, 2^32)`, so at most one of
//! `{0, +2^32}` brings it into `[0, 2^32)`.
//!
//! **Division** (`div, divu, rem, remu`). Compute `|A|`, `|B|` via `SA`/`SB` (forced `0` for
//! the unsigned variants), each RANGE8-decomposed; a quotient/remainder magnitude pair
//! `Q, R` (also RANGE8-decomposed) satisfying `|A| = Q*|B| + R` and `R < |B|` when `B != 0`
//! (the product `Q*|B|` fits the field by the same `< p` bound as the multiplier above);
//! `DIVZ` selected by the two-constraint is-zero gadget on `B` (`B*INVB = 1-DIVZ` *and*
//! `DIVZ*B = 0` — the first alone is not enough, since a prover could set `INVB=0` and
//! falsely claim `DIVZ=1` with `B != 0`; that gap is exactly the "wrong DIVZ" cheating test).
//! Final sign fix-up selects `mag` (`Q` for div/divu, `R` for rem/remu) and negates it (via
//! the same 2's-complement-style `mag + (2^32 - 2*mag)` trick as `SA`/`SB` use elsewhere)
//! when the op-appropriate sign flag calls for it — gated by `1 - QH3`, where `QH3` is
//! `[mag == 0]` (another is-zero gadget, reusing `QH3`/`INV`): *without* that gate, the naive
//! formula gives exactly `2^32` (unrepresentable) whenever `mag = 0` and negation is called
//! for — an ordinary case (e.g. `REM(-4, 2) = 0`), not just an edge case.
//!
//! **No dedicated MIN/-1 overflow selector.** The spec sketch called for one; this
//! implementation doesn't need it. For `A = MIN = 0x8000_0000`, `B = -1 = 0xffff_ffff`:
//! `|A| = 2^31`, `|B| = 1`, so the *unsigned* core gives `Q = 2^31, R = 0` — already the
//! required overflow result, because `2^31`, left unnegated (same-sign quotient, since both
//! `A` and `B` are negative), *is* `0x8000_0000` in 32-bit arithmetic: representing `+2^31`
//! in 32-bit two's complement is impossible, so "don't negate" and "wrap to MIN" coincide by
//! construction. `R = 0` similarly matches directly. No branch of the pipeline above treats
//! this `(A,B)` pair specially, and none needs to.
use super::{bus, limbs, nibble::NibbleCounts, range::RangeCounts, F};
use crate::emulator::{AluEvent, CycleEvent};
use crate::isa::AluOp;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

pub mod col {
    pub const FLAG0: usize = 0;   // 19 flags (M2.6: +8 M-extension ops), AluOp code order
    pub const A: usize = 19; pub const B: usize = 20; pub const C: usize = 21;
    pub const A0: usize = 22; pub const B0: usize = 26; pub const C0: usize = 30;
    /// shift quotient / sll high word limbs / bitwise AL0..3 / **M2.6 mul**: the three
    /// cross-term products `T0,T1,T2` and the schoolbook carry `CARRY` (four *field*
    /// values, not byte limbs — see the `alu` doc comment) / **M2.6 div**: the quotient
    /// magnitude's own byte limbs.
    pub const Q0: usize = 34;
    /// compare difference / right-shift remainder limbs / bitwise BL0..3 / **M2.6 mul**:
    /// the sign-correction borrow bit (`S0`) plus `CARRY`'s own three byte limbs (`S1..3`)
    /// / **M2.6 div**: the remainder magnitude's own byte limbs.
    pub const S0: usize = 38;
    /// pw - 1 - r limbs / bitwise CL0..3 / **M2.6 mul**: `LO`'s own byte limbs, populated
    /// on every mul-family row regardless of which op is selected (this is what pins the
    /// shared `CARRY` witness to its unique honest value — see the `alu` doc comment).
    /// Unused on div rows (the shipped division design decomposes no `|A|` columns — see the
    /// in-AIR comment at the division block).
    pub const T0: usize = 42;
    pub const SA: usize = 46; pub const SB: usize = 47; pub const SHH: usize = 48; pub const PW: usize = 49;
    /// four adder carries. Unconditionally boolean; unused as limbs on div rows (same note
    /// as `T0` — `|A|`/`|B|` are pure expressions there, not column decompositions).
    pub const CARRY0: usize = 50;
    pub const INV: usize = 54; pub const IS_REAL: usize = 55; pub const MULT: usize = 56;
    /// A's top-limb (A0+3) low nibble's high-nibble companion, used on `slt`/`sra` rows and
    /// (M2.6) `mulh`/`mulhsu`/`div`/`rem` rows to extract A's sign bit.
    pub const AH3: usize = 57;
    /// B's relevant limb's high nibble: B's top limb (limb 3) on `slt`/(M2.6) `mulh`/`div`/
    /// `rem` rows (for SB), B's limb 0 on shift rows (for the shift-amount high bit).
    pub const BH_N: usize = 58;
    /// `sll`'s overflow check: Q's top limb (Q0+3)'s high nibble / **M2.6 div**: whether the
    /// row's op-selected magnitude (quotient for div/divu, remainder for rem/remu) is zero —
    /// see the `alu` doc comment's remainder-sign-fix discussion.
    pub const QH3: usize = 59;
    /// M2.6 div: `[B == 0]`, forced by the two-constraint is-zero gadget on `B`/`INVB`.
    pub const DIVZ: usize = 60;
    /// M2.6 div: `B`'s field inverse when `B != 0` (arbitrary, `INVB = 0` by convention,
    /// when `DIVZ = 1`).
    pub const INVB: usize = 61;
    /// M2.6 div: the third and fourth byte of `|B| - R - 1` (the `R < |B|` bound), reusing
    /// the otherwise-idle `SHH`/`PW` columns for the first two bytes — see the `alu` doc
    /// comment.
    pub const DB2: usize = 62; pub const DB3: usize = 63;
    pub const WIDTH: usize = 64;
}
use col::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct AluAir;

impl<Fld> BaseAir<Fld> for AluAir { fn width(&self) -> usize { WIDTH } }

// A fixed Goldilocks constant: 16⁻¹ mod (2^64 - 2^32 + 1) = 17293822565076172801.
// Used only to derive a nibble-pair's HIGH half from its LOW half as a pure
// expression (never a witness column) in cases where BOTH nibbles already get an
// independent, real lookup elsewhere on the same row (the bitwise case below) — see
// the doc comment on `bitwise_high_nibble`.
const INV16: u64 = 17_293_822_565_076_172_801;

/// For bitwise rows only: given a byte limb `byte` and its already-looked-up low
/// nibble `lo` (bound to [0,16) by the row's own low-nibble AND4/OR4/XOR4 lookup),
/// the high nibble is `(byte - lo) * 16⁻¹` as a pure expression — no extra column,
/// no extra lookup. This is sound *only* because `lo` already has an independent,
/// non-dummy lookup on this row (the low-nibble AND4/OR4/XOR4 call): the map
/// `byte ↦ (byte - lo) * 16⁻¹` is a field bijection, and only byte values in [0,256)
/// map to a high-nibble result in [0,16) (the bijection's unique preimage for any
/// target in [0,16) is exactly `lo + 16*target`, which is <256). So constraining the
/// *derived* high nibble to a valid AND4/OR4/XOR4 row (its second, real lookup) is
/// enough to force `byte < 256` with zero extra columns. This does NOT generalize to
/// an isolated nibble extraction (sign bits, shift amount, memory alignment) where
/// the low nibble has no other lookup of its own — those need an explicit dummy
/// range-check lookup in addition (see `nibble_lo_dummy_range` below).
fn bitwise_high_nibble<AB: AirBuilder>(byte: AB::Expr, lo: AB::Expr) -> AB::Expr {
    (byte - lo) * AB::Expr::from_u64(INV16)
}

/// Isolated nibble extraction: the companion low nibble has no other lookup on this
/// row, so it needs its own dummy range-check lookup (weight 0 used as an arbitrary
/// in-range mask; the output slot is pinned to 0 — since the companion range check's
/// own output value is unused, any consistent fixed constant works as long as the
/// row exists in the table for every nibble; we key against 0 for simplicity, i.e.
/// AND4[x, 0, 0] holds for every x in [0,16)).
fn nibble_lo_dummy_range<AB: AirBuilder + InteractionBuilder>(b: &mut AB, lo: AB::Expr, gate: AB::Expr) {
    bus::AND4.lookup_key(b, [lo, AB::Expr::ZERO, AB::Expr::ZERO], Count::bounded(gate, 1));
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for AluAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let one = AB::Expr::ONE;
        let c8 = |k: u32| AB::Expr::from_u32(1u32 << (8 * k));
        let f = |op: AluOp| v(FLAG0 + op.code() as usize);
        let (add, sub, and, or, xor, sll, srl, sra, slt, sltu, eq) = (
            f(AluOp::Add), f(AluOp::Sub), f(AluOp::And), f(AluOp::Or), f(AluOp::Xor), f(AluOp::Sll),
            f(AluOp::Srl), f(AluOp::Sra), f(AluOp::Slt), f(AluOp::Sltu), f(AluOp::Eq),
        );
        let (mul, mulh, mulhu, mulhsu, div, divu, rem, remu) = (
            f(AluOp::Mul), f(AluOp::Mulh), f(AluOp::Mulhu), f(AluOp::Mulhsu),
            f(AluOp::Div), f(AluOp::Divu), f(AluOp::Rem), f(AluOp::Remu),
        );
        let is_real = v(IS_REAL);
        b.assert_bool(is_real.clone());
        // INVARIANT — for every `table_entry` in this crate, the count must be forced to
        // zero wherever the message columns are unconstrained. On a padding row every op
        // flag is zero (so the provided `op` decodes as `Add`), the limb range checks are
        // gated on `is_real`, and every arithmetic constraint carries a flag factor — so
        // `A`, `B` and `C` are free field elements there. Without this line `MULT` was the
        // last free column, and a padding row provided an arbitrary `(Add, a, b, c)` tuple
        // with arbitrary multiplicity: the CPU consumes `Add` for every ADD/ADDI, every
        // load/store address, every JALR target and the whole slot-2 `(0, pc, imm, tgt)`
        // lookup, so `fib(10) = 999` was provable (`tests/cheating.rs`).
        b.assert_zero((one.clone() - is_real.clone()) * v(MULT));
        let mut sum = AB::Expr::ZERO;
        for i in 0..AluOp::COUNT { b.assert_bool(v(FLAG0 + i)); sum += v(FLAG0 + i); }
        b.assert_eq(sum, is_real.clone());

        // limb recomposition and range checks
        let word = |base: usize| v(base) + v(base + 1) * c8(1) + v(base + 2) * c8(2) + v(base + 3) * c8(3);
        b.assert_eq(word(A0), v(A));
        b.assert_eq(word(B0), v(B));
        b.assert_eq(word(C0), v(C));
        // RANGE8 gates: `g_ab` drops A/B's byte-range lookups on bitwise rows, where the
        // nibble table already binds every limb twice (low nibble, real lookup; high
        // nibble, derived-but-still-looked-up — see `bitwise_high_nibble`'s doc comment),
        // which is a strictly stronger byte-range proof than RANGE8 gives. `g_c` further
        // drops C's lookup on `slt`/`sltu`/`eq` rows, where `(cmp+eq)*C*(C-1)=0` (below)
        // already forces `C ∈ {0,1}` directly — also strictly stronger than a byte-range
        // check. Both gates stay sums of boolean row-selector flags (never a product), so
        // `Count::bounded(gate, 1)` still holds: on any row exactly one flag is 1 (the
        // `sum == is_real` constraint above), so each gate expression evaluates to 0 or 1.
        //
        // INVARIANT re-argued for these two gates specifically: on a bitwise row, `g_ab`
        // is 0, so A0..3/B0..3 are NOT bus message columns for RANGE8 on that row — but
        // they remain fully constrained by the nibble lookups a few lines below (the low
        // nibble is a real AND4/OR4/XOR4 lookup input, the high nibble is a field-forced
        // function of the byte and that low nibble, itself also looked up), so nothing is
        // free there. On an `slt`/`sltu`/`eq` row, `g_c` is 0, so C0..3 are not RANGE8
        // message columns. That is safe — but not because `word(C0) == C` (above) pins
        // C0..3 individually: it's one linear equation in four field elements, so it does
        // *not* force C0 = C ∈ {0,1} and C1 = C2 = C3 = 0 (infinitely many other C0..3
        // solve it too). The real reason is that nothing else on an `slt`/`sltu`/`eq` row
        // consumes C0..3, so an unconstrained decomposition there is harmless — unlike
        // `add`/`sub`/`sll`/`mul`/`div` rows, where C0..3 (or `mul`'s alias T0..3) are
        // load-bearing and stay RANGE8-checked. Any new consumer of C0..3 on a cmp/eq row
        // must re-enable the RANGE8 checks. On every other row kind (add/sub, shifts) both
        // gates are 1, matching the pre-M2.4 unconditional behavior exactly.
        let g_ab = is_real.clone() - and.clone() - or.clone() - xor.clone();
        let g_c = g_ab.clone() - slt.clone() - sltu.clone() - eq.clone();
        for i in 0..4 {
            bus::RANGE8.lookup_key(b, [v(A0 + i)], Count::bounded(g_ab.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(B0 + i)], Count::bounded(g_ab.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(C0 + i)], Count::bounded(g_c.clone(), 1));
        }
        let cmp = slt.clone() + sltu.clone();
        let rshift = srl.clone() + sra.clone();
        let shift = sll.clone() + rshift.clone();
        for i in 0..4 {
            bus::RANGE8.lookup_key(b, [v(S0 + i)], Count::bounded(cmp.clone() + rshift.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(T0 + i)], Count::bounded(rshift.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(Q0 + i)], Count::bounded(shift.clone(), 1));
        }

        // shared adder: x + y = z (mod 2^32) with limb carries
        let adder = add.clone() + sub.clone() + cmp.clone();
        for i in 0..4 {
            let x = add.clone() * v(A0 + i) + sub.clone() * v(B0 + i) + cmp.clone() * v(B0 + i);
            let y = add.clone() * v(B0 + i) + sub.clone() * v(C0 + i) + cmp.clone() * v(S0 + i);
            let z = add.clone() * v(C0 + i) + (sub.clone() + cmp.clone()) * v(A0 + i);
            let cin = if i == 0 { AB::Expr::ZERO } else { v(CARRY0 + i - 1) };
            b.assert_bool(v(CARRY0 + i));
            b.assert_zero((one.clone() - adder.clone()) * v(CARRY0 + i));
            b.assert_zero(x + y + cin - z - v(CARRY0 + i) * AB::Expr::from_u32(256));
        }
        let borrow = v(CARRY0 + 3);

        // sign bits: A's sign on slt/sra rows and (M2.6) mulh/mulhsu/div/rem rows (AH3, from
        // A0+3's high nibble); B's sign on slt rows and (M2.6) mulh/div/rem rows only
        // (BH_N, from B0+3's high nibble) — MULHSU treats B as unsigned, so it is
        // deliberately excluded from `need_sb`, and DIVU/REMU are excluded from both (their
        // own `(divu+remu)*(SA+SB)=0` constraint below forces SA=SB=0 there). Each isolated
        // low-nibble companion (a3_lo/b3_lo) gets its own dummy range-check lookup since
        // nothing else on these rows looks it up; see `nibble_lo_dummy_range`'s doc comment.
        let need_sa = slt.clone() + sra.clone() + mulh.clone() + mulhsu.clone() + div.clone() + rem.clone();
        let need_sb = slt.clone() + mulh.clone() + div.clone() + rem.clone();
        b.assert_bool(v(SA));
        b.assert_bool(v(SB));
        let a3_lo = v(A0 + 3) - AB::Expr::from_u32(16) * v(AH3);
        nibble_lo_dummy_range(b, a3_lo, need_sa.clone());
        bus::AND4.lookup_key(b, [v(AH3), AB::Expr::from_u32(8), v(SA) * AB::Expr::from_u32(8)], Count::bounded(need_sa.clone(), 1));
        let b3_lo = v(B0 + 3) - AB::Expr::from_u32(16) * v(BH_N);
        nibble_lo_dummy_range(b, b3_lo, need_sb.clone());
        bus::AND4.lookup_key(b, [v(BH_N), AB::Expr::from_u32(8), v(SB) * AB::Expr::from_u32(8)], Count::bounded(need_sb.clone(), 1));
        b.assert_zero(srl.clone() * v(SA));

        // compares
        b.assert_zero((cmp.clone() + eq.clone()) * v(C) * (v(C) - one.clone()));
        b.assert_zero(sltu.clone() * (v(C) - borrow.clone()));
        let sx = v(SA) + v(SB) - v(SA) * v(SB) * AB::Expr::TWO;
        b.assert_zero(slt.clone() * (v(C) - (one.clone() - sx.clone()) * borrow.clone() - sx * v(SA)));
        let diff = v(A) - v(B);
        b.assert_zero(eq.clone() * (diff.clone() * v(INV) + v(C) - one.clone()));
        b.assert_zero(eq.clone() * v(C) * diff);

        // bitwise: low nibbles are stored scratch (Q0..3/S0..3/T0..3, meaningful only on
        // bitwise rows — every other op either gates its own use of these columns to zero
        // or leaves them unused), high nibbles are derived expressions bound by the row's
        // own second lookup (`bitwise_high_nibble`). Two lookups per limb, eight per row.
        for i in 0..4 {
            let (al, bl, cl) = (v(Q0 + i), v(S0 + i), v(T0 + i));
            let ah = bitwise_high_nibble::<AB>(v(A0 + i), al.clone());
            let bh = bitwise_high_nibble::<AB>(v(B0 + i), bl.clone());
            let ch = bitwise_high_nibble::<AB>(v(C0 + i), cl.clone());
            bus::AND4.lookup_key(b, [al.clone(), bl.clone(), cl.clone()], Count::bounded(and.clone(), 1));
            bus::AND4.lookup_key(b, [ah.clone(), bh.clone(), ch.clone()], Count::bounded(and.clone(), 1));
            bus::OR4.lookup_key(b, [al.clone(), bl.clone(), cl.clone()], Count::bounded(or.clone(), 1));
            bus::OR4.lookup_key(b, [ah.clone(), bh.clone(), ch.clone()], Count::bounded(or.clone(), 1));
            bus::XOR4.lookup_key(b, [al, bl, cl], Count::bounded(xor.clone(), 1));
            bus::XOR4.lookup_key(b, [ah, bh, ch], Count::bounded(xor.clone(), 1));
        }

        // shifts. The shift amount `sh = b & 31` is decomposed as B0's low nibble
        // (`b0_lo`, derived — not stored — from B0 and BH_N, exactly like the sign-bit
        // extraction above; BH_N is reused here for B's limb-0 high nibble, safe because
        // shift and slt never co-occur) plus 16 times SHH, B0's high nibble's bit 0.
        let b0_lo = v(B0) - AB::Expr::from_u32(16) * v(BH_N);
        nibble_lo_dummy_range(b, b0_lo.clone(), shift.clone());
        bus::AND4.lookup_key(b, [v(BH_N), AB::Expr::ONE, v(SHH)], Count::bounded(shift.clone(), 1));
        let sh = b0_lo + AB::Expr::from_u32(16) * v(SHH);
        bus::POW2.lookup_key(b, [sh, v(PW)], Count::bounded(shift.clone(), 1));
        let q = word(Q0);
        let r = word(S0);
        let t = word(T0);
        let two32 = AB::Expr::from_u64(1 << 32);
        b.assert_zero(sll.clone() * (v(A) * v(PW) - q.clone() * two32 - v(C)));
        // sll's overflow check: Q's top limb's high nibble (QH3) must have its top bit
        // clear, via the same isolated-extraction pattern as the sign bits above.
        let q3_lo = v(Q0 + 3) - AB::Expr::from_u32(16) * v(QH3);
        nibble_lo_dummy_range(b, q3_lo, sll.clone());
        bus::AND4.lookup_key(b, [v(QH3), AB::Expr::from_u32(8), AB::Expr::ZERO], Count::bounded(sll.clone(), 1));
        // right shifts: complement when negative (sra), shift, complement back
        let flip = |x: AB::Expr| x.clone() + v(SA) * (AB::Expr::from_u32(255) - x * AB::Expr::TWO);
        let a_prime = flip(v(A0)) + flip(v(A0 + 1)) * c8(1) + flip(v(A0 + 2)) * c8(2) + flip(v(A0 + 3)) * c8(3);
        b.assert_zero(rshift.clone() * (a_prime - q * v(PW) - r.clone()));
        b.assert_zero(rshift.clone() * (v(PW) - one.clone() - r - t));
        for i in 0..4 { b.assert_zero(rshift.clone() * (v(C0 + i) - flip(v(Q0 + i)))); }

        // M2.6 multiplication: `mul, mulh, mulhu, mulhsu`. Exact integer identity over
        // 16-bit halves — see the module doc comment for the full soundness argument
        // (the `HI = 2^32-1` product-attack rejection in particular).
        let is_mul = mul.clone() + mulh.clone() + mulhu.clone() + mulhsu.clone();
        let (al, ah) = (v(A0) + c8(1) * v(A0 + 1), v(A0 + 2) + c8(1) * v(A0 + 3));
        let (bl, bh) = (v(B0) + c8(1) * v(B0 + 1), v(B0 + 2) + c8(1) * v(B0 + 3));
        // T0, T1, T2 (the three cross-term products) and CARRY alias Q0..3 as whole field
        // values, not byte limbs — al/ah/bl/bh are each < 2^16 (forced by A0..3/B0..3's own
        // RANGE8 checks above, which `is_mul` does not exclude from `g_ab`), so T0 < 2^32,
        // T1 < 2^33, T2 < 2^32: each is forced to its exact integer value by the identity
        // below, no separate range check needed for any of the three.
        let (mt0, mt1, mt2, carry) = (v(Q0), v(Q0 + 1), v(Q0 + 2), v(Q0 + 3));
        b.assert_zero(is_mul.clone() * (mt0.clone() - al.clone() * bl.clone()));
        b.assert_zero(is_mul.clone() * (mt1.clone() - (al.clone() * bh.clone() + ah.clone() * bl.clone())));
        b.assert_zero(is_mul.clone() * (mt2.clone() - ah * bh));
        // CARRY's own three byte limbs (S1..3; S0 is the sign-correction borrow below),
        // RANGE8-checked: bounds CARRY < 2^24. Looser than the honest range (< 2^17), but
        // sufficient — see the module doc comment's uniqueness argument.
        let carry_limbs = v(S0 + 1) + c8(1) * v(S0 + 2) + c8(2) * v(S0 + 3);
        b.assert_zero(is_mul.clone() * (carry.clone() - carry_limbs));
        for c in [S0 + 1, S0 + 2, S0 + 3] { bus::RANGE8.lookup_key(b, [v(c)], Count::bounded(is_mul.clone(), 1)); }
        let lo = mt0 + AB::Expr::from_u32(1 << 16) * mt1 - AB::Expr::from_u64(1u64 << 32) * carry.clone();
        let hi = mt2 + carry;
        // LO's own byte limbs (T0..3), populated and RANGE8-checked on *every* mul-family
        // row regardless of which op is selected — not just `mul` rows. This is the fix
        // that makes MULHU/MULH/MULHSU sound: without an unconditional range proof that LO
        // itself is < 2^32, CARRY is only pinned by the `mul` flag's own `C = LO` check, so
        // a MULHU-only row would leave CARRY (hence HI = T2 + CARRY) essentially free — see
        // the module doc comment.
        b.assert_zero(is_mul.clone() * (word(T0) - lo.clone()));
        for i in 0..4 { bus::RANGE8.lookup_key(b, [v(T0 + i)], Count::bounded(is_mul.clone(), 1)); }
        // sign correction for mulh/mulhsu: HI_signed = HI - SA*B - [mulh]*SB*A (mod 2^32),
        // MULHSU using only SA since it treats B as unsigned. A single boolean borrow
        // suffices (verified by case analysis over SA/SB in the module doc comment).
        let borrow = v(S0);
        b.assert_zero((mulh.clone() + mulhsu.clone()) * borrow.clone() * (borrow.clone() - one.clone()));
        let hi_signed = hi.clone() - v(SA) * v(B) - mulh.clone() * v(SB) * v(A) + borrow * AB::Expr::from_u64(1u64 << 32);
        b.assert_zero(mul.clone() * (v(C) - lo));
        b.assert_zero(mulhu.clone() * (v(C) - hi));
        b.assert_zero((mulh.clone() + mulhsu.clone()) * (v(C) - hi_signed));

        // M2.6 division: `div, divu, rem, remu`. Unsigned-core identity `|A| = Q*|B| + R`,
        // `R < |B|`, with signed variants going through SA/SB and a final sign fix-up. See
        // the module doc comment for the exactness argument and the (deliberate) absence of
        // a separate MIN/-1 overflow selector.
        let is_div = div.clone() + divu.clone() + rem.clone() + remu.clone();
        b.assert_bool(v(DIVZ));
        // is-zero gadget on B: both `B*INVB = 1-DIVZ` *and* `DIVZ*B = 0` are needed — the
        // first alone lets a prover claim DIVZ=1 with INVB=0 even when B != 0 (this is
        // exactly the "wrong DIVZ on a nonzero divisor" cheating test).
        b.assert_zero(is_div.clone() * (v(B) * v(INVB) - (one.clone() - v(DIVZ))));
        b.assert_zero(is_div.clone() * v(DIVZ) * v(B));
        // |A|, |B| as pure expressions — *not* independently byte-decomposed. `A`, `B` are
        // already < 2^32 (their own RANGE8 checks, `is_div` not excluded from `g_ab`), and
        // SA/SB are genuine 0/1 flags tied to A/B's true sign bits (`need_sa`/`need_sb`
        // include div/rem; forced to 0 on divu/remu by the dedicated constraint below) — so
        // `SA=1` structurally implies `A >= 2^31 > 0`, hence `|A| = 2^32-A in (0, 2^31]`,
        // and symmetrically for `|B|`. Both stay < 2^32 with no separate range check.
        // (Deliberately NOT decomposed into T0..3/CARRY0..3: those columns carry an
        // *unconditional* role elsewhere — T0..3 is `mul`'s LO limbs, and CARRY0..3 is
        // forced boolean by the add/sub/cmp adder's own `assert_bool` on every row — so
        // reusing either for `|A|`/`|B|`'s bytes here would conflict with that.)
        let abs_a = v(A) + v(SA) * (AB::Expr::from_u64(1u64 << 32) - AB::Expr::TWO * v(A));
        let abs_b = v(B) + v(SB) * (AB::Expr::from_u64(1u64 << 32) - AB::Expr::TWO * v(B));
        for i in 0..4 {
            bus::RANGE8.lookup_key(b, [v(Q0 + i)], Count::bounded(is_div.clone(), 1));
            bus::RANGE8.lookup_key(b, [v(S0 + i)], Count::bounded(is_div.clone(), 1));
        }
        let q = word(Q0);
        let r = word(S0);
        // `normal`: a genuine (nonzero-divisor) division actually happened on this row.
        let normal = is_div.clone() * (one.clone() - v(DIVZ));
        b.assert_zero(normal.clone() * (abs_a.clone() - q.clone() * abs_b.clone() - r.clone()));
        // R < |B|, via a direct range check on |B| - R - 1 (no per-limb borrow chain
        // needed: the same "small values can't wrap the field" argument as everywhere else
        // in this table — see the module doc comment). Reuses the otherwise-idle SHH/PW for
        // two of the four bytes; DB2/DB3 are new.
        let diff = abs_b.clone() - r.clone() - one.clone();
        let diff_limbs = v(SHH) + c8(1) * v(PW) + c8(2) * v(DB2) + c8(3) * v(DB3);
        b.assert_zero(normal.clone() * (diff - diff_limbs));
        for c in [SHH, PW, DB2, DB3] { bus::RANGE8.lookup_key(b, [v(c)], Count::bounded(normal.clone(), 1)); }
        // Sign fix-up. `mag` selects the row's op-defined magnitude (quotient for div/divu,
        // remainder for rem/remu); `QH3` is forced (by the two-constraint is-zero gadget
        // below, reusing `INV`) to `[mag == 0]`. Without gating the correction by
        // `1 - QH3`, the naive `mag + neg*(2^32-2*mag)` formula gives `2^32` (out of range)
        // whenever `mag = 0` and `neg = 1` — an ordinary case (e.g. REM(-4, 2) = 0), not
        // just the MIN/-1 edge case — which is why this gate exists.
        let mag = (div.clone() + divu.clone()) * q.clone() + (rem.clone() + remu.clone()) * r.clone();
        b.assert_zero(normal.clone() * (mag.clone() * v(INV) - (one.clone() - v(QH3))));
        b.assert_zero(normal.clone() * v(QH3) * mag.clone());
        let neg = div.clone() * (v(SA) + v(SB) - AB::Expr::TWO * v(SA) * v(SB)) + rem.clone() * v(SA);
        let c_signed = mag.clone() + neg * (one.clone() - v(QH3)) * (AB::Expr::from_u64(1u64 << 32) - AB::Expr::TWO * mag);
        b.assert_zero(normal.clone() * (v(C) - c_signed));
        // DIVZ path: DIV/DIVU -> 0xffff_ffff; REM/REMU -> the original dividend `A`.
        b.assert_zero(v(DIVZ) * (div.clone() + divu.clone()) * (v(C) - AB::Expr::from_u64(0xffff_ffff)));
        b.assert_zero(v(DIVZ) * (rem.clone() + remu.clone()) * (v(C) - v(A)));
        // Unsigned variants never claim a sign (closes the same forgery the `(divu+remu)`
        // exclusion from `need_sa`/`need_sb` leaves open otherwise: without this, a
        // dishonest witness could set SA/SB nonzero on a divu/remu row even though nothing
        // looks them up there).
        b.assert_zero((divu.clone() + remu.clone()) * (v(SA) + v(SB)));

        // provide (op, a, b, c)
        let mut op = AB::Expr::ZERO;
        for i in 0..AluOp::COUNT { op += v(FLAG0 + i) * AB::Expr::from_u32(i as u32); }
        bus::ALU.table_entry(b, [op, v(A), v(B), v(C)], v(MULT));
    }
}

fn set_limbs(row: &mut [F], base: usize, x: u32, range: &mut RangeCounts, count: bool) {
    let l = limbs(x);
    for i in 0..4 { row[base + i] = l[i]; if count { range.range8((x >> (8 * i)) & 0xff); } }
}

/// Sets `hi_col` to `byte`'s high nibble and `sa_col` to its top bit, counting the
/// dummy low-nibble range check and the real `AND4[hi,8,sa*8]` extraction lookup.
fn sign_bit(row: &mut [F], byte: u32, hi_col: usize, sa_col: usize, nibble: &mut NibbleCounts) {
    let lo = byte & 0xf;
    let hi = byte >> 4;
    row[hi_col] = F::from_u32(hi);
    row[sa_col] = F::from_u32(hi >> 3); // top bit of the nibble == top bit of the byte
    nibble.and4(lo, 0);
    nibble.and4(hi, 8);
}

/// Fill one ALU row from an event and count its RANGE8/AND4/OR4/XOR4/POW2 lookups.
pub fn fill_row(row: &mut [F], ev: &AluEvent, range: &mut RangeCounts, nibble: &mut NibbleCounts) {
    let AluEvent { op, a, b, c } = *ev;
    assert_eq!(c, op.eval(a, b), "ALU event {op:?}({a:#x}, {b:#x}) = {c:#x} does not match reference semantics");
    row[FLAG0 + op.code() as usize] = F::ONE;
    row[A] = F::from_u32(a); row[B] = F::from_u32(b); row[C] = F::from_u32(c);
    row[IS_REAL] = F::ONE; row[MULT] = F::ONE;
    // Mirror the AIR's `g_ab`/`g_c` gates exactly: bitwise rows (And/Or/Xor) don't count
    // A/B/C's RANGE8 lookups at all (the nibble lookups below bind them instead); cmp/eq
    // rows (Slt/Sltu/Eq) count A/B but not C (C's own boolean constraint binds it instead).
    let count_ab = !matches!(op, AluOp::And | AluOp::Or | AluOp::Xor);
    let count_c = count_ab && !matches!(op, AluOp::Slt | AluOp::Sltu | AluOp::Eq);
    set_limbs(row, A0, a, range, count_ab); set_limbs(row, B0, b, range, count_ab); set_limbs(row, C0, c, range, count_c);
    let (a3, b3, b0) = ((a >> 24) & 0xff, (b >> 24) & 0xff, b & 0xff);
    let adder = |row: &mut [F], x: u32, y: u32| {
        // carries of x + y limb-wise
        let mut carry = 0u32;
        for i in 0..4 {
            let s = ((x >> (8 * i)) & 0xff) + ((y >> (8 * i)) & 0xff) + carry;
            carry = s >> 8;
            row[CARRY0 + i] = F::from_u32(carry);
        }
    };
    match op {
        AluOp::Add => adder(row, a, b),
        AluOp::Sub => adder(row, b, c),
        AluOp::Slt | AluOp::Sltu => {
            let d = a.wrapping_sub(b);
            set_limbs(row, S0, d, range, true);
            adder(row, b, d);
            if op == AluOp::Slt {
                sign_bit(row, a3, AH3, SA, nibble);
                sign_bit(row, b3, BH_N, SB, nibble);
            }
        }
        AluOp::Eq => { if a != b { row[INV] = (F::from_u32(a) - F::from_u32(b)).inverse(); } }
        AluOp::And | AluOp::Or | AluOp::Xor => {
            for i in 0..4 {
                let (ab, bb, cb) = ((a >> (8 * i)) & 0xff, (b >> (8 * i)) & 0xff, (c >> (8 * i)) & 0xff);
                let (al, ah) = (ab & 0xf, ab >> 4);
                let (bl, bh) = (bb & 0xf, bb >> 4);
                let cl = cb & 0xf;
                row[Q0 + i] = F::from_u32(al);
                row[S0 + i] = F::from_u32(bl);
                row[T0 + i] = F::from_u32(cl);
                match op {
                    AluOp::And => { nibble.and4(al, bl); nibble.and4(ah, bh); }
                    AluOp::Or => { nibble.or4(al, bl); nibble.or4(ah, bh); }
                    AluOp::Xor => { nibble.xor4(al, bl); nibble.xor4(ah, bh); }
                    _ => unreachable!(),
                }
            }
        }
        AluOp::Sll | AluOp::Srl | AluOp::Sra => {
            let sh = b & 31; let pw = 1u32 << sh;
            row[PW] = F::from_u32(pw);
            // shift-amount decomposition: b0's low nibble (implied, not stored — see the
            // eval comment) plus BH_N (b0's high nibble) and SHH = BH_N's bottom bit.
            let bh_n = b0 >> 4;
            row[BH_N] = F::from_u32(bh_n);
            row[SHH] = F::from_u32(bh_n & 1);
            nibble.and4(b0 & 0xf, 0);
            nibble.and4(bh_n, 1);
            range.pow2(sh);
            if op == AluOp::Sll {
                let hi = ((a as u64 * pw as u64) >> 32) as u32;
                set_limbs(row, Q0, hi, range, true);
                let hi3 = (hi >> 24) & 0xff;
                let qh3 = hi3 >> 4;
                row[QH3] = F::from_u32(qh3);
                nibble.and4(hi3 & 0xf, 0);
                nibble.and4(qh3, 8);
            } else {
                let sa = if op == AluOp::Sra { a >> 31 } else { 0 };
                if op == AluOp::Sra { sign_bit(row, a3, AH3, SA, nibble); }
                let ap = if sa == 1 { !a } else { a };
                let q = ap >> sh; let r = ap - q * pw; let t = pw - 1 - r;
                set_limbs(row, Q0, q, range, true); set_limbs(row, S0, r, range, true); set_limbs(row, T0, t, range, true);
            }
        }
        AluOp::Mul | AluOp::Mulh | AluOp::Mulhu | AluOp::Mulhsu => {
            let (al, ah) = ((a & 0xffff) as u64, (a >> 16) as u64);
            let (bl, bh) = ((b & 0xffff) as u64, (b >> 16) as u64);
            let t0 = al * bl; let t1 = al * bh + ah * bl; let t2 = ah * bh;
            let n = t0 + (t1 << 16) + (t2 << 32); // exact, == (a as u64) * (b as u64)
            let lo = (n & 0xffff_ffff) as u32;
            let hi = (n >> 32) as u32;
            let carry = (hi as u64) - t2; // HI - T2, exact, honestly < 2^17
            row[Q0] = F::from_u64(t0); row[Q0 + 1] = F::from_u64(t1); row[Q0 + 2] = F::from_u64(t2); row[Q0 + 3] = F::from_u64(carry);
            for i in 0..3 {
                let byte = ((carry >> (8 * i)) & 0xff) as u32;
                row[S0 + 1 + i] = F::from_u32(byte);
                range.range8(byte);
            }
            for i in 0..4 {
                let byte = (lo >> (8 * i)) & 0xff;
                row[T0 + i] = F::from_u32(byte);
                range.range8(byte);
            }
            if matches!(op, AluOp::Mulh | AluOp::Mulhsu) {
                sign_bit(row, a3, AH3, SA, nibble);
                let sa = a >> 31;
                let sb = if op == AluOp::Mulh { sign_bit(row, b3, BH_N, SB, nibble); b >> 31 } else { 0 };
                let correction = (sa as u64) * (b as u64) + if op == AluOp::Mulh { (sb as u64) * (a as u64) } else { 0 };
                let raw = hi as i64 - correction as i64;
                let borrow = if raw < 0 { 1u32 } else { 0u32 };
                row[S0] = F::from_u32(borrow);
                debug_assert_eq!((raw + (borrow as i64) * (1i64 << 32)) as u32, c, "mulh/mulhsu sign-correction borrow mismatch");
            }
        }
        AluOp::Div | AluOp::Divu | AluOp::Rem | AluOp::Remu => {
            let signed = matches!(op, AluOp::Div | AluOp::Rem);
            let sa = if signed { a >> 31 } else { 0 };
            let sb = if signed { b >> 31 } else { 0 };
            if signed {
                sign_bit(row, a3, AH3, SA, nibble);
                sign_bit(row, b3, BH_N, SB, nibble);
            }
            // |A|, |B| as plain u64s — not stored in any column (see the AIR's comment on
            // why T0..3/CARRY0..3 aren't available for this: T0..3 is `mul`'s LO limbs and
            // CARRY0..3 is the add/sub/cmp adder's own unconditionally-boolean carries).
            let abs_a = if sa == 1 { (1u64 << 32) - a as u64 } else { a as u64 };
            let abs_b = if sb == 1 { (1u64 << 32) - b as u64 } else { b as u64 };
            let divz = b == 0;
            row[DIVZ] = F::from_u32(divz as u32);
            row[INVB] = if !divz { F::from_u32(b).inverse() } else { F::ZERO };
            let (q_core, r_core) = if divz { (0u32, 0u32) } else { ((abs_a / abs_b) as u32, (abs_a % abs_b) as u32) };
            set_limbs(row, Q0, q_core, range, true);
            set_limbs(row, S0, r_core, range, true);
            if !divz {
                let diff = abs_b - r_core as u64 - 1;
                let d = diff as u32;
                row[SHH] = F::from_u32(d & 0xff);
                row[PW] = F::from_u32((d >> 8) & 0xff);
                row[DB2] = F::from_u32((d >> 16) & 0xff);
                row[DB3] = F::from_u32((d >> 24) & 0xff);
                for i in 0..4 { range.range8((d >> (8 * i)) & 0xff); }
                let mag = if matches!(op, AluOp::Div | AluOp::Divu) { q_core } else { r_core };
                row[QH3] = F::from_u32((mag == 0) as u32);
                row[INV] = if mag != 0 { F::from_u32(mag).inverse() } else { F::ZERO };
            }
        }
    }
}

pub fn alu_trace(events: &[CycleEvent], height: usize, range: &mut RangeCounts, nibble: &mut NibbleCounts) -> RowMajorMatrix<F> {
    let evs: Vec<&AluEvent> = events.iter().flat_map(|e| e.alu.iter()).collect();
    assert!(evs.len() < height, "alu table needs a padding row: {} ops, height {height}", evs.len());
    let mut v = F::zero_vec(height * WIDTH);
    for (i, ev) in evs.iter().enumerate() { fill_row(&mut v[i * WIDTH..(i + 1) * WIDTH], ev, range, nibble); }
    RowMajorMatrix::new(v, WIDTH)
}
