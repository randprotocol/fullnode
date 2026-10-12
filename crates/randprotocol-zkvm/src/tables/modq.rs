//! The `MODQ` chip (private multisig phase 3): Dilithium2's ring arithmetic mod
//! `q = 8 380 417` as a coprocessor. One 1 024-row block per `SYS_MODQ` call, for the four ops
//! of `crate::modq` (`NTT`, `INTT`, `DOT4`, `MSUB4`), and a chip that owns its memory traffic.
//! Spec: `docs/superpowers/specs/2026-10-11-rvm-modq-chip-design.md` §3.3–§3.5.
//!
//! ## Block geometry
//!
//! `BLOCK = 1024`, the period of the preprocessed columns. Row `r` of a block is read two ways at
//! once:
//!
//! * **transform view** — stage `p = r >> 7`, butterfly `b = r & 127`: eight stages of 128
//!   butterflies are exactly one NTT or INTT of a 256-coefficient polynomial;
//! * **pointwise view** — coefficient `c = r >> 2`, poly `k = r & 3`, `k` fastest: 256
//!   coefficients of four polynomials, so a `DOT4` sum is four adjacent rows.
//!
//! A call is one cpu cycle, so one block per call is what bounds the table's height against the
//! tier (`modq_log_height`).
//!
//! ## Column layout
//!
//! Preprocessed (period 1 024, `pre::WIDTH = 16`): `IS_FIRST`/`IS_LAST` (the block's first and
//! last row), `STAGE` (`p`), `S_FIRST`/`S_LAST` (`p = 0`, `p = 7`), `JF`/`VF` (the NTT pair
//! `(j, j + len)`), `JI`/`VI` (the INTT pair), `ZF` (the NTT twiddle `ζ_{2^p + g}`), `FI` (the INTT
//! outer factor: 1, or `n⁻¹` on stage 7), `ZI` (the INTT twiddle `q − ζ_k`, times `n⁻¹` on stage 7),
//! `PK`/`PC` (`k`, `c`) and `K_FIRST`/`K_LAST` (`k = 0`, `k = 3`).
//!
//! Main (`col::WIDTH = 59`):
//!
//! | columns | what |
//! |---|---|
//! | `IS_REAL`, `CLK`, `BASE`, `A1` | 4 — block-constant; the `MODQ` handshake `(clk, base, a1)` |
//! | `IS_NTT`, `IS_INTT`, `IS_DOT`, `IS_MSUB` | 4 — block-constant one-hot op, sum `= IS_REAL` |
//! | `OUT_BITS`, `A_BITS`, `B_BITS` | 15 — block-constant 5-bit poly offsets |
//! | `U_L`, `V_L`, `W_L` | 9 — byte limbs of the inputs `U`, `V` and the multiplier `W` (`< 2^24`) |
//! | `O0_L`, `D0_L`, `K0_L` | 3 + 3 + 4 — output 0, `q − 1 − O0`, and the quotient |
//! | `O1_L`, `D1_L`, `K1_L` | 3 + 3 + 4 — output 1, likewise |
//! | `IDX_U`, `IDX_V` | 2 — the op-selected butterfly indices (keep the wire messages degree 1) |
//! | `ADDR_U`, `ADDR_V`, `ADDR_W`, `ADDR_O0`, `ADDR_O1` | 5 — the op-selected memory addresses |
//!
//! `4 + 4 + 15 + 9 + 10 + 10 + 2 + 5 = 59`. `U = Σ U_L[i]·256^i`, and likewise `V`, `W`, `O0`,
//! `D0`, `K0`, …: linear forms, not columns.
//!
//! ## The arithmetic, and why byte limbs
//!
//! Every row proves two exact integer identities (spec §3.4 rule 2):
//!
//! ```text
//! O0 + q·K0 = α0·U + β0·V             O1 + q·K1 = α1·U + β1·V + γ1
//! ```
//!
//! with op-selected coefficients `α`/`β`/`γ` (an NTT row is the CT butterfly `(u + ζv, u − ζv)`,
//! an INTT row the GS butterfly `(FI·(u + v), ZI·(u − v))`, a `DOT4` row `O0 = U + W·V`, an
//! `MSUB4` row `O1 = U − W·V`). Goldilocks has `p ≈ 2^64`, and every term is a non-negative
//! integer below `2^50` (`|α|, |β| ≤ q < 2^23`, inputs `< 2^24`), except `MSUB4`'s `−W·V`, which
//! `γ1 = q·2^26 > 2^48` offsets. `K < 2^32` makes `q·K < 2^55`. So neither side can wrap mod `p`,
//! each field identity is an integer identity, and with `0 ≤ O ≤ q − 1` it pins `O = RHS mod q`
//! and `K = ⌊RHS / q⌋` uniquely.
//!
//! Those bounds come from `RANGE8` lookups on 29 byte limbs per real row (spec §3.5): three each
//! for `U`, `V`, `W` and `O`, three for `D = q − 1 − O` (the upper bound that makes the output
//! **canonical**), four for each `K`. A shifted lookup of `2^k·x` alone would not bound `x`, so
//! there are none. No new table, and ~210 fewer columns than a bit decomposition.
//!
//! ## Wires between stages
//!
//! A transform's seven inter-stage hand-offs never touch memory: stage `p` sends its outputs on
//! `MODQ_WIRE` as `[CLK, p + 1, index, value]`, stage `p + 1` receives its inputs under the same
//! key. Within a stage `IDX_U`/`IDX_V` cover `0..256` exactly once, and `CLK` is unique per real
//! block (the cpu's `MODQ` lookup), so the permutation check fixes every hand-off's value.
//!
//! ## Degree
//!
//! Every rule is degree ≤ 3: rule 2's `IS_DOT·W·V`, `IS_MSUB·W·V`, `IS_INTT·ZI·U` terms, and
//! rule 4's gated transitions. Bus messages are degree 1, counts degree ≤ 2.
//!
//! ## Padding
//!
//! A padding block has every selector zero (`IS_REAL = 0`, so the one-hot sum zeroes the op
//! bits), which zeroes every coefficient, address, index and bus count; its outputs and quotients
//! are 0 and its `D` limbs are those of `q − 1`. No `RANGE8` lookups (their count is `IS_REAL`).
//!
//! ## The chip's memory traffic
//!
//! As `sha256`: the cpu row only looks up `(CLK, BASE, A1)` on `MODQ`; this table sends every
//! word the call reads at `ts = 4·CLK` and every word it writes at `ts = 4·CLK + 1` on `MEMORY`
//! (rule 6), at most five sends per row, each with a 0/1 count. A transform reads on stage 0 and
//! writes on stage 7; `DOT4` reads `V`, `W` every row and writes `O0` on `k = 3`; `MSUB4` reads `U`
//! and `V` every row, `W` (the broadcast `ĉ[c]`) once on `k = 0` — carried by rule 4, because four
//! reads at one `(addr, ts)` would break the memory table's strict order — and writes `O1` every
//! row. `MODQ` is a lookup with no `MULT`: a real block is always claimed.
use super::range::RangeCounts;
use super::{bus, F};
use crate::emulator::SPACE_RAM;
use crate::modq::{self, Args, Op, Poly, N, N_INV, Q};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

/// Rows per call: 8 stages × 128 butterflies, or 256 coefficients × 4 polys.
pub const BLOCK: usize = 1024;
/// One block: the floor for a table that exists at all (above the private floor 7).
pub const MIN_LOG_HEIGHT: u8 = 10;
/// The flat defensive ceiling on a declared `modq_log_height` (1 024 calls).
pub const MAX_LOG_HEIGHT: u8 = 20;

/// Butterflies per stage.
const HALF: usize = N / 2;
/// Transform stages.
const STAGES: usize = 8;
/// `MSUB4`'s offset, `q·2^26 > 2^48 > W·V`, keeps the right-hand side non-negative.
const MSUB_OFFSET: u64 = (Q as u64) << 26;

pub mod pre {
    pub const IS_FIRST: usize = 0;
    pub const IS_LAST: usize = 1;
    /// `p = r >> 7`.
    pub const STAGE: usize = 2;
    /// `p = 0`, `p = 7`.
    pub const S_FIRST: usize = 3;
    pub const S_LAST: usize = 4;
    /// NTT pair `(j, j + len)` at stage `p`.
    pub const JF: usize = 5;
    pub const VF: usize = 6;
    /// INTT pair `(j, j + len)` at stage `p`.
    pub const JI: usize = 7;
    pub const VI: usize = 8;
    /// NTT `ζ_{2^p + g}`.
    pub const ZF: usize = 9;
    /// INTT outer factor: 1, or `n⁻¹` on stage 7.
    pub const FI: usize = 10;
    /// INTT `q − ζ_k`, or `n⁻¹·(q − ζ_k) mod q` on stage 7.
    pub const ZI: usize = 11;
    /// `k = r & 3`, `c = r >> 2`.
    pub const PK: usize = 12;
    pub const PC: usize = 13;
    /// `k = 0`, `k = 3`.
    pub const K_FIRST: usize = 14;
    pub const K_LAST: usize = 15;
    pub const WIDTH: usize = 16;
}

pub mod col {
    pub const IS_REAL: usize = 0;
    pub const CLK: usize = 1;
    pub const BASE: usize = 2;
    /// The `a1` word (spec §3.1).
    pub const A1: usize = 3;
    pub const IS_NTT: usize = 4;
    pub const IS_INTT: usize = 5;
    pub const IS_DOT: usize = 6;
    pub const IS_MSUB: usize = 7;
    /// 5 bits each, little-endian.
    pub const OUT_BITS: usize = 8;
    pub const A_BITS: usize = 13;
    pub const B_BITS: usize = 18;
    /// 3 byte limbs each.
    pub const U_L: usize = 23;
    pub const V_L: usize = 26;
    pub const W_L: usize = 29;
    pub const O0_L: usize = 32;
    pub const D0_L: usize = 35;
    /// 4 byte limbs.
    pub const K0_L: usize = 38;
    pub const O1_L: usize = 42;
    pub const D1_L: usize = 45;
    pub const K1_L: usize = 48;
    pub const IDX_U: usize = 52;
    pub const IDX_V: usize = 53;
    pub const ADDR_U: usize = 54;
    pub const ADDR_V: usize = 55;
    pub const ADDR_W: usize = 56;
    pub const ADDR_O0: usize = 57;
    pub const ADDR_O1: usize = 58;
    pub const WIDTH: usize = 59;
    /// The block-constant columns: `IS_REAL ..= B_BITS + 4`.
    pub const BLOCK_CONSTANT: usize = 23;
}

/// The byte-limb groups and their widths, in rule-8 order: 29 `RANGE8` lookups per real row.
const LIMBS: [(usize, usize); 9] = [
    (col::U_L, 3),
    (col::V_L, 3),
    (col::W_L, 3),
    (col::O0_L, 3),
    (col::D0_L, 3),
    (col::K0_L, 4),
    (col::O1_L, 3),
    (col::D1_L, 3),
    (col::K1_L, 4),
];

/// `Σ_{i<n} row[base + i]·256^i` (`n = 1` reads a whole cell).
pub fn limbs_value(row: &[F], base: usize, n: usize) -> u64 {
    (0..n).map(|i| row[base + i].as_canonical_u64() << (8 * i)).sum()
}

/// One `SYS_MODQ` call: the cpu row's `CLK`, the syscall's `BASE` and `a1`, and the input
/// polynomials in `modq::CallIo::inputs` order (`NTT`/`INTT` `[p]`; `DOT4` `[a0..a3, b0..b3]`;
/// `MSUB4` `[w0..w3, c, t0..t3]`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModqEvent {
    pub clk: u32,
    pub base: u32,
    pub a1: u32,
    pub inputs: Vec<Poly>,
}

/// `0` for no calls (no modq table); otherwise one block per call, rounded up to a power of two,
/// floored at one block.
pub fn modq_log_height(n_calls: usize) -> u8 {
    if n_calls == 0 {
        return 0;
    }
    (super::pad_height(BLOCK * n_calls, BLOCK).trailing_zeros() as u8).max(super::MIN_PRIVATE_TABLE_LOG_HEIGHT)
}

/// NTT stage `p`, butterfly `b`: `(j, j + len, ζ index)`.
fn ntt_pair(p: usize, b: usize) -> (usize, usize, usize) {
    let len = HALF >> p;
    let g = b / len;
    let j = 2 * len * g + b % len;
    (j, j + len, (1 << p) + g)
}

/// INTT stage `p`, butterfly `b`: `(j, j + len, ζ index)` — the reference's GS order.
fn intt_pair(p: usize, b: usize) -> (usize, usize, usize) {
    let len = 1usize << p;
    let g = b / len;
    let j = 2 * len * g + b % len;
    (j, j + len, (N >> p) - 1 - g)
}

const QU: u64 = Q as u64;

/// `(FI, ZI)` of INTT stage `p`, butterfly `b`, under a twiddle source `zeta`.
fn intt_factors(p: usize, b: usize, zeta: &dyn Fn(usize) -> u32) -> (u64, u64) {
    let f = if p == STAGES - 1 { N_INV as u64 } else { 1 };
    let zp = QU - zeta(intt_pair(p, b).2) as u64 % QU;
    (f, f * zp % QU)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ModqAir;

impl<Fld: Field> BaseAir<Fld> for ModqAir {
    fn width(&self) -> usize {
        col::WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        pre::WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        unreachable!("call ModqAir::preprocessed_trace_at(height) instead")
    }
}

impl ModqAir {
    /// The 16 periodic columns for a table of `height` rows (a multiple of `BLOCK`).
    pub fn preprocessed_trace_at<Fld: Field>(height: usize) -> RowMajorMatrix<Fld> {
        assert_eq!(height % BLOCK, 0, "modq height must be a multiple of {BLOCK}");
        let mut one = Fld::zero_vec(BLOCK * pre::WIDTH);
        for r in 0..BLOCK {
            let row = &mut one[r * pre::WIDTH..(r + 1) * pre::WIDTH];
            let (p, b, k, c) = (r >> 7, r & 127, r & 3, r >> 2);
            let (jf, vf, zf) = ntt_pair(p, b);
            let (ji, vi, _) = intt_pair(p, b);
            let (fi, zi) = intt_factors(p, b, &modq::zeta);
            row[pre::IS_FIRST] = Fld::from_bool(r == 0);
            row[pre::IS_LAST] = Fld::from_bool(r == BLOCK - 1);
            row[pre::STAGE] = Fld::from_usize(p);
            row[pre::S_FIRST] = Fld::from_bool(p == 0);
            row[pre::S_LAST] = Fld::from_bool(p == STAGES - 1);
            row[pre::JF] = Fld::from_usize(jf);
            row[pre::VF] = Fld::from_usize(vf);
            row[pre::JI] = Fld::from_usize(ji);
            row[pre::VI] = Fld::from_usize(vi);
            row[pre::ZF] = Fld::from_u32(modq::zeta(zf));
            row[pre::FI] = Fld::from_u64(fi);
            row[pre::ZI] = Fld::from_u64(zi);
            row[pre::PK] = Fld::from_usize(k);
            row[pre::PC] = Fld::from_usize(c);
            row[pre::K_FIRST] = Fld::from_bool(k == 0);
            row[pre::K_LAST] = Fld::from_bool(k == 3);
        }
        let mut v = Vec::with_capacity(height * pre::WIDTH);
        for _ in 0..height / BLOCK {
            v.extend_from_slice(&one);
        }
        RowMajorMatrix::new(v, pre::WIDTH)
    }
}

impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ModqAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        eval_minus(b, None)
    }
}

/// Cheating-suite hook (spec §5, pre-flight ruling 1): one soundness-bearing line of `ModqAir`,
/// named for the defence it is. `ModqAirWithout(Some(d))` (`cheating` feature) evaluates every
/// constraint but `d`'s, so a test can show a forgery accepted with only `d` off and rejected with
/// it on. `eval_minus(None)` — `ModqAir` itself — names none of these.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "cheating"), allow(dead_code))]
pub enum Defence {
    /// Rule 2's `O0 + q·K0` identity.
    OutputIdentityO0,
    /// Rule 2's `O1 + q·K1` identity.
    OutputIdentityO1,
    /// Rule 2's `D0 = q − 1 − O0` identity and rule 8's three `D0` limb lookups.
    CanonicalO0,
    /// Rule 2's `D1 = q − 1 − O1` identity and rule 8's three `D1` limb lookups.
    CanonicalO1,
    /// Rule 8's three `U` limb lookups.
    InputRangeU,
    /// Rule 8's three `V` limb lookups.
    InputRangeV,
    /// Rule 8's three `W` limb lookups.
    InputRangeW,
    /// Rule 5's four `MODQ_WIRE` interactions (one permutation argument; no line of it is
    /// separable).
    Wire,
    /// Rule 4's `DOT4` start: `IS_DOT·K_FIRST·U = 0`.
    DotStart,
    /// Rule 4's `DOT4` carry: `U' = O0` within a coefficient.
    DotCarry,
    /// Rule 4's `MSUB4` broadcast line.
    MsubCarry,
    /// Rule 1's `A1` identity.
    A1Decomposition,
    /// Rule 1's `T·A = 0`.
    CanonicalArgsA,
    /// Rule 1's `T·B = 0`.
    CanonicalArgsB,
}

/// Cheating-suite hook (`cheating` feature only): `ModqAir` minus one [`Defence`]. `ModqAirWithout(None)` evaluates exactly
/// `ModqAir`'s constraints (a unit test checks it symbolically). `chips()` never builds this type;
/// the production machine cannot reach it.
#[cfg(feature = "cheating")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ModqAirWithout(pub Option<Defence>);

#[cfg(feature = "cheating")]
impl<Fld: Field> BaseAir<Fld> for ModqAirWithout {
    fn width(&self) -> usize {
        col::WIDTH
    }
    fn preprocessed_width(&self) -> usize {
        pre::WIDTH
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Fld>> {
        unreachable!("call ModqAir::preprocessed_trace_at(height) instead")
    }
}

#[cfg(feature = "cheating")]
impl<AB: AirBuilder + InteractionBuilder> Air<AB> for ModqAirWithout
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        eval_minus(b, self.0)
    }
}

/// `ModqAir`'s constraints, less the group `off` names (`None`: all of them, in the same order).
fn eval_minus<AB: AirBuilder + InteractionBuilder>(b: &mut AB, off: Option<Defence>)
where
    AB::F: Field,
{
    let on = |d: Defence| off != Some(d);
    {
        let p = b.preprocessed().clone();
        let m = b.main();
        let pc = |i: usize| -> AB::Expr { p.current(i).unwrap().into() };
        let v = |i: usize| -> AB::Expr { m.current(i).unwrap().into() };
        let n = |i: usize| -> AB::Expr { m.next(i).unwrap().into() };
        let c = |x: u64| AB::Expr::from_u64(x);
        let one = AB::Expr::ONE;
        let q = || c(QU);
        // `Σ_{i<width} cell(base + i)·radix^i`.
        let compose = |cell: &dyn Fn(usize) -> AB::Expr, base: usize, width: usize, radix: u64| -> AB::Expr {
            (0..width).map(|i| cell(base + i) * c(radix.pow(i as u32))).sum()
        };
        let num = |base: usize, width: usize| compose(&v, base, width, 256);
        let next_num = |base: usize, width: usize| compose(&n, base, width, 256);

        let is_real = v(col::IS_REAL);
        let (ntt, intt, dot, msub) = (v(col::IS_NTT), v(col::IS_INTT), v(col::IS_DOT), v(col::IS_MSUB));
        let t = ntt.clone() + intt.clone();
        let out = compose(&v, col::OUT_BITS, 5, 2);
        let a = compose(&v, col::A_BITS, 5, 2);
        let bb = compose(&v, col::B_BITS, 5, 2);

        // --- 1. Booleans, one-hot, the `A1` decomposition, canonical args, block constancy. --
        b.assert_bool(is_real.clone());
        for i in col::IS_NTT..col::BLOCK_CONSTANT {
            b.assert_bool(v(i));
        }
        b.assert_eq(ntt.clone() + intt.clone() + dot.clone() + msub.clone(), is_real.clone());
        // The reserved positions of `a1` have no column, and every column here is boolean, so an
        // `a1` with a reserved bit set has no satisfying assignment.
        if on(Defence::A1Decomposition) {
            b.assert_eq(
                v(col::A1),
                intt.clone()
                    + dot.clone() * c(2)
                    + msub.clone() * c(3)
                    + out.clone() * c(1 << 8)
                    + a.clone() * c(1 << 16)
                    + bb.clone() * c(1 << 24),
            );
        }
        if on(Defence::CanonicalArgsA) {
            b.assert_zero(t.clone() * a.clone());
        }
        if on(Defence::CanonicalArgsB) {
            b.assert_zero(t.clone() * bb.clone());
        }
        {
            let in_block = one.clone() - pc(pre::IS_LAST);
            let mut tr = b.when_transition();
            for i in 0..col::BLOCK_CONSTANT {
                tr.assert_zero(in_block.clone() * (n(i) - v(i)));
            }
        }

        // --- 2. The arithmetic: exact integer identities on byte limbs. ---------------------
        let (u, vv, w) = (num(col::U_L, 3), num(col::V_L, 3), num(col::W_L, 3));
        let (o0, d0, k0) = (num(col::O0_L, 3), num(col::D0_L, 3), num(col::K0_L, 4));
        let (o1, d1, k1) = (num(col::O1_L, 3), num(col::D1_L, 3), num(col::K1_L, 4));
        let (zf, fi, zi) = (pc(pre::ZF), pc(pre::FI), pc(pre::ZI));
        let alpha0 = ntt.clone() + intt.clone() * fi.clone() + dot.clone();
        let beta0 = ntt.clone() * zf.clone() + intt.clone() * fi + dot.clone() * w.clone();
        let alpha1 = ntt.clone() + intt.clone() * zi.clone() + msub.clone();
        let beta1 = ntt.clone() * (q() - zf) + intt.clone() * (q() - zi) - msub.clone() * w.clone();
        let gamma1 = msub.clone() * c(MSUB_OFFSET);
        if on(Defence::OutputIdentityO0) {
            b.assert_eq(o0.clone() + q() * k0, alpha0 * u.clone() + beta0 * vv.clone());
        }
        if on(Defence::OutputIdentityO1) {
            b.assert_eq(o1.clone() + q() * k1, alpha1 * u.clone() + beta1 * vv.clone() + gamma1);
        }
        if on(Defence::CanonicalO0) {
            b.assert_eq(d0, q() - one.clone() - o0.clone());
        }
        if on(Defence::CanonicalO1) {
            b.assert_eq(d1, q() - one.clone() - o1.clone());
        }
        b.assert_zero(t.clone() * w.clone());

        // --- 3. Indices and addresses. ------------------------------------------------------
        let (pk, pcc) = (pc(pre::PK), pc(pre::PC));
        let base = v(col::BASE);
        let poly = |i: AB::Expr| base.clone() + i * c(256);
        b.assert_eq(v(col::IDX_U), ntt.clone() * pc(pre::JF) + intt.clone() * pc(pre::JI));
        b.assert_eq(v(col::IDX_V), ntt.clone() * pc(pre::VF) + intt.clone() * pc(pre::VI));
        let (idx_u, idx_v) = (v(col::IDX_U), v(col::IDX_V));
        b.assert_eq(
            v(col::ADDR_U),
            t.clone() * (poly(out.clone()) + idx_u.clone())
                + msub.clone() * (poly(out.clone() + pk.clone()) + pcc.clone()),
        );
        b.assert_eq(
            v(col::ADDR_V),
            t.clone() * (poly(out.clone()) + idx_v.clone())
                + dot.clone() * (poly(a.clone() + pk.clone()) + pcc.clone())
                + msub.clone() * (poly(bb.clone() + pk.clone()) + pcc.clone()),
        );
        b.assert_eq(
            v(col::ADDR_W),
            dot.clone() * (poly(bb.clone() + pk.clone()) + pcc.clone()) + msub.clone() * (poly(a.clone()) + pcc.clone()),
        );
        b.assert_eq(
            v(col::ADDR_O0),
            t.clone() * (poly(out.clone()) + idx_u.clone()) + dot.clone() * (poly(out.clone()) + pcc.clone()),
        );
        b.assert_eq(
            v(col::ADDR_O1),
            t.clone() * (poly(out.clone()) + idx_v.clone()) + msub.clone() * (poly(out.clone() + pk) + pcc),
        );

        // --- 4. Pointwise chaining: the `DOT4` running sum, the `MSUB4` broadcast. -----------
        let (k_first, k_last) = (pc(pre::K_FIRST), pc(pre::K_LAST));
        if on(Defence::DotStart) {
            b.assert_zero(dot.clone() * k_first.clone() * u.clone());
        }
        {
            let mut tr = b.when_transition();
            let carry = one.clone() - k_last.clone();
            if on(Defence::DotCarry) {
                tr.assert_zero(dot.clone() * carry.clone() * (next_num(col::U_L, 3) - o0.clone()));
            }
            if on(Defence::MsubCarry) {
                tr.assert_zero(msub.clone() * carry * (next_num(col::W_L, 3) - w.clone()));
            }
        }

        // --- 5. `MODQ_WIRE`: a transform's inter-stage hand-offs. --------------------------
        let (stage, s_first, s_last) = (pc(pre::STAGE), pc(pre::S_FIRST), pc(pre::S_LAST));
        let clk = v(col::CLK);
        let sends = t.clone() * (one.clone() - s_last.clone());
        let recvs = t.clone() * (one.clone() - s_first.clone());
        if on(Defence::Wire) {
            for (idx, val) in [(idx_u.clone(), o0.clone()), (idx_v.clone(), o1.clone())] {
                bus::MODQ_WIRE.send(b, [clk.clone(), stage.clone() + one.clone(), idx, val], Count::bounded(sends.clone(), 1));
            }
            for (idx, val) in [(idx_u, u.clone()), (idx_v, vv.clone())] {
                bus::MODQ_WIRE.receive(b, [clk.clone(), stage.clone(), idx, val], Count::bounded(recvs.clone(), 1));
            }
        }

        // --- 6. `MEMORY`: the chip's own reads (slot 0) and writes (slot 1). ----------------
        let space = c(SPACE_RAM as u64);
        let ts_read = clk.clone() * c(4);
        let ts_write = clk.clone() * c(4) + one.clone();
        let sends = [
            (col::ADDR_U, ts_read.clone(), u, false, t.clone() * s_first.clone() + msub.clone()),
            (col::ADDR_V, ts_read.clone(), vv, false, t.clone() * s_first + dot.clone() + msub.clone()),
            (col::ADDR_W, ts_read, w, false, dot.clone() + msub.clone() * k_first),
            (col::ADDR_O0, ts_write.clone(), o0, true, t.clone() * s_last.clone() + dot * k_last),
            (col::ADDR_O1, ts_write, o1, true, t * s_last + msub),
        ];
        for (addr, ts, value, is_write, count) in sends {
            bus::MEMORY.send(
                b,
                [space.clone(), v(addr), ts, value, AB::Expr::from_bool(is_write)],
                Count::bounded(count, 1),
            );
        }

        // --- 7. `MODQ`: one entry per real block, on its first row. ------------------------
        bus::MODQ.table_entry(b, [clk, base, v(col::A1)], is_real.clone() * pc(pre::IS_FIRST));

        // --- 8. `RANGE8`: the 29 limbs of every real row. ----------------------------------
        for (start, width) in LIMBS {
            if !limb_group_on(start, off) {
                continue;
            }
            for i in 0..width {
                bus::RANGE8.lookup_key(b, [v(start + i)], Count::bounded(is_real.clone(), 1));
            }
        }
    }
}

/// Whether rule 8 looks up the limb group starting at `start` with `off` switched off.
fn limb_group_on(start: usize, off: Option<Defence>) -> bool {
    match off {
        Some(Defence::InputRangeU) => start != col::U_L,
        Some(Defence::InputRangeV) => start != col::V_L,
        Some(Defence::InputRangeW) => start != col::W_L,
        Some(Defence::CanonicalO0) => start != col::D0_L,
        Some(Defence::CanonicalO1) => start != col::D1_L,
        _ => true,
    }
}

/// Write `x` into `row[base .. base + n]` as `n` little-endian bytes, counting each on `RANGE8`
/// when `range` is given.
fn put_limbs(row: &mut [F], base: usize, n: usize, x: u64, range: Option<&mut RangeCounts>) {
    assert!(x < 1u64 << (8 * n), "modq trace: {x} does not fit {n} bytes");
    for i in 0..n {
        row[base + i] = F::from_u64((x >> (8 * i)) & 0xff);
    }
    if let Some(r) = range {
        for i in 0..n {
            r.range8(((x >> (8 * i)) & 0xff) as u32);
        }
    }
}

/// The eight stage states of a transform under a twiddle source (`[0]` the input, `[8]` the
/// result): `modq::ntt_stages`/`intt_stages` with `zeta` swapped in.
fn stages(input: &Poly, inverse: bool, zeta: &dyn Fn(usize) -> u32) -> [Poly; STAGES + 1] {
    let mut s = [[0u32; N]; STAGES + 1];
    s[0] = *input;
    for p in 0..STAGES {
        for bf in 0..HALF {
            let (j, jl, _) = if inverse { intt_pair(p, bf) } else { ntt_pair(p, bf) };
            let (u, v) = (s[p][j] as u64 % QU, s[p][jl] as u64 % QU);
            let (o0, o1) = if inverse {
                let (f, zi) = intt_factors(p, bf, zeta);
                (f * ((u + v) % QU) % QU, zi * ((u + QU - v) % QU) % QU)
            } else {
                let z = zeta(ntt_pair(p, bf).2) as u64 % QU;
                let tv = z * v % QU;
                ((u + tv) % QU, (u + QU - tv) % QU)
            };
            s[p + 1][j] = o0 as u32;
            s[p + 1][jl] = o1 as u32;
        }
    }
    s
}

/// The real-row fields: `(U, V, W, O0, K0, O1, K1, IDX_U, IDX_V, [ADDR_U, ADDR_V, ADDR_W,
/// ADDR_O0, ADDR_O1])`.
#[derive(Clone, Copy)]
struct Row {
    u: u64,
    v: u64,
    w: u64,
    o0: u64,
    k0: u64,
    o1: u64,
    k1: u64,
    idx: (usize, usize),
    addr: [u32; 5],
}

/// `RHS → (RHS mod q, ⌊RHS / q⌋)`.
fn split(rhs: u128) -> (u64, u64) {
    ((rhs % QU as u128) as u64, (rhs / QU as u128) as u64)
}

/// The value-level lie `forge_block` plants in one block (spec §5). `Honest` is `modq_trace`'s
/// witness. Whatever a lie changes, every later value of the block is recomputed from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "cheating"), allow(dead_code))]
enum BlockLie {
    Honest,
    NonCanonicalO0 { stage: usize },
    NonCanonicalO1 { stage: usize },
    SwapUV { stage: usize },
    ButterflyOutput { stage: usize, delta: u32 },
    ButterflyOutputO1 { stage: usize, delta: u32 },
    ReadValue { delta: u32 },
    DotStart { coefficient: usize, delta: u32 },
    DotCarry { coefficient: usize, k: usize, delta: u32 },
    MsubBroadcast { coefficient: usize, k: usize, delta: u32 },
}

/// One block's 1 024 rows for the op and poly offsets `args`, transforms under `zeta`, with `lie`
/// planted where it lands and propagated: a transform's later stages are recomputed from the
/// forged values, a `DOT4` sum carries the forged one, an `MSUB4` row computes with the forged `W`.
fn block_rows(ev: &ModqEvent, args: Args, zeta: &dyn Fn(usize) -> u32, lie: BlockLie) -> Vec<Row> {
    let want_inputs = match args.op {
        Op::Ntt | Op::Intt => 1,
        Op::Dot4 => 8,
        Op::Msub4 => 9,
    };
    assert_eq!(ev.inputs.len(), want_inputs, "modq trace: {:?} takes {want_inputs} input polys", args.op);
    assert!(
        ev.inputs.iter().all(|p| p.iter().all(|&x| x < modq::INPUT_BOUND)),
        "modq trace: an input word is >= 2^24"
    );
    let poly = |i: u32, c: usize| ev.base + 256 * i + c as u32;
    let addmod = |x: u64, d: u32| (x + d as u64) % QU;
    let mut rows = Vec::with_capacity(BLOCK);
    match args.op {
        Op::Ntt | Op::Intt => {
            let inverse = args.op == Op::Intt;
            let pair = |p: usize, bf: usize| if inverse { intt_pair(p, bf) } else { ntt_pair(p, bf) };
            let mut cur: [u64; N] = core::array::from_fn(|i| ev.inputs[0][i] as u64);
            if let BlockLie::ReadValue { delta } = lie {
                let j = pair(0, 0).0;
                cur[j] = addmod(cur[j], delta);
            }
            // The honest stage states, for the debug cross-check below.
            let honest = (lie == BlockLie::Honest).then(|| stages(&ev.inputs[0], inverse, zeta));
            for p in 0..STAGES {
                let mut nxt = [0u64; N];
                let mut fired = false;
                for bf in 0..HALF {
                    let (j, jl, _) = pair(p, bf);
                    let (a0, b0, a1, b1) = if inverse {
                        let (f, zi) = intt_factors(p, bf, zeta);
                        (f, f, zi, QU - zi)
                    } else {
                        let z = zeta(ntt_pair(p, bf).2) as u64 % QU;
                        (1, z, 1, QU - z)
                    };
                    let (mut u, mut v) = (cur[j], cur[jl]);
                    if lie == (BlockLie::SwapUV { stage: p }) && !fired && u != v {
                        core::mem::swap(&mut u, &mut v);
                        fired = true;
                    }
                    let (mut o0, mut k0) = split(a0 as u128 * u as u128 + b0 as u128 * v as u128);
                    let (mut o1, mut k1) = split(a1 as u128 * u as u128 + b1 as u128 * v as u128);
                    match lie {
                        BlockLie::NonCanonicalO0 { stage } if stage == p && !fired && k0 >= 1 => {
                            o0 += QU;
                            k0 -= 1;
                            fired = true;
                        }
                        BlockLie::NonCanonicalO1 { stage } if stage == p && !fired && k1 >= 1 => {
                            o1 += QU;
                            k1 -= 1;
                            fired = true;
                        }
                        BlockLie::ButterflyOutput { stage, delta } if stage == p && !fired => {
                            o0 = addmod(o0, delta);
                            fired = true;
                        }
                        BlockLie::ButterflyOutputO1 { stage, delta } if stage == p && !fired => {
                            o1 = addmod(o1, delta);
                            fired = true;
                        }
                        _ => {}
                    }
                    if let Some(s) = &honest {
                        debug_assert_eq!((o0, o1), (s[p + 1][j] as u64, s[p + 1][jl] as u64), "modq trace: butterfly {p}/{bf}");
                    }
                    nxt[j] = o0;
                    nxt[jl] = o1;
                    let (au, av) = (poly(args.out, j), poly(args.out, jl));
                    rows.push(Row { u, v, w: 0, o0, k0, o1, k1, idx: (j, jl), addr: [au, av, 0, au, av] });
                }
                match lie {
                    BlockLie::NonCanonicalO0 { stage }
                    | BlockLie::NonCanonicalO1 { stage }
                    | BlockLie::SwapUV { stage }
                    | BlockLie::ButterflyOutput { stage, .. }
                    | BlockLie::ButterflyOutputO1 { stage, .. }
                        if stage == p =>
                    {
                        assert!(fired, "forge_block: {lie:?} found no row to land on");
                    }
                    _ => {}
                }
                cur = nxt;
            }
            // With the honest twiddles a transform block must end at the host model's result.
            #[cfg(debug_assertions)]
            if lie == BlockLie::Honest && (1..N).all(|k| zeta(k) == modq::zeta(k)) {
                let mut want = ev.inputs[0];
                if inverse { modq::intt(&mut want) } else { modq::ntt(&mut want) }
                assert!(cur.iter().zip(want.iter()).all(|(&a, &b)| a == b as u64), "modq trace: transform disagrees with crate::modq");
            }
        }
        Op::Dot4 => {
            assert!(matches!(lie, BlockLie::Honest | BlockLie::DotCarry { .. } | BlockLie::DotStart { .. }), "forge_block: {lie:?} on a DOT4 block");
            let mut acc = 0u64; // the running sum
            for r in 0..BLOCK {
                let (k, c) = (r & 3, r >> 2);
                let mut u = if k == 0 { 0 } else { acc };
                match lie {
                    BlockLie::DotCarry { coefficient, k: kk, delta } if coefficient == c && kk == k => u = addmod(u, delta),
                    BlockLie::DotStart { coefficient, delta } if coefficient == c && k == 0 => u = delta as u64 % QU,
                    _ => {}
                }
                let (v, w) = (ev.inputs[k][c] as u64, ev.inputs[4 + k][c] as u64);
                let (o0, k0) = split(u as u128 + w as u128 * v as u128);
                acc = o0;
                let addr = [0, poly(args.a + k as u32, c), poly(args.b + k as u32, c), poly(args.out, c), 0];
                rows.push(Row { u, v, w, o0, k0, o1: 0, k1: 0, idx: (0, 0), addr });
            }
        }
        Op::Msub4 => {
            assert!(matches!(lie, BlockLie::Honest | BlockLie::MsubBroadcast { .. }), "forge_block: {lie:?} on an MSUB4 block");
            for r in 0..BLOCK {
                let (k, c) = (r & 3, r >> 2);
                let (u, v, mut w) = (ev.inputs[k][c] as u64, ev.inputs[5 + k][c] as u64, ev.inputs[4][c] as u64);
                if let BlockLie::MsubBroadcast { coefficient, k: kk, delta } = lie {
                    if coefficient == c && kk == k {
                        w = addmod(w, delta);
                    }
                }
                let (o1, k1) = split(u as u128 + MSUB_OFFSET as u128 - w as u128 * v as u128);
                let ao = poly(args.out + k as u32, c);
                let addr = [ao, poly(args.b + k as u32, c), poly(args.a, c), 0, ao];
                rows.push(Row { u, v, w, o0: 0, k0: 0, o1, k1, idx: (0, 0), addr });
            }
        }
    }
    rows
}

/// `D = q − 1 − O` into `row[base ..]`: three counted bytes when `O` is canonical; otherwise (only
/// `forge_block`'s non-canonical lie) the field element `q − 1 − O` in limb 0, the identity kept
/// and the byte bound broken.
fn put_d(row: &mut [F], base: usize, o: u64, range: &mut RangeCounts) {
    if o < QU {
        put_limbs(row, base, 3, QU - 1 - o, Some(range));
    } else {
        row[base] = F::from_u64(QU - 1) - F::from_u64(o);
        row[base + 1] = F::ZERO;
        row[base + 2] = F::ZERO;
    }
}

/// Write one block: the handshake `(ev.clk, ev.base, ev.a1)`, the op one-hot and poly-offset bits
/// of `args`, and `vals`' rows, counting every limb into `range`.
fn write_block(rows: &mut [F], ev: &ModqEvent, args: Args, vals: &[Row], range: &mut RangeCounts) {
    for (r, x) in vals.iter().enumerate() {
        let row = &mut rows[r * col::WIDTH..(r + 1) * col::WIDTH];
        row[col::IS_REAL] = F::ONE;
        row[col::CLK] = F::from_u32(ev.clk);
        row[col::BASE] = F::from_u32(ev.base);
        row[col::A1] = F::from_u32(ev.a1);
        row[col::IS_NTT + args.op as usize] = F::ONE;
        for i in 0..5 {
            row[col::OUT_BITS + i] = F::from_bool(args.out >> i & 1 == 1);
            row[col::A_BITS + i] = F::from_bool(args.a >> i & 1 == 1);
            row[col::B_BITS + i] = F::from_bool(args.b >> i & 1 == 1);
        }
        put_limbs(row, col::U_L, 3, x.u, Some(range));
        put_limbs(row, col::V_L, 3, x.v, Some(range));
        put_limbs(row, col::W_L, 3, x.w, Some(range));
        put_limbs(row, col::O0_L, 3, x.o0, Some(range));
        put_d(row, col::D0_L, x.o0, range);
        put_limbs(row, col::K0_L, 4, x.k0, Some(range));
        put_limbs(row, col::O1_L, 3, x.o1, Some(range));
        put_d(row, col::D1_L, x.o1, range);
        put_limbs(row, col::K1_L, 4, x.k1, Some(range));
        row[col::IDX_U] = F::from_usize(x.idx.0);
        row[col::IDX_V] = F::from_usize(x.idx.1);
        for (i, a) in x.addr.iter().enumerate() {
            row[col::ADDR_U + i] = F::from_u32(*a);
        }
    }
}

fn fill_block(rows: &mut [F], ev: &ModqEvent, range: &mut RangeCounts, zeta: &dyn Fn(usize) -> u32) {
    let args = Args::decode(ev.a1).unwrap_or_else(|| panic!("modq trace: a1 {:#x} does not decode", ev.a1));
    let vals = block_rows(ev, args, zeta, BlockLie::Honest);
    write_block(rows, ev, args, &vals, range);
}

/// Padding: every selector zero, outputs 0, `D = q − 1`, no `RANGE8` lookups.
fn fill_padding(rows: &mut [F]) {
    for row in rows.chunks_mut(col::WIDTH) {
        put_limbs(row, col::D0_L, 3, QU - 1, None);
        put_limbs(row, col::D1_L, 3, QU - 1, None);
    }
}

// ---- Cheating-suite hooks (spec §5, pre-flight ruling 1) ------------------------------------
// Nothing in `chips()`, `build_traces` or `verify` reaches these.

/// One forgery for `forge_block` (`cheating` feature only). Each names the block (event index)
/// it lands in.
#[cfg(feature = "cheating")]
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lie {
    None,
    /// First row of `stage` with `K0 >= 1`: `O0 += q`, `K0 -= 1`.
    NonCanonicalO0 { block: usize, stage: usize },
    /// First row of `stage` with `K1 >= 1`: `O1 += q`, `K1 -= 1`.
    NonCanonicalO1 { block: usize, stage: usize },
    /// First row of `stage` with `U != V`: swap them.
    SwapUV { block: usize, stage: usize },
    /// `O0 += delta mod q` on the stage's first row, `K0` kept.
    ButterflyOutput { block: usize, stage: usize, delta: u32 },
    /// `O1 += delta mod q` on the stage's first row, `K1` kept.
    ButterflyOutputO1 { block: usize, stage: usize, delta: u32 },
    /// First stage-0 row with `U_L[1] >= 1`: `U_L[0] += 256`, `U_L[1] -= 1` (the value `U` kept).
    InputLimbCarry { block: usize },
    /// `InputLimbCarry` on `V_L`: the block's first row with `V_L[1] >= 1`.
    InputLimbCarryV { block: usize },
    /// `InputLimbCarry` on `W_L`: the block's first row with `W_L[1] >= 1` (a `DOT4`/`MSUB4` block).
    InputLimbCarryW { block: usize },
    /// `DOT4` row `(coefficient, 0)`: `U = delta mod q` instead of 0, the sum carrying it.
    DotStart { block: usize, coefficient: usize, delta: u32 },
    /// Stage-0 row 0: `U += delta mod q`, a read memory never held.
    ReadValue { block: usize, delta: u32 },
    /// `DOT4` row `(coefficient, k)`: `U += delta mod q`, the running sum broken.
    DotCarry { block: usize, coefficient: usize, k: usize, delta: u32 },
    /// `MSUB4` row `(coefficient, k)`: `W += delta mod q`, the broadcast `ĉ` changed.
    MsubBroadcast { block: usize, coefficient: usize, k: usize, delta: u32 },
    /// Recompute the block as `op`, keeping `A1`.
    OpAs { block: usize, op: Op },
    /// Every block computed with `ζ(k % 255 + 1)`.
    ShiftedZetas,
    /// `IS_REAL = IS_NTT = 1` on a padding block: the zero NTT at `(CLK, BASE, A1) = (0, 0, 0)`.
    RealPadding { block: usize },
    /// `machine::build_traces_forged` only: no modq table at all, and none of its memory traffic
    /// or range counts.
    NoModqTable,
}

/// A forged modq trace, consistent everywhere but the lie: its `RANGE8` counts (every in-range
/// limb of every real row; an out-of-range limb is omitted) and the `MEMORY` accesses its rows
/// send, per block as `(CLK, accesses)`, carrying the forged values.
#[cfg(feature = "cheating")]
#[doc(hidden)]
pub struct Forged {
    pub trace: RowMajorMatrix<F>,
    pub range: RangeCounts,
    pub accesses: Vec<(u32, Vec<crate::emulator::MemAccess>)>,
}

/// Build the modq trace of `events` with `lie` planted (spec §5): `K` and `D` are recomputed on
/// every row, a transform's later stages and the block's memory writes are re-derived from the
/// lie, and the range counts and memory accesses are read back off the forged trace. `a1` is
/// decoded as `modq::call_unchecked` does (valid fields only).
#[cfg(feature = "cheating")]
#[doc(hidden)]
pub fn forge_block(events: &[ModqEvent], log_height: u8, lie: Lie) -> Forged {
    assert!((MIN_LOG_HEIGHT..=MAX_LOG_HEIGHT).contains(&log_height), "modq log height {log_height}");
    let height = 1usize << log_height;
    assert!(events.len() <= height / BLOCK, "modq table needs {} blocks, height {height}", events.len());
    let shifted = |k: usize| modq::zeta(k % 255 + 1);
    let zeta: &dyn Fn(usize) -> u32 = if lie == Lie::ShiftedZetas { &shifted } else { &modq::zeta };
    assert_ne!(lie, Lie::NoModqTable, "forge_block: NoModqTable is build_traces_forged's");
    let zero_ntt = ModqEvent { clk: 0, base: 0, a1: 0, inputs: vec![[0; N]] };
    if let Lie::RealPadding { block } = lie {
        assert!(block >= events.len() && block < height / BLOCK, "forge_block: block {block} is not padding");
    }
    let mut v = F::zero_vec(height * col::WIDTH);
    let mut scratch = RangeCounts::default();
    for (blk, rows) in v.chunks_mut(BLOCK * col::WIDTH).enumerate() {
        let ev = match events.get(blk) {
            Some(ev) => ev,
            None if lie == (Lie::RealPadding { block: blk }) => &zero_ntt,
            None => {
                fill_padding(rows);
                continue;
            }
        };
        let mut args = Args::decode_fields(ev.a1);
        let here = |b: usize| b == blk;
        let block_lie = match lie {
            Lie::NonCanonicalO0 { block, stage } if here(block) => BlockLie::NonCanonicalO0 { stage },
            Lie::NonCanonicalO1 { block, stage } if here(block) => BlockLie::NonCanonicalO1 { stage },
            Lie::ButterflyOutputO1 { block, stage, delta } if here(block) => BlockLie::ButterflyOutputO1 { stage, delta },
            Lie::DotStart { block, coefficient, delta } if here(block) => BlockLie::DotStart { coefficient, delta },
            Lie::SwapUV { block, stage } if here(block) => BlockLie::SwapUV { stage },
            Lie::ButterflyOutput { block, stage, delta } if here(block) => BlockLie::ButterflyOutput { stage, delta },
            Lie::ReadValue { block, delta } if here(block) => BlockLie::ReadValue { delta },
            Lie::DotCarry { block, coefficient, k, delta } if here(block) => BlockLie::DotCarry { coefficient, k, delta },
            Lie::MsubBroadcast { block, coefficient, k, delta } if here(block) => BlockLie::MsubBroadcast { coefficient, k, delta },
            _ => BlockLie::Honest,
        };
        if let Lie::OpAs { block, op } = lie {
            if here(block) {
                assert_ne!(args.op, op, "forge_block: OpAs must change the op");
                args.op = op;
            }
        }
        let vals = block_rows(ev, args, zeta, block_lie);
        write_block(rows, ev, args, &vals, &mut scratch);
        let carry = match lie {
            Lie::InputLimbCarry { block } if here(block) => Some((col::U_L, HALF)),
            Lie::InputLimbCarryV { block } if here(block) => Some((col::V_L, BLOCK)),
            Lie::InputLimbCarryW { block } if here(block) => Some((col::W_L, BLOCK)),
            _ => None,
        };
        if let Some((limb, within)) = carry {
            let r = (0..within)
                .find(|r| rows[r * col::WIDTH + limb + 1] != F::ZERO)
                .unwrap_or_else(|| panic!("forge_block: {lie:?} found no row with limb 1 >= 1"));
            rows[r * col::WIDTH + limb] += F::from_u32(256);
            rows[r * col::WIDTH + limb + 1] -= F::ONE;
        }
    }
    let trace = RowMajorMatrix::new(v, col::WIDTH);
    Forged { range: range_counts_without(&trace, None), accesses: accesses_of(&trace), trace }
}

/// The `RANGE8` counts rule 8 asks for with `off` switched off: every in-range limb of every real
/// row, limb groups `off` skips left out. A limb `>= 256` is not counted, so its lookup (if on)
/// cannot balance.
#[cfg(feature = "cheating")]
#[doc(hidden)]
pub fn range_counts_without(trace: &RowMajorMatrix<F>, off: Option<Defence>) -> RangeCounts {
    let mut r = RangeCounts::default();
    for row in trace.values.chunks(col::WIDTH) {
        if row[col::IS_REAL] != F::ONE {
            continue;
        }
        for (start, width) in LIMBS {
            if !limb_group_on(start, off) {
                continue;
            }
            for i in 0..width {
                let x = row[start + i].as_canonical_u64();
                if x < 256 {
                    r.range8(x as u32);
                }
            }
        }
    }
    r
}

/// The `MEMORY` sends of rule 6, read off a trace: per real block, `(CLK, reads at slot 0 then
/// writes at slot 1)`.
#[cfg(feature = "cheating")]
fn accesses_of(trace: &RowMajorMatrix<F>) -> Vec<(u32, Vec<crate::emulator::MemAccess>)> {
    use crate::emulator::MemAccess;
    let mut out = Vec::new();
    for blk in trace.values.chunks(BLOCK * col::WIDTH) {
        if blk[col::IS_REAL] != F::ONE {
            continue;
        }
        let clk = blk[col::CLK].as_canonical_u64() as u32;
        let (mut reads, mut writes) = (Vec::new(), Vec::new());
        for (r, row) in blk.chunks(col::WIDTH).enumerate() {
            let is = |c: usize| row[c] == F::ONE;
            let (t, dot, msub) = (is(col::IS_NTT) || is(col::IS_INTT), is(col::IS_DOT), is(col::IS_MSUB));
            let (s_first, s_last, k_first, k_last) = (r >> 7 == 0, r >> 7 == STAGES - 1, r & 3 == 0, r & 3 == 3);
            let acc = |addr: usize, val: usize, w: bool| MemAccess {
                space: SPACE_RAM,
                addr: row[addr].as_canonical_u64() as u32,
                slot: w as u32,
                value: limbs_value(row, val, 3) as u32,
                is_write: w,
            };
            if (t && s_first) || msub { reads.push(acc(col::ADDR_U, col::U_L, false)); }
            if (t && s_first) || dot || msub { reads.push(acc(col::ADDR_V, col::V_L, false)); }
            if dot || (msub && k_first) { reads.push(acc(col::ADDR_W, col::W_L, false)); }
            if (t && s_last) || (dot && k_last) { writes.push(acc(col::ADDR_O0, col::O0_L, true)); }
            if (t && s_last) || msub { writes.push(acc(col::ADDR_O1, col::O1_L, true)); }
        }
        reads.extend(writes);
        out.push((clk, reads));
    }
    out
}

/// `modq_trace` with the transforms' twiddles taken from `zeta` instead of `modq::zeta`: a
/// self-consistent block for the wrong-ζ forgery (spec §5). The preprocessed `ZF`/`ZI` are
/// always the honest ones, so such a block is rejected.
#[doc(hidden)]
pub fn modq_trace_with_zetas(
    events: &[ModqEvent],
    log_height: u8,
    range: &mut RangeCounts,
    zeta: &dyn Fn(usize) -> u32,
) -> RowMajorMatrix<F> {
    assert!(
        (MIN_LOG_HEIGHT..=MAX_LOG_HEIGHT).contains(&log_height),
        "modq log height {log_height} outside [{MIN_LOG_HEIGHT}, {MAX_LOG_HEIGHT}]"
    );
    let height = 1usize << log_height;
    assert!(events.len() <= height / BLOCK, "modq table needs {} blocks, height {height}", events.len());
    let mut v = F::zero_vec(height * col::WIDTH);
    for (blk, rows) in v.chunks_mut(BLOCK * col::WIDTH).enumerate() {
        match events.get(blk) {
            Some(ev) => fill_block(rows, ev, range, zeta),
            None => fill_padding(rows),
        }
    }
    RowMajorMatrix::new(v, col::WIDTH)
}

/// One 1 024-row block per event, in event order, then padding blocks up to `1 << log_height`.
/// Counts every real row's 29 limbs into `range`.
pub fn modq_trace(events: &[ModqEvent], log_height: u8, range: &mut RangeCounts) -> RowMajorMatrix<F> {
    modq_trace_with_zetas(events, log_height, range, &modq::zeta)
}

#[cfg(all(test, feature = "cheating"))]
mod tests {
    use super::*;
    use crate::machine::{Challenge, Val};
    use p3_air::symbolic::AirLayout;
    use p3_lookup::InteractionSymbolicBuilder;

    fn symbolic<A>(air: &A) -> (String, String)
    where
        A: BaseAir<Val> + Air<InteractionSymbolicBuilder<Val, Challenge>>,
    {
        let mut sb = InteractionSymbolicBuilder::<Val, Challenge>::new(AirLayout::from_air::<Val>(air));
        air.eval(&mut sb);
        (format!("{:?}", sb.base_constraints()), format!("{:?}", sb.global_interactions()))
    }

    /// The cheating suite's switch is inert when nothing is switched off: `ModqAirWithout(None)`
    /// emits exactly `ModqAir`'s constraints and interactions, in order; every `Some(d)` emits fewer.
    #[test]
    fn modq_air_without_none_is_modq_air() {
        let full = symbolic(&ModqAir);
        assert_eq!(symbolic(&ModqAirWithout(None)), full);
        for d in [
            Defence::OutputIdentityO0,
            Defence::OutputIdentityO1,
            Defence::CanonicalO0,
            Defence::CanonicalO1,
            Defence::InputRangeU,
            Defence::InputRangeV,
            Defence::InputRangeW,
            Defence::Wire,
            Defence::DotStart,
            Defence::DotCarry,
            Defence::MsubCarry,
            Defence::A1Decomposition,
            Defence::CanonicalArgsA,
            Defence::CanonicalArgsB,
        ] {
            assert_ne!(symbolic(&ModqAirWithout(Some(d))), full, "{d:?} must switch something off");
        }
    }
}
