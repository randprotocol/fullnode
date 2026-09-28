//! Constraint set 7 (audit INT-2 / GV-1, the 2026-09-27 zkVM review): the LogUp-terminal blind.
//!
//! **The leak.** A batch proof publishes one LogUp terminal per instance
//! (`BatchProof::lookup_terminals`): the sum over the instance's rows of every message's
//! `multiplicity / (bus_prefix − fingerprint)`, computed by the prover from the raw trace. The
//! challenges behind `bus_prefix` and the fingerprint's `β` are Fiat–Shamir draws from public data,
//! so anyone holding a proof can replay them, build the trace a candidate witness would produce and
//! compare its terminals with the published ones. The terminal is therefore an *unsalted*,
//! checkable commitment to its table's contents: the input table's is a function of a call's private
//! words (whatever `H_IN`'s salt hides), the program table's of how often each instruction ran (on a
//! bundle, which input slots are dummies and the popcount of each real leaf index), and every other
//! table's of its value histogram. `tests/logup_blind.rs` replays exactly that attack.
//!
//! **The blind.** Every instance gets five columns, appended after its own (`machine::Chip` adds
//! them to every table, so no table's column list moves): `OUT0, OUT1` and `IN0, IN1`, two
//! base-field coordinates each of one blinding value, and `FIRST`, the first-row selector as a
//! column. On its **first row** — multiplicity `FIRST`, weight 1 — the instance *sends*
//! `[OUT0, OUT1]` and *receives* `[IN0, IN1]` on the dedicated `BLIND` bus; on every other row all
//! five columns are pinned to zero (a transition constraint on the next row), so they carry nothing
//! there — AGENTS.md invariant 1, message
//! columns pinned wherever the row does not send. The honest prover orders the batch's `N`
//! instances in a fixed cycle (`chips()` order) and draws `N` fresh values `r_0 .. r_{N−1}`:
//! instance `i` sends `r_i` and receives `r_{i−1 mod N}` ([`fresh`]). Nothing else constrains
//! them — a free witness, like any other main-trace column.
//!
//! **What it does to the terminals.** With `P` the `BLIND` bus's prefix and `u(r) = r₀·β + r₁` the
//! fingerprint of a two-coordinate message, instance `i`'s terminal gains
//! `s_i − s_{i−1}`, where `s_i = 1 / (P − u(r_i))`. The shifts cancel around the cycle, so the sum
//! the verifier checks is exactly what it was.
//!
//! **Soundness is unchanged.** `BLIND` is one more global bus, balanced by construction for an
//! honest prover, and for a dishonest one exactly as constrained as every other bus: the `r` values
//! are main-trace columns, committed *before* `(α, β)` are drawn, and `BLIND` has its own prefix
//! offset, so a send/receive multiset that does not balance leaves a non-zero rational function of
//! `α` in the total, which a random `α` does not zero except with probability bounded by its degree
//! over `|F_{p²}|` — the standard LogUp argument, with nothing the prover can choose after the
//! challenge. What a prover *can* do with the columns is balance them some other way, or not blind
//! at all (`r_i` all equal): either only changes what its own proof hides. `tests/cheating.rs`'
//! `mismatched_blinds_are_refused` and `a_blind_on_a_later_row_is_refused` pin the two ways to get
//! it wrong.
//!
//! **Why the shift hides the terminals — and why the blind is an extension element.** The shift is
//! uniform only if `s_i` is. `s ↦ 1/(P − s)` is a bijection of `F_{p²}` minus a point, so `s_i` is
//! uniform exactly when `u(r_i)` is uniform over `F_{p²}`. With `(r₀, r₁)` uniform over `F_p²` and
//! `β ∉ F_p` (probability `1 − 1/p`), `(r₀, r₁) ↦ r₀·β + r₁` is an `F_p`-linear bijection onto
//! `F_{p²}`, so `u(r_i)` is uniform. Given `(α, β)` and the witness, the `s_i` are then i.i.d.
//! uniform (up to the `1/p²` chance that `u(r_i) = P`), so the vector of shifts `(s_i − s_{i−1})_i`
//! is uniform on the hyperplane `{d : Σ d_i = 0}` — and since the unblinded terminals `T⁰` also sum
//! to zero, the published `T = T⁰ + d` is uniform on that hyperplane whatever `T⁰` was: the
//! terminals say nothing about the witness beyond `Σ T = 0`, which the verifier checks anyway.
//!
//! A single base-field coordinate — `~2^64` values per blind — would *not* do, and not for want of
//! entropy: `s_i` would range over the `p`-element set `S = {1/(P − x) : x ∈ F_p}`, a thin curve in
//! `F_{p²}`. An observer testing a candidate `T⁰` against `T` needs one unknown, `s_0 ∈ S`: every
//! `s_i = s_0 + Σ_{j ≤ i} (T_j − T⁰_j)` must land in `S`, and "`x ∈ S`" is the single `F_p`-equation
//! "`P − 1/x` has zero second coordinate". That is `N − 1` equations in one unknown over `F_p` —
//! satisfiable for the true `T⁰` and, for a false one, by about `p · p^{−(N−1)} = p^{2−N}` values
//! of `s_0` in expectation: at the batch's nine to eleven instances, never. So the blind spans the challenge field, two columns
//! each way.
//!
//! **What else a proof opens.** The blind hides the *terminals*. Every other place the table's
//! contents could surface is a hiding-PCS opening: the main and permutation (running-sum) columns
//! are committed through `HidingFriPcs`, which interleaves one uniform row per trace row, and a
//! proof opens each at no more than `num_queries + 2` points — hidden as long as the table has at
//! least that many rows (`tables::MIN_PRIVATE_TABLE_LOG_HEIGHT`'s doc comment has the argument).
//! Constraint set 7 therefore floors **every** declared table at `2^7` rows, verifier-side too
//! (`machine::check_declared_heights`): before it the program table could be 16 rows, the input and
//! public tables 4, the keccak table 32 and the sha256 table 64 — tables whose permutation columns,
//! not only their main columns, an observer could read back. The fixed-height tables are all larger
//! (`range`/`nibble` 256 rows, `cpu` `2^t ≥ 2^10`, `alu`, `memory`, `poseidon2` above that).
use super::{bus, F};
use p3_air::{AirBuilder, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

/// The blind's five columns, as offsets from the table's own width (they are appended after it).
pub mod col {
    /// The two coordinates of the value this instance sends on `BLIND`.
    pub const OUT0: usize = 0;
    pub const OUT1: usize = 1;
    /// The two coordinates of the value it receives — its predecessor's `OUT` in the cycle.
    pub const IN0: usize = 2;
    pub const IN1: usize = 3;
    /// `1` on the first row, `0` on every other — the two messages' multiplicity. A column rather
    /// than the builder's own `is_first_row` selector: with the selector as an interaction's count,
    /// `p3-batch-stark` 0.7 builds proofs its own verifier refuses (`OodEvaluationMismatch` on the
    /// first instance, every honest proof — measured; the same selector in an ordinary
    /// `when_first_row` constraint is fine, and `check_constraints`/`check_lookups` pass on the
    /// trace), so the selector is materialised and pinned instead: `FIRST = 1` on the first row,
    /// `FIRST' = 0` on every transition.
    pub const FIRST: usize = 4;
    pub const WIDTH: usize = 5;
}

/// One instance's first-row blind: `[OUT0, OUT1, IN0, IN1]` (the `FIRST` flag is not a choice, so
/// it is not part of it).
pub type Blind = [F; 4];

/// The blind's constraints and its two messages, for a table whose own columns end at `base`.
pub fn eval<AB: AirBuilder + InteractionBuilder>(b: &mut AB, base: usize) {
    let m = b.main();
    let v = |i: usize| -> AB::Expr { m.current(base + i).unwrap().into() };
    let n = |i: usize| -> AB::Expr { m.next(base + i).unwrap().into() };
    // `FIRST` is the first-row selector, as a column (its doc comment has why): one on the first
    // row, and — with the four value columns — zero on every row after it: row `r + 1` is pinned
    // from row `r`'s transition, which covers rows `1 .. h − 1`. The value columns' pin is not
    // needed for soundness (their multiplicity is zero there), but a message column nothing pins on
    // a row that does not send is exactly what AGENTS.md's invariant 1 forbids.
    b.when_first_row().assert_one(v(col::FIRST));
    for i in 0..col::WIDTH {
        b.when_transition().assert_zero(n(i));
    }
    bus::BLIND.send(b, [v(col::OUT0), v(col::OUT1)], Count::bounded(v(col::FIRST), 1));
    bus::BLIND.receive(b, [v(col::IN0), v(col::IN1)], Count::bounded(v(col::FIRST), 1));
}

/// A uniform base-field element: rejection-sampled from 64-bit draws, so exactly uniform (a plain
/// reduction mod `p` would be `2^-32` off, and the argument above wants uniform).
fn uniform(rng: &mut impl rand::Rng) -> F {
    loop {
        let x = rng.next_u64();
        if x < F::ORDER_U64 {
            return F::from_u64(x);
        }
    }
}

/// Fresh blinds for a batch of `n` instances in `chips()` order, from OS entropy: `n` values
/// `r_i ∈ F_p²`, instance `i` sending `r_i` and receiving `r_{i−1 mod n}`.
pub fn fresh(n: usize) -> Vec<Blind> {
    let mut rng = rand::rng();
    let r: Vec<[F; 2]> = (0..n).map(|_| [uniform(&mut rng), uniform(&mut rng)]).collect();
    (0..n).map(|i| {
        let prev = r[(i + n - 1) % n];
        [r[i][0], r[i][1], prev[0], prev[1]]
    }).collect()
}

/// `trace` with the blind's five columns appended: `blind` and `FIRST = 1` on row 0, zero below.
pub fn widen(trace: &RowMajorMatrix<F>, blind: &Blind) -> RowMajorMatrix<F> {
    let (h, w) = (trace.height(), trace.width());
    let wide = w + col::WIDTH;
    let mut v = Vec::with_capacity(h * wide);
    for r in 0..h {
        v.extend_from_slice(&trace.values[r * w..(r + 1) * w]);
        if r == 0 {
            v.extend_from_slice(blind);
            v.push(F::ONE);
        } else {
            v.extend_from_slice(&[F::ZERO; col::WIDTH]);
        }
    }
    RowMajorMatrix::new(v, wide)
}
