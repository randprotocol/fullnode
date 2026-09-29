//! Shared by the integration tests (`mod common;`), which are separate crates and so cannot
//! `use` each other's items. Home of `rejects()`, the one definition of what counts as "the
//! constraint system caught this" — it lived in `tests/cheating.rs` and had been copied, in
//! slightly weaker form, into `tests/viewing.rs` and `tests/bundle.rs`; the copies drifted
//! (neither accepted `LOOKUP_BALANCE_PANIC`), which is exactly how a test starts passing for
//! the wrong reason. `tests/cheating.rs` owns the test that checks this helper itself
//! (`rejects_only_counts_a_constraint_failure_or_a_verify_error`).
//!
//! Each test crate compiles its own copy of this module and uses only part of it, hence the
//! blanket `dead_code` allow.
#![allow(dead_code)]

/// M4.4 Task 5: the hand-built ELF64 fixtures `tests/sbpf_elf.rs` and `tests/sbpf_abi.rs` share.
pub mod sbpf_elf_builder;

/// M4.4 Task 5: `solana-sbpf` 0.11.1 as the differential oracle for `sbpf-core`. It lives under
/// `common` rather than in `randprotocol_zkvm::sbpf` because it is a dev-dependency and `src/sbpf.rs` is
/// library code; only `tests/sbpf_interp.rs` and `tests/sbpf_elf.rs` use it.
pub mod sbpf_oracle;

use std::panic::{catch_unwind, AssertUnwindSafe};

/// The panic `p3-batch-stark`'s debug constraint checker raises when a row violates a
/// constraint. Its full form is
/// `"constraints not satisfied on row {row_index}: failed constraints = {rendered}"` —
/// the `panic!` at the end of the row loop in
/// `~/.cargo/registry/src/index.crates.io-*/p3-batch-stark-0.7.0/src/check_constraints.rs`
/// (line 132 in that release). Matching the fixed prefix is what separates "the constraint
/// system caught this" from any other unwind. This check runs *per AIR instance*, using only
/// that instance's own trace, so it only catches a violation that's local to one table's own
/// row constraints (e.g. the range table's `mp·(1 − is_pow2) = 0`).
pub const CONSTRAINT_PANIC: &str = "constraints not satisfied on row";

/// The panic `p3-lookup`'s debug bus-balance checker
/// (`p3_lookup::debug_util::check_lookups`, `check_lookups`'s `assert_empty`) raises when a
/// *global* lookup — one whose provider and consumers live in different AIR instances, which
/// is every bus in this crate except the ALU/CPU's shared-table cases — has a nonzero net
/// multiplicity for some tuple, after every instance's own `CONSTRAINT_PANIC` pass has
/// already run clean. For a table with no row-level validity marker of its own — the nibble
/// table's every `(a, b)` row is a genuine AND/OR/XOR entry, unlike the range table's
/// `is_pow2` flag — an unpaid extra multiplicity is *only* visible cross-instance: the row
/// itself is perfectly well-formed, so `CONSTRAINT_PANIC` never fires, and this is the sole
/// mechanism left to catch it. It is exactly as much "the constraint system caught this" as
/// `CONSTRAINT_PANIC` — just checked at the scope of the whole batch instead of one row of
/// one instance.
pub const LOOKUP_BALANCE_PANIC: &str = "Lookup mismatch (";

/// A tamper counts as rejected only if `verify` returned an error, or if the panic came from
/// one of the two constraint-system checks above. Anything else — a trace-builder `assert!`,
/// an index out of bounds — means the test tripped over something other than the constraint
/// it was written for, so it must fail rather than pass for the wrong reason.
pub fn rejects(f: impl FnOnce() -> Result<(), randprotocol_zkvm::machine::VerifyError>) -> bool {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => false,
        Ok(Err(_)) => true,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            let is_constraint = msg.contains(CONSTRAINT_PANIC) || msg.contains(LOOKUP_BALANCE_PANIC);
            if !is_constraint { eprintln!("rejects(): panic was not a constraint failure: {msg}"); }
            is_constraint
        }
    }
}

// ── Symbolic reads of an AIR (`tests/air_invariants.rs`, `tests/next_constraint_set.rs`) ─────
// The recursion crate's `tests/common/mod.rs` helpers, ported: the tests that check a table's
// soundness *rules* — every value the cpu row sends bound, no padding row sending anything — do
// not keep their own list of what a table's `eval` does; they run `eval` through Plonky3's own
// symbolic interaction builder and evaluate the constraints and messages it really emits at
// concrete rows. Deleting a constraint or a send changes what they see. Unlike the rVM's tables,
// five of this machine's read preprocessed columns, so a row here is a main row *and* a
// preprocessed row.
use p3_air::symbolic::{AirLayout, BaseEntry, BaseLeaf, SymbolicExpr, SymbolicExpression};
use randprotocol_zkvm::machine::{Challenge, Val};

pub type Interaction = p3_lookup::SymbolicInteraction<Val>;
pub type Expr = SymbolicExpression<Val>;

/// Every global interaction and base constraint `air.eval` emits.
pub fn symbolic_air<A>(air: &A) -> (Vec<Interaction>, Vec<Expr>)
where
    A: p3_air::BaseAir<Val> + p3_air::Air<p3_lookup::InteractionSymbolicBuilder<Val, Challenge>>,
{
    let mut sb = p3_lookup::InteractionSymbolicBuilder::<Val, Challenge>::new(AirLayout::from_air::<Val>(air));
    air.eval(&mut sb);
    (sb.global_interactions().to_vec(), sb.base_constraints())
}

/// A row pair: the main trace's current and next rows, and the preprocessed trace's.
#[derive(Clone, Debug)]
pub struct Rows {
    pub cur: Vec<Val>,
    pub next: Vec<Val>,
    pub pre_cur: Vec<Val>,
    pub pre_next: Vec<Val>,
    /// The instance's public values (the cpu's `pv` vector; empty for every other table).
    pub public: Vec<Val>,
}

pub fn random_felt(rng: &mut impl rand::Rng) -> Val {
    use p3_field::PrimeCharacteristicRing;
    Val::from_u64(rng.next_u64() % 0xFFFF_FFFF_0000_0001)
}

impl Rows {
    pub fn random(width: usize, pre_width: usize, rng: &mut impl rand::Rng) -> Rows {
        let mut v = |n: usize| (0..n).map(|_| random_felt(rng)).collect::<Vec<_>>();
        Rows { cur: v(width), next: v(width), pre_cur: v(pre_width), pre_next: v(pre_width), public: vec![] }
    }
}

/// A base-field symbolic expression at one row pair, on a transition row that is neither the first
/// nor the last (the rows every per-row rule lives on) unless `boundary` says otherwise.
pub fn eval_rows(e: &Expr, r: &Rows) -> Val { eval_boundary(e, r, false, false) }

/// [`eval_rows`] on a boundary row: the table's first row (`is_first`) or its last (`is_last`,
/// where the transition selector is zero).
pub fn eval_boundary(e: &Expr, r: &Rows, is_first: bool, is_last: bool) -> Val {
    use p3_field::PrimeCharacteristicRing;
    let flag = |b: bool| if b { Val::ONE } else { Val::ZERO };
    match e {
        SymbolicExpr::Leaf(l) => match l {
            BaseLeaf::Variable(v) => match v.entry {
                BaseEntry::Main { offset: 0 } => r.cur[v.index],
                BaseEntry::Main { offset: 1 } => r.next[v.index],
                BaseEntry::Preprocessed { offset: 0 } => r.pre_cur[v.index],
                BaseEntry::Preprocessed { offset: 1 } => r.pre_next[v.index],
                BaseEntry::Public => r.public[v.index],
                other => panic!("an AIR here read {other:?}"),
            },
            BaseLeaf::IsFirstRow => flag(is_first),
            BaseLeaf::IsLastRow => flag(is_last),
            BaseLeaf::IsTransition => flag(!is_last),
            BaseLeaf::Constant(c) => *c,
        },
        SymbolicExpr::Add { x, y, .. } => eval_boundary(x, r, is_first, is_last) + eval_boundary(y, r, is_first, is_last),
        SymbolicExpr::Sub { x, y, .. } => eval_boundary(x, r, is_first, is_last) - eval_boundary(y, r, is_first, is_last),
        SymbolicExpr::Neg { x, .. } => -eval_boundary(x, r, is_first, is_last),
        SymbolicExpr::Mul { x, y, .. } => eval_boundary(x, r, is_first, is_last) * eval_boundary(y, r, is_first, is_last),
    }
}

/// Which slot of a row pair a column lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    Cur,
    Next,
    PreCur,
    PreNext,
}

fn slot_mut(r: &mut Rows, s: Slot) -> &mut Vec<Val> {
    match s {
        Slot::Cur => &mut r.cur,
        Slot::Next => &mut r.next,
        Slot::PreCur => &mut r.pre_cur,
        Slot::PreNext => &mut r.pre_next,
    }
}

/// Does `e` depend on column `col` of `slot` at this row pair? Two random perturbations, so a
/// chance cancellation cannot hide a dependency.
pub fn depends(e: &Expr, r: &Rows, slot: Slot, col: usize, rng: &mut impl rand::Rng) -> bool {
    use p3_field::PrimeCharacteristicRing;
    let base = eval_rows(e, r);
    (0..2).any(|_| {
        let mut moved = r.clone();
        slot_mut(&mut moved, slot)[col] += random_felt(rng) + Val::ONE;
        eval_rows(e, &moved) != base
    })
}

/// The single current-row main column a message field is, or `None` for anything composite.
pub fn as_column(e: &Expr) -> Option<usize> {
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) if v.entry == (BaseEntry::Main { offset: 0 }) => Some(v.index),
        _ => None,
    }
}

/// Constraint set 8 (Task A1): a real tier-10 proof for `gas.rs`'s native-ceiling test — the
/// smallest guest already used across the suite (`guests::fib`), proved at a fixed tier so
/// `gas_max(Tier(10), 0, 0)` (1 279: 1 023 cycles + 256 for the absorb rows) is the exact ceiling the test checks against. `fib(20)`
/// is far under that budget (`tests/emulator.rs` runs the same call), and the test profile is
/// what every other proving test in this crate uses (`tests/zk.rs`).
pub fn fib_proof_tier_10() -> (randprotocol_zkvm::isa::Program, randprotocol_zkvm::machine::Proof) {
    use randprotocol_zkvm::machine::{FriProfile, Machine, Tier};
    let m = Machine::new(FriProfile::Test);
    let p = randprotocol_zkvm::guests::fib(20);
    let (proof, _exec) = m.prove(&p, &[], &[], Some(Tier(10))).expect("fib(20) proves at tier 10");
    (p, proof)
}

// ── The fixed lookup tables (issue #66) ──────────────────────────────────────────────────────────
// Five buses have a *fixed* provider: `range` (RANGE8, POW2) and `nibble` (AND4, OR4, XOR4) are
// preprocessed tables whose only witness is how often each row is used. A cheating prover picks
// those multiplicities freely, so after it tampers a row the only question a fixed bus asks is
// whether every tuple the row now consumes is a row of the table at all. The helpers below answer
// that, and rewrite the two tables' multiplicity columns the way such a prover would — so a
// cheating test that tampers an ALU row is caught by the constraint it is written for, never by a
// multiplicity the test forgot to move.
use randprotocol_zkvm::machine::{chips, Chip, Tier, Traces};
use randprotocol_zkvm::tables::{bus, nibble, range};

/// Is `name` one of the five buses a fixed table provides?
pub fn is_fixed_bus(name: &str) -> bool {
    [bus::RANGE8.name(), bus::POW2.name(), bus::AND4.name(), bus::OR4.name(), bus::XOR4.name()].contains(&name)
}

/// Is `tuple` a row of the fixed table behind bus `name`? (`false` for any other bus.)
pub fn in_fixed_table(name: &str, tuple: &[Val]) -> bool {
    use p3_field::PrimeField64;
    let u: Vec<u64> = tuple.iter().map(|v| v.as_canonical_u64()).collect();
    let nib = |f: fn(u64, u64) -> u64| u.len() == 3 && u[0] < 16 && u[1] < 16 && u[2] == f(u[0], u[1]);
    if name == bus::RANGE8.name() {
        u.len() == 1 && u[0] < 256
    } else if name == bus::POW2.name() {
        u.len() == 2 && u[0] < 32 && u[1] == 1 << u[0]
    } else if name == bus::AND4.name() {
        nib(|a, b| a & b)
    } else if name == bus::OR4.name() {
        nib(|a, b| a | b)
    } else if name == bus::XOR4.name() {
        nib(|a, b| a ^ b)
    } else {
        false
    }
}

/// The table rows of `t` padded to the chip's width with zero blind columns (constraint set 7's
/// blind is not in `Traces`; on every row but the first it is zero, and no fixed bus reads it).
fn chip_row(m: &p3_matrix::dense::RowMajorMatrix<Val>, r: usize) -> Vec<Val> {
    use p3_matrix::Matrix;
    let (w, h) = (m.width(), m.height());
    m.values[(r % h) * w..(r % h) * w + w].to_vec()
}

/// Every fixed-bus tuple the non-fixed tables of `t` consume, with its summed (signed) count.
pub fn fixed_demand(t: &Traces, tier: Tier) -> std::collections::BTreeMap<(String, Vec<u64>), Val> {
    use p3_air::BaseAir;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_matrix::Matrix;
    let mut demand = std::collections::BTreeMap::new();
    for (chip, m) in chips(tier, t.keccak_log_height, t.sha256_log_height).iter().zip(t.as_slice()) {
        if matches!(chip, Chip::Range(_) | Chip::Nibble(_)) {
            continue;
        }
        let (interactions, _) = symbolic_air(chip);
        let fixed: Vec<&Interaction> = interactions.iter().filter(|i| is_fixed_bus(&i.bus_name)).collect();
        if fixed.is_empty() {
            continue;
        }
        let pre = BaseAir::<Val>::preprocessed_trace(chip);
        let pre_row = |i: usize| pre.as_ref().map(|p| chip_row(p, i)).unwrap_or_default();
        let public = if matches!(chip, Chip::Cpu(_)) { t.public_values.clone() } else { vec![] };
        let h = m.height();
        for r in 0..h {
            let rows = Rows { cur: chip_row(m, r), next: chip_row(m, r + 1), pre_cur: pre_row(r), pre_next: pre_row(r + 1), public: public.clone() };
            for i in &fixed {
                let c = eval_boundary(&i.count, &rows, r == 0, r == h - 1);
                if c == Val::ZERO {
                    continue;
                }
                let key: Vec<u64> = i.fields.iter().map(|f| eval_boundary(f, &rows, r == 0, r == h - 1).as_canonical_u64()).collect();
                *demand.entry((i.bus_name.clone(), key)).or_insert(Val::ZERO) += c;
            }
        }
    }
    demand
}

/// Rewrite the range and nibble tables' multiplicity columns so they pay exactly what the other
/// tables of `t` consume — what a cheating prover, who picks those columns freely, does after a
/// tamper. Returns every demanded tuple no table row can pay (those stay unpaid: the bus is left
/// unbalanced, which is the fixed table catching the tamper).
pub fn repay_fixed_tables(t: &mut Traces, tier: Tier) -> Vec<String> {
    use p3_field::PrimeCharacteristicRing;
    // The provider's sign: a table row with multiplicity 1, read through the range table's own
    // symbolic interaction. `demand + sign·M = 0` is what balances, so `M = −sign·demand`.
    let (range_ints, _) = symbolic_air(&randprotocol_zkvm::tables::range::RangeAir);
    let probe = Rows { cur: vec![Val::ONE; range::col::WIDTH], next: vec![Val::ONE; range::col::WIDTH], pre_cur: vec![Val::ZERO; range::pre::WIDTH], pre_next: vec![Val::ZERO; range::pre::WIDTH], public: vec![] };
    let sign = eval_rows(&range_ints.iter().find(|i| i.bus_name == bus::RANGE8.name()).expect("range provides RANGE8").count, &probe);
    assert!(sign == Val::ONE || sign == Val::NEG_ONE, "a table row's count is its multiplicity");
    let demand = fixed_demand(t, tier);
    for r in 0..range::HEIGHT {
        t.range.values[r * range::col::WIDTH + range::col::M_RANGE] = Val::ZERO;
        t.range.values[r * range::col::WIDTH + range::col::M_POW2] = Val::ZERO;
    }
    for r in 0..nibble::HEIGHT {
        for c in [nibble::col::M_AND, nibble::col::M_OR, nibble::col::M_XOR] {
            t.nibble.values[r * nibble::col::WIDTH + c] = Val::ZERO;
        }
    }
    let mut unpaid = Vec::new();
    for ((name, key), d) in demand {
        let tuple: Vec<Val> = key.iter().map(|&k| Val::from_u64(k)).collect();
        if !in_fixed_table(&name, &tuple) {
            unpaid.push(format!("{name}{key:?}"));
            continue;
        }
        let m = -(sign * d);
        let slot = if name == bus::RANGE8.name() {
            &mut t.range.values[key[0] as usize * range::col::WIDTH + range::col::M_RANGE]
        } else if name == bus::POW2.name() {
            &mut t.range.values[key[0] as usize * range::col::WIDTH + range::col::M_POW2]
        } else {
            let c = if name == bus::AND4.name() { nibble::col::M_AND } else if name == bus::OR4.name() { nibble::col::M_OR } else { nibble::col::M_XOR };
            &mut t.nibble.values[nibble::row_of(key[0] as u32, key[1] as u32) * nibble::col::WIDTH + c]
        };
        *slot = m;
    }
    unpaid
}
