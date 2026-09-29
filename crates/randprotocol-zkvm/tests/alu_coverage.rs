//! Issue #66 (the #62 review of the ALU, circuits `b9ffc39`): the ALU's coverage beyond the
//! hand-written forgeries in `tests/cheating.rs`. The review proved the table sound (a z3 model of
//! `AluAir::eval`, `tools/alu_z3/`) and found the tests thinner than the proof; this file closes the
//! gaps it listed, all of them read off the real `eval` through Plonky3's symbolic builder
//! (`common::symbolic_air`), never a hand-kept copy of the constraints:
//!
//! 1. **Completeness** (`every_alu_op_is_complete_on_edge_and_random_operands`): every op on every
//!    pair of edge operands and on seeded random ones goes through `alu::fill_row`, and the row
//!    satisfies every constraint, consumes only tuples the fixed tables hold, and consumes exactly
//!    the lookups `fill_row` counted for the range and nibble tables.
//! 2. **Row-level mutation fuzzing** (`no_tamper_of_an_honest_alu_row_provides_a_false_tuple`):
//!    one- and two-cell tampers of honest rows — from `fill_row` on edge and random operands, from a
//!    call trace and from a shielded-bundle execution — and whatever the constraints and the fixed
//!    tables still admit must provide a *true* `(op, a, b, c)`. The provided tuple is treated as the
//!    row's output, free to disagree with the rest of the batch: this is the soundness of the ALU
//!    table itself, the question the cpu relies on.
//! 3. **Trace-level mutation fuzzing** (`a_single_cell_tamper_of_an_alu_or_cpu_row_is_caught_by_the_batch_check`):
//!    single cells of the ALU and cpu rows of an honest call trace and an honest bundle trace are
//!    tampered, and the batch's own check — every constraint on the two row pairs the cell sits in,
//!    every non-fixed bus still balanced, every fixed-bus tuple still a table row — must refuse every
//!    tamper of a column the row sends on a bus. A sample of the verdicts is replayed through the real
//!    prover (`Machine::prove_traces`, whose debug build runs Plonky3's constraint and lookup checkers)
//!    and must agree.
//! 4. **Column roles** (`every_alu_column_has_the_role_its_op_gives_it`): the ALU reuses columns
//!    across ops (`Q/S/T` are shift words, bitwise nibbles, product terms and division limbs; `BH_N`
//!    is a shift-amount nibble and a sign nibble; `SHH/PW` are shift bits and division limbs; C0..3
//!    are not range-checked on compare rows). A table of which bus or constraint reads each column on
//!    each op, generated from `eval` over honest rows, is pinned here, so a future change that reads a
//!    column on an op where it means something else fails with the new table printed.
mod common;
use common::*;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use rand::{Rng as _, SeedableRng};
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::emulator::{execute, AluEvent, Execution};
use randprotocol_zkvm::guests;
use randprotocol_zkvm::isa::{AluOp, BranchCond, Instr, Program};
use randprotocol_zkvm::machine::{build_traces_salted, build_traces_salted_with, chips, Chip, FriProfile, Machine, Tier, Traces, Val};
use randprotocol_zkvm::ledger::CommitmentTree;
use randprotocol_zkvm::notes::{self, Note, SpendKey, Word8, DEPTH};
use randprotocol_zkvm::tables::{alu, blind, bus, nibble, range};
use std::collections::{BTreeMap, BTreeSet};

type Rng = rand::rngs::StdRng;

fn u32_of(rng: &mut Rng) -> u32 { rng.next_u64() as u32 }

// ── The ALU row, read through `eval` ────────────────────────────────────────────────────────────

/// Every column a symbolic expression reads (the ALU has no next-row or preprocessed reads).
fn columns_of(e: &Expr, out: &mut BTreeSet<usize>) {
    use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr};
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => {
            if matches!(v.entry, BaseEntry::Main { .. }) { out.insert(v.index); }
        }
        SymbolicExpr::Leaf(_) => {}
        SymbolicExpr::Add { x, y, .. } | SymbolicExpr::Sub { x, y, .. } | SymbolicExpr::Mul { x, y, .. } => {
            columns_of(x, out);
            columns_of(y, out);
        }
        SymbolicExpr::Neg { x, .. } => columns_of(x, out),
    }
}

fn reads(e: &Expr) -> BTreeSet<usize> {
    let mut s = BTreeSet::new();
    columns_of(e, &mut s);
    s
}

/// Why an ALU row was refused.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Refusal {
    /// Base constraint number `k` (in `eval`'s order) is non-zero.
    Constraint(usize),
    /// The row consumes a tuple the named fixed table does not hold.
    NotInTable(String),
}

/// `AluAir::eval` as data: its base constraints and its interactions, each with the columns it reads.
struct AluCheck {
    constraints: Vec<(Expr, BTreeSet<usize>)>,
    interactions: Vec<(Interaction, BTreeSet<usize>)>,
}

impl AluCheck {
    fn new() -> AluCheck {
        let (interactions, constraints) = symbolic_air(&alu::AluAir);
        assert!(interactions.iter().all(|i| i.bus_name == bus::ALU.name() || is_fixed_bus(&i.bus_name)), "the ALU talks to the fixed tables and provides ALU, nothing else");
        AluCheck {
            constraints: constraints.into_iter().map(|c| { let r = reads(&c); (c, r) }).collect(),
            interactions: interactions
                .into_iter()
                .map(|i| {
                    let mut r = reads(&i.count);
                    for f in &i.fields { columns_of(f, &mut r); }
                    (i, r)
                })
                .collect(),
        }
    }

    fn at(row: &[Val]) -> Rows { Rows { cur: row.to_vec(), next: row.to_vec(), pre_cur: vec![], pre_next: vec![], public: vec![] } }

    /// The whole check: every constraint, and every fixed-bus tuple the row consumes a table row.
    fn check(&self, row: &[Val]) -> Result<(), Refusal> { self.check_touching(row, None) }

    /// [`Self::check`] restricted to what reads a column in `touched` — exact for a tamper of those
    /// columns in a row that passed the whole check (nothing else changed value).
    fn check_touching(&self, row: &[Val], touched: Option<&[usize]>) -> Result<(), Refusal> {
        let hit = |cols: &BTreeSet<usize>| touched.is_none_or(|t| t.iter().any(|c| cols.contains(c)));
        let r = Self::at(row);
        for (k, (c, cols)) in self.constraints.iter().enumerate() {
            if hit(cols) && eval_rows(c, &r) != Val::ZERO {
                return Err(Refusal::Constraint(k));
            }
        }
        for (i, cols) in &self.interactions {
            if i.bus_name == bus::ALU.name() || !hit(cols) || eval_rows(&i.count, &r) == Val::ZERO {
                continue;
            }
            let t: Vec<Val> = i.fields.iter().map(|f| eval_rows(f, &r)).collect();
            if !in_fixed_table(&i.bus_name, &t) {
                return Err(Refusal::NotInTable(format!("{}{:?}", i.bus_name, t.iter().map(|v| v.as_canonical_u64()).collect::<Vec<_>>())));
            }
        }
        Ok(())
    }

    /// Every fixed-bus tuple the row consumes, with its count as a signed integer.
    fn consumed(&self, row: &[Val]) -> BTreeMap<(String, Vec<u64>), i64> {
        let r = Self::at(row);
        let mut out = BTreeMap::new();
        for (i, _) in &self.interactions {
            let c = eval_rows(&i.count, &r);
            if i.bus_name == bus::ALU.name() || c == Val::ZERO {
                continue;
            }
            let n = if c == Val::ONE { 1 } else if c == Val::NEG_ONE { -1 } else { panic!("a lookup count of {c} on one row") };
            let key = i.fields.iter().map(|f| eval_rows(f, &r).as_canonical_u64()).collect();
            *out.entry((i.bus_name.clone(), key)).or_insert(0) += n;
        }
        out
    }
}

/// `Ok` iff the tuple the row provides is true: a zero multiplicity provides nothing, and anything
/// else must be a real op on 32-bit operands whose `C` is `op.eval(A, B)`.
fn provides_the_truth(row: &[Val]) -> Result<(), String> {
    use alu::col::*;
    if row[MULT] == Val::ZERO {
        return Ok(());
    }
    let op = (0..AluOp::COUNT).fold(Val::ZERO, |s, i| s + row[FLAG0 + i] * Val::from_u32(i as u32)).as_canonical_u64();
    let (a, b, c) = (row[A].as_canonical_u64(), row[B].as_canonical_u64(), row[C].as_canonical_u64());
    if op >= AluOp::COUNT as u64 {
        return Err(format!("provides op code {op}"));
    }
    let op = AluOp::from_code(op as u32);
    if a >> 32 != 0 || b >> 32 != 0 {
        return Err(format!("provides {op:?}({a:#x}, {b:#x}) on an operand past 32 bits"));
    }
    let want = op.eval(a as u32, b as u32) as u64;
    if c != want {
        return Err(format!("provides {op:?}({a:#x}, {b:#x}) = {c:#x}, the truth is {want:#x}"));
    }
    Ok(())
}

/// An honest ALU row for `op(a, b)` and the lookups `fill_row` counted for it.
fn honest_row(op: AluOp, a: u32, b: u32) -> (Vec<Val>, range::RangeCounts, nibble::NibbleCounts) {
    let mut row = vec![Val::ZERO; alu::col::WIDTH];
    let (mut rc, mut nc) = (range::RangeCounts::default(), nibble::NibbleCounts::default());
    alu::fill_row(&mut row, &AluEvent { op, a, b, c: op.eval(a, b) }, &mut rc, &mut nc);
    (row, rc, nc)
}

/// What `fill_row` counted, as the same `(bus, tuple) → count` map `AluCheck::consumed` reads.
fn counted(rc: &range::RangeCounts, nc: &nibble::NibbleCounts) -> BTreeMap<(String, Vec<u64>), i64> {
    let mut out = BTreeMap::new();
    let mut put = |bus: &str, key: Vec<u64>, n: u64| if n != 0 { out.insert((bus.to_string(), key), n as i64); };
    for (x, &n) in rc.range.iter().enumerate() { put(bus::RANGE8.name(), vec![x as u64], n); }
    for (s, &n) in rc.pow2.iter().enumerate().filter(|&(_, &n)| n != 0) { put(bus::POW2.name(), vec![s as u64, 1u64 << s], n); }
    for a in 0..16u64 {
        for b in 0..16u64 {
            let r = nibble::row_of(a as u32, b as u32);
            if let Some(&n) = nc.and.get(r) { put(bus::AND4.name(), vec![a, b, a & b], n); }
            if let Some(&n) = nc.or.get(r) { put(bus::OR4.name(), vec![a, b, a | b], n); }
            if let Some(&n) = nc.xor.get(r) { put(bus::XOR4.name(), vec![a, b, a ^ b], n); }
        }
    }
    out
}

/// Operands at every boundary the ALU's gadgets care about: zero, one, the byte and nibble edges,
/// the shift-amount wrap (31/32/33), the sign bit (`INT_MIN`, `INT_MIN + 1`, `-1`, `-2`, `-8`),
/// and two arbitrary words.
const EDGES: [u32; 27] = [
    0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 33, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x1_0000,
    0x7fff_ffff, 0x8000_0000, 0x8000_0001, 0xffff_fff8, 0xffff_fffe, 0xffff_ffff, 0x1234_5678, 0xdead_beef,
];

/// `n` seeded random operand pairs: a third full words, a third small (bytes), a third mixed with
/// an edge — so shifts see small amounts and divisions see small divisors often.
fn random_pairs(rng: &mut Rng, n: usize) -> Vec<(u32, u32)> {
    (0..n)
        .map(|k| match k % 3 {
            0 => (u32_of(rng), u32_of(rng)),
            1 => (u32_of(rng) & 0xff, u32_of(rng) & 0xff),
            _ => (EDGES[(rng.next_u64() % EDGES.len() as u64) as usize], u32_of(rng) >> (rng.next_u64() % 32)),
        })
        .collect()
}

// ── 1. Completeness ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_alu_op_is_complete_on_edge_and_random_operands() {
    let check = AluCheck::new();
    let mut rng = Rng::seed_from_u64(0x66_0001);
    // The cases the review named, spelled out so a change to `EDGES` cannot drop them.
    let named = [
        (AluOp::Div, 0x8000_0000, 0xffff_ffff), (AluOp::Rem, 0x8000_0000, 0xffff_ffff), // INT_MIN / −1
        (AluOp::Div, 5, 0), (AluOp::Divu, 5, 0), (AluOp::Rem, 0xffff_fff9, 0), (AluOp::Remu, 5, 0), // ÷ 0
        (AluOp::Rem, 0xffff_fffc, 2), (AluOp::Div, 0, 0xffff_ffff), // a zero magnitude to negate
        (AluOp::Mulh, 0x8000_0000, 0x8000_0000), (AluOp::Mulhsu, 0x8000_0000, 0xffff_ffff), (AluOp::Mulhu, 0xffff_ffff, 0xffff_ffff),
        (AluOp::Sra, 0x8000_0000, 31), (AluOp::Sll, 0xffff_ffff, 31), (AluOp::Srl, 0xffff_ffff, 0xffff_ffff),
    ];
    let mut failures = Vec::new();
    let mut rows = 0;
    for op in AluOp::ALL {
        let mut pairs: Vec<(u32, u32)> = EDGES.iter().flat_map(|&a| EDGES.iter().map(move |&b| (a, b))).collect();
        pairs.extend(random_pairs(&mut rng, 300));
        pairs.extend(named.iter().filter(|(o, _, _)| *o == op).map(|&(_, a, b)| (a, b)));
        for (a, b) in pairs {
            rows += 1;
            let (row, rc, nc) = honest_row(op, a, b);
            if let Err(e) = check.check(&row) {
                failures.push(format!("{op:?}({a:#x}, {b:#x}): the honest row is refused: {e:?}"));
                continue;
            }
            if let Err(e) = provides_the_truth(&row) {
                failures.push(format!("{op:?}({a:#x}, {b:#x}): {e}"));
            }
            let (want, got) = (counted(&rc, &nc), check.consumed(&row));
            // `lookup_key` counts are sends: every one the row makes is `+1`.
            if want != got {
                failures.push(format!("{op:?}({a:#x}, {b:#x}): fill_row counted {want:?}, the row consumes {got:?}"));
            }
        }
    }
    eprintln!("{rows} honest rows over {} ops", AluOp::COUNT);
    assert!(failures.is_empty(), "{} incomplete rows:\n  {}", failures.len(), failures.iter().take(40).cloned().collect::<Vec<_>>().join("\n  "));
}

// ── 2. Row-level mutation fuzzing ───────────────────────────────────────────────────────────────

/// A call that runs every ALU op, in register form, on operand pairs that hit the gadgets (a sign
/// fix-up, a zero magnitude, `INT_MIN / −1`, `÷ 0`, a shift past 31, mixed signs), plus an `EQ`
/// taken and not taken — tier 10.
fn alu_tour() -> Program {
    let mut a = Assembler::new(0);
    let pairs: [(i32, i32); 8] = [(0x1234_5678, -7), (-8, 1), (-1, 1), (-7, 0), (i32::MIN, -1), (0x0f, 0xf0), (-4, 2), (31, 33)];
    type Op = fn(u32, u32, u32) -> Instr;
    let ops: [Op; 18] = [add, sub, and, or, xor, sll, srl, sra, slt, sltu, mul, mulh, mulhu, mulhsu, div, divu, rem, remu];
    for (x, y) in pairs {
        a.extend(li(5, x));
        a.extend(li(6, y));
        for f in ops { a.push(f(7, 5, 6)); }
    }
    for (k, (x, y)) in [(5, 5), (5, 7)].into_iter().enumerate() {
        a.extend(li(5, x));
        a.extend(li(6, y));
        a.branch(BranchCond::Eq, 5, 6, &format!("eq{k}"));
        a.label(&format!("eq{k}"));
    }
    a.extend(write_output(0, 7));
    a.extend(halt());
    a.assemble()
}

/// An honest shielded-bundle execution (one real input, one dummy) — the guest the chain proves
/// most, at tier 14. Its notes' blinding is random, so its operands differ from run to run; the
/// shapes do not.
fn bundle_execution() -> (Program, Vec<u32>, Execution) {
    let sk = SpendKey([0x66; 8]);
    let pk = sk.viewing_key().pk();
    let (asset, time) = (0u32, 1_700_000_000u32);
    let mut tree = CommitmentTree::new();
    let real = Note::new(pk, SpendKey([7; 8]).viewing_key().pk(), 1_000, asset, time);
    tree.append(real.commitment());
    let (path, idx) = tree.path_for(&real.commitment()).unwrap();
    let dummy: (Note, [Word8; DEPTH], u32) = (Note::new([0; 8], [0; 8], 0, asset, time), [[0; 8]; DEPTH], 0);
    let inputs = [(real, path, idx), dummy];
    let outputs = [Note::new(pk, pk, 1_000, asset, time), Note::new([0; 8], pk, 0, asset, time)];
    let program = guests::bundle();
    let words = notes::bundle_inputs(&sk, &inputs, &outputs, tree.root(), 0, 0, asset, time);
    let e = execute(&program, &words, &[], 1 << 22).unwrap();
    (program, words, e)
}

/// The distinct `(op, a, b)` an execution feeds the ALU.
fn alu_events(e: &Execution) -> Vec<(AluOp, u32, u32)> {
    let set: BTreeSet<(u32, u32, u32)> = e.events.iter().flat_map(|c| c.alu.iter()).map(|ev| (ev.op.code(), ev.a, ev.b)).collect();
    set.into_iter().map(|(o, a, b)| (AluOp::from_code(o), a, b)).collect()
}

/// The values a tamper of `v` tries: its neighbours, the field's `−1`, a random field element, a
/// random byte, a random word, and `v` shifted by `2^32` (an out-of-range twin of a 32-bit value).
fn tamper_values(v: Val, rng: &mut Rng) -> Vec<Val> {
    let mut out = vec![v + Val::ONE, v - Val::ONE, Val::NEG_ONE, random_felt(rng), Val::from_u32(u32_of(rng) & 0xff), Val::from_u32(u32_of(rng)), v + Val::from_u64(1 << 32)];
    out.retain(|&x| x != v);
    out
}

/// The columns an honest row's provided tuple is made of, less `MULT` (the multiplicity is the
/// batch's to balance, and a row may provide its true tuple any number of times).
fn tuple_columns() -> Vec<usize> {
    use alu::col::*;
    let mut v: Vec<usize> = (FLAG0..FLAG0 + AluOp::COUNT).collect();
    v.extend([A, B, C, IS_REAL]);
    v.extend(A0..A0 + 4);
    v.extend(B0..B0 + 4);
    v.extend(C0..C0 + 4);
    v
}

#[test]
fn no_tamper_of_an_honest_alu_row_provides_a_false_tuple() {
    use alu::col::*;
    let check = AluCheck::new();
    let mut rng = Rng::seed_from_u64(0x66_0002);
    // The honest rows: edge and random operands for every op, then every distinct ALU event of a
    // call and a sample of a bundle's.
    let mut sources: Vec<(AluOp, u32, u32)> = Vec::new();
    for op in AluOp::ALL {
        for _ in 0..8 {
            let pick = |rng: &mut Rng| EDGES[(rng.next_u64() % EDGES.len() as u64) as usize];
            sources.push((op, pick(&mut rng), pick(&mut rng)));
        }
        sources.extend(random_pairs(&mut rng, 6).into_iter().map(|(a, b)| (op, a, b)));
    }
    let tour = execute(&alu_tour(), &[], &[], 10_000).unwrap();
    sources.extend(alu_events(&tour));
    let (_, _, bundle) = bundle_execution();
    let bundle_events = alu_events(&bundle);
    let stride = (bundle_events.len() / 150).max(1);
    sources.extend(bundle_events.iter().step_by(stride).copied());

    let tuple = tuple_columns();
    let mut forgeries = Vec::new();
    let mut tuple_cell_accepted = Vec::new();
    let (mut tampers, mut refused) = (0usize, 0usize);
    let mut accepted_cols: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for &(op, a, b) in &sources {
        let (honest, _, _) = honest_row(op, a, b);
        check.check(&honest).unwrap_or_else(|e| panic!("{op:?}({a:#x}, {b:#x}): honest row refused: {e:?}"));
        let mut try_row = |cells: &[(usize, Val)], single: bool| {
            let mut row = honest.clone();
            for &(c, v) in cells { row[c] = v; }
            if row == honest { return; }
            tampers += 1;
            let touched: Vec<usize> = cells.iter().map(|&(c, _)| c).collect();
            match check.check_touching(&row, Some(&touched)) {
                Err(_) => refused += 1,
                Ok(()) => {
                    if let Err(e) = provides_the_truth(&row) {
                        forgeries.push(format!("{op:?}({a:#x}, {b:#x}) with {cells:?}: {e}"));
                    }
                    if single {
                        accepted_cols.entry(format!("{op:?}")).or_default().insert(cells[0].0);
                        if tuple.contains(&cells[0].0) { tuple_cell_accepted.push(format!("{op:?}({a:#x}, {b:#x}): column {} := {}", cells[0].0, cells[0].1)); }
                    }
                }
            }
        };
        // Every single cell, several values each.
        for col in 0..WIDTH {
            for v in tamper_values(honest[col], &mut rng) { try_row(&[(col, v)], true); }
        }
        // A word and one of its limbs moved together, so the recomposition still holds: the tamper
        // a prover makes to change A, B or C without tripping `word(X0) = X`.
        for (word, base) in [(A, A0), (B, B0), (C, C0), (Q0, Q0), (S0, S0), (T0, T0)] {
            for k in 0..4 {
                for d in [1i64, -1, 2, 16, -16] {
                    let dv = if d < 0 { -Val::from_u64(d.unsigned_abs()) } else { Val::from_u64(d as u64) };
                    let scale = Val::from_u64(1 << (8 * k));
                    if word == base {
                        // Q/S/T have no word column: move two adjacent limbs against each other.
                        if k < 3 { try_row(&[(base + k, honest[base + k] + dv * Val::from_u32(256)), (base + k + 1, honest[base + k + 1] - dv)], false); }
                    } else {
                        try_row(&[(word, honest[word] + dv * scale), (base + k, honest[base + k] + dv)], false);
                    }
                }
            }
        }
        // Random pairs of cells.
        for _ in 0..48 {
            let (c1, c2) = ((rng.next_u64() % WIDTH as u64) as usize, (rng.next_u64() % WIDTH as u64) as usize);
            let (v1, v2) = (tamper_values(honest[c1], &mut rng)[(rng.next_u64() % 4) as usize], tamper_values(honest[c2], &mut rng)[(rng.next_u64() % 4) as usize]);
            try_row(&[(c1, v1), (c2, v2)], false);
        }
    }
    eprintln!("{} honest rows, {tampers} tampers, {refused} refused, {} admitted (every one still provides its true tuple)", sources.len(), tampers - refused);
    for (op, cols) in &accepted_cols { eprintln!("  {op}: single-cell tampers admitted only in columns {cols:?}"); }
    assert!(forgeries.is_empty(), "SOUNDNESS: an admitted ALU row provides a false tuple:\n  {}", forgeries.join("\n  "));
    assert!(tuple_cell_accepted.is_empty(), "a single-cell tamper of a tuple column was admitted:\n  {}", tuple_cell_accepted.join("\n  "));
    assert!(refused * 2 > tampers, "the tampers are mostly refused ({refused} of {tampers})");
}

/// The fix-up formula's `2^32 − 0` (issue #66's example): `REM(-4, 2) = 0` has a zero remainder
/// to "negate", and forging `QH3 = 0` asks for `C = 2^32`, which no byte decomposition holds. The
/// row is refused by the `QH3` gadget's first half (`mag·INV = 1 − QH3` with `mag = 0`); and with
/// that constraint set aside, still by `C`'s `RANGE8` limbs — two independent guards.
#[test]
fn a_zero_remainder_negated_to_two_to_the_32_is_refused_twice() {
    use alu::col::*;
    let check = AluCheck::new();
    let (mut row, _, _) = honest_row(AluOp::Rem, (-4i32) as u32, 2);
    assert_eq!(row[QH3], Val::ONE);
    row[QH3] = Val::ZERO;
    row[C] = Val::from_u64(1 << 32);
    row[C0 + 3] = Val::from_u32(256);
    let gadget = check
        .constraints
        .iter()
        .position(|(_, cols)| cols.contains(&QH3) && cols.contains(&INV))
        .expect("the magnitude's is-zero gadget reads QH3 and INV");
    assert_eq!(check.check(&row), Err(Refusal::Constraint(gadget)), "caught by `mag·INV = 1 − QH3`");
    // Without the gadget: every other constraint holds, and C's top limb is no byte.
    let without = AluCheck { constraints: check.constraints.iter().enumerate().filter(|&(k, _)| k != gadget).map(|(_, c)| c.clone()).collect(), interactions: check.interactions.iter().map(|(i, c)| (i.clone(), c.clone())).collect() };
    assert_eq!(without.check(&row), Err(Refusal::NotInTable("RANGE8[256]".into())), "then caught by C's RANGE8 limbs");
}

// ── 3. Trace-level mutation fuzzing ─────────────────────────────────────────────────────────────

/// One table of a batch, read through its `eval`, with the row pairs a single-cell tamper touches.
struct ChipCheck {
    trace: RowMajorMatrix<Val>,
    pre: Option<RowMajorMatrix<Val>>,
    public: Vec<Val>,
    constraints: Vec<(Expr, BTreeSet<(Slot, usize)>)>,
    interactions: Vec<(Interaction, BTreeSet<(Slot, usize)>)>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Admitted,
    /// A constraint of the table fails on a row pair the tamper is in.
    Constraint,
    /// A non-fixed bus no longer balances (a message the row sends or provides changed).
    Unbalanced(String),
    /// The row now consumes a tuple the fixed table does not hold.
    NotInTable(String),
}

fn slots_of(e: &Expr, out: &mut BTreeSet<(Slot, usize)>) {
    use p3_air::symbolic::{BaseEntry, BaseLeaf, SymbolicExpr};
    match e {
        SymbolicExpr::Leaf(BaseLeaf::Variable(v)) => match v.entry {
            BaseEntry::Main { offset: 0 } => { out.insert((Slot::Cur, v.index)); }
            BaseEntry::Main { offset: 1 } => { out.insert((Slot::Next, v.index)); }
            _ => {}
        },
        SymbolicExpr::Leaf(_) => {}
        SymbolicExpr::Add { x, y, .. } | SymbolicExpr::Sub { x, y, .. } | SymbolicExpr::Mul { x, y, .. } => {
            slots_of(x, out);
            slots_of(y, out);
        }
        SymbolicExpr::Neg { x, .. } => slots_of(x, out),
    }
}

impl ChipCheck {
    /// `chip`'s trace from `t`, widened with a fresh blind exactly as `prove_traces` does.
    fn new(chip: &Chip, trace: &RowMajorMatrix<Val>, public: Vec<Val>) -> ChipCheck {
        use p3_air::BaseAir;
        let (interactions, constraints) = symbolic_air(chip);
        let with = |e: &Expr| { let mut s = BTreeSet::new(); slots_of(e, &mut s); s };
        ChipCheck {
            trace: blind::widen(trace, &blind::fresh(1)[0]),
            pre: BaseAir::<Val>::preprocessed_trace(chip),
            public,
            constraints: constraints.iter().map(|c| (c.clone(), with(c))).collect(),
            interactions: interactions
                .into_iter()
                .map(|i| {
                    let mut s = with(&i.count);
                    for f in &i.fields { slots_of(f, &mut s); }
                    (i, s)
                })
                .collect(),
        }
    }

    fn height(&self) -> usize { self.trace.height() }
    fn row(&self, r: usize) -> Vec<Val> {
        let (w, h) = (self.trace.width(), self.trace.height());
        self.trace.values[(r % h) * w..(r % h) * w + w].to_vec()
    }
    fn pre_row(&self, r: usize) -> Vec<Val> {
        self.pre.as_ref().map(|p| { let (w, h) = (p.width(), p.height()); p.values[(r % h) * w..(r % h) * w + w].to_vec() }).unwrap_or_default()
    }
    /// The row pair whose current row is `p`, with row `r` replaced by `tampered`.
    fn pair(&self, p: usize, r: usize, tampered: &[Val]) -> Rows {
        let h = self.height();
        let get = |i: usize| if i % h == r { tampered.to_vec() } else { self.row(i) };
        Rows { cur: get(p), next: get(p + 1), pre_cur: self.pre_row(p), pre_next: self.pre_row(p + 1), public: self.public.clone() }
    }

    /// Every constraint holds on every row pair (the honest trace; sanity for the checker).
    fn all_hold(&self) -> Result<(), String> {
        let h = self.height();
        for p in 0..h {
            let rows = self.pair(p, usize::MAX, &[]);
            if let Some(k) = self.constraints.iter().position(|(c, _)| eval_boundary(c, &rows, p == 0, p == h - 1) != Val::ZERO) {
                return Err(format!("constraint {k} fails on row {p}"));
            }
        }
        Ok(())
    }

    /// The batch's verdict on setting cell `(r, col)` to `v`: the two row pairs the row is in are
    /// re-checked, the messages they send on every non-fixed bus must be exactly what they were, and
    /// every fixed-bus tuple they consume must be a table row (the prover repays the table).
    fn verdict(&self, r: usize, col: usize, v: Val) -> Verdict {
        let h = self.height();
        let honest = self.row(r);
        let mut tampered = honest.clone();
        tampered[col] = v;
        let mut delta: BTreeMap<(String, Vec<u64>), Val> = BTreeMap::new();
        for p in [(r + h - 1) % h, r] {
            let slot = if p == r { Slot::Cur } else { Slot::Next };
            let (before, after) = (self.pair(p, r, &honest), self.pair(p, r, &tampered));
            let (first, last) = (p == 0, p == h - 1);
            for (c, s) in &self.constraints {
                if s.contains(&(slot, col)) && eval_boundary(c, &after, first, last) != Val::ZERO {
                    return Verdict::Constraint;
                }
            }
            for (i, s) in &self.interactions {
                if !s.contains(&(slot, col)) {
                    continue;
                }
                for (rows, sign) in [(&before, -Val::ONE), (&after, Val::ONE)] {
                    let n = eval_boundary(&i.count, rows, first, last);
                    if n == Val::ZERO {
                        continue;
                    }
                    let t: Vec<Val> = i.fields.iter().map(|f| eval_boundary(f, rows, first, last)).collect();
                    if is_fixed_bus(&i.bus_name) {
                        if sign == Val::ONE && !in_fixed_table(&i.bus_name, &t) {
                            return Verdict::NotInTable(i.bus_name.clone());
                        }
                    } else {
                        *delta.entry((i.bus_name.clone(), t.iter().map(|x| x.as_canonical_u64()).collect())).or_insert(Val::ZERO) += sign * n;
                    }
                }
            }
        }
        match delta.into_iter().find(|(_, n)| *n != Val::ZERO) {
            Some(((bus, _), _)) => Verdict::Unbalanced(bus),
            None => Verdict::Admitted,
        }
    }

    /// Columns a non-fixed-bus message the row sends or provides really depends on (a tamper of one
    /// of these changes a message, so the batch must refuse it).
    fn carried(&self, r: usize, rng: &mut Rng) -> BTreeSet<usize> {
        let h = self.height();
        let rows = self.pair(r, usize::MAX, &[]);
        let mut out = BTreeSet::new();
        for (i, s) in &self.interactions {
            if is_fixed_bus(&i.bus_name) || eval_boundary(&i.count, &rows, r == 0, r == h - 1) == Val::ZERO {
                continue;
            }
            for &(slot, col) in s {
                if slot == Slot::Cur && !out.contains(&col) && i.fields.iter().chain([&i.count]).any(|f| depends(f, &rows, Slot::Cur, col, rng)) {
                    out.insert(col);
                }
            }
        }
        out
    }
}

/// One tamper, for the replay through the prover.
#[derive(Clone, Debug)]
struct Tamper { chip: usize, row: usize, col: usize, value: Val, verdict: Verdict }

/// Fuzz the ALU (chip 3) and cpu (chip 1) rows of `t`; returns every tamper made, and fails the
/// test on a tuple or carried column the batch admits.
fn fuzz_batch(name: &str, t: &Traces, tier: Tier, alu_rows: usize, cpu_rows: usize, rng: &mut Rng) -> Vec<Tamper> {
    use alu::col::*;
    let cs = chips(tier, t.keccak_log_height, t.sha256_log_height);
    let tuple = tuple_columns();
    let mut all = Vec::new();
    let mut failures = Vec::new();
    for (k, rows_wanted) in [(3usize, alu_rows), (1usize, cpu_rows)] {
        let public = if k == 1 { t.public_values.clone() } else { vec![] };
        let chip = ChipCheck::new(&cs[k], t.as_slice()[k], public);
        chip.all_hold().unwrap_or_else(|e| panic!("{name}: chip {k}: the honest trace fails: {e}"));
        let width = cs[k].table_width();
        let is_real_col = if k == 3 { IS_REAL } else { randprotocol_zkvm::tables::cpu::col::IS_REAL };
        let real: Vec<usize> = (0..chip.height()).filter(|&r| chip.row(r)[is_real_col] == Val::ONE).collect();
        let stride = (real.len() / rows_wanted).max(1);
        let mut by_verdict: BTreeMap<Verdict, usize> = BTreeMap::new();
        for &r in real.iter().step_by(stride) {
            let carried = chip.carried(r, rng);
            let honest = chip.row(r);
            for col in 0..width {
                for v in [honest[col] + Val::ONE, random_felt(rng)] {
                    let verdict = chip.verdict(r, col, v);
                    *by_verdict.entry(verdict.clone()).or_insert(0) += 1;
                    if verdict == Verdict::Admitted {
                        let must = if k == 3 { tuple.contains(&col) || col == MULT } else { carried.contains(&col) };
                        if must { failures.push(format!("{name}: chip {k} row {r}: the tamper of column {col} to {v} is admitted")); }
                    }
                    all.push(Tamper { chip: k, row: r, col, value: v, verdict });
                }
            }
        }
        eprintln!("{name}: chip {k}: {} real rows fuzzed, verdicts {by_verdict:?}", real.iter().step_by(stride).count());
    }
    assert!(failures.is_empty(), "the batch admits a tamper it must refuse:\n  {}", failures.join("\n  "));
    all
}

#[test]
fn a_single_cell_tamper_of_an_alu_or_cpu_row_is_caught_by_the_batch_check() {
    let mut rng = Rng::seed_from_u64(0x66_0003);
    // A call: the ALU tour at tier 10.
    let p = alu_tour();
    let build = || {
        let e = execute(&p, &[], &[], 10_000).unwrap();
        build_traces_salted_with(&p, &[], &[], [0u32; 4], &e, Tier(10), Default::default()).unwrap()
    };
    let t = build();
    let mut honest = build();
    assert!(repay_fixed_tables(&mut honest, Tier(10)).is_empty());
    assert!(honest.range.values == t.range.values && honest.nibble.values == t.nibble.values, "the repayment reproduces the honest fixed tables");
    let tampers = fuzz_batch("call", &t, Tier(10), usize::MAX, 96, &mut rng);

    // A bundle: the guest the chain proves most, at tier 14 (traces only — no proof).
    let (bp, words, be) = bundle_execution();
    let bt = build_traces_salted_with(&bp, &words, &[], [0u32; 4], &be, Tier(14), Default::default()).unwrap();
    fuzz_batch("bundle", &bt, Tier(14), 96, 64, &mut rng);

    // Replay a sample of the call's verdicts through the real prover: its debug build runs
    // Plonky3's own constraint and lookup checkers, a release build the verifier. Every kind of
    // refusal on both tables, and admitted tampers, must come out the same.
    let mut sample: Vec<Tamper> = Vec::new();
    let mut seen: BTreeMap<(usize, Verdict), usize> = BTreeMap::new();
    for tp in tampers.iter().filter(|tp| tp.row > 1) {
        let n = seen.entry((tp.chip, tp.verdict.clone())).or_insert(0);
        let quota = if tp.verdict == Verdict::Admitted { 2 } else { 1 };
        if *n < quota && (rng.next_u64() % 7 == 0) {
            *n += 1;
            sample.push(tp.clone());
        }
    }
    assert!(sample.iter().any(|tp| tp.verdict == Verdict::Admitted) && sample.iter().any(|tp| tp.verdict != Verdict::Admitted), "the sample has both kinds: {sample:?}");
    let m = Machine::new(FriProfile::Test);
    for tp in &sample {
        let mut t = build();
        let w = if tp.chip == 3 { alu::col::WIDTH } else { randprotocol_zkvm::tables::cpu::col::WIDTH };
        let trace = if tp.chip == 3 { &mut t.alu } else { &mut t.cpu };
        trace.values[tp.row * w + tp.col] = tp.value;
        repay_fixed_tables(&mut t, Tier(10));
        let refused = rejects(|| { let pr = m.prove_traces(&p, &t, Tier(10)); m.verify(&p.digest(), &pr) });
        eprintln!("replayed {tp:?}: the prover {}", if refused { "refuses" } else { "proves" });
        assert_eq!(refused, tp.verdict != Verdict::Admitted, "the batch check and the prover disagree on {tp:?}");
    }
}

// ── 4. Column roles ─────────────────────────────────────────────────────────────────────────────

/// The ALU's column names, for the role table.
fn column_name(c: usize) -> String {
    use alu::col::*;
    let named: [(usize, &str, usize); 18] = [
        (A, "A", 1), (B, "B", 1), (C, "C", 1), (A0, "A", 4), (B0, "B", 4), (C0, "C", 4), (Q0, "Q", 4), (S0, "S", 4), (T0, "T", 4),
        (SA, "SA", 1), (SB, "SB", 1), (SHH, "SHH", 1), (PW, "PW", 1), (CARRY0, "CARRY", 4), (INV, "INV", 1), (AH3, "AH3", 1), (BH_N, "BH_N", 1), (QH3, "QH3", 1),
    ];
    for (base, name, n) in named {
        if (base..base + n).contains(&c) {
            return if n == 1 { name.to_string() } else { format!("{name}{}", c - base) };
        }
    }
    match c { DIVZ => "DIVZ".into(), INVB => "INVB".into(), DB2 => "DB2".into(), DB3 => "DB3".into(), IS_REAL => "IS_REAL".into(), MULT => "MULT".into(), _ => format!("FLAG{}", c - FLAG0) }
}

/// Each op's columns and what reads them there, over honest rows: `m` the provided `ALU` tuple,
/// `r` a `RANGE8` lookup, `n` a nibble lookup (`AND4`/`OR4`/`XOR4`), `p` a `POW2` lookup, `k` a base
/// constraint (one that really depends on the column at that row), `w` `fill_row` writes a nonzero
/// value there. The flags, `IS_REAL` and `MULT` — structure, read on every row — are left out; a
/// column no row of the op reads or writes is not listed (it is free on that op).
const PINNED_ROLES: &str = "\
Add: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:krw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw SA:k SB:k CARRY0:kw CARRY1:kw CARRY2:kw CARRY3:kw DIVZ:k
Sub: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:krw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw SA:k SB:k CARRY0:kw CARRY1:kw CARRY2:kw CARRY3:kw DIVZ:k
And: A:kmw B:kmw C:kmw A0:knw A1:knw A2:knw A3:knw B0:knw B1:knw B2:knw B3:knw C0:knw C1:knw C2:knw C3:knw Q0:nw Q1:nw Q2:nw Q3:nw S0:nw S1:nw S2:nw S3:nw T0:nw T1:nw T2:nw T3:nw SA:k SB:k CARRY0:k CARRY1:k CARRY2:k CARRY3:k DIVZ:k
Or: A:kmw B:kmw C:kmw A0:knw A1:knw A2:knw A3:knw B0:knw B1:knw B2:knw B3:knw C0:knw C1:knw C2:knw C3:knw Q0:nw Q1:nw Q2:nw Q3:nw S0:nw S1:nw S2:nw S3:nw T0:nw T1:nw T2:nw T3:nw SA:k SB:k CARRY0:k CARRY1:k CARRY2:k CARRY3:k DIVZ:k
Xor: A:kmw B:kmw C:kmw A0:knw A1:knw A2:knw A3:knw B0:knw B1:knw B2:knw B3:knw C0:knw C1:knw C2:knw C3:knw Q0:nw Q1:nw Q2:nw Q3:nw S0:nw S1:nw S2:nw S3:nw T0:nw T1:nw T2:nw T3:nw SA:k SB:k CARRY0:k CARRY1:k CARRY2:k CARRY3:k DIVZ:k
Sll: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:knprw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw Q0:krw Q1:krw Q2:krw Q3:knrw SA:k SB:k SHH:npw PW:kpw CARRY0:k CARRY1:k CARRY2:k CARRY3:k BH_N:npw QH3:nw DIVZ:k
Srl: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:knprw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw Q0:krw Q1:krw Q2:krw Q3:krw S0:krw S1:krw S2:krw S3:krw T0:krw T1:krw T2:krw T3:krw SA:k SB:k SHH:npw PW:kpw CARRY0:k CARRY1:k CARRY2:k CARRY3:k BH_N:npw DIVZ:k
Sra: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:knrw B0:knprw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw Q0:krw Q1:krw Q2:krw Q3:krw S0:krw S1:krw S2:krw S3:krw T0:krw T1:krw T2:krw T3:krw SA:knw SB:k SHH:npw PW:kpw CARRY0:k CARRY1:k CARRY2:k CARRY3:k AH3:nw BH_N:npw DIVZ:k
Slt: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:knrw B0:krw B1:krw B2:krw B3:knrw C0:kw C1:k C2:k C3:k S0:krw S1:krw S2:krw S3:krw SA:knw SB:knw CARRY0:kw CARRY1:kw CARRY2:kw CARRY3:kw AH3:nw BH_N:nw DIVZ:k
Sltu: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:krw B1:krw B2:krw B3:krw C0:kw C1:k C2:k C3:k S0:krw S1:krw S2:krw S3:krw SA:k SB:k CARRY0:kw CARRY1:kw CARRY2:kw CARRY3:kw DIVZ:k
Eq: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:krw B1:krw B2:krw B3:krw C0:kw C1:k C2:k C3:k SA:k SB:k CARRY0:k CARRY1:k CARRY2:k CARRY3:k INV:kw DIVZ:k
Mul: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:krw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw Q0:kw Q1:kw Q2:kw Q3:kw S1:krw S2:krw S3:krw T0:krw T1:krw T2:krw T3:krw SA:k SB:k CARRY0:k CARRY1:k CARRY2:k CARRY3:k DIVZ:k
Mulh: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:knrw B0:krw B1:krw B2:krw B3:knrw C0:krw C1:krw C2:krw C3:krw Q0:kw Q1:kw Q2:kw Q3:kw S0:kw S1:krw S2:krw S3:krw T0:krw T1:krw T2:krw T3:krw SA:knw SB:knw CARRY0:k CARRY1:k CARRY2:k CARRY3:k AH3:nw BH_N:nw DIVZ:k
Mulhu: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:krw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw Q0:kw Q1:kw Q2:kw Q3:kw S1:krw S2:krw S3:krw T0:krw T1:krw T2:krw T3:krw SA:k SB:k CARRY0:k CARRY1:k CARRY2:k CARRY3:k DIVZ:k
Mulhsu: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:knrw B0:krw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw Q0:kw Q1:kw Q2:kw Q3:kw S0:kw S1:krw S2:krw S3:krw T0:krw T1:krw T2:krw T3:krw SA:knw SB:k CARRY0:k CARRY1:k CARRY2:k CARRY3:k AH3:nw DIVZ:k
Div: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:knrw B0:krw B1:krw B2:krw B3:knrw C0:krw C1:krw C2:krw C3:krw Q0:krw Q1:krw Q2:krw Q3:krw S0:krw S1:krw S2:krw S3:krw SA:knw SB:knw SHH:krw PW:krw CARRY0:k CARRY1:k CARRY2:k CARRY3:k INV:kw AH3:nw BH_N:nw QH3:kw DIVZ:kw INVB:kw DB2:krw DB3:krw
Divu: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:krw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw Q0:krw Q1:krw Q2:krw Q3:krw S0:krw S1:krw S2:krw S3:krw SA:k SB:k SHH:krw PW:krw CARRY0:k CARRY1:k CARRY2:k CARRY3:k INV:kw QH3:kw DIVZ:kw INVB:kw DB2:krw DB3:krw
Rem: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:knrw B0:krw B1:krw B2:krw B3:knrw C0:krw C1:krw C2:krw C3:krw Q0:krw Q1:krw Q2:krw Q3:krw S0:krw S1:krw S2:krw S3:krw SA:knw SB:knw SHH:krw PW:krw CARRY0:k CARRY1:k CARRY2:k CARRY3:k INV:kw AH3:nw BH_N:nw QH3:kw DIVZ:kw INVB:kw DB2:krw DB3:krw
Remu: A:kmw B:kmw C:kmw A0:krw A1:krw A2:krw A3:krw B0:krw B1:krw B2:krw B3:krw C0:krw C1:krw C2:krw C3:krw Q0:krw Q1:krw Q2:krw Q3:krw S0:krw S1:krw S2:krw S3:krw SA:k SB:k SHH:krw PW:krw CARRY0:k CARRY1:k CARRY2:k CARRY3:k INV:kw QH3:kw DIVZ:kw INVB:kw DB2:krw DB3:krw
";

fn roles_table() -> (String, BTreeMap<u32, BTreeMap<usize, BTreeSet<char>>>, Vec<String>) {
    use alu::col::*;
    let check = AluCheck::new();
    let mut rng = Rng::seed_from_u64(0x66_0004);
    let mut table: BTreeMap<u32, BTreeMap<usize, BTreeSet<char>>> = BTreeMap::new();
    // BH_N's partners: which of B's limbs share a lookup field with it, per op.
    let mut bh_partners: BTreeMap<u32, BTreeSet<usize>> = BTreeMap::new();
    for op in AluOp::ALL {
        let mut pairs: Vec<(u32, u32)> = EDGES.iter().step_by(3).flat_map(|&a| EDGES.iter().step_by(4).map(move |&b| (a, b))).collect();
        pairs.extend(random_pairs(&mut rng, 24));
        let roles = table.entry(op.code()).or_default();
        for (a, b) in pairs {
            let (row, _, _) = honest_row(op, a, b);
            let rows = AluCheck::at(&row);
            for col in A..WIDTH {
                if col == IS_REAL || col == MULT {
                    continue;
                }
                let set = roles.entry(col).or_default();
                if row[col] != Val::ZERO { set.insert('w'); }
                for (i, cols) in &check.interactions {
                    if !cols.contains(&col) || eval_rows(&i.count, &rows) == Val::ZERO { continue; }
                    if !i.fields.iter().any(|f| depends(f, &rows, Slot::Cur, col, &mut rng)) { continue; }
                    let tag = if i.bus_name == bus::ALU.name() { 'm' } else if i.bus_name == bus::RANGE8.name() { 'r' } else if i.bus_name == bus::POW2.name() { 'p' } else { 'n' };
                    set.insert(tag);
                    if col == BH_N {
                        for f in &i.fields {
                            if depends(f, &rows, Slot::Cur, BH_N, &mut rng) {
                                for bl in B0..B0 + 4 { if depends(f, &rows, Slot::Cur, bl, &mut rng) { bh_partners.entry(op.code()).or_default().insert(bl - B0); } }
                            }
                        }
                    }
                }
                if check.constraints.iter().any(|(c, cols)| cols.contains(&col) && depends(c, &rows, Slot::Cur, col, &mut rng)) {
                    set.insert('k');
                }
            }
        }
        roles.retain(|_, s| !s.is_empty());
    }
    let mut text = String::new();
    for (op, roles) in &table {
        let cells: Vec<String> = roles.iter().map(|(c, s)| format!("{}:{}", column_name(*c), s.iter().collect::<String>())).collect();
        text.push_str(&format!("{:?}: {}\n", AluOp::from_code(*op), cells.join(" ")));
    }
    let partners = bh_partners.iter().map(|(op, s)| format!("{:?} BH_N pairs with B limb(s) {s:?}", AluOp::from_code(*op))).collect();
    (text, table, partners)
}

#[test]
fn every_alu_column_has_the_role_its_op_gives_it() {
    use alu::col::*;
    let (text, table, partners) = roles_table();
    let mut failures = Vec::new();
    for (&code, roles) in &table {
        let op = AluOp::from_code(code);
        // `fill_row` writes only columns something reads on that op: a value written where nothing
        // looks is a column whose meaning on this op nobody checks.
        for (c, s) in roles {
            if s.contains(&'w') && s.len() == 1 { failures.push(format!("{op:?}: fill_row writes {} and nothing reads it", column_name(*c))); }
        }
        // C0..3 are not range-checked on compare rows (`g_c`); nothing but `word(C0) = C` may read them.
        if matches!(op, AluOp::Slt | AluOp::Sltu | AluOp::Eq) {
            for c in C0..C0 + 4 {
                let s = roles.get(&c).cloned().unwrap_or_default();
                if s.iter().any(|t| "mrnp".contains(*t)) { failures.push(format!("{op:?}: {} is read by a bus ({s:?}) on a row that does not range-check it", column_name(c))); }
            }
        }
        // BH_N means B0's high nibble on shift rows and B3's on the rows that take B's sign.
        let bh = roles.get(&BH_N).cloned().unwrap_or_default();
        let shift = matches!(op, AluOp::Sll | AluOp::Srl | AluOp::Sra);
        let signed_b = matches!(op, AluOp::Slt | AluOp::Mulh | AluOp::Div | AluOp::Rem);
        if !shift && !signed_b && !bh.is_empty() { failures.push(format!("{op:?}: BH_N has a role ({bh:?}) on an op that neither shifts nor takes B's sign")); }
    }
    for line in &partners {
        let shift = ["Sll ", "Srl ", "Sra "].iter().any(|p| line.starts_with(p));
        let want = if shift { "{0}" } else { "{3}" };
        if !line.ends_with(want) { failures.push(format!("{line}, expected {want}")); }
    }
    assert_eq!(partners.len(), 7, "BH_N is read on the three shifts and the four ops that take B's sign: {partners:?}");
    assert!(failures.is_empty(), "column roles:\n  {}", failures.join("\n  "));
    assert_eq!(text, PINNED_ROLES, "the ALU's column roles changed; if deliberately, re-pin PINNED_ROLES with:\n{text}");
}
