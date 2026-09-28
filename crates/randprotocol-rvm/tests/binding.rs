//! rVM R5 (randprotocol/fullnode#58): "every value a row writes is bound", for every chip.
//!
//! `tests/cpu.rs`' `every_value_the_cpu_row_writes_is_bound_on_every_opcode` is this rule for the
//! cpu table, opcode by opcode. RVM-1 and the three reduce-chip gaps were the same class on other
//! chips, so this is the rule table-driven over the rest of the machine, on a real trace of
//! `common::every_chip_program` (every chip reached), the way `tests/tables.rs` runs the
//! padding-row rule. A value is **bound on its row** when changing that one column alone breaks
//! a constraint on one of the two row pairs the row is part of (so it is pinned by the chip's own
//! arithmetic, or chained to the row before or after) — or, for a value a write carries, when the
//! column is the value of a read the same row sends (the memory table then pins it). Three rules:
//!
//! 1. **Writes.** Every `REG`/`RAM` message a chip sends with `is_write = 1` carries a value whose
//!    every input column is bound — the poseidon2 chip's outputs by the permutation, the reduce
//!    chip's write-backs by the column step over values it read or chained.
//! 2. **Reads the memory tables answer.** On every real row of the `REG` and `RAM` tables that is
//!    a read, `VALUE` is bound (read-after-write, or zero on a fresh address). The fields of the
//!    messages they receive are otherwise the sender's, matched by the bus.
//! 3. **Published values.** On every real row of the public table, `VALUE` is bound (to the
//!    proof's public values).
//!
//! The cpu is `tests/cpu.rs`'s; the program and range tables provide preprocessed entries and
//! write nothing.
mod common;

use p3_air::BaseAir;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use randprotocol_rvm::isa::F;
use randprotocol_rvm::machine::{Chip, Tier};
use randprotocol_rvm::tables::{bus, memory, public};

/// One chip's trace, constraints and messages, with the evaluation plumbing the rules share.
struct Table {
    name: &'static str,
    constraints: Vec<p3_air::symbolic::SymbolicExpression<F>>,
    interactions: Vec<p3_lookup::SymbolicInteraction<F>>,
    rows: Vec<Vec<F>>,
    pre: Vec<Vec<F>>,
    public: Vec<F>,
}

impl Table {
    fn h(&self) -> usize { self.rows.len() }
    fn pre_row(&self, i: usize) -> &[F] { self.pre.get(i).map(|r| r.as_slice()).unwrap_or(&[]) }
    /// The row pairs row `r` is part of: `(r − 1, r)` (the wrap pair `(h − 1, 0)` for row 0) and
    /// `(r, r + 1)`.
    fn pairs(&self, r: usize) -> [usize; 2] { [(r + self.h() - 1) % self.h(), r] }
    /// Every constraint holds on the pair starting at row `i`, with `rows` as given.
    fn pair_holds(&self, rows: &[Vec<F>], i: usize) -> bool {
        let j = (i + 1) % self.h();
        self.constraints.iter().all(|c| {
            common::eval_row(c, &rows[i], &rows[j], (self.pre_row(i), self.pre_row(j)), &self.public, i == 0, i == self.h() - 1)
                == F::ZERO
        })
    }
    /// Evaluates `e` on the pair starting at row `r`, with `cur` in place of row `r`.
    fn eval(&self, e: &p3_air::symbolic::SymbolicExpression<F>, r: usize, cur: &[F]) -> F {
        let j = (r + 1) % self.h();
        common::eval_row(e, cur, &self.rows[j], (self.pre_row(r), self.pre_row(j)), &self.public, r == 0, r == self.h() - 1)
    }
    /// Is column `col` of row `r` bound: does every change to it alone break a constraint on one
    /// of the row's two pairs? A random value, then `1` and `0` (a flag column is only ever free
    /// as a boolean, and a random value would fail its `assert_bool` and hide exactly that).
    fn bound(&self, r: usize, col: usize, rng: &mut impl rand::Rng) -> bool {
        let honest = self.rows[r][col];
        [common::random_felt(rng), common::random_felt(rng), F::ONE, F::ZERO].into_iter().filter(|x| *x != honest).all(|x| {
            let mut rows = self.rows.clone();
            rows[r][col] = x;
            !self.pairs(r).iter().all(|&i| self.pair_holds(&rows, i))
        })
    }
    /// The row-`r` columns `e` depends on (changing one alone changes `e`'s value there).
    fn inputs(&self, e: &p3_air::symbolic::SymbolicExpression<F>, r: usize, rng: &mut impl rand::Rng) -> Vec<usize> {
        let base = self.eval(e, r, &self.rows[r]);
        (0..self.rows[r].len())
            .filter(|&c| {
                (0..2).any(|_| {
                    let mut cur = self.rows[r].clone();
                    cur[c] += common::random_felt(rng) + F::ONE;
                    self.eval(e, r, &cur) != base
                })
            })
            .collect()
    }
}

/// The every-chip trace, one `Table` per chip but the cpu and range tables.
fn tables() -> Vec<Table> {
    let p = common::every_chip_program();
    let exec = randprotocol_rvm::emulator::execute(&p, &[], 1000).unwrap();
    let t = randprotocol_rvm::machine::build_traces(&p, &exec, Tier(8)).unwrap();
    let chips = randprotocol_rvm::machine::chips(&std::sync::Arc::new(p.clone()), Tier(8), t.reduce_log_height);
    assert_eq!(chips.len(), 8, "the program reaches every chip, the reduce chip included");
    let rows_of = |m: &p3_matrix::dense::RowMajorMatrix<F>| -> Vec<Vec<F>> {
        (0..m.height()).map(|r| m.values[r * m.width()..(r + 1) * m.width()].to_vec()).collect()
    };
    let mut out = Vec::new();
    for (k, (chip, trace)) in chips.iter().zip(t.as_slice()).enumerate() {
        let name = match chip {
            Chip::Cpu(_) | Chip::Range(_) => continue,
            Chip::Program(_) => "program",
            Chip::RegMemory(_) => "reg",
            Chip::RamMemory(_) => "ram",
            Chip::Poseidon2(_) => "poseidon2",
            Chip::Public(_) => "public",
            Chip::Reduce(_) => "reduce",
        };
        let (interactions, constraints) = common::symbolic_air(chip);
        out.push(Table {
            name,
            constraints,
            interactions,
            rows: rows_of(trace),
            pre: BaseAir::<F>::preprocessed_trace(chip).map(|m| rows_of(&m)).unwrap_or_default(),
            public: if k == randprotocol_rvm::machine::PUBLIC_VALUES_INDEX { t.public_values.clone() } else { vec![] },
        });
    }
    out
}

fn is_memory_bus(i: &p3_lookup::SymbolicInteraction<F>) -> bool {
    (i.bus_name == bus::REG.name() || i.bus_name == bus::RAM.name()) && i.fields.len() == 4
}

#[test]
fn every_value_a_chip_writes_or_answers_is_bound_on_its_row() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x0bc0_de58);
    let mut failures: Vec<String> = Vec::new();
    let mut checked = std::collections::BTreeMap::<&str, usize>::new();
    for t in tables() {
        for r in 0..t.h() {
            let cur = &t.rows[r];
            let active: Vec<&p3_lookup::SymbolicInteraction<F>> =
                t.interactions.iter().filter(|i| t.eval(&i.count, r, cur) != F::ZERO).collect();
            // Rule 1: the writes this row sends (the memory tables *receive*; rule 2 is theirs).
            if !matches!(t.name, "reg" | "ram") {
                let read_values: Vec<usize> = active
                    .iter()
                    .filter(|i| is_memory_bus(i) && t.eval(&i.fields[3], r, cur) == F::ZERO)
                    .filter_map(|i| common::as_column(&i.fields[2]))
                    .collect();
                for i in active.iter().filter(|i| is_memory_bus(i) && t.eval(&i.fields[3], r, cur) == F::ONE) {
                    *checked.entry(t.name).or_default() += 1;
                    for col in t.inputs(&i.fields[2], r, &mut rng) {
                        if !read_values.contains(&col) && !t.bound(r, col, &mut rng) {
                            failures.push(format!(
                                "{} row {r}: a {} write carries column {col}, which nothing binds (no read on the row, no constraint)",
                                t.name, i.bus_name
                            ));
                        }
                    }
                }
            }
            // Rule 2: the value a memory table answers a read with.
            if matches!(t.name, "reg" | "ram") && cur[memory::col::IS_REAL] == F::ONE && cur[memory::col::IS_WRITE] == F::ZERO {
                *checked.entry(t.name).or_default() += 1;
                if !t.bound(r, memory::col::VALUE, &mut rng) {
                    failures.push(format!("{} row {r}: a read's VALUE is free (no read-after-write, no fresh-address zero)", t.name));
                }
            }
            // Rule 3: a published value.
            if t.name == "public" && cur[public::col::IS_REAL] == F::ONE {
                *checked.entry(t.name).or_default() += 1;
                if !t.bound(r, public::col::VALUE, &mut rng) {
                    failures.push(format!("public row {r}: VALUE is free (not pinned to the proof's public values)"));
                }
            }
        }
    }
    eprintln!("bound values checked, per table: {checked:?}");
    for table in ["reg", "ram", "poseidon2", "public", "reduce"] {
        assert!(checked.get(table).copied().unwrap_or(0) > 0, "the trace exercises no {table} value: the rule checked nothing there");
    }
    assert!(failures.is_empty(), "values nothing binds:\n  {}", failures.join("\n  "));
}
