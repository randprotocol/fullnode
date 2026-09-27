//! Per-table unit tests: the memory table (Task 3), and later tables as they land (Tasks 4–5, 8).
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use randprotocol_rvm::emulator::MemAccess;
use randprotocol_rvm::isa::F;
use randprotocol_rvm::tables::memory::{col, memory_trace, REGISTER_BASE};
use randprotocol_rvm::tables::range::RangeCounts;

fn read(addr: u64, ts: u32, value: u64) -> MemAccess {
    MemAccess { addr, ts, value: F::from_u64(value), is_write: false }
}
fn write(addr: u64, ts: u32, value: u64) -> MemAccess {
    MemAccess { addr, ts, value: F::from_u64(value), is_write: true }
}

fn cell(t: &p3_matrix::dense::RowMajorMatrix<F>, row: usize, c: usize) -> F {
    t.get(row, c).unwrap()
}

#[test]
fn the_trace_sorts_by_addr_then_ts_and_read_after_write_holds() {
    // Deliberately unsorted: the builder sorts.
    let accesses = vec![
        write(100, 0, 42),
        write(REGISTER_BASE + 3, 0, 7),
        read(100, 16, 42),
        write(REGISTER_BASE + 3, 16, 9),
        read(REGISTER_BASE + 3, 32, 9),
        read(5, 48, 0), // first touch of a fresh address reads zero
    ];
    let mut counts = RangeCounts::default();
    let t = memory_trace(&accesses, 16, &mut counts);
    let mut last = (0u64, 0u64);
    for i in 0..6 {
        let addr = cell(&t, i, col::ADDR).as_canonical_u64();
        let ts = cell(&t, i, col::TS).as_canonical_u64();
        assert!((addr, ts) > last, "rows are sorted by (addr, ts)");
        last = (addr, ts);
        assert_eq!(cell(&t, i, col::IS_REAL), F::ONE);
    }
    // Row 0 is addr 5 (fresh read of zero), then 100, then the register cell.
    assert_eq!(cell(&t, 0, col::ADDR).as_canonical_u64(), 5);
    assert_eq!(cell(&t, 0, col::VALUE), F::ZERO);
    assert_eq!(cell(&t, 1, col::ADDR).as_canonical_u64(), 100);
    assert_eq!(cell(&t, 1, col::IS_WRITE), F::ONE);
    assert_eq!(cell(&t, 2, col::VALUE), F::from_u64(42));
    assert_eq!(cell(&t, 2, col::IS_WRITE), F::ZERO);
    assert_eq!(cell(&t, 3, col::ADDR).as_canonical_u64(), REGISTER_BASE + 3);
    // The delta limbs recompose the AIR's own key arithmetic (research's audit-ZM2 lesson):
    // the key is the address itself, and the delta is (key_n - key_l - 1) on an address change.
    let mut limb_sum = |i: usize| -> u64 {
        (0..4).map(|k| cell(&t, i, col::D0 + k).as_canonical_u64() << (8 * k)).sum::<u64>()
    };
    // Row 0 (addr 5) -> row 1 (addr 100): changed, delta = 100 - 5 - 1 = 94.
    assert_eq!(cell(&t, 0, col::ADDR_CHANGED), F::ONE);
    assert_eq!(limb_sum(0), 94);
    // Row 1 -> row 2: same address, ts 0 -> 16, delta = 15.
    assert_eq!(cell(&t, 1, col::ADDR_CHANGED), F::ZERO);
    assert_eq!(limb_sum(1), 15);
    // DIFF_INV is the inverse of the key difference on a change, zero otherwise.
    let diff = F::from_u64(100 - 5);
    assert_eq!(cell(&t, 0, col::DIFF_INV) * diff, F::ONE);
    assert_eq!(cell(&t, 1, col::DIFF_INV), F::ZERO);
}

#[test]
#[should_panic(expected = "two accesses to the same address at the same timestamp")]
fn a_same_address_same_timestamp_pair_is_a_builder_error() {
    let accesses = vec![write(7, 0, 1), read(7, 0, 1)];
    let mut counts = RangeCounts::default();
    memory_trace(&accesses, 4, &mut counts);
}

#[test]
#[should_panic(expected = "read does not match last write")]
fn a_read_that_disagrees_with_the_last_write_is_a_builder_error() {
    let accesses = vec![write(7, 0, 1), read(7, 8, 2)];
    let mut counts = RangeCounts::default();
    memory_trace(&accesses, 4, &mut counts);
}

#[test]
#[should_panic(expected = "first read of a fresh address must be zero")]
fn a_nonzero_first_touch_is_a_builder_error() {
    let accesses = vec![read(7, 0, 9)];
    let mut counts = RangeCounts::default();
    memory_trace(&accesses, 4, &mut counts);
}

#[test]
fn register_and_ram_histories_split_by_address_class() {
    // What `build_traces` (Task 6) does: each instance's trace is built from its own class.
    let accesses = vec![
        write(REGISTER_BASE + 1, 0, 11),
        write(300, 0, 22),
        read(REGISTER_BASE + 1, 16, 11),
        read(300, 16, 22),
    ];
    let is_reg = |a: &MemAccess| a.addr >= REGISTER_BASE;
    let regs: Vec<MemAccess> = accesses.iter().copied().filter(|a| is_reg(a)).collect();
    let ram: Vec<MemAccess> = accesses.iter().copied().filter(|a| !is_reg(a)).collect();
    let mut counts = RangeCounts::default();
    let rt = memory_trace(&regs, 4, &mut counts);
    let mt = memory_trace(&ram, 4, &mut counts);
    assert!(cell(&rt, 0, col::ADDR).as_canonical_u64() >= REGISTER_BASE);
    assert!(cell(&mt, 0, col::ADDR).as_canonical_u64() < REGISTER_BASE);
    assert_eq!(cell(&rt, 1, col::VALUE), F::from_u64(11));
    assert_eq!(cell(&mt, 1, col::VALUE), F::from_u64(22));
}

// ── Task 4: the public table and the interface digest ────────────────────────────────────────
use randprotocol_rvm::public_values::{public_digest, RVM_PUB_DOMAIN};
use randprotocol_rvm::tables::public::{col as pcol, public_trace, HEIGHT as PUBLIC_HEIGHT};

#[test]
fn the_public_trace_pins_one_selector_per_real_row_and_none_on_padding() {
    let published = [F::from_u64(11), F::from_u64(22), F::from_u64(33), F::from_u64(44)];
    let t = public_trace(&published, PUBLIC_HEIGHT);
    for i in 0..4 {
        assert_eq!(cell(&t, i, pcol::IDX).as_canonical_u64(), i as u64);
        assert_eq!(cell(&t, i, pcol::VALUE), published[i]);
        assert_eq!(cell(&t, i, pcol::IS_REAL), F::ONE);
        for j in 0..4 {
            assert_eq!(cell(&t, i, pcol::SEL0 + j), if i == j { F::ONE } else { F::ZERO }, "SEL_{j} on row {i}");
        }
    }
    for i in 4..PUBLIC_HEIGHT {
        assert_eq!(cell(&t, i, pcol::IS_REAL), F::ZERO);
        for j in 0..4 {
            assert_eq!(cell(&t, i, pcol::SEL0 + j), F::ZERO, "no selector on padding row {i}");
        }
    }
}

#[test]
#[should_panic(expected = "the interface digest is always four words")]
fn the_public_trace_accepts_exactly_four_published_words() {
    public_trace(&[F::ONE, F::TWO], PUBLIC_HEIGHT);
}

#[test]
fn the_interface_digest_is_capacity_seeded_and_binds_length() {
    // The construction, pinned against accidental change: domain and length in the capacity
    // lanes, then one permutation per four-word block with the padding-free partial rule.
    let words: Vec<F> = (1..=39u64).map(F::from_u64).collect();
    let mut state = [F::ZERO; 8];
    state[4] = F::from_u64(RVM_PUB_DOMAIN);
    state[5] = F::from_u64(39);
    let mut done = 0;
    while done < 39 {
        let k = (39 - done).min(4);
        state[..k].copy_from_slice(&words[done..done + k]);
        state = randprotocol_zkvm::hash::permute_state(state);
        done += k;
    }
    assert_eq!(public_digest(&words), <[F; 4]>::try_from(&state[..4]).unwrap());
    // A different length is a different digest even on a shared prefix (the capacity length) —
    // the padding-free-sponge concern `research/AGENTS.md` records, closed by construction.
    assert_ne!(public_digest(&words), public_digest(&words[..38]));
    // The domain does not collide with the program (15) or inner-vk (16) domains.
    assert_eq!(RVM_PUB_DOMAIN, 17);
}

// ── Task 6: the cpu table's width and every table's max constraint degree, pinned ─────────────
use randprotocol_rvm::isa::{Instr, Op, Program};
use randprotocol_rvm::machine::Tier;
use randprotocol_rvm::tables::{cpu, memory, poseidon2, program as program_table, public as public_table, range};

#[test]
fn the_table_widths_and_constraint_degrees_are_pinned() {
    assert_eq!(cpu::col::WIDTH, 72, "the cpu's designed width after Tasks 8–9 (26 selectors + the SPONGE group-2 limbs) and ZKQ-3 (the base-address groups 3 and 4)");
    assert_eq!(memory::col::WIDTH, 11);
    assert_eq!(program_table::col::WIDTH, 3);
    assert_eq!(program_table::pre::WIDTH, 4);
    assert_eq!(public_table::col::WIDTH, 7);
    assert_eq!(poseidon2::col::WIDTH, 341);
    assert_eq!(range::col::WIDTH, 1);
    let p = Program {
        instrs: vec![
            Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(7) },
            Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO },
        ],
        checkpoints: vec![],
    };
    // In `chips()` order: program, cpu, reg_memory, ram_memory, poseidon2, public, range.
    let degs = randprotocol_rvm::machine::max_constraint_degrees(&p, Tier(8));
    assert_eq!(degs.len(), 7);
    // Pinned at the measured values (the symbolic checker over the real, same-bus-packed lookup
    // contexts); a change here means a changed quotient-chunk count and belongs in the docs.
    // The cpu's 8 comes from the packed lookup fraction-pins, not its row logic (the same
    // finding `research/tests/tables.rs` records for the RV32 cpu, also 8 — and 8 is this
    // config's budget ceiling, `log2_ceil(degree - 1) <= log_blowup = 3`).
    assert_eq!(degs, vec![2, 8, 4, 4, 4, 2, 2]);
}

// ── The reduce chip's run rules, read off `ReduceAir::eval` (the 2026-09-27 zk scan) ──────────
use randprotocol_rvm::tables::{bus, reduce as reduce_table};

fn reduce_row(real: bool, first: bool, rng: &mut impl rand::Rng) -> Vec<F> {
    use reduce_table::col::*;
    let mut r: Vec<F> = (0..WIDTH).map(|_| common::random_felt(rng)).collect();
    r[IS_REAL] = F::from_bool(real);
    r[IS_FIRST] = F::from_bool(first);
    r
}

/// OPCODES-1 / TABLES-1, as a rule: every column a run row's RAM messages use as an *address* or
/// a *timestamp* must be carried from the row before by a transition constraint — one that, with
/// the next row inside the same run, depends on the next row's copy of the column, and with the
/// next row starting a new run does not (a run's first row is bound by the cpu's dispatch
/// instead). Only then is a later row's memory traffic at the address and the clock the dispatch
/// named, rather than wherever the prover put it.
#[test]
fn every_reduce_run_row_carries_its_addresses_and_clock_from_the_row_before() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x0bc0_de01);
    let (interactions, constraints) = common::symbolic_air(&reduce_table::ReduceAir);
    let (cur, next_in_run, next_first) = (reduce_row(true, false, &mut rng), reduce_row(true, false, &mut rng), reduce_row(true, true, &mut rng));
    // The columns the RAM messages' address and timestamp fields read.
    let mut used = std::collections::BTreeSet::new();
    for i in interactions.iter().filter(|i| i.bus_name == bus::RAM.name()) {
        for field in &i.fields[0..2] {
            for c in 0..reduce_table::col::WIDTH {
                if common::depends(field, &cur, &next_in_run, c, false, &mut rng) {
                    used.insert(c);
                }
            }
        }
    }
    assert!(used.contains(&reduce_table::col::CLK) && used.contains(&reduce_table::col::DESCR_PTR), "sanity: {used:?}");
    let unchained: Vec<usize> = used
        .iter()
        .copied()
        .filter(|&c| {
            !constraints.iter().any(|k| {
                common::depends(k, &cur, &next_in_run, c, true, &mut rng) && !common::depends(k, &cur, &next_first, c, true, &mut rng)
            })
        })
        .collect();
    assert!(
        unchained.is_empty(),
        "the reduce chip's RAM messages use columns {unchained:?} (CLK = {}) as an address or timestamp, and nothing carries them from one run row to the next",
        reduce_table::col::CLK
    );
}

/// V-OPCODES-1, as a rule: no padding row the chip's constraints admit sends anything. Every
/// assignment of the row-kind witnesses (`IS_FIRST`, `IS_LAST`, `LEN1`, `LEN` ∈ {0, 1, 2}, the
/// gadget's inverse solved where it can be) to a padding row followed by ordinary padding is
/// tried; each one every constraint accepts must have a zero count on every message the chip
/// sends or provides (`RAM`, `REDUCE`, `RANGE8`).
#[test]
fn no_admissible_padding_reduce_row_sends_a_message() {
    use p3_field::Field;
    use reduce_table::col::*;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x0bc0_de02);
    let (interactions, constraints) = common::symbolic_air(&reduce_table::ReduceAir);
    let mut next = vec![F::ZERO; WIDTH];
    next[LEN1_INV] = F::NEG_ONE; // ordinary padding (`reduce_trace`'s own)
    let mut sends = Vec::new();
    for first in [false, true] {
        for last in [false, true] {
            for len1 in [false, true] {
                for len in 0u64..3 {
                    let mut cur: Vec<F> = (0..WIDTH).map(|_| common::random_felt(&mut rng)).collect();
                    cur[IS_REAL] = F::ZERO;
                    cur[IS_FIRST] = F::from_bool(first);
                    cur[IS_LAST] = F::from_bool(last);
                    cur[LEN1] = F::from_bool(len1);
                    cur[LEN] = F::from_u64(len);
                    cur[LEN1_INV] = if len == 1 { F::ZERO } else { (F::ONE - cur[LEN1]) * (cur[LEN] - F::ONE).inverse() };
                    if constraints.iter().any(|c| common::eval_at(c, &cur, &next) != F::ZERO) {
                        continue; // not an admissible padding row
                    }
                    for i in &interactions {
                        if common::eval_at(&i.count, &cur, &next) != F::ZERO {
                            sends.push(format!("IS_FIRST={first} IS_LAST={last} LEN1={len1} LEN={len}: sends on {}", i.bus_name));
                        }
                    }
                }
            }
        }
    }
    sends.dedup();
    assert!(sends.is_empty(), "admissible padding rows of the reduce chip send messages:\n  {}", sends.join("\n  "));
}

/// ZKR-4, as a rule: a run ends on its `IS_LAST` row. A real row that is not a last row must be
/// followed by a row of the same run — so the constraints must refuse it followed by padding, or
/// by a new run's first row, and must refuse it as the table's final row. Checked on the honest
/// run's own first row (`reduce_run_program`'s three columns, from `build_traces`), so every
/// row-local constraint holds and only a run-structure rule can refuse the pair.
#[test]
fn a_reduce_run_must_end_on_its_last_row() {
    use reduce_table::col::*;
    let p = {
        let mut v = vec![];
        let st = |v: &mut Vec<Instr>, addr: u64, val: u64| {
            v.push(Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(val) });
            v.push(Instr { op: Op::Store, rd: 1, ra: 0, b: F::from_u64(addr) });
        };
        for (k, val) in [100u64, 120, 3, 1, 0, 0, 0, 1, 0, 3, 0].iter().enumerate() {
            st(&mut v, 200 + k as u64, *val);
        }
        v.push(Instr { op: Op::Faddi, rd: 2, ra: 0, b: F::from_u64(200) });
        v.push(Instr { op: Op::Reduce, rd: 0, ra: 2, b: F::ZERO });
        for _ in 0..4 {
            v.push(Instr { op: Op::Public, rd: 0, ra: 0, b: F::ZERO });
        }
        v.push(Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO });
        Program { instrs: v, checkpoints: vec![] }
    };
    let exec = randprotocol_rvm::emulator::execute(&p, &[], 1000).unwrap();
    let t = randprotocol_rvm::machine::build_traces(&p, &exec, Tier(8)).unwrap();
    let red = t.reduce.unwrap();
    let row = |k: usize| red.values[k * WIDTH..(k + 1) * WIDTH].to_vec();
    let (first, padding) = (row(0), row(3));
    assert_eq!((first[IS_REAL], first[IS_FIRST], first[IS_LAST]), (F::ONE, F::ONE, F::ZERO), "row 0 opens a three-row run");
    assert_eq!(padding[IS_REAL], F::ZERO);
    let (_, constraints) = common::symbolic_air(&reduce_table::ReduceAir);
    // The honest pair holds, so the harness is not refusing it for an unrelated reason.
    assert!(constraints.iter().all(|c| common::eval_at(c, &first, &row(1)) == F::ZERO), "the honest pair holds");
    let refused = |cur: &[F], next: &[F], last: bool| constraints.iter().any(|c| common::eval_at_boundary(c, cur, next, false, last) != F::ZERO);
    let mut open = Vec::new();
    if !refused(&first, &padding, false) {
        open.push("a non-last run row followed by padding");
    }
    if !refused(&first, &first, false) {
        open.push("a non-last run row followed by a new run's first row");
    }
    if !refused(&first, &padding, true) {
        open.push("a non-last run row as the table's final row");
    }
    assert!(open.is_empty(), "the reduce chip lets a run stop short of its IS_LAST row: {open:?}");
}

/// ZKQ-3 on the reduce chip: the cpu's REDUCE row range-checks nothing (REDUCE is not among its
/// subjects), so the chip must: the descriptor's eleven cells and both arrays' first and last
/// cells. Each case moves one of them below zero on the honest run's first row (and its chained
/// copies on the next row), with the run's last cell back inside the range, and asks whether any
/// choice of byte limbs completes the pair.
#[test]
fn a_reduce_run_touching_a_cell_outside_the_address_space_is_refused() {
    use reduce_table::col::*;
    let p = {
        let mut v = vec![];
        for (k, val) in [100u64, 120, 3, 1, 0, 0, 0, 1, 0, 3, 0].iter().enumerate() {
            v.push(Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(*val) });
            v.push(Instr { op: Op::Store, rd: 1, ra: 0, b: F::from_u64(200 + k as u64) });
        }
        v.push(Instr { op: Op::Faddi, rd: 2, ra: 0, b: F::from_u64(200) });
        v.push(Instr { op: Op::Reduce, rd: 0, ra: 2, b: F::ZERO });
        for _ in 0..4 {
            v.push(Instr { op: Op::Public, rd: 0, ra: 0, b: F::ZERO });
        }
        v.push(Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO });
        Program { instrs: v, checkpoints: vec![] }
    };
    let exec = randprotocol_rvm::emulator::execute(&p, &[], 1000).unwrap();
    let t = randprotocol_rvm::machine::build_traces(&p, &exec, Tier(8)).unwrap();
    let red = t.reduce.unwrap();
    let row = |k: usize| red.values[k * WIDTH..(k + 1) * WIDTH].to_vec();
    let (interactions, constraints) = common::symbolic_air(&reduce_table::ReduceAir);
    let limbs = common::range_checked_columns(&interactions);
    let minus = |k: u64| F::ZERO - F::from_u64(k);
    // The run is three columns: vals are cells ADDR_V .. ADDR_V + 5, row cells ADDR_R .. ADDR_R + 2.
    let cases: [(&str, usize, F); 3] = [
        ("the descriptor at p − 5 (its last cell, + 10, is 5)", DESCR_PTR, minus(5)),
        ("the vals array at p − 2 (its last cell, + 5, is 3)", ADDR_V, minus(2)),
        ("the row array at p − 1 (its last cell, + 2, is 1)", ADDR_R, minus(1)),
    ];
    assert!(common::admits_byte_limbs(&constraints, &row(0), &row(1), &limbs).is_ok(), "the honest pair is admitted");
    let mut admitted = Vec::new();
    for (what, col, value) in cases {
        let (mut cur, mut next) = (row(0), row(1));
        let shift = value - cur[col];
        cur[col] += shift;
        next[col] += shift; // the chained copy on the run's next row
        if common::admits_byte_limbs(&constraints, &cur, &next, &limbs).is_ok() {
            admitted.push(what);
        }
    }
    assert!(admitted.is_empty(), "ZKQ-3: the reduce chip admits runs outside the address space: {admitted:?}");
}

// ── R6 / RVMv2 R5: no admissible padding row of any chip sends a message ─────────────────────
//
// `no_admissible_padding_reduce_row_sends_a_message` (above) is this rule for one chip, with the
// row kinds enumerated by hand. This is the rule for every chip, table-driven the way
// `research/tests/air_invariants.rs` runs it for the RV32 machine: from an honest padding row
// between two honest padding rows, every column the constraints leave free there (one at a time,
// kept only if both row pairs still satisfy every constraint) is set at random, and then no
// message the chip sends or provides may have a non-zero count. The range table is skipped: every
// row of it is a table entry whose count is a provided multiplicity, balanced by the global sum.

/// A program that reaches every chip: registers and RAM (`STORE`, `LOAD`), a `POSEIDON2`
/// dispatch, a three-row `REDUCE` run over a hand-written descriptor, the four `PUBLIC`s, `HALT`.
fn every_chip_program() -> Program {
    let mut v = vec![];
    let st = |v: &mut Vec<Instr>, addr: u64, val: u64| {
        v.push(Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(val) });
        v.push(Instr { op: Op::Store, rd: 1, ra: 0, b: F::from_u64(addr) });
    };
    for (k, val) in [100u64, 120, 3, 1, 0, 0, 0, 1, 0, 3, 0].iter().enumerate() {
        st(&mut v, 200 + k as u64, *val);
    }
    v.push(Instr { op: Op::Load, rd: 3, ra: 0, b: F::from_u64(201) });
    v.push(Instr { op: Op::Faddi, rd: 2, ra: 0, b: F::from_u64(200) });
    v.push(Instr { op: Op::Reduce, rd: 0, ra: 2, b: F::ZERO });
    v.push(Instr { op: Op::Faddi, rd: 7, ra: 0, b: F::from_u64(64) });
    v.push(Instr { op: Op::Poseidon2, rd: 0, ra: 7, b: F::ZERO });
    for _ in 0..4 {
        v.push(Instr { op: Op::Public, rd: 0, ra: 0, b: F::ZERO });
    }
    v.push(Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO });
    Program { instrs: v, checkpoints: vec![] }
}

#[test]
fn no_admissible_padding_row_of_any_chip_sends_a_message() {
    use p3_air::BaseAir;
    use randprotocol_rvm::machine::Chip;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x0bc0_de03);
    let p = every_chip_program();
    let exec = randprotocol_rvm::emulator::execute(&p, &[], 1000).unwrap();
    let t = randprotocol_rvm::machine::build_traces(&p, &exec, Tier(8)).unwrap();
    assert!(t.reduce.is_some(), "the program dispatches REDUCE, so the batch declares the chip");
    let chips = randprotocol_rvm::machine::chips(&std::sync::Arc::new(p.clone()), Tier(8), t.reduce_log_height);
    let row_of = |m: &p3_matrix::dense::RowMajorMatrix<F>, r: usize| -> Vec<F> {
        let w = m.width();
        m.values[r * w..(r + 1) * w].to_vec()
    };
    let mut failures = Vec::new();
    let mut checked = 0;
    for (k, (chip, trace)) in chips.iter().zip(t.as_slice()).enumerate() {
        if matches!(chip, Chip::Range(_)) {
            continue;
        }
        let h = trace.height();
        let r = h - 2;
        let pre = BaseAir::<F>::preprocessed_trace(chip);
        let pre_row = |i: usize| pre.as_ref().map(|m| row_of(m, i)).unwrap_or_default();
        let public: Vec<F> = if k == randprotocol_rvm::machine::PUBLIC_VALUES_INDEX { t.public_values.clone() } else { vec![] };
        let (interactions, constraints) = common::symbolic_air(chip);
        let (prev, next) = (row_of(trace, r - 1), row_of(trace, r + 1));
        let holds = |cur: &Vec<F>| {
            constraints.iter().all(|c| {
                common::eval_full(c, &prev, cur, (&pre_row(r - 1), &pre_row(r)), &public) == F::ZERO
                    && common::eval_full(c, cur, &next, (&pre_row(r), &pre_row(r + 1)), &public) == F::ZERO
            })
        };
        let sends = |cur: &Vec<F>| -> Vec<String> {
            interactions
                .iter()
                .filter(|i| common::eval_full(&i.count, cur, &next, (&pre_row(r), &pre_row(r + 1)), &public) != F::ZERO)
                .map(|i| i.bus_name.clone())
                .collect()
        };
        let mut cur = row_of(trace, r);
        assert!(holds(&cur), "chip {k}: the honest row {r} fails a constraint");
        assert!(sends(&cur).is_empty(), "chip {k}: honest row {r} of {h} is not padding (it sends {:?})", sends(&cur));
        // And its predecessor is padding, so `r` is not the real/padding boundary — where a
        // table's own rules may admit one more real row and a cross-table balance refuses it (the
        // RV32 harness's comment in `research/tests/air_invariants.rs` has the case it met).
        assert!(
            interactions.iter().all(|i| common::eval_full(&i.count, &prev, &cur, (&pre_row(r - 1), &pre_row(r)), &public) == F::ZERO),
            "chip {k}: row {} before the checked row is not padding",
            r - 1
        );
        let mut free = Vec::new();
        // A random value first, then `1`: a flag column is only ever free as a boolean, and a
        // random field element would fail its `assert_bool` and hide exactly that freedom.
        for col in 0..cur.len() {
            let keep = cur[col];
            for candidate in [common::random_felt(&mut rng), F::ONE] {
                cur[col] = candidate;
                if holds(&cur) {
                    free.push(col);
                    break;
                }
                cur[col] = keep;
            }
        }
        checked += 1;
        let s = sends(&cur);
        eprintln!("chip {k}: padding row {r} of {h}, {} of {} columns free, sends {s:?}", free.len(), cur.len());
        if !s.is_empty() {
            failures.push(format!("chip {k}: a padding row with free columns {free:?} sends on {s:?}"));
        }
    }
    assert_eq!(checked, 7, "every chip but range: program, cpu, reg, ram, poseidon2, public, reduce");
    assert!(failures.is_empty(), "admissible padding rows send messages:\n  {}", failures.join("\n  "));
}
/// R4 (the 2026-09-27 rVM review): the pin above builds a program with no `REDUCE`, so its batch
/// has seven instances and the reduce chip's width and degree were pinned by nothing — the chip
/// every dormant high finding of that review (RVM-2, TABLES-1, V-TABLES-1) lives in. Here the same
/// pin over a program that dispatches `REDUCE`, with the chip declared: eight instances, reduce
/// last, and the other seven unchanged by its presence.
#[test]
fn the_reduce_chip_width_and_constraint_degree_are_pinned() {
    assert_eq!(reduce_table::col::WIDTH, 39, "the reduce chip's designed width (Task 8's run row, ZKQ-3's range limbs)");
    let p = Program {
        instrs: vec![
            Instr { op: Op::Faddi, rd: 2, ra: 0, b: F::from_u64(200) },
            Instr { op: Op::Reduce, rd: 0, ra: 2, b: F::ZERO },
            Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO },
        ],
        checkpoints: vec![],
    };
    let degs = randprotocol_rvm::machine::max_constraint_degrees_declaring(&p, Tier(8), true);
    assert_eq!(degs.len(), 8, "program, cpu, reg, ram, poseidon2, public, range, reduce");
    assert_eq!(&degs[..7], &[2, 8, 4, 4, 4, 2, 2], "declaring the reduce chip moves no other table's degree");
    // Measured: 8 — like the cpu's, this config's budget ceiling (`log2_ceil(degree − 1) ≤
    // log_blowup = 3`), so the reduce chip has no degree headroom left: one more degree-2 factor on
    // any of its lookups or constraints and the batch needs a larger blowup. That is what a pin is
    // for.
    assert_eq!(degs[7], 8);
}

