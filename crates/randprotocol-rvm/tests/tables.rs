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
    assert_eq!(cpu::col::WIDTH, 84, "72 + the HINTN selector + its eight word columns (Cut B) + the COMPRESS selector (Cut C) + the FOLD and POW selectors (phase 3)");
    assert_eq!(memory::col::WIDTH, 11);
    assert_eq!(program_table::col::WIDTH, 3);
    assert_eq!(program_table::pre::WIDTH, 4);
    assert_eq!(public_table::col::WIDTH, 7);
    assert_eq!(poseidon2::col::WIDTH, 343, "341 + IS_COMPRESS, BIT (Cut C)");
    assert_eq!(range::col::WIDTH, 1);
    let p = Program {
        instrs: vec![
            Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(7) },
            Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO },
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
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

/// R4 (the 2026-09-27 rVM review): the pin above builds a program with no `REDUCE`, so its batch
/// has seven instances and the reduce chip's width and degree were pinned by nothing — the chip
/// every dormant high finding of that review (RVM-2, TABLES-1, V-TABLES-1) lives in. Here the same
/// pin over a program that dispatches `REDUCE`, with the chip declared: eight instances, reduce
/// last, and the other seven unchanged by its presence.
#[test]
fn the_reduce_chip_width_and_constraint_degree_are_pinned() {
    assert_eq!(reduce_table::col::WIDTH, 81, "Cut D's 30 + the fold kind's 40 (Cut E2) + the pow kind's 11 (Cut F)");
    assert_eq!(reduce_table::pre::WIDTH, 20, "preprocessed 9 + the 11-column coefficient table (Cut E2)");
    let p = common::reduce_chain_program(true);
    let degs = randprotocol_rvm::machine::max_constraint_degrees_declaring(&p, Tier(8), true);
    assert_eq!(degs.len(), 8, "program, cpu, reg, ram, poseidon2, public, range, reduce");
    assert_eq!(&degs[..7], &[2, 8, 4, 4, 4, 2, 2], "declaring the reduce chip moves no other table's degree");
    // Measured: 8 — like the cpu's, this config's budget ceiling (`log2_ceil(degree − 1) ≤
    // log_blowup = 3`), so the reduce chip has no degree headroom left: one more degree-2 factor on
    // any of its lookups or constraints and the batch needs a larger blowup. That is what a pin is
    // for. Cut D made every message degree 1 (counts and values are columns); the measured value
    // did not move: 8 → 8. Cut E2's fold kind (two buses, four more RAM sends, every constraint
    // degree 2 before gating) measured 8 → 8 as well, and so did Cut F's pow kind (one more
    // lookup bus, two RAM sends, two RANGE8 lookups; its product step is degree 5 after gating).
    assert!(degs[7] <= 8, "the reduce chip's degree must stay within log_blowup = 3");
    assert_eq!(degs[7], 8, "Cut D, Cut E2, Cut F: the reduce chip's degree, measured (≤ 8)");
}

// ── The reduce chip's run rules after Cut D (read off `ReduceAir::eval`) ─────────────────────
use randprotocol_rvm::tables::{bus, reduce as reduce_table};

fn reduce_air() -> reduce_table::ReduceAir {
    reduce_table::ReduceAir::new(std::sync::Arc::new(vec![]), 16)
}

/// The run row kind's own columns (Cut D's 30); the fold and pow kinds (Tasks 3–4) append theirs
/// after it, and these rule tests hold them at zero — they are about run rows.
const REDUCE_KIND_COLS: usize = 30;

fn reduce_row(real: bool, first: bool, rng: &mut impl rand::Rng) -> Vec<F> {
    use reduce_table::col::*;
    let mut r: Vec<F> = (0..WIDTH).map(|c| if c < REDUCE_KIND_COLS { common::random_felt(rng) } else { F::ZERO }).collect();
    r[IS_REAL] = F::from_bool(real);
    r[IS_FIRST] = F::from_bool(first);
    r
}

/// A row of the fold kind (Cut E2) or the pow kind (Cut F): that kind's own columns and the shared
/// `CLK` random, its kind flag set, `first` its start flag, and every other column zero — the
/// carry rule below is about one kind's rows at a time.
fn kind_row(kind: std::ops::Range<usize>, flag: usize, start: usize, first: bool, rng: &mut impl rand::Rng) -> Vec<F> {
    use reduce_table::col::*;
    let mut r = vec![F::ZERO; WIDTH];
    for c in kind.chain([CLK]) {
        r[c] = common::random_felt(rng);
    }
    r[flag] = F::ONE;
    r[start] = F::from_bool(first);
    r
}

/// OPCODES-1 / TABLES-1, as a rule, for each of the chip's three row kinds: every column a row's
/// RAM messages use as an address or a timestamp is carried from the row before when the next row
/// is the same run's — and so is every column in that kind's `must` list, which holds the carried
/// columns that are not RAM fields but would free a run if uncarried. The final fix wave (the
/// whole-branch review, Important 1) widened this from the reduce kind's 30 columns to the fold
/// kind (`CLK`, `F_MSG`, `F_A`, `F_K`, `U0`, `U1`: the addresses, the arity the end rule and the
/// result address read, the index, and `u`) and the pow kind (`CLK`, `P_BASE`, `P_OFF`, `P_L`,
/// `P_K`), and added the reduce kind's `ROW_END` (R5's end marker: uncarried, a run can end early
/// and skip columns — `tests/cheating.rs`'s `a_reduce_run_ending_early_is_rejected_by_the_row_end_carry`).
/// A column is carried when some constraint depends on its next-row value along a run and no
/// longer does when the next row starts a new run.
#[test]
fn every_reduce_run_row_carries_its_addresses_and_clock_from_the_row_before() {
    use reduce_table::col::*;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x0bc0_de01);
    let (interactions, constraints) = common::symbolic_air(&reduce_air());
    type RowFn = Box<dyn Fn(bool, &mut rand::rngs::StdRng) -> Vec<F>>;
    let kinds: [(&str, std::ops::Range<usize>, RowFn, Vec<usize>); 3] = [
        ("reduce", 0..REDUCE_KIND_COLS, Box::new(|first, rng| reduce_row(true, first, rng)), vec![CLK, ADDR_V, ADDR_R, KEY, ALPHA_ADDR, RES, ROW_END]),
        // Phase-2 rows that are not last: the phase switch, which reads `n(F_K)` too, is off there,
        // so the K step is the one rule on `n(F_K)` (on phase-1 rows the switch masked its
        // deletion — mutation-checked, final fix wave).
        ("fold", IS_FOLD..IS_POW, Box::new(|first, rng| {
            let mut r = kind_row(IS_FOLD..IS_POW, IS_FOLD, F_FIRST, first, rng);
            r[F_PH1] = F::ZERO;
            r[F_LAST] = F::ZERO;
            r
        }), vec![CLK, F_MSG, F_A, F_K, U0, U1]),
        ("pow", IS_POW..WIDTH, Box::new(|first, rng| kind_row(IS_POW..WIDTH, IS_POW, P_FIRST, first, rng)), vec![CLK, P_BASE, P_OFF, P_L, P_K]),
    ];
    for (name, cols, row, must) in kinds {
        let (cur, next_in_run, next_first) = (row(false, &mut rng), row(false, &mut rng), row(true, &mut rng));
        let mut used = std::collections::BTreeSet::new();
        for i in interactions.iter().filter(|i| i.bus_name == bus::RAM.name()) {
            for field in &i.fields[0..2] {
                for c in cols.clone().chain([CLK]) {
                    if common::depends(field, &cur, &next_in_run, c, false, &mut rng) {
                        used.insert(c);
                    }
                }
            }
        }
        assert!(used.iter().all(|c| must.contains(c)), "{name}: a RAM address/timestamp column outside the pinned list: {used:?} against {must:?}");
        assert!(used.contains(&CLK) && used.len() >= 3, "sanity, {name}: {used:?}");
        let unchained: Vec<usize> = must
            .iter()
            .copied()
            .filter(|&c| {
                !constraints.iter().any(|k| common::depends(k, &cur, &next_in_run, c, true, &mut rng) && !common::depends(k, &cur, &next_first, c, true, &mut rng))
            })
            .collect();
        assert!(unchained.is_empty(), "{name} kind: columns {unchained:?} are not carried along a run");
    }
}

/// V-OPCODES-1, as a rule: no admissible padding row sends or provides anything, whatever its
/// row-kind witnesses — off the provider region (the preprocessed columns are zero there). Every
/// column is random except the three kind columns (zero: it is padding) and the witnesses that are
/// enumerated: the run kind's `IS_FIRST`, `IS_LAST`, `CHAIN_START`, `CARRY`, the fold kind's
/// `F_FIRST`, `F_PH1`, `F_LAST`, the pow kind's `P_FIRST`, `P_LAST`, `P_BIT`, and the two provider
/// multiplicities `MULT` and `MULT_C` (each zero or random). Task 5 sweep (Task 3 review): the
/// fold and pow kinds' columns are random here too — they were held at zero, so a padding row's
/// fold or pow message was never tried — and a random `MULT`/`MULT_C` off the provider region is
/// tried, which the provider rules alone refuse (`a_multiplicity_off_the_layout_is_refused_by_the_provider_rule`).
#[test]
fn no_admissible_padding_reduce_row_sends_a_message() {
    use reduce_table::col::*;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x0bc0_de02);
    let (interactions, constraints) = common::symbolic_air(&reduce_air());
    let next = vec![F::ZERO; WIDTH];
    let flags = [IS_FIRST, IS_LAST, CHAIN_START, CARRY, F_FIRST, F_PH1, F_LAST, P_FIRST, P_LAST, P_BIT];
    let mut sends = Vec::new();
    let mut admitted = 0;
    for bits in 0u32..1 << (flags.len() + 2) {
        let mut cur: Vec<F> = (0..WIDTH).map(|_| common::random_felt(&mut rng)).collect();
        for c in [IS_REAL, IS_FOLD, IS_POW] {
            cur[c] = F::ZERO;
        }
        for (k, &c) in flags.iter().enumerate() {
            cur[c] = F::from_bool(bits >> k & 1 != 0);
        }
        cur[WRITES] = cur[IS_LAST] * (F::ONE - cur[CARRY]);
        cur[READ_ALPHA] = cur[IS_FIRST] * cur[CHAIN_START];
        if bits >> flags.len() & 1 == 0 {
            cur[MULT] = F::ZERO;
        }
        if bits >> (flags.len() + 1) & 1 == 0 {
            cur[MULT_C] = F::ZERO;
        }
        if constraints.iter().any(|c| common::eval_at(c, &cur, &next) != F::ZERO) {
            continue;
        }
        admitted += 1;
        for i in &interactions {
            if common::eval_at(&i.count, &cur, &next) != F::ZERO {
                sends.push(format!("kinds {bits:012b}: sends on {}", i.bus_name));
            }
        }
    }
    assert!(admitted >= 1, "the all-zero kind assignment is admissible padding");
    assert!(sends.is_empty(), "admissible padding rows of the reduce chip send messages:\n  {}", sends.join("\n  "));
}

/// Task 5 sweep (Task 1a review): `MULT·(1 − L_IS_ENTRY) = 0`, pinned on its own. A row past the
/// layout with `MULT = 1` would provide the all-zero `REDUCE_LAYOUT` entry. No run can consume that
/// entry — its flags are 0, so its first row must be a continuation entered by a carry from entry
/// `ENTRY − 1 = −1`, and every real row's `ENTRY` is a layout index (looked up on a first row,
/// carried on the rest), never `−1` — so an end-to-end forgery is refused by the bus imbalance as
/// well (`tests/cheating.rs`'s `a_multiplicity_off_the_layout_is_rejected`), and the provider rule
/// is defence in depth that no proof-level forgery can isolate. Here it is isolated at the AIR: on
/// an honest padding row off the provider region, setting `MULT` (or, for the coefficient table's
/// rule, `MULT_C`) violates exactly one constraint, and it is that rule — the row with the
/// multiplicity cleared satisfies every constraint.
#[test]
fn a_multiplicity_off_the_layout_is_refused_by_the_provider_rule() {
    use reduce_table::col::*;
    let (_, constraints) = common::symbolic_air(&reduce_air());
    let zero = vec![F::ZERO; WIDTH];
    assert!(constraints.iter().all(|c| common::eval_at(c, &zero, &zero) == F::ZERO), "an all-zero padding row is admissible");
    for (name, c) in [("MULT", MULT), ("MULT_C", MULT_C)] {
        let mut cur = zero.clone();
        cur[c] = F::ONE;
        let violated: Vec<usize> = (0..constraints.len()).filter(|&k| common::eval_at(&constraints[k], &cur, &zero) != F::ZERO).collect();
        assert_eq!(violated.len(), 1, "{name} = 1 off the provider region violates exactly one constraint: {violated:?}");
        assert_eq!(common::eval_at(&constraints[violated[0]], &cur, &zero), F::ONE, "{name}: the violated rule is `{name}·(1 − provider flag)`");
    }
}

/// ZKR-4 and R5, as a rule: a run ends exactly on the row where ADDR_R = ROW_END. Checked on
/// the honest split chain's rows with their real preprocessed rows.
#[test]
fn a_reduce_run_must_end_where_its_row_ends() {
    use p3_air::BaseAir;
    use reduce_table::col::*;
    let p = common::reduce_chain_program(true);
    let exec = randprotocol_rvm::emulator::execute(&p, &[], 1000).unwrap();
    let t = randprotocol_rvm::machine::build_traces(&p, &exec, Tier(8)).unwrap();
    let air = reduce_table::ReduceAir::new(std::sync::Arc::new(p.reduce_layout.clone()), 1 << t.reduce_log_height);
    let pre = BaseAir::<F>::preprocessed_trace(&air).unwrap();
    let red = t.reduce.unwrap();
    let row = |k: usize| red.values[k * WIDTH..(k + 1) * WIDTH].to_vec();
    let prow = |k: usize| pre.values[k * reduce_table::pre::WIDTH..(k + 1) * reduce_table::pre::WIDTH].to_vec();
    let (_, constraints) = common::symbolic_air(&air);
    let holds = |cur: &[F], next: &[F], k: usize| constraints.iter().all(|c| common::eval_full(c, cur, next, (&prow(k), &prow(k + 1)), &[]) == F::ZERO);
    assert!((0..3).all(|k| holds(&row(k), &row(k + 1), k)), "the honest rows hold");
    let mut early = row(0);
    early[IS_LAST] = F::ONE; // row 0 is ADDR_R = 120, ROW_END = 121
    early[WRITES] = F::ZERO; // CARRY = 1
    assert!(!holds(&early, &row(1), 0), "IS_LAST before ADDR_R reaches ROW_END is refused");
    let mut late = row(1);
    late[IS_LAST] = F::ZERO;
    late[END_INV] = F::ONE;
    assert!(!holds(&late, &row(2), 1), "a run running past ROW_END is refused");
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

#[test]
fn no_admissible_padding_row_of_any_chip_sends_a_message() {
    use p3_air::BaseAir;
    use randprotocol_rvm::machine::Chip;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x0bc0_de03);
    let p = common::every_chip_program();
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
