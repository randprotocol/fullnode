//! Per-table unit tests: the memory table (Task 3), and later tables as they land (Tasks 4–5, 8).
mod common;

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use shrugg_rvm::emulator::MemAccess;
use shrugg_rvm::isa::F;
use shrugg_rvm::tables::memory::{col, memory_trace, REGISTER_BASE};
use shrugg_rvm::tables::range::RangeCounts;

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
use shrugg_rvm::public_values::{public_digest, RVM_PUB_DOMAIN};
use shrugg_rvm::tables::public::{col as pcol, public_trace, HEIGHT as PUBLIC_HEIGHT};

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
        state = shrugg_zkvm::hash::permute_state(state);
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
use shrugg_rvm::isa::{Instr, Op, Program};
use shrugg_rvm::machine::Tier;
use shrugg_rvm::tables::{cpu, memory, poseidon2, program as program_table, public as public_table, range};

#[test]
fn the_table_widths_and_constraint_degrees_are_pinned() {
    assert_eq!(cpu::col::WIDTH, 66, "the cpu's designed width after Tasks 8–9 (26 selectors + the SPONGE group-2 limbs)");
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
    let degs = shrugg_rvm::machine::max_constraint_degrees(&p, Tier(8));
    assert_eq!(degs.len(), 7);
    // Pinned at the measured values (the symbolic checker over the real, same-bus-packed lookup
    // contexts); a change here means a changed quotient-chunk count and belongs in the docs.
    // The cpu's 8 comes from the packed lookup fraction-pins, not its row logic (the same
    // finding `research/tests/tables.rs` records for the RV32 cpu, also 8 — and 8 is this
    // config's budget ceiling, `log2_ceil(degree - 1) <= log_blowup = 3`).
    assert_eq!(degs, vec![2, 8, 4, 4, 4, 2, 2]);
}
