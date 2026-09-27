//! R6 (the 2026-09-27 zkVM review) / RVMv2 R5: table-driven soundness rules for this machine's
//! AIRs, read off `eval` itself — the RV32 twins of `recursion/tests/cpu.rs`'s
//! `every_value_the_cpu_row_writes_is_bound_on_every_opcode` (RVM-1) and `recursion/tests/tables.rs`'
//! padding rules. Neither keeps its own list of what a table does: both run the real `eval` through
//! Plonky3's symbolic interaction builder (`common::symbolic_air`) and evaluate the constraints and
//! messages it emits at concrete rows taken from an honest trace. Deleting a constraint or widening a
//! count changes what they see.
//!
//! 1. **Every value the cpu row writes is bound.** On every row kind an honest run produces (one
//!    representative row per distinct selector pattern, ALU op and branch op), each column the value
//!    of a `MEMORY` *write* depends on — a register write-back, a store's merged word, a hash
//!    write-back lane — must be pinned by something other than the prover's choice: a `MEMORY` read
//!    on the same row carries it, or a lookup whose provider computes it carries it (`ALU`,
//!    `INPUT_READ`, `PUBLIC_READ`, `POSEIDON2`, `PROGRAM`, …; a pure range check such as `RANGE8` or
//!    `AND4` does not count, it bounds a value without fixing it), or a base constraint that reads it
//!    and reads no inverse witness (`INV0`, `DINV0`, `IINV0`, `PINV0` — the non-zero gadgets'
//!    free helpers: `x·inv = 1 − eq` depends on `x` without pinning it, since the prover picks
//!    `inv` alongside). The rVM test's rule for the same exclusion is "not with every selector
//!    cold"; it does not transfer, because this cpu pins an undefined `C` to zero with the
//!    selector-free `(1 − defines_c)·C` — a real binding a cold row still reads. Selector columns in
//!    a write's value (`IS_HASH_OUT` gating a lane) are structure, bound by the selector rules and
//!    the `PROGRAM` fetch, and are not value columns. A written column nothing binds is a free
//!    value entering the machine's state — the RVM-1 shape.
//! 2. **No admissible padding row sends a message.** For every table, starting from an honest padding
//!    row between two honest padding rows (idle blocks for the hash chips, whose padding is a
//!    preprocessed pattern rather than an `IS_REAL` column), every column the constraints leave free
//!    there is set to a random value — one column at a time, kept only if every constraint on both
//!    row pairs still holds — and then every message the table sends or provides must have a zero
//!    count. A padding row that can send something is a free message on a bus; the V-OPCODES-1 shape.
//!    Greedy one-column freedom is not an exhaustive search of joint freedom, but it is exactly the
//!    freedom an ungated count or an unpinned multiplicity column has.
mod common;
use common::*;

use p3_air::BaseAir;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::isa::{BranchCond, Program, REG_A0};
use randprotocol_zkvm::machine::{build_traces_salted_with, chips, Chip, ProveOptions, Tier, Traces, Val};
use randprotocol_zkvm::tables::{bus, cpu};

const T0: u32 = 5;
const T1: u32 = 6;
const T2: u32 = 7;
const S0: u32 = 8;
const S1: u32 = 9;
const RAM: i32 = 0x1000;
const KECCAK_AT: i32 = 0x2000;
const SHA256_AT: i32 = 0x3000;
const P2_AT: i32 = 0x4000;

/// One program that runs every row kind the cpu has: each RV32IM ALU op in register and immediate
/// form, every load and store width (signed and unsigned), every branch condition taken and not,
/// `jal`, `jalr`, `lui`, `auipc`, and every syscall — `READ_INPUT`, `READ_PUBLIC`,
/// `WRITE_OUTPUT`, `POSEIDON2`, `KECCAK`, `SHA256`, `HALT` — plus, through the trace builder, the
/// program-, input- and public-digest rows every proof starts with.
fn every_kind() -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(T0, 0x1234_5678));
    a.extend(li(T1, -7));
    for f in [add, sub, and, or, xor, sll, srl, sra, slt, sltu, mul, mulh, mulhu, mulhsu, div, divu, rem, remu] {
        a.push(f(T2, T0, T1));
    }
    for f in [addi, andi, ori, xori, slti, sltiu] {
        a.push(f(T2, T0, -3));
    }
    for f in [slli, srli, srai] {
        a.push(f(T2, T1, 5));
    }
    a.extend(li(S0, RAM));
    a.push(sw(S0, T0, 0));
    a.push(sh(S0, T1, 4));
    a.push(sb(S0, T1, 9));
    for f in [lw, lh, lhu, lb, lbu] {
        a.push(f(T2, S0, 0));
    }
    a.push(lh(T2, S0, 2));
    a.push(lb(T2, S0, 3));
    a.push(lui(T2, 0xabcd_e000));
    a.push(auipc(T2, 0x0000_1000));
    // Each condition both ways round, so every one is taken once and not taken once; the target
    // is the next instruction either way.
    for (k, cond) in [BranchCond::Eq, BranchCond::Ne, BranchCond::Lt, BranchCond::Ge, BranchCond::Ltu, BranchCond::Geu].into_iter().enumerate() {
        for (x, y, l) in [(T0, T1, format!("b{k}x")), (T1, T0, format!("b{k}y"))] {
            a.branch(cond, x, y, &l);
            a.label(&l);
        }
    }
    a.jal(S1, "after_jal");
    a.label("after_jal");
    a.extend(li(T2, 0));
    a.push(auipc(T2, 0));
    a.push(jalr(S1, T2, 8));
    a.extend(read_input(0));
    a.push(mv(S1, REG_A0));
    a.extend(read_public(0));
    a.extend(write_output(0, S1));
    a.extend(call_poseidon2(P2_AT / 4, 6));
    a.extend(call_keccak(KECCAK_AT / 4));
    a.extend(call_sha256(SHA256_AT as u32 / 4));
    a.extend(halt());
    a.assemble()
}

/// The honest traces of `every_kind` at tier 12, with both hash tables present (they are used) and
/// the chips in `machine::chips` order.
fn traces() -> (Program, Traces, Vec<Chip>) {
    let p = every_kind();
    let (inputs, public) = ([0xdead_beefu32, 2, 3], [0x0bad_cafeu32]);
    let e = execute(&p, &inputs, &public, 1 << 16).expect("every_kind runs");
    let t = build_traces_salted_with(&p, &inputs, &public, [1, 2, 3, 4], &e, Tier(12), ProveOptions::default()).expect("every_kind builds");
    let c = chips(Tier(12), t.keccak_log_height, t.sha256_log_height);
    (p, t, c)
}

fn row_of(m: &p3_matrix::dense::RowMajorMatrix<Val>, r: usize) -> Vec<Val> {
    let w = m.width();
    let h = m.height();
    m.values[(r % h) * w..(r % h) * w + w].to_vec()
}

/// `MEMORY`'s five fields are `(space, addr, ts, value, is_write)`.
const MEM_VALUE: usize = 3;
const MEM_IS_WRITE: usize = 4;

/// Buses whose message fixes a value only up to a range, never to one value: carrying a column on
/// one of these is not a binding.
fn is_range_bus(name: &str) -> bool { name == bus::RANGE8.name() || name == bus::AND4.name() }

#[test]
fn every_value_the_cpu_row_writes_is_bound_on_every_row_kind() {
    use cpu::col::*;
    use std::collections::BTreeMap;
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x7a_6b76_6d31);
    let (_, t, _) = traces();
    let (interactions, constraints) = symbolic_air(&randprotocol_zkvm::tables::cpu::CpuAir);
    assert!(interactions.iter().any(|i| i.bus_name == bus::MEMORY.name()), "eval sends on MEMORY");

    // One representative real row per kind: the selector pattern, the ALU op and the branch op.
    let mut kinds: BTreeMap<Vec<u64>, usize> = BTreeMap::new();
    for r in 0..t.cpu.height() - 1 {
        let row = row_of(&t.cpu, r);
        if row[IS_REAL] != Val::ONE {
            continue;
        }
        let key: Vec<u64> = SELECTORS.iter().chain([ALU_OP, BR_OP].iter()).map(|&c| row[c].as_canonical_u64()).collect();
        kinds.entry(key).or_insert(r);
    }
    assert!(kinds.len() >= 40, "every_kind should produce many row kinds, got {}", kinds.len());

    let inverse_witnesses: Vec<usize> = [INV0, DINV0, IINV0, PINV0].iter().flat_map(|&c| c..c + 4).filter(|&c| c < WIDTH).collect();
    let inverse_witnesses: Vec<usize> = inverse_witnesses.into_iter().filter(|&c| c != INV0 + 2 && c != INV0 + 3).collect(); // `INV0` is two wide
    let mut failures: Vec<String> = Vec::new();
    let mut writes_checked = 0;
    for (key, &r) in &kinds {
        let rows = Rows { cur: row_of(&t.cpu, r), next: row_of(&t.cpu, r + 1), pre_cur: vec![], pre_next: vec![], public: t.public_values.clone() };
        let sent: Vec<&Interaction> = interactions.iter().filter(|i| eval_rows(&i.count, &rows) != Val::ZERO).collect();
        let writes: Vec<&&Interaction> = sent.iter().filter(|i| i.bus_name == bus::MEMORY.name() && eval_rows(&i.fields[MEM_IS_WRITE], &rows) == Val::ONE).collect();
        let reads: Vec<&&Interaction> = sent.iter().filter(|i| i.bus_name == bus::MEMORY.name() && eval_rows(&i.fields[MEM_IS_WRITE], &rows) == Val::ZERO).collect();
        let lookups: Vec<&&Interaction> = sent.iter().filter(|i| i.bus_name != bus::MEMORY.name() && !is_range_bus(i.bus_name.as_str())).collect();
        for w in &writes {
            for col in 0..WIDTH {
                if SELECTORS.contains(&col) || !depends(&w.fields[MEM_VALUE], &rows, Slot::Cur, col, &mut rng) {
                    continue;
                }
                writes_checked += 1;
                let by_read = reads.iter().any(|m| depends(&m.fields[MEM_VALUE], &rows, Slot::Cur, col, &mut rng));
                let by_lookup = lookups.iter().any(|m| m.fields.iter().any(|f| depends(f, &rows, Slot::Cur, col, &mut rng)));
                let by_constraint = constraints
                    .iter()
                    .any(|k| depends(k, &rows, Slot::Cur, col, &mut rng) && !inverse_witnesses.iter().any(|&c| depends(k, &rows, Slot::Cur, c, &mut rng)));
                if !(by_read || by_lookup || by_constraint) {
                    failures.push(format!("row {r} (selectors/alu_op/br_op {key:?}): the MEMORY write's value reads column {col}, and nothing binds it"));
                }
            }
        }
    }
    eprintln!("{} row kinds, {writes_checked} written-value columns checked", kinds.len());
    assert!(failures.is_empty(), "the cpu table's binding rule is broken:\n  {}", failures.join("\n  "));
}

/// The padding row of each table the second test starts from: a row index whose honest row is
/// padding and whose neighbours are too. `None` for the two fixed lookup tables (`range`,
/// `nibble`): every row of theirs is a table entry and every count a provided multiplicity that the
/// global LogUp sum balances — they have no padding.
fn padding_row(chip: &Chip, trace: &p3_matrix::dense::RowMajorMatrix<Val>) -> Option<usize> {
    let h = trace.height();
    match chip {
        Chip::Range(_) | Chip::Nibble(_) => None,
        // Honest padding is a suffix everywhere else; the row before the last has padding on both
        // sides whenever there are three padding rows, which `padding_row`'s caller checks.
        _ => Some(h - 2),
    }
}

#[test]
fn no_admissible_padding_row_sends_a_message() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(0x7a_6b76_6d32);
    let (_, t, cs) = traces();
    let mut failures = Vec::new();
    let mut checked = 0;
    for (k, (chip, trace)) in cs.iter().zip(t.as_slice()).enumerate() {
        let Some(r) = padding_row(chip, trace) else { continue };
        let w = BaseAir::<Val>::width(chip);
        let pre = BaseAir::<Val>::preprocessed_trace(chip);
        let pre_row = |i: usize| pre.as_ref().map(|m| row_of(m, i)).unwrap_or_default();
        let (interactions, constraints) = symbolic_air(chip);
        let public = if matches!(chip, Chip::Cpu(_)) { t.public_values.clone() } else { vec![] };
        let rows_at = |prev: &Vec<Val>, cur: &Vec<Val>, i: usize| Rows { cur: prev.clone(), next: cur.clone(), pre_cur: pre_row(i), pre_next: pre_row(i + 1), public: public.clone() };
        let prev = row_of(trace, r - 1);
        let next = row_of(trace, r + 1);
        let mut cur = row_of(trace, r);
        // The honest padding row itself sends nothing and satisfies everything (sanity, and the
        // check that `r` is padding at all).
        let holds = |cur: &Vec<Val>| {
            let (a, b) = (rows_at(&prev, cur, r - 1), rows_at(cur, &next, r));
            constraints.iter().all(|c| eval_rows(c, &a) == Val::ZERO && eval_rows(c, &b) == Val::ZERO)
        };
        assert!(holds(&cur), "chip {k}: the honest row {r} fails a constraint");
        let sends = |cur: &Vec<Val>| -> Vec<String> {
            let rows = rows_at(cur, &next, r);
            interactions.iter().filter(|i| eval_rows(&i.count, &rows) != Val::ZERO).map(|i| i.bus_name.clone()).collect()
        };
        assert!(sends(&cur).is_empty(), "chip {k}: honest row {r} is not padding (it sends {:?})", sends(&cur));
        // Its predecessor is padding too, so `r` is not the real/padding boundary. At the boundary
        // a table's own constraints may well admit one more real row — the public and input
        // tables' prefix rule does, by design: `real_count == n` is held by the `*_DIGEST` bus's
        // balance against the cpu's digest rows, not by the table — and that is a cross-table
        // argument this row-local harness cannot make. (It found exactly that when the public
        // table had two padding rows: row 2, after two real rows, could be flipped real.)
        let prev_rows = rows_at(&prev, &row_of(trace, r), r - 1);
        assert!(
            interactions.iter().all(|i| eval_rows(&i.count, &prev_rows) == Val::ZERO),
            "chip {k}: row {} before the checked row is not padding",
            r - 1
        );
        let mut free = Vec::new();
        // A random value first, then `1`: a flag column is only ever free as a boolean, and a
        // random field element would fail its `assert_bool` and hide exactly that freedom.
        for col in 0..w {
            let keep = cur[col];
            for candidate in [random_felt(&mut rng), Val::ONE] {
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
        eprintln!("chip {k}: padding row {r}, {} of {w} columns free, sends {:?}", free.len(), s);
        if !s.is_empty() {
            failures.push(format!("chip {k}: a padding row with free columns {free:?} sends on {s:?}"));
        }
    }
    assert!(checked >= 8, "every table but range/nibble has a padding row to check ({checked})");
    assert!(failures.is_empty(), "admissible padding rows send messages:\n  {}", failures.join("\n  "));
}
