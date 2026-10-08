//! The soundness suite (plan Tasks 6, 8, 10): every test builds a wrong witness and checks the
//! machine rejects it, through `rejects()` and nothing else — a per-instance constraint-checker
//! panic (`CONSTRAINT_PANIC`), a global lookup-balance panic (`LOOKUP_BALANCE_PANIC`), or a
//! verify error counts; anything else means the test tripped on something it did not mean to.
mod common;

use common::rejects;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::Matrix;
use randprotocol_rvm::emulator::execute;
use randprotocol_rvm::isa::{F, Instr, Op, Program};
use randprotocol_rvm::machine::{build_traces, FriProfile, Machine, Tier, Traces};
use randprotocol_rvm::tables::{cpu, memory, poseidon2, program as program_table, public as public_table};

fn i(op: Op, rd: u8, ra: u8, b: u64) -> Instr {
    Instr { op, rd, ra, b: F::from_u64(b) }
}
fn ir(op: Op, rd: u8, ra: u8, rb: u8) -> Instr {
    i(op, rd, ra, rb as u64)
}

/// The honest setup: one program touching every table — base and extension arithmetic, an `INV`,
/// a store/load round trip, a permutation, and the four published words R5 requires.
fn setup() -> (Machine, Program, Traces) {
    let p = Program {
        instrs: vec![
            i(Op::Faddi, 1, 0, 7),          // 0
            i(Op::Faddi, 2, 0, 5),          // 1
            ir(Op::Fadd, 3, 1, 2),          // 2: r3 = 12
            i(Op::Inv, 4, 3, 0),            // 3: r4 = 12^-1
            i(Op::Faddi, 5, 0, 100),        // 4
            i(Op::Store, 2, 5, 3),          // 5: mem[103] = 5
            i(Op::Load, 6, 5, 3),           // 6: r6 = 5
            i(Op::Faddi, 7, 0, 64),         // 7: ptr
            i(Op::Store, 1, 7, 0),          // 8: mem[64] = 7
            i(Op::Store, 2, 7, 1),          // 9: mem[65] = 5
            i(Op::Poseidon2, 0, 7, 0),      // 10: permute cells 64..71
            i(Op::Load, 8, 7, 0),           // 11
            i(Op::Public, 0, 3, 0),         // 12
            i(Op::Public, 0, 6, 0),         // 13
            i(Op::Public, 0, 8, 0),         // 14
            i(Op::Public, 0, 4, 0),         // 15
            i(Op::Halt, 0, 0, 0),           // 16
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    };
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

fn prove_and_verify(m: &Machine, p: &Program, t: &Traces) -> Result<(), randprotocol_rvm::machine::VerifyError> {
    let proof = m.prove_traces(p, t, Tier(8));
    m.verify(p, &proof)
}

#[test]
fn honest_traces_pass() {
    let (m, p, t) = setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

#[test]
fn a_wrong_arithmetic_result_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Row 2 is the FADD: claim the sum is 13, not 12.
    t.cpu.values[2 * w + cpu::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_skipped_row_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Mark the LOAD row as padding: the pc chain and the CLK chain break.
    t.cpu.values[6 * w + cpu::col::IS_REAL] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_bad_inv_hint_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Row 3 is the INV: any value but the true inverse fails `ra·rd = 1`.
    t.cpu.values[3 * w + cpu::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn an_address_above_two_to_the_twentyfour_with_forged_limbs_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // The LOAD row's limb columns are what pins its address below 2^24; shifting one limb is a
    // forged range proof. (The honest machine refuses the address outright at the emulator —
    // `tests/cpu.rs` — this is the row-level range check that makes the AIR agree.)
    t.cpu.values[6 * w + cpu::col::LIMB0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_register_write_to_r0_surfacing_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // Rewrite the FADD to target r0, and claim the write is not dropped (RD_IS_ZERO = 0 while
    // RD = 0): the is-zero gadget itself fails first.
    t.cpu.values[2 * w + cpu::col::RD] = F::ZERO;
    t.cpu.values[2 * w + cpu::col::RD_IS_ZERO] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_fetch_count_short_by_one_is_rejected() {
    let (m, p, mut t) = setup();
    let w = program_table::col::WIDTH;
    // The FADD lives at program row 2; drop its fetch count and the cpu's fetch is unclaimed.
    let mult = t.program.values[2 * w + program_table::col::MULT];
    assert_eq!(mult, F::ONE);
    t.program.values[2 * w + program_table::col::MULT] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_skipped_permutation_is_rejected() {
    let (m, p, mut t) = setup();
    let w = poseidon2::col::WIDTH;
    // The one real permutation row vanishes (its bus claims go with it): the cpu's dispatch has
    // no provider — and the memory table's reads and writes have no sender either.
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_REAL] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_REAL] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::MULT] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::IS_PERM] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn an_extra_permutation_is_rejected() {
    let (m, p, mut t) = setup();
    let w = poseidon2::col::WIDTH;
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_REAL] == F::ONE).unwrap();
    // Clone the real row into the padding row after it: a permutation nothing dispatched.
    for c in 0..w {
        t.poseidon2.values[(row + 1) * w + c] = t.poseidon2.values[row * w + c];
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_tampered_memory_value_is_rejected() {
    let (m, p, mut t) = setup();
    let w = memory::col::WIDTH;
    // The "wrong Merkle sibling" shape: the value the RAM table claims a read returned is not
    // the value last written — read-after-write is the transition constraint that catches it.
    let row = (0..t.ram.height()).find(|r| {
        t.ram.values[r * w + memory::col::IS_REAL] == F::ONE
            && t.ram.values[r * w + memory::col::IS_WRITE] == F::ZERO
    }).unwrap();
    t.ram.values[row * w + memory::col::VALUE] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_forged_public_value_is_rejected() {
    let (m, p, t) = setup();
    // (a) The batch public values, tampered after the fact: the transcript binds them.
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.public_values[0] += 1;
    assert!(rejects(|| m.verify(&p, &proof)));
    // (b) The public table's own VALUE column: the selector tie `VALUE = pv[i]` fails on the row.
    let (_, _, mut t2) = setup();
    let w = public_table::col::WIDTH;
    t2.public.values[w + public_table::col::VALUE] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t2)));
}

#[test]
fn a_proof_of_one_program_does_not_verify_against_another() {
    let (m, p, t) = setup();
    let proof = m.prove_traces(&p, &t, Tier(8));
    let mut other = p.clone();
    other.instrs[2] = ir(Op::Fsub, 3, 1, 2);
    // R1: the preprocessed cap binds the program — a different program is a different key.
    assert!(rejects(|| m.verify(&other, &proof)));
}

#[test]
fn a_proof_at_the_wrong_tier_is_rejected() {
    let (m, p, t) = setup();
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.tier = Tier(10);
    assert!(rejects(|| m.verify(&p, &proof)));
}

#[test]
fn an_out_of_range_tier_is_an_error_not_a_panic() {
    let (m, p, t) = setup();
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.tier = Tier(99);
    assert!(matches!(m.verify(&p, &proof), Err(randprotocol_rvm::machine::VerifyError::Tier)));
}

// ── Task 8: the reduce chip's tranche ─────────────────────────────────────────────────────────
use p3_field::BasedVectorSpace;
use randprotocol_rvm::isa::EF;
use randprotocol_rvm::tables::reduce as reduce_table;

/// An honest setup: Cut D's split chain (`common::reduce_chain_program(true)`): entry 0's two
/// rows carrying into entry 1's one row, 267 published.
fn reduce_setup() -> (Machine, Program, Traces, Vec<F>) {
    let p = common::reduce_chain_program(true);
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t, vec![])
}

fn reduce_verify(m: &Machine, p: &Program, t: &Traces) -> Result<(), randprotocol_rvm::machine::VerifyError> {
    let proof = m.prove_traces(p, t, Tier(8));
    m.verify(p, &proof)
}

#[test]
fn honest_reduce_traces_pass() {
    let (m, p, t, _) = reduce_setup();
    assert!(t.reduce.is_some(), "the setup's batch carries the reduce table");
    reduce_verify(&m, &p, &t).unwrap();
}

#[test]
fn a_wrong_accumulated_value_in_the_reduction_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    // The second row's accumulator, shifted by one: the chain to the next row fails.
    r.values[w + reduce_table::col::ACC0] += F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// R5: a run claiming its last row early (row 0, ADDR_R ≠ ROW_END).
#[test]
fn a_dropped_column_in_the_reduction_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let r = t.reduce.as_mut().unwrap();
    r.values[reduce_table::col::IS_LAST] = F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// Spec §5: a run whose address differs from the preprocessed layout's — the vals pointer moved by
/// one extension cell on every row of entry 0 (so the in-entry chain still holds): the
/// REDUCE_LAYOUT lookup has no provider, and the moved reads have no writes.
#[test]
fn a_run_whose_address_differs_from_the_layout_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    for row in 0..2 {
        r.values[row * w + reduce_table::col::ADDR_V] += F::TWO;
    }
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// Spec §5: a wrong CARRY — entry 0's last row claims to close the chain. Its CARRY no longer
/// matches the layout's flags, and entry 1's first row (CHAIN_START = 0) is entered without a carry.
#[test]
fn a_wrong_carry_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    for row in 0..2 {
        r.values[row * w + reduce_table::col::CARRY] = F::ZERO;
    }
    r.values[w + reduce_table::col::WRITES] = F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// Spec §5: a chain result tampered — the continuation entry starts from an accumulator other than
/// the one carried (and the forged result's write follows from it).
#[test]
fn a_chain_continuation_starting_from_a_forged_accumulator_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    r.values[2 * w + reduce_table::col::ACC0] += F::ONE;
    r.values[2 * w + reduce_table::col::OUT0] += F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// Task 5 sweep (Task 1a review): a carry hands its accumulator to the *next* entry. The layout
/// is a three-entry chain — entry 0 (carries), entry 1 (a continuation that carries), entry 2 (a
/// continuation that closes, with entry 1's fields as `common::reduce_chain_program(true)`'s
/// closing entry has them) — and the program dispatches entry 0 and then entry 2, skipping 1.
/// The emulator refuses that (`ReduceChain`), so the execution is the honest two-entry chain's,
/// relabelled: its second `REDUCE` becomes this program's `REDUCE 2` and its event's entry 2.
/// Entry 2 reads exactly what the honest closing entry read, so the run's rows, the layout lookup
/// (entry 2's provider row, `MULT` 1), the `REDUCE` dispatch `[clk + 1, 2]`, the `CLK + 1` carry,
/// the accumulator hand-over and every RAM message balance; only `n(ENTRY) = ENTRY + 1` on the
/// carrying row refuses it. (Over a real layout, skipping entries drops columns from a reduction.)
#[test]
fn a_carry_followed_by_the_wrong_entry_is_rejected_by_the_entry_step() {
    let honest = common::reduce_chain_program(true);
    let mut p = honest.clone();
    let close = honest.reduce_layout[1];
    p.reduce_layout = vec![honest.reduce_layout[0], randprotocol_rvm::isa::ReduceEntry { carry: true, ..close }, close];
    let second = p.instrs.iter().rposition(|x| x.op == Op::Reduce).unwrap();
    assert_eq!(p.instrs[second].b, F::ONE, "the honest chain's second dispatch is entry 1");
    p.instrs[second].b = F::TWO;
    assert_eq!(Machine::check_program(&p), Ok(()), "the three-entry layout is a legal chain");
    assert!(matches!(execute(&p, &[], 10_000), Err(randprotocol_rvm::emulator::ExecError::ReduceChain { .. })), "the emulator refuses the skip");
    let m = Machine::new(FriProfile::Test);
    let mut exec = execute(&honest, &[], 10_000).unwrap();
    let ev = exec.events.iter_mut().find(|e| e.pc as usize == second).unwrap();
    ev.instr = p.instrs[second];
    ev.b_val[0] = F::TWO; // the cpu row's immediate operand, as the fetched instruction carries it
    ev.reduce.as_mut().unwrap().entry = 2;
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    let w = reduce_table::col::WIDTH;
    let red = t.reduce.as_ref().unwrap();
    assert_eq!((red.values[w + reduce_table::col::CARRY], red.values[2 * w + reduce_table::col::ENTRY]), (F::ONE, F::TWO), "entry 0's carrying row hands over to entry 2");
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a carry from entry 0 into entry 2 VERIFIED, skipping entry 1");
}

/// The provider region: a multiplicity on a row past the layout provides an all-zero entry.
#[test]
fn a_multiplicity_off_the_layout_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    r.values[5 * w + reduce_table::col::MULT] = F::ONE;
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

/// Fix round 1 (Task 1a review): a declared layout whose entry's addresses wrap (`u64::MAX`
/// bases) is refused by `verify` at the program check — before any key is built — whatever proof
/// accompanies it.
#[test]
fn a_declared_layout_whose_addresses_wrap_is_refused_before_any_key() {
    let (m, p, t, _) = reduce_setup();
    let proof = m.prove_traces(&p, &t, Tier(8));
    let mut forged = p.clone();
    forged.reduce_layout[0] = randprotocol_rvm::isa::ReduceEntry { key: u64::MAX, vals: u64::MAX, len: 1, row: 0, alpha: 0, res: 2, chain_start: true, carry: false };
    let keys = m.cached_keys();
    assert!(matches!(
        m.verify(&forged, &proof),
        Err(randprotocol_rvm::machine::VerifyError::Program(randprotocol_rvm::isa::DecodeError::Layout { entry: 0 }))
    ));
    assert_eq!(m.cached_keys(), keys, "no verifier key is built for the forged layout");
}

#[test]
fn a_reduce_dispatch_with_no_chip_run_is_rejected() {
    let (m, p, mut t, _) = reduce_setup();
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_mut().unwrap();
    // The whole run vanishes: the cpu's dispatch has no provider (and the run's reads and
    // write-backs have no sender either).
    for i in 0..r.height() {
        r.values[i * w + reduce_table::col::IS_REAL] = F::ZERO;
        r.values[i * w + reduce_table::col::IS_FIRST] = F::ZERO;
        r.values[i * w + reduce_table::col::IS_LAST] = F::ZERO;
    }
    assert!(rejects(|| reduce_verify(&m, &p, &t)));
}

#[test]
fn a_reduce_proof_declaring_no_table_is_rejected() {
    let (m, p, t, _) = reduce_setup();
    // The keccak pattern's verify-side rule: a proof carrying a reduce instance cannot declare
    // `reduce_log_height = 0`. Before the final fix wave the degree-bits vector's length
    // mismatch refused it (`VerifyError::Tier`); now the canonical-height check, which runs
    // first, does: the program's canonical height is the floor, 4.
    let mut proof = m.prove_traces(&p, &t, Tier(8));
    proof.reduce_log_height = 0;
    assert!(matches!(
        m.verify(&p, &proof),
        Err(randprotocol_rvm::machine::VerifyError::ReduceHeightNotCanonical { declared: 0, canonical: Some(4) })
    ));
}

/// The final fix wave (the whole-branch review's Important 2, INTERFACE-4 / AGG-3): the verifier
/// key is built at the declared reduce height, so a proof that could declare any height in range
/// could make a node build a fresh key per value. A proof declaring one height above the
/// program's canonical one — its batch's degree bits declaring the same, so every shape check
/// before the key agrees with it — is refused as `ReduceHeightNotCanonical` before any key is
/// built (the cache count unchanged); the honest proof at the canonical height still verifies.
/// (Red first: with the canonical check deleted in a scratch copy, the forged proof reaches
/// `verifier_key` and the cache count moves — recorded in the final fix report.)
#[test]
fn a_declared_reduce_height_above_the_canonical_one_is_refused_before_any_key() {
    let (m, p, t, _) = reduce_setup();
    let canonical = randprotocol_rvm::machine::canonical_reduce_log_height(&p, 1);
    assert_eq!(canonical, Some(t.reduce_log_height), "the honest prover declares the canonical height");
    let proof = m.prove_traces(&p, &t, Tier(8));
    m.verify(&p, &proof).expect("the canonical height verifies");
    let mut forged: randprotocol_rvm::machine::Proof = postcard::from_bytes(&proof.to_bytes()).unwrap();
    forged.reduce_log_height += 1;
    *forged.batch.degree_bits.last_mut().unwrap() += 1; // the reduce instance's, kept consistent
    let keys = m.cached_keys();
    match m.verify(&p, &forged) {
        Err(randprotocol_rvm::machine::VerifyError::ReduceHeightNotCanonical { declared, canonical: c }) => {
            assert_eq!((declared, c), (t.reduce_log_height + 1, canonical), "the error names both heights")
        }
        other => panic!("a reduce height one above the canonical one must be refused as non-canonical, got {other:?}"),
    }
    assert_eq!(m.cached_keys(), keys, "no verifier key is built for a non-canonical reduce height");
    // `verify_n` is the same check at another N: 100 000 passes of this program's three rows are
    // 300 000 rows, canonical `2^19`, which the honest one-pass proof does not declare.
    assert!(matches!(
        m.verify_n(&p, &proof, 100_000),
        Err(randprotocol_rvm::machine::VerifyError::ReduceHeightNotCanonical { declared: 4, canonical: Some(19) })
    ));
    assert_eq!(m.cached_keys(), keys);
}

/// The final fix wave (Important 3): `prove` refuses a run whose reduce-chip rows exceed
/// `2^REDUCE_MAX_LOG_HEIGHT − 1` — a proof `verify` could never accept — after the emulation and
/// before any trace is built. A counted loop of 16 385 `POW`s of 64 bits each (zero bits read from
/// fresh cells) is 1 048 640 rows, 65 over the ceiling: refused as `ProveError::ReduceRows`, with
/// no proving (the refusal returns before `build_traces`). One iteration fewer fits.
#[test]
fn a_run_past_the_reduce_ceiling_is_refused_before_any_trace() {
    use randprotocol_rvm::machine::{max_reduce_n, ProveError, REDUCE_MAX_LOG_HEIGHT};
    let looped = |n: u64| Program {
        instrs: vec![
            i(Op::Faddi, 4, 0, 400),          // 0: the bits buffer (cells 400–463, never written: zeros)
            i(Op::Faddi, 5, 0, n),            // 1: the counter
            i(Op::Pow, 2, 4, 256 * 64),       // 2: off 0, L 64
            i(Op::Faddi, 5, 5, F::NEG_ONE.as_canonical_u64()), // 3
            i(Op::Jne, 5, 0, 2),              // 4
            i(Op::Public, 0, 0, 0),
            i(Op::Public, 0, 0, 0),
            i(Op::Public, 0, 0, 0),
            i(Op::Public, 0, 0, 0),
            i(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    };
    let max = (1usize << REDUCE_MAX_LOG_HEIGHT) - 1;
    assert_eq!(max / 64, 16_383, "16 383 runs of 64 rows fit, 16 384 do not");
    let m = Machine::new(FriProfile::Test);
    match m.prove(&looped(16_385), &[], None) {
        Err(ProveError::ReduceRows { rows, max: got }) => assert_eq!((rows, got), (16_385 * 64, max)),
        Err(e) => panic!("expected ReduceRows, got {e:?}"),
        Ok(_) => panic!("a run past the reduce ceiling was proved"),
    }
    let exec = execute(&looped(16_383), &[], 1 << 20).unwrap();
    randprotocol_rvm::machine::check_reduce_rows(&exec).expect("16 383 runs of 64 rows fit the ceiling");
    let exec = execute(&looped(16_384), &[], 1 << 20).unwrap();
    assert!(matches!(randprotocol_rvm::machine::check_reduce_rows(&exec), Err(ProveError::ReduceRows { rows: 1_048_576, .. })));
    // The static count is per pass, not per run: a looped program's canonical height is not its
    // run's — `program_rows` is exact only for programs that execute each POW/FOLD/REDUCE once per
    // proof (the verifier programs), which is why `max_reduce_n` is a property of those.
    assert_eq!(randprotocol_rvm::tables::reduce::program_rows(&looped(16_385)), 64);
    assert_eq!(max_reduce_n(&looped(1)), 16_383);
}

// ── Task 9: the poseidon2 chip's SPONGE row kind tranche ──────────────────────────────────────

/// An honest setup with one `SPONGE` absorb over a four-word message.
fn sponge_setup() -> (Machine, Program, Traces) {
    use randprotocol_rvm::dsl::{Builder, Checkpoints, Digest, Liveness};
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(41);
    let mut b = Builder::with_liveness(Checkpoints::Off, Liveness::On);
    let mut tape: Vec<F> = vec![];
    let src = b.alloc(4);
    for k in 0..4i64 {
        let w = common::random_felt(&mut rng);
        let v = b.hint();
        tape.push(w);
        b.store(src, k, v);
    }
    // Hint the words into the cells, then one absorb block: `sponge` emits one `SPONGE` here.
    let out = Digest(b.alloc(4));
    randprotocol_rvm::dsl::hash::sponge(&mut b, src, 4, out);
    for k in 0..4 {
        let v = b.load(out.0, k);
        b.public(v);
    }
    let p = b.finish();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &tape, 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

#[test]
fn an_absorb_row_with_a_wrong_source_cell_is_rejected() {
    let (m, p, mut t) = sponge_setup();
    let w = memory::col::WIDTH;
    // The RAM trace's read of the absorb's first source cell, shifted by one: read-after-write
    // is the transition constraint that refuses it (the "wrong Merkle sibling" shape again).
    let row = (0..t.ram.height()).find(|r| {
        t.ram.values[r * w + memory::col::IS_REAL] == F::ONE
            && t.ram.values[r * w + memory::col::IS_WRITE] == F::ZERO
    }).unwrap();
    t.ram.values[row * w + memory::col::VALUE] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_skipped_absorb_is_rejected() {
    let (m, p, mut t) = sponge_setup();
    let w = poseidon2::col::WIDTH;
    // The absorb row vanishes (its SPONGE-bus claims go with it): the cpu's dispatch has no
    // provider — `LOOKUP_BALANCE_PANIC` on `SPONGE`.
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_SPONGE] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_SPONGE] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::IS_REAL] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::MULT] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_sponge_row_claiming_the_plain_poseidon2_kind_is_rejected() {
    let (m, p, mut t) = sponge_setup();
    let w = poseidon2::col::WIDTH;
    // The absorb row claims to be a plain in-place permutation instead: the SPONGE bus loses
    // its entry and POSEIDON2 gains one nobody dispatched.
    let row = (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_SPONGE] == F::ONE).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_SPONGE] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::IS_PERM] = F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

// ── Cut B: HINTN, eight tape words into eight cells in one cpu row ────────────────────────────

fn hintn_setup() -> (Machine, Program, Traces) {
    let p = Program { instrs: vec![
        i(Op::Faddi, 1, 0, 100),
        i(Op::Hintn, 0, 1, 0),
        i(Op::Load, 2, 1, 7),
        // R5's four published words: the eighth tape word, then three zeros.
        i(Op::Public, 0, 2, 0),
        i(Op::Public, 0, 0, 0),
        i(Op::Public, 0, 0, 0),
        i(Op::Public, 0, 0, 0),
        i(Op::Halt, 0, 0, 0),
    ], checkpoints: vec![], reduce_layout: vec![] };
    let tape: Vec<F> = (1..=8).map(F::from_u64).collect();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &tape, 100).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

#[test]
fn honest_hintn_traces_pass() {
    let (m, p, t) = hintn_setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

/// The HINTN row's base moved to `p − 1` (so `A0 + B + 7 = 6`, in range by the top alone) with the
/// group-3 base limbs forged to spell 0: refused by `Machine::verify`. What refuses it first is
/// not the range groups but the row's `REG` read of `ra` — the edited `A0` no longer matches the
/// `r1` the register table holds — so this is a whole-machine forgery test, not a test of the
/// range gating. The range gating on HINTN's base and top is tested at the AIR, with the operand
/// left free, by `tests/cpu.rs`'s ZKQ-3 cases (`a_multi_cell_access_whose_base_wraps_below_zero_is_refused`,
/// its "HINTN at A0 + B = p − 1" case and its `2^24` top-end control).
#[test]
fn a_hintn_base_just_below_zero_with_forged_limbs_is_rejected() {
    let (m, p, mut t) = hintn_setup();
    let w = cpu::col::WIDTH;
    let row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::SEL0 + Op::Hintn as usize] == F::ONE).unwrap();
    t.cpu.values[row * w + cpu::col::A0] = -F::ONE; // p − 1, with B = 0
    for c in [cpu::col::G3LIMB0, cpu::col::G3LIMB1, cpu::col::G3LIMB2] {
        t.cpu.values[row * w + c] = F::ZERO;
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// The top cell at `2^24`: base `2^24 − 7` with the group-1 limbs forged to spell `2^24 − 1`:
/// refused by `Machine::verify`, first by the row's `REG` read of `ra` (the edited `A0` no longer
/// matches `r1`), not by the range groups — as the test above. The range gating at HINTN's top end
/// is `tests/cpu.rs`'s `a_multi_cell_access_whose_base_wraps_below_zero_is_refused` (its HINTN
/// `2^24` control).
#[test]
fn a_hintn_run_ending_at_two_to_the_twentyfour_with_forged_limbs_is_rejected() {
    let (m, p, mut t) = hintn_setup();
    let w = cpu::col::WIDTH;
    let row = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::SEL0 + Op::Hintn as usize] == F::ONE).unwrap();
    t.cpu.values[row * w + cpu::col::A0] = F::from_u64((1 << 24) - 7);
    let top = (1u64 << 24) - 1;
    for (k, c) in [cpu::col::LIMB0, cpu::col::LIMB1, cpu::col::LIMB2].iter().enumerate() {
        t.cpu.values[row * w + c] = F::from_u64((top >> (8 * k)) & 0xff);
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

// ── Task 10: the full-suite pass — the remaining per-table tamper vectors ─────────────────────

#[test]
fn a_padding_row_with_a_selector_set_is_rejected() {
    let (m, p, mut t) = setup();
    let w = cpu::col::WIDTH;
    // AGENTS.md invariant 2: on a padding row every send count is a selector expression, so one
    // hot selector is one sum over `IS_REAL = 0` — the count constraint itself refuses it before
    // any bus comes into it.
    let pad = (0..t.cpu.height()).find(|r| t.cpu.values[r * w + cpu::col::IS_REAL] == F::ZERO).unwrap();
    t.cpu.values[pad * w + cpu::col::SEL0 + Op::Fadd as usize] = F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_forged_memory_delta_limb_is_rejected() {
    let (m, p, mut t) = setup();
    let w = memory::col::WIDTH;
    // The `(addr, ts)` sort's delta, forged by one limb: the delta-equality constraint fails on
    // the row (and a forged limb is exactly what the RANGE8 lookup exists to refuse).
    let row = (0..t.ram.height()).find(|r| t.ram.values[r * w + memory::col::IS_REAL] == F::ONE).unwrap();
    t.ram.values[row * w + memory::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

#[test]
fn a_published_value_out_of_order_is_rejected() {
    let (m, p, mut t) = setup();
    let w = public_table::col::WIDTH;
    // Rows 1 and 2 of the public table swapped: `SEL_i·(IDX − i) = 0` and `VALUE = pv[i]` cannot
    // both hold on the swapped rows.
    t.public.values.swap(1 * w + public_table::col::VALUE, 2 * w + public_table::col::VALUE);
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

// ── RVM-1: the STOREE high lane (the 2026-09-27 recursion-VM report) ──────────────────────────
//
// An extension value is the pair `(c0, c1)` in registers `(rd, rd + 1)` or cells `(a, a + 1)`.
// Before RVM-1's fix a STOREE row sent `RAM.write(a + 1, D1)` but no `REG` message read `rd + 1`,
// so `D1` — the stored high lane — was a free witness column: the emulator filled it honestly,
// the trace builder mirrored the gap, and nothing in the constraint system disagreed with a
// prover who put anything else there. LOADE then read the forged lane back as if it had been
// computed. The vectors below forge that lane (a) in a hand-written program, (b) in a value the
// DSL's register allocator spilled on its own (RVM-1a: every spill is a STOREE/LOADE pair, so
// every spilled extension value was forgeable), and (c) for symmetry on the LOADE side, which
// was always bound. Each is refused three ways, so the tests show the *constraints* refusing it
// and not only the host: through the honest `build_traces` (whose read-after-write assertion may
// refuse first — a host check, not a proof-system one), and through two hand-built trace sets
// that skip every host assertion — the register table an unfixed trace builder would produce
// (no read of `rd + 1`: after the fix the cpu's new `REG` message has no receiver, a bus
// imbalance), and the fixed builder's register table with its forged read kept (the memory
// table's read-after-write constraint refuses it).
use randprotocol_rvm::emulator::{Execution, MemAccess};
use randprotocol_rvm::tables::{pad_height, range};

/// The forged lane: `0xC0FFEE`, the report's value.
const FORGED: u64 = 0xC0FFEE;

/// `TS_RD1_READ`: the slot of the cpu's new `REG` read of `rd + 1` on a STOREE row. The unfixed
/// builder's register table is the fixed one's minus every access at this slot on a STOREE row
/// (before the fix there are none, so the filter is the identity and both tables are the
/// honest builder's).
const TS_RD1_READ: u32 = 5;

/// The report's program (§5.1): store `(11, 22)`, load it back, publish the loaded high lane
/// first and the register it came from last — so a forgery shows up as a published word that
/// disagrees with the register file inside one proof's own public values.
fn storee_program() -> Program {
    Program {
        instrs: vec![
            i(Op::Faddi, 2, 0, 11),   // 0: r2 = 11
            i(Op::Faddi, 3, 0, 22),   // 1: r3 = 22
            i(Op::Faddi, 6, 0, 1000), // 2: r6 = 1000
            i(Op::Storee, 2, 6, 0),   // 3: mem[1000..1002] = (r2, r3)
            i(Op::Loade, 4, 6, 0),    // 4: (r4, r5) = mem[1000..1002]
            i(Op::Public, 0, 5, 0),   // 5: publish r5 (honestly 22)
            i(Op::Public, 0, 4, 0),   // 6: publish r4 = 11
            i(Op::Public, 0, 2, 0),   // 7: publish r2 = 11
            i(Op::Public, 0, 3, 0),   // 8: publish r3 = 22, straight from the register file
            i(Op::Halt, 0, 0, 0),     // 9
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    }
}

/// Rewrite, in an honest run, exactly what the loaded high lane being `value` implies: the
/// LOADE row's `d[1]` and its read of `a + 1`, then the one PUBLIC that reads `rd + 1` (its
/// operand and the published word). With `storee = Some(s)`, the STOREE row's `d[1]` and its
/// write of `a + 1` too — the RVM-1 forgery; with `None`, the stored lane stays honest and only
/// the load lies — vector (c). Everything the forged register reaches is checked to be that one
/// PUBLIC (and HALT), so the rewritten run is internally consistent everywhere the constraints
/// could look except where the finding says they do not.
fn forge_high_lane(exec: &mut Execution, storee: Option<usize>, loade: usize, value: F) {
    let l = &exec.events[loade];
    assert_eq!(l.instr.op, Op::Loade, "event {loade} is the LOADE");
    let cell = l.mem[1].addr;
    let reg = l.instr.rd + 1;
    if let Some(s) = storee {
        let e = &mut exec.events[s];
        assert_eq!(e.instr.op, Op::Storee, "event {s} is the STOREE");
        assert!(e.mem[1].is_write && e.mem[1].addr == cell, "the STOREE writes the cell the LOADE reads");
        e.d[1] = value;
        e.mem[1].value = value;
        // Nothing between the store and the load touches the cell: the forged write is the
        // last write the load's read sees.
        for (k, e) in exec.events[s + 1..loade].iter().enumerate() {
            assert!(e.mem.iter().all(|m| m.addr != cell), "event {} touches the forged cell", s + 1 + k);
        }
    }
    let l = &mut exec.events[loade];
    assert!(!l.mem[1].is_write);
    l.d[1] = value;
    l.mem[1].value = value;
    let mut published = exec.events[..loade].iter().filter(|e| e.instr.op == Op::Public).count();
    let mut reached = 0;
    for e in exec.events[loade + 1..].iter_mut() {
        match e.instr.op {
            Op::Public => {
                if e.instr.ra == reg {
                    e.a[0] = value;
                    exec.public[published] = value;
                    reached += 1;
                }
                published += 1;
            }
            Op::Halt => {}
            other => panic!("the forged register must reach only PUBLIC rows, found {other:?}"),
        }
    }
    assert_eq!(reached, 1, "exactly one PUBLIC publishes the forged lane");
}

/// `memory::memory_trace` minus its host assertions (strictly increasing keys, read-after-write,
/// fresh reads zero): the same columns computed the same way, so a forged access list turns into
/// a trace the *constraints* have to refuse. On an honest list it is `memory_trace` exactly
/// (`the_unchecked_memory_trace_is_memory_trace_on_honest_input` below pins that).
fn memory_trace_unchecked(accesses: &[MemAccess], height: usize, counts: &mut range::RangeCounts) -> p3_matrix::dense::RowMajorMatrix<F> {
    use memory::col::*;
    let mut rows: Vec<&MemAccess> = accesses.iter().collect();
    rows.sort_by_key(|a| (a.addr, a.ts));
    assert!(rows.len() < height);
    let mut v = F::zero_vec(height * WIDTH);
    for (k, r) in rows.iter().enumerate() {
        let base = k * WIDTH;
        v[base + ADDR] = F::from_u64(r.addr);
        v[base + TS] = F::from_u64(r.ts as u64);
        v[base + VALUE] = r.value;
        v[base + IS_WRITE] = F::from_bool(r.is_write);
        v[base + IS_REAL] = F::ONE;
        if let Some(nx) = rows.get(k + 1) {
            let changed = nx.addr != r.addr;
            let delta: u64 = if changed { nx.addr - r.addr - 1 } else { (nx.ts as u64).wrapping_sub(r.ts as u64 + 1) };
            v[base + ADDR_CHANGED] = F::from_bool(changed);
            v[base + DIFF_INV] = if changed { F::from_u64(nx.addr - r.addr).inverse() } else { F::ZERO };
            for (j, c) in [D0, D1, D2, D3].iter().enumerate() {
                let limb = (delta >> (8 * j)) as u32 & 0xff;
                v[base + c] = F::from_u32(limb);
                counts.range8(limb);
            }
        }
    }
    p3_matrix::dense::RowMajorMatrix::new(v, WIDTH)
}

/// Every table, built from the run's events the way `build_traces` builds them, except that the
/// register and RAM access lists are given explicitly and both memory tables go through
/// [`memory_trace_unchecked`] — the "honest trace builder bypassed" path. The reduce chip's trace
/// is given explicitly too (with its declared log-height), or `None` for a program with no
/// REDUCE rows.
fn traces_bypassing_host_checks(p: &Program, exec: &Execution, tier: Tier, reg_acc: &[MemAccess], ram_acc: &[MemAccess]) -> Traces {
    traces_from_parts(p, exec, tier, reg_acc, ram_acc, None)
}

fn traces_from_parts(
    p: &Program,
    exec: &Execution,
    tier: Tier,
    reg_acc: &[MemAccess],
    ram_acc: &[MemAccess],
    reduce: Option<(p3_matrix::dense::RowMajorMatrix<F>, u8)>,
) -> Traces {
    use randprotocol_rvm::machine::{program_log_height, MIN_LOG_HEIGHT};
    assert!(reduce.is_some() || exec.events.iter().all(|e| e.reduce.is_none()));
    let mut counts = range::RangeCounts::default();
    let cpu_t = cpu::cpu_trace(&exec.events, tier.cpu_height(), &mut counts);
    // Cut F: the reduce chip's own range lookups — each pow run's immediate bytes on its first row.
    if let Some((red, _)) = &reduce {
        use reduce_table::col::{P_FIRST, P_L, P_OFF, WIDTH};
        for row in red.values.chunks(WIDTH).filter(|r| r[P_FIRST] == F::ONE) {
            counts.range8(row[P_OFF].as_canonical_u64() as u32);
            counts.range8(row[P_L].as_canonical_u64() as u32);
        }
    }
    let reg_lh = pad_height(reg_acc.len() + 1, 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8;
    let reg = memory_trace_unchecked(reg_acc, 1 << reg_lh, &mut counts);
    let ram_lh = pad_height(ram_acc.len() + 1, 1 << MIN_LOG_HEIGHT).trailing_zeros() as u8;
    let ram = memory_trace_unchecked(ram_acc, 1 << ram_lh, &mut counts);
    let perms = cpu::perm_events(&exec.events);
    let p2 = poseidon2::poseidon2_log_height(perms.len());
    Traces {
        program: program_table::program_trace(p, &exec.events, 1 << program_log_height(p.instrs.len())),
        cpu: cpu_t,
        reg,
        ram,
        poseidon2: poseidon2::poseidon2_trace(&perms, 1 << p2),
        public: public_table::public_trace(&exec.public, public_table::HEIGHT),
        range: range::range_trace(&counts),
        reduce_log_height: reduce.as_ref().map_or(0, |r| r.1),
        reduce: reduce.map(|r| r.0),
        public_values: exec.public.clone(),
        reg_log_height: reg_lh,
        ram_log_height: ram_lh,
        poseidon2_log_height: p2,
    }
}

fn prove_and_verify_at(m: &Machine, p: &Program, t: &Traces, tier: Tier) -> Result<(), randprotocol_rvm::machine::VerifyError> {
    let proof = m.prove_traces(p, t, tier);
    m.verify(p, &proof)
}

/// The three ways a forged run can reach the prover, each of which must be refused. `what` names
/// the forgery in the failure message, which is the red a missing constraint produces.
fn assert_forged_run_is_refused(m: &Machine, p: &Program, forged: &Execution, tier: Tier, what: &str) {
    let published: Vec<u64> = forged.public.iter().map(|x| x.as_canonical_u64()).collect();
    // (1) The honest trace builder on the forged run. Its read-after-write `assert!` refusing
    // the run is a *host* refusal — worth having, but a prover need not run it — so it is
    // accepted here and the constraint-level refusal is shown by (2) and (3).
    let honest_path = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let t = build_traces(p, forged, tier).unwrap();
        prove_and_verify_at(m, p, &t, tier)
    }));
    match honest_path {
        Ok(Ok(())) => panic!("{what}: the forged run VERIFIED through the honest trace builder, publishing {published:?}"),
        Ok(Err(_)) => {}
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            assert!(
                msg.contains("read does not match last write") || msg.contains(common::CONSTRAINT_PANIC) || msg.contains(common::LOOKUP_BALANCE_PANIC),
                "{what}: the honest path failed for an unrelated reason: {msg}"
            );
        }
    }
    let ram = cpu::ram_accesses(&forged.events);
    let reg_fixed = cpu::register_accesses(&forged.events);
    // (2) The register table an unfixed trace builder produces: no read of `rd + 1` on a STOREE
    // row. After the fix the cpu row still sends that read, and nothing receives it.
    let reg_unfixed: Vec<MemAccess> = reg_fixed
        .iter()
        .copied()
        .filter(|a| !(a.ts % 16 == TS_RD1_READ && forged.events[(a.ts / 16) as usize].instr.op == Op::Storee))
        .collect();
    let t = traces_bypassing_host_checks(p, forged, tier, &reg_unfixed, &ram);
    assert!(
        rejects(|| prove_and_verify_at(m, p, &t, tier)),
        "{what}: the forged run VERIFIED with the unfixed builder's register table, publishing {published:?}"
    );
    // (3) The fixed builder's register table with the forged read of `rd + 1` in it, host checks
    // skipped: the memory table's read-after-write constraint has to refuse it.
    let t = traces_bypassing_host_checks(p, forged, tier, &reg_fixed, &ram);
    assert!(
        rejects(|| prove_and_verify_at(m, p, &t, tier)),
        "{what}: the forged run VERIFIED with the register table carrying its forged read, publishing {published:?}"
    );
}

#[test]
fn the_unchecked_memory_trace_is_memory_trace_on_honest_input() {
    let p = storee_program();
    let exec = execute(&p, &[], 1000).unwrap();
    for acc in [cpu::register_accesses(&exec.events), cpu::ram_accesses(&exec.events)] {
        let h = pad_height(acc.len() + 1, 16);
        let (mut c1, mut c2) = (range::RangeCounts::default(), range::RangeCounts::default());
        assert_eq!(memory::memory_trace(&acc, h, &mut c1).values, memory_trace_unchecked(&acc, h, &mut c2).values);
        assert_eq!(c1.range, c2.range);
    }
    // And the bypass path proves an honest run: what (2)/(3) refuse is the forgery, not the path.
    let m = Machine::new(FriProfile::Test);
    let t = traces_bypassing_host_checks(&p, &exec, Tier(8), &cpu::register_accesses(&exec.events), &cpu::ram_accesses(&exec.events));
    prove_and_verify_at(&m, &p, &t, Tier(8)).unwrap();
}

/// (a) RVM-1 itself: the report's ten-instruction program with the stored high lane forged to
/// `0xC0FFEE` while `r3` still holds 22.
#[test]
fn a_forged_storee_high_lane_is_rejected() {
    let p = storee_program();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 1000).unwrap();
    assert_eq!(exec.public, [22u64, 11, 11, 22].map(F::from_u64).to_vec(), "the honest run");
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    prove_and_verify(&m, &p, &t).unwrap();

    let mut forged = exec.clone();
    forge_high_lane(&mut forged, Some(3), 4, F::from_u64(FORGED));
    assert_eq!(forged.public, [FORGED, 11, 11, 22].map(F::from_u64).to_vec(), "the forged run");
    assert_forged_run_is_refused(&m, &p, &forged, Tier(8), "RVM-1 (a), a forged STOREE high lane");
}

/// (b) RVM-1a: the same forgery on a value the DSL's allocator spilled by itself. Fourteen
/// extension values are live at once against the allocator's twelve register pairs, so the
/// replay spills; `x`, defined first and used last, is reloaded (LOADE into scratch) only to be
/// published. The test finds its spill — a STOREE with `ra = r0`, the allocator's absolute form —
/// and forges the spilled high lane.
#[test]
fn a_forged_spilled_extension_value_is_rejected() {
    use randprotocol_rvm::dsl::{Builder, Checkpoints};
    let ef = |a: u64, b: u64| EF::from_basis_coefficients_slice(&[F::from_u64(a), F::from_u64(b)]).unwrap();
    let mut b = Builder::new(Checkpoints::Off);
    let x = b.ext_constant(ef(11, 22));
    let others: Vec<_> = (0..13u64).map(|k| b.ext_constant(ef(100 + k, 200 + k))).collect();
    let mut acc = others[0];
    for o in &others[1..] {
        acc = b.ext_add(acc, *o);
    }
    b.public_ext(acc);
    b.public_ext(x);
    let p = b.finish();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let tier = Tier::for_cycles(exec.cpu_rows()).unwrap();
    let t = build_traces(&p, &exec, tier).unwrap();
    prove_and_verify_at(&m, &p, &t, tier).unwrap();
    assert_eq!(exec.public[2..], [F::from_u64(11), F::from_u64(22)], "x is published last");

    // `x`'s reload is the last LOADE; its spill is the STOREE (r0-relative) that wrote the cell.
    let loade = exec.events.iter().rposition(|e| e.instr.op == Op::Loade).expect("x was spilled and reloaded");
    let cell = exec.events[loade].mem[0].addr;
    let storee = exec.events[..loade]
        .iter()
        .rposition(|e| e.instr.op == Op::Storee && e.mem[0].addr == cell)
        .expect("the spill that wrote x's cell");
    assert_eq!(exec.events[storee].instr.ra, 0, "a spill: the allocator's absolute-address STOREE");
    assert_eq!(exec.events[storee].d, [F::from_u64(11), F::from_u64(22)], "the spilled value is x");

    let mut forged = exec.clone();
    forge_high_lane(&mut forged, Some(storee), loade, F::from_u64(FORGED));
    assert_eq!(forged.public[3], F::from_u64(FORGED));
    assert_forged_run_is_refused(&m, &p, &forged, tier, "RVM-1a (b), a forged spilled extension value");
}

/// (c) Symmetry: a forged LOADE high lane with the stored lane honest. LOADE writes both lanes to
/// registers from its two RAM reads, so this was bound before RVM-1's fix and must stay so.
#[test]
fn a_forged_loade_high_lane_is_rejected() {
    let p = storee_program();
    let m = Machine::new(FriProfile::Test);
    let mut forged = execute(&p, &[], 1000).unwrap();
    forge_high_lane(&mut forged, None, 4, F::from_u64(FORGED));
    assert_eq!(forged.public, [FORGED, 11, 11, 22].map(F::from_u64).to_vec());
    assert_forged_run_is_refused(&m, &p, &forged, Tier(8), "(c), a forged LOADE high lane");
}

// ── The reduce chip's run rules (the 2026-09-27 zk scan: OPCODES-1/TABLES-1, V-OPCODES-1, ZKR-4) ──
//
// One program for the whole tranche: a three-column REDUCE run over hand-stored cells, its
// result loaded back and published. vals (extension, two cells each) at 100..105 =
// (10, 0), (20, 0), (30, 0); row at 120..122 = 4, 5, 6; inv (1, 0) at 210, alpha (3, 0) at 212,
// layout entry 0 (Cut D) writing the result to 214 — so the honest result is
// (10 − 4)·1 + (20 − 5)·3 + (30 − 6)·9 = 267. With `stale_first`, column 1's
// cells (102, 103, 121) first hold (7, 0) and 7 — a difference of zero — and a filler row marks
// the clock at which those stale values were live.
fn reduce_run_program(stale_first: bool) -> Program {
    let mut v = vec![];
    let st = |v: &mut Vec<Instr>, addr: u64, val: u64| {
        v.push(i(Op::Faddi, 1, 0, val));
        v.push(i(Op::Store, 1, 0, addr));
    };
    if stale_first {
        st(&mut v, 102, 7);
        st(&mut v, 103, 0);
        st(&mut v, 121, 7);
        v.push(i(Op::Faddi, 9, 0, 0)); // the filler row: the stale-read clock
    }
    for (addr, val) in [(100u64, 10u64), (101, 0), (102, 20), (103, 0), (104, 30), (105, 0), (120, 4), (121, 5), (122, 6), (210, 1), (211, 0), (212, 3), (213, 0)] {
        st(&mut v, addr, val);
    }
    v.push(i(Op::Reduce, 0, 0, 0));
    v.push(i(Op::Load, 3, 0, 214));
    v.push(i(Op::Load, 4, 0, 215));
    v.push(i(Op::Public, 0, 3, 0));
    v.push(i(Op::Public, 0, 4, 0));
    v.push(i(Op::Public, 0, 3, 0));
    v.push(i(Op::Public, 0, 4, 0));
    v.push(i(Op::Halt, 0, 0, 0));
    let reduce_layout = vec![randprotocol_rvm::isa::ReduceEntry { vals: 100, row: 120, len: 3, key: 210, alpha: 212, res: 214, chain_start: true, carry: false }];
    Program { instrs: v, checkpoints: vec![], reduce_layout }
}

fn events_of(exec: &Execution, op: Op) -> Vec<usize> {
    exec.events.iter().enumerate().filter(|(_, e)| e.instr.op == op).map(|(k, _)| k).collect()
}

/// Rewrite what the cpu reads back from the result cell (214) — the first LOAD and every
/// PUBLIC of `r3` — to `acc0`, as a forged reduction implies.
fn forge_accumulator_readback(exec: &mut Execution, acc0: F) {
    let l = events_of(exec, Op::Load)[0];
    assert_eq!(exec.events[l].mem[0].addr, 214);
    exec.events[l].mem[0].value = acc0;
    exec.events[l].d[0] = acc0;
    for k in events_of(exec, Op::Public) {
        if exec.events[k].instr.ra == 3 {
            exec.events[k].a[0] = acc0;
        }
    }
    exec.public[0] = acc0;
    exec.public[2] = acc0;
}

#[test]
fn the_reduce_run_program_is_honest_and_publishes_267() {
    let m = Machine::new(FriProfile::Test);
    for stale in [false, true] {
        let p = reduce_run_program(stale);
        let exec = execute(&p, &[], 1000).unwrap();
        assert_eq!(exec.public[0], F::from_u64(267));
        let t = build_traces(&p, &exec, Tier(8)).unwrap();
        prove_and_verify(&m, &p, &t).unwrap();
        // And through the host-check-free path the forgeries below use, so a refusal there is
        // the forgery's and not the path's.
        let (reg, ram) = (cpu::register_accesses(&exec.events), cpu::ram_accesses(&exec.events));
        let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((t.reduce.unwrap(), t.reduce_log_height)));
        prove_and_verify(&m, &p, &t).unwrap();
    }
}

/// OPCODES-1 / TABLES-1: a run's rows after the first read at `16·CLK + slot`, and nothing tied
/// a later row's CLK to the first row's (the one the cpu's dispatch binds). So row 1 could read
/// its column at a clock of the prover's choosing — here, before column 1's cells were
/// overwritten — and the reduction used stale values: 222 published against an honest 267.
#[test]
fn a_reduce_row_reading_at_a_stale_clock_is_rejected() {
    let p = reduce_run_program(true);
    let m = Machine::new(FriProfile::Test);
    let mut exec = execute(&p, &[], 1000).unwrap();
    let filler = exec.events.iter().position(|e| e.instr.op == Op::Faddi && e.instr.rd == 9).unwrap() as u32;
    let r = events_of(&exec, Op::Reduce)[0];
    {
        let e = &mut exec.events[r];
        // The event's log (Cut D): the key's two reads, alpha's two, three reads per column, the
        // result's two writes.
        let stale = [F::from_u64(7), F::ZERO, F::from_u64(7)];
        for k in 0..3 {
            let a = &mut e.mem[4 + 3 + k];
            a.ts = filler * 16 + a.ts % 16;
            a.value = stale[k];
        }
        // acc = (10 − 4)·1 + (7 − 7)·3 + (30 − 6)·9 = 222.
        e.mem[4 + 9].value = F::from_u64(222);
    }
    forge_accumulator_readback(&mut exec, F::from_u64(222));
    let mut t = build_traces(&p, &exec, Tier(8)).unwrap();
    let w = reduce_table::col::WIDTH;
    t.reduce.as_mut().unwrap().values[w + reduce_table::col::CLK] = F::from_u64(filler as u64);
    assert!(
        rejects(|| prove_and_verify(&m, &p, &t)),
        "OPCODES-1: a reduce row reading at a stale clock VERIFIED, publishing 222 against an honest 267"
    );
}

/// V-OPCODES-1's forged padding row: `IS_LAST = 1` with `ADDR_R = ROW_END` (so R5 holds) and
/// `WRITES = 1` on the first padding row after the run, `CLK = clk_r + 1/16` — CLK is a field
/// element, so `16·CLK + 14` is `16·clk_r + 15`, any timestamp at all — and the output column set
/// to `value`. Its two result-write messages land in the result cells (214, 215) between the real
/// write and the cpu's LOAD; the RAM log carries them (on the HALT event, which is where
/// `ram_accesses` picks them up). [`padding_writeback_traces`]'s `first` also sets `IS_FIRST`, the
/// variant that claims a whole one-row run on padding.
fn forge_padding_writeback(exec: &mut Execution, value: F) {
    let r = events_of(exec, Op::Reduce)[0];
    let clk_r = exec.events[r].clk;
    let base = clk_r * 16;
    // 214 ← value at 16·clk_r + 15, 215 ← 0 at + 16 (APOW = 0 on the forged row, so the step adds
    // nothing to ACC0 = value).
    let writes = [(214u64, base + 15, value), (215, base + 16, F::ZERO)];
    let h = events_of(exec, Op::Halt)[0];
    for (addr, ts, value) in writes {
        exec.events[h].mem.push(MemAccess { addr, ts, value, is_write: true });
    }
}

fn padding_writeback_traces(p: &Program, value: F, first: bool) -> (Execution, Traces) {
    use reduce_table::col::*;
    let mut exec = execute(p, &[], 1000).unwrap();
    forge_padding_writeback(&mut exec, value);
    forge_accumulator_readback(&mut exec, value);
    let mut t = build_traces(p, &exec, Tier(8)).unwrap();
    let clk_r = exec.events[events_of(&exec, Op::Reduce)[0]].clk;
    let w = WIDTH;
    let red = t.reduce.as_mut().unwrap();
    let row = 3; // the first padding row after the three-row run
    let rv = &mut red.values[row * w..(row + 1) * w];
    assert_eq!(rv[IS_REAL], F::ZERO, "row 3 is padding");
    rv[IS_LAST] = F::ONE;
    rv[CLK] = F::from_u64(clk_r as u64) + F::from_u64(16).inverse();
    rv[RES] = F::from_u64(214);
    rv[ADDR_R] = F::ZERO;
    rv[ROW_END] = F::ZERO;
    rv[ACC0] = value;
    rv[OUT0] = value;
    rv[WRITES] = F::ONE;
    if first {
        rv[IS_FIRST] = F::ONE;
    }
    (exec, t)
}

/// V-OPCODES-1: `IS_LAST` was the `LEN == 1` gadget's output on every row, padding included, and
/// `IS_FIRST` was a free boolean there — so a padding row could send the four write-backs (or,
/// with `IS_FIRST`, a whole phantom run's messages). Here it writes 777 into the accumulator cell
/// after the real write-back, and the cpu's LOAD reads 777 instead of 267.
#[test]
fn a_padding_reduce_row_writing_the_accumulator_is_rejected() {
    let p = reduce_run_program(false);
    let m = Machine::new(FriProfile::Test);
    let (exec, t) = padding_writeback_traces(&p, F::from_u64(777), false);
    assert_eq!(exec.public[0], F::from_u64(777));
    assert!(
        rejects(|| prove_and_verify(&m, &p, &t)),
        "V-OPCODES-1: a padding reduce row's write-back VERIFIED, publishing 777 against an honest 267"
    );
}

/// The `IS_FIRST` variant: the same forged row also claims to start a run. Before the fix this
/// was already refused — not by any row constraint, but because its `REDUCE` dispatch entry has
/// no cpu row consuming it (a bus imbalance) — so it is not a red of its own; after the fix the
/// row itself is refused too (`IS_FIRST·(1 − IS_REAL) = 0`).
#[test]
fn a_padding_reduce_row_claiming_a_run_start_is_rejected() {
    let p = reduce_run_program(false);
    let m = Machine::new(FriProfile::Test);
    let (_, t) = padding_writeback_traces(&p, F::from_u64(777), true);
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a padding reduce row claiming a run start VERIFIED");
}

/// ZKR-4: nothing forced a run to *end* on its `IS_LAST` row. A run whose first row is followed
/// by padding (rows 1–2 zeroed into ordinary padding, and the RAM log rebuilt without their reads
/// and without the write-back) was accepted, so the write-back never happened and the cpu read
/// the accumulator cell's pre-reduction value: 0 published against an honest 267.
#[test]
fn a_reduce_run_that_never_reaches_its_last_row_is_rejected() {
    let p = reduce_run_program(false);
    let m = Machine::new(FriProfile::Test);
    let mut exec = execute(&p, &[], 1000).unwrap();
    let honest = build_traces(&p, &exec, Tier(8)).unwrap();
    let (mut red, lh) = (honest.reduce.clone().unwrap(), honest.reduce_log_height);
    let w = reduce_table::col::WIDTH;
    for row in 1..3 {
        for c in 0..w {
            red.values[row * w + c] = F::ZERO;
        }
    }
    let r = events_of(&exec, Op::Reduce)[0];
    // Keep the key's and alpha's reads and column 0's three; drop columns 1–2 and the result write.
    exec.events[r].mem.truncate(4 + 3);
    forge_accumulator_readback(&mut exec, F::ZERO);
    let reg = cpu::register_accesses(&exec.events);
    let ram = cpu::ram_accesses(&exec.events);
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((red, lh)));
    assert!(
        rejects(|| prove_and_verify(&m, &p, &t)),
        "ZKR-4: a reduce run that never reached its last row VERIFIED, publishing 0 against an honest 267"
    );
}

// ── OPCODES-4: the public table's four rows are all real ──────────────────────────────────────

/// OPCODES-4 (low): the public table let its trailing rows be padding, and a padding row pins
/// nothing — so a program that published fewer than four words left the remaining public values
/// free. Here a program publishes two; the proof claims four, the last two chosen at will.
/// (Every shipped program publishes exactly the four-word interface digest, so this was not
/// reachable through them; the table's own rule now says what R5 always meant.)
#[test]
fn public_values_a_program_never_published_are_rejected() {
    let p = Program {
        instrs: vec![
            i(Op::Faddi, 1, 0, 5),
            i(Op::Faddi, 2, 0, 6),
            i(Op::Public, 0, 1, 0),
            i(Op::Public, 0, 2, 0),
            i(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    };
    let m = Machine::new(FriProfile::Test);
    let mut exec = execute(&p, &[], 1000).unwrap();
    assert_eq!(exec.public.len(), 2);
    // The claimed four: the two published words, then two the program never produced.
    exec.public.extend([F::from_u64(0xDEAD), F::from_u64(0xBEEF)]);
    let reg = cpu::register_accesses(&exec.events);
    let ram = cpu::ram_accesses(&exec.events);
    let mut t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, None);
    // Rows 2 and 3 of the public table become padding: nothing on the cpu side consumes them.
    let w = public_table::col::WIDTH;
    for row in 2..4 {
        let r = &mut t.public.values[row * w..(row + 1) * w];
        r[public_table::col::IS_REAL] = F::ZERO;
        r[public_table::col::VALUE] = F::ZERO;
        for k in 0..4 {
            r[public_table::col::SEL0 + k] = F::ZERO;
        }
    }
    assert!(
        rejects(|| prove_and_verify(&m, &p, &t)),
        "OPCODES-4: a proof claiming public values [5, 6, 0xDEAD, 0xBEEF] for a program that published two words VERIFIED"
    );
}

// ── ZKQ-3: an extension pair never starts at r31 ──────────────────────────────────────────────

/// An extension operand names `(r, r + 1)`, so `r31` as its first register reaches register
/// cell `2^24 + 32` — a 33rd register the machine does not have. The emulator and
/// `Machine::check_program` (the prover's entry) refuse such a program, but the AIR decodes
/// every register index in five bits and never looks at `r + 1`, and `Machine::verify` did not
/// run the program check: a hand-built trace of `LOADE r31` proved and verified. Here the honest
/// run of `LOADE r30` is rewritten to `LOADE r31` in the program and the trace alike.
#[test]
fn an_extension_pair_starting_at_r31_is_rejected() {
    let mut p = Program {
        instrs: vec![
            i(Op::Faddi, 6, 0, 1000),
            i(Op::Loade, 30, 6, 0),
            i(Op::Public, 0, 0, 0),
            i(Op::Public, 0, 0, 0),
            i(Op::Public, 0, 0, 0),
            i(Op::Public, 0, 0, 0),
            i(Op::Halt, 0, 0, 0),
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    };
    let m = Machine::new(FriProfile::Test);
    let mut exec = execute(&p, &[], 1000).unwrap();
    p.instrs[1].rd = 31;
    exec.events[1].instr.rd = 31;
    assert!(Machine::check_program(&p).is_err(), "the prover's program check refuses it");
    let reg = cpu::register_accesses(&exec.events);
    assert!(reg.iter().any(|a| a.addr == memory::REGISTER_BASE + 32), "the trace writes register cell 2^24 + 32");
    let ram = cpu::ram_accesses(&exec.events);
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, None);
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "ZKQ-3: a proof of LOADE r31 (a pair reaching register 32) VERIFIED");
}

// ── issue #45 B1: the end-to-end forged-aggregate exercise against the fixed rVM ───────────────
//
// The toy RVM-1 vectors above (`a_forged_storee_high_lane_is_rejected` and the spill twin) isolate
// the freedom: a stored extension high lane the constraints did not bind, surfaced to a published
// word so nothing else could catch it. #45 asks the same question at the scale that matters — the
// *aggregate verifier* over a real inner proof, which stores ~14 370 such lanes per inner proof
// (the REDUCE descriptors and the register allocator's extension spills). Two legs:
//
//  1. the malicious inner proof: a tampered bundle proof that does not verify natively cannot be
//     aggregated at all — the tape's transcript replay is the native verifier's own checks, so a
//     bad proof never reaches the prover (in-suite, no proving);
//  2. the forged stored lane inside the aggregate verifier's own execution: forge one STOREE high
//     lane the way RVM-1 describes and show the *fixed* rVM refuses the aggregate proof. This is a
//     tier-19 rVM prove (tier 18 since phase 2's row cuts), so it is `#[ignore]`d for the big machine
//     (95.5 GB measured on Linux at tier 19; `docs/04-phase2-row-cuts.md` has the live heap).
//
// What the red-first run found (the 512 GB box, 2026-10-01, `EXT_READ_RD` emptied in a scratch copy
// — RVM-1's fix alone reverted, never committed):
//
//  - the toy vectors above go red: "the forged run VERIFIED ... publishing [12648430, 11, 11, 22]"
//    (and the spill twin's [1378, 2678, 11, 12648430]) — the forgery is accepted;
//  - leg 2 below stays green on the reverted rVM. Its teeth are the RAM table's read-after-write,
//    not RVM-1: the forged lane is written but the spill's reload (a LOADE 493 rows later) still
//    reads the honest value, so the RAM log disagrees with itself ("read does not match last write
//    at addr 0x3"). It is kept as the fixed rVM's refusal of the un-propagated forgery and does
//    not by itself test RVM-1;
//  - letting the program carry the forged lane forward (the emulator's STOREE storing 0xC0FFEE at
//    one clock — the fully propagated forgery) at 41 of the run's 14 788 STOREE rows traps every
//    time in the verifier's own checks: `commit phase root[*]`, `quotient identity[*]`,
//    `sample_bits decomposition`, `lookup terminal sum`. A random lane value is caught by the
//    arithmetic that consumes it; a lane value *chosen* to cancel a failing check (the report's
//    §6 path) was not constructed, so that the reverted rVM cannot be forged at this scale is not
//    claimed — what RVM-1's fix removes is exactly that choice, and the toy vectors are its red.

use randprotocol_rvm::programs::verify_rv32n;
use randprotocol_rvm::shape::{InnerKey as ZkInnerKey, InnerShape as ZkInnerShape};
use randprotocol_rvm::witness::WitnessTape;

fn agg_shape_and_key(p: &randprotocol_zkvm::machine::Proof) -> (ZkInnerShape, ZkInnerKey) {
    let shape = ZkInnerShape::of(
        FriProfile::Test,
        p.tier,
        p.program_log_height,
        p.input_log_height,
        p.keccak_log_height,
        p.sha256_log_height,
        p.public_log_height,
        p.mem_log_height,
    );
    let key = ZkInnerKey::of(FriProfile::Test, &shape);
    (shape, key)
}

/// Leg 1: a bundle proof tampered so it no longer verifies natively cannot be aggregated — the
/// aggregate tape's transcript replay refuses it before any rVM proving. (In-suite, emulation only.)
#[test]
fn a_malicious_inner_proof_cannot_be_aggregated() {
    use randprotocol_rvm::aggregate::{aggregate, AggregateError, InnerVerifierKey};
    let mut bp = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let zk = randprotocol_zkvm::machine::Machine::new(FriProfile::Test);
    zk.verify(&bp.hc, &bp.proof).expect("the honest inner proof verifies natively");

    // Tamper one published output word: still 35 canonical values (the shape check passes), but no
    // longer the proof's own transcript.
    bp.proof.public_values[randprotocol_zkvm::tables::cpu::pv::OUT0] += 1;
    assert!(zk.verify(&bp.hc, &bp.proof).is_err(), "the tampered inner proof does not verify natively");

    let (shape, key) = agg_shape_and_key(&bp.proof);
    let vk = InnerVerifierKey { shape, key };
    let m = Machine::new(FriProfile::Test);
    match aggregate(&m, &vk, std::slice::from_ref(&bp.proof), &common::TEST_BINDING, None) {
        Err(AggregateError::Tape(_)) => {}
        Err(e) => panic!("a malicious inner proof must be refused at the tape replay, got {e:?}"),
        Ok(_) => panic!("a malicious inner proof must never yield an aggregate"),
    }
}

/// Forge a STOREE's stored high lane in an aggregate-verifier execution, keeping the RAM store side
/// consistent (the high cell's write carries the forged value). `rd + 1`'s register value is left
/// honest, so the fix's `REG.read(rd+1)` disagrees with it; the unfixed register table omits that
/// read entirely. Returns the forged execution and the index of the STOREE spill it hit.
fn forge_a_stored_spill(exec: &mut Execution) -> usize {
    // A register-allocator spill of an extension value: STOREE with `ra == r0` (the absolute-address
    // form) writing two cells. The aggregate verifier makes thousands.
    let idx = exec
        .events
        .iter()
        .position(|e| e.instr.op == Op::Storee && e.instr.ra == 0 && e.mem.len() == 2 && e.mem[1].is_write)
        .expect("the aggregate verifier spills extension values with STOREE");
    let e = &mut exec.events[idx];
    e.d[1] = F::from_u64(FORGED);
    e.mem[1].value = F::from_u64(FORGED);
    idx
}

/// Leg 2: the forged stored lane inside the real aggregate verifier, refused by the fixed rVM with
/// the unfixed builder's register table (no `rd + 1` read) and with the fixed table carrying the
/// forged read. A tier-19 rVM prove per variant, so `#[ignore]`d. On the fixed rVM the REG read the
/// fix adds is unmatched; the un-propagated reload also breaks the RAM table's read-after-write,
/// which is why this test stays green with RVM-1 reverted (the block comment above).
#[test]
#[ignore = "issue45 B1: the forged-aggregate exercise, tier 18 rVM prove since phase 2 (tier 19 before: 95.5 GB measured on Linux), ~30 min/variant. Run: \
            cargo test --release -p recursion --test cheating a_forged_stored_high_lane_in_the_aggregate_verifier_is_refused -- --ignored --nocapture"]
fn a_forged_stored_high_lane_in_the_aggregate_verifier_is_refused() {
    let bp = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = agg_shape_and_key(&bp.proof);
    let program = verify_rv32n(&shape, &key, randprotocol_rvm::dsl::Checkpoints::Off).program;
    let tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, std::slice::from_ref(&bp.proof), &common::TEST_BINDING).unwrap();
    let m = Machine::new(FriProfile::Test);

    let honest = execute(&program, &tape.words, 1 << 24).expect("the honest aggregate accepts");
    let tier = Tier::for_cycles(honest.cpu_rows()).expect("the N=1 aggregate has a tier");
    assert_eq!(tier, Tier(18), "the test-profile N=1 aggregate is tier 18 (202 472 rows since phase 3's Cut D, 231 224 since phase 2's row cuts; tier 19 before)");
    // The reduce trace depends only on REDUCE events, which the STOREE forgery does not touch, so
    // the honest build's reduce table is the one the forged trace uses.
    let honest_traces = build_traces(&program, &honest, tier).unwrap();
    let reduce = (honest_traces.reduce.clone().unwrap(), honest_traces.reduce_log_height);

    let mut forged = honest.clone();
    let storee = forge_a_stored_spill(&mut forged);
    eprintln!(
        "forged the stored high lane of STOREE event {storee} (of {} events) to {FORGED:#x}",
        forged.events.len()
    );
    let ram = cpu::ram_accesses(&forged.events);
    let reg_fixed = cpu::register_accesses(&forged.events);

    // Variant (2): the unfixed builder's register table — no `rd + 1` read on any STOREE row.
    let reg_unfixed: Vec<randprotocol_rvm::emulator::MemAccess> = reg_fixed
        .iter()
        .copied()
        .filter(|a| !(a.ts % 16 == TS_RD1_READ && forged.events[(a.ts / 16) as usize].instr.op == Op::Storee))
        .collect();
    let t = traces_from_parts(&program, &forged, tier, &reg_unfixed, &ram, Some(reduce.clone()));
    assert!(
        rejects(|| prove_and_verify_at(&m, &program, &t, tier)),
        "the forged aggregate VERIFIED with the unfixed register table"
    );

    // Variant (3): the fixed register table, carrying the forged `rd + 1` read.
    let t = traces_from_parts(&program, &forged, tier, &reg_fixed, &ram, Some(reduce));
    assert!(
        rejects(|| prove_and_verify_at(&m, &program, &t, tier)),
        "the forged aggregate VERIFIED with the register table carrying its forged read"
    );
}

// ── Cut C: COMPRESS, the poseidon2 chip's third row kind — one forgery per new invariant ──────
//
// Each test below establishes that `Machine::verify` refuses its edit; the constraint each one
// targets is named in its comment, but which check fires first is not pinned. The spec's §5 case
// "an output lane written to the sibling instead of the state" has no test: it is not expressible
// by a trace edit, since the chip's write address is the expression `PTR + k`, never a free column.

/// `tests/emulator.rs`'s `bit = 1` program (`common::compress_program`): one `COMPRESS` whose
/// children swap, so a forgery that un-swaps them is visible.
fn compress_setup() -> (Machine, Program, Traces) {
    let p = common::compress_program(1);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (Machine::new(FriProfile::Test), p, t)
}

fn compress_row(t: &Traces) -> usize {
    let w = poseidon2::col::WIDTH;
    (0..t.poseidon2.height()).find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_COMPRESS] == F::ONE).unwrap()
}

#[test]
fn honest_compress_traces_pass() {
    let (m, p, t) = compress_setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

/// BIT = 2 on the chip row: refused by `Machine::verify` (the target is `assert_bool(BIT)`).
#[test]
fn a_compress_row_with_a_non_boolean_bit_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = compress_row(&t);
    t.poseidon2.values[row * w + poseidon2::col::BIT] = F::from_u64(2);
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// The chip row's BIT flipped against the cpu row's D0: refused by `Machine::verify` (the targets
/// are the COMPRESS bus message, which no longer matches, and the RAM reads, now claiming swapped
/// children).
#[test]
fn a_compress_row_whose_bit_disagrees_with_the_dispatch_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = compress_row(&t);
    t.poseidon2.values[row * w + poseidon2::col::BIT] = F::ZERO;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// The row claims the plain kind with BIT still set: refused by `Machine::verify` (the target is
/// `(1 − IS_COMPRESS)·BIT = 0`).
#[test]
fn a_compress_row_claiming_the_plain_kind_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = compress_row(&t);
    t.poseidon2.values[row * w + poseidon2::col::IS_COMPRESS] = F::ZERO;
    t.poseidon2.values[row * w + poseidon2::col::IS_PERM] = F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// The sibling pointer moved by one cell: refused by `Machine::verify` (the target is the four
/// sibling reads, which find no matching writes).
#[test]
fn a_compress_row_reading_the_sibling_from_the_wrong_address_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = compress_row(&t);
    t.poseidon2.values[row * w + poseidon2::col::SRC_PTR] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// A padding row with IS_COMPRESS set: refused by `Machine::verify` (the targets are
/// `MULT = IS_REAL` and the kind sum).
#[test]
fn a_padding_row_claiming_compress_is_rejected() {
    let (m, p, mut t) = compress_setup();
    let w = poseidon2::col::WIDTH;
    let row = (0..t.poseidon2.height()).rev().find(|r| t.poseidon2.values[r * w + poseidon2::col::IS_REAL] == F::ZERO).unwrap();
    t.poseidon2.values[row * w + poseidon2::col::IS_COMPRESS] = F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

// ── Cut E2: the fold row kind ─────────────────────────────────────────────────────────────────
fn fold_setup() -> (Machine, Program, Traces) {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(41);
    let ys: Vec<EF> = (0..8).map(|_| common::random_ext(&mut rng)).collect();
    let (p, _) = common::fold_program(&[(3, ys, common::random_ext(&mut rng))]);
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

fn fold_first_row(t: &Traces) -> usize {
    let w = reduce_table::col::WIDTH;
    let r = t.reduce.as_ref().unwrap();
    (0..r.height()).find(|k| r.values[k * w + reduce_table::col::F_FIRST] == F::ONE).unwrap()
}

#[test]
fn honest_fold_traces_pass() {
    let (m, p, t) = fold_setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

/// Spec §5: a FOLD run with a tampered B_m — the first phase-2 row's top accumulator.
#[test]
fn a_fold_run_with_a_tampered_coefficient_accumulator_is_rejected() {
    let (m, p, mut t) = fold_setup();
    let (w, row) = (reduce_table::col::WIDTH, fold_first_row(&t) + 8);
    t.reduce.as_mut().unwrap().values[row * w + reduce_table::col::D0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// Spec §5: a FOLD whose u differs from the cpu's — every row of the run (so the carry holds).
/// Over a random row the Horner steps no longer reproduce the trace's accumulators, so the
/// transition constraints refuse it before the `FOLD` bus is reached; the bus binding of `u` alone
/// is isolated by `a_fold_run_whose_u_is_not_the_dispatched_u_is_rejected_by_the_fold_bus`.
#[test]
fn a_fold_whose_u_differs_from_the_dispatch_is_rejected_by_the_horner_steps() {
    let (m, p, mut t) = fold_setup();
    let (w, first) = (reduce_table::col::WIDTH, fold_first_row(&t));
    let r = t.reduce.as_mut().unwrap();
    for row in first..first + 16 {
        r.values[row * w + reduce_table::col::U0] += F::ONE;
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// Spec §5: a FOLD run cut short — its last phase-2 row turned into padding. The trace no longer
/// sends the result's two writes the run's RAM log holds, so the `RAM` bus refuses it (with the
/// must-continue rule deleted it is still refused — mutation-checked, final fix wave); the run
/// ending without `F_LAST` also violates the must-continue rule, which
/// `a_fold_run_stopping_before_its_last_row_is_rejected_by_the_must_continue_rule` isolates.
#[test]
fn a_fold_run_cut_short_is_rejected_by_its_missing_result_write() {
    let (m, p, mut t) = fold_setup();
    let (w, last) = (reduce_table::col::WIDTH, fold_first_row(&t) + 15);
    let r = t.reduce.as_mut().unwrap();
    for c in 0..w {
        if c != reduce_table::col::MULT && c != reduce_table::col::MULT_C {
            r.values[last * w + c] = F::ZERO;
        }
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// A phase-1 row whose coefficients are not the table's, over a non-zero `y`: the accumulator step
/// `n(D) = D + C·y` refuses it before the lookup is reached. The `FOLD_COEFF` binding alone is
/// isolated by `a_fold_coefficient_off_the_table_is_rejected_by_the_coefficient_lookup`.
#[test]
fn a_fold_row_with_a_coefficient_off_the_table_is_rejected_by_the_accumulator_step() {
    let (m, p, mut t) = fold_setup();
    let (w, first) = (reduce_table::col::WIDTH, fold_first_row(&t));
    t.reduce.as_mut().unwrap().values[first * w + reduce_table::col::C0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// A fold run that begins right after the last reduce row without `F_FIRST` sends no `FOLD`
/// message and would still write its result: the reduce-to-fold boundary must start a run.
///
/// The forgery is balanced on every bus, so only that boundary rule can refuse it: after the
/// honest reduce run's last row (row 2), one headless phase-2 fold row (`K = 1`, `F_A = 1`,
/// `F_LAST`) — no `F_FIRST`, so no `FOLD` message and no cpu dispatch; no phase-1 row, so no
/// coefficient lookup and no read. The fold columns of the last reduce row are free witness, and
/// the run carry from it (`F_MSG`, `F_A`, `U`, `CLK`, `K + 1`, the Horner step) makes the forged
/// row write `(777, 0)` to cells 500–501 at the reduce row's clock. The RAM table is given those
/// two writes, so `RAM` balances too. With the boundary constraint deleted this forgery verifies.
#[test]
fn a_headless_fold_run_after_the_reduce_rows_is_rejected() {
    use reduce_table::col::*;
    let p = reduce_run_program(false);
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 1000).unwrap();
    let honest = build_traces(&p, &exec, Tier(8)).unwrap();
    let (mut red, lh) = (honest.reduce.clone().unwrap(), honest.reduce_log_height);
    let w = WIDTH;
    let (last, forged) = (2usize, 3usize);
    assert_eq!(red.values[last * w + IS_LAST], F::ONE, "row 2 is the reduce run's last row");
    assert_eq!(red.values[forged * w + IS_REAL], F::ZERO, "row 3 is padding");
    let clk = red.values[last * w + CLK];
    // The last reduce row's free fold columns: the carry's source.
    red.values[last * w + F_K] = F::ZERO;
    red.values[last * w + F_A] = F::ONE;
    red.values[last * w + F_MSG] = F::from_u64(494); // 494 + 2·1 + 4 = 500
    red.values[last * w + U0] = F::ONE;
    red.values[last * w + D0] = F::from_u64(777);
    // The headless row: phase 2, K = 1 = 2·F_A − 1, so it is its run's last row.
    let r = &mut red.values[forged * w..(forged + 1) * w];
    r[IS_FOLD] = F::ONE;
    r[F_LAST] = F::ONE;
    r[F_K] = F::ONE;
    r[F_A] = F::ONE;
    r[F_MSG] = F::from_u64(494);
    r[CLK] = clk;
    r[U0] = F::ONE;
    r[FACC0] = F::from_u64(777); // the Horner step from row 2: 0·u + D_0
    r[FOUT0] = F::from_u64(777); // FACC·u + D_0, with this row's D all zero
    let reg = cpu::register_accesses(&exec.events);
    let mut ram = cpu::ram_accesses(&exec.events);
    let ts = clk.as_canonical_u64() as u32 * 16;
    ram.push(MemAccess { addr: 500, ts: ts + 14, value: F::from_u64(777), is_write: true });
    ram.push(MemAccess { addr: 501, ts: ts + 15, value: F::ZERO, is_write: true });
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((red, lh)));
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a headless fold run after the last reduce row VERIFIED, writing 777 to cell 500");
}

// ── Cut E2 fix round 1: forgeries each refused by exactly one rule ───────────────────────────
// Every forgery below keeps every other constraint and every other bus satisfied, and each test
// was mutation-checked: with its one rule deleted from `ReduceAir::eval` the forgery VERIFIES.

fn fold_traces(p: &Program) -> (Machine, Traces) {
    let exec = execute(p, &[], 10_000).unwrap();
    (Machine::new(FriProfile::Test), build_traces(p, &exec, Tier(8)).unwrap())
}

/// The `FOLD` bus binds `u`. Over a constant row every `B_{m≥1}` is zero, so each Horner
/// accumulator stays zero and `FOUT = B_0` for any `u`: changing `U0` on all 2a rows of the run
/// keeps every constraint and the RAM bus satisfied, and only the dispatch `(clk, msg, u, a)` the
/// cpu sends no longer matches the run's `FOLD` provide.
#[test]
fn a_fold_run_whose_u_is_not_the_dispatched_u_is_rejected_by_the_fold_bus() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(42);
    let y = common::random_ext(&mut rng);
    let (p, _) = common::fold_program(&[(3, vec![y; 8], common::random_ext(&mut rng))]);
    let (m, mut t) = fold_traces(&p);
    prove_and_verify(&m, &p, &t).expect("the honest constant-row fold verifies");
    let (w, first) = (reduce_table::col::WIDTH, fold_first_row(&t));
    let r = t.reduce.as_mut().unwrap();
    for row in first..first + 16 {
        assert_eq!(r.values[row * w + reduce_table::col::FACC0], F::ZERO, "a constant row keeps FACC at zero");
        r.values[row * w + reduce_table::col::U0] += F::ONE;
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a fold run at a u the cpu never dispatched VERIFIED");
}

/// The `FOLD_COEFF` lookup binds the coefficients. With `y_0 = 0`, row 0's `C·y_0` is zero
/// whatever `C` is, so a tampered `C0` there leaves every accumulator, the result and the RAM
/// bus unchanged; only the lookup of `(a, 0, C0..C7)` in the committed table refuses it.
#[test]
fn a_fold_coefficient_off_the_table_is_rejected_by_the_coefficient_lookup() {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(43);
    let mut ys: Vec<EF> = (0..8).map(|_| common::random_ext(&mut rng)).collect();
    ys[0] = EF::ZERO;
    let (p, _) = common::fold_program(&[(3, ys, common::random_ext(&mut rng))]);
    let (m, mut t) = fold_traces(&p);
    prove_and_verify(&m, &p, &t).expect("the honest fold with y_0 = 0 verifies");
    let (w, first) = (reduce_table::col::WIDTH, fold_first_row(&t));
    t.reduce.as_mut().unwrap().values[first * w + reduce_table::col::C0] += F::ONE;
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a phase-1 row with a coefficient off the table VERIFIED");
}

/// The zero-row fold's message base and arity, and so its cells: `y_k` at `MSG + 2k`, the four
/// salts, then the result pair at [`zero_row_result`] (Task 5 sweep: the forgeries below named
/// these as literals).
const ZERO_ROW_MSG: u64 = 300;
const ZERO_ROW_ARITY: u64 = 2;

/// The result cell the fold run writes: after the row's `2a` cells and its salts.
fn zero_row_result() -> u64 {
    zero_row_result_at(ZERO_ROW_ARITY)
}

/// [`zero_row_result`] at another arity.
fn zero_row_result_at(arity: u64) -> u64 {
    ZERO_ROW_MSG + 2 * arity + randprotocol_rvm::isa::FOLD_SALT_CELLS
}

/// An arity-2 fold of the all-zero row at u = 3 whose result is never read back by the program
/// (so a forged result needs only its two RAM writes changed): the cells are stored as zero, the
/// fold runs, and the program publishes four zeros.
fn zero_row_fold_program() -> Program {
    zero_row_fold_program_at(ZERO_ROW_ARITY)
}

/// [`zero_row_fold_program`] at another arity (final fix wave: the arity-4 `F_A` carry forgery).
fn zero_row_fold_program_at(arity: u64) -> Program {
    let mut v: Vec<Instr> = (ZERO_ROW_MSG..ZERO_ROW_MSG + 2 * arity).map(|a| i(Op::Store, 0, 0, a)).collect();
    v.extend([i(Op::Faddi, 2, 0, 3), i(Op::Faddi, 3, 0, 0), i(Op::Faddi, 4, 0, ZERO_ROW_MSG), i(Op::Fold, 2, 4, arity)]);
    v.extend([i(Op::Public, 0, 0, 0), i(Op::Public, 0, 0, 0), i(Op::Public, 0, 0, 0), i(Op::Public, 0, 0, 0), i(Op::Halt, 0, 0, 0)]);
    Program { instrs: v, checkpoints: vec![], reduce_layout: vec![] }
}

/// The phase switch zeroes the Horner accumulator. Over the all-zero row every `B_m` is zero and
/// the honest result is 0; a first phase-2 row with `FACC = 1` instead runs Horner to
/// `FACC·u^a = 9` (u = 3, a = 2). The chain and `FOUT` are recomputed and the RAM table is given
/// the forged result writes, so only the switch's `FACC = 0` rule refuses it.
#[test]
fn a_fold_run_whose_horner_does_not_start_at_zero_is_rejected_by_the_phase_switch() {
    use reduce_table::col::*;
    let p = zero_row_fold_program();
    let m = Machine::new(FriProfile::Test);
    let mut exec = execute(&p, &[], 1000).unwrap();
    let honest = build_traces(&p, &exec, Tier(8)).unwrap();
    prove_and_verify(&m, &p, &honest).expect("the honest zero-row fold verifies");
    let (mut red, lh) = (honest.reduce.clone().unwrap(), honest.reduce_log_height);
    let first = fold_first_row(&honest);
    let w = WIDTH;
    assert_eq!(red.values[(first + 3) * w + FOUT0], F::ZERO, "the honest fold of the zero row is zero");
    red.values[(first + 2) * w + FACC0] = F::ONE; // the first phase-2 row (K = a = 2)
    red.values[(first + 3) * w + FACC0] = F::from_u64(3); // 1·u + D_0
    red.values[(first + 3) * w + FOUT0] = F::from_u64(9); // 3·u + D_0
    let f = exec.events.iter().position(|e| e.instr.op == Op::Fold).unwrap();
    let res = exec.events[f].mem.iter_mut().find(|a| a.is_write && a.addr == zero_row_result()).unwrap();
    res.value = F::from_u64(9);
    let reg = cpu::register_accesses(&exec.events);
    let ram = cpu::ram_accesses(&exec.events);
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((red, lh)));
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a fold whose Horner started at FACC = 1 VERIFIED, writing 9 for the zero row's 0");
}

/// The phase switch happens at `K = a`. An arity-2 run that switches one row early (phase 1 is
/// row 0 alone, phase 2 rows 1–3) skips `y_1`: its two reads are dropped from the RAM table and
/// the coefficient table's `(2, 1)` multiplicity with them. Over the all-zero row the result is
/// still 0, so every other constraint and every bus balances; only the switch's `n(K) = a` rule
/// refuses it. (Over a non-zero row this run would fold a row with `y_1` never read.)
#[test]
fn a_fold_run_whose_phase_switch_is_early_is_rejected_by_the_switch_index() {
    use reduce_table::col::*;
    let p = zero_row_fold_program();
    let m = Machine::new(FriProfile::Test);
    let mut exec = execute(&p, &[], 1000).unwrap();
    let honest = build_traces(&p, &exec, Tier(8)).unwrap();
    let (mut red, lh) = (honest.reduce.clone().unwrap(), honest.reduce_log_height);
    let first = fold_first_row(&honest);
    let w = WIDTH;
    let row1 = (first + 1) * w;
    red.values[row1 + F_PH1] = F::ZERO;
    red.values[row1 + Y0] = F::ZERO;
    red.values[row1 + Y1] = F::ZERO;
    for j in 0..8 {
        red.values[row1 + C0 + j] = F::ZERO;
    }
    // The coefficient table's row for (a = 2, k = 1) is row 1; its multiplicity loses the lookup.
    red.values[w + MULT_C] -= F::ONE;
    let f = exec.events.iter().position(|e| e.instr.op == Op::Fold).unwrap();
    // y_1's two cells, MSG + 2 and MSG + 3, are the reads the early switch skips.
    exec.events[f].mem.retain(|a| a.is_write || a.addr < ZERO_ROW_MSG + 2);
    let reg = cpu::register_accesses(&exec.events);
    let ram = cpu::ram_accesses(&exec.events);
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((red, lh)));
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a fold run whose phase 1 ended at K = a − 2 VERIFIED, never reading y_1");
}

// ── Final fix wave (the whole-branch review, Important 1): the fold kind's structure rules and the
// reduce kind's `ROW_END` carry ────────────────────────────────────────────────────────────────
// Each forgery below keeps every other constraint and every bus satisfied, so the one rule its
// name gives is the only one that refuses it; each was mutation-checked in a scratch copy (that
// rule deleted from `ReduceAir::eval`, the test run alone: it fails with its "VERIFIED" message),
// recorded in the final fix report. The fold forgeries run over the all-zero row
// (`zero_row_fold_program[_at]`, u = 3), whose honest result is 0 and is never read back, so a
// forged run needs only its RAM log edited; the pow kind's Task 4/5 forgeries are the template.

/// The fold kind's own columns, `IS_FOLD..=FOUT1`: what a forgery moves between rows or clears
/// when a fold row becomes padding. `MULT_C` (col 69) is the provider region's, not the row's;
/// `CLK` (shared by every kind) is handled by each forgery.
const FOLD_KIND: std::ops::RangeInclusive<usize> = reduce_table::col::IS_FOLD..=reduce_table::col::FOUT1;

/// The honest zero-row fold at `arity`: the machine, the run, its reduce trace and declared
/// log-height, and the run's first row. The honest proof verifies.
fn zero_row_parts(arity: u64) -> (Machine, Program, Execution, p3_matrix::dense::RowMajorMatrix<F>, u8, usize) {
    let p = zero_row_fold_program_at(arity);
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 1000).unwrap();
    let honest = build_traces(&p, &exec, Tier(8)).unwrap();
    prove_and_verify(&m, &p, &honest).expect("the honest zero-row fold verifies");
    let first = fold_first_row(&honest);
    (m, p, exec, honest.reduce.unwrap(), honest.reduce_log_height, first)
}

/// The run's `FOLD` event (its y reads and its result writes).
fn fold_event(exec: &mut Execution) -> &mut randprotocol_rvm::emulator::Event {
    exec.events.iter_mut().find(|e| e.instr.op == Op::Fold).unwrap()
}

/// Copy fold row `from`'s kind columns and clock onto row `to` (the provider multiplicities stay).
fn move_fold_row(red: &mut p3_matrix::dense::RowMajorMatrix<F>, from: usize, to: usize) {
    let w = reduce_table::col::WIDTH;
    for c in FOLD_KIND.chain([reduce_table::col::CLK]) {
        red.values[to * w + c] = red.values[from * w + c];
    }
}

/// Turn row `row` into padding: its fold kind columns and its clock cleared.
fn clear_fold_row(red: &mut p3_matrix::dense::RowMajorMatrix<F>, row: usize) {
    let w = reduce_table::col::WIDTH;
    for c in FOLD_KIND.chain([reduce_table::col::CLK]) {
        red.values[row * w + c] = F::ZERO;
    }
}

/// A forged reduce-chip trace with the run's (edited) RAM log, through the host-check-free path.
fn reduce_forgery_refused(m: &Machine, p: &Program, exec: &Execution, red: p3_matrix::dense::RowMajorMatrix<F>, lh: u8) -> bool {
    let reg = cpu::register_accesses(&exec.events);
    let ram = cpu::ram_accesses(&exec.events);
    let t = traces_from_parts(p, exec, Tier(8), &reg, &ram, Some((red, lh)));
    rejects(|| prove_and_verify(m, p, &t))
}

/// `F_MSG` is carried along a fold run. Every row after the first moves its row base 20 cells on:
/// `y_1` is read from the fresh cells 322–323 (zero, as the row's own cells are) and the result
/// is written to 328–329 instead of 308–309. The first row keeps the dispatched base, so the
/// `FOLD` message balances, and the RAM log carries the moved reads and writes; only
/// `n(F_MSG) = F_MSG` along the run refuses it. (Over a real row the run would fold values from
/// any cells and write its result anywhere.)
#[test]
fn a_fold_run_moving_its_row_base_mid_run_is_rejected_by_the_base_carry() {
    use reduce_table::col::*;
    let (m, p, mut exec, mut red, lh, first) = zero_row_parts(ZERO_ROW_ARITY);
    for row in first + 1..first + 4 {
        red.values[row * WIDTH + F_MSG] += F::from_u64(20);
    }
    for a in fold_event(&mut exec).mem.iter_mut().filter(|a| a.is_write || a.addr >= ZERO_ROW_MSG + 2) {
        a.addr += 20;
    }
    assert!(reduce_forgery_refused(&m, &p, &exec, red, lh), "a fold run that moved its row base mid-run VERIFIED, writing its result 20 cells away");
}

/// `CLK` is carried along a fold run. Every row after the first claims the next clock: `y_1`'s
/// reads and the result's writes move to `16·(clk + 1) + slot`, which the RAM log carries (nothing
/// else touches those cells afterwards); the first row (the `FOLD` message) keeps the dispatch
/// clock. Only `n(CLK) = CLK` along the run refuses it. (Unpinned, a run reads `y_k` at a clock
/// of its choosing — the OPCODES-1 stale read, for the fold kind.)
#[test]
fn a_fold_run_moving_its_clock_mid_run_is_rejected_by_the_clock_carry() {
    use reduce_table::col::*;
    let (m, p, mut exec, mut red, lh, first) = zero_row_parts(ZERO_ROW_ARITY);
    for row in first + 1..first + 4 {
        red.values[row * WIDTH + CLK] += F::ONE;
    }
    for a in fold_event(&mut exec).mem.iter_mut().filter(|a| a.is_write || a.addr >= ZERO_ROW_MSG + 2) {
        a.ts += 16;
    }
    assert!(reduce_forgery_refused(&m, &p, &exec, red, lh), "a fold run that moved its clock mid-run VERIFIED");
}

/// `F_A` is carried along a fold run. An arity-4 run whose phase-2 rows claim `a = 3`: phase 1
/// (K = 0..3) keeps the dispatched arity, so its coefficient lookups and the switch at
/// `n(K) = 4` hold, and phase 2 then ends at `K = 2·3 − 1 = 5` — two Horner steps short — and
/// writes its result to `MSG + 2·3 + 4`, the row's last two salt cells, instead of
/// `MSG + 2·4 + 4`. Over the zero row the Horner chain is zero either way; rows 6–7 become padding
/// and the RAM log's result writes move down two cells. Only `n(F_A) = F_A` refuses it.
#[test]
fn a_fold_run_changing_its_arity_mid_run_is_rejected_by_the_arity_carry() {
    use reduce_table::col::*;
    let (m, p, mut exec, mut red, lh, first) = zero_row_parts(4);
    for row in first + 4..first + 6 {
        red.values[row * WIDTH + F_A] = F::from_u64(3);
    }
    red.values[(first + 5) * WIDTH + F_LAST] = F::ONE;
    for row in first + 6..first + 8 {
        clear_fold_row(&mut red, row);
    }
    for a in fold_event(&mut exec).mem.iter_mut().filter(|a| a.is_write) {
        assert!(a.addr >= zero_row_result_at(4));
        a.addr -= 2;
    }
    assert!(reduce_forgery_refused(&m, &p, &exec, red, lh), "a fold run that changed its arity mid-run VERIFIED, ending two rows early in the salt cells");
}

/// `U` is carried along a fold run: every row after the first changes `U0` (`lane` 0) or `U1`
/// (`lane` 1). Over a constant row every `B_{m≥1}` is zero, so the Horner accumulator stays zero
/// and the result is `B_0` whatever `u` the phase-2 rows use; the first row keeps the dispatched
/// `u`, so the `FOLD` message balances. Only that lane's `n(U) = U` refuses it. (Over a real row
/// the run would fold at a `u` the cpu never dispatched; the bus binding of the first row's `u`
/// is `a_fold_run_whose_u_is_not_the_dispatched_u_is_rejected_by_the_fold_bus`.)
fn fold_u_moved_mid_run_refused(lane: usize) -> bool {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(44);
    let y = common::random_ext(&mut rng);
    let (p, _) = common::fold_program(&[(3, vec![y; 8], common::random_ext(&mut rng))]);
    let (m, mut t) = fold_traces(&p);
    prove_and_verify(&m, &p, &t).expect("the honest constant-row fold verifies");
    let (w, first) = (reduce_table::col::WIDTH, fold_first_row(&t));
    let r = t.reduce.as_mut().unwrap();
    for row in first + 1..first + 16 {
        assert_eq!(r.values[row * w + reduce_table::col::FACC0], F::ZERO, "a constant row keeps FACC at zero");
        r.values[row * w + reduce_table::col::U0 + lane] += F::ONE;
    }
    rejects(|| prove_and_verify(&m, &p, &t))
}

#[test]
fn a_fold_run_moving_u0_mid_run_is_rejected_by_the_u0_carry() {
    assert!(fold_u_moved_mid_run_refused(0), "a fold run whose phase-2 rows used another u0 VERIFIED");
}

#[test]
fn a_fold_run_moving_u1_mid_run_is_rejected_by_the_u1_carry() {
    assert!(fold_u_moved_mid_run_refused(1), "a fold run whose phase-2 rows used another u1 VERIFIED");
}

/// A run starts with zero accumulators. The review's example: the zero row at arity 2 with
/// `D0 = 1` from the first row — phase 1 adds `C·0`, so pair 0 enters Horner at 1, and the run
/// writes `1·u = 3` where the honest fold is 0. Every step from the first row on is the honest
/// recurrence (`FACC = 1` on the last row, `FOUT = 3`), the RAM log's result write says 3; only
/// `F_FIRST·D = 0` refuses it.
#[test]
fn a_fold_run_starting_with_a_dirty_accumulator_is_rejected_by_the_zero_start_rule() {
    use reduce_table::col::*;
    let (m, p, mut exec, mut red, lh, first) = zero_row_parts(ZERO_ROW_ARITY);
    for row in first..first + 3 {
        red.values[row * WIDTH + D0] = F::ONE; // pair 0 through phase 1 and into the first phase-2 row
    }
    red.values[(first + 3) * WIDTH + FACC0] = F::ONE; // 0·u + D_0
    red.values[(first + 3) * WIDTH + FOUT0] = F::from_u64(3); // 1·u + D_0 (pair 0 shifted out: 0)
    fold_event(&mut exec).mem.iter_mut().find(|a| a.is_write && a.addr == zero_row_result()).unwrap().value = F::from_u64(3);
    assert!(reduce_forgery_refused(&m, &p, &exec, red, lh), "a fold run starting at D0 = 1 VERIFIED, writing 3 for the zero row's 0");
}

/// A run starts at `K = 0`. An arity-2 run that starts at `K = 1` is three rows: phase 1 is the
/// one row K = 1 (it reads `y_1` and looks up the table's `(2, 1)` row), the switch lands at
/// `n(K) = 2 = a`, and phase 2 is K = 2, 3 with the last row at `2a − 1`. `y_0` is never read: its
/// two reads leave the RAM log and the table's `(2, 0)` multiplicity drops by one. The `FOLD`
/// message, the lookups, the K step, the switch and the end rule all hold; only `F_FIRST·K = 0`
/// refuses it.
#[test]
fn a_fold_run_starting_past_k_zero_is_rejected_by_the_first_index_rule() {
    use reduce_table::col::*;
    let (m, p, mut exec, mut red, lh, first) = zero_row_parts(ZERO_ROW_ARITY);
    assert_eq!(first, 0, "a fold-only program's run starts at row 0, beside the coefficient table");
    // Row 0 becomes the honest row 1 (K = 1, its coefficients and its read) with row 0's start flag.
    move_fold_row(&mut red, 1, 0);
    red.values[F_FIRST] = F::ONE;
    move_fold_row(&mut red, 2, 1);
    move_fold_row(&mut red, 3, 2);
    clear_fold_row(&mut red, 3);
    red.values[MULT_C] -= F::ONE; // the table's (2, 0) row, at row 0
    fold_event(&mut exec).mem.retain(|a| a.is_write || a.addr >= ZERO_ROW_MSG + 2);
    assert!(reduce_forgery_refused(&m, &p, &exec, red, lh), "a fold run starting at K = 1 VERIFIED, never reading y_0");
}

/// `K` steps by one. An arity-2 run whose index jumps from 0 to 2: phase 1 is row K = 0 alone
/// (the switch at `n(K) = 2 = a` holds), then K = 2, 3. `y_1` is never read: its reads leave the
/// RAM log and the table's `(2, 1)` multiplicity drops. Only `n(K) = K + 1` refuses it. (The
/// early switch with the K step intact is `a_fold_run_whose_phase_switch_is_early_is_rejected_by_the_switch_index`.)
#[test]
fn a_fold_run_skipping_an_index_is_rejected_by_the_index_step() {
    use reduce_table::col::*;
    let (m, p, mut exec, mut red, lh, first) = zero_row_parts(ZERO_ROW_ARITY);
    move_fold_row(&mut red, first + 2, first + 1);
    move_fold_row(&mut red, first + 3, first + 2);
    clear_fold_row(&mut red, first + 3);
    red.values[WIDTH + MULT_C] -= F::ONE; // the table's (2, 1) row, at row 1
    fold_event(&mut exec).mem.retain(|a| a.is_write || a.addr < ZERO_ROW_MSG + 2);
    assert!(reduce_forgery_refused(&m, &p, &exec, red, lh), "a fold run whose index jumped 0 → 2 VERIFIED, never reading y_1");
}

/// A run ends at `K = 2a − 1`. An arity-2 run that claims `F_LAST` at K = 2 writes the Horner value
/// one step early (over the zero row still 0, at the same cells and clock, so the RAM log is the
/// honest one) and its fourth row becomes padding. Only `F_LAST·(K − 2a + 1) = 0` refuses it.
#[test]
fn a_fold_run_ending_before_k_two_a_minus_one_is_rejected_by_the_end_rule() {
    use reduce_table::col::*;
    let (m, p, exec, mut red, lh, first) = zero_row_parts(ZERO_ROW_ARITY);
    red.values[(first + 2) * WIDTH + F_LAST] = F::ONE;
    clear_fold_row(&mut red, first + 3);
    assert!(reduce_forgery_refused(&m, &p, &exec, red, lh), "a fold run ending at K = 2a − 2 VERIFIED, one Horner step short");
}

/// A run continues until `F_LAST`. An arity-2 run that stops after K = 2 with no last row: its
/// fourth row becomes padding and its result is never written (the RAM log's two result writes
/// dropped), so the result cell keeps whatever it held. Only `IS_FOLD·(1 − F_LAST)·(1 − n(IS_FOLD))
/// = 0` refuses it.
#[test]
fn a_fold_run_stopping_before_its_last_row_is_rejected_by_the_must_continue_rule() {
    let (m, p, mut exec, mut red, lh, first) = zero_row_parts(ZERO_ROW_ARITY);
    clear_fold_row(&mut red, first + 3);
    fold_event(&mut exec).mem.retain(|a| !a.is_write);
    assert!(reduce_forgery_refused(&m, &p, &exec, red, lh), "a fold run that stopped before its last row VERIFIED, never writing its result");
}

/// `ROW_END` is carried along a reduce run (R5's end marker: `IS_LAST ⟺ ADDR_R = ROW_END`). The
/// three-column run of `reduce_run_program` that ends at its second row: row 1 sets `ROW_END` to
/// its own `ADDR_R` (121) and claims `IS_LAST`, writing `(10 − 4)·1 + (20 − 5)·3 = 51` where the
/// honest reduction is 267; row 2 becomes padding, column 2's reads leave the RAM log, and the
/// cpu reads 51 back. The first row keeps the layout's `ROW_END` (122), so the `REDUCE_LAYOUT`
/// lookup balances. Only `n(ROW_END) = ROW_END` along the run refuses it.
///
/// (The other in-run carries: `RES` is pinned by `tests/tables.rs`'s carry rule; `ENTRY` and
/// `CARRY` are not pinned by a forgery — a changed `ENTRY` or `CARRY` mid-run only matters on a
/// carrying last row, whose next entry the cpu's `REDUCE [clk, entry]` dispatch and
/// `check_layout`'s chain rules already fix — see the comment at the carry in `ReduceAir::eval`.)
#[test]
fn a_reduce_run_ending_early_is_rejected_by_the_row_end_carry() {
    use reduce_table::col::*;
    let p = reduce_run_program(false);
    let m = Machine::new(FriProfile::Test);
    let mut exec = execute(&p, &[], 1000).unwrap();
    let honest = build_traces(&p, &exec, Tier(8)).unwrap();
    let (mut red, lh) = (honest.reduce.clone().unwrap(), honest.reduce_log_height);
    let w = WIDTH;
    assert_eq!(red.values[2 * w + IS_LAST], F::ONE, "row 2 is the honest run's last row");
    let r1 = &mut red.values[w..2 * w];
    assert_eq!(r1[ADDR_R], F::from_u64(121));
    r1[IS_LAST] = F::ONE;
    r1[ROW_END] = F::from_u64(121);
    r1[END_INV] = F::ZERO;
    r1[OUT0] = F::from_u64(51);
    r1[OUT1] = F::ZERO;
    r1[WRITES] = F::ONE;
    for c in 0..MULT {
        red.values[2 * w + c] = F::ZERO;
    }
    let r = events_of(&exec, Op::Reduce)[0];
    // The event's log: the key's two reads, alpha's two, three per column, the result's two writes.
    let log = &mut exec.events[r].mem;
    assert_eq!(log.len(), 4 + 9 + 2);
    log.drain(4 + 6..4 + 9);
    assert!(log[4 + 6].is_write && log[4 + 6].addr == 214);
    log[4 + 6].value = F::from_u64(51);
    forge_accumulator_readback(&mut exec, F::from_u64(51));
    assert!(reduce_forgery_refused(&m, &p, &exec, red, lh), "a reduce run that ended at its second row VERIFIED, publishing 51 against an honest 267");
}

// ── Cut F: the pow row kind ──────────────────────────────────────────────────────────────────
// `common::pow_program(bits, 5, 11, g_11, GENERATOR)`: an 11-row run reading cells 405–415 (row K
// reads cell 400 + 5 + 10 − K) and writing cell 464. Every forgery below past the brief's three
// keeps every other constraint and every bus satisfied — the forged run's reads and output are
// carried into the event log (and so into the RAM table, the LOAD of cell 464 and the published
// words) — so exactly one rule refuses it; each was mutation-checked: with that rule deleted from
// `ReduceAir::eval` (or `CpuAir::eval`, for the bus bindings) the forgery VERIFIES.

const POW_OFF: u64 = 5;
const POW_LEN: usize = 11;

fn pow_bits(seed: u64) -> Vec<u64> {
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(seed);
    (0..64).map(|_| rand::RngExt::random::<bool>(&mut rng) as u64).collect()
}

fn pow_g() -> F {
    <F as p3_field::TwoAdicField>::two_adic_generator(POW_LEN)
}

fn pow_setup() -> (Machine, Program, Traces) {
    let p = common::pow_program(&pow_bits(51), POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 10_000).unwrap();
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    (m, p, t)
}

fn pow_first_row(red: &p3_matrix::dense::RowMajorMatrix<F>) -> usize {
    let w = reduce_table::col::WIDTH;
    (0..red.height()).find(|k| red.values[k * w + reduce_table::col::P_FIRST] == F::ONE).unwrap()
}

/// The honest run of `p`, its reduce trace and declared log-height (the honest proof verified).
fn pow_parts(p: &Program) -> (Machine, Execution, p3_matrix::dense::RowMajorMatrix<F>, u8) {
    pow_parts_checked(p, true)
}

fn pow_parts_checked(p: &Program, check: bool) -> (Machine, Execution, p3_matrix::dense::RowMajorMatrix<F>, u8) {
    let exec = execute(p, &[], 10_000).unwrap();
    let t = build_traces(p, &exec, Tier(8)).unwrap();
    let m = Machine::new(FriProfile::Test);
    if check {
        prove_and_verify(&m, p, &t).expect("the honest pow program verifies");
    }
    (m, exec, t.reduce.unwrap(), t.reduce_log_height)
}

/// Recompute the run's product from row `from` on, with each row's own `P_BIT` and `P_G`: every
/// later `P_S`, and the last row's `P_OUT`, which is returned.
fn pow_restep(red: &mut p3_matrix::dense::RowMajorMatrix<F>, first: usize, from: usize) -> F {
    use reduce_table::col::*;
    let w = WIDTH;
    let last = first + POW_LEN - 1;
    let mut out = F::ZERO;
    for row in from..=last {
        let r = &red.values[row * w..(row + 1) * w];
        let step = r[P_S] * (F::ONE + r[P_BIT] * (r[P_G] - F::ONE));
        if row == last {
            red.values[row * w + P_OUT] = step;
            out = step;
        } else {
            red.values[(row + 1) * w + P_S] = step;
        }
    }
    out
}

/// Carry a forged pow output through the event log: the POW row's write of cell 464, the LOAD
/// that reads it back, the four PUBLICs and the published words.
fn pow_set_output(exec: &mut Execution, out: F) {
    let at = exec.events.iter().position(|e| e.instr.op == Op::Pow).unwrap();
    let ev = &mut exec.events[at];
    ev.pow.as_mut().unwrap().out = out;
    ev.mem.iter_mut().find(|a| a.is_write).unwrap().value = out;
    for e in exec.events[at + 1..].iter_mut() {
        match e.instr.op {
            Op::Load => {
                e.d[0] = out;
                e.mem[0].value = out;
            }
            Op::Public => e.a[0] = out,
            _ => {}
        }
    }
    exec.public = vec![out; 4];
}

/// The POW event's read of `addr`.
fn pow_read(exec: &mut Execution, addr: u64) -> &mut MemAccess {
    let e = exec.events.iter_mut().find(|e| e.instr.op == Op::Pow).unwrap();
    e.mem.iter_mut().find(|a| !a.is_write && a.addr == addr).unwrap()
}

fn pow_refused(m: &Machine, p: &Program, exec: &Execution, red: p3_matrix::dense::RowMajorMatrix<F>, lh: u8) -> bool {
    let reg = cpu::register_accesses(&exec.events);
    let ram = cpu::ram_accesses(&exec.events);
    let t = traces_from_parts(p, exec, Tier(8), &reg, &ram, Some((red, lh)));
    rejects(|| prove_and_verify(m, p, &t))
}

#[test]
fn honest_pow_traces_pass() {
    let (m, p, t) = pow_setup();
    prove_and_verify(&m, &p, &t).unwrap();
}

/// A pow row whose bit is 2. The bits are hinted (so the cell's value is free witness), the
/// emulator's `NonBooleanBit` refusal is bypassed by editing the honest run: the hint, its store,
/// the POW's read and everything downstream of the product say 2 consistently, and the honest
/// trace builder then computes the run with that bit. Every bus balances and every other rule
/// holds; only the chip's own booleanity rule on `P_BIT` refuses it — the chip does not rely on
/// the bits having been checked upstream.
#[test]
fn a_pow_row_with_a_non_boolean_bit_is_rejected() {
    let bits = pow_bits(52);
    let mut v = vec![];
    for k in 0..64u64 {
        v.push(i(Op::Hint, 1, 0, 0));
        v.push(i(Op::Store, 1, 0, 400 + k));
    }
    v.extend([Instr { op: Op::Faddi, rd: 2, ra: 0, b: pow_g() }, Instr { op: Op::Faddi, rd: 3, ra: 0, b: F::GENERATOR }, i(Op::Faddi, 4, 0, 400)]);
    v.extend([i(Op::Pow, 2, 4, POW_OFF + 256 * POW_LEN as u64), i(Op::Load, 6, 0, 464)]);
    v.extend([i(Op::Public, 0, 6, 0), i(Op::Public, 0, 6, 0), i(Op::Public, 0, 6, 0), i(Op::Public, 0, 6, 0), i(Op::Halt, 0, 0, 0)]);
    let p = Program { instrs: v, checkpoints: vec![], reduce_layout: vec![] };
    let tape: Vec<F> = bits.iter().map(|&b| F::from_u64(b)).collect();
    let m = Machine::new(FriProfile::Test);
    let mut exec = execute(&p, &tape, 10_000).unwrap();
    prove_and_verify(&m, &p, &build_traces(&p, &exec, Tier(8)).unwrap()).expect("the honest hinted-bits run verifies");
    // Row K = 3 reads cell 400 + 5 + 10 − 3 = 412: the hint and store of bit 12.
    let (j, two) = (12usize, F::TWO);
    exec.events[2 * j].d[0] = two;
    exec.events[2 * j + 1].d[0] = two;
    exec.events[2 * j + 1].mem[0].value = two;
    pow_read(&mut exec, 400 + j as u64).value = two;
    let ev = exec.events.iter().find(|e| e.instr.op == Op::Pow).unwrap();
    let pe = ev.pow.unwrap();
    let (mut g, mut s) = (pe.g, pe.s0);
    for a in ev.mem.iter().filter(|a| !a.is_write) {
        s *= F::ONE + a.value * (g - F::ONE);
        g = g.square();
    }
    pow_set_output(&mut exec, s);
    let t = build_traces(&p, &exec, Tier(8)).unwrap();
    let w = reduce_table::col::WIDTH;
    let red = t.reduce.as_ref().unwrap();
    assert_eq!(red.values[(pow_first_row(red) + 3) * w + reduce_table::col::P_BIT], two);
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a pow run reading the bit 2 VERIFIED");
}

/// A ladder that skips a square: `P_G` on row 1 is `G` again (row 0's), and every later row
/// squares on from there, so only the first transition's `n(P_G) = P_G²` breaks. The product and
/// the output are recomputed with that ladder and carried into the event log.
#[test]
fn a_pow_run_whose_ladder_skips_a_square_is_rejected() {
    use reduce_table::col::*;
    let p = common::pow_program(&pow_bits(53), POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    let mut g = pow_g();
    for k in 1..POW_LEN {
        red.values[(first + k) * w + P_G] = g;
        g = g.square();
    }
    let out = pow_restep(&mut red, first, first);
    pow_set_output(&mut exec, out);
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow ladder that skipped a square VERIFIED");
}

/// The brief's cut-short run: the last row turned into padding (its `MULT`/`MULT_C` kept). Not
/// isolated — its read and the output write vanish too; the length rule alone is isolated by
/// `a_pow_run_ending_before_its_length_is_rejected_by_the_length_rule`.
#[test]
fn a_pow_run_cut_short_is_rejected() {
    let (m, p, mut t) = pow_setup();
    let w = reduce_table::col::WIDTH;
    let last = pow_first_row(t.reduce.as_ref().unwrap()) + POW_LEN - 1;
    let r = t.reduce.as_mut().unwrap();
    for c in 0..w {
        if c != reduce_table::col::MULT && c != reduce_table::col::MULT_C {
            r.values[last * w + c] = F::ZERO;
        }
    }
    assert!(rejects(|| prove_and_verify(&m, &p, &t)));
}

/// The length rule: a run that ends one row early (`P_LAST` at `K = L − 2`) while its `P_L`, and
/// so the dispatched immediate, still say `L`. The dropped row's bit (cell 405) is 0, so the
/// product is the honest one; its read leaves the event log. Only `P_LAST ⇒ K = L − 1` refuses it.
#[test]
fn a_pow_run_ending_before_its_length_is_rejected_by_the_length_rule() {
    use reduce_table::col::*;
    let mut bits = pow_bits(54);
    bits[POW_OFF as usize] = 0;
    let p = common::pow_program(&bits, POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    let (end, dropped) = (first + POW_LEN - 2, first + POW_LEN - 1);
    let honest_out = red.values[dropped * w + P_OUT];
    red.values[end * w + P_LAST] = F::ONE;
    let r = &red.values[end * w..(end + 1) * w];
    let step = r[P_S] * (F::ONE + r[P_BIT] * (r[P_G] - F::ONE));
    assert_eq!(step, honest_out, "the dropped row's bit is 0");
    red.values[end * w + P_OUT] = step;
    for c in IS_POW..WIDTH {
        red.values[dropped * w + c] = F::ZERO;
    }
    let e = exec.events.iter_mut().find(|e| e.instr.op == Op::Pow).unwrap();
    e.mem.retain(|a| a.is_write || a.addr != 400 + POW_OFF);
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run of L − 1 rows declaring L VERIFIED");
}

/// The product chain: row 4's `P_S` is not row 3's step (doubled), and every later row steps on
/// from it honestly, so only the transition into row 4 breaks.
#[test]
fn a_pow_run_whose_product_skips_a_step_is_rejected_by_the_product_chain() {
    use reduce_table::col::*;
    let p = common::pow_program(&pow_bits(55), POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    red.values[(first + 4) * w + P_S] *= F::TWO;
    let out = pow_restep(&mut red, first, first + 4);
    pow_set_output(&mut exec, out);
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow product chain broken at row 4 VERIFIED");
}

/// The output rule: the last row writes `P_OUT = step + 1` (and the event log carries it).
#[test]
fn a_pow_output_off_the_last_step_is_rejected_by_the_output_rule() {
    use reduce_table::col::*;
    let p = common::pow_program(&pow_bits(56), POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, last) = (WIDTH, pow_first_row(&red) + POW_LEN - 1);
    red.values[last * w + P_OUT] += F::ONE;
    let out = red.values[last * w + P_OUT];
    pow_set_output(&mut exec, out);
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow output one past its last step VERIFIED");
}

/// The `POW` bus binds `G`. With every bit of the run zero the product is `base` whatever the
/// ladder, so a run on `G' = 3·G` (squared honestly) changes nothing but the provided `G`.
#[test]
fn a_pow_run_on_a_g_the_cpu_never_dispatched_is_rejected_by_the_pow_bus() {
    use reduce_table::col::*;
    let p = common::pow_program(&[0; 64], POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    let mut g = F::from_u64(3) * pow_g();
    for k in 0..POW_LEN {
        red.values[(first + k) * w + P_G] = g;
        g = g.square();
    }
    assert_eq!(pow_restep(&mut red, first, first), F::GENERATOR, "an all-zero run is base");
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run on a G the cpu never dispatched VERIFIED");
}

/// The `POW` bus binds `base`: the run starts from `base + 1`, its product and output follow.
#[test]
fn a_pow_run_from_a_base_the_cpu_never_dispatched_is_rejected_by_the_pow_bus() {
    use reduce_table::col::*;
    let p = common::pow_program(&pow_bits(57), POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    red.values[first * w + P_S] += F::ONE;
    let out = pow_restep(&mut red, first, first);
    pow_set_output(&mut exec, out);
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run from a base the cpu never dispatched VERIFIED");
}

/// The `POW` bus binds `off + 256·L`: an all-zero run moved one cell up (`P_OFF = 6` on every row,
/// cells 406–416, every one a stored zero). The reads and product are honest for the moved run;
/// only the immediate the chip provides (`6 + 256·11`) differs from the one the cpu dispatched.
#[test]
fn a_pow_run_at_an_offset_the_cpu_never_dispatched_is_rejected_by_the_pow_bus() {
    use reduce_table::col::*;
    let p = common::pow_program(&[0; 64], POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    for k in 0..POW_LEN {
        red.values[(first + k) * w + P_OFF] += F::ONE;
    }
    let e = exec.events.iter_mut().find(|e| e.instr.op == Op::Pow).unwrap();
    for a in e.mem.iter_mut().filter(|a| !a.is_write) {
        a.addr += 1;
    }
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run at an offset the cpu never dispatched VERIFIED");
}

/// Row `K` reads the bit at `buf + off + L − 1 − K`. A run that takes its bits low-first
/// (`P_BIT_K = bit_{off+K}`) reads the same eleven cells in the other order, so the RAM table's
/// accesses are the honest ones; only the address the row's read is sent at pairs each value
/// with the wrong cell. (Deleting the `− K` direction — sending `buf + off + K` — makes it verify.
/// The honest run is not pre-verified here, unlike its neighbours: under that mutation the honest
/// trace is the one that fails, and `honest_pow_traces_pass` covers it.)
#[test]
fn a_pow_run_reading_its_bits_low_first_is_rejected_by_the_bit_address() {
    use reduce_table::col::*;
    let bits = pow_bits(58);
    let run = &bits[POW_OFF as usize..POW_OFF as usize + POW_LEN];
    assert!(run.iter().ne(run.iter().rev()), "the run's bits are not a palindrome");
    let p = common::pow_program(&bits, POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts_checked(&p, false);
    let (w, first) = (WIDTH, pow_first_row(&red));
    for k in 0..POW_LEN {
        red.values[(first + k) * w + P_BIT] = F::from_u64(run[k]);
    }
    let out = pow_restep(&mut red, first, first);
    pow_set_output(&mut exec, out);
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run reading its bits low-first VERIFIED");
}

/// `P_BASE` is carried along the run: an all-zero run whose middle rows (K = 1..9) read from
/// `buf + 100` (fresh cells, zero) and whose last row comes back to write cell 464. The reads
/// are moved in the event log too; only the carry rule refuses it.
#[test]
fn a_pow_run_moving_its_buffer_mid_run_is_rejected_by_the_base_carry() {
    use reduce_table::col::*;
    let p = common::pow_program(&[0; 64], POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    for k in 1..POW_LEN - 1 {
        red.values[(first + k) * w + P_BASE] += F::from_u64(100);
        let addr = 400 + POW_OFF + POW_LEN as u64 - 1 - k as u64;
        pow_read(&mut exec, addr).addr += 100;
    }
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run that moved its buffer mid-run VERIFIED");
}

/// One headless pow row written into the row after `src` (a reduce or fold run's last row), as
/// that run's free pow columns carry it: buffer 436, off 0, L 2, K 1 (so `P_LAST`), `G = 1`,
/// `S = 777`, bit 0 read from the fresh cell 436, output 777 written to cell 500 at `src`'s
/// clock. No `P_FIRST`, so no `POW` message and no range lookup; the RAM log is given the read
/// and the write, so every bus balances.
fn forge_headless_pow(red: &mut p3_matrix::dense::RowMajorMatrix<F>, src: usize, ram: &mut Vec<MemAccess>) {
    use reduce_table::col::*;
    let w = WIDTH;
    let clk = red.values[src * w + CLK];
    for (row, k) in [(src, 0u64), (src + 1, 1)] {
        let r = &mut red.values[row * w..(row + 1) * w];
        r[P_BASE] = F::from_u64(436);
        r[P_L] = F::TWO;
        r[P_K] = F::from_u64(k);
        r[P_G] = F::ONE;
        r[P_S] = F::from_u64(777);
    }
    let r = &mut red.values[(src + 1) * w..(src + 2) * w];
    assert_eq!(r[IS_REAL] + r[IS_FOLD] + r[IS_POW], F::ZERO, "the forged row was padding");
    r[IS_POW] = F::ONE;
    r[P_LAST] = F::ONE;
    r[P_OUT] = F::from_u64(777);
    r[CLK] = clk;
    let ts = clk.as_canonical_u64() as u32 * 16;
    ram.push(MemAccess { addr: 436, ts, value: F::ZERO, is_write: false });
    ram.push(MemAccess { addr: 500, ts: ts + 15, value: F::from_u64(777), is_write: true });
}

/// A pow run entered from the last fold row must start (`P_FIRST`): a headless one would write
/// a forged output at the fold's clock. Only the entry rule refuses it.
#[test]
fn a_headless_pow_run_after_the_fold_rows_is_rejected() {
    use reduce_table::col::*;
    let p = zero_row_fold_program();
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 1000).unwrap();
    let honest = build_traces(&p, &exec, Tier(8)).unwrap();
    let (mut red, lh) = (honest.reduce.clone().unwrap(), honest.reduce_log_height);
    let last = fold_first_row(&honest) + 3;
    assert_eq!(red.values[last * WIDTH + F_LAST], F::ONE, "the fold run's last row");
    let reg = cpu::register_accesses(&exec.events);
    let mut ram = cpu::ram_accesses(&exec.events);
    forge_headless_pow(&mut red, last, &mut ram);
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((red, lh)));
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a headless pow run after the last fold row VERIFIED, writing 777 to cell 500");
}

/// The same after the last reduce row.
#[test]
fn a_headless_pow_run_after_the_reduce_rows_is_rejected() {
    use reduce_table::col::*;
    let p = reduce_run_program(false);
    let m = Machine::new(FriProfile::Test);
    let exec = execute(&p, &[], 1000).unwrap();
    let honest = build_traces(&p, &exec, Tier(8)).unwrap();
    let (mut red, lh) = (honest.reduce.clone().unwrap(), honest.reduce_log_height);
    assert_eq!(red.values[2 * WIDTH + IS_LAST], F::ONE, "row 2 is the reduce run's last row");
    let reg = cpu::register_accesses(&exec.events);
    let mut ram = cpu::ram_accesses(&exec.events);
    forge_headless_pow(&mut red, 2, &mut ram);
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((red, lh)));
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a headless pow run after the last reduce row VERIFIED, writing 777 to cell 500");
}

/// Pow rows come after the fold rows: a headless fold row (phase 2, `K = 1 = 2a − 1`, so `F_LAST`)
/// straight after a pow run would write `(777, 0)` to cells 500–501 at the pow's clock with no
/// `FOLD` message — the fold kind's own entry rules cover only the reduce→fold and fold→fold
/// boundaries. The pow run's last row carries it (its free fold columns), the RAM log has the two
/// writes; only `IS_POW·n(IS_FOLD) = 0` refuses it.
#[test]
fn a_headless_fold_row_after_a_pow_run_is_rejected() {
    use reduce_table::col::*;
    let p = common::pow_program(&pow_bits(59), POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, exec, mut red, lh) = pow_parts(&p);
    let (w, last) = (WIDTH, pow_first_row(&red) + POW_LEN - 1);
    let clk = red.values[last * w + CLK];
    let src = &mut red.values[last * w..(last + 1) * w];
    src[F_A] = F::ONE;
    src[F_MSG] = F::from_u64(494);
    src[U0] = F::ONE;
    src[D0] = F::from_u64(777);
    let r = &mut red.values[(last + 1) * w..(last + 2) * w];
    r[IS_FOLD] = F::ONE;
    r[F_LAST] = F::ONE;
    r[F_K] = F::ONE;
    r[F_A] = F::ONE;
    r[F_MSG] = F::from_u64(494);
    r[CLK] = clk;
    r[U0] = F::ONE;
    r[FACC0] = F::from_u64(777);
    r[FOUT0] = F::from_u64(777);
    let reg = cpu::register_accesses(&exec.events);
    let mut ram = cpu::ram_accesses(&exec.events);
    let ts = clk.as_canonical_u64() as u32 * 16;
    ram.push(MemAccess { addr: 500, ts: ts + 14, value: F::from_u64(777), is_write: true });
    ram.push(MemAccess { addr: 501, ts: ts + 15, value: F::ZERO, is_write: true });
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((red, lh)));
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a headless fold row after a pow run VERIFIED, writing 777 to cell 500");
}

/// Pow rows come after the reduce rows: a headless reduce row (`IS_REAL`, `IS_LAST`, no
/// `IS_FIRST`, so no `REDUCE` or layout lookup) after a pow run would write `(777, 0)` to cells
/// 500–501 — `RES` is the carried, unlooked-up column. The pow run's last row carries it (its
/// free reduce columns: `ACC0 = 777`, `APOW = 0`, `RES = 500`, the addresses one step back); its
/// three reads are fresh zero cells (600, 601, 610). Only `IS_POW·n(IS_REAL) = 0` refuses it.
#[test]
fn a_headless_reduce_row_after_a_pow_run_is_rejected() {
    use reduce_table::col::*;
    let p = common::pow_program(&pow_bits(60), POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, exec, mut red, lh) = pow_parts(&p);
    let (w, last) = (WIDTH, pow_first_row(&red) + POW_LEN - 1);
    let clk = red.values[last * w + CLK];
    for (row, av, ar) in [(last, 598u64, 609u64), (last + 1, 600, 610)] {
        let r = &mut red.values[row * w..(row + 1) * w];
        r[ACC0] = F::from_u64(777);
        r[ADDR_V] = F::from_u64(av);
        r[ADDR_R] = F::from_u64(ar);
        r[ROW_END] = F::from_u64(610);
        r[RES] = F::from_u64(500);
    }
    let r = &mut red.values[(last + 1) * w..(last + 2) * w];
    r[IS_REAL] = F::ONE;
    r[IS_LAST] = F::ONE;
    r[CLK] = clk;
    r[WRITES] = F::ONE;
    r[OUT0] = F::from_u64(777);
    let reg = cpu::register_accesses(&exec.events);
    let mut ram = cpu::ram_accesses(&exec.events);
    let ts = clk.as_canonical_u64() as u32 * 16;
    for (addr, slot) in [(600u64, 11u32), (601, 12), (610, 13)] {
        ram.push(MemAccess { addr, ts: ts + slot, value: F::ZERO, is_write: false });
    }
    ram.push(MemAccess { addr: 500, ts: ts + 14, value: F::from_u64(777), is_write: true });
    ram.push(MemAccess { addr: 501, ts: ts + 15, value: F::ZERO, is_write: true });
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((red, lh)));
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a headless reduce row after a pow run VERIFIED, writing 777 to cell 500");
}

// ── Task 5 sweep (Task 4 review): the four pow rules no forgery isolated ─────────────────────
// Each forgery below keeps every other constraint and every bus satisfied and is refused by the
// one rule its name gives; each was mutation-checked in a scratch copy (the rule deleted from
// `ReduceAir::eval`, the test run alone: VERIFIED), recorded in the Task 5 report.

/// `CLK` is carried along a pow run. An all-zero run whose middle rows (K = 1..L − 2) claim the next
/// clock: their bit reads move to `16·(clk + 1) + 0`, which the RAM log carries (no other access
/// touches those cells after the run), and the first row (the `POW` message) and the last (the
/// output write) keep the dispatch clock. Only `n(CLK) = CLK` along the run refuses it.
#[test]
fn a_pow_run_moving_its_clock_mid_run_is_rejected_by_the_clock_carry() {
    use reduce_table::col::*;
    let p = common::pow_program(&[0; 64], POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    for k in 1..POW_LEN - 1 {
        red.values[(first + k) * w + CLK] += F::ONE;
        let addr = 400 + POW_OFF + POW_LEN as u64 - 1 - k as u64;
        pow_read(&mut exec, addr).ts += 16;
    }
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run that moved its clock mid-run VERIFIED");
}

/// `P_OFF` is carried along a pow run: an all-zero run whose middle rows (K = 1..L − 2) read at
/// `off + 20` — cells 426–434, stored zeros no other row reads — while the first row (the range
/// lookup and the `POW` message) and the last (the length rule) keep the dispatched offset. The
/// reads move in the event log; only `n(P_OFF) = P_OFF` refuses it.
#[test]
fn a_pow_run_moving_its_offset_mid_run_is_rejected_by_the_offset_carry() {
    use reduce_table::col::*;
    let p = common::pow_program(&[0; 64], POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    for k in 1..POW_LEN - 1 {
        red.values[(first + k) * w + P_OFF] += F::from_u64(20);
        let addr = 400 + POW_OFF + POW_LEN as u64 - 1 - k as u64;
        pow_read(&mut exec, addr).addr += 20;
    }
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run that moved its offset mid-run VERIFIED");
}

/// `P_L` is carried along a pow run: the same move by the length instead (`L + 20` on the middle
/// rows; the bit address is `buf + off + L − 1 − K`). The last row keeps `L`, so the length rule
/// `P_LAST ⇒ K = L − 1` holds; only `n(P_L) = P_L` refuses it.
#[test]
fn a_pow_run_changing_its_length_mid_run_is_rejected_by_the_length_carry() {
    use reduce_table::col::*;
    let p = common::pow_program(&[0; 64], POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    for k in 1..POW_LEN - 1 {
        red.values[(first + k) * w + P_L] += F::from_u64(20);
        let addr = 400 + POW_OFF + POW_LEN as u64 - 1 - k as u64;
        pow_read(&mut exec, addr).addr += 20;
    }
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run that changed its length mid-run VERIFIED");
}

/// A run starts at `K = 0`: an all-zero run that starts at `K = 1` instead runs `L − 1` rows
/// (K = 1..L − 1), so it never reads row 0's bit (cell 415, the highest) and its ladder starts at
/// the dispatched `G` one row late. Over all-zero bits the product is `base` whatever the ladder,
/// so the output is the honest one; the dropped read leaves the event log and the run's last row
/// becomes padding. The `POW` message, the range lookups, the carries, the steps and the length
/// rule (the last row is `K = L − 1`) all hold; only `P_FIRST·P_K = 0` refuses it.
#[test]
fn a_pow_run_starting_past_k_zero_is_rejected_by_the_first_index_rule() {
    use reduce_table::col::*;
    let p = common::pow_program(&[0; 64], POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, mut exec, mut red, lh) = pow_parts(&p);
    let (w, first) = (WIDTH, pow_first_row(&red));
    let mut g = pow_g();
    for j in 0..POW_LEN - 1 {
        let r = &mut red.values[(first + j) * w..(first + j + 1) * w];
        r[P_K] = F::from_u64(j as u64 + 1);
        r[P_G] = g;
        r[P_LAST] = F::from_bool(j == POW_LEN - 2);
        r[P_OUT] = if j == POW_LEN - 2 { F::GENERATOR } else { F::ZERO };
        g = g.square();
    }
    for c in IS_POW..WIDTH {
        red.values[(first + POW_LEN - 1) * w + c] = F::ZERO;
    }
    red.values[(first + POW_LEN - 1) * w + CLK] = F::ZERO;
    let e = exec.events.iter_mut().find(|e| e.instr.op == Op::Pow).unwrap();
    e.mem.retain(|a| a.is_write || a.addr != 400 + POW_OFF + POW_LEN as u64 - 1);
    assert!(pow_refused(&m, &p, &exec, red, lh), "a pow run starting at K = 1 VERIFIED, never reading its highest bit");
}

/// The table's first row, if it is a pow row, starts a run (the transition rules see no row
/// before it). A program with only a `POW` puts its run at row 0; here a headless one-row run
/// (`P_LAST`, no `P_FIRST`, so no `POW` message: buffer 600, off 0, L 1, `G = 1`, `S = 777`, the
/// bit read from the fresh cell 600) takes row 0 and writes 777 to cell 664 at the honest run's
/// clock; the honest run follows from row 1 (its columns moved down one row; no provider
/// multiplicity is non-zero in a pow-only program, so nothing else moves). The RAM log is given the
/// read and the write. Only the first-row rule `IS_POW ⇒ P_FIRST` refuses it.
#[test]
fn a_headless_pow_row_at_the_tables_first_row_is_rejected() {
    use reduce_table::col::*;
    let p = common::pow_program(&pow_bits(61), POW_OFF, POW_LEN as u64, pow_g(), F::GENERATOR);
    let (m, exec, mut red, lh) = pow_parts(&p);
    let w = WIDTH;
    assert_eq!(pow_first_row(&red), 0, "a pow-only program's run starts at row 0");
    assert!(POW_LEN < red.height() - 1, "room for one more row before the padding");
    assert!((0..red.height()).all(|r| red.values[r * w + MULT] == F::ZERO && red.values[r * w + MULT_C] == F::ZERO));
    let clk = red.values[CLK];
    for row in (1..=POW_LEN).rev() {
        for c in [CLK].into_iter().chain(IS_POW..WIDTH) {
            red.values[row * w + c] = red.values[(row - 1) * w + c];
        }
    }
    let r = &mut red.values[0..w];
    for c in [CLK].into_iter().chain(IS_POW..WIDTH) {
        r[c] = F::ZERO;
    }
    r[IS_POW] = F::ONE;
    r[P_LAST] = F::ONE;
    r[CLK] = clk;
    r[P_BASE] = F::from_u64(600);
    r[P_L] = F::ONE;
    r[P_G] = F::ONE;
    r[P_S] = F::from_u64(777);
    r[P_OUT] = F::from_u64(777);
    let reg = cpu::register_accesses(&exec.events);
    let mut ram = cpu::ram_accesses(&exec.events);
    let ts = clk.as_canonical_u64() as u32 * 16;
    ram.push(MemAccess { addr: 600, ts, value: F::ZERO, is_write: false });
    ram.push(MemAccess { addr: 664, ts: ts + 15, value: F::from_u64(777), is_write: true });
    let t = traces_from_parts(&p, &exec, Tier(8), &reg, &ram, Some((red, lh)));
    assert!(rejects(|| prove_and_verify(&m, &p, &t)), "a headless pow row at the table's first row VERIFIED, writing 777 to cell 664");
}
