//! COV-2 / INT-6 / ZKH-1: the private-data tables are tall enough for the hiding PCS to hide them.
//!
//! Plonky3 0.7.0's `HidingFriPcs` (`p3-fri/src/hiding_pcs.rs`, `commit`) blinds a height-`h` trace
//! by interleaving exactly `h` random rows into it: every committed column becomes a polynomial of
//! degree `< 2h` whose `2h` coefficients are `h` secret trace values and `h` uniform random ones.
//! A proof then *evaluates* that polynomial at every distinct FRI query point that lands in the
//! table's LDE (up to `num_queries`) and at the two out-of-domain points `ζ`, `ζg` — `k` linear
//! equations in the `2h` unknowns. While `k ≤ h` the `h` random rows absorb every one of them and
//! the trace is perfectly hidden; once `k > h` the verifier learns `k − h` linear relations among
//! the secret values themselves. A reviewer's sweep turned exactly that into a full 128-byte
//! keccak preimage and a 64-of-64 boolean column from real production proofs.
//!
//! So the test is the inequality itself, counted off a real proof: for each table that carries
//! private data (`input`, `keccak`, `sha256`), the distinct rows its main-trace matrix is opened at
//! across all queries, plus the two out-of-domain points, must not exceed `h`, the table's own
//! height (= the number of random rows the PCS interleaved). Proved at the `Production` profile
//! (80 queries), because that is the profile whose query count the chain runs and the one the
//! floor is sized for — at the `Test` profile's 16 queries a 32-row keccak table would pass by
//! accident.
use std::collections::HashSet;

use p3_field::PrimeField64;
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::isa::*;
use randprotocol_zkvm::isa::Program;
use randprotocol_zkvm::machine::{FriProfile, Machine, Proof, Tier};
use randprotocol_zkvm::tables::MIN_PRIVATE_TABLE_LOG_HEIGHT;

const T0: u32 = 5;
const S0: u32 = 8;
const S1: u32 = 9;
const KECCAK_AT: i32 = 0x1000;
const SHA256_AT: i32 = 0x2000;

/// The smallest call that touches every private-data table: four private input words, one keccak
/// permutation over a state that holds them, and one sha256 compression over a block copied out
/// of the permuted state. Every one of the three tables is at its *minimal* honest height without
/// the floor — `input` 8 rows (4 words + padding), `keccak` 32 (one block), `sha256` 64 (one
/// block) — which is the shape the finding is about.
fn private_call() -> Program {
    let mut a = Assembler::new(0);
    a.extend(li(S0, KECCAK_AT));
    for idx in 0..4 {
        a.extend(read_input(idx));
        a.push(sw(S0, REG_A0, 4 * idx as i32));
    }
    a.extend(call_keccak(KECCAK_AT / 4));
    a.extend(li(S1, SHA256_AT));
    for i in 0..randprotocol_zkvm::sha256::BLOCK_WORDS {
        a.push(lw(T0, S0, 4 * i as i32));
        a.push(sw(S1, T0, 4 * i as i32));
    }
    for (i, h) in randprotocol_zkvm::sha256::IV.iter().enumerate() {
        a.extend(li(T0, *h as i32));
        a.push(sw(S1, T0, 4 * (randprotocol_zkvm::sha256::BLOCK_WORDS + i) as i32));
    }
    a.extend(call_sha256(SHA256_AT as u32 / 4));
    for k in 0..8 {
        a.push(lw(T0, S1, 4 * (randprotocol_zkvm::sha256::BLOCK_WORDS + k) as i32));
        a.extend(write_output(k as u32, T0));
    }
    a.extend(halt());
    a.assemble()
}

/// The main-trace round of the batch opening, and the number of *distinct* rows each instance's
/// matrix is opened at in it. `p3-batch-stark` 0.7.0 opens its rounds in the order
/// randomization (round 0, present because the PCS is hiding), main trace (round 1), quotient,
/// preprocessed, permutation (`prover.rs`, "Build the opening rounds"); round 1 carries exactly one
/// matrix per instance, in `machine::chips` order. `opened_values[q][m]` is matrix `m`'s committed
/// row at query `q`'s reduced index — two queries that reduce to the same row open the same values,
/// and a fresh uniform-random interleave makes two *different* rows agreeing on every column an
/// event of probability ~`p^-(w+4)`, so counting distinct value vectors counts distinct rows.
fn distinct_main_rows(proof: &Proof) -> Vec<usize> {
    let rounds = &proof.batch.opening_proof.1.input_openings;
    let main = &rounds[1];
    let instances = proof.batch.degree_bits.len();
    (0..instances)
        .map(|m| {
            let rows: HashSet<Vec<u64>> = main
                .opened_values
                .iter()
                .map(|q| q[m].iter().map(|x| x.as_canonical_u64()).collect())
                .collect();
            rows.len()
        })
        .collect()
}

/// The two out-of-domain points every main-trace column is opened at besides the FRI queries: `ζ`
/// and `ζ·g` (`p3-batch-stark`'s round 1 opens `next_point(ζ)` for every AIR with a next-row
/// column, and each of these three does).
const OOD_POINTS: usize = 2;

#[test]
fn the_floor_covers_the_production_query_count() {
    // The arithmetic behind the constant, pinned so a retune of either side trips here first.
    let h = 1usize << MIN_PRIVATE_TABLE_LOG_HEIGHT;
    assert!(h >= FriProfile::Production.num_queries() + OOD_POINTS, "{h} random rows < 80 queries + 2 OOD points");
    assert!(h >= FriProfile::Test.num_queries() + OOD_POINTS);
    // And the floor is the smallest power of two that does it — one bit taller doubles three
    // tables' prover cost for nothing.
    assert!((h / 2) < FriProfile::Production.num_queries() + OOD_POINTS);
}

#[test]
fn a_small_calls_private_tables_are_opened_at_fewer_points_than_their_random_rows() {
    let m = Machine::new(FriProfile::Production);
    let p = private_call();
    let inputs = [0x1111_1111u32, 0x2222_2222, 0x3333_3333, 0x4444_4444];
    let t0 = std::time::Instant::now();
    let (proof, exec) = m.prove(&p, &inputs, &[], Some(Tier(10))).expect("the call proves at tier 10");
    eprintln!("production proof, tier 10: {} bytes, proved in {:?}", proof.size(), t0.elapsed());
    assert_eq!(exec.events.iter().filter(|e| e.keccak_row.is_some()).count(), 1);
    assert_eq!(exec.events.iter().filter(|e| e.sha256_row.is_some()).count(), 1);
    // The unchanged verifier accepts the floored shape.
    m.verify(&p.digest(), &proof).expect("the unchanged verifier accepts the floored heights");

    let queries = FriProfile::Production.num_queries();
    let rows = distinct_main_rows(&proof);
    // `machine::chips` order: program 0, cpu 1, memory 2, alu 3, range 4, nibble 5, poseidon2 6,
    // input 7, keccak 8, sha256 9, public 10.
    assert_eq!(rows.len(), 11, "a call with both hash tables is an eleven-instance batch");
    let tables = [
        ("input", 7, proof.input_log_height),
        ("keccak", 8, proof.keccak_log_height),
        ("sha256", 9, proof.sha256_log_height),
    ];
    eprintln!(
        "program: log height {}, {} distinct opened rows + {OOD_POINTS} OOD (NOT floored — see docs/03-privacy.md)",
        proof.program_log_height, rows[0]
    );
    // Print every table before asserting any, so a red run shows the whole picture.
    for (name, idx, lh) in tables {
        eprintln!("{name}: log height {lh} ({} random rows), {} distinct opened rows + {OOD_POINTS} OOD", 1usize << lh, rows[idx]);
    }
    for (name, idx, lh) in tables {
        let h = 1usize << lh;
        assert!(lh >= MIN_PRIVATE_TABLE_LOG_HEIGHT, "{name} declared log height {lh} < {MIN_PRIVATE_TABLE_LOG_HEIGHT}");
        assert!(h >= queries + OOD_POINTS, "{name}: {h} random rows cannot absorb {queries} queries + {OOD_POINTS} OOD points");
        assert!(
            rows[idx] + OOD_POINTS <= h,
            "{name}: opened at {} distinct rows + {OOD_POINTS} OOD points > {h} random rows — the verifier learns {} linear relations among the private trace values",
            rows[idx],
            rows[idx] + OOD_POINTS - h,
        );
    }
}

/// The floor applies to a table that exists; it never conjures one. A call with no keccak or
/// sha256 still declares `0` for both (an eight-instance-plus-public batch, `machine::chips`), and
/// its input table is floored even when the call reads no input at all — an empty private tape is
/// still a table whose padding rows the PCS opens.
#[test]
fn the_floor_never_adds_an_absent_hash_table() {
    let m = Machine::new(FriProfile::Test);
    let p = randprotocol_zkvm::guests::balance_check(1000);
    let (proof, _) = m.prove(&p, &[400, 250, 300, 75], &[], Some(Tier(10))).unwrap();
    assert_eq!(proof.keccak_log_height, 0);
    assert_eq!(proof.sha256_log_height, 0);
    assert_eq!(proof.input_log_height, MIN_PRIVATE_TABLE_LOG_HEIGHT);
    m.verify(&p.digest(), &proof).unwrap();
}

/// HCS-3 (the 2026-09-27 zkVM review): with `ProveOptions::pad_absent_hash_tables` a call that
/// never hashes declares the keccak and sha256 tables anyway, all padding, at the floor — and the
/// unchanged verifier accepts it. Its header's hash-table heights are then exactly those of
/// `private_call`, which really runs one permutation and one compression: from the header alone the
/// two are the same kind of call. Off by default (the test above pins that the default prover
/// never adds a table), because it costs proving time and hides nothing unless others do it too.
///
/// Measured on this laptop (tier 10, `balance_check`, `--release`, one run each; this test prints
/// the Test-profile pair as `default` / `padded`): Test 300 708 → 850 026 bytes, ~6.9 → ~7.1 s;
/// Production 1 305 415 → 3 622 604 bytes, 6.3 → 7.2 s (`ProveOptions`' doc comment weighs it).
#[test]
fn padded_hash_tables_verify_and_hide_presence() {
    use randprotocol_zkvm::machine::ProveOptions;
    let m = Machine::new(FriProfile::Test);
    let p = randprotocol_zkvm::guests::balance_check(1000);
    let inputs = [400, 250, 300, 75];
    let t0 = std::time::Instant::now();
    let (plain, _) = m.prove(&p, &inputs, &[], Some(Tier(10))).unwrap();
    let t_plain = t0.elapsed();
    let t0 = std::time::Instant::now();
    let opts = ProveOptions { pad_absent_hash_tables: true, ..Default::default() };
    let (padded, exec) = m.prove_with_options(&p, &inputs, &[], Some(Tier(10)), opts).unwrap();
    let t_padded = t0.elapsed();
    eprintln!("default: {} bytes, {t_plain:?}; padded: {} bytes, {t_padded:?}", plain.size(), padded.size());
    assert_eq!(exec.events.iter().filter(|e| e.keccak_row.is_some() || e.sha256_row.is_some()).count(), 0, "the call never hashes");
    assert_eq!((plain.keccak_log_height, plain.sha256_log_height), (0, 0));
    assert_eq!((padded.keccak_log_height, padded.sha256_log_height), (MIN_PRIVATE_TABLE_LOG_HEIGHT, MIN_PRIVATE_TABLE_LOG_HEIGHT));
    // Nothing else in the header moves: the idle tables add no cycle and no memory access.
    assert_eq!(
        (padded.tier, padded.program_log_height, padded.input_log_height, padded.public_log_height, padded.mem_log_height),
        (plain.tier, plain.program_log_height, plain.input_log_height, plain.public_log_height, plain.mem_log_height)
    );
    assert_eq!(padded.batch.degree_bits.len(), plain.batch.degree_bits.len() + 2);
    m.verify(&p.digest(), &padded).expect("the unchanged verifier accepts all-padding hash tables");
    assert_eq!(padded.public_values, {
        // Same statement: every public value but the salted H_IN (a fresh salt per proof) agrees.
        let mut v = plain.public_values.clone();
        for i in 0..8 {
            v[randprotocol_zkvm::tables::cpu::pv::IN0 + i] = padded.public_values[randprotocol_zkvm::tables::cpu::pv::IN0 + i];
        }
        // Constraint set 8: and the declared gas limit, which by default is the header's own
        // ceiling (`gas::gas_max`) — the padded header declares both hash tables, so its ceiling
        // is higher. It says nothing the header's heights do not already say.
        v[randprotocol_zkvm::tables::cpu::pv::GAS] = randprotocol_zkvm::gas::gas_max(Tier(10), MIN_PRIVATE_TABLE_LOG_HEIGHT, MIN_PRIVATE_TABLE_LOG_HEIGHT);
        v
    });
    // The header a real one-permutation, one-compression call declares — the same two heights.
    let (real, _) = m.prove(&private_call(), &[1, 2, 3, 4], &[], Some(Tier(10))).unwrap();
    assert_eq!((real.keccak_log_height, real.sha256_log_height), (padded.keccak_log_height, padded.sha256_log_height));
    // And the option never changes a table a call already has.
    let (real_padded, _) = m.prove_with_options(&private_call(), &[1, 2, 3, 4], &[], Some(Tier(10)), opts).unwrap();
    assert_eq!((real_padded.keccak_log_height, real_padded.sha256_log_height), (real.keccak_log_height, real.sha256_log_height));
    m.verify(&private_call().digest(), &real_padded).unwrap();
}
