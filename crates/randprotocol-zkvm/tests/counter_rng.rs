//! Fullnode #151 (v0.8.3): the hiding PCS's random columns and the hiding MMCS's Merkle salts are
//! counter-mode ChaCha20 streams (`p3_merkle_tree::counter_rng`), one per (lane, chunk of rows),
//! keyed by a 256-bit secret the configuration's generator draws once per call — generated in
//! parallel instead of serially behind a lock.
//!
//! What this file pins:
//! - the vendored module: chunk `c` is exactly stream `(lane, c)`, in order, so the thread count
//!   cannot change a value; values are reproducible per key and lane and differ across them; no
//!   salt repeats across chunks or lanes; the values spread evenly over the field;
//! - which generators hand out keys: OS entropy and a seed-keyed sponge do, a verifier key's label
//!   stream does not (and is not advanced by being asked), so no verifier key moves;
//! - a whole proof under seeded generators, fixed blinds and a fixed `H_IN` salt is byte-for-byte
//!   reproducible, another seed gives other bytes, and both verify;
//! - a proof from this prover is accepted by the verifier path v0.8.0 nodes run (`ZkExecutor`'s
//!   `non_canonical_proof` / `auth_header` / `verify_auth`, the same code: #151 touches no
//!   verifier function), and its wire encoding round-trips canonically.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_merkle_tree::counter_rng::{self, random_matrix, CounterModeRng, CHUNK_ROWS};
use rand::{RngExt, SeedableRng};
use randprotocol_core::confidential::ConfidentialExecutor;
use randprotocol_zkvm::emulator::execute;
use randprotocol_zkvm::executor::{decode_canonical, prove_auth, ZkExecutor};
use randprotocol_zkvm::key_derivation_v2::{self as v2, KeyRngV2, SaltRng};
use randprotocol_zkvm::machine::{build_traces_salted_with, config_with_rngs, Backend, FriProfile, Machine, ProveOptions, Tier, Val, TIERS};
use randprotocol_zkvm::notes::SpendKey;
use randprotocol_zkvm::tables::blind::Blind;
use randprotocol_zkvm::guests;
use std::collections::BTreeSet;

const KEY: [u8; 32] = [7; 32];

/// The chunking is a fixed function of the height: the parallel fill equals the chunks drawn one
/// after another, each from its own stream.
#[test]
fn the_values_are_the_chunk_streams_in_order() {
    let (h, w) = (3 * CHUNK_ROWS + 17, 5);
    let m = random_matrix::<Val>(h, w, &KEY, 9);
    let mut want = Vec::new();
    for c in 0..h.div_ceil(CHUNK_ROWS) {
        let rows = CHUNK_ROWS.min(h - c * CHUNK_ROWS);
        let mut rng = counter_rng::stream(&KEY, 9, c);
        want.extend((0..rows * w).map(|_| rng.random::<Val>()));
    }
    assert_eq!(m.values, want);
    let mut filled = vec![Val::ZERO; h * w];
    counter_rng::fill(&mut filled, w, &KEY, 9);
    assert_eq!(filled, want, "fill and random_matrix agree");
}

/// Same key, lane and shape: the same values. Another lane or another key: other values.
#[test]
fn it_is_deterministic_per_key_and_lane() {
    let a = random_matrix::<Val>(2 * CHUNK_ROWS, 4, &KEY, 0);
    assert_eq!(a, random_matrix::<Val>(2 * CHUNK_ROWS, 4, &KEY, 0));
    assert_ne!(a, random_matrix::<Val>(2 * CHUNK_ROWS, 4, &KEY, 1));
    assert_ne!(a, random_matrix::<Val>(2 * CHUNK_ROWS, 4, &[8; 32], 0));
}

/// No salt repeats across 64 chunks of two lanes (overlapping streams would repeat whole runs;
/// for independent uniform Goldilocks⁴ salts the chance of any repeat here is below 2^-200).
#[test]
fn no_salt_repeats_across_chunks_or_lanes() {
    let h = 32 * CHUNK_ROWS;
    let mut seen = BTreeSet::new();
    for lane in 0..2 {
        let m = random_matrix::<Val>(h, 4, &KEY, lane);
        for row in m.values.as_chunks::<4>().0 {
            let salt: [u64; 4] = row.map(|x| x.as_canonical_u64());
            assert!(seen.insert(salt), "a salt repeated");
        }
    }
    assert_eq!(seen.len(), 2 * h);
    // And no single element repeats either (2^17 draws from a 2^64 field: a repeat is ~2^-30).
    let all: BTreeSet<u64> = seen.iter().flatten().copied().collect();
    assert_eq!(all.len(), 2 * h * 4);
}

/// Statistical sanity: each of 16 equal buckets of `[0, p)` holds 1/16 of 2^16 samples within five
/// standard deviations, and the top bit is set about half the time.
#[test]
fn the_values_are_spread_over_the_field() {
    let m = random_matrix::<Val>(1 << 14, 4, &KEY, 3);
    let n = m.values.len() as f64;
    let mut buckets = [0usize; 16];
    for x in &m.values {
        buckets[((x.as_canonical_u64() as u128 * 16) / Val::ORDER_U64 as u128) as usize] += 1;
    }
    let (mean, sd) = (n / 16.0, (n * (1.0 / 16.0) * (15.0 / 16.0)).sqrt());
    for b in buckets {
        assert!((b as f64 - mean).abs() < 5.0 * sd, "bucket {b} vs mean {mean}");
    }
    let high = m.values.iter().filter(|x| x.as_canonical_u64() >> 63 == 1).count() as f64;
    assert!((high - n / 2.0).abs() < 5.0 * (n / 4.0).sqrt());
}

/// OS entropy and a seed-keyed sponge hand out fresh keys; a label stream hands out none and is
/// not advanced by the question — so a verifier key's salts are the serial stream, unchanged.
#[test]
fn only_secret_generators_hand_out_counter_mode_keys() {
    let mut fresh = SaltRng::fresh();
    let (a, b) = (fresh.counter_mode_key().unwrap(), fresh.counter_mode_key().unwrap());
    assert_ne!(a, b);
    let mut seeded = SaltRng::from_seed([3; 32]);
    let k = seeded.counter_mode_key().unwrap();
    assert_eq!(Some(k), SaltRng::from_seed([3; 32]).counter_mode_key(), "seeded: reproducible");
    assert_ne!(Some(k), seeded.counter_mode_key());

    let mut label = KeyRngV2::from_label(v2::MMCS_LABEL);
    assert_eq!(label.counter_mode_key(), None);
    let mut untouched = KeyRngV2::from_label(v2::MMCS_LABEL);
    assert_eq!(label.random::<u64>(), untouched.random::<u64>(), "asking does not advance the stream");
    assert_eq!(SaltRng::key(v2::MMCS_LABEL).counter_mode_key(), None);
}

/// Fixed, balanced LogUp blinds (`tables::blind::fresh`'s shape, from constants).
fn fixed_blinds(n: usize) -> Vec<Blind> {
    let r: Vec<[Val; 2]> = (0..n).map(|i| [Val::from_u64(1 + i as u64), Val::from_u64(1000 + i as u64)]).collect();
    (0..n)
        .map(|i| {
            let prev = r[(i + n - 1) % n];
            [r[i][0], r[i][1], prev[0], prev[1]]
        })
        .collect()
}

/// A proof under seeded generators: the main/permutation/quotient random columns, the
/// randomisation polynomial and every Merkle salt are counter-mode streams from those seeds.
fn seeded_proof(seed: u8) -> (Machine, randprotocol_zkvm::isa::Program, randprotocol_zkvm::machine::Proof) {
    let mut m = Machine::new(FriProfile::Test);
    m.config = config_with_rngs(
        FriProfile::Test,
        SaltRng::Fresh(rand::rngs::StdRng::seed_from_u64(u64::from(seed))),
        SaltRng::from_seed([seed; 32]),
    );
    let p = guests::balance_check(1000);
    let inputs = [400, 250, 300, 75];
    let exec = execute(&p, &inputs, &[], Tier(*TIERS.last().unwrap()).max_cycles()).unwrap();
    let tier = Tier(TIERS[0]);
    let traces = build_traces_salted_with(&p, &inputs, &[], [1, 2, 3, 4], &exec, tier, ProveOptions::default()).unwrap();
    let blinds = fixed_blinds(traces.as_slice().len());
    let proof = m.prove_traces_with_blinds(&p, &traces, tier, &blinds);
    (m, p, proof)
}

/// A seeded run stays deterministic: same seeds, same bytes (whatever the thread count — the
/// chunking is fixed); another seed, other bytes; both verify.
#[test]
fn a_seeded_proof_is_reproducible_and_verifies() {
    let (m, p, a) = seeded_proof(1);
    let (_, _, b) = seeded_proof(1);
    let (_, _, c) = seeded_proof(2);
    assert_eq!(a.to_bytes(), b.to_bytes(), "same seeds: the same proof");
    assert_ne!(a.to_bytes(), c.to_bytes(), "another seed: other randomness");
    m.verify(&p.digest(), &a).unwrap();
    m.verify(&p.digest(), &c).unwrap();
}

/// A proof from this prover is accepted by the verifier path every v0.8.0 node runs at admission
/// (the same functions, unchanged by #151): the canonical-proof rule, the auth header's structural
/// checks, and the STARK verify against the binding — and its encoding is canonical.
#[test]
fn a_new_proof_passes_the_unchanged_v080_verifier_path() {
    const BINDING: [u32; 8] = [0x1111_1111, 2, 3, 4, 5, 6, 7, 0xffff_ffff];
    let (proof, c, tier) = prove_auth(FriProfile::Test, &SpendKey([7; 8]), &[9; 8], &BINDING, Backend::Cpu).unwrap();
    assert_eq!(tier, 10);
    assert_eq!(decode_canonical(&proof).unwrap().to_bytes(), proof, "wire format: canonical round trip");
    let ex = ZkExecutor::new(FriProfile::Test);
    assert_eq!(ex.non_canonical_proof(&proof), None);
    let (_shape, published, _gas) = ex.auth_header(&proof).unwrap();
    assert_eq!(published, c);
    assert_eq!(ex.verify_auth(&ZkExecutor::hc_auth(), &proof, &BINDING), Ok(c));
    let mut other = BINDING;
    other[0] ^= 1;
    assert!(ex.verify_auth(&ZkExecutor::hc_auth(), &proof, &other).is_err(), "and still bound to its binding");
}
