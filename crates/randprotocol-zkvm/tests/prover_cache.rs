//! ZKVM-110: the prover's preprocessed data is cached per shape, by bytes.
//!
//! Before it, every prove rebuilt that data — the range, nibble, Poseidon2 round-constant and hash
//! chips' periodic tables, extended and committed — although it is a function of the shape alone.
//! `Machine` now keeps it (`machine::PROVER_KEY_BUDGET`, `Machine::set_prover_key_budget`). What
//! these tests hold it to, through the public API and real proofs:
//!
//! - a repeat prove of a shape does not rebuild, and its proof verifies;
//! - **the cache shares nothing a proof must draw for itself**: two proofs of the *same* program,
//!   inputs and `H_IN` salt made from one cached entry still have different main, permutation,
//!   quotient and randomisation commitments (the cached tree is public data under public salts;
//!   `machine.rs`' `two_builds_of_one_key_are_the_same_bytes` pins that it is deterministic);
//! - the program is not part of the key and need not be: two programs of one shape share an entry
//!   and each proof still verifies under its own program digest only;
//! - shapes never share: proofs of different shapes interleaved, with and without eviction, all
//!   verify, and the budget bounds what is held.
//!
//! The hooks (`prover_key_builds`, `prover_key_bytes`, `has_cached_prover_key`) are `#[doc(hidden)]`
//! test instruments. The cache's own policy is unit-tested in `machine.rs` (`prover_cache_tests`).
use randprotocol_zkvm::guests;
use randprotocol_zkvm::machine::{FriProfile, Machine, Proof, Tier, VerifierKeyShape};

fn bytes<T: serde::Serialize>(x: &T) -> Vec<u8> { postcard::to_allocvec(x).expect("serialises") }
fn shape(p: &Proof) -> VerifierKeyShape { VerifierKeyShape::of_proof(p) }

#[test]
fn a_repeat_prove_reuses_the_preprocessed_data_and_shares_no_blinding() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let salt = [1, 2, 3, 4];
    assert_eq!(m.prover_key_builds(), 0);
    let (a, _) = m.prove_salted(&p, &[], &[], salt, Some(Tier(10))).unwrap();
    assert_eq!(m.prover_key_builds(), 1);
    assert!(m.has_cached_prover_key(shape(&a)));
    let held = m.prover_key_bytes();
    assert!(held > 0);
    let (b, _) = m.prove_salted(&p, &[], &[], salt, Some(Tier(10))).unwrap();
    assert_eq!(m.prover_key_builds(), 1, "the repeat prove took the cached data");
    assert_eq!(m.prover_key_bytes(), held, "and the cache holds the one entry");
    m.verify(&p.digest(), &a).unwrap();
    m.verify(&p.digest(), &b).unwrap();
    // Same program, same inputs, same `H_IN` salt: the two witnesses are the same, so the public
    // values agree — and everything committed under per-proof randomness must still differ.
    assert_eq!(a.public_values, b.public_values);
    let (ca, cb) = (&a.batch.commitments, &b.batch.commitments);
    assert_ne!(bytes(&ca.main), bytes(&cb.main), "main commitment shared between two proofs");
    assert_ne!(bytes(&ca.permutation), bytes(&cb.permutation), "permutation commitment shared");
    assert_ne!(bytes(&ca.quotient_chunks), bytes(&cb.quotient_chunks), "quotient commitment shared");
    assert!(ca.random.is_some(), "a hiding proof commits a randomisation polynomial");
    assert_ne!(bytes(&ca.random), bytes(&cb.random), "randomisation commitment shared");
    assert_ne!(bytes(&a.batch.lookup_terminals), bytes(&b.batch.lookup_terminals), "LogUp terminals shared: the blinds were not fresh");
}

#[test]
fn two_programs_of_one_shape_share_an_entry_and_each_proof_binds_its_own_program() {
    let m = Machine::new(FriProfile::Test);
    let (p, q) = (guests::fib(10), guests::fib(11));
    assert_ne!(p.digest(), q.digest());
    let (a, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
    let (b, _) = m.prove(&q, &[], &[], Some(Tier(10))).unwrap();
    assert_eq!(shape(&a), shape(&b), "the two programs have one shape");
    assert_eq!(m.prover_key_builds(), 1, "so they share one preprocessed entry");
    m.verify(&p.digest(), &a).unwrap();
    m.verify(&q.digest(), &b).unwrap();
    assert!(m.verify(&q.digest(), &a).is_err(), "a proof of `p` verified as `q`");
    assert!(m.verify(&p.digest(), &b).is_err(), "a proof of `q` verified as `p`");
}

#[test]
fn shapes_never_share_with_or_without_eviction() {
    let m = Machine::new(FriProfile::Test);
    let fib = guests::fib(10);
    let msg: Vec<u8> = (0..64u8).collect();
    let keccak = guests::keccak_demo(&msg);
    let sha = guests::sha256_demo();
    let programs = [&fib, &keccak, &sha];
    let prove_all = |m: &Machine| -> Vec<Proof> {
        programs.iter().map(|p| {
            let (proof, _) = m.prove(p, &[], &[], Some(Tier(10))).unwrap();
            m.verify(&p.digest(), &proof).unwrap();
            proof
        }).collect()
    };
    // Everything fits: three shapes, three builds, then three hits.
    let first = prove_all(&m);
    let shapes: Vec<_> = first.iter().map(shape).collect();
    assert!(shapes[0] != shapes[1] && shapes[1] != shapes[2] && shapes[0] != shapes[2], "three distinct shapes");
    assert_eq!(m.prover_key_builds(), 3);
    prove_all(&m);
    assert_eq!(m.prover_key_builds(), 3, "the second round is all hits");
    assert!(shapes.iter().all(|s| m.has_cached_prover_key(*s)));

    // A budget of exactly the plain shape's entry: it is the smallest of the three (the other two
    // commit a hash chip's periodic columns as well), so it is the only one that is ever kept.
    let total = m.prover_key_bytes();
    m.set_prover_key_budget(0);
    assert_eq!(m.prover_key_bytes(), 0);
    m.set_prover_key_budget(total);
    m.prove(&fib, &[], &[], Some(Tier(10))).unwrap();
    let plain = m.prover_key_bytes();
    assert!(plain > 0 && plain < total);
    m.set_prover_key_budget(plain);
    let builds = m.prover_key_builds();
    for round in 0..2 {
        prove_all(&m); // each proof is verified inside
        assert!(m.prover_key_bytes() <= plain, "round {round}: the budget holds");
        assert!(m.has_cached_prover_key(shapes[0]) && !m.has_cached_prover_key(shapes[1]) && !m.has_cached_prover_key(shapes[2]), "round {round}: only the entry that fits is kept");
    }
    assert_eq!(m.prover_key_builds(), builds + 4, "the two over-budget shapes are rebuilt each time, the plain one never");

    // Off: every prove builds, as before the cache, and still verifies.
    m.set_prover_key_budget(0);
    let builds = m.prover_key_builds();
    prove_all(&m);
    assert_eq!(m.prover_key_builds(), builds + 3);
    assert_eq!(m.prover_key_bytes(), 0);
}
