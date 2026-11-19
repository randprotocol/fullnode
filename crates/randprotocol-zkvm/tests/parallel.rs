//! The `parallel` feature (ZKVM-109): what holds under any thread count, and what does not.
//!
//! The feature turns on Plonky3's rayon. Its contract is **keys and digests unchanged, every proof
//! verifies** — not "the same bytes as the serial build":
//!
//! - *Keys.* `tests/verifier_key.rs` pins each shape's preprocessed commitment and `CommonData` as
//!   SHA-256 constants taken from the serial build, so that file passing under `--features parallel`
//!   is the statement that no key moved. Nothing here repeats it.
//! - *Proofs verify, and the part committed before the quotient reproduces.* The one test that runs
//!   by default, below; it holds serially and on any number of threads.
//! - *Proof bytes do not reproduce on more than one thread*, even with every seed fixed. Two steps
//!   depend on scheduling, both upstream Plonky3 0.7.0 behaviour:
//!   1. the batch prover computes each instance's quotient inside a parallel iterator
//!      (`vendor/p3-batch-stark/src/prover.rs`, `per_instance`) and calls `pcs.get_quotient_ldes`
//!      there, which forks its blinding RNG from the one shared PCS RNG
//!      (`vendor/p3-fri/src/hiding_pcs.rs`, `fork_rng`) — so which instance gets which child seed is
//!      whichever worker reaches the lock first, and the quotient commitment moves;
//!   2. the query proof-of-work search is rayon's `find_map_any`
//!      (`p3-challenger-0.7.0/src/grinding_challenger.rs`, `DuplexChallenger::grind`), which returns
//!      *a* witness, not the smallest — and the witness is absorbed, so the query indices move.
//!   Measured 2026-11-17 with a throwaway patch that ran the instance loop in order and searched the
//!   witness sequentially: ten of ten 16-thread proofs then equalled the serial bytes, and with
//!   either step alone left in they did not. Neither is patched here — no key, digest or test depends
//!   on proof bytes, every real prove draws OS entropy, and the fullnode's prover has always run this
//!   way. The `#[ignore]`d diagnostic at the bottom re-measures it.
use p3_field::PrimeCharacteristicRing;
use randprotocol_zkvm::guests;
use randprotocol_zkvm::machine::{build_traces_salted, seeded_config_for_tests, FriProfile, Machine, Proof, Tier, Val};
use sha2::{Digest, Sha256};

/// `fib(10)` at `tier`, with every source of entropy fixed: the input salt, the LogUp blinds and a
/// config salted from two labels. Verified before it is returned.
fn seeded_proof(tier: Tier) -> Proof {
    let mut m = Machine::new(FriProfile::Test);
    m.config = seeded_config_for_tests(FriProfile::Test, b"tests/parallel/mmcs", b"tests/parallel/pcs");
    let p = guests::fib(10);
    let exec = randprotocol_zkvm::emulator::execute(&p, &[], &[], 1 << 20).unwrap();
    let traces = build_traces_salted(&p, &[], &[], [1, 2, 3, 4], &exec, tier, randprotocol_zkvm::gas::gas_max(tier, 0, 0)).unwrap();
    // Balanced blinds, as `tables::blind::fresh` builds them: instance `i` sends `r_i` and receives
    // `r_{i-1 mod n}`.
    let n = traces.as_slice().len();
    let r: Vec<[Val; 2]> = (0..n as u64).map(|i| [Val::from_u64(1000 + i), Val::from_u64(2000 + i)]).collect();
    let blinds: Vec<_> = (0..n).map(|i| { let q = r[(i + n - 1) % n]; [r[i][0], r[i][1], q[0], q[1]] }).collect();
    let proof = m.prove_traces_with_blinds(&p, &traces, tier, &blinds);
    m.verify(&p.digest(), &proof).expect("a proof made by this build verifies");
    proof
}

fn bytes<T: serde::Serialize>(x: &T) -> Vec<u8> { postcard::to_allocvec(x).expect("serialises") }
fn short(b: &[u8]) -> String { hex::encode(&Sha256::digest(b)[..6]) }

/// True when nothing in this build can reorder work: the feature is off, or rayon has one thread.
fn single_threaded() -> bool {
    !cfg!(feature = "parallel") || std::env::var("RAYON_NUM_THREADS").as_deref() == Ok("1")
}

/// Runs by default, with the feature on or off and on any number of threads: an ordinary proof
/// (OS entropy, as every real prove) verifies, two seeded proofs verify, and what the prover commits
/// *before* the quotient — the main and permutation traces, drawn and committed in instance order —
/// is the same in both. That is the part of a proof rayon must not move: it is the witness.
#[test]
fn a_proof_verifies_and_the_trace_commitments_do_not_depend_on_scheduling() {
    let m = Machine::new(FriProfile::Test);
    let p = guests::fib(10);
    let (proof, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
    m.verify(&p.digest(), &proof).unwrap();

    let (a, b) = (seeded_proof(Tier(10)), seeded_proof(Tier(10)));
    let (ca, cb) = (&a.batch.commitments, &b.batch.commitments);
    assert_eq!(bytes(&ca.main), bytes(&cb.main), "the main-trace commitment of a seeded proof moved between two runs");
    assert_eq!(bytes(&ca.permutation), bytes(&cb.permutation), "the permutation commitment of a seeded proof moved between two runs");
    assert_eq!(a.public_values, b.public_values);
    if single_threaded() {
        assert_eq!(a.to_bytes(), b.to_bytes(), "on one thread a seeded proof is one byte string");
    }
}

/// The diagnostic behind the module comment — a measurement, not an assertion, on more than one
/// thread. `REPS` seeded proofs (default 4) at tier `T` (default 10), each printed as its length, its
/// SHA-256 and a short digest per part. From `research/`:
///
///     cargo test --test parallel -- --ignored --nocapture                       # one digest
///     RAYON_NUM_THREADS=1 cargo test --features parallel --test parallel -- --ignored --nocapture
///                                                                               # the same digest
///     cargo test --features parallel --test parallel -- --ignored --nocapture   # `quotient` and
///                                                                               # `query-pow` move
///
/// The first two print the same SHA-256 on every line (asserted). The third prints a different one
/// per proof: `main`, `permutation` and `random` stay, `quotient` and `query-pow` move, and everything
/// derived from them (`opened`, the FRI openings) moves with them.
#[test]
#[ignore = "diagnostic: prints which parts of a seeded proof move under rayon"]
fn seeded_proofs_reproduce_on_one_thread_and_only_there() {
    let env = |k: &str, d: usize| std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d);
    let (tier, reps) = (Tier(env("T", 10)), env("REPS", 4));
    let mut first: Option<Vec<u8>> = None;
    for _ in 0..reps {
        let proof = seeded_proof(tier);
        let all = proof.to_bytes();
        let c = &proof.batch.commitments;
        let (random_openings, fri) = &proof.batch.opening_proof;
        println!(
            "{} bytes, sha256 {}: main {} permutation {} quotient {} random {} opened {} random-openings {} fri-commits {} query-pow {:?}",
            all.len(), hex::encode(Sha256::digest(&all)), short(&bytes(&c.main)), short(&bytes(&c.permutation)),
            short(&bytes(&c.quotient_chunks)), short(&bytes(&c.random)), short(&bytes(&proof.batch.opened_values)),
            short(&bytes(random_openings)), short(&bytes(&fri.commit_phase_commits)), fri.query_pow_witness,
        );
        match &first {
            None => first = Some(all),
            Some(f) if single_threaded() => assert_eq!(f, &all, "one thread, fixed seeds: the proof must not move"),
            Some(_) => {}
        }
    }
}
