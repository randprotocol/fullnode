//! Fullnode #151 (v0.8.3): `prove_traces` takes the preprocessed `ProverData` from a process-wide
//! cache keyed by the proving shape, instead of rebuilding it (LDE + Merkle tree) for every proof.
//!
//! Its own test binary, so the build counter (`machine::prover_data_builds`) sees no other test's
//! proofs.

use randprotocol_zkvm::guests;
use randprotocol_zkvm::machine::{prover_data_builds, FriProfile, Machine, PROVER_DATA_CACHE_MAX_TIER};

/// Two proofs of one shape — from two different `Machine`s, as the wallet and `rand-prover` make
/// one per proof — build the preprocessed data once, and both proofs verify on a third machine that
/// recomputes the verifier key from scratch (so the cached commitment is the verifier key's: the
/// build is a pure function of the shape).
#[test]
fn proofs_of_one_shape_share_one_preprocessed_build_and_verify() {
    assert!(PROVER_DATA_CACHE_MAX_TIER >= 14, "the bundle guest's tier is cached");
    let p = guests::balance_check(1000);
    let inputs = [400, 250, 300, 75];
    let before = prover_data_builds();
    let (a, _) = Machine::new(FriProfile::Test).prove(&p, &inputs, &[], None).unwrap();
    assert_eq!(prover_data_builds(), before + 1, "the first proof builds");
    let (b, _) = Machine::new(FriProfile::Test).prove(&p, &inputs, &[], None).unwrap();
    assert_eq!(prover_data_builds(), before + 1, "the second proof of the shape is a cache hit");
    assert_ne!(a.to_bytes(), b.to_bytes(), "the proofs' own randomness is still fresh");

    // The cached preprocessed commitment is exactly the one a verifier recomputes: the prover's
    // transcript observes the cached commitment and the verifier's observes the one it rebuilds,
    // so a difference would change every challenge and fail the verify.
    let v = Machine::new(FriProfile::Test);
    v.verify(&p.digest(), &a).unwrap();
    v.verify(&p.digest(), &b).unwrap();

    // Another profile is another shape: its own build.
    let (c, _) = Machine::new(FriProfile::Production).prove(&p, &inputs, &[], None).unwrap();
    assert_eq!(prover_data_builds(), before + 2);
    Machine::new(FriProfile::Production).verify(&p.digest(), &c).unwrap();
}
