//! The fixture-cache generator: proves the bundle fixtures `$FIXTURE_KS` (comma-separated `k`s)
//! at `$FIXTURE_PROFILE` (`Test` or `Production`) into `$RECURSION_FIXTURES`, skipping any
//! already cached and still verifying. `#[ignore]`d — it is a tool, not a test: the prover is
//! single-threaded per proof, so a cache is generated as several of these in parallel, one
//! disjoint `k` list each, e.g. (the 128 GB box, 13 test + 50 production fixtures):
//!
//! ```text
//! for ks in 0,1,2,3,4,5,6 7,8,9,10,11,12; do
//!   FIXTURE_PROFILE=Test FIXTURE_KS=$ks RECURSION_FIXTURES=/root/recursion-fixtures \
//!     cargo test --release --test fixtures -- --ignored --nocapture &
//! done
//! ```
mod common;

use randprotocol_zkvm::machine::{FriProfile, Machine};

#[test]
#[ignore = "the fixture-cache generator: FIXTURE_PROFILE=Test|Production FIXTURE_KS=0,1,.. -- --ignored"]
fn generate_fixtures() {
    let profile = match std::env::var("FIXTURE_PROFILE").as_deref() {
        Ok("Production") => FriProfile::Production,
        Ok("Test") | Err(_) => FriProfile::Test,
        Ok(other) => panic!("FIXTURE_PROFILE={other}: Test or Production"),
    };
    let ks: Vec<usize> = std::env::var("FIXTURE_KS")
        .expect("FIXTURE_KS=0,1,..")
        .split(',')
        .filter(|k| !k.trim().is_empty())
        .map(|k| k.trim().parse().expect("FIXTURE_KS is a comma-separated list of indices"))
        .collect();
    let m = Machine::new(profile);
    for k in ks {
        let t = std::time::Instant::now();
        common::bundle_proof_at(&m, profile, k);
        eprintln!("{profile:?}-{k}: {:.1} s", t.elapsed().as_secs_f64());
    }
}
