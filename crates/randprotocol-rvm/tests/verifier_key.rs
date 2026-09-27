//! HCS-1 (the 2026-09-27 zkVM review), the rVM's half: a known-answer test on the verifier key.
//!
//! The rVM's key is program-dependent (the program table is preprocessed) and, like the RV32
//! machine's, its preprocessed commitment is salted from `StdRng::seed_from_u64(KEY_SEED)`
//! (`machine::key_config`) — so `rand`'s `StdRng` stream is part of what every aggregate verifier
//! must agree on, exactly as `research/tests/verifier_key.rs` explains for the RV32 keys. `rand`,
//! `rand_core` and `chacha20` are pinned exactly in `Cargo.toml`; this test is the tripwire behind
//! the pin. What it pins is the sixteen-element Merkle cap itself (the value `InnerKey`/`RvmKey`
//! absorb), in canonical form, for a two-instruction program at tier 8, with and without the reduce
//! chip declared (one cap: see `WANT`) — the cap is the part the salt stream decides, and a changed stream, salt draw or
//! preprocessed table changes it. **A red here is a consensus event for any chain with an
//! aggregation section** (none is live): re-pinning it means new aggregate verifier keys.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_rvm::isa::{Instr, Op, Program};
use randprotocol_rvm::machine::{FriProfile, Machine, Tier};

use randprotocol_rvm::isa::F;

fn cap_hex(m: &Machine, p: &Program, reduce: bool) -> Vec<String> {
    let common = m.verifier_key(p, Tier(8), reduce);
    let pre = common.preprocessed.as_ref().expect("the program and range tables are preprocessed");
    pre.commitment.roots().iter().flatten().map(|x| format!("{:016x}", x.as_canonical_u64())).collect()
}

/// The cap, in `roots()` order: four digests of four elements.
///
/// The same cap answers with the reduce chip declared and without it, and that too is measured: the
/// reduce chip has no preprocessed columns, so declaring it changes the batch's lookups and degree
/// bits but not the preprocessed commitment.
const WANT: [&str; 16] = [
    "730a4ee1a0135cf8", "17b7e54ab9062ce6", "d464809da9cba8e9", "74ec546f45bba12d",
    "77d349a3e9d5c9c8", "0d3ea3f49e917e2f", "d79ca6f3e9714609", "f1586cfe86a9a90e",
    "18a5ebe79ec72014", "faa8c9200775ce2c", "a96faac2de788f4d", "f892b2ccf905dc10",
    "2968e37466bd0dc4", "2d27a9217ce75a68", "5fccb466ee6d7ccb", "d6c84f3da5b6e10d",
];

#[test]
fn the_rvm_verifier_keys_answer_their_known_caps() {
    let p = Program {
        instrs: vec![
            Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(7) },
            Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO },
        ],
        checkpoints: vec![],
    };
    // Both profiles: the profile changes FRI's query count and grinding, never the preprocessed
    // commitment, so one pin serves both (measured, as in `research/tests/verifier_key.rs`).
    for profile in [FriProfile::Test, FriProfile::Production] {
        let m = Machine::new(profile);
        let (plain, reduce) = (cap_hex(&m, &p, false), cap_hex(&m, &p, true));
        eprintln!("{profile:?} no reduce: {plain:?}");
        eprintln!("{profile:?} reduce:    {reduce:?}");
        assert_eq!(plain, WANT, "{profile:?}: the rVM verifier key changed (no reduce chip)");
        assert_eq!(reduce, WANT, "{profile:?}: the rVM verifier key changed (reduce chip declared)");
    }
}
