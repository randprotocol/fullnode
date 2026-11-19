//! HCS-1 (the 2026-09-27 zkVM review), the rVM's half: a known-answer test on the verifier key.
//!
//! The rVM's key is program-dependent (the program table is preprocessed) and, like the RV32
//! machine's, its preprocessed commitment is salted from a deterministic stream
//! (`machine::key_config`) that every aggregate verifier must agree on, exactly as
//! `research/tests/verifier_key.rs` explains for the RV32 keys. Through constraint set 6 that was
//! `StdRng::seed_from_u64(KEY_SEED)`; since constraint set 7 it is `key_derivation_v2`'s stream
//! under the rVM's own labels, so no `rand` release can move it. What it pins is the sixteen-element Merkle cap itself (the value `InnerKey`/`RvmKey`
//! absorb), in canonical form, for a two-instruction program at tier 8, with and without the reduce
//! chip declared (two caps: `WANT`, `WANT_REDUCE`) — the cap is the part the salt stream decides, and a changed stream, salt draw or
//! preprocessed table changes it. **A red here is a consensus event for any chain with an
//! aggregation section** (none is live): re-pinning it means new aggregate verifier keys.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use randprotocol_rvm::isa::{Instr, Op, Program};
use randprotocol_rvm::machine::{FriProfile, Machine, Tier};

use randprotocol_rvm::isa::F;

fn cap_hex(m: &Machine, p: &Program, reduce: bool) -> Vec<String> {
    let common = m.verifier_key(p, Tier(8), if reduce { 4 } else { 0 });
    let pre = common.preprocessed.as_ref().expect("the program and range tables are preprocessed");
    pre.commitment.roots().iter().flatten().map(|x| format!("{:016x}", x.as_canonical_u64())).collect()
}

/// The cap, in `roots()` order: four digests of four elements.
///
/// Cut D: declaring the reduce chip adds its preprocessed region (an empty layout: all-zero rows),
/// so the cap differs; both caps are pinned.
///
/// Re-pinned for constraint set 7 (HCS-1): the rVM's key config draws its salts from
/// `key_derivation_v2`'s stream under the labels `rvm/key/mmcs` / `rvm/key/pcs`
/// (`machine::KEY_MMCS_LABEL`) instead of `StdRng::seed_from_u64(KEY_SEED)`. The constraint-set-6
/// cap began `730a4ee1a0135cf8, 17b7e54ab9062ce6, …`.
/// Re-pinned for the rate-¼ profile (2026-10-06, docs/07): the preprocessed tables' LDE is half as
/// tall, so the cap moved (was dd11c3f0972cfe5b, c8cc668625c3cda5, …).
/// Re-pinned for constraint set 11: the Grain Poseidon2 table (ZKVM-107) hashes the cap and the
/// key is `KeyVersion::Set(11)` (ZKVM-113: the salt labels carry `/cs11`), so the cap moved (was
/// 4e14ef4f8527212c, 39abffdf6b6fb627, …).
const WANT: [&str; 16] = [
    "df24e9f4603f9e70", "77e55bf08c015042", "c139dfea74403541", "a1906ec8834a43a8",
    "9b179e0007020890", "a1e9260c5d7c8232", "948e615b16a88cdd", "a9e507041a746aff",
    "73a8223b4ef5618e", "2f61173c739959fa", "0cd967c90a58ff10", "523d7447f219b79e",
    "c8cdeb4218e357d7", "e1cced905500dfc1", "a80a27db84c3f55c", "218efa0aadf8b97d",
];

/// The cap with the reduce chip declared at height 2^4 over an empty layout (Cut D), its
/// preprocessed region carrying the 14-row fold coefficient table (Cut E2; was `1136b74d…`).
/// Re-pinned for the rate-¼ profile (2026-10-06, docs/07): the preprocessed tables' LDE is half as
/// tall, so the cap moved (was 1465f60a95152d43, 208336379a094499, …).
/// Re-pinned for constraint set 11 as `WANT` was (was 5205f8d6c2e6ce42, b1c87a5072bd142c, …).
const WANT_REDUCE: [&str; 16] = [
    "9cd7b805a9f92fbc", "6e163a72ab062177", "b1933c114fc2a8ff", "b96df928f9b0c580",
    "cb4125b4ba452c67", "c3f724548faa423f", "88f9d7303e5d6572", "2e83cb8241e472e0",
    "f709400315d2bd70", "7eef1228154d601f", "b65cb39b77b78f46", "1bd463b6d8b3ca83",
    "bfbf31fd7d0ea8ae", "07e56ae959bfbb8a", "16e92edfb1967696", "b87725d06db20281",
];

#[test]
fn the_rvm_verifier_keys_answer_their_known_caps() {
    let p = Program {
        instrs: vec![
            Instr { op: Op::Faddi, rd: 1, ra: 0, b: F::from_u64(7) },
            Instr { op: Op::Halt, rd: 0, ra: 0, b: F::ZERO },
        ],
        checkpoints: vec![],
        reduce_layout: vec![],
    };
    // Both profiles: the profile changes FRI's query count and grinding, never the preprocessed
    // commitment, so one pin serves both (measured, as in `research/tests/verifier_key.rs`).
    for profile in [FriProfile::Test, FriProfile::Production] {
        let m = Machine::new(profile);
        let (plain, reduce) = (cap_hex(&m, &p, false), cap_hex(&m, &p, true));
        eprintln!("{profile:?} no reduce: {plain:?}");
        eprintln!("{profile:?} reduce:    {reduce:?}");
        assert_eq!(plain, WANT, "{profile:?}: the rVM verifier key changed (no reduce chip)");
        assert_eq!(reduce, WANT_REDUCE, "{profile:?}: the rVM verifier key changed (reduce chip declared)");
    }
}
