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
const WANT: [&str; 16] = [
    "4e14ef4f8527212c", "39abffdf6b6fb627", "77dba1fca47bd529", "1149f207d69f3d21",
    "38d8bf05f71313f2", "a767f6cb30ed83bf", "a0c290fec3d7016b", "de49af02fb435a3c",
    "b4855501d9b837e2", "212f60829db81b6e", "beb03d2bf7606f5b", "7ed5b38464c415f7",
    "e18a16a44a5ea4f3", "0a4bda1ada5fee5a", "fb907f69091592e4", "2ae406805452fc82",
];

/// The cap with the reduce chip declared at height 2^4 over an empty layout (Cut D), its
/// preprocessed region carrying the 14-row fold coefficient table (Cut E2; was `1136b74d…`).
/// Re-pinned for the rate-¼ profile (2026-10-06, docs/07): the preprocessed tables' LDE is half as
/// tall, so the cap moved (was 1465f60a95152d43, 208336379a094499, …).
const WANT_REDUCE: [&str; 16] = [
    "5205f8d6c2e6ce42", "b1c87a5072bd142c", "f16b2575ed208c23", "b6bfe82e21425b11",
    "a3fd14f45d8ef8ea", "46b95bcb577308b0", "3a5c8e491f325d2a", "ee107e757a6a959c",
    "b9a03d0f0eb5596a", "bfe98de8f84aeb9c", "ff062c9ee5d89d02", "19efa19d86e59a66",
    "d76a5537e800ca08", "805f7624087c6c78", "7ce29bce0c49424c", "ee12a4cbde4d205b",
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
