//! The width-8 Goldilocks Poseidon2 round constants, as a literal table (audit finding ZKV-2).
//!
//! Every Poseidon2 hash this zkVM computes — the Merkle commitments and the Fiat–Shamir
//! challenger (`machine::permutation`), the in-circuit `poseidon2` chip's preprocessed round
//! constants (`tables::poseidon2::round_constants`), the program/input/public digests
//! (`hash.rs`), and `rand-zkvm-cuda`'s GPU and CPU-twin Merkle engines — reads the numbers
//! below and nothing else. `rand-zkvm-cuda` has no dependency on this crate (the dependency runs
//! the other way), so it compiles this very file into itself with a `#[path]` module
//! (`rand-zkvm-cuda/src/constants.rs`): one table, two crates, no copy. That is why this file
//! names only `p3_*` and `rand` paths, never `crate::`.
//!
//! ## How the numbers were made
//!
//! Before this table existed the permutation was built as
//! `Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(PERM_SEED))`, with
//! `PERM_SEED = 0x5261_6e64_5a4b` ("RandZK"), and the chain's hashes (the genesis hash, every
//! program digest, every commitment) were computed with it. The table is that draw, printed once
//! and committed — the same 86 field elements, so not one hash output changes. The draw, exactly:
//!
//! - `rand 0.10.2`'s `StdRng` (ChaCha12, `chacha20 0.10.2`), seeded by
//!   `rand_core 0.10.1`'s `SeedableRng::seed_from_u64(PERM_SEED)`;
//! - `p3-poseidon2 0.7.0`'s `new_from_rng_128` picks `(rounds_f, rounds_p) = (8, 22)` for
//!   Goldilocks width 8 without touching the RNG, then draws, in this order:
//!   `ExternalLayerConstants::new_from_rng(8, rng)` — the 4 initial rows ([`INITIAL`]), then the
//!   4 terminal rows ([`TERMINAL`]), each row eight `StandardUniform` samples — and then 22
//!   `StandardUniform` scalars for the partial rounds ([`INTERNAL`]);
//! - a Goldilocks `StandardUniform` sample is `p3-goldilocks 0.7.0`'s rejection sampler over
//!   `next_u64` (a draw `>= p` is discarded and redrawn), so every value is already canonical.
//!
//! ## Why a table and not the draw
//!
//! `rand` documents `StdRng` as *not* reproducible across versions: its algorithm may change in
//! any release. A dependency bump could then have silently changed all 86 constants, every hash
//! with them — an unannounced consensus fork — and an auditor could not check the constants
//! without running the RNG. Now the numbers are in the source, and `tests::the_table_is_the_seeded_draw`
//! re-runs the draw only to prove the table equals it on today's `rand`: if a future `rand`
//! changes `StdRng`, that test goes red, not the chain. `tests::the_permutation_answers_its_known_vectors`
//! pins three permutation outputs captured on the pre-table build.
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_poseidon2::ExternalLayerConstants;

/// The seed the table was drawn from ("RandZK"). Nothing derives constants from it any more;
/// it survives as the name `rand-zkvm-cuda`'s engines are keyed on (`constants::permutation`),
/// and in the test below that re-runs the draw.
pub const PERM_SEED: u64 = 0x5261_6e64_5a4b;

/// The 4 initial full rounds' constants (the first half of `ExternalLayerConstants`).
pub const INITIAL: [[u64; 8]; 4] = [
    [0xee75a7f2107126c1, 0xd57d10c167af2323, 0x4229e088ee92d68a, 0xe1614b8522f9edfd, 0xaab92b6d01582b3b, 0x97d27cc9bab4251c, 0x98f51ee076c58f7b, 0x1318292a9d21dc29],
    [0x23ef19745f84736c, 0x433b3bb1130d4f75, 0x3391c4f3e01e4a98, 0x44eb89e1e2bcdf1c, 0x4c4eda2a35accf9d, 0x28e11d56b36e45e5, 0x4da623de96c338b1, 0xba4dbc2bce4c8a0f],
    [0xbc85eed58a9b7745, 0x23e79833d8e14a2d, 0xab21189e14e49139, 0x56f9b94ec3779c7d, 0x299e9a969c442ec7, 0x554b2db9a60a9ed6, 0xd4749224c7f4b4c1, 0x148bbafd9a5eda40],
    [0x0df862d37fcb4bdb, 0xcdbea10868b506bc, 0x467a7199b3f2b56f, 0x3abd55c99c4e8fd6, 0xcc144ce8d7401d8a, 0x08bd5f9b9b27e2a6, 0x567998b7de34f2bf, 0x6a3b9291a5ce797b],
];

/// The 22 partial rounds' constants, one scalar each (added to lane 0 only).
pub const INTERNAL: [u64; 22] = [
    0xb4a835a8cf918c3f, 0xfc8e76ddb453dce0, 0x8c482d91150cbbb3, 0x1647c2a95052a02e,
    0x229410bcacea59aa, 0x95b3a2391389bc0d, 0xd8e94d4c2993e464, 0x7f38bf21c1521128,
    0x1f4d8ea8df153211, 0x6c3108043a789868, 0xb43065f502f235c3, 0xa350c3ac510528cd,
    0x7a9e0efb9a8dec74, 0x49efc1d4bcad501a, 0xaadce63e6421ce48, 0xa7cf9e4ee247eab6,
    0xc13bd889a7b0bb77, 0x3214d332ecc1f5a6, 0x44e9d60696221771, 0xcdc1d0e4a7c2d60c,
    0x23e11c18f32582c0, 0x91f0f07e761248ad,
];

/// The 4 terminal full rounds' constants (the second half of `ExternalLayerConstants`).
pub const TERMINAL: [[u64; 8]; 4] = [
    [0x8d8b439f471d3ed8, 0x6f306da8e7460bd1, 0x232495c2971b558b, 0xf5fac7d16c4bd3e4, 0x2afafe770334cb30, 0xeb207e7e4c8d9fc6, 0x8a96037107bc1178, 0xf1f324d786de2550],
    [0x19187837e670ae50, 0x1960443a687a8d8c, 0xf63d378c5cc93b62, 0x687ae437f5a304ad, 0x69bff4277cf0e371, 0x93fa2bddac4ec4db, 0x0b15e520e37982a6, 0xb3acaa5e2aa2755e],
    [0xdd6f2419a8e88629, 0x7aca3b451c80cfc6, 0x4ef863d6f17d4ea1, 0x7f9fe7304c74e395, 0x1b7a60765cc0afc8, 0x894938b3e73d019c, 0x614d2e03db7f63a7, 0xd43e0575caaa4b7c],
    [0x2f9df0ebffe678a3, 0x641d03c34d5055d9, 0x87b22e63efbc1bca, 0x1b495476ff8afc22, 0x538eac6fda3a7632, 0xe18814f30a053036, 0x544bd2c06d7d6a60, 0x30ca8f9f4bdaebde],
];

/// [`INITIAL`] and [`TERMINAL`] as the `ExternalLayerConstants` `p3_poseidon2` builds from.
pub fn external() -> ExternalLayerConstants<Goldilocks, 8> {
    ExternalLayerConstants::new(INITIAL.map(Goldilocks::new_array).to_vec(), TERMINAL.map(Goldilocks::new_array).to_vec())
}

/// [`INTERNAL`] as field elements.
pub fn internal() -> [Goldilocks; 22] {
    Goldilocks::new_array(INTERNAL)
}

/// The permutation, built from the table. `Poseidon2Goldilocks` is a different type per target
/// (`p3_goldilocks`'s fused NEON implementation on aarch64, which takes its constants by
/// reference; the generic `Poseidon2` elsewhere, which takes them by value) — the constants and
/// the permutation they define are the same on both.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
pub fn permutation() -> Poseidon2Goldilocks<8> {
    Poseidon2Goldilocks::<8>::new(&external(), &internal())
}

/// See the aarch64 twin above.
#[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
pub fn permutation() -> Poseidon2Goldilocks<8> {
    Poseidon2Goldilocks::<8>::new(external(), internal().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_symmetric::Permutation;
    use rand::distr::StandardUniform;
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    /// The table is exactly the draw it replaced (the module comment's recipe, step by step).
    /// Red here after a `rand` upgrade means `StdRng` changed — the table stays, the chain is
    /// unaffected, and this test's recipe needs the old `rand` pinned to re-prove the equality.
    #[test]
    fn the_table_is_the_seeded_draw() {
        let mut rng = StdRng::seed_from_u64(PERM_SEED);
        let ext = ExternalLayerConstants::<Goldilocks, 8>::new_from_rng(8, &mut rng);
        let internal: Vec<Goldilocks> = (&mut rng).sample_iter(StandardUniform).take(22).collect();
        assert_eq!(ext.get_initial_constants(), &INITIAL.map(Goldilocks::new_array)[..], "initial rows");
        assert_eq!(ext.get_terminal_constants(), &TERMINAL.map(Goldilocks::new_array)[..], "terminal rows");
        assert_eq!(internal, super::internal().to_vec(), "internal scalars");
        // And the whole permutation, as `p3` would have built it from the seed.
        let seeded = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut StdRng::seed_from_u64(PERM_SEED));
        let table = permutation();
        let mut s = StdRng::seed_from_u64(0x2b5f);
        for _ in 0..64 {
            let x: [Goldilocks; 8] = core::array::from_fn(|_| s.sample(StandardUniform));
            assert_eq!(table.permute(x), seeded.permute(x));
        }
    }

    /// Three outputs of the permutation, captured on the build before this table existed (circuits
    /// `573ef2e`, the seeded draw): zero, `0..8`, and every lane at `p - 1`.
    #[test]
    fn the_permutation_answers_its_known_vectors() {
        let vectors: [([u64; 8], [u64; 8]); 3] = [
            (
                [0; 8],
                [0x1e4b2c9eebb442b0, 0x2fbb0154ab9d22da, 0x9c397e8d1b856b3d, 0x3900699f4fe93a6e, 0xcb37891674d3ad6b, 0x9b530f7ac1ef1f56, 0x0510bc15edfecf33, 0xf9caffe23a93cd28],
            ),
            (
                [0, 1, 2, 3, 4, 5, 6, 7],
                [0x682c703ce406cd60, 0x35fe4cacd5147b44, 0xf0b819068ae2838e, 0xde5f0a9ba791a8f4, 0xcf8ee9826729b322, 0x38e89ce1e7fcb535, 0xf58f43c0801e00db, 0x694ec48edbb331fa],
            ),
            (
                [0xffff_ffff_0000_0000; 8],
                [0xdfebf956a8205183, 0xbacca056a5ba1b75, 0xdc24d665e3f9864b, 0x1ad86aab4b3e131a, 0xc68f628d6f8833e6, 0x0b913e0aa0757959, 0x248d88435c62b658, 0x7bc6fc5500a81dbc],
            ),
        ];
        let perm = permutation();
        for (input, want) in vectors {
            assert_eq!(perm.permute(Goldilocks::new_array(input)), Goldilocks::new_array(want), "permute({input:x?})");
        }
    }
}
