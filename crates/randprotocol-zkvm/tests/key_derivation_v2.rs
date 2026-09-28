//! HCS-1: the stable verifier-key salt derivation, live since constraint set 7
//! (`key_derivation_v2`'s module comment has the why and the wiring). These tests show the three
//! things that make it a fix rather than a second guard: it is deterministic, it is a known answer
//! computed from this repository's own constants (no `rand` generator anywhere in it), and it drops
//! into the hiding MMCS a verifier key is committed through, unchanged.
use p3_field::{Field, PrimeCharacteristicRing};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use rand::{Rng, SeedableRng};
use randprotocol_zkvm::key_derivation_v2::{self as v2, KeyRngV2};
use randprotocol_zkvm::machine::{permutation, Compress, Hash, Val};

fn draw(mut r: KeyRngV2, n: usize) -> Vec<u64> { (0..n).map(|_| r.next_u64()).collect() }

/// The live derivation since constraint set 7 (chain 16): every verifier key is salted from it
/// (`machine::key_config`), and `tests/verifier_key.rs` pins the keys it gives.
#[test]
fn v2_is_the_live_derivation() {
    assert!(v2::ACTIVE);
}

#[test]
fn the_stream_is_deterministic() {
    assert_eq!(draw(KeyRngV2::from_label(b"x"), 64), draw(KeyRngV2::from_label(b"x"), 64));
    let (a, b) = (v2::key_rngs(), v2::key_rngs());
    assert_eq!(draw(a.0, 16), draw(b.0, 16));
    assert_eq!(draw(a.1, 16), draw(b.1, 16));
}

/// Labels, the label/seed marker and the length are all in the preimage: no two of these streams
/// agree. `b"a"` against `b"a\0"` is the HCS-4 case (`POSEIDON2`'s `[a]` against `[a, 0]`), which
/// the length in the capacity lane closes here.
#[test]
fn distinct_inputs_give_distinct_streams() {
    let mut seed = [0u8; 32];
    seed[..5].copy_from_slice(b"label");
    let streams = [
        draw(KeyRngV2::from_label(v2::MMCS_LABEL), 8),
        draw(KeyRngV2::from_label(v2::PCS_LABEL), 8),
        draw(KeyRngV2::from_label(b"a"), 8),
        draw(KeyRngV2::from_label(b"a\0"), 8),
        draw(KeyRngV2::from_label(b""), 8),
        draw(KeyRngV2::from_seed([0; 32]), 8),
        draw(KeyRngV2::from_seed(seed), 8),
    ];
    for i in 0..streams.len() {
        for j in 0..i {
            assert_ne!(streams[i], streams[j], "streams {j} and {i} agree");
        }
    }
}

/// The known answer: the MMCS stream's first eight `u64`s, and the same stream's first 16 bytes
/// through `fill_bytes`. Everything that produced them is in this repository — `DOMAIN`, the
/// label, `poseidon2_constants`' table and the sponge in `key_derivation_v2.rs` — so no dependency
/// update can move them; a red here means that file or the committed Poseidon2 table changed.
#[test]
fn the_mmcs_stream_answers_its_known_values() {
    let got = draw(KeyRngV2::from_label(v2::MMCS_LABEL), 8);
    let hex: Vec<String> = got.iter().map(|x| format!("{x:016x}")).collect();
    assert_eq!(
        hex,
        [
            "0abd7c39ca80b705", "8338764a19583721", "74ba1f7092ddcc3e", "f575a5c3320d071d",
            "250d26a66bfcaf67", "b31fb5a39b4f79cf", "26903d35c61ff9bb", "d17a3f0625ab4fa2",
        ]
    );
    let mut bytes = [0u8; 16];
    KeyRngV2::from_label(v2::MMCS_LABEL).fill_bytes(&mut bytes);
    // The same words, in order, little-endian: `fill_bytes` and `next_u64` read one stream.
    let words: Vec<u8> = got[..2].iter().flat_map(|x| x.to_le_bytes()).collect();
    assert_eq!(bytes.to_vec(), words);
}

/// It is a drop-in for the hiding MMCS's `R`: the type the next cut's `ValMmcs` alias becomes
/// type-checks, commits, and two independently constructed instances salt identically — the
/// property a verifier key needs.
#[test]
fn it_salts_the_hiding_mmcs_reproducibly() {
    type Packing = <Val as Field>::Packing;
    type V2Mmcs = MerkleTreeHidingMmcs<Packing, Packing, Hash, Compress, KeyRngV2, 2, 4, 4>;
    let mmcs = || {
        let perm = permutation();
        V2Mmcs::new(Hash::new(perm.clone()), Compress::new(perm), 2, v2::key_rngs().0)
    };
    let mat = || RowMajorMatrix::new((0..64u64 * 4).map(Val::from_u64).collect(), 4);
    let (a, _) = p3_commit::Mmcs::commit(&mmcs(), vec![mat()]);
    let (b, _) = p3_commit::Mmcs::commit(&mmcs(), vec![mat()]);
    assert_eq!(a, b);
    // And the salts matter: the same matrix under the other label's stream commits differently.
    let perm = permutation();
    let other = V2Mmcs::new(Hash::new(perm.clone()), Compress::new(perm), 2, v2::key_rngs().1);
    let (c, _) = p3_commit::Mmcs::commit(&other, vec![mat()]);
    assert_ne!(a, c);
}

/// Constraint set 7's wiring: one salt type, two sources (`SaltRng`). p3's hiding MMCS and PCS
/// clone themselves through `R::from_rng`, which for `SaltRng` is always the `key_derivation_v2`
/// stream — so whatever p3 clones, a verifier key's salts never pass through `StdRng`, and a
/// proving config's clones are the Poseidon2 sponge keyed by 32 bytes of OS entropy.
#[test]
fn a_salt_rng_reseeds_into_the_v2_stream_whatever_its_source() {
    use rand::SeedableRng;
    let mut fresh = v2::SaltRng::fresh();
    assert!(matches!(v2::SaltRng::from_rng(&mut fresh), v2::SaltRng::Key(_)));
    let mut key = v2::SaltRng::key(v2::MMCS_LABEL);
    assert!(matches!(v2::SaltRng::from_rng(&mut key), v2::SaltRng::Key(_)));
    // And a key-sourced `SaltRng` is exactly the label's `KeyRngV2` stream.
    assert_eq!(draw_salt(v2::SaltRng::key(v2::MMCS_LABEL), 8), draw(KeyRngV2::from_label(v2::MMCS_LABEL), 8));
}

fn draw_salt(mut r: v2::SaltRng, n: usize) -> Vec<u64> { (0..n).map(|_| r.next_u64()).collect() }
