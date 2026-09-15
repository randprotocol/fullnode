//! The N-proof witness tape (M5.3): one count word, then each proof's
//! fourteen segments in the single-proof order. `segment_refs` must tile
//! the tape exactly, and an N=1 tape is the single-proof tape with the
//! count word prepended.

mod common;

use p3_field::PrimeCharacteristicRing;
use shrugg_zkvm::machine::{FriProfile, Proof};
use shrugg_rvm::isa::F;
use shrugg_rvm::reference::ReplayError;
use shrugg_rvm::shape::{InnerKey, InnerShape};
use shrugg_rvm::witness::{Segment, TapeError, WitnessTape};

fn shape_and_key(p: &Proof) -> (InnerShape, InnerKey) {
    let shape = InnerShape::of(
        FriProfile::Test,
        p.tier,
        p.program_log_height,
        p.input_log_height,
        p.keccak_log_height,
        p.sha256_log_height,
        p.public_log_height,
        p.mem_log_height,
    );
    let key = InnerKey::of(FriProfile::Test, &shape);
    (shape, key)
}

/// An N=1 tape is exactly `[1]` followed by the single-proof tape, and its
/// refs are the single-proof segment ranges shifted by one word.
#[test]
fn n1_tape_is_single_proof_tape_with_count_prefix() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let single = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let multi = WitnessTape::build_n(
        FriProfile::Test,
        &shape,
        &key,
        std::slice::from_ref(&p.proof),
    )
    .unwrap();

    assert_eq!(multi.words[0], F::from_usize(1), "the tape opens with N");
    assert_eq!(
        &multi.words[1..],
        single.words.as_slice(),
        "an N=1 tape past the count word is the single-proof tape, word for word"
    );

    let refs = multi.segment_refs();
    assert_eq!(refs.len(), 14, "one proof carries fourteen segments");
    for (s, r) in refs.iter().enumerate() {
        assert_eq!(r.proof, 0);
        assert_eq!(r.segment, single.segments[s].0);
        assert_eq!(
            (r.start, r.len),
            (single.segments[s].1 + 1, single.segments[s].2),
            "segment {s} shifts by the count word"
        );
    }
}

/// Three fixtures tile as `[N=3]` plus three region layouts; every proof's
/// header pins that proof's declared heights, and the regions are
/// byte-identical to the individually built single-proof tapes.
#[test]
fn n3_layout_tiles_and_pins_declared_heights() {
    let proofs: Vec<Proof> = common::bundle_proofs(FriProfile::Test, 3)
        .into_iter()
        .map(|p| p.proof)
        .collect();
    let (shape, key) = shape_and_key(&proofs[0]);
    for p in &proofs[1..] {
        assert_eq!(
            shape_and_key(p).0,
            shape,
            "every fixture proof must share one shape"
        );
    }
    let tape = WitnessTape::build_n(FriProfile::Test, &shape, &key, &proofs).unwrap();

    assert_eq!(tape.words[0], F::from_usize(3));
    let refs = tape.segment_refs();
    assert_eq!(refs.len(), 3 * 14);

    // The refs tile the tape exactly, in proof-then-segment order, starting past the count word.
    let mut cursor = 1;
    for (j, p) in proofs.iter().enumerate() {
        let single = WitnessTape::build(FriProfile::Test, &shape, &key, p).unwrap();
        for s in 0..14usize {
            let r = refs[j * 14 + s];
            assert_eq!(r.proof, j);
            assert_eq!(r.segment, single.segments[s].0);
            assert_eq!(
                r.start, cursor,
                "proof {j} segment {s} starts where the last ended"
            );
            assert_eq!(r.len, single.segments[s].2);
            assert_eq!(
                &tape.words[r.start..r.start + r.len],
                &single.words[single.segments[s].1..single.segments[s].1 + single.segments[s].2],
                "proof {j} segment {s} matches its single-proof tape region"
            );
            cursor += r.len;
        }
        // The header pins this proof's declared shape: tier, then the six log-heights in the
        // machine's argument order.
        let header = refs[j * 14];
        assert_eq!(header.segment, Segment::Header);
        assert_eq!(tape.words[header.start], F::from_usize(p.tier.0 as usize));
        let declared = [
            p.program_log_height,
            p.input_log_height,
            p.keccak_log_height,
            p.sha256_log_height,
            p.public_log_height,
            p.mem_log_height,
        ];
        for (k, h) in declared.iter().enumerate() {
            assert_eq!(
                tape.words[header.start + 1 + k],
                F::from_usize(*h as usize),
                "proof {j}'s header pins its declared height {k}"
            );
        }
    }
    assert_eq!(cursor, tape.words.len(), "the refs cover the tape exactly");
}

/// A proof whose declared shape is not the tape's is refused at the shape
/// check, before any region is written.
#[test]
fn wrong_shape_proof_is_refused() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let wrong_shape = InnerShape::of(
        FriProfile::Test,
        p.proof.tier,
        p.proof.program_log_height,
        p.proof.input_log_height + 1,
        p.proof.keccak_log_height,
        p.proof.sha256_log_height,
        p.proof.public_log_height,
        p.proof.mem_log_height,
    );
    let wrong_key = InnerKey::of(FriProfile::Test, &wrong_shape);
    let err = WitnessTape::build_n(
        FriProfile::Test,
        &wrong_shape,
        &wrong_key,
        std::slice::from_ref(&p.proof),
    )
    .expect_err("a proof of another shape must be refused");
    assert_eq!(err, TapeError::Replay(ReplayError::Shape));
}

/// The single-proof `build` path reports its own segments as proof 0, tiling
/// from word 0 (there is no count word).
#[test]
fn single_proof_segment_refs_tile_the_tape() {
    let p = common::bundle_proofs(FriProfile::Test, 1).pop().unwrap();
    let (shape, key) = shape_and_key(&p.proof);
    let tape = WitnessTape::build(FriProfile::Test, &shape, &key, &p.proof).unwrap();
    let refs = tape.segment_refs();
    assert_eq!(refs.len(), 14);
    let mut cursor = 0;
    for r in refs {
        assert_eq!(r.proof, 0);
        assert_eq!(r.start, cursor);
        cursor += r.len;
    }
    assert_eq!(cursor, tape.words.len());
}
