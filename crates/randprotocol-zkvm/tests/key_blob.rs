//! Verifier-key blobs (`Machine::export_verifier_key_with_modq` / `Machine::install_verifier_key`):
//! a key built on one machine, shipped as bytes and installed on another without a build. The
//! fullnode's reason is the tier-18 `msauth` key (~80 s, ~4 GB to build on a 4 GB validator).
//! Everything here is the Test profile at tier 10 with one modq block, except the `#[ignore]`d
//! Production export at the msauth shape.
use randprotocol_zkvm::asm::{ops::*, Assembler};
use randprotocol_zkvm::machine::{
    FriProfile, InstallKeyError, Machine, Proof, Tier, VerifierKeyBlob, VerifierKeyShape, VerifyError, CONSTRAINT_SET,
    VERIFIER_KEY_BLOB_FORMAT,
};
use randprotocol_zkvm::machine::{Config, Val};
use p3_batch_stark::{config::Commitment, CommonData};
use p3_lookup::Lookup;
use sha2::{Digest, Sha256};

/// `common`'s postcard layout, structurally (postcard has no field names): the preprocessed
/// `(commitment, per-instance (matrix_index, width, degree_bits), matrix_to_instance)` and each
/// instance's packed lookups (`Lookups` is serde-transparent over its `Vec<Lookup>`).
type Wire = (Option<(Commitment<Config>, Vec<Option<(u64, u64, u64)>>, Vec<u64>)>, Vec<Vec<Lookup<Val>>>);

/// Field-by-field equality of two `CommonData`s (Plonky3's type has no `PartialEq`).
fn assert_same_key(x: &CommonData<Config>, y: &CommonData<Config>) {
    let (px, py) = (x.preprocessed.as_ref().unwrap(), y.preprocessed.as_ref().unwrap());
    assert_eq!(postcard::to_allocvec(&px.commitment).unwrap(), postcard::to_allocvec(&py.commitment).unwrap(), "commitment");
    assert_eq!(px.instances.len(), py.instances.len());
    for (i, (a, b)) in px.instances.iter().zip(&py.instances).enumerate() {
        let f = |m: &Option<p3_batch_stark::common::PreprocessedInstanceMeta>| m.as_ref().map(|m| (m.matrix_index, m.width, m.degree_bits));
        assert_eq!(f(a), f(b), "instance {i} placement");
    }
    assert_eq!(px.matrix_to_instance, py.matrix_to_instance, "matrix_to_instance");
    assert_eq!(postcard::to_allocvec(&x.lookups).unwrap(), postcard::to_allocvec(&y.lookups).unwrap(), "lookups");
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// A tier-10 proof of a guest making one `NTT0` call: one 1 024-row modq block (the
/// `tests/modq.rs::measure_modq_proof_sizes_at_tier_10` fixture).
fn one_block_proof(m: &Machine) -> ([u32; 8], Proof) {
    let mut a = Assembler::new(0);
    a.extend(call_modq(0x1000, 0));
    a.extend(halt());
    let p = a.assemble();
    let (proof, _) = m.prove(&p, &[], &[], Some(Tier(10))).unwrap();
    assert_eq!(proof.modq_log_height, 10, "one block");
    (p.digest(), proof)
}

fn export_for(m: &Machine, proof: &Proof) -> VerifierKeyBlob {
    let s = VerifierKeyShape::of_proof(proof);
    m.export_verifier_key_with_modq(s.tier, s.program_log_height, s.input_log_height, s.keccak_log_height, s.sha256_log_height, s.modq_log_height, s.public_log_height)
}

#[test]
fn a_blob_round_trips_and_the_installing_machine_builds_nothing() {
    let a = Machine::new(FriProfile::Test);
    let (hc, proof) = one_block_proof(&a);
    a.verify(&hc, &proof).unwrap();
    let blob = export_for(&a, &proof);
    assert_eq!(a.key_builds(), 1, "the export reused the key verify built");
    assert_eq!((blob.format_version, blob.profile, blob.constraint_set), (VERIFIER_KEY_BLOB_FORMAT, FriProfile::Test, CONSTRAINT_SET));
    assert_eq!(blob.shape, VerifierKeyShape::of_proof(&proof));

    // Over the wire: bytes, decoded; trailing bytes refused.
    let bytes = blob.to_bytes();
    let decoded = VerifierKeyBlob::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, blob);
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(matches!(VerifierKeyBlob::from_bytes(&longer), Err(InstallKeyError::Decode(_))));
    println!(
        "KEY-BLOB: profile=Test shape=tier{}/p{}/i{}/k{}/s{}/m{}/pub{} bytes={} sha256={}",
        blob.shape.tier.0, blob.shape.program_log_height, blob.shape.input_log_height, blob.shape.keccak_log_height,
        blob.shape.sha256_log_height, blob.shape.modq_log_height, blob.shape.public_log_height,
        bytes.len(), hex(&Sha256::digest(&bytes)),
    );

    let b = Machine::new(FriProfile::Test);
    b.install_verifier_key(&decoded).unwrap();
    assert_eq!(b.cached_keys(), 1);
    b.verify(&hc, &proof).unwrap();
    b.verify_public(&hc, &[], &proof).unwrap();
    assert_eq!(b.key_builds(), 0, "verify used the installed key");
    // The installed key equals a fresh build's, on a separate machine that really builds it.
    let c = Machine::new(FriProfile::Test);
    let s = VerifierKeyShape::of_proof(&proof);
    let key = |m: &Machine| m.verifier_key_with_modq(s.tier, s.program_log_height, s.input_log_height, s.keccak_log_height, s.sha256_log_height, s.modq_log_height, s.public_log_height);
    assert_same_key(&key(&b), &key(&c));
    assert_eq!(c.key_builds(), 1, "c built its own");
    assert_eq!(b.key_builds(), 0);
    assert_eq!(export_for(&c, &proof), blob);
}

#[test]
fn the_pinned_install_hashes_raw_bytes_before_decoding() {
    let a = Machine::new(FriProfile::Test);
    let blob = a.export_verifier_key_with_modq(Tier(10), 7, 7, 0, 0, 10, 7);
    let bytes = blob.to_bytes();
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(randprotocol_zkvm::sha256::sha256(&bytes), pin, "the crate's sha256 is SHA-256");

    // A wrong pin, and bytes that would not even decode: refused by the hash, not the decoder.
    let b = Machine::new(FriProfile::Test);
    assert!(matches!(b.install_verifier_key_pinned(&bytes, &[0; 32]), Err(InstallKeyError::Pin { got }) if got == pin));
    let garbage = vec![0xff; 64];
    assert!(matches!(b.install_verifier_key_pinned(&garbage, &pin), Err(InstallKeyError::Pin { .. })));
    let mut flipped = bytes.clone();
    flipped[bytes.len() / 2] ^= 1;
    assert!(matches!(b.install_verifier_key_pinned(&flipped, &pin), Err(InstallKeyError::Pin { .. })));
    assert_eq!(b.cached_keys(), 0);

    b.install_verifier_key_pinned(&bytes, &pin).unwrap();
    assert_eq!((b.cached_keys(), b.key_builds()), (1, 0));
}

#[test]
fn a_tampered_lookup_multiplicity_is_refused_on_install() {
    let a = Machine::new(FriProfile::Test);
    let blob = a.export_verifier_key_with_modq(Tier(10), 7, 7, 0, 0, 10, 7);
    let (pre, mut lookups): Wire = postcard::from_bytes(&blob.common).unwrap();
    // Round-trip check of the structural decode itself.
    assert_eq!(postcard::to_allocvec(&(&pre, &lookups)).unwrap(), blob.common);
    let m = &mut lookups[1][0].multiplicities[0];
    *m = -m.clone();
    let mut bad = blob.clone();
    bad.common = postcard::to_allocvec(&(&pre, &lookups)).unwrap();
    let b = Machine::new(FriProfile::Test);
    assert!(matches!(b.install_verifier_key(&bad), Err(InstallKeyError::Structure(e)) if e.contains("lookups")));
    assert_eq!(b.cached_keys(), 0);
    b.install_verifier_key(&blob).unwrap();
}

#[test]
fn a_tampered_commitment_fails_an_honest_proof() {
    let a = Machine::new(FriProfile::Test);
    let (hc, proof) = one_block_proof(&a);
    let blob = export_for(&a, &proof);
    // `common` starts with the `Some` tag of the preprocessed commitment, then the commitment's
    // field elements as varints. Flipping bit 0 of a byte never touches a varint's continuation bit,
    // so the bytes still decode — to a different commitment — unless the value leaves the field.
    let mut reached_verify = 0;
    for at in 1..=16 {
        let mut bad = blob.clone();
        bad.common[at] ^= 1;
        let b = Machine::new(FriProfile::Test);
        match b.install_verifier_key(&bad) {
            Err(InstallKeyError::Decode(_)) => continue,
            Err(e) => panic!("byte {at}: unexpected refusal {e:?}"),
            Ok(()) => {}
        }
        reached_verify += 1;
        assert!(matches!(b.verify(&hc, &proof), Err(VerifyError::Batch(_))), "byte {at}: a tampered key accepted an honest proof");
        assert_eq!(b.key_builds(), 0, "the tampered key was used, not rebuilt");
    }
    assert!(reached_verify >= 8, "non-vacuity: {reached_verify} tampered keys installed");
}

#[test]
fn a_blob_of_another_profile_format_or_constraint_set_is_refused() {
    let a = Machine::new(FriProfile::Test);
    let blob = a.export_verifier_key_with_modq(Tier(10), 7, 7, 0, 0, 10, 7);
    let b = Machine::new(FriProfile::Test);

    let mut x = blob.clone();
    x.profile = FriProfile::Production;
    assert_eq!(b.install_verifier_key(&x), Err(InstallKeyError::Profile { blob: FriProfile::Production, machine: FriProfile::Test }));
    assert!(matches!(Machine::new(FriProfile::Production).install_verifier_key(&blob), Err(InstallKeyError::Profile { .. })));

    let mut x = blob.clone();
    x.format_version += 1;
    assert!(matches!(b.install_verifier_key(&x), Err(InstallKeyError::Format { .. })));

    let mut x = blob.clone();
    x.constraint_set -= 1;
    assert_eq!(b.install_verifier_key(&x), Err(InstallKeyError::ConstraintSet { blob: CONSTRAINT_SET - 1, machine: CONSTRAINT_SET }));

    // A shape `verify` would refuse, and a key whose structure belongs to another shape.
    let mut x = blob.clone();
    x.shape.tier = Tier(99);
    assert_eq!(b.install_verifier_key(&x), Err(InstallKeyError::Shape(VerifyError::Tier)));
    let mut x = blob.clone();
    x.shape.modq_log_height = 0;
    assert!(matches!(b.install_verifier_key(&x), Err(InstallKeyError::Structure(_))));
    let mut x = blob.clone();
    x.common.truncate(x.common.len() - 1);
    assert!(matches!(b.install_verifier_key(&x), Err(InstallKeyError::Decode(_))));

    assert_eq!(b.cached_keys(), 0, "nothing was installed");
    b.install_verifier_key(&blob).unwrap();
    assert_eq!((b.cached_keys(), b.key_builds()), (1, 0));
}

#[test]
fn a_filled_slot_is_never_replaced() {
    let a = Machine::new(FriProfile::Test);
    let blob = a.export_verifier_key_with_modq(Tier(10), 7, 7, 0, 0, 10, 7);
    // A structurally valid key with a different commitment (the first tampered byte that decodes).
    let forged = (1..=16)
        .map(|at| { let mut f = blob.clone(); f.common[at] ^= 1; f })
        .find(|f| Machine::new(FriProfile::Test).install_verifier_key(f).is_ok())
        .expect("some single-bit change decodes");
    assert_ne!(forged.common, blob.common);

    // Over a built key: identical is a no-op, different is refused.
    a.install_verifier_key(&blob).unwrap();
    assert_eq!(a.install_verifier_key(&forged), Err(InstallKeyError::SlotFilled));

    // Over an installed key, the same.
    let b = Machine::new(FriProfile::Test);
    b.install_verifier_key(&blob).unwrap();
    b.install_verifier_key(&blob).unwrap();
    assert_eq!(b.install_verifier_key(&forged), Err(InstallKeyError::SlotFilled));
    assert_eq!(b.export_verifier_key_with_modq(Tier(10), 7, 7, 0, 0, 10, 7), blob, "the slot still holds the original");
    assert_eq!(b.key_builds(), 0);
}

#[test]
fn a_proof_of_another_shape_still_builds_its_own_key() {
    let a = Machine::new(FriProfile::Test);
    let (hc, proof) = one_block_proof(&a);
    // A key for a different shape (one more program row) is installed; the proof's shape misses.
    let s = VerifierKeyShape::of_proof(&proof);
    let blob = a.export_verifier_key_with_modq(s.tier, s.program_log_height + 1, s.input_log_height, s.keccak_log_height, s.sha256_log_height, s.modq_log_height, s.public_log_height);
    let b = Machine::new(FriProfile::Test);
    b.install_verifier_key(&blob).unwrap();
    b.verify(&hc, &proof).unwrap();
    assert_eq!((b.key_builds(), b.cached_keys()), (1, 2), "a normal build for the proof's own shape");
}

/// Measurement, not a gate — **run outside the agent harness** (≈4 GB, ≈80 s):
/// `cargo +1.98.1 test --release --test key_blob -- --ignored --nocapture`. Exports the Production
/// key at the msauth shape (`msauth::PINNED_*`, tier 18), prints its size, build wall and SHA-256,
/// and writes the blob to `target/msauth-tier18-production.vkblob` (hash it with `b3sum` for a
/// blake3 pin).
#[test]
#[ignore]
fn export_the_production_msauth_key() {
    use randprotocol_zkvm::msauth::*;
    let m = Machine::new(FriProfile::Production);
    let t0 = std::time::Instant::now();
    let blob = m.export_verifier_key_with_modq(MSAUTH_TIER, PINNED_PROGRAM_LOG_HEIGHT, PINNED_INPUT_LOG_HEIGHT, PINNED_KECCAK_LOG_HEIGHT, 0, PINNED_MODQ_LOG_HEIGHT, PINNED_PUBLIC_LOG_HEIGHT);
    let wall = t0.elapsed();
    let bytes = blob.to_bytes();
    let out = format!("{}/../target/msauth-tier18-production.vkblob", env!("CARGO_MANIFEST_DIR"));
    let _ = std::fs::write(&out, &bytes);
    println!(
        "KEY-BLOB: profile=Production shape=tier{}/p{}/i{}/k{}/s0/m{}/pub{} (mem {}) bytes={} build_wall={:.1}s sha256={} file={out}",
        MSAUTH_TIER.0, PINNED_PROGRAM_LOG_HEIGHT, PINNED_INPUT_LOG_HEIGHT, PINNED_KECCAK_LOG_HEIGHT, PINNED_MODQ_LOG_HEIGHT,
        PINNED_PUBLIC_LOG_HEIGHT, PINNED_MEM_LOG_HEIGHT, bytes.len(), wall.as_secs_f64(), hex(&Sha256::digest(&bytes)),
    );
    let fresh = Machine::new(FriProfile::Production);
    fresh.install_verifier_key_pinned(&bytes, &Sha256::digest(&bytes).into()).unwrap();
    assert_eq!(fresh.key_builds(), 0);
}
