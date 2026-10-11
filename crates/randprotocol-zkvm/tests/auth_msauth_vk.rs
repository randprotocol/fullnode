//! Plan Task 2b: the precomputed msauth verifier key — the executor's install checks. Node-local
//! (the sync excludes `auth*.rs`). The tests here need no real key blob: each refusal happens
//! before the machine is asked for a key, and none of them builds one.

use randprotocol_zkvm::executor::msauth_vk::{self, BlobProfile, MsauthKeySource, MsauthVkError, VerifierKeyBlob, VerifierKeyHeader};
use randprotocol_zkvm::executor::{MsauthShape, ZkExecutor};
use randprotocol_zkvm::machine::FriProfile;

/// A blob with the right header (Test profile, the pinned msauth shape) and junk `common`.
fn synthetic(profile: BlobProfile, shape: MsauthShape) -> Vec<u8> {
    let b = VerifierKeyBlob {
        header: VerifierKeyHeader { format_version: 1, profile, shape, constraint_set: 9 },
        common: vec![7; 64],
    };
    postcard::to_allocvec(&b).unwrap()
}

fn assert_nothing_installed(ex: &ZkExecutor) {
    assert!(!ex.msauth_key_ready());
    assert_eq!(ex.msauth_key_builds(), 0, "a refused blob never falls back to a build");
    assert_eq!(ex.msauth_machine_key_builds(), 0);
    assert_eq!(ex.msauth_key_source(), MsauthKeySource::Absent);
}

#[test]
fn a_blob_whose_sha256_is_not_the_pin_is_refused_naming_both_digests() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let bytes = synthetic(BlobProfile::Test, ZkExecutor::msauth_heights());
    let got = msauth_vk::digest(&bytes);
    assert_eq!(got.len(), 64);
    // This build's own pin (no file hashes to the placeholder, and no synthetic blob to a real pin).
    let e = ex.install_msauth_vk(&bytes).unwrap_err();
    assert_eq!(e, MsauthVkError::Digest { got: got.clone(), want: msauth_vk::pin(FriProfile::Test).to_string() });
    let text = e.to_string();
    assert!(text.contains(&got) && text.contains(msauth_vk::pin(FriProfile::Test)) && text.contains("sha256"), "{text}");
    assert_nothing_installed(&ex);
}

#[test]
fn the_digest_is_sha256_of_the_raw_bytes() {
    // FIPS 180-2 "abc".
    assert_eq!(msauth_vk::digest(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

#[test]
fn a_pinned_blob_for_another_profile_is_refused_by_name() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let bytes = synthetic(BlobProfile::Production, ZkExecutor::msauth_heights());
    let e = ex.install_msauth_vk_with_pin(&bytes, &msauth_vk::digest(&bytes)).unwrap_err();
    assert!(matches!(e, MsauthVkError::Profile { .. }), "{e}");
    assert!(e.to_string().contains("profile"), "{e}");
    assert_nothing_installed(&ex);
}

#[test]
fn a_pinned_blob_for_another_shape_is_refused_by_name() {
    let want = ZkExecutor::msauth_heights();
    let tweaks: [(&str, MsauthShape); 4] = [
        ("tier", MsauthShape { tier: want.tier - 2, ..want }),
        ("program", MsauthShape { program_log_height: want.program_log_height + 1, ..want }),
        ("modq", MsauthShape { modq_log_height: want.modq_log_height + 1, ..want }),
        ("public", MsauthShape { public_log_height: want.public_log_height + 1, ..want }),
    ];
    for (what, shape) in tweaks {
        let ex = ZkExecutor::new(FriProfile::Test);
        let bytes = synthetic(BlobProfile::Test, shape);
        let e = ex.install_msauth_vk_with_pin(&bytes, &msauth_vk::digest(&bytes)).unwrap_err();
        assert!(matches!(e, MsauthVkError::Shape { .. }), "{what}: {e}");
        assert!(e.to_string().contains("shape"), "{what}: {e}");
        assert_nothing_installed(&ex);
    }
}

#[test]
fn pinned_bytes_that_do_not_decode_are_refused() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let bytes = vec![0xffu8; 3];
    let e = ex.install_msauth_vk_with_pin(&bytes, &msauth_vk::digest(&bytes)).unwrap_err();
    assert!(matches!(e, MsauthVkError::Decode(_)), "{e}");
    assert_nothing_installed(&ex);
}

#[test]
fn both_pins_are_lowercase_sha256_hex() {
    for p in [FriProfile::Test, FriProfile::Production] {
        assert_eq!(msauth_vk::pin(p).len(), 64);
        assert!(msauth_vk::pin(p).bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
