//! Plan Task 2b: the precomputed msauth verifier key — the executor's install checks. Node-local
//! (the sync excludes `auth*.rs`). The tests here need no real key blob: each refusal happens
//! before the machine is asked for a key, and none of them builds one.

use randprotocol_zkvm::executor::msauth_vk::{self, key_shape, MsauthKeySource, MsauthVkError, VerifierKeyBlob, VerifierKeyShape};
use randprotocol_zkvm::executor::ZkExecutor;
use randprotocol_zkvm::machine::{FriProfile, Tier, CONSTRAINT_SET, VERIFIER_KEY_BLOB_FORMAT};

fn msauth_shape() -> VerifierKeyShape {
    key_shape(ZkExecutor::msauth_heights())
}

/// A blob with the given header and junk `common` (the vendored blob type, `to_bytes`).
fn synthetic(profile: FriProfile, shape: VerifierKeyShape) -> Vec<u8> {
    VerifierKeyBlob { format_version: VERIFIER_KEY_BLOB_FORMAT, profile, shape, constraint_set: CONSTRAINT_SET, common: vec![7; 64] }.to_bytes()
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
    let bytes = synthetic(FriProfile::Test, msauth_shape());
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
    let bytes = synthetic(FriProfile::Production, msauth_shape());
    let e = ex.install_msauth_vk_with_pin(&bytes, &msauth_vk::digest(&bytes)).unwrap_err();
    assert!(matches!(e, MsauthVkError::Profile { .. }), "{e}");
    assert!(e.to_string().contains("profile"), "{e}");
    assert_nothing_installed(&ex);
}

#[test]
fn a_pinned_blob_for_another_shape_is_refused_by_name() {
    let want = msauth_shape();
    let tweaks: [(&str, VerifierKeyShape); 4] = [
        ("tier", VerifierKeyShape { tier: Tier(want.tier.0 - 2), ..want }),
        ("program", VerifierKeyShape { program_log_height: want.program_log_height + 1, ..want }),
        ("modq", VerifierKeyShape { modq_log_height: want.modq_log_height + 1, ..want }),
        ("public", VerifierKeyShape { public_log_height: want.public_log_height + 1, ..want }),
    ];
    for (what, shape) in tweaks {
        let ex = ZkExecutor::new(FriProfile::Test);
        let bytes = synthetic(FriProfile::Test, shape);
        let e = ex.install_msauth_vk_with_pin(&bytes, &msauth_vk::digest(&bytes)).unwrap_err();
        assert!(matches!(e, MsauthVkError::Shape { .. }), "{what}: {e}");
        assert!(e.to_string().contains("shape"), "{what}: {e}");
        assert_nothing_installed(&ex);
    }
}

/// Past the node's own checks (digest, profile, shape all right), the machine's install refuses
/// junk `common` — nothing installed, nothing built.
#[test]
fn a_pinned_blob_with_the_right_header_and_junk_common_is_refused_by_the_machine() {
    let ex = ZkExecutor::new(FriProfile::Test);
    let bytes = synthetic(FriProfile::Test, msauth_shape());
    let e = ex.install_msauth_vk_with_pin(&bytes, &msauth_vk::digest(&bytes)).unwrap_err();
    assert!(matches!(e, MsauthVkError::Decode(_) | MsauthVkError::Install(_)), "{e}");
    assert_nothing_installed(&ex);
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
        assert!(msauth_vk::pin_bytes(msauth_vk::pin(p)).is_some());
    }
}
