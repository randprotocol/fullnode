//! CON-601: the chain-22 pinned state-proof verifier keys (`executor::perp_vk`). Node-local (the
//! sync excludes `perp_vk.rs`). The default run checks the committed files against this build's
//! pins without building anything; the ignored test regenerates them on a big host.

use randprotocol_zkvm::executor::perp_vk;
use randprotocol_zkvm::machine::FriProfile;

fn keys_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("keys")
}

fn unhex(s: &str) -> [u8; 32] {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    d
}

#[test]
fn chain22_pins_are_four_canonical_tier18_shapes_none_pending() {
    let pins = perp_vk::chain22_pins(FriProfile::Production);
    let got: Vec<_> = pins
        .iter()
        .map(|(s, _)| (s.tier, s.program_log_height, s.input_log_height, s.public_log_height, s.poseidon2_log_height, s.keccak_log_height, s.sha256_log_height))
        .collect();
    assert_eq!(got, vec![(18, 14, 16, 7, 20, 0, 0), (18, 14, 16, 8, 20, 0, 0), (18, 14, 16, 9, 20, 0, 0), (18, 14, 16, 10, 20, 0, 0)]);
    for (shape, sha) in &pins {
        assert!(sha.len() == 64 && sha.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{shape:?}: {sha}");
        assert_ne!(*sha, perp_vk::PIN_PENDING, "{shape:?} is still pending");
    }
    assert!(perp_vk::chain22_pins(FriProfile::Test).is_empty());
}

/// Every committed key file hashes to its pin and passes the pre-install checks (decode, profile,
/// shape) — no machine, no build.
#[test]
fn the_committed_chain22_files_match_the_pins_and_their_shapes() {
    for (shape, sha) in perp_vk::chain22_pins(FriProfile::Production) {
        let name = perp_vk::file_name(FriProfile::Production, &shape);
        let bytes = std::fs::read(keys_dir().join(&name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(perp_vk::digest(&bytes), sha, "{name}");
        perp_vk::check(&bytes, &unhex(sha), FriProfile::Production, &shape).unwrap_or_else(|e| panic!("{name} {e}"));
        // and one of them is not another's key
        let other = perp_vk::chain22_shapes().into_iter().find(|s| *s != shape).unwrap();
        assert!(perp_vk::check(&bytes, &unhex(sha), FriProfile::Production, &other).unwrap_err().contains("not the pinned shape"));
        assert!(perp_vk::check(&bytes, &unhex(sha), FriProfile::Test, &shape).unwrap_err().contains("profile"));
    }
}

/// The keygen is deterministic: a fresh Production export regenerates each committed file byte for
/// byte. Keygen-scale (four tier-18 key builds, ~21 s and ~1.7 GB each with `parallel`):
/// `cargo +1.98.1 test --release -p randprotocol-zkvm --features parallel --test perp_vk -- --ignored`
#[test]
#[ignore = "builds the four tier-18 Production state-proof keys"]
fn the_chain22_files_regenerate_byte_for_byte() {
    for (shape, sha) in perp_vk::chain22_pins(FriProfile::Production) {
        let name = perp_vk::file_name(FriProfile::Production, &shape);
        let blob = perp_vk::blob(FriProfile::Production, &shape).unwrap();
        assert_eq!(perp_vk::digest(&blob), sha, "{name}");
        assert_eq!(blob, std::fs::read(keys_dir().join(&name)).unwrap(), "{name}");
    }
}
