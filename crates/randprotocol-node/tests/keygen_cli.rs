//! `rand-node keygen` as an operator runs it: the built binary, a real `--out` (VK-7, audit v6).

use std::process::Command;

fn keygen(out: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rand-node")).arg("keygen").arg("--out").arg(out).output().expect("rand-node runs")
}

/// A second `keygen` to the same `--out` used to truncate the first key — a validator's, an
/// authority's, a vesting beneficiary's — with nothing said. It now fails, says why, and leaves
/// the file byte for byte as it was.
#[test]
fn a_second_keygen_to_the_same_path_fails_and_leaves_the_first_key_intact() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("node.key.json");
    let first = keygen(&out);
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    let before = std::fs::read(&out).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let second = keygen(&out);
    assert!(!second.status.success(), "a second keygen to the same path succeeded");
    let err = String::from_utf8_lossy(&second.stderr);
    assert!(err.contains("refusing to overwrite"), "{err}");
    assert!(String::from_utf8_lossy(&second.stdout).is_empty(), "no address is printed for a key that was not written");
    assert!(std::fs::read(&out).unwrap() == before, "the first key file changed");
}
