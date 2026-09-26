//! Audit finding CS6-1 ("EVM and sBPF guests are unpublished binaries"): every file under
//! `guests-compiled/` is a copy of circuits' `guests-compiled/` at one commit, and
//! `guests-compiled/PROVENANCE.md` says which commit and how each file is rebuilt from source.
//! These tests keep the copies equal to that manifest, so a swapped binary fails `cargo test`
//! here and not only CI's byte comparison against circuits.
//!
//! Node-local, not vendored (`deploy/sync-zkvm.sh` excludes it; `--delete` would remove it).

use randprotocol_core::notes::word8_to_hex;
use randprotocol_zkvm::executor::ZkExecutor;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("guests-compiled")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// `SHA256SUMS`'s lines, `(digest, path relative to guests-compiled/)`, in `shasum -a 256` form.
fn manifest() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(dir().join("SHA256SUMS")).expect("guests-compiled/SHA256SUMS");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let (sum, path) = l.split_once("  ").unwrap_or_else(|| panic!("not a `shasum -a 256` line: {l:?}"));
            assert_eq!(sum.len(), 64, "{l:?}");
            (sum.to_string(), path.to_string())
        })
        .collect()
}

/// Every regular file under `guests-compiled/`, relative to it, except the two manifest files.
fn vendored_files() -> BTreeSet<String> {
    fn walk(root: &Path, d: &Path, out: &mut BTreeSet<String>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                out.insert(p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(&dir(), &dir(), &mut out);
    out.remove("SHA256SUMS");
    out.remove("PROVENANCE.md");
    out
}

#[test]
fn every_vendored_guest_and_asset_hashes_to_its_manifest_line() {
    for (want, path) in manifest() {
        let bytes = std::fs::read(dir().join(&path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(sha256_hex(&bytes), want, "guests-compiled/{path} is not the file PROVENANCE.md names");
    }
}

#[test]
fn the_manifest_covers_every_vendored_file_and_nothing_else() {
    let listed: BTreeSet<String> = manifest().into_iter().map(|(_, p)| p).collect();
    assert_eq!(listed, vendored_files(), "guests-compiled/ and SHA256SUMS disagree on which files are vendored");
}

/// circuits writes `bin/<guest>.bin.sha256` beside each image; the copy must name the same digest
/// the manifest does, or the two pins would each vouch for a different file.
#[test]
fn each_circuits_pin_names_the_manifest_digest() {
    let manifest = manifest();
    for guest in ["fib", "keccak256", "evm", "sbpf"] {
        let bin = format!("bin/{guest}.bin");
        let want = &manifest.iter().find(|(_, p)| *p == bin).unwrap_or_else(|| panic!("{bin} not in SHA256SUMS")).0;
        let pin = std::fs::read_to_string(dir().join(format!("{bin}.sha256"))).unwrap();
        assert_eq!(pin, format!("{want}  {guest}.bin\n"), "{bin}.sha256");
    }
}

/// The manifest's circuits commit is the one CI checks the copies and rebuilds against.
#[test]
fn the_manifest_names_the_circuits_commit_ci_pins() {
    let provenance = std::fs::read_to_string(dir().join("PROVENANCE.md")).unwrap();
    let named = provenance
        .lines()
        .find_map(|l| l.strip_prefix("circuits: "))
        .expect("PROVENANCE.md has no `circuits: <commit>` line")
        .trim();
    let ci = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml")).unwrap();
    let pinned = ci
        .lines()
        .find_map(|l| l.trim().strip_prefix("CIRCUITS_PIN: "))
        .expect("ci.yml has no CIRCUITS_PIN")
        .trim();
    assert_eq!(named, pinned, "PROVENANCE.md and ci.yml's CIRCUITS_PIN name different circuits commits");
}

/// The guest the chain runs is not a vendored binary: it is `guests::bundle_hidden()`, assembled
/// from this crate's source. Its `hc` is what chain 14's genesis pins; a source change that moves
/// it has to fail here, not at a node's first block.
#[test]
fn the_chain_14_bundle_guest_is_the_genesis_pin() {
    let genesis = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/genesis-chain14.json")).unwrap();
    let genesis: serde_json::Value = serde_json::from_str(&genesis).unwrap();
    let pin = "83d3a3704a1fcdb9bae7136c0a947ffa34bd53f055388395ed705fe8cacd0ef8";
    assert_eq!(word8_to_hex(&ZkExecutor::hc_bundle()), pin, "guests::bundle_hidden() no longer assembles to chain 14's hc_bundle");
    assert_eq!(genesis["hc_bundle"].as_str().unwrap(), pin, "deploy/genesis-chain14.json's hc_bundle");
}
