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

/// The vendored circuits crates (`evm-core`, `sbpf-core`), the second directory with the same
/// manifest-and-pin shape as `guests-compiled/` (audit v6 PROC-2, issue #109:
/// `vendor/circuits/PROVENANCE.md`).
fn vendor_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/circuits")
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// `SHA256SUMS`'s lines, `(digest, path relative to guests-compiled/)`, in `shasum -a 256` form.
fn manifest() -> Vec<(String, String)> {
    manifest_in(&dir())
}

/// The same, for any directory that carries a `SHA256SUMS` in that form.
fn manifest_in(root: &Path) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(root.join("SHA256SUMS")).unwrap_or_else(|e| panic!("{}/SHA256SUMS: {e}", root.display()));
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
    vendored_files_in(&dir())
}

/// The same, for any directory with the `SHA256SUMS` + `PROVENANCE.md` pair.
fn vendored_files_in(root: &Path) -> BTreeSet<String> {
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
    walk(root, root, &mut out);
    out.remove("SHA256SUMS");
    out.remove("PROVENANCE.md");
    out
}

/// The `circuits: <commit>` line of a PROVENANCE.md.
fn provenance_commit(root: &Path) -> String {
    let provenance = std::fs::read_to_string(root.join("PROVENANCE.md")).unwrap_or_else(|e| panic!("{}/PROVENANCE.md: {e}", root.display()));
    provenance
        .lines()
        .find_map(|l| l.strip_prefix("circuits: "))
        .unwrap_or_else(|| panic!("{}/PROVENANCE.md has no `circuits: <commit>` line", root.display()))
        .trim()
        .to_string()
}

/// ci.yml's `CIRCUITS_PIN`.
fn ci_pin() -> String {
    let ci = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml")).unwrap();
    ci.lines()
        .find_map(|l| l.trim().strip_prefix("CIRCUITS_PIN: "))
        .expect("ci.yml has no CIRCUITS_PIN")
        .trim()
        .to_string()
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

/// The branch-free hidden guest (`guests::bundle_hidden_v2()`, INT-2 / GV-1) assembles to one
/// fixed digest, pinned here so that a source change moving it fails in this crate rather than
/// at the first block of the chain whose genesis names it. No genesis in the repository names it
/// yet: it takes effect at the cut whose `hc_bundle` is this value. v1's pin (above) is unmoved
/// by its arrival — the two guests share one assembler function and v1's instruction stream is
/// byte-for-byte what it was.
#[test]
fn the_branch_free_bundle_guest_is_pinned() {
    let v2 = "651043e2ff2fef28df2d8edbdbbc387668577af72dcc584ee7d850e093a2839b";
    assert_eq!(word8_to_hex(&ZkExecutor::hc_hidden_bundle_v2()), v2, "guests::bundle_hidden_v2() no longer assembles to its pinned digest");
    assert_eq!(word8_to_hex(&ZkExecutor::hc_hidden_bundle()), "83d3a3704a1fcdb9bae7136c0a947ffa34bd53f055388395ed705fe8cacd0ef8");
    assert_eq!(ZkExecutor::known_hc_bundles().map(|h| word8_to_hex(&h))[..2], ["83d3a3704a1fcdb9bae7136c0a947ffa34bd53f055388395ed705fe8cacd0ef8", v2]);
}

/// Bundle guest v3 (`guests::bundle_hidden_v3()`, delegated proving Phase 2: `nk` and `salt` in,
/// `c = H(AUTH, nk, salt)` in the digest) assembles to one fixed digest, pinned like v2's. No
/// genesis names it yet. v1's and v2's pins (above) are unmoved by its arrival: the three share
/// one assembler function, and v1/v2 keep their RAM layout (`HIDDEN_LAYOUT_V1`) and instruction
/// stream byte for byte.
#[test]
fn the_split_authorisation_bundle_guest_is_pinned() {
    let v3 = "60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce";
    assert_eq!(word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()), v3, "guests::bundle_hidden_v3() no longer assembles to its pinned digest");
    assert_eq!(
        ZkExecutor::known_hc_bundles().map(|h| word8_to_hex(&h)),
        [
            "83d3a3704a1fcdb9bae7136c0a947ffa34bd53f055388395ed705fe8cacd0ef8".to_string(),
            "651043e2ff2fef28df2d8edbdbbc387668577af72dcc584ee7d850e093a2839b".to_string(),
            v3.to_string(),
        ]
    );
}

/// The auth guest (`guests::auth()`, delegated proving Phase 2: `sk` and `salt` in,
/// `c = H(AUTH, nk, salt)` out, the transaction binding as its public segment, proved locally at
/// `AUTH_TIER`) assembles to one fixed digest — the
/// value a genesis carries as `hc_auth` beside a v3 `hc_bundle`. Pinned like the bundle guests, so
/// a source change that moves it fails here rather than at the first block of the chain whose
/// genesis names it. No genesis in the repository names it yet.
#[test]
fn the_auth_guest_is_pinned() {
    let auth = "1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1";
    assert_eq!(word8_to_hex(&ZkExecutor::hc_auth()), auth, "the auth guest no longer assembles to its pinned digest");
    assert!(
        !ZkExecutor::known_hc_bundles().map(|h| word8_to_hex(&h)).contains(&auth.to_string()),
        "the auth guest's digest must not be a bundle guest's"
    );
}

/// ZKG-2: the pin above, for every genesis file the repository carries — chain 15 included, which
/// the chain-14-only test never read. A chain from 14 on pins the hidden-asset guest
/// (`guests::bundle_hidden()`); chains 6–13 pin the retired 2-in-2-out guest, which still
/// assembles from this crate's source (`ZkExecutor::legacy_bundle_program`). A file whose
/// `hc_bundle` is neither is a genesis this build could not have cut. Chains 14 and 15 pin v1
/// exactly; a later file may name v1 or the branch-free v2 (`bundle_hidden_v2()`), and from chain
/// 17 on the split-authorisation v3 (`bundle_hidden_v3()`) — whose file must then name this
/// source's auth guest as `hc_auth` too (and a file naming `hc_auth` must pin v3).
#[test]
fn every_genesis_files_bundle_guest_is_the_one_this_source_assembles() {
    let hidden = word8_to_hex(&ZkExecutor::hc_bundle());
    let branch_free = word8_to_hex(&ZkExecutor::hc_hidden_bundle_v2());
    let legacy = word8_to_hex(&ZkExecutor::hc_legacy_bundle());
    let split = word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3());
    let auth = word8_to_hex(&ZkExecutor::hc_auth());
    let deploy = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
    let mut checked = BTreeSet::new();
    for entry in std::fs::read_dir(&deploy).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        let Some(chain) = name.strip_prefix("genesis-chain").and_then(|r| r.strip_suffix(".json")) else {
            continue;
        };
        let chain: u32 = chain.parse().unwrap_or_else(|_| panic!("{name}: not genesis-chain<N>.json"));
        let genesis: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(deploy.join(&name)).unwrap()).unwrap();
        let Some(pin) = genesis.get("hc_bundle").and_then(|v| v.as_str()) else {
            continue;
        };
        let hc_auth = genesis.get("hc_auth").and_then(|v| v.as_str());
        assert_eq!(hc_auth.is_some(), pin == split, "{name}: hc_auth and bundle guest v3 come as a pair");
        if chain >= 17 && pin == split {
            assert_eq!(hc_auth, Some(auth.as_str()), "{name}'s hc_auth is not auth()'s digest");
            checked.insert(chain);
            continue;
        }
        if chain >= 16 && pin == branch_free {
            checked.insert(chain);
            continue;
        }
        let (want, guest) = if chain >= 14 { (&hidden, "bundle_hidden") } else { (&legacy, "the retired bundle") };
        assert_eq!(pin, want.as_str(), "{name}'s hc_bundle is not {guest}()'s digest");
        checked.insert(chain);
    }
    assert!(checked.contains(&14) && checked.contains(&15), "chains 14 and 15 must be among the files checked: {checked:?}");
    assert!(checked.contains(&17), "chain 17 (the first v3 + hc_auth genesis) must be among the files checked: {checked:?}");
}

// ── vendor/circuits: the two interpreter cores (audit v6 PROC-2, issue #109) ────────────────────
//
// `evm-core` and `sbpf-core` were path dependencies on a sibling `circuits/` checkout, which no
// clone of this repository alone has. They are vendored copies now, with the same manifest and
// pin `guests-compiled/` has, and the same tests hold them to it.

#[test]
fn every_vendored_circuits_crate_file_hashes_to_its_manifest_line() {
    let root = vendor_dir();
    for (want, path) in manifest_in(&root) {
        let bytes = std::fs::read(root.join(&path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        assert_eq!(sha256_hex(&bytes), want, "vendor/circuits/{path} is not the file PROVENANCE.md names");
    }
}

#[test]
fn the_vendored_circuits_manifest_covers_every_file_and_nothing_else() {
    let root = vendor_dir();
    let listed: BTreeSet<String> = manifest_in(&root).into_iter().map(|(_, p)| p).collect();
    assert_eq!(listed, vendored_files_in(&root), "vendor/circuits/ and its SHA256SUMS disagree on which files are vendored");
    for crate_name in ["evm-core", "sbpf-core"] {
        assert!(listed.contains(&format!("{crate_name}/Cargo.toml")), "{crate_name} is not among the vendored crates");
        assert!(!listed.contains(&format!("{crate_name}/Cargo.lock")), "{crate_name}/Cargo.lock must not be vendored: the workspace's lock is the one cargo reads");
    }
}

/// Both vendored directories are copies of ONE circuits commit, the one CI checks them against.
#[test]
fn the_vendored_circuits_crates_name_the_circuits_commit_ci_pins() {
    assert_eq!(provenance_commit(&vendor_dir()), ci_pin(), "vendor/circuits/PROVENANCE.md and ci.yml's CIRCUITS_PIN name different circuits commits");
    assert_eq!(provenance_commit(&vendor_dir()), provenance_commit(&dir()), "vendor/circuits/ and guests-compiled/ were synced from different circuits commits");
}

/// The premise of vendoring them: neither crate has a dependency, so the copies add nothing to the
/// dependency tree beyond themselves (`deploy/sync-zkvm.sh` refuses to vendor one that grew any;
/// this is the same check on what is committed).
#[test]
fn the_vendored_circuits_crates_have_no_dependencies() {
    for crate_name in ["evm-core", "sbpf-core"] {
        let manifest = std::fs::read_to_string(vendor_dir().join(crate_name).join("Cargo.toml")).unwrap();
        let mut in_deps = false;
        for line in manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_deps = line == "[dependencies]" || line.starts_with("[dependencies.") || line == "[dev-dependencies]" || line == "[build-dependencies]";
                assert!(!line.starts_with("[dependencies."), "{crate_name}: {line}");
                continue;
            }
            if in_deps && !line.is_empty() && !line.starts_with('#') {
                panic!("{crate_name}/Cargo.toml declares a dependency: {line}");
            }
        }
        assert!(manifest.contains("[workspace]"), "{crate_name}/Cargo.toml lost its `[workspace]` table; the root Cargo.toml's `exclude` entry counts on it");
    }
}

/// The CUDA backend `rand-zkvm-cuda` is a git dependency of two crates; cargo treats two
/// revisions of one git package as two packages, so both manifests must name one revision, a
/// full commit hash, of the public repository.
#[test]
fn the_cuda_backend_is_one_git_revision_in_both_manifests() {
    let line_in = |crate_dir: &str| {
        let manifest = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../").join(crate_dir).join("Cargo.toml")).unwrap();
        manifest
            .lines()
            .find(|l| l.starts_with("rand-zkvm-cuda = "))
            .unwrap_or_else(|| panic!("{crate_dir}/Cargo.toml has no rand-zkvm-cuda dependency line"))
            .to_string()
    };
    let (zkvm, rvm) = (line_in("randprotocol-zkvm"), line_in("randprotocol-rvm"));
    assert_eq!(zkvm, rvm, "the two manifests name rand-zkvm-cuda differently");
    let rev = zkvm
        .split_once("rev = \"")
        .and_then(|(_, r)| r.split_once('"'))
        .map(|(r, _)| r)
        .unwrap_or_else(|| panic!("no rev in {zkvm}"));
    assert!(rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit()), "rev must be a full commit hash: {rev}");
    assert!(zkvm.contains("git = \"https://github.com/randprotocol/zkp-circuits\""), "{zkvm}");
    assert!(zkvm.contains("optional = true"), "{zkvm}");
    assert!(!zkvm.contains("path ="), "a path dependency outside the repository again: {zkvm}");
}
