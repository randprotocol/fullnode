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
    for guest in ["fib", "keccak256", "evm", "sbpf", "dilithium-verify", "msauth"] {
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

// ── The guests' digests: constraint set 11 moved every one ───────────────────────────────────────
//
// A guest's `hc` is a Poseidon2 digest of its program, and constraint set 11 (circuits 76a48dc)
// replaced the Poseidon2 round constants (Grain), so every guest this source assembles has a new
// `hc` while its instruction stream is byte for byte what it was. The genesis files of chains
// 14–21 (cut under sets 6–9) keep naming the old digests — those chains are run by the set-9
// release line (v0.8.6), which this build refuses (`constraint_set::build_genesis`) — and a cut
// from chain 22 on names these. Both columns are pinned: a source change that moves a current
// digest fails here, and so does an edit to a committed genesis file.

/// Through constraint set 10: the digests chains 14–21's genesis files name.
const SET_10_HC_BUNDLE_V1: &str = "83d3a3704a1fcdb9bae7136c0a947ffa34bd53f055388395ed705fe8cacd0ef8";
const SET_10_HC_BUNDLE_V2: &str = "651043e2ff2fef28df2d8edbdbbc387668577af72dcc584ee7d850e093a2839b";
const SET_10_HC_BUNDLE_V3: &str = "60af094acfe65d85fdb18fb3d06cf9085dcf28c96e59e87f1ee527226e6e3fce";
const SET_10_HC_AUTH: &str = "1e4e347f44cf86750b30a9a4bdf9ec9256efe353d4ff8017451eca7d195639c1";
const SET_10_HC_AUTH_MULTISIG: &str = "9705f8e2f1bc8561848b29cb8efd57c37e3e39788fa58a5f03304d8019668247";
const SET_10_HC_LEGACY_BUNDLE: &str = "4a27356f379571036025a4a8661c294b0edec2b7cf7fbfd60b472b186cbd4afb";

/// Constraint set 11: what this source assembles (chain 22's cut names v3, auth and msauth).
const HC_BUNDLE_V1: &str = "71eedbfb5977995ffcb8a2adbf9776e77c8a457888afa2f9c76ffd288d8fee70";
const HC_BUNDLE_V2: &str = "3aff63618cadf9771dd2bd2ca8c87d0bb725c56fdf9bed6a266d8ea8f6546046";
const HC_BUNDLE_V3: &str = "00782b22b1efdf6bbc4d9001b27baa28c03e75732090c6ccd494ddd1365c141e";
const HC_AUTH: &str = "8373994c200819c899236f822f0315efea213b3506a1df0785544a6c90a46078";
const HC_LEGACY_BUNDLE: &str = "6e968302c051ad991ccc3b432397434ed39a3fa4d6a01000d2ea3e2c9762dc1d";

/// The guest the chain runs is not a vendored binary: it is `guests::bundle_hidden()`, assembled
/// from this crate's source. Chain 14's genesis pins its set-6 digest; this source's is set 11's.
#[test]
fn the_chain_14_bundle_guest_is_the_genesis_pin() {
    let genesis = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/genesis-chain14.json")).unwrap();
    let genesis: serde_json::Value = serde_json::from_str(&genesis).unwrap();
    assert_eq!(word8_to_hex(&ZkExecutor::hc_bundle()), HC_BUNDLE_V1, "guests::bundle_hidden() no longer assembles to its set-11 digest");
    assert_eq!(genesis["hc_bundle"].as_str().unwrap(), SET_10_HC_BUNDLE_V1, "deploy/genesis-chain14.json's hc_bundle");
}

/// The branch-free hidden guest (`guests::bundle_hidden_v2()`, INT-2 / GV-1), pinned so a source
/// change moving it fails here. v1 and v2 share one assembler function.
#[test]
fn the_branch_free_bundle_guest_is_pinned() {
    assert_eq!(word8_to_hex(&ZkExecutor::hc_hidden_bundle_v2()), HC_BUNDLE_V2, "guests::bundle_hidden_v2() no longer assembles to its pinned digest");
    assert_eq!(word8_to_hex(&ZkExecutor::hc_hidden_bundle()), HC_BUNDLE_V1);
    assert_eq!(ZkExecutor::known_hc_bundles().map(|h| word8_to_hex(&h))[..2], [HC_BUNDLE_V1, HC_BUNDLE_V2]);
}

/// Bundle guest v3 (`guests::bundle_hidden_v3()`, split authorisation), pinned like v2's. The
/// value chain 22's genesis carries as `hc_bundle` (`deploy/cut-chain22-genesis.sh`'s
/// `EXPECT_HC_BUNDLE`).
#[test]
fn the_split_authorisation_bundle_guest_is_pinned() {
    assert_eq!(word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()), HC_BUNDLE_V3, "guests::bundle_hidden_v3() no longer assembles to its pinned digest");
    assert_eq!(
        ZkExecutor::known_hc_bundles().map(|h| word8_to_hex(&h)),
        [HC_BUNDLE_V1.to_string(), HC_BUNDLE_V2.to_string(), HC_BUNDLE_V3.to_string()]
    );
    let cut = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/cut-chain22-genesis.sh")).unwrap();
    assert!(cut.contains(&format!("EXPECT_HC_BUNDLE=${{EXPECT_HC_BUNDLE:-{HC_BUNDLE_V3}}}")), "the chain-22 cut expects this hc_bundle");
}

/// The auth guest (`guests::auth()`, split authorisation): the value a genesis carries as
/// `hc_auth` beside a v3 `hc_bundle`.
#[test]
fn the_auth_guest_is_pinned() {
    assert_eq!(word8_to_hex(&ZkExecutor::hc_auth()), HC_AUTH, "the auth guest no longer assembles to its pinned digest");
    assert!(
        !ZkExecutor::known_hc_bundles().map(|h| word8_to_hex(&h)).contains(&HC_AUTH.to_string()),
        "the auth guest's digest must not be a bundle guest's"
    );
    let cut = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/cut-chain22-genesis.sh")).unwrap();
    assert!(cut.contains(&format!("EXPECT_HC_AUTH=${{EXPECT_HC_AUTH:-{HC_AUTH}}}")), "the chain-22 cut expects this hc_auth");
}

/// The docs name the pinned multisig auth guest and its tier, as they do hc_auth.
#[test]
fn the_docs_name_the_multisig_auth_guest() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let hc = word8_to_hex(&ZkExecutor::hc_auth_multisig());
    for doc in ["docs/shielded.md", "docs/prover.md", "docs/rpc.md"] {
        let text = std::fs::read_to_string(root.join(doc)).unwrap();
        assert!(text.contains("hc_auth_multisig"), "{doc} does not mention hc_auth_multisig");
    }
    let shielded = std::fs::read_to_string(root.join("docs/shielded.md")).unwrap();
    assert!(shielded.contains(&hc) && shielded.contains("tier 18"), "docs/shielded.md names the guest's digest and tier");
}

/// ZKG-2: every genesis file the repository carries names a bundle guest this repository can
/// account for. Chains 6–13 pin the retired 2-in-2-out guest, 14 and 15 v1, from 16 v1 or the
/// branch-free v2, from 17 the split-authorisation v3 with `hc_auth` — at their own constraint
/// set's digests (set 10's and earlier, the `SET_10_*` column) through chain 21, and at this
/// source's (set 11) from chain 22 on. `hc_auth` and v3 come as a pair.
#[test]
fn every_genesis_files_bundle_guest_is_the_one_this_source_assembles() {
    let current = (
        word8_to_hex(&ZkExecutor::hc_bundle()),
        word8_to_hex(&ZkExecutor::hc_hidden_bundle_v2()),
        word8_to_hex(&ZkExecutor::hc_legacy_bundle()),
        word8_to_hex(&ZkExecutor::hc_hidden_bundle_v3()),
        word8_to_hex(&ZkExecutor::hc_auth()),
    );
    assert_eq!(current, (HC_BUNDLE_V1.into(), HC_BUNDLE_V2.into(), HC_LEGACY_BUNDLE.into(), HC_BUNDLE_V3.into(), HC_AUTH.into()));
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
        let (v1, v2, legacy, v3, auth) = if chain <= 21 {
            (SET_10_HC_BUNDLE_V1, SET_10_HC_BUNDLE_V2, SET_10_HC_LEGACY_BUNDLE, SET_10_HC_BUNDLE_V3, SET_10_HC_AUTH)
        } else {
            (HC_BUNDLE_V1, HC_BUNDLE_V2, HC_LEGACY_BUNDLE, HC_BUNDLE_V3, HC_AUTH)
        };
        let hc_auth = genesis.get("hc_auth").and_then(|v| v.as_str());
        assert_eq!(hc_auth.is_some(), pin == v3, "{name}: hc_auth and bundle guest v3 come as a pair");
        if chain >= 17 && pin == v3 {
            assert_eq!(hc_auth, Some(auth), "{name}'s hc_auth is not auth()'s digest");
        } else if !(chain >= 16 && pin == v2) {
            let (want, guest) = if chain >= 14 { (v1, "bundle_hidden") } else { (legacy, "the retired bundle") };
            assert_eq!(pin, want, "{name}'s hc_bundle is not {guest}()'s digest");
        }
        checked.insert(chain);
    }
    assert!(checked.contains(&14) && checked.contains(&15), "chains 14 and 15 must be among the files checked: {checked:?}");
    assert!(checked.contains(&17) && checked.contains(&21), "chains 17 and 21 must be among the files checked: {checked:?}");
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

/// Private multisig phase 4: the re-vendor brought the MODQ chip (syscall 8, `MODQ_MAX_GAS` since set 11), the
/// `msauth` host model and the compiled `msauth` guest, and the guest is in the manifest.
#[test]
fn the_msauth_guest_and_the_modq_chip_are_vendored() {
    let manifest = manifest();
    for path in ["bin/msauth.bin", "bin/msauth.bin.sha256", "bin/dilithium-verify.bin", "bin/dilithium-verify.bin.sha256"] {
        assert!(manifest.iter().any(|(_, p)| p == path), "{path} is not in SHA256SUMS");
    }
    assert_eq!(randprotocol_zkvm::isa::SYS_MODQ, 8);
    assert_eq!(randprotocol_zkvm::gas::MODQ_MAX_GAS, 304, "constraint set 11 prices MODQ per op; MSUB4 is the heaviest");
    assert_eq!(randprotocol_zkvm::msauth::MSAUTH_WORDS, 17 + randprotocol_zkvm::msauth::M_MAX * 967);
    assert!(!randprotocol_zkvm::guests::compiled::msauth().words.is_empty());
    // Its tags are node-local and sit beside auth.rs's: AUTH is the same 65.
    assert_eq!(randprotocol_zkvm::msauth::AUTH, randprotocol_zkvm::auth::AUTH_DOMAIN);
}

/// Constraint set 11 moved every guest's digest (Grain constants): none of the set-10 digests the
/// committed genesis files name is one this source assembles, and the msauth guest is none of the
/// bundle or auth guests.
#[test]
fn constraint_set_11_moved_every_guest_program() {
    let msauth = randprotocol_zkvm::guests::compiled::msauth().digest();
    for (now, then) in [
        (HC_BUNDLE_V1, SET_10_HC_BUNDLE_V1),
        (HC_BUNDLE_V2, SET_10_HC_BUNDLE_V2),
        (HC_BUNDLE_V3, SET_10_HC_BUNDLE_V3),
        (HC_AUTH, SET_10_HC_AUTH),
        (MSAUTH_HC, SET_10_HC_AUTH_MULTISIG),
        (HC_LEGACY_BUNDLE, SET_10_HC_LEGACY_BUNDLE),
    ] {
        assert_ne!(now, then);
    }
    assert_eq!(randprotocol_zkvm::machine::CONSTRAINT_SET, 11);
    assert!(!ZkExecutor::known_hc_bundles().contains(&msauth) && msauth != ZkExecutor::hc_auth());
}

/// The multisig auth guest (`guests::compiled::msauth()`, private multisig phase 4) is the value a
/// genesis carries as `hc_auth_multisig`: the digest of the vendored `msauth.bin` (the file's
/// sha256 is the manifest's) under constraint set 11's Poseidon2 (chain 21's, set 9, is
/// `SET_10_HC_AUTH_MULTISIG`), pinned so a re-vendor that moves it fails here, not at a chain's
/// first block.
const MSAUTH_HC: &str = "41db73c507ab1f24ebe76d9c425b42a08ed9a02b4b1284d410502729ce6b9cd1";

#[test]
fn the_multisig_auth_guest_is_pinned() {
    assert_eq!(MSAUTH_HC.len(), 64, "write circuits Task 8's msauth hc into MSAUTH_HC (Task 2 Step 3)");
    assert_eq!(word8_to_hex(&ZkExecutor::hc_auth_multisig()), MSAUTH_HC);
    assert_eq!(randprotocol_zkvm::executor::MSAUTH_TIER, 18, "the MODQ ruling: tier 18 only");
    assert_ne!(ZkExecutor::hc_auth_multisig(), ZkExecutor::hc_auth());
    assert!(!ZkExecutor::known_hc_bundles().contains(&ZkExecutor::hc_auth_multisig()));
}

/// The precomputed msauth verifier key (plan Task 2b, spec §3.6) is consensus-critical: a wrong
/// commitment could let a forged multisig proof verify. Both profiles' blobs are pinned by the
/// SHA-256 of their file bytes. Both are committed (`keys/msauth-vk-{test,production}.bin`) and
/// must hash to their pins; `$MSAUTH_VK_PRODUCTION_BLOB`, if set, is checked as well (a release
/// asset about to ship), and `docs/deploy.md` must name the production pin so an operator can
/// compare by hand.
#[test]
fn the_msauth_verifier_key_blobs_are_pinned() {
    use randprotocol_zkvm::executor::msauth_vk::{digest, MSAUTH_VK_SHA256_PRODUCTION, MSAUTH_VK_SHA256_TEST, PIN_PENDING};
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (profile, pin) in [("test", MSAUTH_VK_SHA256_TEST), ("production", MSAUTH_VK_SHA256_PRODUCTION)] {
        assert_eq!(pin.len(), 64, "{profile}: a SHA-256 pin is 64 hex characters");
        assert!(pin.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{profile}: lowercase hex");
        assert_ne!(pin, PIN_PENDING, "{profile}: the pin is still the placeholder");
    }
    let test = root.join("keys/msauth-vk-test.bin");
    let bytes = std::fs::read(&test).unwrap_or_else(|e| panic!("{}: {e}; run `rand-node keygen-msauth-vk --profile test --out {}`", test.display(), test.display()));
    assert_eq!(digest(&bytes), MSAUTH_VK_SHA256_TEST, "test msauth key blob {} ({} bytes): write the computed digest (left) into MSAUTH_VK_SHA256_TEST", test.display(), bytes.len());
    let committed = root.join("keys/msauth-vk-production.bin");
    let bytes = std::fs::read(&committed).unwrap_or_else(|e| panic!("{}: {e}; run `rand-node keygen-msauth-vk --profile production --out {}`", committed.display(), committed.display()));
    assert_eq!(digest(&bytes), MSAUTH_VK_SHA256_PRODUCTION, "production msauth key blob {} ({} bytes): write the computed digest (left) into MSAUTH_VK_SHA256_PRODUCTION", committed.display(), bytes.len());
    if let Some(extra) = std::env::var_os("MSAUTH_VK_PRODUCTION_BLOB").map(PathBuf::from) {
        let bytes = std::fs::read(&extra).unwrap_or_else(|e| panic!("{}: {e}", extra.display()));
        assert_eq!(digest(&bytes), MSAUTH_VK_SHA256_PRODUCTION, "MSAUTH_VK_PRODUCTION_BLOB {} is not the pinned production blob", extra.display());
    }
    let deploy = std::fs::read_to_string(root.join("../../docs/deploy.md")).unwrap();
    assert!(deploy.contains(MSAUTH_VK_SHA256_PRODUCTION), "docs/deploy.md names the production msauth key pin");
}
