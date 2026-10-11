//! The precomputed msauth verifier key on the node side (plan Task 2b, spec §3.6).
//!
//! The tier-18 msauth key costs 78.6 s and ~4 GB to build; the fleet's validators are
//! `s-2vcpu-4gb`. So a node on a chain naming `hc_auth_multisig` **loads** the key from one fixed
//! file beside its binary (`/usr/local/bin/msauth-vk-production.bin` on the fleet), overridden
//! only by `--msauth-vk <path>` or `RAND_MSAUTH_VK`, and refuses to start if the file is missing
//! or is not the pinned blob. There is no automatic fallback build: only `--build-msauth-key`
//! (development, a ≥ 8 GB host) builds it.
//!
//! `rand-node keygen-msauth-vk` writes the file (a big host), prints a file's digest (`--check`,
//! what the deploy scripts compare) and prints this build's pin (`--print-pinned`).

use anyhow::{anyhow, bail, Context, Result};
pub use randprotocol_zkvm::executor::msauth_vk::MsauthKeySource;
use randprotocol_zkvm::executor::msauth_vk;
use randprotocol_zkvm::machine::FriProfile;
use std::path::{Path, PathBuf};

/// The environment variable that overrides the key file's location (after `--msauth-vk`).
pub const ENV_PATH: &str = "RAND_MSAUTH_VK";

/// How `run` finds or makes the msauth key.
#[derive(Clone, Debug, Default)]
pub struct MsauthKeyOptions {
    /// `--msauth-vk <path>`; `None` falls back to `RAND_MSAUTH_VK`, then to the file beside the
    /// running binary.
    pub path: Option<PathBuf>,
    /// `--build-msauth-key`: when the file is missing, build the key on this host instead of
    /// refusing to start (development only; never set by a deploy script).
    pub build: bool,
}

/// The environment variable that lets a release build run from a checkout's `target/` read the
/// committed blob (see [`resolve_path`]); debug builds there need no flag.
pub const ENV_DEV_FALLBACK: &str = "RAND_MSAUTH_VK_DEV_FALLBACK";

/// The key file this node reads: `--msauth-vk`, else `RAND_MSAUTH_VK`, else
/// `msauth-vk-<profile>.bin` beside the running executable — the fleet's
/// `/usr/local/bin/msauth-vk-production.bin`. Only for a developer's binary is there a fallback,
/// when that file is absent: the committed `crates/randprotocol-zkvm/keys/msauth-vk-<profile>.bin`,
/// and only when the running executable lives under this source tree's own `target/` (a
/// `cargo run`, a `target/release/rand-node`) **and** it is a debug build or
/// `RAND_MSAUTH_VK_DEV_FALLBACK=1` is set. A fleet host that built in its own checkout installs
/// the binary into `/usr/local/bin`, so it never reads a mutable git tree: a missing fixed-path
/// file fails the start loudly there. The pin is checked whichever file is read.
pub fn resolve_path(opts: &MsauthKeyOptions, profile: FriProfile) -> Result<PathBuf> {
    if let Some(p) = &opts.path {
        return Ok(p.clone());
    }
    if let Some(p) = std::env::var_os(ENV_PATH).filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().context("locating the running binary for the msauth key file")?;
    let opted_in = cfg!(debug_assertions) || std::env::var_os(ENV_DEV_FALLBACK).is_some_and(|v| v == "1");
    Ok(default_path(&exe, profile, opted_in))
}

/// [`resolve_path`]'s default for an executable at `exe`: beside it, or — only when that file is
/// absent, `exe` is under this source tree's `target/` and `opted_in` — the committed blob.
pub fn default_path(exe: &Path, profile: FriProfile, opted_in: bool) -> PathBuf {
    let beside = exe.with_file_name(msauth_vk::file_name(profile));
    if opted_in && !beside.exists() && in_source_target(exe) {
        let tree = source_tree_path(profile);
        if tree.exists() {
            return tree;
        }
    }
    beside
}

/// The workspace root this binary was built from (`CARGO_MANIFEST_DIR/../..`).
fn source_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether `exe` is inside this source tree's `target/` directory (both sides canonicalised, so a
/// symlinked or relative path does not sneak past).
fn in_source_target(exe: &Path) -> bool {
    let (Ok(exe), Ok(target)) = (exe.canonicalize(), source_root().join("target").canonicalize()) else {
        return false;
    };
    exe.starts_with(target)
}

/// The committed blob in a source tree: `crates/randprotocol-zkvm/keys/msauth-vk-<profile>.bin`.
pub fn source_tree_path(profile: FriProfile) -> PathBuf {
    source_root().join("crates/randprotocol-zkvm/keys").join(msauth_vk::file_name(profile))
}


/// The startup obligation (spec §3.6). On a chain without `hc_auth_multisig` there is no key:
/// `Absent`, and the path is never read. Otherwise the file at `path` is read and handed to
/// `install` (`ZkExecutor::install_msauth_vk` behind the executor trait), which checks the digest
/// against this build's pin, the profile and the shape, and installs it: `Loaded`. A missing
/// file is `Built` only with `build` set — the caller then builds — and otherwise an error naming
/// the path and the expected digest, which `run` turns into a startup failure. A file that is
/// present but refused is an error even with `build`: a wrong blob on disk is never papered over.
pub fn load_msauth_key(
    path: &Path,
    profile: FriProfile,
    multisig: bool,
    build: bool,
    install: impl FnOnce(&[u8]) -> Result<(), String>,
) -> Result<MsauthKeySource> {
    if !multisig {
        return Ok(MsauthKeySource::Absent);
    }
    let pin = msauth_vk::pin(profile);
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && build => {
            tracing::warn!("msauth verifier key: {} missing; --build-msauth-key: building the tier-18 msauth key (~4 GB, ~80 s)", path.display());
            return Ok(MsauthKeySource::Built);
        }
        Err(e) => bail!(
            "msauth verifier key: {} missing ({e}) (expected sha256 {pin}); install it from the release, or run with --build-msauth-key on a ≥ 8 GB host",
            path.display()
        ),
    };
    install(&bytes).map_err(|e| {
        anyhow!(
            "msauth verifier key: {} has sha256 {} and was refused: {e} (expected sha256 {pin}); install it from the release, or run with --build-msauth-key on a ≥ 8 GB host",
            path.display(),
            msauth_vk::digest(&bytes)
        )
    })?;
    tracing::info!("msauth verifier key loaded from {} (sha256 {pin})", path.display());
    Ok(MsauthKeySource::Loaded)
}

/// `rand-node keygen-msauth-vk --profile <p> --out <file>`: build the key (a big host: 78.6 s,
/// ~4 GB at Production), write the blob to a new file (never over an existing one) and return
/// its sha256 and size.
pub fn keygen(profile: FriProfile, out: &Path) -> Result<(String, usize)> {
    if out.exists() {
        bail!("{} exists; refusing to overwrite a key file", out.display());
    }
    let blob = msauth_vk::blob(profile).map_err(|e| anyhow!("building the msauth verifier key: {e}"))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .with_context(|| format!("creating {}", out.display()))?;
    std::io::Write::write_all(&mut f, &blob).with_context(|| format!("writing {}", out.display()))?;
    Ok((msauth_vk::digest(&blob), blob.len()))
}

/// `rand-node keygen-msauth-vk --check <file>`: the file's sha256, as the deploy scripts compare
/// it against `--print-pinned`.
pub fn check_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(msauth_vk::digest(&bytes))
}

/// The profile named on the command line.
pub fn parse_profile(s: &str) -> Result<FriProfile> {
    randprotocol_zkvm::executor::ZkExecutor::profile_from_str(s).ok_or_else(|| anyhow!("--profile must be production or test, not {s}"))
}

/// Whether the chain names `hc_auth_multisig`, i.e. whether this node must hold the msauth key.
///
/// TASK-3: `gs.ledger.hc_auth_multisig().is_some()` once plan Task 3 adds the genesis field. No
/// genesis carries it before then, so until then no node reads a key file.
pub fn chain_has_msauth(_gs: &randprotocol_core::genesis::GenesisState) -> bool {
    false
}

/// `node::start_with`'s step: [`resolve_path`] and [`load_msauth_key`] into `executor` (the bare
/// one, not the caching wrapper) for the chain's profile. An `Err` is a startup failure.
pub fn startup(
    gs: &randprotocol_core::genesis::GenesisState,
    opts: &MsauthKeyOptions,
    executor: &dyn randprotocol_core::confidential::ConfidentialExecutor,
) -> Result<MsauthKeySource> {
    if !chain_has_msauth(gs) {
        return Ok(MsauthKeySource::Absent);
    }
    let profile = parse_profile(&gs.fri_profile)?;
    let path = resolve_path(opts, profile)?;
    load_msauth_key(&path, profile, true, opts.build, |blob| executor.install_msauth_vk(blob))
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_zkvm::executor::ZkExecutor;

    fn never(_: &[u8]) -> Result<(), String> {
        panic!("the key file must not be read or installed here")
    }

    /// A missing file on a multisig chain fails the start, naming the path and the expected
    /// SHA-256, and builds nothing.
    #[test]
    fn a_missing_key_file_fails_naming_the_path_and_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("msauth-vk-test.bin");
        let ex = ZkExecutor::new(FriProfile::Test);
        let e = load_msauth_key(&path, FriProfile::Test, true, false, never).unwrap_err().to_string();
        assert!(e.contains(&path.display().to_string()), "{e}");
        assert!(e.contains(&format!("expected sha256 {}", msauth_vk::pin(FriProfile::Test))), "{e}");
        assert!(e.contains("--build-msauth-key"), "{e}");
        assert_eq!(ex.msauth_key_builds(), 0);
        assert!(!ex.msauth_key_ready());
    }

    /// A present file whose SHA-256 is not the pin is refused with the path, its digest and the
    /// expected one — through the real executor, which builds nothing.
    #[test]
    fn a_wrong_digest_fails_naming_the_path_got_and_expected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("msauth-vk-test.bin");
        std::fs::write(&path, b"not the msauth key").unwrap();
        let got = msauth_vk::digest(b"not the msauth key");
        let ex = ZkExecutor::new(FriProfile::Test);
        let e = load_msauth_key(&path, FriProfile::Test, true, false, |b| ex.install_msauth_vk(b).map_err(|e| e.to_string()))
            .unwrap_err()
            .to_string();
        assert!(e.contains(&path.display().to_string()), "{e}");
        assert!(e.contains(&format!("has sha256 {got}")), "{e}");
        assert!(e.contains(&format!("expected sha256 {}", msauth_vk::pin(FriProfile::Test))), "{e}");
        assert_eq!(ex.msauth_key_builds(), 0);
        assert_eq!(ex.msauth_machine_key_builds(), 0);
        assert!(!ex.msauth_key_ready());
    }

    /// `--build-msauth-key` is the only build path: a missing file is `Built` only with it set,
    /// and a present-but-refused file is an error even with it (a wrong blob is never papered
    /// over by a build).
    #[test]
    fn only_the_build_flag_turns_a_missing_file_into_a_build() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.bin");
        assert!(load_msauth_key(&missing, FriProfile::Test, true, false, never).is_err());
        assert_eq!(load_msauth_key(&missing, FriProfile::Test, true, true, never).unwrap(), MsauthKeySource::Built);
        let wrong = dir.path().join("wrong.bin");
        std::fs::write(&wrong, b"x").unwrap();
        assert!(load_msauth_key(&wrong, FriProfile::Test, true, true, |_| Err("refused".into())).is_err());
    }

    /// A chain without `hc_auth_multisig` needs no key: `Absent`, and the path is never read.
    #[test]
    fn a_chain_without_multisig_never_reads_the_path() {
        let path = Path::new("/nonexistent/msauth-vk-production.bin");
        assert_eq!(load_msauth_key(path, FriProfile::Production, false, false, never).unwrap(), MsauthKeySource::Absent);
        assert_eq!(load_msauth_key(path, FriProfile::Production, false, true, never).unwrap(), MsauthKeySource::Absent);
    }

    /// The node's load path pointed at the committed Test blob (`--msauth-vk`): `Loaded`, then the
    /// warm thread's `warm_auth_multisig` finds the key ready and nothing is ever built.
    #[test]
    fn the_test_blob_loads_through_the_node_path_and_warm_builds_nothing() {
        let blob = Path::new(env!("CARGO_MANIFEST_DIR")).join("../randprotocol-zkvm/keys/msauth-vk-test.bin");
        let opts = MsauthKeyOptions { path: Some(blob), build: false };
        let ex = ZkExecutor::new(FriProfile::Test);
        let path = resolve_path(&opts, FriProfile::Test).unwrap();
        let source = load_msauth_key(&path, FriProfile::Test, true, opts.build, |b| ex.install_msauth_vk(b).map_err(|e| e.to_string())).unwrap();
        assert_eq!(source, MsauthKeySource::Loaded);
        ex.warm_auth_multisig();
        assert!(ex.auth_multisig_key_ready());
        assert_eq!(ex.msauth_machine_key_builds(), 0);
        assert_eq!(ex.msauth_key_builds(), 0);
    }

    /// The path order: `--msauth-vk`, then `RAND_MSAUTH_VK`, then the file beside the binary.
    #[test]
    fn the_flag_wins() {
        let flag = MsauthKeyOptions { path: Some(PathBuf::from("/x/key.bin")), build: false };
        assert_eq!(resolve_path(&flag, FriProfile::Production).unwrap(), PathBuf::from("/x/key.bin"));
    }

    /// Review fix 1: an executable outside this source tree (a fleet host's `/usr/local/bin`, a
    /// copied binary) gets the fixed path only, opted in or not — never the git tree's blob.
    #[test]
    fn an_exe_outside_the_tree_gets_the_fixed_path_only() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("rand-node");
        std::fs::write(&exe, b"").unwrap();
        for opted_in in [false, true] {
            assert_eq!(default_path(&exe, FriProfile::Production, opted_in), dir.path().join("msauth-vk-production.bin"));
        }
        let fleet = Path::new("/usr/local/bin/rand-node");
        assert_eq!(default_path(fleet, FriProfile::Production, true), PathBuf::from("/usr/local/bin/msauth-vk-production.bin"));
    }

    /// An executable under the tree's `target/` falls back to the committed blob only when opted
    /// in (a debug build, or `RAND_MSAUTH_VK_DEV_FALLBACK=1`), and never past a file beside it.
    #[test]
    fn an_exe_in_the_tree_target_falls_back_only_when_opted_in() {
        let exe = std::env::current_exe().unwrap(); // target/release/deps/<test binary>
        assert!(in_source_target(&exe), "the test binary runs from this tree's target/");
        let beside = exe.with_file_name("msauth-vk-production.bin");
        assert!(!beside.exists());
        assert_eq!(default_path(&exe, FriProfile::Production, false), beside);
        let tree = default_path(&exe, FriProfile::Production, true);
        assert_eq!(tree, source_tree_path(FriProfile::Production));
        assert_eq!(msauth_vk::digest(&std::fs::read(&tree).unwrap()), msauth_vk::pin(FriProfile::Production));
    }

    /// Only tests may install against a pin of their choosing: the node never names the hook.
    #[test]
    fn the_node_never_calls_the_test_pin_hook() {
        let hook = concat!("install_msauth_vk", "_with_pin");
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    assert!(!std::fs::read_to_string(&p).unwrap().contains(hook), "{} names {hook}", p.display());
                }
            }
        }
    }

    /// No deploy script ever builds the key on a validator: `--build-msauth-key` is development
    /// only, and the roll ships the blob.
    #[test]
    fn no_deploy_script_passes_the_build_flag() {
        let deploy = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
        let mut stack = vec![deploy];
        let mut seen = 0;
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Ok(s) = std::fs::read_to_string(&p) {
                    seen += 1;
                    assert!(!s.contains("--build-msauth-key"), "{} passes --build-msauth-key", p.display());
                }
            }
        }
        assert!(seen > 10, "read the deploy directory");
    }
}
