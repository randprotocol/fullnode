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

/// The key file this node reads: `--msauth-vk`, else `RAND_MSAUTH_VK`, else
/// `msauth-vk-<profile>.bin` beside the running executable — the fleet's
/// `/usr/local/bin/msauth-vk-production.bin`.
pub fn resolve_path(opts: &MsauthKeyOptions, profile: FriProfile) -> Result<PathBuf> {
    if let Some(p) = &opts.path {
        return Ok(p.clone());
    }
    if let Some(p) = std::env::var_os(ENV_PATH).filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().context("locating the running binary for the msauth key file")?;
    Ok(exe.with_file_name(msauth_vk::file_name(profile)))
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
            "msauth verifier key: {} missing ({e}) (expected blake3 {pin}); install it from the release, or run with --build-msauth-key on a ≥ 8 GB host",
            path.display()
        ),
    };
    install(&bytes).map_err(|e| {
        anyhow!(
            "msauth verifier key: {} has blake3 {} and was refused: {e} (expected blake3 {pin}); install it from the release, or run with --build-msauth-key on a ≥ 8 GB host",
            path.display(),
            msauth_vk::digest(&bytes)
        )
    })?;
    tracing::info!("msauth verifier key loaded from {} (blake3 {pin})", path.display());
    Ok(MsauthKeySource::Loaded)
}

/// `rand-node keygen-msauth-vk --profile <p> --out <file>`: build the key (a big host: 78.6 s,
/// ~4 GB at Production), write the blob to a new file (never over an existing one) and return
/// its blake3 and size.
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

/// `rand-node keygen-msauth-vk --check <file>`: the file's blake3, as the deploy scripts compare
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
