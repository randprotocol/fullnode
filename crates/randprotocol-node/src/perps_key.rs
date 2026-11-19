//! CON-601: the pinned, precomputed perps state-proof verifier keys on the node side.
//!
//! A block carrying a tier-18 state proof made every validator build its key — ~3.3–4 GB at tier
//! 18 (`docs/perps.md`), more than a 2 GB or 4 GB validator holds — and node policy cannot refuse
//! a valid block. So a chain whose genesis lists `perps.state_proof_keys` (each a shape and the
//! SHA-256 of its key file; chain 22 on) admits only those shapes, and this node **loads** each
//! key from its file instead of building it, exactly as it loads the msauth key
//! ([`crate::msauth_key`]): from one fixed directory — `--perps-key-dir <dir>`, else
//! `RAND_PERPS_KEY_DIR`, else the running binary's own directory (`/usr/local/bin` on the fleet)
//! — one file per pinned shape, named by
//! `randprotocol_zkvm::executor::perp_vk::file_name`. A missing file or one whose SHA-256 is not
//! the genesis' pin refuses the start. There is no build fallback at all: a pinned key is never
//! built by a node (`rand-node keygen-perp-vk` builds the files, on a big host).
//!
//! Only a developer's binary, run from this tree's `target/`, falls back to the committed files in
//! `crates/randprotocol-zkvm/keys/` (a debug build, or `RAND_PERPS_KEY_DEV_FALLBACK=1`), as the
//! msauth key does.

use anyhow::{anyhow, bail, Context, Result};
use randprotocol_core::confidential::{ConfidentialExecutor, ProofShape};
use randprotocol_core::ledger::perps::StateProofKeyPin;
use randprotocol_zkvm::executor::perp_vk;
use randprotocol_zkvm::machine::FriProfile;
use serde::Serialize;
use std::path::{Path, PathBuf};

/// The environment variable that overrides the key directory (after `--perps-key-dir`).
pub const ENV_DIR: &str = "RAND_PERPS_KEY_DIR";
/// The environment variable that lets a release build run from a checkout's `target/` read the
/// committed files (debug builds there need no flag).
pub const ENV_DEV_FALLBACK: &str = "RAND_PERPS_KEY_DEV_FALLBACK";

/// How `run` (and `verify`) find the pinned key files.
#[derive(Clone, Debug, Default)]
pub struct PerpsKeyOptions {
    /// `--perps-key-dir <dir>`; `None` falls back to `RAND_PERPS_KEY_DIR`, then to the directory
    /// of the running binary.
    pub dir: Option<PathBuf>,
}

/// Where this node's state-proof keys come from: `rand_status.perps_keys`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PerpsKeyStatus {
    /// `"loaded"` — every pinned key installed from its file — or `"absent"`: the chain pins no
    /// state-proof key (no perps, or chain 21's on-demand builds).
    pub source: PerpsKeySource,
    /// How many pinned keys this node holds (the genesis' count when `loaded`).
    pub keys: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerpsKeySource {
    /// Every pinned key installed from its file.
    Loaded,
    /// The chain pins no state-proof key.
    #[default]
    Absent,
}

/// The chain's pinned keys (`perps.state_proof_keys`), empty on a chain without them.
pub fn chain_pins(gs: &randprotocol_core::genesis::GenesisState) -> Vec<StateProofKeyPin> {
    gs.ledger.perps().map(|p| p.config.state_proof_keys.clone()).unwrap_or_default()
}

/// `node::load_genesis`'s step: tell the bare executor the pins, so it is in pinned mode (never a
/// state-proof key build) before any caller sees it.
pub fn set_pins(gs: &randprotocol_core::genesis::GenesisState, executor: &dyn ConfidentialExecutor) {
    let pins: Vec<(ProofShape, [u8; 32])> = chain_pins(gs).iter().map(|k| (k.shape(), k.sha256)).collect();
    executor.set_perp_pinned_keys(&pins);
}

/// The directory this node reads: `--perps-key-dir`, else `RAND_PERPS_KEY_DIR`, else the running
/// binary's directory — and for a developer's binary under this tree's `target/` (a debug build,
/// or `RAND_PERPS_KEY_DEV_FALLBACK=1`), the committed `crates/randprotocol-zkvm/keys/` when the
/// binary's directory lacks `first`'s file.
pub fn resolve_dir(opts: &PerpsKeyOptions, first: Option<&str>) -> Result<PathBuf> {
    if let Some(d) = &opts.dir {
        return Ok(d.clone());
    }
    if let Some(d) = std::env::var_os(ENV_DIR).filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d));
    }
    let exe = std::env::current_exe().context("locating the running binary for the perps key files")?;
    let opted_in = cfg!(debug_assertions) || std::env::var_os(ENV_DEV_FALLBACK).is_some_and(|v| v == "1");
    Ok(default_dir(&exe, first, opted_in))
}

/// [`resolve_dir`]'s default for an executable at `exe`.
pub fn default_dir(exe: &Path, first: Option<&str>, opted_in: bool) -> PathBuf {
    let beside = exe.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    if let Some(name) = first {
        if opted_in && !beside.join(name).exists() && in_source_target(exe) && source_tree_dir().join(name).exists() {
            return source_tree_dir();
        }
    }
    beside
}

fn source_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn in_source_target(exe: &Path) -> bool {
    let (Ok(exe), Ok(target)) = (exe.canonicalize(), source_root().join("target").canonicalize()) else {
        return false;
    };
    exe.starts_with(target)
}

/// The committed key files in a source tree: `crates/randprotocol-zkvm/keys/`.
pub fn source_tree_dir() -> PathBuf {
    source_root().join("crates/randprotocol-zkvm/keys")
}

/// The startup obligation: on a chain without pins, `Absent` and nothing is read. Otherwise each
/// pin's file in `dir` is read and installed through `executor` (which checks the bytes' SHA-256
/// against the pins before decoding, then the profile and the shape); every pin must load, or the
/// error names the file, the digest it has and the one the genesis pins.
pub fn load_keys(
    pins: &[StateProofKeyPin],
    profile: FriProfile,
    dir: &Path,
    executor: &dyn ConfidentialExecutor,
) -> Result<PerpsKeyStatus> {
    if pins.is_empty() {
        return Ok(PerpsKeyStatus::default());
    }
    for pin in pins {
        let shape = pin.shape();
        let path = dir.join(perp_vk::file_name(profile, &shape));
        let want = pin.sha256_hex();
        let bytes = std::fs::read(&path).map_err(|e| {
            anyhow!(
                "perps state-proof key: {} missing ({e}) (genesis perps.state_proof_keys pins sha256 {want} for {shape:?}); install the release's perp-vk files beside rand-node, or point --perps-key-dir at them",
                path.display()
            )
        })?;
        let got = perp_vk::digest(&bytes);
        if got != want {
            bail!(
                "perps state-proof key: {} has sha256 {got}, not the {want} genesis perps.state_proof_keys pins for {shape:?}; install the release's perp-vk files",
                path.display()
            );
        }
        let installed = executor
            .install_perp_vk(&bytes)
            .map_err(|e| anyhow!("perps state-proof key: {} (sha256 {got}) was refused: {e}", path.display()))?;
        if installed != shape {
            bail!("perps state-proof key: {} installed as {installed:?}, not the pinned {shape:?}", path.display());
        }
    }
    let keys = executor.perp_pinned_keys_installed();
    if keys != pins.len() {
        bail!("perps state-proof keys: {keys} of the {} pinned keys are installed", pins.len());
    }
    tracing::info!("perps state-proof keys: {keys} pinned keys loaded from {}", dir.display());
    Ok(PerpsKeyStatus { source: PerpsKeySource::Loaded, keys })
}

/// `node::start_with`'s step (and `rand-node verify`'s): [`resolve_dir`] and [`load_keys`] into
/// `executor` (the bare one). An `Err` is a startup failure.
pub fn startup(
    gs: &randprotocol_core::genesis::GenesisState,
    opts: &PerpsKeyOptions,
    executor: &dyn ConfidentialExecutor,
) -> Result<PerpsKeyStatus> {
    let pins = chain_pins(gs);
    if pins.is_empty() {
        return Ok(PerpsKeyStatus::default());
    }
    let profile = crate::msauth_key::parse_profile(&gs.fri_profile)?;
    let first = perp_vk::file_name(profile, &pins[0].shape());
    let dir = resolve_dir(opts, Some(&first))?;
    load_keys(&pins, profile, &dir, executor)
}

/// `rand-node keygen-perp-vk --profile <p> --out-dir <dir> [--max-tier T --engine-program-log-height H --max-window-blocks N]`:
/// build each canonical shape's key (a big host at tier 18) and write `<dir>/<file_name>` (never
/// over an existing file). Returns `(file name, sha256, size)` per shape, in shape order — what
/// `perps.state_proof_keys` lists.
pub fn keygen(profile: FriProfile, shapes: &[ProofShape], out_dir: &Path) -> Result<Vec<(String, String, usize)>> {
    let mut out = Vec::new();
    for shape in shapes {
        let name = perp_vk::file_name(profile, shape);
        let path = out_dir.join(&name);
        if path.exists() {
            bail!("{} exists; refusing to overwrite a key file", path.display());
        }
        let t0 = std::time::Instant::now();
        let blob = perp_vk::blob(profile, shape).map_err(|e| anyhow!("building the state-proof key: {e}"))?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("creating {}", path.display()))?;
        std::io::Write::write_all(&mut f, &blob).with_context(|| format!("writing {}", path.display()))?;
        tracing::info!("{name}: built in {:.1} s", t0.elapsed().as_secs_f64());
        out.push((name, perp_vk::digest(&blob), blob.len()));
    }
    Ok(out)
}

/// The `state_proof_keys` JSON for `shapes` and their files' digests in `dir` — what the cut
/// splices into the genesis (`rand-node keygen-perp-vk --genesis-json <dir>`).
pub fn genesis_json(profile: FriProfile, shapes: &[ProofShape], dir: &Path) -> Result<serde_json::Value> {
    let mut keys = Vec::new();
    for s in shapes {
        let path = dir.join(perp_vk::file_name(profile, s));
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        keys.push(serde_json::json!({
            "tier": s.tier,
            "program_log_height": s.program_log_height,
            "input_log_height": s.input_log_height,
            "public_log_height": s.public_log_height,
            "poseidon2_log_height": s.poseidon2_log_height,
            "sha256": perp_vk::digest(&bytes),
        }));
    }
    Ok(serde_json::Value::Array(keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::confidential::ConfidentialError;
    use randprotocol_core::ledger::perps::canonical_state_proof_shapes;
    use randprotocol_zkvm::executor::{prove_perp, ZkExecutor};

    /// A tier-10 perps-shaped proof (the fib guest standing in for the engine) and the canonical
    /// pinned shapes of a `max_tier` 10 chain at its program height, with their key blobs
    /// exported from a separate machine.
    type Fixture = (Vec<u8>, [u32; 8], Vec<u32>, ProofShape, Vec<(ProofShape, Vec<u8>)>);

    fn fixture() -> Fixture {
        let program = randprotocol_zkvm::guests::fib(10);
        let segment: Vec<u32> = (0..40).collect();
        let (bytes, _, _) = prove_perp(FriProfile::Test, &program, &[], &segment, Some(10)).unwrap();
        let shape = randprotocol_zkvm::executor::proof_shape(&bytes).unwrap();
        let shapes = canonical_state_proof_shapes(10, shape.program_log_height, 64)
            .into_iter()
            .map(|s| ProofShape { input_log_height: shape.input_log_height, ..s })
            .collect::<Vec<_>>();
        assert!(shapes.contains(&shape), "{shape:?} among {shapes:?}");
        let blobs = shapes.iter().map(|s| (*s, perp_vk::blob(FriProfile::Test, s).unwrap())).collect();
        (bytes, program.digest(), segment, shape, blobs)
    }

    fn pins_of(blobs: &[(ProofShape, Vec<u8>)]) -> Vec<StateProofKeyPin> {
        blobs
            .iter()
            .map(|(s, b)| StateProofKeyPin {
                tier: s.tier,
                program_log_height: s.program_log_height,
                input_log_height: s.input_log_height,
                public_log_height: s.public_log_height,
                poseidon2_log_height: s.poseidon2_log_height,
                sha256: randprotocol_zkvm::sha256::sha256(b),
            })
            .collect()
    }

    fn pinned_executor(pins: &[StateProofKeyPin]) -> ZkExecutor {
        let ex = ZkExecutor::new(FriProfile::Test);
        ex.set_perp_config(10, pins[0].program_log_height);
        ex.set_perp_pinned_keys(&pins.iter().map(|k| (k.shape(), k.sha256)).collect::<Vec<_>>());
        ex
    }

    fn write_blobs(dir: &Path, blobs: &[(ProofShape, Vec<u8>)]) {
        for (s, b) in blobs {
            std::fs::write(dir.join(perp_vk::file_name(FriProfile::Test, s)), b).unwrap();
        }
    }

    /// A pinned shape verifies under the key loaded from its file — through the node's loader —
    /// with no state-proof key built.
    #[test]
    fn a_pinned_shape_verifies_under_the_loaded_blob_with_no_build() {
        let (bytes, hc, segment, _, blobs) = fixture();
        let pins = pins_of(&blobs);
        let dir = tempfile::tempdir().unwrap();
        write_blobs(dir.path(), &blobs);
        let ex = pinned_executor(&pins);
        let status = load_keys(&pins, FriProfile::Test, dir.path(), &ex).unwrap();
        assert_eq!(status, PerpsKeyStatus { source: PerpsKeySource::Loaded, keys: pins.len() });
        ex.verify_perp(&hc, 10, &segment, &bytes).expect("the pinned shape verifies");
        assert!(ex.perp_proof_admissible(&bytes, &hc, 10, &segment, pins[0].program_log_height));
        assert_eq!(ex.perp_key_builds(), 0, "verified under the loaded key: nothing built");
    }

    /// A shape the genesis does not pin is refused before any key is built — by the verify path
    /// and the pool's pre-screen alike — even on an executor holding every pinned key.
    #[test]
    fn an_unpinned_shape_is_refused_with_no_build() {
        let (bytes, hc, segment, shape, blobs) = fixture();
        // Pin every canonical shape but the proof's own.
        let others: Vec<_> = blobs.iter().filter(|(s, _)| *s != shape).cloned().collect();
        let pins = pins_of(&others);
        let dir = tempfile::tempdir().unwrap();
        write_blobs(dir.path(), &others);
        let ex = pinned_executor(&pins);
        load_keys(&pins, FriProfile::Test, dir.path(), &ex).unwrap();
        match ex.verify_perp(&hc, 10, &segment, &bytes) {
            Err(ConfidentialError::InvalidProof(why)) => assert!(why.contains("not one of the chain's"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert!(!ex.perp_proof_admissible(&bytes, &hc, 10, &segment, shape.program_log_height));
        // Neither a warm nor a keep builds it either.
        ex.warm_perp(&shape);
        ex.keep_perp_key(&shape);
        assert_eq!(ex.perp_key_builds(), 0);
        // And a pinned shape whose file was never installed is refused, not built.
        let ex = pinned_executor(&pins_of(&blobs));
        match ex.verify_perp(&hc, 10, &segment, &bytes) {
            Err(ConfidentialError::InvalidProof(why)) => assert!(why.contains("is not loaded on this node"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(ex.perp_key_builds(), 0);
    }

    /// A missing file and a file whose SHA-256 is not the pin both fail the load, naming the file
    /// and the expected digest, and install nothing; so does a pinned digest whose bytes are for
    /// another shape (a genesis pinning shape A with B's file's digest).
    #[test]
    fn a_missing_or_mismatched_blob_is_refused() {
        let (_, _, _, _, blobs) = fixture();
        let pins = pins_of(&blobs);
        let dir = tempfile::tempdir().unwrap();
        let ex = pinned_executor(&pins);
        let e = format!("{:#}", load_keys(&pins, FriProfile::Test, dir.path(), &ex).unwrap_err());
        let first = dir.path().join(perp_vk::file_name(FriProfile::Test, &pins[0].shape()));
        assert!(e.contains(&first.display().to_string()) && e.contains("missing") && e.contains(&pins[0].sha256_hex()), "{e}");
        // A flipped byte: its digest is not the pin.
        write_blobs(dir.path(), &blobs);
        let mut bad = blobs[0].1.clone();
        *bad.last_mut().unwrap() ^= 1;
        std::fs::write(&first, &bad).unwrap();
        let e = format!("{:#}", load_keys(&pins, FriProfile::Test, dir.path(), &ex).unwrap_err());
        assert!(e.contains(&perp_vk::digest(&bad)) && e.contains(&pins[0].sha256_hex()), "{e}");
        assert_eq!(ex.perp_pinned_keys_installed(), 0);
        // The executor itself refuses unpinned bytes before decoding them.
        assert!(ex.install_perp_vk(b"junk").unwrap_err().contains("none of the"));
        // Swapped digests: shape 0 pinned with shape 1's file's digest and vice versa.
        let mut swapped = pins.clone();
        let (a, b) = (swapped[0].sha256, swapped[1].sha256);
        swapped[0].sha256 = b;
        swapped[1].sha256 = a;
        let ex = pinned_executor(&swapped);
        std::fs::write(&first, &blobs[1].1).unwrap();
        let e = format!("{:#}", load_keys(&swapped, FriProfile::Test, dir.path(), &ex).unwrap_err());
        assert!(e.contains("not the pinned shape"), "{e}");
        assert_eq!(ex.perp_key_builds(), 0);
    }

    /// A chain without pins reads nothing and keeps chain 21's behaviour: an executor never told
    /// pins builds a key on demand, as before.
    #[test]
    fn a_chain_without_pins_reads_nothing_and_builds_on_demand() {
        let (bytes, hc, segment, _, _) = fixture();
        let ex = ZkExecutor::new(FriProfile::Test);
        let status = load_keys(&[], FriProfile::Test, Path::new("/nonexistent"), &ex).unwrap();
        assert_eq!(status, PerpsKeyStatus::default());
        ex.set_perp_pinned_keys(&[]);
        ex.verify_perp(&hc, 10, &segment, &bytes).expect("verifies, built on demand");
        assert_eq!(ex.perp_key_builds(), 1);
        assert!(ex.install_perp_vk(b"x").is_err(), "no pins, nothing to install");
    }

    /// The directory order: `--perps-key-dir`, then (absent the file beside the binary) the
    /// committed keys for a developer's binary only.
    #[test]
    fn the_flag_wins_and_a_fleet_binary_reads_beside_itself() {
        let flag = PerpsKeyOptions { dir: Some(PathBuf::from("/x/keys")) };
        assert_eq!(resolve_dir(&flag, None).unwrap(), PathBuf::from("/x/keys"));
        let fleet = Path::new("/usr/local/bin/rand-node");
        assert_eq!(default_dir(fleet, Some("perp-vk-production-t18-pg14-in16-pub7-p2h20.bin"), true), PathBuf::from("/usr/local/bin"));
    }

    /// The committed chain-22 files are this build's pins, and the in-tree fallback finds them.
    #[test]
    fn the_committed_chain22_files_are_this_builds_pins() {
        let pins = perp_vk::chain22_pins(FriProfile::Production);
        assert_eq!(pins.len(), 4);
        for (shape, want) in pins {
            let path = source_tree_dir().join(perp_vk::file_name(FriProfile::Production, &shape));
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            assert_eq!(perp_vk::digest(&bytes), want, "{}", path.display());
            let blob = randprotocol_zkvm::machine::VerifierKeyBlob::from_bytes(&bytes).unwrap();
            assert_eq!(blob.shape, perp_vk::key_shape(&shape));
            assert_eq!(blob.profile, FriProfile::Production);
        }
        let exe = std::env::current_exe().unwrap();
        let name = perp_vk::file_name(FriProfile::Production, &perp_vk::chain22_shapes()[0]);
        assert_eq!(default_dir(&exe, Some(&name), true), source_tree_dir());
        assert_ne!(default_dir(&exe, Some(&name), false), source_tree_dir());
    }

    /// No deploy script and no node source names a perps key build flag: there is none.
    #[test]
    fn the_node_has_no_perps_key_build_path() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        for e in std::fs::read_dir(&src).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "rs") {
                let s = std::fs::read_to_string(&p).unwrap();
                assert!(!s.contains(concat!("--build-", "perps-key")), "{}", p.display());
            }
        }
    }
}
