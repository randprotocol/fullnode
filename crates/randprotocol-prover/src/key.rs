//! The prover's long-lived ML-KEM-768 key: a 64-byte seed on disk (mode 0600, written once),
//! the decapsulation key and the encapsulation key derived from it, and the fingerprint a
//! wallet shows its user to confirm it is pairing with the right prover.

use crate::wire::Dk;
use ml_kem::kem::FromSeed;
use ml_kem::{KeyExport, MlKem768};
use rand::Rng;
use randprotocol_core::crypto::Hash;
use randprotocol_core::fingerprint::Fingerprint;
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Write};
use std::path::Path;
use zeroize::Zeroizing;

pub const FINGERPRINT_DOMAIN: &[u8] = b"rand-prover-fingerprint-1";
const KEY_FILE_VERSION: u32 = 1;
const KEY_FILE_KIND: &str = "rand-prover-key";

/// The prover's key. Only the seed is secret material worth storing; `Debug` is deliberately
/// not derived.
pub struct ProverKey {
    seed: Zeroizing<[u8; 64]>,
    dk: Dk,
    ek_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    version: u32,
    kind: String,
    seed: String,
}

impl ProverKey {
    pub fn generate() -> ProverKey {
        let mut seed = Zeroizing::new([0u8; 64]);
        rand::rng().fill_bytes(&mut seed[..]);
        ProverKey::from_zeroizing(seed)
    }

    pub fn from_seed(seed: [u8; 64]) -> ProverKey { ProverKey::from_zeroizing(Zeroizing::new(seed)) }

    fn from_zeroizing(seed: Zeroizing<[u8; 64]>) -> ProverKey {
        let (dk, ek) = MlKem768::from_seed(&ml_kem::Seed::from(*seed));
        ProverKey { seed, dk, ek_bytes: ek.to_bytes().to_vec() }
    }

    pub fn kem_ek(&self) -> &[u8] { &self.ek_bytes }

    pub fn dk(&self) -> &Dk { &self.dk }

    pub fn fingerprint(&self) -> Fingerprint { fingerprint_of(self.kem_ek()) }

    /// Writes the key file at mode 0600 from the moment it exists; refuses to replace any file
    /// (`ErrorKind::AlreadyExists`), so a prover's key is never silently rotated.
    pub fn save_new(&self, path: &Path) -> std::io::Result<()> {
        let file = KeyFile { version: KEY_FILE_VERSION, kind: KEY_FILE_KIND.into(), seed: hex::encode(&self.seed[..]) };
        let text = Zeroizing::new(serde_json::to_string_pretty(&file).map_err(|e| Error::new(ErrorKind::Other, e))?);
        drop(Zeroizing::new(file.seed)); // the struct's hex copy of the seed, wiped now that `text` holds it
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path)?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()
    }

    /// Reads a key file written by [`ProverKey::save_new`]; on unix, refuses one that group or
    /// other can read, like `node.key.json`.
    pub fn load(path: &Path) -> std::io::Result<ProverKey> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!("{} is group/world readable (mode {:o}); chmod 600", path.display(), mode & 0o777),
                ));
            }
        }
        let text = Zeroizing::new(std::fs::read_to_string(path)?);
        let bad = |why: String| Error::new(ErrorKind::InvalidData, format!("{}: {why}", path.display()));
        let file: KeyFile = serde_json::from_str(&text).map_err(|e| bad(e.to_string()))?;
        let hex_seed = Zeroizing::new(file.seed);
        if file.kind != KEY_FILE_KIND { return Err(bad(format!("kind {:?}, expected {KEY_FILE_KIND:?}", file.kind))); }
        if file.version != KEY_FILE_VERSION { return Err(bad(format!("version {}, expected {KEY_FILE_VERSION}", file.version))); }
        let mut seed = Zeroizing::new([0u8; 64]);
        hex::decode_to_slice(hex_seed.as_bytes(), &mut seed[..]).map_err(|e| bad(format!("seed: {e}")))?;
        Ok(ProverKey::from_zeroizing(seed))
    }
}

/// `Fingerprint(blake3(FINGERPRINT_DOMAIN ‖ kem_ek)[..10])` — its own domain, so a prover's
/// fingerprint never collides in meaning with an address's.
pub fn fingerprint_of(kem_ek: &[u8]) -> Fingerprint {
    let h = Hash::digest_domain(FINGERPRINT_DOMAIN, kem_ek).0;
    Fingerprint(h[..10].try_into().expect("10 of 32 bytes"))
}
