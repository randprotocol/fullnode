//! On-disk key file: only the 32-byte seed is secret; the rest is derived.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use shrugg_core::Keypair;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct KeyFile {
    pub seed: String,
    pub address: String,
    pub public_key: String,
}

impl KeyFile {
    pub fn from_keypair(kp: &Keypair) -> KeyFile {
        KeyFile {
            seed: hex::encode(kp.seed()),
            address: kp.address().to_base58(),
            public_key: kp.public_key().to_hex(),
        }
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self)?;
        // Create with owner-only permissions from the start: writing first and
        // chmodding afterwards leaves the seed world-readable for a window.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("writing {}", path.display()))?;
            f.write_all(s.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
            // The mode above only applies to newly created files; tighten a
            // pre-existing file's permissions too.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(not(unix))]
        std::fs::write(path, s).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn read(path: &Path) -> Result<KeyFile> {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(serde_json::from_str(&s)?)
    }

    pub fn seed_bytes(&self) -> Result<[u8; 32]> {
        let v = hex::decode(&self.seed)?;
        v.try_into().map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))
    }

    pub fn keypair(&self) -> Result<Keypair> {
        Ok(Keypair::from_seed(self.seed_bytes()?)?)
    }
}

pub fn load_keypair(path: &Path) -> Result<Keypair> {
    KeyFile::read(path)?.keypair()
}
