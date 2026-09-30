//! On-disk key file: only the 32-byte seed is secret; the rest is derived.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use randprotocol_core::Keypair;
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

    /// Write a new key file, refusing to touch an existing path (VK-7, audit v6). This is what
    /// `rand-node keygen` writes: a validator's key, a token authority's, a vesting beneficiary's,
    /// the pause key. Nothing keeps a second copy of the seed, and the key signs its own `Unbond`,
    /// `Withdraw` and `ClaimVested`, so truncating one — a second `keygen` to the same `--out`, a
    /// shell history replayed — loses what it controls for good. There is deliberately no
    /// overwriting sibling and no `--force`: no caller in this tree replaces a key, and an operator
    /// who means to moves the old file aside first.
    pub fn write_new(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self)?;
        let refused = || format!("{} already exists or cannot be created; refusing to overwrite a key file (move the old one aside first)", path.display());
        // `create_new` closes the exists-then-write race, and the mode is part of the `open`:
        // writing first and chmodding afterwards leaves the seed world-readable for a window.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).with_context(refused)?;
            f.write_all(s.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
            // On disk before the address is printed: a power loss right after must not leave an
            // empty file where the only copy of the seed should be.
            f.sync_all().with_context(|| format!("flushing {}", path.display()))?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path).with_context(refused)?;
            f.write_all(s.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
            f.sync_all().with_context(|| format!("flushing {}", path.display()))?;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// VK-7 (audit v6): `rand-node keygen` truncated whatever was at `--out`. The file is a
    /// validator's, a token authority's, a vesting beneficiary's or the pause key — the only copy
    /// of its seed — so a second write to the same path must fail and leave the first key's bytes
    /// exactly as they were.
    #[test]
    fn a_second_key_written_to_the_same_path_is_refused_and_the_first_survives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key.json");
        let first = Keypair::generate();
        KeyFile::from_keypair(&first).write_new(&path).unwrap();
        let before = std::fs::read(&path).unwrap();

        let second = KeyFile::from_keypair(&Keypair::generate()).write_new(&path);
        assert!(second.is_err(), "a second key was written over the first");
        let why = format!("{:#}", second.unwrap_err());
        assert!(why.contains("refusing to overwrite"), "{why}");
        assert!(std::fs::read(&path).unwrap() == before, "the first key file changed");
        assert_eq!(load_keypair(&path).unwrap().address(), first.address());
    }

    /// The file is owner-only from the moment it exists (the mode is part of the `open`, not a
    /// `chmod` after the seed is already on disk).
    #[cfg(unix)]
    #[test]
    fn a_new_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key.json");
        KeyFile::from_keypair(&Keypair::generate()).write_new(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
