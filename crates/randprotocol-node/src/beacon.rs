//! The validator's beacon seed file (genesis `beacon`; `randprotocol_core::ledger::beacon`,
//! `docs/evm-block-context.md` §11) and the reveal source the consensus loop reads it through.
//!
//! `<datadir>/beacon.seed.json` (mode 0600, beside `node.key.json`) holds the 32-byte seeds of
//! this validator's hash chains, newest last. Each seed is as secret as the validator's key is
//! for the beacon: whoever holds it knows every reveal this validator will ever make from that
//! chain. **The file is bound to one chain id and one validator address** (the link hashes
//! both), so a copy on another host is useless to that host and dangerous to this one; never
//! copy it between hosts, and never restore it from a backup onto a second machine.
//!
//! No position is stored. The reveal for a block is the preimage of the commitment the chain
//! holds for this validator, found by walking from the seed — which is crash-safe (nothing to
//! write before a proposal leaves) and right after an abandoned block (the chain's commitment
//! did not move, so the same reveal is given again).
//!
//! A file keeps its older seeds: after `rand-node beacon recommit` the old chain still opens
//! the old commitment until the new one is in force, so a validator that recommits before its
//! chain runs out misses no slot.

use anyhow::{bail, Context, Result};
use randprotocol_core::consensus::RevealSource;
use randprotocol_core::ledger::beacon::SeedChain;
use randprotocol_core::Address;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The seed file's name inside a data directory.
pub const SEED_FILE: &str = "beacon.seed.json";

/// The longest chain the tools build (2^24 links: ~16 MiB of checkpoints' worth of walking,
/// seconds to build). Not consensus; a typo guard.
pub const MAX_SEED_LINKS: u64 = 1 << 24;

/// One hash chain: its secret seed, its length, and the commitment `L^links(seed)` it registers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedEntry {
    /// 64 hex characters. Secret.
    pub seed: String,
    pub links: u64,
    /// 64 hex characters: what the chain's genesis or a `BeaconCommit` carries. Checked against
    /// the seed when the file is loaded.
    pub commitment: String,
}

/// The file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedFile {
    pub version: u32,
    pub chain_id: u64,
    /// The validator's address, base58.
    pub validator: String,
    /// Oldest first; the last is the newest commitment.
    pub seeds: Vec<SeedEntry>,
}

/// The seed file's path in `datadir`.
pub fn seed_path(datadir: &Path) -> PathBuf {
    datadir.join(SEED_FILE)
}

fn check_links(links: u64) -> Result<()> {
    if links == 0 || links > MAX_SEED_LINKS {
        bail!("--links {links}: a seed chain has 1..={MAX_SEED_LINKS} links");
    }
    Ok(())
}

/// A fresh random seed and its chain for `validator` on `chain_id`.
fn fresh_entry(chain_id: u64, validator: &Address, links: u64) -> SeedEntry {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let chain = SeedChain::new(chain_id, *validator, seed, links);
    SeedEntry { seed: hex::encode(seed), links, commitment: hex::encode(chain.commitment()) }
}

/// Write `text` to a file that must not exist yet, mode 0600 from the first byte, flushed.
fn write_new_secret(path: &Path, text: &str) -> Result<()> {
    use std::io::Write;
    let refused = || format!("{} already exists or cannot be created; refusing to overwrite a beacon seed file", path.display());
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path).with_context(refused)?;
    f.write_all(text.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
    f.sync_all().with_context(|| format!("flushing {}", path.display()))?;
    Ok(())
}

impl SeedFile {
    pub fn read(path: &Path) -> Result<SeedFile> {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: SeedFile = serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?;
        if file.version != 1 {
            bail!("{}: seed file version {} (this build reads 1)", path.display(), file.version);
        }
        Ok(file)
    }

    pub fn validator(&self) -> Result<Address> {
        Address::from_base58(&self.validator).map_err(|e| anyhow::anyhow!("seed file validator `{}`: {e}", self.validator))
    }

    /// The newest entry's commitment: what `beacon init` printed, or the last `recommit` sent.
    pub fn newest_commitment(&self) -> Option<&str> {
        self.seeds.last().map(|e| e.commitment.as_str())
    }

    /// Create the file with one fresh chain. Refuses an existing path: a second `init` would
    /// throw away the seed behind a commitment the chain may already hold.
    pub fn create(path: &Path, chain_id: u64, validator: &Address, links: u64) -> Result<SeedEntry> {
        check_links(links)?;
        let entry = fresh_entry(chain_id, validator, links);
        let file = SeedFile { version: 1, chain_id, validator: validator.to_base58(), seeds: vec![entry.clone()] };
        write_new_secret(path, &serde_json::to_string_pretty(&file)?)?;
        Ok(entry)
    }

    /// Add a fresh chain to an existing file (or create the file), keeping every older seed, and
    /// return the new entry. The file is replaced by rename, so a crash leaves the old file or
    /// the new one, never a torn one. The file must be this chain's and this validator's.
    pub fn append(path: &Path, chain_id: u64, validator: &Address, links: u64) -> Result<SeedEntry> {
        check_links(links)?;
        if !path.exists() {
            return Self::create(path, chain_id, validator, links);
        }
        let mut file = Self::read(path)?;
        if file.chain_id != chain_id || file.validator()? != *validator {
            bail!(
                "{} is chain {}'s seed file for validator {}, not chain {chain_id}'s for {}: it was made on another host or for another chain; move it aside",
                path.display(),
                file.chain_id,
                file.validator,
                validator.to_base58()
            );
        }
        let entry = fresh_entry(chain_id, validator, links);
        file.seeds.push(entry.clone());
        let tmp = path.with_extension("json.tmp");
        let _ = std::fs::remove_file(&tmp);
        write_new_secret(&tmp, &serde_json::to_string_pretty(&file)?)?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(entry)
    }

    /// Every chain in the file, walked from its seed, oldest first. An entry whose seed does not
    /// give its recorded commitment under this file's chain id and validator is an error: the
    /// file was edited, or belongs to another validator.
    pub fn chains(&self) -> Result<Vec<SeedChain>> {
        let validator = self.validator()?;
        let mut out = Vec::with_capacity(self.seeds.len());
        for (i, e) in self.seeds.iter().enumerate() {
            let seed: [u8; 32] = hex::decode(&e.seed)
                .ok()
                .and_then(|b| b.try_into().ok())
                .with_context(|| format!("seed {i}: not 64 hex characters"))?;
            if e.links == 0 || e.links > MAX_SEED_LINKS {
                bail!("seed {i}: {} links", e.links);
            }
            let chain = SeedChain::new(self.chain_id, validator, seed, e.links);
            if hex::encode(chain.commitment()) != e.commitment.to_ascii_lowercase() {
                bail!("seed {i} does not give its recorded commitment for chain {} and validator {}: the file is not this validator's", self.chain_id, self.validator);
            }
            out.push(chain);
        }
        Ok(out)
    }
}

/// What the file last looked like on disk: enough to notice that `beacon recommit` replaced it.
type Stamp = Option<(std::time::SystemTime, u64)>;

fn stamp_of(path: &Path) -> Stamp {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().ok()?, m.len()))
}

struct Loaded {
    chains: Vec<SeedChain>,
    stamp: Stamp,
    /// The last commitment no chain opened, with the file as it then was: asked again with the
    /// file unchanged, the answer is the same, and the whole-chain walk is not repeated every
    /// time this validator's slot comes round.
    missed: Option<[u8; 32]>,
}

/// The node's [`RevealSource`]: the seed file of one validator on one chain, re-read when it
/// changes on disk (a `recommit` while the node runs).
pub struct SeedSource {
    path: PathBuf,
    chain_id: u64,
    validator: Address,
    loaded: Mutex<Loaded>,
}

impl SeedSource {
    /// Open the seed file in `datadir` for `validator` on `chain_id`. A missing or unusable
    /// file is not an error here: the node runs, votes and misses its own slots (and says so),
    /// and picks the file up when it appears.
    pub fn open(datadir: &Path, chain_id: u64, validator: Address) -> SeedSource {
        let source = SeedSource {
            path: seed_path(datadir),
            chain_id,
            validator,
            loaded: Mutex::new(Loaded { chains: Vec::new(), stamp: None, missed: None }),
        };
        source.reload(&mut source.loaded.lock().unwrap_or_else(|e| e.into_inner()));
        source
    }

    fn reload(&self, loaded: &mut Loaded) {
        loaded.stamp = stamp_of(&self.path);
        loaded.missed = None;
        loaded.chains = Vec::new();
        if loaded.stamp.is_none() {
            tracing::warn!("no beacon seed file at {}: this validator cannot reveal and will miss its slots (`rand-node beacon init` / `recommit`)", self.path.display());
            return;
        }
        let chains = SeedFile::read(&self.path).and_then(|f| {
            if f.chain_id != self.chain_id || f.validator()? != self.validator {
                bail!("it is chain {}'s file for validator {}, not chain {}'s for {}", f.chain_id, f.validator, self.chain_id, self.validator.to_base58());
            }
            f.chains()
        });
        match chains {
            Ok(chains) => {
                tracing::info!("beacon seed file {}: {} chain(s)", self.path.display(), chains.len());
                loaded.chains = chains;
            }
            Err(e) => tracing::error!("beacon seed file {} is unusable ({e:#}): this validator will miss its slots", self.path.display()),
        }
    }

    /// The reveal for `commitment` and how many reveals its chain has left (this one included),
    /// or `None` when no seed in the file opens it.
    pub fn reveal_and_remaining(&self, commitment: &[u8; 32]) -> Option<([u8; 32], u64)> {
        let mut loaded = self.loaded.lock().unwrap_or_else(|e| e.into_inner());
        if stamp_of(&self.path) != loaded.stamp {
            self.reload(&mut loaded);
        }
        if loaded.missed == Some(*commitment) {
            return None;
        }
        // Newest first: after a recommit the new chain is the one in use.
        let found = loaded.chains.iter().rev().find_map(|c| c.reveal_for(commitment));
        if found.is_none() {
            loaded.missed = Some(*commitment);
        }
        found
    }
}

impl RevealSource for SeedSource {
    fn reveal(&self, commitment: &[u8; 32]) -> Option<[u8; 32]> {
        self.reveal_and_remaining(commitment).map(|(r, _)| r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use randprotocol_core::ledger::beacon::link;
    use randprotocol_core::Keypair;

    fn validator(i: u8) -> Address {
        Keypair::from_seed([i; 32]).unwrap().address()
    }

    /// `init` writes a 0600 file that round-trips, whose commitment is `L^links(seed)` for this
    /// chain and validator, and refuses to overwrite it.
    #[test]
    fn a_seed_file_is_created_once_private_and_gives_its_commitment() {
        let dir = tempfile::tempdir().unwrap();
        let path = seed_path(dir.path());
        let entry = SeedFile::create(&path, 22, &validator(1), 40).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let file = SeedFile::read(&path).unwrap();
        assert_eq!((file.version, file.chain_id, file.validator().unwrap()), (1, 22, validator(1)));
        assert_eq!(file.seeds, vec![entry.clone()]);
        assert_eq!(file.newest_commitment(), Some(entry.commitment.as_str()));
        let mut x: [u8; 32] = hex::decode(&entry.seed).unwrap().try_into().unwrap();
        for _ in 0..40 {
            x = link(22, &validator(1), &x);
        }
        assert_eq!(hex::encode(x), entry.commitment);
        let e = SeedFile::create(&path, 22, &validator(1), 40).unwrap_err();
        assert!(format!("{e:#}").contains("refusing to overwrite"), "{e:#}");
        assert_eq!(SeedFile::read(&path).unwrap().seeds, vec![entry], "the refused init left the file alone");
        for bad in [0, MAX_SEED_LINKS + 1] {
            assert!(SeedFile::create(&dir.path().join("x.json"), 22, &validator(1), bad).is_err());
        }
        // Two files never share a seed.
        let other = SeedFile::create(&dir.path().join("other.json"), 22, &validator(1), 40).unwrap();
        assert_ne!(other.seed, file.seeds[0].seed);
    }

    /// `recommit` appends a chain and keeps the old one; a file for another validator or chain
    /// is refused, and a file whose seed does not give its commitment does not load.
    #[test]
    fn a_recommit_appends_and_a_foreign_or_edited_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = seed_path(dir.path());
        let first = SeedFile::append(&path, 22, &validator(1), 8).unwrap();
        let second = SeedFile::append(&path, 22, &validator(1), 16).unwrap();
        let file = SeedFile::read(&path).unwrap();
        assert_eq!(file.seeds, vec![first.clone(), second.clone()]);
        assert_eq!(file.chains().unwrap().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "still private after the rename");
        }
        for (chain, v) in [(23, validator(1)), (22, validator(2))] {
            let e = SeedFile::append(&path, chain, &v, 8).unwrap_err();
            assert!(format!("{e:#}").contains("another host or for another chain"), "{e:#}");
        }
        assert_eq!(SeedFile::read(&path).unwrap().seeds.len(), 2);
        // The same seeds under another validator's name: the commitments no longer match.
        let mut copied = file.clone();
        copied.validator = validator(2).to_base58();
        assert!(format!("{:#}", copied.chains().err().expect("a foreign file")).contains("not this validator's"));
        let mut edited = file;
        edited.seeds[0].seed = hex::encode([7u8; 32]);
        assert!(edited.chains().is_err());
    }

    /// The source answers from the file, newest chain first, picks up a recommit made while it
    /// is open, answers nothing for a commitment no seed opens (and nothing when there is no
    /// file, or the file is another validator's), and never fails to open.
    #[test]
    fn the_seed_source_reveals_from_the_file_and_follows_a_recommit() {
        let dir = tempfile::tempdir().unwrap();
        let v = validator(1);
        let none = SeedSource::open(dir.path(), 22, v);
        assert_eq!(none.reveal(&[1; 32]), None, "no file: no reveal, no panic");
        let first = SeedFile::create(&seed_path(dir.path()), 22, &v, 8).unwrap();
        let c1: [u8; 32] = hex::decode(&first.commitment).unwrap().try_into().unwrap();
        // The source opened before the file existed picks it up.
        let (r1, left) = none.reveal_and_remaining(&c1).expect("the file appeared");
        assert_eq!((link(22, &v, &r1), left), (c1, 8));
        assert_eq!(none.reveal_and_remaining(&r1).unwrap().1, 7);
        assert_eq!(none.reveal(&c1), Some(r1), "asked again after an abandoned block: the same reveal");
        assert_eq!(none.reveal(&[9; 32]), None);
        assert_eq!(none.reveal(&[9; 32]), None, "the remembered miss");
        // A recommit while the node runs: the new chain opens its commitment, the old one still
        // opens the old.
        let second = SeedFile::append(&seed_path(dir.path()), 22, &v, 4).unwrap();
        let c2: [u8; 32] = hex::decode(&second.commitment).unwrap().try_into().unwrap();
        let (r2, left) = none.reveal_and_remaining(&c2).expect("the appended chain");
        assert_eq!((link(22, &v, &r2), left), (c2, 4));
        assert_eq!(none.reveal(&r1).map(|r| link(22, &v, &r)), Some(r1));
        // Another validator's node pointed at this datadir gets nothing.
        let foreign = SeedSource::open(dir.path(), 22, validator(2));
        assert_eq!(foreign.reveal(&c1), None);
        assert_eq!(SeedSource::open(dir.path(), 23, v).reveal(&c1), None);
    }
}
