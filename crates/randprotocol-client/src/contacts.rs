//! Named addresses (spec 2026-09-26 §3.1), at `<key path>.contacts.json`, mode 0600.

use anyhow::{anyhow, Result};
use randprotocol_core::notes::ShieldedAddress;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct Contacts { pub entries: BTreeMap<String, String> }

fn path_for(key: &Path) -> PathBuf { PathBuf::from(format!("{}.contacts.json", key.display())) }

impl Contacts {
    pub fn load(key: &Path) -> Result<Contacts> {
        match std::fs::read_to_string(path_for(key)) {
            Ok(s) => Ok(serde_json::from_str(&s)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Contacts::default()),
            Err(e) => Err(e.into()),
        }
    }
    pub fn save(&self, key: &Path) -> Result<()> {
        let p = path_for(key);
        let tmp = p.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
            let mut f = o.open(&tmp)?;
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, p)?;
        Ok(())
    }
    pub fn add(&mut self, name: &str, a: &ShieldedAddress) -> Result<()> {
        let lower = name.to_ascii_lowercase();
        if name.is_empty() || name.chars().count() > 64 || lower.starts_with("rand1") || lower.starts_with("randpay:") {
            return Err(anyhow!("a contact name is 1-64 characters and cannot start with rand1 or randpay:"));
        }
        if self.entries.contains_key(name) { return Err(anyhow!("a contact named {name} exists")); }
        if let Some(other) = self.name_of(a) { return Err(anyhow!("this address is already saved as {other}")); }
        self.entries.insert(name.to_string(), a.to_string());
        Ok(())
    }
    pub fn remove(&mut self, name: &str) -> Result<()> {
        self.entries.remove(name).map(|_| ()).ok_or_else(|| anyhow!("no contact named {name}"))
    }
    pub fn get(&self, name: &str) -> Option<ShieldedAddress> {
        self.entries.get(name).and_then(|s| ShieldedAddress::parse(s).ok())
    }
    pub fn name_of(&self, a: &ShieldedAddress) -> Option<&str> {
        let s = a.to_string();
        self.entries.iter().find(|(_, v)| **v == s).map(|(k, _)| k.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn addr() -> ShieldedAddress {
        randprotocol_zkvm::address::address_of(&randprotocol_zkvm::notes::SpendKey::random().viewing_key())
    }
    #[test]
    fn names_that_look_like_addresses_or_links_are_refused() {
        let mut c = Contacts::default();
        for bad in ["", "rand1abc", "RAND1abc", "randpay:x", "RandPay:x", &"n".repeat(65)] {
            assert!(c.add(bad, &addr()).is_err(), "{bad:?}");
        }
        c.add("alice", &addr()).unwrap();
        assert!(c.add("alice", &addr()).is_err(), "unique name");
    }
    #[test]
    fn an_address_lives_under_one_name() {
        let (mut c, a) = (Contacts::default(), addr());
        c.add("alice", &a).unwrap();
        assert!(c.add("alice2", &a).is_err());
        assert_eq!(c.name_of(&a), Some("alice"));
    }
    #[test]
    fn the_file_is_private_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("w.key.json");
        let (mut c, a) = (Contacts::default(), addr());
        c.add("alice", &a).unwrap();
        c.save(&key).unwrap();
        let p = dir.path().join("w.key.json.contacts.json");
        #[cfg(unix)]
        { use std::os::unix::fs::PermissionsExt; assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600); }
        assert_eq!(Contacts::load(&key).unwrap().get("alice"), Some(a));
    }
}
